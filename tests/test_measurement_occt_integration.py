"""@brief 有 OCP 时验证真实 STEP 的独立尺寸测量与签名闭环。"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.desktop.cad_workbench.measurement_bundle import create_measurement_bundle
from apps.desktop.cad_workbench.measurement_trust import canonical_sha256
from scripts.cad_evidence_verifier import verify_bundle


OCP = pytest.importorskip("OCP")


def test_real_step_dimension_attestation(tmp_path: Path) -> None:
    from OCP.BRepAlgoAPI import BRepAlgoAPI_Cut
    from OCP.BRepPrimAPI import BRepPrimAPI_MakeBox, BRepPrimAPI_MakeCylinder
    from OCP.IFSelect import IFSelect_RetDone
    from OCP.STEPControl import STEPControl_AsIs, STEPControl_Writer
    from OCP.gp import gp_Ax2, gp_Dir, gp_Pnt

    box = BRepPrimAPI_MakeBox(
        gp_Pnt(-30.0, -20.0, -6.0),
        60.0,
        40.0,
        12.0,
    ).Shape()
    hole = BRepPrimAPI_MakeCylinder(
        gp_Ax2(gp_Pnt(0.0, 0.0, -20.0), gp_Dir(0.0, 0.0, 1.0)),
        5.0,
        40.0,
    ).Shape()
    cut = BRepAlgoAPI_Cut(box, hole)
    cut.Build()
    assert cut.IsDone()
    step = tmp_path / "plate.step"
    writer = STEPControl_Writer()
    assert writer.Transfer(cut.Shape(), STEPControl_AsIs) == IFSelect_RetDone
    assert writer.Write(str(step)) == IFSelect_RetDone

    spec = {
        "schema": "cad-dimension-verification/v1",
        "units": "mm",
        "source": "deterministic_parser",
        "artifacts": {"requiredKinds": ["step"], "measurementKinds": ["step"]},
        "checks": {
            "envelope": {"expectedUm": [12000, 40000, 60000], "toleranceUm": 1},
            "holes": [{"diameterUm": 10000, "count": 1, "toleranceUm": 1}],
        },
    }
    session = {
        "sessionId": "session-occt",
        "jobId": "job-occt",
        "runId": "run-occt",
        "nonce": secrets.token_hex(32),
        "spec": spec,
        "specSha256": canonical_sha256(spec),
    }
    bundle = create_measurement_bundle(
        [{"kind": "step", "path": str(step), "exists": True, "producedThisRun": True}],
        allowed_roots=[tmp_path],
        session=session,
        spec_sha256=session["specSha256"],
        output_path=tmp_path / "bundle.zip",
    )

    attestation = verify_bundle(
        bundle_path=Path(bundle["path"]),
        session=session,
        private_key=Ed25519PrivateKey.generate(),
        workflow_repository="private/cad-evidence",
        workflow_ref="refs/heads/main",
        workflow_sha="d" * 40,
        runner_id="occt-runner",
        argv=["python", "cad_evidence_verifier.py"],
        now=datetime.now(timezone.utc),
    )

    assert attestation["decision"] == "pass"
    assert attestation["artifacts"][0]["envelopeUm"] == [12000, 40000, 60000]
    assert attestation["artifacts"][0]["holes"] == [
        {"diameterUm": 10000, "count": 1}
    ]
