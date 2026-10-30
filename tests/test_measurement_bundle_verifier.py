"""@brief 受控证明包和独立验证器回归。"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.desktop.cad_workbench.measurement_bundle import (
    create_measurement_bundle,
    open_measurement_bundle,
)
from apps.desktop.cad_workbench.measurement_trust import (
    ATTESTATION_DOMAIN,
    MeasurementTrustError,
    canonical_sha256,
    public_key_id,
    verify_signed_document,
)
from scripts import cad_evidence_verifier


def _spec_and_session() -> tuple[dict, dict]:
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
        "sessionId": "session-" + secrets.token_hex(8),
        "jobId": "job-bundle",
        "runId": "run-bundle",
        "nonce": secrets.token_hex(32),
        "spec": spec,
        "specSha256": canonical_sha256(spec),
    }
    return spec, session


def test_bundle_roundtrip_uses_relative_members_and_hashes(tmp_path: Path) -> None:
    step = tmp_path / "model.step"
    step.write_text("ISO-10303-21;\nEND-ISO-10303-21;\n", encoding="utf-8")
    _, session = _spec_and_session()
    bundle = create_measurement_bundle(
        [
            {
                "kind": "step",
                "path": str(step),
                "exists": True,
                "producedThisRun": True,
                "sha256": hashlib.sha256(step.read_bytes()).hexdigest(),
                "sizeBytes": step.stat().st_size,
            }
        ],
        allowed_roots=[tmp_path],
        session=session,
        spec_sha256=session["specSha256"],
        output_path=tmp_path / "evidence.zip",
    )

    manifest, members = open_measurement_bundle(bundle["path"])

    assert manifest["sessionId"] == session["sessionId"]
    assert manifest["artifacts"][0]["bundlePath"] == "artifacts/artifact-001.step"
    assert manifest["artifacts"][0]["sha256"] == hashlib.sha256(step.read_bytes()).hexdigest()
    assert members["artifacts/artifact-001.step"] == step.read_bytes()
    assert str(tmp_path) not in json.dumps(manifest, ensure_ascii=False)


def test_bundle_rejects_zip_path_traversal(tmp_path: Path) -> None:
    bundle_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(bundle_path, "w") as bundle:
        bundle.writestr("../escape.step", "bad")

    with pytest.raises(MeasurementTrustError, match="非法 ZIP 成员"):
        open_measurement_bundle(bundle_path)


def test_bundle_rejects_hardlink_source(tmp_path: Path) -> None:
    source = tmp_path / "source.step"
    source.write_text("ISO-10303-21;\nEND-ISO-10303-21;\n", encoding="utf-8")
    linked = tmp_path / "linked.step"
    try:
        os.link(source, linked)
    except OSError:
        pytest.skip("当前文件系统不支持硬链接")
    _, session = _spec_and_session()

    with pytest.raises(MeasurementTrustError, match="硬链接"):
        create_measurement_bundle(
            [{"kind": "step", "path": str(linked), "exists": True, "producedThisRun": True}],
            allowed_roots=[tmp_path],
            session=session,
            spec_sha256=session["specSha256"],
            output_path=tmp_path / "unsafe.zip",
        )


def test_independent_verifier_uses_its_own_measurement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    step = tmp_path / "model.step"
    step.write_text("ISO-10303-21;\nEND-ISO-10303-21;\n", encoding="utf-8")
    spec, session = _spec_and_session()
    bundle = create_measurement_bundle(
        [{"kind": "step", "path": str(step), "exists": True, "producedThisRun": True}],
        allowed_roots=[tmp_path],
        session=session,
        spec_sha256=session["specSha256"],
        output_path=tmp_path / "evidence.zip",
    )
    checked = datetime.now(timezone.utc)
    measured = {
        "validSolids": 1,
        "envelopeUm": [60000, 40000, 12000],
        "holes": [{"diameterUm": 10000, "count": 1}],
        "geometryFingerprintSha256": hashlib.sha256(b"measured-geometry").hexdigest(),
    }
    monkeypatch.setattr(cad_evidence_verifier, "_load_shape", lambda _path: (object(), 1.0))
    monkeypatch.setattr(
        cad_evidence_verifier,
        "_shape_measurement",
        lambda _shape, _unit_to_mm=1.0: measured,
    )
    monkeypatch.setattr(
        cad_evidence_verifier,
        "_process_created_at",
        lambda _pid: checked.isoformat(),
    )
    private_key = Ed25519PrivateKey.generate()

    attestation = cad_evidence_verifier.verify_bundle(
        bundle_path=Path(bundle["path"]),
        session=session,
        private_key=private_key,
        workflow_repository="private/cad-evidence",
        workflow_ref="refs/heads/main",
        workflow_sha="b" * 40,
        runner_id="runner-1",
        argv=["python", "cad_evidence_verifier.py"],
        now=checked,
    )

    assert attestation["decision"] == "pass"
    assert attestation["artifacts"][0]["geometryFingerprintSha256"] == measured["geometryFingerprintSha256"]
    assert attestation["verifier"]["exitCode"] == 0
    trust_root = {
        "schema": "cad-measurement-trust-root/v1",
        "keys": [
            {
                "keyId": public_key_id(private_key.public_key()),
                "publicKeyPem": private_key.public_key()
                .public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode("ascii"),
                "purposes": ["measurement_attestation"],
                "notBefore": (checked - timedelta(days=1)).isoformat(),
                "revokedAt": None,
            }
        ],
        "rotationLog": [
            {
                "keyId": public_key_id(private_key.public_key()),
                "addedAt": (checked - timedelta(days=2)).isoformat(),
                "reason": "test fixture",
            }
        ],
    }
    verify_signed_document(
        attestation,
        schema_name="measurement_attestation.schema.json",
        domain=ATTESTATION_DOMAIN,
        trust_root=trust_root,
        now=checked,
        required_purpose="measurement_attestation",
    )


def test_fake_step_is_signed_as_blocked_not_pass(tmp_path: Path) -> None:
    step = tmp_path / "fake.step"
    step.write_text("ISO-10303-21;\nEND-ISO-10303-21;\n", encoding="utf-8")
    spec, session = _spec_and_session()
    bundle = create_measurement_bundle(
        [{"kind": "step", "path": str(step), "exists": True, "producedThisRun": True}],
        allowed_roots=[tmp_path],
        session=session,
        spec_sha256=session["specSha256"],
        output_path=tmp_path / "fake-evidence.zip",
    )

    attestation = cad_evidence_verifier.verify_bundle(
        bundle_path=Path(bundle["path"]),
        session=session,
        private_key=Ed25519PrivateKey.generate(),
        workflow_repository="private/cad-evidence",
        workflow_ref="refs/heads/main",
        workflow_sha="c" * 40,
        runner_id="runner-1",
        argv=["python", "cad_evidence_verifier.py"],
    )

    assert attestation["decision"] == "blocked"
    assert attestation["artifacts"][0]["validSolids"] == 0
    assert attestation["artifacts"][0]["envelopeUm"] is None
