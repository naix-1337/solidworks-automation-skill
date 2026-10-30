"""@brief 受保护验证会话、封装、回传与本地验签集成。"""
from __future__ import annotations

import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from apps.desktop.cad_workbench.artifact_ledger import build_artifact_ledger
from apps.desktop.cad_workbench.measurement_bundle import open_measurement_bundle
from apps.desktop.cad_workbench.measurement_remote import (
    HttpMeasurementClient,
    MeasurementTransportError,
    complete_measurement_session,
    prepare_measurement_session,
)
from apps.desktop.cad_workbench.measurement_trust import (
    ATTESTATION_DOMAIN,
    sign_document,
)
from apps.desktop.cad_workbench.reviewer_gate import evaluate_ledger
from tests.measurement_trust_support import make_signed_evidence


class FakeClient:
    def __init__(self) -> None:
        self.request: dict | None = None
        self.session_id = "session-" + secrets.token_hex(8)
        self.nonce = secrets.token_hex(32)
        self.uploaded_bundle: Path | None = None
        self.finalized = False
        self.evidence: dict | None = None

    def create_session(self, request):
        self.request = dict(request)
        return {
            "sessionId": self.session_id,
            "nonce": self.nonce,
            "uploadUrl": "https://upload.invalid/one-time",
            "expiresAt": (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat(),
        }

    def upload_bundle(self, upload_url: str, bundle_path: Path) -> None:
        assert upload_url.startswith("https://")
        self.uploaded_bundle = bundle_path

    def finalize_session(self, session_id: str) -> None:
        assert session_id == self.session_id
        self.finalized = True

    def get_attestation(self, session_id: str, timeout_seconds: float = 180.0):
        assert session_id == self.session_id
        assert self.uploaded_bundle is not None
        manifest, members = open_measurement_bundle(self.uploaded_bundle)
        artifact = manifest["artifacts"][0]
        with tempfile.TemporaryDirectory(prefix="remote-session-test-") as temporary:
            extracted = Path(temporary) / "artifact.step"
            extracted.write_bytes(members[artifact["bundlePath"]])
            evidence = make_signed_evidence(
                extracted,
                run_id=self.request["runId"],
                job_id=self.request["jobId"],
            )
        attestation = dict(evidence["attestation"])
        attestation["sessionId"] = self.session_id
        attestation["nonce"] = self.nonce
        attestation["specSha256"] = self.request["specSha256"]
        attestation = sign_document(attestation, evidence["privateKey"], ATTESTATION_DOMAIN)
        evidence["attestation"] = attestation
        self.evidence = evidence
        return attestation

    def online_status(self, attestation_id: str):
        assert self.evidence is not None
        return self.evidence["onlineStatus"](attestation_id)


def test_measurement_session_roundtrip_passes_only_after_signed_remote_result(tmp_path: Path) -> None:
    queue_dir = tmp_path / "queue"
    project = tmp_path / "project"
    project.mkdir()
    job = {
        "id": "session-job",
        "runId": "session-job",
        "executor": "agent",
        "objective": "创建 60 x 40 x 12 mm 校准板，中心孔直径 10 mm，四角孔直径 4 mm。",
        "expectedOutput": "STEP",
        "projectPath": str(project / "project.cadstudio.json"),
    }
    client = FakeClient()

    prepared = prepare_measurement_session(job, client)

    assert prepared["status"] == "passed"
    assert job["verificationSpec"]["sha256"] == client.request["specSha256"]
    assert "uploadUrl" in prepared["session"]
    assert "uploadUrl" not in job["verificationSession"]
    step = project / "model.step"
    step.write_text("ISO-10303-21;\nEND-ISO-10303-21;\n", encoding="utf-8")
    result = {
        "message": "done",
        "artifacts": [{"kind": "step", "path": str(step)}],
        "artifactBaseline": {
            "schemaVersion": "2.0",
            "entries": {},
            "complete": True,
            "truncated": False,
            "scannedCount": 0,
            "errors": [],
        },
    }
    ledger = build_artifact_ledger(queue_dir, job, result)

    completed = complete_measurement_session(
        job=job,
        ledger=ledger,
        allowed_roots=[project],
        client=client,
        evidence_dir=queue_dir / "evidence",
        session=prepared["session"],
    )

    assert completed["status"] == "submitted"
    assert Path(completed["attestationPath"]).is_file()
    ledger["measurementAttestation"] = completed["attestation"]
    assert client.evidence is not None
    review = evaluate_ledger(
        ledger,
        trust_root=client.evidence["trustRoot"],
        online_status=client.online_status,
    )
    assert review["status"] == "pass"


def test_ambiguous_spec_requires_confirmation_before_session(tmp_path: Path) -> None:
    client = FakeClient()
    job = {
        "id": "ambiguous",
        "objective": "创建 60 x 40 x 12 mm 板，孔径 10 mm。",
        "expectedOutput": "STEP",
        "projectPath": str(tmp_path / "part.cadstudio.json"),
    }

    prepared = prepare_measurement_session(job, client)

    assert prepared["status"] == "blocked"
    assert prepared["code"] == "confirmation_required"
    assert client.request is None

    job["verificationSpecConfirmed"] = True
    confirmed = prepare_measurement_session(job, client)
    assert confirmed["status"] == "passed"
    assert job["verificationSpec"]["spec"]["source"] == "user_confirmed"


def test_remote_client_rejects_plaintext_control_plane() -> None:
    with pytest.raises(MeasurementTransportError, match="HTTPS"):
        HttpMeasurementClient("http://verifier.invalid", "token")
