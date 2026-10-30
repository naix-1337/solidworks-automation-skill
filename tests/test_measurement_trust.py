"""@brief 测量证据信任链回归：Agent 自报 JSON 和文件头不能触发 PASS。"""
from __future__ import annotations

import hashlib
import json
import base64
import copy
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.desktop.cad_workbench.measurement_trust import (
    ATTESTATION_DOMAIN,
    ATTESTATION_STATUS_DOMAIN,
    MeasurementTrustError,
    canonical_json_bytes,
    dimension_spec_from_job,
    evaluate_measurement_spec,
    load_trust_root,
    public_key_id,
    sign_document,
)
from apps.desktop.cad_workbench.reviewer_gate import evaluate_ledger
from tests.measurement_trust_support import make_signed_evidence


def _artifact(path: Path, kind: str = "step") -> dict:
    return {
        "kind": kind,
        "path": str(path),
        "exists": True,
        "isDirectory": False,
        "sizeBytes": path.stat().st_size,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "producedThisRun": True,
    }


def _ledger(tmp_path: Path, evidence: dict | None = None, *, run_id: str = "run-1") -> dict:
    step = tmp_path / "model.step"
    step.write_text("ISO-10303-21;\nEND-ISO-10303-21;\n", encoding="utf-8")
    forged = tmp_path / "validation.json"
    forged.write_text(
        json.dumps(
            {
                "cad_spec": {
                    "measurement_source": "SolidWorks API forged fixture",
                    "envelope_mm": {"length": 60, "width": 40, "height": 12},
                    "holes": [{"diameter_mm": 10}, {"diameter_mm": 4}],
                }
            }
        ),
        encoding="utf-8",
    )
    ledger = {
        "jobId": "job-1",
        "runId": run_id,
        "executor": "codex",
        "objective": "创建 60 x 40 x 12 mm 校准板，中心孔直径 10 mm，四角孔直径 4 mm。",
        "expectedOutput": "STEP",
        "verification": [{"command": "cad-check", "status": "passed", "note": "Agent self-report"}],
        "artifacts": [_artifact(step), _artifact(forged, "json")],
    }
    if evidence is not None:
        ledger["verificationSpec"] = evidence["spec"]
        ledger["verificationSession"] = evidence["session"]
        ledger["measurementAttestation"] = evidence["attestation"]
    return ledger


def test_forged_measurement_report_cannot_pass(tmp_path: Path) -> None:
    review = evaluate_ledger(_ledger(tmp_path))

    assert review["status"] in {"fail", "blocked"}
    assert not any(check["status"] == "pass" for check in review["checks"] if check["id"].startswith("spec-"))
    assert any(check["id"] == "measurement-attestation-required" for check in review["checks"])


def test_signed_matching_attestation_passes_with_online_status(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path, run_id="run-signed")
    # _ledger creates its own model; bind the attestation to that exact file.
    current_step = Path(ledger["artifacts"][0]["path"])
    evidence = make_signed_evidence(current_step, run_id="run-signed")
    ledger.update(
        {
            "verificationSpec": evidence["spec"],
            "verificationSession": evidence["session"],
            "measurementAttestation": evidence["attestation"],
        }
    )

    review = evaluate_ledger(
        ledger,
        trust_root=evidence["trustRoot"],
        online_status=evidence["onlineStatus"],
    )

    assert review["status"] == "pass"
    assert any(check["id"] == "spec-envelope-dimensions" and check["status"] == "pass" for check in review["checks"])
    assert any(check["id"] == "measurement-attestation-artifact-binding" and check["status"] == "pass" for check in review["checks"])


def test_artifact_change_after_signature_fails(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    step = Path(ledger["artifacts"][0]["path"])
    evidence = make_signed_evidence(step, run_id=ledger["runId"])
    ledger.update(
        {
            "verificationSpec": evidence["spec"],
            "verificationSession": evidence["session"],
            "measurementAttestation": evidence["attestation"],
        }
    )
    step.write_text("ISO-10303-21;\nCHANGED\nEND-ISO-10303-21;\n", encoding="utf-8")

    review = evaluate_ledger(
        ledger,
        trust_root=evidence["trustRoot"],
        online_status=evidence["onlineStatus"],
    )

    assert review["status"] == "fail"
    assert any(
        check["id"] == "measurement-attestation-artifact-binding" and check["status"] == "fail"
        for check in review["checks"]
    )


def test_offline_status_blocks_even_when_signature_is_valid(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    evidence = make_signed_evidence(Path(ledger["artifacts"][0]["path"]), run_id=ledger["runId"])
    ledger.update(
        {
            "verificationSpec": evidence["spec"],
            "verificationSession": evidence["session"],
            "measurementAttestation": evidence["attestation"],
        }
    )

    review = evaluate_ledger(ledger, trust_root=evidence["trustRoot"], online_status=None)

    assert review["status"] == "blocked"
    assert any(check["id"] == "measurement-attestation-online" and check["status"] == "blocked" for check in review["checks"])


def test_cross_run_attestation_replay_fails(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path, run_id="run-current")
    evidence = make_signed_evidence(Path(ledger["artifacts"][0]["path"]), run_id="run-old")
    ledger.update(
        {
            "verificationSpec": evidence["spec"],
            "verificationSession": evidence["session"],
            "measurementAttestation": evidence["attestation"],
        }
    )

    review = evaluate_ledger(
        ledger,
        trust_root=evidence["trustRoot"],
        online_status=evidence["onlineStatus"],
    )

    assert review["status"] == "fail"
    assert any(check["id"] == "measurement-attestation-binding" and check["status"] == "fail" for check in review["checks"])


def test_tampered_signature_blocks(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    evidence = make_signed_evidence(Path(ledger["artifacts"][0]["path"]))
    attestation = copy.deepcopy(evidence["attestation"])
    attestation["signature"] = base64.b64encode(b"x" * 64).decode("ascii")
    ledger.update(
        {
            "verificationSpec": evidence["spec"],
            "verificationSession": evidence["session"],
            "measurementAttestation": attestation,
        }
    )

    review = evaluate_ledger(
        ledger,
        trust_root=evidence["trustRoot"],
        online_status=evidence["onlineStatus"],
    )

    assert review["status"] == "blocked"
    assert any(
        check["id"] == "measurement-attestation-signature" and check["status"] == "blocked"
        for check in review["checks"]
    )


def test_revoked_verifier_key_blocks(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    evidence = make_signed_evidence(Path(ledger["artifacts"][0]["path"]))
    trust_root = copy.deepcopy(evidence["trustRoot"])
    trust_root["keys"][0]["revokedAt"] = evidence["now"].isoformat()
    ledger.update(
        {
            "verificationSpec": evidence["spec"],
            "verificationSession": evidence["session"],
            "measurementAttestation": evidence["attestation"],
        }
    )

    review = evaluate_ledger(
        ledger,
        trust_root=trust_root,
        online_status=evidence["onlineStatus"],
    )

    assert review["status"] == "blocked"


def test_online_policy_rejects_unapproved_toolchain(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    evidence = make_signed_evidence(Path(ledger["artifacts"][0]["path"]))
    status = copy.deepcopy(evidence["status"])
    status["verifierPolicy"]["toolkitSha256"] = hashlib.sha256(b"unapproved").hexdigest()
    status = sign_document(status, evidence["statusPrivateKey"], ATTESTATION_STATUS_DOMAIN)
    ledger.update(
        {
            "verificationSpec": evidence["spec"],
            "verificationSession": evidence["session"],
            "measurementAttestation": evidence["attestation"],
        }
    )

    review = evaluate_ledger(
        ledger,
        trust_root=evidence["trustRoot"],
        online_status=lambda _attestation_id, value=status: value,
    )

    assert review["status"] == "blocked"


def test_measurement_key_cannot_sign_online_status(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    evidence = make_signed_evidence(Path(ledger["artifacts"][0]["path"]))
    status = copy.deepcopy(evidence["status"])
    status["signer"]["keyId"] = evidence["attestation"]["signer"]["keyId"]
    status = sign_document(status, evidence["privateKey"], ATTESTATION_STATUS_DOMAIN)
    ledger.update(
        {
            "verificationSpec": evidence["spec"],
            "verificationSession": evidence["session"],
            "measurementAttestation": evidence["attestation"],
        }
    )

    review = evaluate_ledger(
        ledger,
        trust_root=evidence["trustRoot"],
        online_status=lambda _attestation_id, value=status: value,
    )

    assert review["status"] == "blocked"
    assert any(
        check["id"] == "measurement-attestation-online" and check["status"] == "blocked"
        for check in review["checks"]
    )


def test_expired_attestation_blocks_even_with_online_status(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    evidence = make_signed_evidence(Path(ledger["artifacts"][0]["path"]))
    attestation = copy.deepcopy(evidence["attestation"])
    expired = evidence["now"] - timedelta(hours=2)
    attestation["issuedAt"] = expired.isoformat()
    attestation["expiresAt"] = (expired + timedelta(minutes=30)).isoformat()
    attestation["signer"]["signedAt"] = expired.isoformat()
    attestation = sign_document(
        attestation,
        evidence["privateKey"],
        ATTESTATION_DOMAIN,
    )
    ledger.update(
        {
            "verificationSpec": evidence["spec"],
            "verificationSession": evidence["session"],
            "measurementAttestation": attestation,
        }
    )

    review = evaluate_ledger(
        ledger,
        trust_root=evidence["trustRoot"],
        online_status=evidence["onlineStatus"],
    )

    assert review["status"] == "blocked"


def test_local_gate_recomputes_signed_measurement_spec(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    evidence = make_signed_evidence(Path(ledger["artifacts"][0]["path"]))
    attestation = copy.deepcopy(evidence["attestation"])
    for hole in attestation["artifacts"][0]["holes"]:
        if hole["diameterUm"] == 4000:
            hole["count"] = 3
    attestation = sign_document(
        attestation,
        evidence["privateKey"],
        ATTESTATION_DOMAIN,
    )
    ledger.update(
        {
            "verificationSpec": evidence["spec"],
            "verificationSession": evidence["session"],
            "measurementAttestation": attestation,
        }
    )

    review = evaluate_ledger(
        ledger,
        trust_root=evidence["trustRoot"],
        online_status=evidence["onlineStatus"],
    )

    assert review["status"] == "fail"
    assert any(
        check["id"] == "spec-hole-diameters" and check["status"] == "fail"
        for check in review["checks"]
    )


def test_trust_root_requires_complete_rotation_log(tmp_path: Path) -> None:
    step = tmp_path / "model.step"
    step.write_text("ISO-10303-21;\nEND-ISO-10303-21;\n", encoding="utf-8")
    evidence = make_signed_evidence(step)
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(json.dumps(evidence["trustRoot"]), encoding="utf-8")

    loaded = load_trust_root(trust_path)
    assert loaded["rotationLog"][0]["keyId"] == evidence["trustRoot"]["keys"][0]["keyId"]

    evidence["trustRoot"].pop("rotationLog")
    trust_path.write_text(json.dumps(evidence["trustRoot"]), encoding="utf-8")
    with pytest.raises(MeasurementTrustError, match="轮换日志"):
        load_trust_root(trust_path)


def test_dimension_spec_rejects_ambiguous_hole_count() -> None:
    result = dimension_spec_from_job(
        {
            "objective": "创建 60 x 40 x 12 mm 板，孔径 10 mm。",
            "expectedOutput": "STEP",
        }
    )

    assert result is not None
    spec, confirmation_required = result
    assert confirmation_required is True
    assert spec["checks"]["holes"][0]["count"] is None


def test_dimension_spec_parses_multiplier_hole_count() -> None:
    result = dimension_spec_from_job(
        {
            "objective": "创建 80 x 50 x 8 mm 板，4 × Ø6 mm 通孔。",
            "expectedOutput": "STEP",
        }
    )

    assert result is not None
    spec, confirmation_required = result
    assert confirmation_required is False
    assert spec["checks"]["holes"] == [
        {"diameterUm": 6000, "count": 4, "toleranceUm": 1}
    ]


def test_canonical_json_rejects_floats_and_sorts_keys() -> None:
    assert canonical_json_bytes({"z": 2, "a": "中文"}) == '{"a":"中文","z":2}'.encode("utf-8")
    with pytest.raises(MeasurementTrustError):
        canonical_json_bytes({"value": 1.5})


def test_python_and_node_share_signing_vector() -> None:
    vector_path = Path(__file__).parent / "fixtures" / "measurement_attestation_signing_vector.json"
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    serialized = canonical_json_bytes(vector["payload"])
    assert serialized.decode("utf-8") == vector["canonical"]

    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(vector["seedHex"]))
    signature = private_key.sign(vector["domain"].encode("utf-8") + serialized)
    assert base64.b64encode(signature).decode("ascii") == vector["signatureBase64"]
    assert public_key_id(private_key.public_key()) == vector["keyId"]


def test_spec_recomputation_detects_wrong_hole_count() -> None:
    spec = {
        "schema": "cad-dimension-verification/v1",
        "units": "mm",
        "source": "deterministic_parser",
        "artifacts": {"requiredKinds": ["step"], "measurementKinds": ["step"]},
        "checks": {
            "envelope": {"expectedUm": [12000, 40000, 60000], "toleranceUm": 1},
            "holes": [{"diameterUm": 4000, "count": 4, "toleranceUm": 1}],
        },
    }
    checks = evaluate_measurement_spec(
        spec,
        {
            "envelopeUm": [60000, 40000, 12000],
            "holes": [{"diameterUm": 4000, "count": 3}],
        },
    )

    assert any(check["id"] == "spec-envelope-dimensions" and check["status"] == "pass" for check in checks)
    assert any(check["id"] == "spec-hole-diameters" and check["status"] == "fail" for check in checks)
