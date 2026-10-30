"""受信测量证明测试夹具；私钥只存在于测试进程。"""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apps.desktop.cad_workbench.measurement_trust import (
    ATTESTATION_DOMAIN,
    ATTESTATION_STATUS_DOMAIN,
    canonical_sha256,
    lock_dimension_spec,
    public_key_id,
    sign_document,
)


def make_signed_evidence(
    step_path: Path,
    *,
    now: datetime | None = None,
    run_id: str = "run-1",
    job_id: str = "job-1",
    decision: str = "pass",
) -> dict[str, Any]:
    checked = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    key = Ed25519PrivateKey.generate()
    status_key = Ed25519PrivateKey.generate()
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    key_id = public_key_id(key.public_key())
    status_key_id = public_key_id(status_key.public_key())
    status_public_pem = status_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    trust_root = {
        "schema": "cad-measurement-trust-root/v1",
        "keys": [
            {
                "keyId": key_id,
                "publicKeyPem": public_pem,
                "purposes": ["measurement_attestation"],
                "notBefore": (checked - timedelta(days=1)).isoformat(),
                "revokedAt": None,
            },
            {
                "keyId": status_key_id,
                "publicKeyPem": status_public_pem,
                "purposes": ["attestation_status"],
                "notBefore": (checked - timedelta(days=1)).isoformat(),
                "revokedAt": None,
            },
        ],
        "rotationLog": [
            {
                "keyId": key_id,
                "addedAt": (checked - timedelta(days=2)).isoformat(),
                "reason": "test fixture",
            },
            {
                "keyId": status_key_id,
                "addedAt": (checked - timedelta(days=2)).isoformat(),
                "reason": "test fixture status key",
            },
        ],
    }
    spec = {
        "schema": "cad-dimension-verification/v1",
        "units": "mm",
        "source": "deterministic_parser",
        "artifacts": {
            "requiredKinds": ["step"],
            "measurementKinds": ["step"],
        },
        "checks": {
            "envelope": {
                "expectedUm": [40000, 12000, 60000],
                "toleranceUm": 1,
            },
            "holes": [
                {"diameterUm": 4000, "count": 4, "toleranceUm": 1},
                {"diameterUm": 10000, "count": 1, "toleranceUm": 1},
            ],
        },
    }
    locked = lock_dimension_spec(spec, confirmation_required=False)
    session_id = "session-" + secrets.token_hex(8)
    nonce = secrets.token_hex(32)
    attestation_id = "att-" + secrets.token_hex(16)
    raw = step_path.read_bytes()
    attestation = {
        "schema": "cad-measurement-attestation/v1",
        "attestationId": attestation_id,
        "sessionId": session_id,
        "jobId": job_id,
        "runId": run_id,
        "nonce": nonce,
        "specSha256": locked["sha256"],
        "verifier": {
            "workflowRepository": "private/cad-evidence",
            "workflowRef": "refs/heads/main",
            "workflowSha": "a" * 40,
            "toolkitSha256": hashlib.sha256(b"test-toolkit").hexdigest(),
            "runtime": {
                "pythonVersion": "3.11.0",
                "platform": "test",
                "dependencyLockSha256": hashlib.sha256(b"test-lock").hexdigest(),
                "dependencyVersionsSha256": hashlib.sha256(b"test-versions").hexdigest(),
            },
            "runnerId": "cad-evidence-runner-1",
            "processId": 4242,
            "processCreatedAt": checked.isoformat(),
            "argv": ["python", "cad_evidence_verifier.py"],
            "argvSha256": canonical_sha256(["python", "cad_evidence_verifier.py"]),
            "exitCode": 0,
        },
        "artifacts": [
            {
                "artifactId": "artifact-001",
                "kind": "step",
                "bundlePath": "artifacts/artifact-001.step",
                "sha256": hashlib.sha256(raw).hexdigest(),
                "sizeBytes": len(raw),
                "geometryFingerprintSha256": hashlib.sha256(b"geometry").hexdigest(),
                "validSolids": 1,
                "envelopeUm": [40000, 12000, 60000],
                "holes": [
                    {"diameterUm": 4000, "count": 4},
                    {"diameterUm": 10000, "count": 1},
                ],
            }
        ],
        "checks": [
            {"id": "artifact-readback", "status": "pass", "message": "readback"},
            {"id": "spec-envelope-dimensions", "status": "pass", "message": "envelope"},
            {"id": "spec-hole-diameters", "status": "pass", "message": "holes"},
        ],
        "decision": decision,
        "issuedAt": checked.isoformat(),
        "expiresAt": (checked + timedelta(minutes=30)).isoformat(),
        "signer": {
            "algorithm": "Ed25519",
            "keyId": key_id,
            "signedAt": checked.isoformat(),
        },
    }
    attestation = sign_document(attestation, key, ATTESTATION_DOMAIN)
    status = {
        "schema": "cad-attestation-status/v1",
        "attestationId": attestation_id,
        "status": "active",
        "verifierPolicy": {
            "workflowRepository": attestation["verifier"]["workflowRepository"],
            "workflowRef": attestation["verifier"]["workflowRef"],
            "workflowSha": attestation["verifier"]["workflowSha"],
            "toolkitSha256": attestation["verifier"]["toolkitSha256"],
            "pythonVersion": attestation["verifier"]["runtime"]["pythonVersion"],
            "platform": attestation["verifier"]["runtime"]["platform"],
            "dependencyLockSha256": attestation["verifier"]["runtime"]["dependencyLockSha256"],
            "dependencyVersionsSha256": attestation["verifier"]["runtime"]["dependencyVersionsSha256"],
        },
        "checkedAt": checked.isoformat(),
        "expiresAt": (checked + timedelta(seconds=45)).isoformat(),
        "signer": {
            "algorithm": "Ed25519",
            "keyId": status_key_id,
            "signedAt": checked.isoformat(),
        },
    }
    status = sign_document(status, status_key, ATTESTATION_STATUS_DOMAIN)
    return {
        "trustRoot": trust_root,
        "spec": locked,
        "session": {
            "schema": "cad-evidence-session/v1",
            "sessionId": session_id,
            "jobId": job_id,
            "runId": run_id,
            "nonce": nonce,
            "specSha256": locked["sha256"],
            "uploadUrl": "https://upload.invalid/one-time",
            "expiresAt": (checked + timedelta(hours=2)).isoformat(),
        },
        "attestation": attestation,
        "status": status,
        "privateKey": key,
        "statusPrivateKey": status_key,
        "onlineStatus": lambda _attestation_id, value=status: value,
        "now": checked,
    }
