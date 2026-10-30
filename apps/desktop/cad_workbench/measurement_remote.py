"""@brief CAD 尺寸证明的受控会话、上传和在线状态客户端。"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence
from urllib.parse import urlparse

import httpx

from .measurement_bundle import create_measurement_bundle
from .measurement_trust import (
    MeasurementTrustError,
    load_trust_root,
    requested_dimension_spec,
)


CONTROL_URL_ENV = "CAD_EVIDENCE_CONTROL_URL"
CONTROL_TOKEN_ENV = "CAD_EVIDENCE_CONTROL_TOKEN"
TRUST_ROOT_PATH = Path(
    os.environ.get(
        "PROGRAMFILES",
        r"C:\Program Files",
    )
) / "CAD Studio" / "evidence" / "measurement_trust_root.json"


class MeasurementTransportError(RuntimeError):
    """控制面或上传通道不可用。"""


class MeasurementClient(Protocol):
    def create_session(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def upload_bundle(self, upload_url: str, bundle_path: Path) -> None: ...

    def finalize_session(self, session_id: str) -> None: ...

    def get_attestation(self, session_id: str, timeout_seconds: float = 180.0) -> Mapping[str, Any]: ...

    def online_status(self, attestation_id: str) -> Mapping[str, Any]: ...


class HttpMeasurementClient:
    """@brief 只访问固定控制面，不接受 Agent 提供的任意 URL 作为状态源。"""

    def __init__(self, base_url: str, token: str, *, timeout_seconds: float = 30.0) -> None:
        parsed = urlparse(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise MeasurementTransportError("测量控制面必须使用 HTTPS。")
        if not token:
            raise MeasurementTransportError("测量控制面令牌为空。")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout_seconds = timeout_seconds

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}

    def _request(
        self,
        method: str,
        path: str,
        *,
        accepted_statuses: set[int] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        try:
            with httpx.Client(
                timeout=self.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.request(
                    method,
                    self.base_url + path,
                    headers=self._headers(),
                    **kwargs,
                )
        except httpx.HTTPError as exc:
            raise MeasurementTransportError(f"测量控制面不可用: {type(exc).__name__}") from exc
        accepted = accepted_statuses or set()
        if (
            (response.status_code < 200 or response.status_code >= 300)
            and response.status_code not in accepted
        ):
            raise MeasurementTransportError(
                f"测量控制面返回 HTTP {response.status_code}"
            )
        if len(response.content) > 1024 * 1024:
            raise MeasurementTransportError("测量控制面 JSON 响应超过 1 MiB。")
        return response

    def create_session(self, request: Mapping[str, Any]) -> Mapping[str, Any]:
        response = self._request("POST", "/v1/verification-sessions", json=dict(request))
        value = response.json()
        if not isinstance(value, dict):
            raise MeasurementTransportError("创建验证会话响应不是 JSON 对象。")
        return value

    def upload_bundle(self, upload_url: str, bundle_path: Path) -> None:
        parsed = urlparse(upload_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise MeasurementTransportError("证明包上传 URL 必须使用 HTTPS。")
        try:
            with bundle_path.open("rb") as handle:
                with httpx.Client(
                    timeout=300.0,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    response = client.put(
                        upload_url,
                        content=handle,
                        headers={"Content-Type": "application/zip"},
                    )
        except httpx.HTTPError as exc:
            raise MeasurementTransportError(f"证明包上传失败: {type(exc).__name__}") from exc
        if response.status_code < 200 or response.status_code >= 300:
            raise MeasurementTransportError(f"证明包上传返回 HTTP {response.status_code}")

    def finalize_session(self, session_id: str) -> None:
        self._request("POST", f"/v1/verification-sessions/{session_id}/finalize")

    def get_attestation(self, session_id: str, timeout_seconds: float = 180.0) -> Mapping[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        while True:
            response = self._request(
                "GET",
                f"/v1/verification-sessions/{session_id}/attestation",
                accepted_statuses={404},
            )
            if response.status_code == 404:
                if time.monotonic() >= deadline:
                    raise MeasurementTransportError("等待远程证明超时。")
                time.sleep(max(0.25, min(3.0, deadline - time.monotonic())))
                continue
            value = response.json()
            if isinstance(value, dict) and value.get("schema") == "cad-measurement-attestation/v1":
                return value
            if time.monotonic() >= deadline:
                raise MeasurementTransportError("等待远程证明超时。")
            time.sleep(max(0.25, min(3.0, deadline - time.monotonic())))

    def online_status(self, attestation_id: str) -> Mapping[str, Any]:
        response = self._request("GET", f"/v1/attestations/{attestation_id}/status")
        value = response.json()
        if not isinstance(value, dict):
            raise MeasurementTransportError("在线证明状态响应不是 JSON 对象。")
        return value


@dataclass
class MeasurementRuntime:
    client: MeasurementClient
    trust_root: Mapping[str, Any]

    @classmethod
    def from_process_environment(cls) -> "MeasurementRuntime | None":
        base_url = str(os.environ.get(CONTROL_URL_ENV) or "").strip()
        token = str(os.environ.get(CONTROL_TOKEN_ENV) or "").strip()
        if not base_url or not token or not TRUST_ROOT_PATH.is_file():
            return None
        return cls(
            client=HttpMeasurementClient(base_url, token),
            trust_root=load_trust_root(TRUST_ROOT_PATH),
        )

    def online_status(self, attestation_id: str) -> Mapping[str, Any]:
        return self.client.online_status(attestation_id)


def _session_from_response(
    response: Mapping[str, Any],
    *,
    job: Mapping[str, Any],
    spec_sha256: str,
) -> dict[str, Any]:
    session_id = str(response.get("sessionId") or "")
    nonce = str(response.get("nonce") or "")
    upload_url = str(response.get("uploadUrl") or "")
    expires_at = str(response.get("expiresAt") or "")
    if (
        not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", session_id)
        or len(nonce) < 32
        or not upload_url
        or not expires_at
    ):
        raise MeasurementTransportError("验证会话响应缺少 sessionId、nonce 或 uploadUrl。")
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MeasurementTransportError("验证会话 expiresAt 不是有效 ISO-8601 时间。") from exc
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise MeasurementTransportError("验证会话 expired 或缺少时区。")
    return {
        "schema": "cad-evidence-session/v1",
        "sessionId": session_id,
        "jobId": str(job.get("id") or ""),
        "runId": str(job.get("id") or ""),
        "nonce": nonce,
        "specSha256": spec_sha256,
        "uploadUrl": upload_url,
        "expiresAt": expires_at,
    }


def prepare_measurement_session(
    job: dict[str, Any],
    client: MeasurementClient | None,
) -> dict[str, Any]:
    """@brief Agent 启动前锁定规格并创建一次性远程验证会话。"""
    try:
        locked = requested_dimension_spec(job)
    except (MeasurementTrustError, KeyError, TypeError, ValueError) as exc:
        return {
            "status": "blocked",
            "code": "spec_invalid",
            "reason": f"验收规格无效: {exc}",
        }
    if locked is None:
        return {"status": "not_applicable"}
    job["verificationSpec"] = locked
    required_kinds = (locked["spec"].get("artifacts") or {}).get("requiredKinds") or []
    if not required_kinds:
        return {
            "status": "review_required",
            "code": "unsupported_format",
            "reason": "首版只信任 STEP/IGES/BREP 尺寸证据；当前任务没有开放 B-Rep 验收产物。",
        }
    if locked.get("confirmationRequired"):
        return {
            "status": "blocked",
            "code": "confirmation_required",
            "reason": "尺寸或孔径数量存在歧义，必须先由用户确认 verificationSpec。",
        }
    if client is None:
        return {
            "status": "blocked",
            "code": "control_plane_missing",
            "reason": "缺少受保护测量控制面配置，生产尺寸任务不能启动。",
        }
    request = {
        "schema": "cad-evidence-session-request/v1",
        "jobId": str(job.get("id") or ""),
        "runId": str(job.get("id") or ""),
        "objective": str(job.get("objective") or job.get("detail") or ""),
        "spec": locked["spec"],
        "specSha256": locked["sha256"],
    }
    try:
        response = client.create_session(request)
        session = _session_from_response(response, job=job, spec_sha256=locked["sha256"])
    except (MeasurementTransportError, MeasurementTrustError, ValueError) as exc:
        return {"status": "blocked", "code": "session_creation_failed", "reason": str(exc)}
    # 上传能力只保留在本次 Worker 内存；队列文件只记录绑定信息。
    persisted_session = {key: value for key, value in session.items() if key != "uploadUrl"}
    job["verificationSession"] = persisted_session
    return {"status": "passed", "session": session}


def complete_measurement_session(
    *,
    job: dict[str, Any],
    ledger: dict[str, Any],
    allowed_roots: Sequence[Path],
    client: MeasurementClient | None,
    evidence_dir: Path,
    session: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """@brief 封装白名单 B-Rep、提交私有 Runner 并取回签名证明。"""
    locked = ledger.get("verificationSpec")
    session = session or ledger.get("verificationSession")
    if not isinstance(locked, dict) or not isinstance(session, dict):
        return {"status": "not_submitted"}
    if client is None:
        return {"status": "blocked", "reason": "缺少测量控制面客户端。"}
    temporary_path: Path | None = None
    try:
        bundle = create_measurement_bundle(
            ledger.get("artifacts") or [],
            allowed_roots=allowed_roots,
            session=session,
            spec_sha256=str(locked.get("sha256") or ""),
            output_path=evidence_dir / f"{session['sessionId']}.bundle.zip",
        )
        client.upload_bundle(str(session["uploadUrl"]), Path(bundle["path"]))
        client.finalize_session(str(session["sessionId"]))
        attestation = client.get_attestation(str(session["sessionId"]))
        attestation_path = evidence_dir / f"{session['sessionId']}.attestation.json"
        temporary_path = attestation_path.with_suffix(".json.tmp")
        temporary_path.write_text(
            json.dumps(attestation, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary_path.replace(attestation_path)
    except (
        MeasurementTransportError,
        MeasurementTrustError,
        KeyError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        return {"status": "blocked", "reason": str(exc)}
    return {
        "status": "submitted",
        "bundlePath": bundle["path"],
        "bundleSha256": bundle["sha256"],
        "attestationPath": str(attestation_path),
        "attestation": dict(attestation),
    }


__all__ = [
    "CONTROL_TOKEN_ENV",
    "CONTROL_URL_ENV",
    "TRUST_ROOT_PATH",
    "HttpMeasurementClient",
    "MeasurementClient",
    "MeasurementRuntime",
    "MeasurementTransportError",
    "complete_measurement_session",
    "prepare_measurement_session",
]
