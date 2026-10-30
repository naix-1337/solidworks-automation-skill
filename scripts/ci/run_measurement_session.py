"""@brief 受保护 Runner 拉取一次性会话、独立验证并回传签名证明。"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.cad_evidence_verifier import (  # noqa: E402
    load_verification_session,
    verify_bundle,
)


MAX_BUNDLE_BYTES = 512 * 1024 * 1024


def _required_environment(name: str) -> str:
    value = str(os.environ.get(name) or "").strip()
    if not value:
        raise RuntimeError(f"缺少环境变量 {name}")
    return value


def _client() -> tuple[str, dict[str, str]]:
    base_url = _required_environment("CAD_EVIDENCE_CONTROL_URL").rstrip("/")
    token = _required_environment("CAD_EVIDENCE_CONTROL_TOKEN")
    parsed = urlparse(base_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise RuntimeError("CAD_EVIDENCE_CONTROL_URL 必须使用 HTTPS")
    return base_url, {"Authorization": f"Bearer {token}", "Accept": "application/json"}


def _download(url: str, headers: dict[str, str], target: Path) -> None:
    with httpx.Client(timeout=300.0, follow_redirects=False, trust_env=False) as client:
        with client.stream("GET", url, headers=headers) as response:
            if response.status_code != 200:
                raise RuntimeError(f"下载证明包失败: HTTP {response.status_code}")
            total = 0
            with target.open("wb") as handle:
                for chunk in response.iter_bytes():
                    total += len(chunk)
                    if total > MAX_BUNDLE_BYTES:
                        raise RuntimeError("证明包超过 512 MiB")
                    handle.write(chunk)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="处理一个受保护 CAD 尺寸验证会话")
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", args.session_id):
        raise RuntimeError("session-id 格式非法")
    base_url, headers = _client()
    control_url = f"{base_url}/v1/verification-sessions/{args.session_id}"
    with httpx.Client(timeout=60.0, follow_redirects=False, trust_env=False) as client:
        response = client.get(control_url, headers=headers)
    if response.status_code != 200:
        raise RuntimeError(f"读取验证会话失败: HTTP {response.status_code}")
    session_payload = response.json()
    if not isinstance(session_payload, dict):
        raise RuntimeError("验证会话响应不是 JSON 对象")

    workflow_repository = _required_environment("GITHUB_REPOSITORY")
    workflow_ref = _required_environment("GITHUB_REF")
    workflow_sha = _required_environment("GITHUB_SHA")
    runner_id = _required_environment("RUNNER_NAME")
    with tempfile.TemporaryDirectory(prefix="cad-evidence-session-") as temporary:
        root = Path(temporary)
        session_path = root / "session.json"
        session_path.write_text(
            json.dumps(session_payload, ensure_ascii=False),
            encoding="utf-8",
        )
        session = load_verification_session(session_path)
        if session["sessionId"] != args.session_id:
            raise RuntimeError("控制面返回了其他会话")
        bundle_path = root / "bundle.zip"
        _download(f"{control_url}/bundle", headers, bundle_path)
        private_key = None
        try:
            from scripts.cad_evidence_verifier import _load_private_key

            private_key = _load_private_key(args.private_key)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"加载 Ed25519 私钥失败: {exc}") from exc
        attestation = verify_bundle(
            bundle_path=bundle_path,
            session=session,
            private_key=private_key,
            workflow_repository=workflow_repository,
            workflow_ref=workflow_ref,
            workflow_sha=workflow_sha,
            runner_id=runner_id,
            argv=sys.argv,
        )
        response = httpx.put(
            f"{control_url}/attestation",
            headers={**headers, "Content-Type": "application/json"},
            content=json.dumps(attestation, ensure_ascii=False).encode("utf-8"),
            timeout=60.0,
            follow_redirects=False,
            trust_env=False,
        )
        if response.status_code < 200 or response.status_code >= 300:
            raise RuntimeError(f"回传签名证明失败: HTTP {response.status_code}")
    print(json.dumps({"sessionId": args.session_id, "decision": attestation["decision"]}, ensure_ascii=False))
    return 0 if attestation["decision"] in {"pass", "fail"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
