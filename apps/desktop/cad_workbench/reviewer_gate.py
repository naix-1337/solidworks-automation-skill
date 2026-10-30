"""@brief 基于 Artifact Ledger 的交付物复核门禁。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Mapping

from .agent_contracts import safe_job_id
from .artifact_ledger import (
    DELIVERY_FILE_EXTENSIONS,
    artifact_requires_current_run_proof,
    sha256_file,
)
from .core import now_iso
from .measurement_trust import verify_measurement_evidence

KNOWN_FORMAT_EXTENSIONS = DELIVERY_FILE_EXTENSIONS


def review_dir(queue_dir: Path) -> Path:
    """@brief 返回 Reviewer Gate 报告目录。"""
    directory = Path(queue_dir) / "reviews"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def review_path_for(queue_dir: Path, job_id: Any) -> Path:
    """@brief 返回指定任务 Reviewer Gate 报告路径。"""
    return review_dir(queue_dir) / f"{safe_job_id(job_id)}.review.json"


def _read_file_sample(path: Path, limit: int = 1024 * 1024) -> bytes:
    """@brief 读取文件开头样本，避免为了格式检查加载超大 CAD 文件。"""
    with Path(path).open("rb") as handle:
        return handle.read(limit)


def _artifact_extension(kind: str, path: Path) -> str:
    """@brief 根据路径后缀或 kind 推断交付物格式。"""
    suffix = path.suffix.lower()
    if suffix:
        return suffix
    normalized = kind.lower().lstrip(".")
    return f".{normalized}" if f".{normalized}" in KNOWN_FORMAT_EXTENSIONS else ""


def _text_sample(sample: bytes) -> str:
    """@brief 把二进制样本宽松转为文本，供 STEP/DXF/STL 文本特征检查。"""
    return sample.decode("utf-8", errors="ignore").upper()


def validate_known_format(kind: str, path: Path) -> dict[str, Any] | None:
    """@brief 对常见 CAD 交付格式做轻量打开性/格式特征检查。"""
    extension = _artifact_extension(kind, path)
    if extension not in KNOWN_FORMAT_EXTENSIONS:
        return None

    sample = _read_file_sample(path)
    text = _text_sample(sample)
    check_id = f"artifact-format-{kind}"

    if extension in {".step", ".stp"}:
        valid = "ISO-10303-21" in text and "END-ISO-10303-21" in text
        return {
            "id": check_id,
            "severity": "P0",
            "status": "pass" if valid else "fail",
            "message": f"STEP 文件{'包含' if valid else '缺少'} ISO-10303-21 结构标记: {path}",
        }

    if extension == ".stl":
        ascii_valid = text.lstrip().startswith("SOLID") and "ENDSOLID" in text
        binary_valid = len(sample) >= 84 and not text.lstrip().startswith("SOLID")
        valid = ascii_valid or binary_valid
        return {
            "id": check_id,
            "severity": "P0",
            "status": "pass" if valid else "fail",
            "message": f"STL 文件{'具备' if valid else '缺少'}可识别的 ASCII/Binary 结构: {path}",
        }

    if extension == ".dxf":
        valid = "SECTION" in text and text.rstrip().endswith("EOF")
        return {
            "id": check_id,
            "severity": "P0",
            "status": "pass" if valid else "fail",
            "message": f"DXF 文件{'包含' if valid else '缺少'} SECTION/EOF 结构标记: {path}",
        }

    if extension == ".pdf":
        valid = sample.startswith(b"%PDF-")
        return {
            "id": check_id,
            "severity": "P0",
            "status": "pass" if valid else "fail",
            "message": f"PDF 文件{'包含' if valid else '缺少'} %PDF 文件头: {path}",
        }

    if extension == ".dwg":
        valid = sample.startswith(b"AC10")
        return {
            "id": check_id,
            "severity": "P0",
            "status": "pass" if valid else "fail",
            "message": f"DWG 文件{'包含' if valid else '缺少'} AutoCAD AC10 版本头: {path}",
        }

    if extension in {".sldprt", ".sldasm", ".slddrw"}:
        label = {
            ".sldprt": "SLDPRT",
            ".sldasm": "SLDASM",
            ".slddrw": "SLDDRW",
        }[extension]
        return {
            "id": check_id,
            "severity": "P1",
            "status": "warning",
            "message": f"{label} 为专有格式，当前仅完成文件级记录，后续需由 SolidWorks 打开复核: {path}",
        }

    return None


def _spec_conformance_checks(
    ledger: dict[str, Any],
    artifacts: list[dict[str, Any]],
    *,
    trust_root: Mapping[str, Any] | None,
    online_status: Callable[[str], Mapping[str, Any] | None] | None,
    measurement_verifier: Callable[..., dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """@brief 只消费锁定规格、受信 B-Rep 测量和在线 Ed25519 证明。"""
    verifier = measurement_verifier or verify_measurement_evidence
    try:
        result = verifier(
            ledger,
            artifacts,
            trust_root=trust_root,
            online_status=online_status,
        )
    except Exception as exc:  # noqa: BLE001 - 信任链异常必须安全阻断
        return [
            {
                "id": "measurement-trust-verifier",
                "severity": "P0",
                "status": "blocked",
                "message": f"测量信任链验证异常: {type(exc).__name__}: {exc}",
            }
        ]
    if result.get("status") == "not_applicable":
        return []
    checks: list[dict[str, Any]] = []
    for check in result.get("checks", []):
        if not isinstance(check, dict):
            continue
        status = "warning" if check.get("status") == "review_required" else check.get("status", "blocked")
        checks.append(
            {
                **dict(check),
                "status": status,
                "severity": "P0" if status in {"fail", "blocked"} else "P1",
            }
        )
    return checks


def evaluate_ledger(
    ledger: dict[str, Any],
    *,
    trust_root: Mapping[str, Any] | None = None,
    online_status: Callable[[str], Mapping[str, Any] | None] | None = None,
    measurement_verifier: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """@brief 根据账本内容生成交付物复核结论。"""
    artifacts = ledger.get("artifacts") if isinstance(ledger.get("artifacts"), list) else []
    checks: list[dict[str, Any]] = []
    delivery_artifacts = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict) and str(artifact.get("kind") or "") != "codex_output"
    ]
    checks.extend(
        _spec_conformance_checks(
            ledger,
            delivery_artifacts,
            trust_root=trust_root,
            online_status=online_status,
            measurement_verifier=measurement_verifier,
        )
    )

    executor = str(ledger.get("executor") or "mock")
    production_executor = executor != "mock"
    verification = ledger.get("verification") if isinstance(ledger.get("verification"), list) else []
    if ledger.get("executor") == "codex" and not verification:
        checks.append(
            {
                "id": "executor-verification-present",
                "severity": "P2",
                "status": "pass",
                "message": "执行器未返回验证记录；Agent 自报验证仅作说明，不参与最终判定。",
            }
        )
    for index, item in enumerate(verification):
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "skipped")
        checks.append(
            {
                "id": f"executor-verification-{index}",
                "severity": "P2",
                "status": "pass",
                "message": (
                    f"Agent 自报验证 {status}（仅展示，不参与最终门禁）: "
                    f"{item.get('command') or '未命名检查'}；{item.get('note') or ''}"
                ),
            }
        )

    risks = ledger.get("risks") if isinstance(ledger.get("risks"), list) else []
    if risks:
        checks.append(
            {
                "id": "executor-residual-risks",
                "severity": "P1",
                "status": "warning",
                "message": "执行器报告残余风险: " + "；".join(str(item) for item in risks),
            }
        )

    required_outputs = ledger.get("requiredOutputs")
    required_output_values = required_outputs if isinstance(required_outputs, list) else []
    expected_output = " ".join(
        [
            str(ledger.get("expectedOutput") or ""),
            *(str(item) for item in required_output_values),
        ]
    )
    expected_output_upper = expected_output.upper()
    expected_groups: list[tuple[str, set[str]]] = []
    format_groups = [
        ("SLDPRT", {".sldprt"}),
        ("SLDASM", {".sldasm"}),
        ("SLDDRW", {".slddrw"}),
        ("STEP", {".step", ".stp"}),
        ("IGES", {".iges", ".igs"}),
        ("BREP", {".brep"}),
        ("STL", {".stl"}),
        ("OBJ", {".obj"}),
        ("GLB", {".glb"}),
        ("GLTF", {".gltf"}),
        ("DWG", {".dwg"}),
        ("DXF", {".dxf"}),
        ("PDF", {".pdf"}),
        ("PNG", {".png"}),
        ("SVG", {".svg"}),
    ]
    for label, extensions in format_groups:
        if label in expected_output_upper:
            expected_groups.append((label, extensions))

    freshness_artifacts = [
        artifact
        for artifact in delivery_artifacts
        if artifact_requires_current_run_proof(artifact)
    ]
    if production_executor and (freshness_artifacts or expected_groups or ledger.get("localCadAutomation") is True):
        stale = [
            artifact for artifact in freshness_artifacts
            if artifact.get("producedThisRun") is False
        ]
        unknown = [
            artifact for artifact in freshness_artifacts
            if artifact.get("producedThisRun") is not True
            and artifact.get("producedThisRun") is not False
        ]
        if stale:
            stale_paths = "；".join(str(item.get("path")) for item in stale)
            checks.append({
                "id": "artifact-current-run",
                "severity": "P0",
                "status": "fail",
                "message": f"发现本轮未变化或复用的交付文件: {stale_paths}",
            })
        elif unknown or not freshness_artifacts:
            unknown_paths = "；".join(str(item.get("path")) for item in unknown)
            checks.append({
                "id": "artifact-current-run",
                "severity": "P1",
                "status": "warning",
                "message": (
                    f"无法确认以下文件是否由本轮生成，需要人工复核: {unknown_paths}"
                    if unknown_paths
                    else "缺少可核验的本轮交付文件基线，需要人工复核。"
                ),
            })
        else:
            checks.append({
                "id": "artifact-current-run",
                "severity": "P2",
                "status": "pass",
                "message": "全部交付文件均已确认由本轮新增或修改。",
            })

    for label, expected_extensions in expected_groups:
        candidates = []
        for artifact in delivery_artifacts:
            if Path(str(artifact.get("path") or "")).suffix.lower() not in expected_extensions:
                continue
            if artifact.get("exists") is not True:
                continue
            candidates.append(artifact)
        matching = [
            artifact for artifact in candidates
            if not production_executor or artifact.get("producedThisRun") is True
        ]
        stale_candidates = [
            artifact for artifact in candidates
            if production_executor and artifact.get("producedThisRun") is False
        ]
        unknown_candidates = [
            artifact for artifact in candidates
            if production_executor
            and artifact.get("producedThisRun") is not True
            and artifact.get("producedThisRun") is not False
        ]
        if matching:
            check_status = "pass"
            severity = "P0"
            message = f"已找到本轮生成的 {label} 交付物，共 {len(matching)} 个。"
        elif unknown_candidates and not stale_candidates:
            check_status = "warning"
            severity = "P1"
            message = f"存在 {label} 文件，但无法确认是否由本轮生成，需要人工复核。"
        else:
            check_status = "fail"
            severity = "P0"
            message = f"期望输出包含 {label}，但没有找到本轮生成的对应文件；AI JSON 回执或旧文件不能代替交付物。"
        checks.append(
            {
                "id": f"expected-cad-deliverable-{label.lower()}",
                "severity": severity,
                "status": check_status,
                "message": message,
            }
        )
    current_run_cad = [
        artifact
        for artifact in delivery_artifacts
        if Path(str(artifact.get("path") or "")).suffix.lower() in DELIVERY_FILE_EXTENSIONS
        and artifact.get("exists") is True
        and (not production_executor or artifact.get("producedThisRun") is True)
    ]
    target = str(ledger.get("target") or "")
    expects_non_cad = "调研报告" in expected_output or "Skills" in target or "规范" in target
    if not expected_groups and ledger.get("localCadAutomation") is True and not expects_non_cad and not current_run_cad:
        checks.append(
            {
                "id": "cad-deliverable-not-declared",
                "severity": "P1",
                "status": "warning",
                "message": "本轮允许本机 CAD 自动化，但没有本轮生成的 CAD/图纸文件；TXT、Markdown 和 AI 回执不能作为 CAD 交付物。",
            }
        )

    if not artifacts:
        checks.append(
            {
                "id": "artifact-present",
                "severity": "P1",
                "status": "warning",
                "message": "任务未声明任何交付物，当前只能确认流程完成，不能确认制造文件齐全。",
            }
        )

    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            continue
        kind = str(artifact.get("kind") or f"artifact_{index}")
        if artifact.get("exists") is not True:
            checks.append(
                {
                    "id": f"artifact-exists-{kind}",
                    "severity": "P0",
                    "status": "fail",
                    "message": f"交付物不存在: {artifact.get('path')}",
                }
            )
            continue
        if artifact.get("isDirectory") is True:
            checks.append(
                {
                    "id": f"artifact-directory-{kind}",
                    "severity": "P2",
                    "status": "warning",
                    "message": f"交付物是目录，当前只记录路径，未递归校验目录内容: {artifact.get('path')}",
                }
            )
            continue
        size_bytes = int(artifact.get("sizeBytes") or 0)
        if size_bytes <= 0:
            checks.append(
                {
                    "id": f"artifact-nonempty-{kind}",
                    "severity": "P0",
                    "status": "fail",
                    "message": f"交付物为空文件: {artifact.get('path')}",
                }
            )
        elif not artifact.get("sha256"):
            checks.append(
                {
                    "id": f"artifact-hash-{kind}",
                    "severity": "P1",
                    "status": "warning",
                    "message": f"交付物缺少 SHA-256: {artifact.get('path')}",
                }
            )
        else:
            path = Path(str(artifact.get("path") or ""))
            try:
                actual_size = path.stat().st_size
                actual_sha256 = sha256_file(path)
            except OSError as exc:
                checks.append(
                    {
                        "id": f"artifact-content-{kind}",
                        "severity": "P0",
                        "status": "fail",
                        "message": f"交付物无法重新读取: {path}: {exc}",
                    }
                )
                continue
            if actual_size != size_bytes or actual_sha256 != artifact.get("sha256"):
                checks.append(
                    {
                        "id": f"artifact-content-{kind}",
                        "severity": "P0",
                        "status": "fail",
                        "message": f"交付物在账本记录后发生变化: {path}",
                    }
                )
                continue
            checks.append(
                {
                    "id": f"artifact-file-{kind}",
                    "severity": "P2",
                    "status": "pass",
                    "message": f"交付物存在且已记录 hash: {artifact.get('path')}",
                }
            )
            format_check = validate_known_format(kind, Path(str(artifact.get("path"))))
            if format_check:
                checks.append(format_check)

    statuses = {check["status"] for check in checks}
    overall = (
        "blocked"
        if "blocked" in statuses
        else "fail"
        if "fail" in statuses
        else "warning"
        if "warning" in statuses
        else "pass"
    )
    return {
        "schemaVersion": "1.0",
        "jobId": ledger.get("jobId"),
        "runId": ledger.get("runId"),
        "status": overall,
        "reviewedAt": now_iso(),
        "artifactCount": len(artifacts),
        "checks": checks,
    }


def write_reviewer_gate(
    queue_dir: Path,
    ledger: dict[str, Any],
    *,
    trust_root: Mapping[str, Any] | None = None,
    online_status: Callable[[str], Mapping[str, Any] | None] | None = None,
    measurement_verifier: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """@brief 写入 Reviewer Gate 报告并返回报告对象。"""
    review = evaluate_ledger(
        ledger,
        trust_root=trust_root,
        online_status=online_status,
        measurement_verifier=measurement_verifier,
    )
    path = review_path_for(queue_dir, ledger.get("jobId"))
    path.write_text(json.dumps(review, ensure_ascii=False, indent=2), encoding="utf-8")
    review["reviewPath"] = str(path)
    return review
