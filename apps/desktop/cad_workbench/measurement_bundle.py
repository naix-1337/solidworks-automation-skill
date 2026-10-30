"""@brief 受控 CAD B-Rep 证明包的封装与安全解包。"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import zipfile
from pathlib import Path
from typing import Any, Iterable, Mapping

from .measurement_trust import BREP_EXTENSIONS, MeasurementTrustError, canonical_sha256, file_sha256


BUNDLE_SCHEMA = "cad-evidence-bundle/v1"
MANIFEST_NAME = "manifest.json"
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_BYTES = 512 * 1024 * 1024


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _validate_source(path: Path, allowed_roots: Iterable[Path]) -> Path:
    if path.suffix.lower() not in BREP_EXTENSIONS:
        raise MeasurementTrustError(f"证明包只接受 STEP/IGES/BREP: {path}")
    if path.is_symlink() or not path.is_file():
        raise MeasurementTrustError(f"证明包源文件必须是普通文件且不能是符号链接: {path}")
    stat_result = path.stat()
    if stat_result.st_nlink != 1:
        raise MeasurementTrustError(f"证明包拒绝硬链接文件: {path}")
    if stat_result.st_size <= 0 or stat_result.st_size > MAX_FILE_BYTES:
        raise MeasurementTrustError(f"证明包源文件大小无效: {path}")
    resolved = path.resolve()
    if not any(_is_relative_to(resolved, root.resolve()) for root in allowed_roots):
        raise MeasurementTrustError(f"证明包源文件不在允许目录内: {path}")
    return resolved


def _write_bundle_member(bundle: zipfile.ZipFile, source: Path, target: str) -> None:
    info = zipfile.ZipInfo(target)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.date_time = (1980, 1, 1, 0, 0, 0)
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    with source.open("rb") as source_handle, bundle.open(info, "w") as target_handle:
        while True:
            chunk = source_handle.read(1024 * 1024)
            if not chunk:
                break
            target_handle.write(chunk)


def create_measurement_bundle(
    artifacts: Iterable[Mapping[str, Any]],
    *,
    allowed_roots: Iterable[Path],
    session: Mapping[str, Any],
    spec_sha256: str,
    output_path: str | Path,
) -> dict[str, Any]:
    """@brief 将本轮主 B-Rep 产物封装为无路径逃逸的一次性证明包。"""
    roots = [Path(root) for root in allowed_roots]
    if not roots:
        raise MeasurementTrustError("证明包缺少允许目录基线。")
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    seen_sources: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            continue
        raw_path = Path(str(artifact.get("path") or ""))
        if raw_path.suffix.lower() not in BREP_EXTENSIONS:
            continue
        if artifact.get("exists") is not True or artifact.get("producedThisRun") is not True:
            continue
        source = _validate_source(raw_path, roots)
        key = os.path.normcase(str(source))
        if key in seen_sources:
            continue
        seen_sources.add(key)
        size_bytes = source.stat().st_size
        total_bytes += size_bytes
        if total_bytes > MAX_TOTAL_BYTES:
            raise MeasurementTrustError("证明包总大小超过 512 MiB。")
        index = len(entries) + 1
        extension = source.suffix.lower()
        bundle_name = f"artifacts/artifact-{index:03d}{extension}"
        entries.append(
            {
                "artifactId": f"artifact-{index:03d}",
                "kind": "step"
                if extension in {".step", ".stp"}
                else "iges"
                if extension in {".iges", ".igs"}
                else "brep",
                "bundlePath": bundle_name,
                "sourcePath": str(source),
                "sha256": file_sha256(source),
                "sizeBytes": size_bytes,
            }
        )
    if not entries:
        raise MeasurementTrustError("没有可封装的 STEP/IGES/BREP 产物。")
    manifest = {
        "schema": BUNDLE_SCHEMA,
        "sessionId": str(session.get("sessionId") or ""),
        "jobId": str(session.get("jobId") or ""),
        "runId": str(session.get("runId") or ""),
        "nonce": str(session.get("nonce") or ""),
        "specSha256": spec_sha256,
        "artifacts": [
            {key: value for key, value in item.items() if key != "sourcePath"}
            for item in entries
        ],
    }
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.unlink(missing_ok=True)
    try:
        with zipfile.ZipFile(temporary, "w", allowZip64=True) as bundle:
            for item in entries:
                _write_bundle_member(bundle, Path(item["sourcePath"]), str(item["bundlePath"]))
            info = zipfile.ZipInfo(MANIFEST_NAME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            bundle.writestr(
                info,
                json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
            )
        if temporary.stat().st_size > MAX_BUNDLE_BYTES:
            raise MeasurementTrustError("证明包压缩后大小超过 512 MiB。")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "path": str(target),
        "sha256": file_sha256(target),
        "sizeBytes": target.stat().st_size,
        "manifest": manifest,
        "manifestSha256": canonical_sha256(manifest),
    }


def _safe_member(info: zipfile.ZipInfo) -> bool:
    name = info.filename
    if not name or name.startswith("/") or "\\" in name or ".." in Path(name).parts:
        return False
    mode = (info.external_attr >> 16) & 0o170000
    return mode in {0, stat.S_IFREG}


def open_measurement_bundle(path: str | Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    """@brief 验证 ZIP 路径、成员类型、大小和哈希，返回内存中的受控成员。"""
    source = Path(path)
    if not source.is_file() or source.is_symlink() or source.stat().st_size > MAX_BUNDLE_BYTES:
        raise MeasurementTrustError("证明包不存在、是链接或超过 512 MiB。")
    members: dict[str, bytes] = {}
    seen: set[str] = set()
    total = 0
    try:
        with zipfile.ZipFile(source, "r", allowZip64=True) as bundle:
            for info in bundle.infolist():
                if not _safe_member(info):
                    raise MeasurementTrustError(f"证明包含非法 ZIP 成员: {info.filename}")
                if info.filename in seen:
                    raise MeasurementTrustError(f"证明包含重复 ZIP 成员: {info.filename}")
                seen.add(info.filename)
                if info.file_size > MAX_FILE_BYTES:
                    raise MeasurementTrustError(f"证明包成员过大: {info.filename}")
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise MeasurementTrustError("证明包解压后总大小超过 512 MiB。")
                if info.is_dir():
                    raise MeasurementTrustError("证明包不允许目录条目。")
                members[info.filename] = bundle.read(info)
    except zipfile.BadZipFile as exc:
        raise MeasurementTrustError("证明包不是有效 ZIP。") from exc
    if MANIFEST_NAME not in members:
        raise MeasurementTrustError("证明包缺少 manifest.json。")
    try:
        manifest = json.loads(members[MANIFEST_NAME].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MeasurementTrustError("证明包 manifest 无法解析。") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != BUNDLE_SCHEMA:
        raise MeasurementTrustError("证明包 manifest schema 不受支持。")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise MeasurementTrustError("证明包 manifest 没有产物。")
    manifest_paths: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise MeasurementTrustError("证明包产物条目格式错误。")
        member_path = str(item.get("bundlePath") or "")
        if (
            not member_path.startswith("artifacts/")
            or member_path.startswith("/")
            or ".." in Path(member_path).parts
            or Path(member_path).suffix.lower() not in BREP_EXTENSIONS
        ):
            raise MeasurementTrustError("证明包产物路径非法。")
        if member_path in manifest_paths or member_path not in members:
            raise MeasurementTrustError("证明包产物缺失或重复。")
        manifest_paths.add(member_path)
        raw = members[member_path]
        if len(raw) != int(item.get("sizeBytes") or -1):
            raise MeasurementTrustError(f"证明包产物大小不一致: {member_path}")
        if hashlib.sha256(raw).hexdigest() != item.get("sha256"):
            raise MeasurementTrustError(f"证明包产物哈希不一致: {member_path}")
    return manifest, members


__all__ = [
    "BUNDLE_SCHEMA",
    "MANIFEST_NAME",
    "MAX_BUNDLE_BYTES",
    "MAX_FILE_BYTES",
    "MAX_TOTAL_BYTES",
    "create_measurement_bundle",
    "open_measurement_bundle",
]
