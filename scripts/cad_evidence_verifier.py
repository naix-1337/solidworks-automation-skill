"""@brief 受保护 Runner 上的独立 CAD B-Rep 尺寸验证与 Ed25519 签发器。

该脚本只消费控制面下发的 session JSON 和受控证明包。它不信任包内 Agent
测量报告，也不执行包中的任何代码。STEP/IGES/BREP 必须由本机 OCCT/OCP
重新读取并生成测量结果。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from importlib import metadata

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from apps.desktop.cad_workbench.measurement_bundle import open_measurement_bundle  # noqa: E402
from apps.desktop.cad_workbench.measurement_trust import (  # noqa: E402
    ATTESTATION_DOMAIN,
    ATTESTATION_MAX_TTL,
    ATTESTATION_SCHEMA,
    MeasurementTrustError,
    canonical_json_bytes,
    canonical_sha256,
    evaluate_measurement_spec,
    file_sha256,
    public_key_id,
    sign_document,
    validate_contract,
)
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _process_created_at(process_id: int) -> str:
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        class FileTime(ctypes.Structure):
            _fields_ = [
                ("dwLowDateTime", wintypes.DWORD),
                ("dwHighDateTime", wintypes.DWORD),
            ]

        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
            ctypes.POINTER(FileTime),
        ]
        kernel32.GetProcessTimes.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel32.OpenProcess(0x1000, False, process_id)
        if not handle:
            raise MeasurementTrustError("无法打开当前验证器进程句柄。")
        try:
            creation = FileTime()
            exit_time = FileTime()
            kernel_time = FileTime()
            user_time = FileTime()
            if not kernel32.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_time),
                ctypes.byref(kernel_time),
                ctypes.byref(user_time),
            ):
                raise MeasurementTrustError("无法读取验证器进程创建时间。")
            ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
            epoch = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks / 10)
            return epoch.isoformat()
        finally:
            kernel32.CloseHandle(handle)
    stat_result = Path(f"/proc/{process_id}/stat").read_text(encoding="utf-8")
    start_ticks = int(stat_result.split()[21])
    boot_time = next(
        float(line.split()[1])
        for line in Path("/proc/stat").read_text(encoding="utf-8").splitlines()
        if line.startswith("btime ")
    )
    return _iso(datetime.fromtimestamp(boot_time + start_ticks / os.sysconf("SC_CLK_TCK"), timezone.utc))


def _toolkit_sha256() -> str:
    digest = hashlib.sha256()
    for path in (
        Path(__file__).resolve(),
        ROOT / "apps/desktop/cad_workbench/measurement_trust.py",
        ROOT / "apps/desktop/cad_workbench/measurement_bundle.py",
        ROOT / "requirements-evidence-verifier.txt",
    ):
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _dependency_versions_sha256() -> str:
    names = (
        "cadquery-ocp",
        "cadquery-ocp-proxy",
        "cryptography",
        "httpx",
        "jsonschema",
        "numpy",
        "vtk",
    )
    versions: dict[str, str | None] = {}
    for name in names:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = None
    return canonical_sha256(versions)


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise MeasurementTrustError("签发密钥不是 Ed25519 私钥。")
    return key


def _step_unit_to_mm(path: Path) -> float:
    with path.open("rb") as handle:
        head = handle.read(4 * 1024 * 1024)
        handle.seek(max(0, path.stat().st_size - 1024 * 1024))
        tail = handle.read()
    text = (head + b"\n" + tail).decode("utf-8", errors="ignore").upper()
    if re.search(r"SI_UNIT\s*\(\s*'?MILLI'?\s*,\s*'?METRE'?\s*\)", text) or re.search(
        r"SI_UNIT\s*\(\s*\.MILLI\.\s*,\s*\.METRE\.\s*\)",
        text,
    ):
        return 1.0
    if re.search(r"SI_UNIT\s*\(\s*\.CENTI\.\s*,\s*\.METRE\.\s*\)", text):
        return 10.0
    if re.search(r"SI_UNIT\s*\(\s*\$?\s*,\s*\.METRE\.\s*\)", text):
        return 1000.0
    if "CONVERSION_BASED_UNIT('INCH'" in text or "CONVERSION_BASED_UNIT('IN'" in text:
        return 25.4
    if "CONVERSION_BASED_UNIT('FOOT'" in text or "CONVERSION_BASED_UNIT('FT'" in text:
        return 304.8
    raise MeasurementTrustError("STEP 文件没有可识别的毫米/米/英寸长度单位。")


def _iges_unit_to_mm(path: Path) -> float:
    text = path.read_text(encoding="utf-8", errors="ignore")[: 256 * 1024].upper()
    global_lines = "\n".join(
        line for line in text.splitlines() if line.rstrip().endswith(tuple("G0123456789"))
    )
    match = re.search(
        r"\b\d+H(MM|MILLIMET(?:ER|RE)|CM|CENTIMET(?:ER|RE)|M|MET(?:ER|RE)|IN|INCH|FT|FOOT|KM|UM|MICRON)\b",
        global_lines,
    )
    if not match:
        raise MeasurementTrustError("IGES 文件没有可识别的长度单位名称。")
    unit = match.group(1)
    if unit in {"MM", "MILLIMETER", "MILLIMETRE"}:
        return 1.0
    if unit in {"CM", "CENTIMETER", "CENTIMETRE"}:
        return 10.0
    if unit in {"M", "METER", "METRE"}:
        return 1000.0
    if unit in {"IN", "INCH"}:
        return 25.4
    if unit in {"FT", "FOOT"}:
        return 304.8
    if unit == "KM":
        return 1_000_000.0
    if unit in {"UM", "MICRON"}:
        return 0.001
    raise MeasurementTrustError(f"IGES 单位不受支持: {unit}")


def _load_shape(path: Path) -> tuple[Any, float]:
    extension = path.suffix.lower()
    if extension in {".step", ".stp"}:
        from OCP.IFSelect import IFSelect_RetDone
        from OCP.STEPControl import STEPControl_Reader

        reader = STEPControl_Reader()
        if reader.ReadFile(str(path)) != IFSelect_RetDone:
            raise MeasurementTrustError(f"STEP 读取失败: {path.name}")
        if reader.TransferRoots() <= 0:
            raise MeasurementTrustError(f"STEP 没有可转移实体: {path.name}")
        shape = reader.OneShape()
        unit_to_mm = _step_unit_to_mm(path)
    elif extension in {".iges", ".igs"}:
        from OCP.IFSelect import IFSelect_RetDone
        from OCP.IGESControl import IGESControl_Reader

        reader = IGESControl_Reader()
        if reader.ReadFile(str(path)) != IFSelect_RetDone:
            raise MeasurementTrustError(f"IGES 读取失败: {path.name}")
        if reader.TransferRoots() <= 0:
            raise MeasurementTrustError(f"IGES 没有可转移实体: {path.name}")
        shape = reader.OneShape()
        unit_to_mm = _iges_unit_to_mm(path)
    elif extension == ".brep":
        from OCP.BRep import BRep_Builder
        from OCP.BRepTools import BRepTools
        from OCP.TopoDS import TopoDS_Shape

        shape = TopoDS_Shape()
        if not BRepTools.Read_s(shape, str(path), BRep_Builder()):
            raise MeasurementTrustError(f"BREP 读取失败: {path.name}")
        # OCCT BREP 不保存物理单位；本项目只接受按毫米坐标写出的 BREP。
        unit_to_mm = 1.0
    else:
        raise MeasurementTrustError(f"不支持的 B-Rep 扩展名: {extension}")
    if shape.IsNull():
        raise MeasurementTrustError(f"B-Rep 形状为空: {path.name}")
    return shape, unit_to_mm


def _shape_measurement(shape, unit_to_mm: float = 1.0) -> dict[str, Any]:
    from OCP.BRepAdaptor import BRepAdaptor_Surface
    from OCP.BRepBndLib import BRepBndLib
    from OCP.BRepCheck import BRepCheck_Analyzer
    from OCP.BRepGProp import BRepGProp
    from OCP.BRepTools import BRepTools
    from OCP.Bnd import Bnd_Box
    from OCP.GProp import GProp_GProps
    from OCP.GeomAbs import GeomAbs_Cylinder
    from OCP.TopAbs import TopAbs_EDGE, TopAbs_FACE, TopAbs_REVERSED, TopAbs_SOLID
    from OCP.TopExp import TopExp_Explorer
    from OCP.TopoDS import TopoDS
    from OCP.gp import gp_Pnt, gp_Vec

    def count(kind) -> int:
        explorer = TopExp_Explorer(shape, kind)
        total = 0
        while explorer.More():
            total += 1
            explorer.Next()
        return total

    valid = bool(BRepCheck_Analyzer(shape).IsValid())
    solid_count = count(TopAbs_SOLID)
    bounds = Bnd_Box()
    BRepBndLib.Add_s(shape, bounds)
    xmin, ymin, zmin, xmax, ymax, zmax = (float(value) for value in bounds.Get())
    if not all(value == value and abs(value) != float("inf") for value in (xmin, ymin, zmin, xmax, ymax, zmax)):
        raise MeasurementTrustError("B-Rep 包围盒包含非有限数值。")
    envelope_um = [
        int(round((xmax - xmin) * unit_to_mm * 1000.0)),
        int(round((ymax - ymin) * unit_to_mm * 1000.0)),
        int(round((zmax - zmin) * unit_to_mm * 1000.0)),
    ]
    if any(value <= 0 for value in envelope_um):
        raise MeasurementTrustError("B-Rep 包围盒退化。")

    volume_props = GProp_GProps()
    surface_props = GProp_GProps()
    BRepGProp.VolumeProperties_s(shape, volume_props)
    BRepGProp.SurfaceProperties_s(shape, surface_props)
    volume_um3 = int(round(float(volume_props.Mass()) * (unit_to_mm ** 3) * 1_000_000_000.0))
    surface_um2 = int(round(float(surface_props.Mass()) * (unit_to_mm ** 2) * 1_000_000.0))
    if solid_count < 1 or volume_um3 <= 0:
        raise MeasurementTrustError("B-Rep 没有有效正体积实体。")

    cylinders: list[dict[str, Any]] = []
    faces: list[dict[str, Any]] = []
    face_explorer = TopExp_Explorer(shape, TopAbs_FACE)
    while face_explorer.More():
        face = TopoDS.Face_s(face_explorer.Current())
        adaptor = BRepAdaptor_Surface(face, True)
        face_props = GProp_GProps()
        BRepGProp.SurfaceProperties_s(face, face_props)
        face_center = face_props.CentreOfMass()
        face_record = {
            "surfaceType": int(adaptor.GetType()),
            "orientation": int(face.Orientation()),
            "areaUm2": int(
                round(float(face_props.Mass()) * (unit_to_mm ** 2) * 1_000_000.0)
            ),
            "centerUm": [
                int(round(float(face_center.X()) * unit_to_mm * 1000.0)),
                int(round(float(face_center.Y()) * unit_to_mm * 1000.0)),
                int(round(float(face_center.Z()) * unit_to_mm * 1000.0)),
            ],
        }
        if adaptor.GetType() == GeomAbs_Cylinder:
            u1, u2, v1, v2 = BRepTools.UVBounds_s(face)
            point = gp_Pnt()
            du = gp_Vec()
            dv = gp_Vec()
            adaptor.D1((u1 + u2) * 0.5, (v1 + v2) * 0.5, point, du, dv)
            normal = du.Crossed(dv)
            if normal.Magnitude() <= 1e-12:
                face_explorer.Next()
                continue
            normal.Normalize()
            if face.Orientation() == TopAbs_REVERSED:
                normal.Reverse()
            cylinder = adaptor.Cylinder()
            axis = cylinder.Axis()
            location = axis.Location()
            direction = axis.Direction()
            radial = (
                point.X() - location.X(),
                point.Y() - location.Y(),
                point.Z() - location.Z(),
            )
            axial = (
                radial[0] * direction.X()
                + radial[1] * direction.Y()
                + radial[2] * direction.Z()
            )
            radial = (
                radial[0] - axial * direction.X(),
                radial[1] - axial * direction.Y(),
                radial[2] - axial * direction.Z(),
            )
            radial_dot_normal = (
                radial[0] * normal.X()
                + radial[1] * normal.Y()
                + radial[2] * normal.Z()
            )
            cylinders.append(
                {
                    "diameterUm": int(
                        round(float(cylinder.Radius()) * 2.0 * unit_to_mm * 1000.0)
                    ),
                    "originUm": [
                        int(round(float(location.X()) * unit_to_mm * 1000.0)),
                        int(round(float(location.Y()) * unit_to_mm * 1000.0)),
                        int(round(float(location.Z()) * unit_to_mm * 1000.0)),
                    ],
                    "axisPpm": [
                        int(round(float(direction.X()) * 1_000_000.0)),
                        int(round(float(direction.Y()) * 1_000_000.0)),
                        int(round(float(direction.Z()) * 1_000_000.0)),
                    ],
                    "internal": radial_dot_normal < -1e-9,
                }
            )
            face_record["cylinder"] = cylinders[-1]
        faces.append(face_record)
        face_explorer.Next()

    from OCP.BRepAdaptor import BRepAdaptor_Curve

    edges: list[dict[str, Any]] = []
    edge_explorer = TopExp_Explorer(shape, TopAbs_EDGE)
    while edge_explorer.More():
        edge = TopoDS.Edge_s(edge_explorer.Current())
        edge_props = GProp_GProps()
        BRepGProp.LinearProperties_s(edge, edge_props)
        edge_center = edge_props.CentreOfMass()
        edges.append(
            {
                "curveType": int(BRepAdaptor_Curve(edge).GetType()),
                "orientation": int(edge.Orientation()),
                "lengthUm": int(
                    round(float(edge_props.Mass()) * unit_to_mm * 1000.0)
                ),
                "centerUm": [
                    int(round(float(edge_center.X()) * unit_to_mm * 1000.0)),
                    int(round(float(edge_center.Y()) * unit_to_mm * 1000.0)),
                    int(round(float(edge_center.Z()) * unit_to_mm * 1000.0)),
                ],
            }
        )
        edge_explorer.Next()

    cylinders.sort(
        key=lambda item: (
            item["diameterUm"],
            item["originUm"],
            item["axisPpm"],
            item["internal"],
        )
    )
    holes_by_diameter: dict[int, int] = {}
    for cylinder in cylinders:
        if cylinder["internal"]:
            diameter = int(cylinder["diameterUm"])
            holes_by_diameter[diameter] = holes_by_diameter.get(diameter, 0) + 1
    holes = [
        {"diameterUm": diameter, "count": holes_by_diameter[diameter]}
        for diameter in sorted(holes_by_diameter)
    ]
    fingerprint = {
        "parser": "OCP-7.9",
        "solidCount": solid_count,
        "volumeUm3": volume_um3,
        "surfaceAreaUm2": surface_um2,
        "envelopeUm": sorted(envelope_um),
        "faces": sorted(
            faces,
            key=lambda item: canonical_json_bytes(item),
        ),
        "edges": sorted(
            edges,
            key=lambda item: canonical_json_bytes(item),
        ),
        "cylinders": cylinders,
    }
    return {
        "validSolids": solid_count if valid else 0,
        "envelopeUm": sorted(envelope_um),
        "holes": holes,
        "geometryFingerprintSha256": canonical_sha256(fingerprint),
        "geometryDetails": fingerprint,
    }


def load_verification_session(path: Path) -> dict[str, Any]:
    session = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(session, dict):
        raise MeasurementTrustError("session 必须是 JSON 对象。")
    required = ("sessionId", "jobId", "runId", "nonce", "spec", "specSha256")
    missing = [field for field in required if not session.get(field)]
    if missing:
        raise MeasurementTrustError("session 缺少字段: " + ", ".join(missing))
    validate_contract(session["spec"], "dimension_verification.schema.json")
    if canonical_sha256(session["spec"]) != session["specSha256"]:
        raise MeasurementTrustError("session 规格摘要不一致。")
    if len(str(session["nonce"])) < 32:
        raise MeasurementTrustError("session nonce 长度不足。")
    return session


def verify_bundle(
    *,
    bundle_path: Path,
    session: dict[str, Any],
    private_key: Ed25519PrivateKey,
    workflow_repository: str,
    workflow_ref: str,
    workflow_sha: str,
    runner_id: str,
    argv: list[str],
    now: datetime | None = None,
) -> dict[str, Any]:
    """@brief 验证受控包、独立测量并签发不可抵赖证明。"""
    if len(workflow_sha) != 40 or any(character not in "0123456789abcdefABCDEF" for character in workflow_sha):
        raise MeasurementTrustError("workflowSha 必须是 40 位 Git commit SHA。")
    if not workflow_repository or not workflow_ref or not runner_id:
        raise MeasurementTrustError("验证器身份字段不完整。")
    manifest, members = open_measurement_bundle(bundle_path)
    for field in ("sessionId", "jobId", "runId", "nonce", "specSha256"):
        if manifest.get(field) != session.get(field):
            raise MeasurementTrustError(f"证明包与控制面 session 的 {field} 不一致。")

    issued_at = (now or _utc_now()).astimezone(timezone.utc)
    expires_at = issued_at + ATTESTATION_MAX_TTL
    artifact_results: list[dict[str, Any]] = []
    all_checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="cad-evidence-verify-") as temporary:
        temp_root = Path(temporary)
        for item in manifest["artifacts"]:
            bundle_path_name = str(item["bundlePath"])
            local_path = temp_root / Path(bundle_path_name).name
            local_path.write_bytes(members[bundle_path_name])
            try:
                shape, unit_to_mm = _load_shape(local_path)
                measured = _shape_measurement(shape, unit_to_mm)
                artifact_check = {
                    "id": "artifact-readback",
                    "status": "pass",
                    "message": f"{bundle_path_name} 已由 OCCT 独立读取。",
                }
            except (MeasurementTrustError, ImportError, ModuleNotFoundError) as exc:
                measured = None
                artifact_check = {
                    "id": "artifact-readback",
                    "status": "blocked",
                    "message": f"{bundle_path_name} 无法独立读取: {exc}",
                }
            if measured is None:
                check_set = [artifact_check]
                artifact = {
                    "artifactId": str(item["artifactId"]),
                    "kind": str(item["kind"]),
                    "bundlePath": bundle_path_name,
                    "sha256": str(item["sha256"]),
                    "sizeBytes": int(item["sizeBytes"]),
                    "geometryFingerprintSha256": None,
                    "validSolids": 0,
                    "envelopeUm": None,
                    "holes": [],
                }
            else:
                artifact = {
                    "artifactId": str(item["artifactId"]),
                    "kind": str(item["kind"]),
                    "bundlePath": bundle_path_name,
                    "sha256": str(item["sha256"]),
                    "sizeBytes": int(item["sizeBytes"]),
                    "geometryFingerprintSha256": measured["geometryFingerprintSha256"],
                    "validSolids": int(measured["validSolids"]),
                    "envelopeUm": list(measured["envelopeUm"]),
                    "holes": list(measured["holes"]),
                }
                if measured["validSolids"] < 1:
                    artifact_check = {
                        "id": "artifact-valid-solid",
                        "status": "fail",
                        "message": f"{bundle_path_name} 没有有效实体。",
                    }
                    check_set = [artifact_check]
                else:
                    check_set = [artifact_check, *evaluate_measurement_spec(session["spec"], measured)]
            artifact_results.append(artifact)
            all_checks.extend(check_set)

    statuses = {check["status"] for check in all_checks}
    decision = "blocked" if "blocked" in statuses else "fail" if "fail" in statuses else "pass"
    signed_at = _utc_now()
    attestation = {
        "schema": ATTESTATION_SCHEMA,
        "attestationId": "att-" + secrets.token_hex(16),
        "sessionId": str(session["sessionId"]),
        "jobId": str(session["jobId"]),
        "runId": str(session["runId"]),
        "nonce": str(session["nonce"]),
        "specSha256": str(session["specSha256"]),
        "verifier": {
            "workflowRepository": workflow_repository,
            "workflowRef": workflow_ref,
            "workflowSha": workflow_sha.lower(),
            "toolkitSha256": _toolkit_sha256(),
            "runtime": {
                "pythonVersion": platform.python_version(),
                "platform": platform.platform(),
                "dependencyLockSha256": file_sha256(
                    ROOT / "requirements-evidence-verifier.txt"
                ),
                "dependencyVersionsSha256": _dependency_versions_sha256(),
            },
            "runnerId": runner_id,
            "processId": os.getpid(),
            "processCreatedAt": _process_created_at(os.getpid()),
            "argv": list(argv),
            "argvSha256": canonical_sha256(list(argv)),
            "exitCode": 0,
        },
        "artifacts": artifact_results,
        "checks": all_checks,
        "decision": decision,
        "issuedAt": _iso(issued_at),
        "expiresAt": _iso(expires_at),
        "signer": {
            "algorithm": "Ed25519",
            "keyId": public_key_id(private_key.public_key()),
            "signedAt": _iso(signed_at),
        },
    }
    signed = sign_document(attestation, private_key, ATTESTATION_DOMAIN)
    validate_contract(signed, "measurement_attestation.schema.json")
    return signed
def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="独立验证 CAD B-Rep 并签发尺寸证明")
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workflow-repository", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--runner-id", required=True)
    args = parser.parse_args(argv)
    try:
        session = load_verification_session(args.session)
        private_key = _load_private_key(args.private_key)
        evidence = verify_bundle(
            bundle_path=args.bundle,
            session=session,
            private_key=private_key,
            workflow_repository=args.workflow_repository,
            workflow_ref=args.workflow_ref,
            workflow_sha=args.workflow_sha,
            runner_id=args.runner_id,
            argv=sys.argv,
        )
        _write_atomic(args.output, evidence)
        print(json.dumps({"status": evidence["decision"], "attestationPath": str(args.output)}, ensure_ascii=False))
        return 0 if evidence["decision"] in {"pass", "fail"} else 2
    except Exception as exc:  # noqa: BLE001 - CLI 必须 fail closed 并输出可诊断错误
        print(json.dumps({"status": "blocked", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
