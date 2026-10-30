"""@brief CAD 尺寸证据的锁定规格、规范序列化与远程签名验证。

本模块刻意不信任 Agent 写入的 ``cad_spec`` 或 ``measurement_source``。
生产 ``PASS`` 只能来自 Agent 权限外验证器签发的
``cad-measurement-attestation/v1``，并在每次验收时在线确认证明状态。
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from jsonschema import Draft202012Validator


DIMENSION_SPEC_SCHEMA = "cad-dimension-verification/v1"
ATTESTATION_SCHEMA = "cad-measurement-attestation/v1"
ATTESTATION_STATUS_SCHEMA = "cad-attestation-status/v1"
ATTESTATION_DOMAIN = b"cad-measurement-attestation/v1\x00"
ATTESTATION_STATUS_DOMAIN = b"cad-attestation-status/v1\x00"
ATTESTATION_MAX_TTL = timedelta(hours=1)
STATUS_MAX_TTL = timedelta(minutes=1)
CLOCK_SKEW = timedelta(minutes=5)
DEFAULT_TOLERANCE_UM = 1

BREP_EXTENSIONS = frozenset({".step", ".stp", ".iges", ".igs", ".brep"})
KIND_ALIASES = {
    "step": "step",
    "stp": "step",
    "iges": "iges",
    "igs": "iges",
    "brep": "brep",
}
FORMAT_LABELS = {
    "STEP": "step",
    "STP": "step",
    "IGES": "iges",
    "IGS": "iges",
    "BREP": "brep",
}
DIMENSION_TRIPLE_PATTERN = re.compile(
    r"(?<![\d.])(\d+(?:\.\d+)?)\s*[xX×]\s*(\d+(?:\.\d+)?)\s*[xX×]\s*"
    r"(\d+(?:\.\d+)?)\s*(?:mm|毫米)",
    re.IGNORECASE,
)
DIAMETER_PATTERN = re.compile(
    r"(?:直径|孔径|[Ø⌀Φφ])\s*(\d+(?:\.\d+)?)\s*(?:mm|毫米)?",
    re.IGNORECASE,
)

_SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
_NUMBER_WORDS = {
    "一": 1,
    "二": 2,
    "两": 2,
    "三": 3,
    "四": 4,
    "五": 5,
    "六": 6,
    "七": 7,
    "八": 8,
    "九": 9,
    "十": 10,
}


class MeasurementTrustError(ValueError):
    """证明、规格或绑定关系不满足信任链要求。"""


def _schema_path(name: str) -> Path:
    return _SCHEMA_DIR / name


@lru_cache(maxsize=8)
def _schema(name: str) -> dict[str, Any]:
    return json.loads(_schema_path(name).read_text(encoding="utf-8"))


def validate_contract(document: Any, schema_name: str) -> None:
    """@brief 按仓库内固定 JSON Schema 验证协议文档。"""
    validator = Draft202012Validator(_schema(schema_name))
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if not errors:
        return
    error = errors[0]
    location = ".".join(str(part) for part in error.absolute_path) or "<root>"
    raise MeasurementTrustError(f"{schema_name}@{location}: {error.message}")


def _reject_surrogate(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise MeasurementTrustError("JSON 字符串包含非法 Unicode 代理项。") from exc


def canonical_json_bytes(value: Any) -> bytes:
    """@brief RFC 8785 受限子集：只允许字符串、布尔、null、安全整数和容器。

    尺寸与时间均使用整数微米或字符串，因此协议通常不会出现浮点数。拒绝浮点
    可避免 Python 与 JavaScript 在指数和尾零格式上的规范化差异。
    """

    def encode(item: Any) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int) and not isinstance(item, bool):
            if abs(item) > 9_007_199_254_740_991:
                raise MeasurementTrustError("JSON 整数超过 RFC 8785 安全整数范围。")
            return str(item)
        if isinstance(item, float):
            raise MeasurementTrustError("签名协议禁止浮点数；请改用整数微米或十进制字符串。")
        if isinstance(item, str):
            _reject_surrogate(item)
            return json.dumps(item, ensure_ascii=False, separators=(",", ":"))
        if isinstance(item, list):
            return "[" + ",".join(encode(child) for child in item) + "]"
        if isinstance(item, Mapping):
            output: list[str] = []
            keys = list(item)
            if any(not isinstance(key, str) for key in keys):
                raise MeasurementTrustError("JSON 对象键必须是字符串。")
            for key in sorted(keys, key=lambda text: text.encode("utf-16-be")):
                _reject_surrogate(key)
                output.append(
                    json.dumps(key, ensure_ascii=False, separators=(",", ":"))
                    + ":"
                    + encode(item[key])
                )
            return "{" + ",".join(output) + "}"
        raise MeasurementTrustError(f"不支持签名 JSON 类型: {type(item).__name__}")

    return encode(value).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def signing_payload(document: Mapping[str, Any], domain: bytes) -> bytes:
    """@brief 带域分隔的签名载荷，排除 signature 字段。"""
    unsigned = {str(key): value for key, value in document.items() if key != "signature"}
    return domain + canonical_json_bytes(unsigned)


def public_key_id(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return f"ed25519:{hashlib.sha256(der).hexdigest()}"


def sign_document(document: Mapping[str, Any], private_key: Ed25519PrivateKey, domain: bytes) -> dict[str, Any]:
    """@brief 由受保护验证器调用；签名覆盖除 signature 外的全部字段。"""
    signed = dict(document)
    signed.pop("signature", None)
    signature = private_key.sign(signing_payload(signed, domain))
    signed["signature"] = base64.b64encode(signature).decode("ascii")
    return signed


def load_trust_root(path: str | Path) -> dict[str, Any]:
    """@brief 读取固定公钥信任根；未知格式直接失败关闭。"""
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("schema") != "cad-measurement-trust-root/v1":
        raise MeasurementTrustError("测量信任根 schema 不受支持。")
    keys = value.get("keys")
    if not isinstance(keys, list) or not keys:
        raise MeasurementTrustError("测量信任根没有公钥。")
    rotation = value.get("rotationLog")
    if not isinstance(rotation, list) or not rotation:
        raise MeasurementTrustError("测量信任根缺少轮换日志。")
    seen: set[str] = set()
    for item in keys:
        if not isinstance(item, dict):
            raise MeasurementTrustError("测量信任根 key 条目必须是对象。")
        key_id = str(item.get("keyId") or "")
        pem = item.get("publicKeyPem")
        purposes = item.get("purposes")
        if (
            not key_id.startswith("ed25519:")
            or not isinstance(pem, str)
            or not isinstance(purposes, list)
            or len(purposes) != 1
            or any(
                purpose not in {"measurement_attestation", "attestation_status"}
                for purpose in purposes
            )
        ):
            raise MeasurementTrustError("测量信任根 key 条目格式错误。")
        public_key = serialization.load_pem_public_key(pem.encode("utf-8"))
        if not isinstance(public_key, Ed25519PublicKey) or public_key_id(public_key) != key_id:
            raise MeasurementTrustError(f"测量信任根 keyId 指纹不一致: {key_id}")
        if key_id in seen:
            raise MeasurementTrustError(f"测量信任根 keyId 重复: {key_id}")
        seen.add(key_id)
    logged: list[str] = []
    for entry in rotation:
        if not isinstance(entry, dict):
            raise MeasurementTrustError("测量信任根轮换日志条目必须是对象。")
        key_id = str(entry.get("keyId") or "")
        if key_id not in seen or key_id in logged:
            raise MeasurementTrustError("测量信任根轮换日志含未知或重复 keyId。")
        _parse_time(entry.get("addedAt"), "rotationLog.addedAt")
        if not str(entry.get("reason") or "").strip():
            raise MeasurementTrustError("测量信任根轮换日志缺少原因。")
        logged.append(key_id)
    if set(logged) != seen:
        raise MeasurementTrustError("测量信任根公钥与轮换日志不完整。")
    purpose_set = {
        str(item.get("purposes", [None])[0])
        for item in keys
        if isinstance(item, dict)
    }
    if purpose_set != {"measurement_attestation", "attestation_status"}:
        raise MeasurementTrustError("测量与在线状态必须使用用途分离的独立密钥。")
    return value


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise MeasurementTrustError(f"{field} 必须是 ISO-8601 时间。")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MeasurementTrustError(f"{field} 不是有效 ISO-8601 时间。") from exc
    if parsed.tzinfo is None:
        raise MeasurementTrustError(f"{field} 必须带时区。")
    return parsed.astimezone(timezone.utc)


def _resolve_public_key(
    trust_root: Mapping[str, Any],
    key_id: str,
    signed_at: datetime,
    now: datetime,
    required_purpose: str,
) -> Ed25519PublicKey:
    for item in trust_root.get("keys") or []:
        if not isinstance(item, dict) or item.get("keyId") != key_id:
            continue
        if required_purpose not in (item.get("purposes") or []):
            raise MeasurementTrustError(f"签名密钥不适用于 {required_purpose}。")
        not_before = item.get("notBefore")
        if not_before and signed_at < _parse_time(not_before, "notBefore"):
            raise MeasurementTrustError("签名密钥尚未生效。")
        revoked_at = item.get("revokedAt")
        if revoked_at and (
            signed_at >= _parse_time(revoked_at, "revokedAt")
            or now >= _parse_time(revoked_at, "revokedAt")
        ):
            raise MeasurementTrustError("签名密钥已撤销。")
        public_key = serialization.load_pem_public_key(str(item["publicKeyPem"]).encode("utf-8"))
        if not isinstance(public_key, Ed25519PublicKey):
            raise MeasurementTrustError("信任根中的密钥不是 Ed25519 公钥。")
        if public_key_id(public_key) != key_id:
            raise MeasurementTrustError("签名密钥指纹不一致。")
        return public_key
    raise MeasurementTrustError("签名密钥不在固定信任根中。")


def verify_signed_document(
    document: Any,
    *,
    schema_name: str,
    domain: bytes,
    trust_root: Mapping[str, Any],
    now: datetime,
    max_signature_age: timedelta = CLOCK_SKEW,
    required_purpose: str,
) -> dict[str, Any]:
    """@brief 验证协议结构、Ed25519 签名、密钥有效期和签名时间。"""
    validate_contract(document, schema_name)
    signer = document["signer"]
    signed_at = _parse_time(signer["signedAt"], "signer.signedAt")
    if signed_at < now - max_signature_age - CLOCK_SKEW or signed_at > now + CLOCK_SKEW:
        raise MeasurementTrustError("签名时间超出允许时钟窗口。")
    public_key = _resolve_public_key(
        trust_root,
        str(signer["keyId"]),
        signed_at,
        now,
        required_purpose,
    )
    try:
        signature = base64.b64decode(str(document["signature"]), validate=True)
        public_key.verify(signature, signing_payload(document, domain))
    except (InvalidSignature, ValueError) as exc:
        raise MeasurementTrustError("Ed25519 签名无效。") from exc
    return dict(signer)


def _um(value: float) -> int:
    return int(round(float(value) * 1000.0))


def _unique_triplets(values: list[tuple[int, int, int]]) -> list[tuple[int, int, int]]:
    unique: list[tuple[int, int, int]] = []
    for value in values:
        normalized = tuple(sorted(value))
        if normalized not in unique:
            unique.append(normalized)
    return unique


def _count_prefix(text: str, start: int) -> int | None:
    prefix = text[max(0, start - 18) : start]
    if "中心孔" in prefix[-8:]:
        return 1
    explicit = re.search(r"(?<![A-Za-z0-9])(\d+)\s*[x×]\s*$", prefix)
    if explicit:
        return int(explicit.group(1))
    match = re.search(
        r"(?<![A-Za-z0-9])(\d+|[一二两三四五六七八九十])\s*(?:个|处|角)?\s*(?:中心)?孔\s*$",
        prefix,
    )
    if not match:
        return None
    raw = match.group(1)
    count = int(raw) if raw.isdigit() else _NUMBER_WORDS.get(raw)
    return count if count and count > 0 else None


def _extract_holes(text: str, tolerance_um: int) -> list[dict[str, Any]]:
    grouped: dict[int, list[int | None]] = {}
    for match in DIAMETER_PATTERN.finditer(text):
        diameter_um = _um(float(match.group(1)))
        count = _count_prefix(text, match.start())
        grouped.setdefault(diameter_um, []).append(count)
    holes: list[dict[str, Any]] = []
    for diameter_um in sorted(grouped):
        counts = grouped[diameter_um]
        if all(isinstance(count, int) and count > 0 for count in counts):
            count: int | None = sum(int(item) for item in counts)
        else:
            count = None
        holes.append(
            {
                "diameterUm": diameter_um,
                "count": count,
                "toleranceUm": tolerance_um,
            }
        )
    return holes


def _format_kind(value: str) -> str | None:
    normalized = value.upper().lstrip(".")
    return FORMAT_LABELS.get(normalized)


def dimension_spec_from_job(
    job: Mapping[str, Any],
) -> tuple[dict[str, Any], bool] | None:
    """@brief 在 Agent 启动前从任务明确尺寸生成确定性锁定规格。

    多个不同外形三元尺寸或无法确定数量的孔径会标记为需用户确认。自由文本
    从不作为最终证明来源，只用于生成待锁定规格。
    """
    strict_rules = job.get("strictRules") if isinstance(job.get("strictRules"), list) else []
    text = "\n".join(
        [
            str(job.get("objective") or ""),
            str(job.get("detail") or ""),
            *(str(item) for item in strict_rules),
        ]
    )
    triplets = _unique_triplets(
        [
            (
                _um(float(match.group(1))),
                _um(float(match.group(2))),
                _um(float(match.group(3))),
            )
            for match in DIMENSION_TRIPLE_PATTERN.finditer(text)
        ]
    )
    holes = _extract_holes(text, DEFAULT_TOLERANCE_UM)
    if not triplets and not holes:
        return None

    required_outputs = job.get("requiredOutputs") if isinstance(job.get("requiredOutputs"), list) else []
    ui_config = job.get("uiConfig") if isinstance(job.get("uiConfig"), dict) else {}
    ui_required = ui_config.get("requiredOutputs") if isinstance(ui_config.get("requiredOutputs"), list) else []
    expected = " ".join(
        [
            str(job.get("expectedOutput") or ""),
            *(str(item) for item in required_outputs),
            *(str(item) for item in ui_required),
        ]
    )
    required_kinds: list[str] = []
    for label, kind in FORMAT_LABELS.items():
        if re.search(rf"(?<![A-Za-z0-9]){re.escape(label)}(?![A-Za-z0-9])", expected.upper()):
            if kind not in required_kinds:
                required_kinds.append(kind)

    confirmation_required = len(triplets) > 1 or any(item["count"] is None for item in holes)
    return {
        "schema": DIMENSION_SPEC_SCHEMA,
        "units": "mm",
        "source": "deterministic_parser",
        "artifacts": {
            "requiredKinds": required_kinds,
            "measurementKinds": sorted(set(required_kinds) or {"step", "iges", "brep"}),
        },
        "checks": {
            "envelope": {
                "expectedUm": list(triplets[0]),
                "toleranceUm": DEFAULT_TOLERANCE_UM,
            }
            if len(triplets) == 1
            else None,
            "holes": holes,
        },
    }, confirmation_required


def lock_dimension_spec(
    spec: Mapping[str, Any],
    *,
    confirmation_required: bool,
    confirmed_at: str | None = None,
) -> dict[str, Any]:
    """@brief 生成规格摘要；摘要绑定后 Agent 不能再修改验收目标。"""
    normalized = json.loads(json.dumps(spec, ensure_ascii=False))
    validate_contract(normalized, "dimension_verification.schema.json")
    wrapper: dict[str, Any] = {
        "spec": normalized,
        "sha256": canonical_sha256(normalized),
        "confirmationRequired": bool(confirmation_required),
    }
    if confirmed_at:
        wrapper["confirmedAt"] = confirmed_at
    return wrapper


def requested_dimension_spec(job: Mapping[str, Any]) -> dict[str, Any] | None:
    """@brief 优先使用任务中预锁定的规格，否则生成未确认的确定性候选。"""
    supplied = job.get("verificationSpec")
    if isinstance(supplied, dict):
        if isinstance(supplied.get("spec"), dict):
            spec = json.loads(json.dumps(supplied["spec"], ensure_ascii=False))
            validate_contract(spec, "dimension_verification.schema.json")
            expected_sha = str(supplied.get("sha256") or "")
            if not expected_sha:
                raise MeasurementTrustError("verificationSpec 缺少 sha256。")
            if expected_sha != canonical_sha256(spec):
                raise MeasurementTrustError("verificationSpec 摘要不一致。")
            confirmation_required = bool(supplied.get("confirmationRequired"))
            confirmed_at = supplied.get("confirmedAt")
            if bool(job.get("verificationSpecConfirmed")) and confirmation_required:
                spec["source"] = "user_confirmed"
                confirmation_required = False
                confirmed_at = confirmed_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
            actual_sha = canonical_sha256(spec)
            return {
                "spec": spec,
                "sha256": actual_sha,
                "confirmationRequired": confirmation_required,
                **(
                    {"confirmedAt": confirmed_at}
                    if confirmed_at
                    else {}
                ),
            }
        validate_contract(supplied, "dimension_verification.schema.json")
        confirmed = bool(job.get("verificationSpecConfirmed"))
        if confirmed:
            supplied = json.loads(json.dumps(supplied, ensure_ascii=False))
            supplied["source"] = "user_confirmed"
        return lock_dimension_spec(
            supplied,
            confirmation_required=not confirmed,
            confirmed_at=(
                datetime.now(timezone.utc).isoformat(timespec="seconds")
                if confirmed
                else None
            ),
        )
    parsed = dimension_spec_from_job(job)
    if parsed is None:
        return None
    spec, confirmation_required = parsed
    return lock_dimension_spec(spec, confirmation_required=confirmation_required)


def _same_envelope(left: Sequence[int], right: Sequence[int], tolerance_um: int) -> bool:
    return len(left) == len(right) == 3 and all(
        abs(int(a) - int(b)) <= tolerance_um for a, b in zip(sorted(left), sorted(right))
    )


def evaluate_measurement_spec(
    spec: Mapping[str, Any],
    measurements: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """@brief 对受信验证器返回的整数微米测量重新执行锁定规格。"""
    checks: list[dict[str, Any]] = []
    expected_envelope = (spec.get("checks") or {}).get("envelope")
    if isinstance(expected_envelope, dict):
        expected = [int(value) for value in expected_envelope.get("expectedUm") or []]
        actual = measurements.get("envelopeUm")
        tolerance = int(expected_envelope.get("toleranceUm", DEFAULT_TOLERANCE_UM))
        passed = isinstance(actual, list) and _same_envelope(expected, actual, tolerance)
        checks.append(
            {
                "id": "spec-envelope-dimensions",
                "status": "pass" if passed else "fail",
                "message": (
                    f"受信 B-Rep 外形尺寸与锁定规格一致: {expected} μm。"
                    if passed
                    else f"受信 B-Rep 外形尺寸不一致；期望 {expected} μm，实际 {actual} μm。"
                ),
            }
        )

    expected_holes = (spec.get("checks") or {}).get("holes")
    if isinstance(expected_holes, list) and expected_holes:
        actual_holes = measurements.get("holes")
        actual_holes = actual_holes if isinstance(actual_holes, list) else []
        failures: list[str] = []
        for expected in expected_holes:
            diameter = int(expected["diameterUm"])
            tolerance = int(expected.get("toleranceUm", DEFAULT_TOLERANCE_UM))
            count_expected = expected.get("count")
            matched = [
                item
                for item in actual_holes
                if isinstance(item, dict)
                and abs(int(item.get("diameterUm", 0)) - diameter) <= tolerance
            ]
            actual_count = sum(int(item.get("count", 0)) for item in matched)
            if not matched:
                failures.append(f"缺少 Ø{diameter / 1000:g} mm")
            elif count_expected is not None and actual_count != int(count_expected):
                failures.append(
                    f"Ø{diameter / 1000:g} mm 数量期望 {count_expected}，实际 {actual_count}"
                )
        checks.append(
            {
                "id": "spec-hole-diameters",
                "status": "fail" if failures else "pass",
                "message": (
                    "受信 B-Rep 孔径与数量符合锁定规格。"
                    if not failures
                    else "孔径证据不符合锁定规格: " + "；".join(failures)
                ),
            }
        )
    return checks


def _local_brep_artifacts(artifacts: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for artifact in artifacts:
        if not isinstance(artifact, Mapping):
            continue
        path = Path(str(artifact.get("path") or ""))
        if (
            path.suffix.lower() not in BREP_EXTENSIONS
            or artifact.get("exists") is not True
            or artifact.get("isDirectory") is True
            or artifact.get("producedThisRun") is not True
        ):
            continue
        kind = KIND_ALIASES.get(path.suffix.lower().lstrip("."))
        if kind is None:
            continue
        result.append(
            {
                "kind": kind,
                "path": str(path),
                "sha256": str(artifact.get("sha256") or ""),
                "sizeBytes": int(artifact.get("sizeBytes") or 0),
            }
        )
    return result


def _aggregate_check_status(checks: Sequence[Mapping[str, Any]]) -> str:
    statuses = {str(item.get("status") or "blocked") for item in checks}
    if "blocked" in statuses:
        return "blocked"
    if "fail" in statuses:
        return "fail"
    if "warning" in statuses or "review_required" in statuses:
        return "review_required"
    return "pass" if checks else "blocked"


def verify_measurement_evidence(
    ledger: Mapping[str, Any],
    artifacts: Sequence[Mapping[str, Any]],
    *,
    trust_root: Mapping[str, Any] | None,
    online_status: Callable[[str], Mapping[str, Any] | None] | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """@brief 验证锁定规格、远程 Ed25519 证明、在线状态及当前产物哈希。"""
    checked_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    try:
        locked = requested_dimension_spec(ledger)
    except (MeasurementTrustError, KeyError, TypeError, ValueError) as exc:
        return {
            "status": "blocked",
            "checks": [
                {
                    "id": "measurement-spec-valid",
                    "status": "blocked",
                    "message": f"锁定验收规格无效: {exc}",
                }
            ],
        }
    if locked is None:
        return {"status": "not_applicable", "checks": []}

    spec = locked["spec"]
    spec_checks: list[dict[str, Any]] = []
    required_kinds = {
        KIND_ALIASES.get(str(kind).lower(), str(kind).lower())
        for kind in (spec.get("artifacts") or {}).get("requiredKinds") or []
    }
    local_breps = _local_brep_artifacts(artifacts)
    local_kinds = {item["kind"] for item in local_breps}
    missing_local = sorted(required_kinds - local_kinds)
    if missing_local:
        spec_checks.append(
            {
                "id": "measurement-primary-brep-present",
                "status": "review_required",
                "message": "没有可受信复测的开放 B-Rep 交付物: " + ", ".join(missing_local),
            }
        )
    if not required_kinds:
        spec_checks.append(
            {
                "id": "measurement-format-supported",
                "status": "review_required",
                "message": "首版可信尺寸复测只覆盖 STEP/IGES/BREP；原生格式仍需人工复核。",
            }
        )
        return {"status": "review_required", "checks": spec_checks}

    if locked.get("confirmationRequired"):
        spec_checks.append(
            {
                "id": "measurement-spec-confirmed",
                "status": "blocked",
                "message": "验收规格存在歧义且尚未由用户确认，不能创建受信验证结论。",
            }
        )
    if trust_root is None:
        spec_checks.append(
            {
                "id": "measurement-trust-root",
                "status": "blocked",
                "message": "未配置固定的测量证明公钥信任根。",
            }
        )

    attestation = ledger.get("measurementAttestation")
    if not isinstance(attestation, dict):
        if isinstance(spec.get("checks", {}).get("envelope"), dict):
            spec_checks.append(
                {
                    "id": "spec-envelope-dimensions",
                    "status": "fail",
                    "message": "缺少独立的 B-Rep 外形尺寸证明；Agent 自写数字不能代替受信测量。",
                }
            )
        if spec.get("checks", {}).get("holes"):
            spec_checks.append(
                {
                    "id": "spec-hole-diameters",
                    "status": "fail",
                    "message": "缺少独立的 B-Rep 孔径证明；Agent 自写数字不能代替受信测量。",
                }
            )
        spec_checks.append(
            {
                "id": "measurement-attestation-required",
                "status": "blocked",
                "message": (
                    "尺寸门禁只接受 cad-measurement-attestation/v1 签名证明。"
                    + (
                        f" 远程验证未完成: {ledger.get('measurementTrustError')}"
                        if ledger.get("measurementTrustError")
                        else ""
                    )
                ),
            }
        )
        return {"status": _aggregate_check_status(spec_checks), "checks": spec_checks}

    try:
        validate_contract(attestation, "measurement_attestation.schema.json")
        if trust_root is None:
            raise MeasurementTrustError("没有可用信任根。")
        verify_signed_document(
            attestation,
            schema_name="measurement_attestation.schema.json",
            domain=ATTESTATION_DOMAIN,
            trust_root=trust_root,
            now=checked_at,
            max_signature_age=ATTESTATION_MAX_TTL,
            required_purpose="measurement_attestation",
        )
        spec_checks.append(
            {
                "id": "measurement-attestation-signature",
                "status": "pass",
                "message": "Ed25519 证明签名、密钥指纹和签名时间有效。",
            }
        )
    except (MeasurementTrustError, KeyError, TypeError, ValueError) as exc:
        spec_checks.append(
            {
                "id": "measurement-attestation-signature",
                "status": "blocked",
                "message": f"测量证明不可信: {exc}",
            }
        )
        return {"status": "blocked", "checks": spec_checks}

    checks_by_id = {item["id"]: item for item in attestation["checks"]}
    verifier = attestation.get("verifier") or {}
    if verifier.get("workflowRef") != "refs/heads/main":
        raise MeasurementTrustError("验证器不是从固定 main 工作流签发。")
    issued_at = _parse_time(attestation["issuedAt"], "issuedAt")
    expires_at = _parse_time(attestation["expiresAt"], "expiresAt")
    signed_at = _parse_time(attestation["signer"]["signedAt"], "signer.signedAt")
    if expires_at <= issued_at or expires_at - issued_at > ATTESTATION_MAX_TTL:
        raise MeasurementTrustError("证明有效期超过 1 小时或时间窗口无效。")
    if signed_at < issued_at - CLOCK_SKEW or signed_at > expires_at:
        raise MeasurementTrustError("证明签名时间不在证明有效窗口内。")
    if checked_at < issued_at - CLOCK_SKEW or checked_at > expires_at:
        raise MeasurementTrustError("测量证明已过期或尚未生效。")

    session = ledger.get("verificationSession")
    if not isinstance(session, dict):
        raise MeasurementTrustError("账本缺少验证会话。")
    expected_bindings = {
        "sessionId": str(session.get("sessionId") or ""),
        "jobId": str(ledger.get("jobId") or ""),
        "runId": str(ledger.get("runId") or ""),
        "nonce": str(session.get("nonce") or ""),
        "specSha256": str(locked.get("sha256") or ""),
    }
    mismatches = [
        field
        for field, expected in expected_bindings.items()
        if str(attestation.get(field) or "") != expected
    ]
    if mismatches:
        spec_checks.append(
            {
                "id": "measurement-attestation-binding",
                "status": "fail",
                "message": "证明未绑定当前任务: " + ", ".join(mismatches),
            }
        )
    else:
        spec_checks.append(
            {
                "id": "measurement-attestation-binding",
                "status": "pass",
                "message": "证明已绑定 session、job、run、nonce 和锁定规格摘要。",
            }
        )

    session_expires_at = _parse_time(session.get("expiresAt"), "session.expiresAt")
    if issued_at > session_expires_at:
        spec_checks.append(
            {
                "id": "measurement-attestation-session-window",
                "status": "blocked",
                "message": "测量证明签发时间晚于一次性会话有效期。",
            }
        )
    else:
        spec_checks.append(
            {
                "id": "measurement-attestation-session-window",
                "status": "pass",
                "message": "证明签发时间位于一次性会话有效期内。",
            }
        )
    attested_by_hash = {
        (str(item["sha256"]), KIND_ALIASES.get(str(item["kind"]), str(item["kind"])))
        for item in attestation["artifacts"]
    }
    binding_failures: list[str] = []
    for artifact in local_breps:
        actual_sha = file_sha256(artifact["path"])
        if actual_sha != artifact["sha256"]:
            binding_failures.append(f"{artifact['path']} 在账本记录后发生变化")
        elif (actual_sha, artifact["kind"]) not in attested_by_hash:
            binding_failures.append(f"{artifact['path']} 没有对应的受信证明")
    if not local_breps:
        binding_failures.append("没有本轮生成的开放 B-Rep 产物")
    if binding_failures:
        spec_checks.append(
            {
                "id": "measurement-attestation-artifact-binding",
                "status": "fail",
                "message": "；".join(binding_failures),
            }
        )
    else:
        spec_checks.append(
            {
                "id": "measurement-attestation-artifact-binding",
                "status": "pass",
                "message": "当前 B-Rep 文件哈希与受信证明逐一匹配。",
            }
        )

    recomputed_by_id: dict[str, dict[str, Any]] = {}
    for measurements in attestation["artifacts"]:
        if int(measurements.get("validSolids") or 0) < 1:
            recomputed_by_id["artifact-valid-solid"] = {
                "id": "artifact-valid-solid",
                "status": "fail",
                "message": f"证明产物没有有效实体: {measurements.get('bundlePath')}",
            }
        for check in evaluate_measurement_spec(spec, measurements):
            existing = recomputed_by_id.get(check["id"])
            if existing is None:
                recomputed_by_id[check["id"]] = check
            elif existing["status"] != check["status"] or existing["message"] != check["message"]:
                combined_status = "fail" if "fail" in {existing["status"], check["status"]} else existing["status"]
                recomputed_by_id[check["id"]] = {
                    "id": check["id"],
                    "status": combined_status,
                    "message": "多个 B-Rep 产物的复算结果不一致；所有声明产物都必须满足锁定规格。",
                }
    recomputed = list(recomputed_by_id.values())
    spec_checks.extend(recomputed)

    remote_statuses = [
        str(item.get("status") or "blocked")
        for item in attestation["checks"]
    ]
    expected_ids = {item["id"] for item in recomputed}
    missing_ids = sorted(expected_ids - set(checks_by_id))
    if missing_ids:
        spec_checks.append(
            {
                "id": "measurement-attestation-checks",
                "status": "blocked",
                "message": "证明缺少必需检查: " + ", ".join(missing_ids),
            }
        )
    elif "blocked" in remote_statuses:
        spec_checks.append(
            {
                "id": "measurement-attestation-checks",
                "status": "blocked",
                "message": "受信验证器报告 blocked。",
            }
        )
    elif "fail" in remote_statuses:
        spec_checks.append(
            {
                "id": "measurement-attestation-checks",
                "status": "fail",
                "message": "受信验证器报告规格不匹配。",
            }
        )
    else:
        spec_checks.append(
            {
                "id": "measurement-attestation-checks",
                "status": "pass",
                "message": "受信验证器检查全部通过。",
            }
        )

    if online_status is None:
        spec_checks.append(
            {
                "id": "measurement-attestation-online",
                "status": "blocked",
                "message": "生产模式禁止离线 PASS，缺少在线证明状态客户端。",
            }
        )
    else:
        try:
            status = online_status(str(attestation["attestationId"]))
            if not isinstance(status, Mapping):
                raise MeasurementTrustError("在线状态为空。")
            verify_signed_document(
                status,
                schema_name="measurement_attestation_status.schema.json",
                domain=ATTESTATION_STATUS_DOMAIN,
                trust_root=trust_root,
                now=checked_at,
                max_signature_age=STATUS_MAX_TTL,
                required_purpose="attestation_status",
            )
            if status.get("attestationId") != attestation.get("attestationId"):
                raise MeasurementTrustError("在线状态绑定了其他证明。")
            status_checked = _parse_time(status["checkedAt"], "status.checkedAt")
            status_expires = _parse_time(status["expiresAt"], "status.expiresAt")
            status_signed = _parse_time(status["signer"]["signedAt"], "status.signer.signedAt")
            if status_expires <= status_checked or status_expires - status_checked > STATUS_MAX_TTL:
                raise MeasurementTrustError("在线状态有效期超过 1 分钟或时间窗口无效。")
            if abs((status_signed - status_checked).total_seconds()) > CLOCK_SKEW.total_seconds():
                raise MeasurementTrustError("在线状态签名时间与检查时间不一致。")
            if checked_at < status_checked - CLOCK_SKEW or checked_at > status_expires:
                raise MeasurementTrustError("在线证明状态已过期。")
            if status.get("status") != "active":
                raise MeasurementTrustError(f"在线证明状态为 {status.get('status')}。")
            policy = status.get("verifierPolicy") or {}
            policy_mismatches = [
                field
                for field in (
                    "workflowRepository",
                    "workflowRef",
                    "workflowSha",
                    "toolkitSha256",
                )
                if str(policy.get(field) or "").casefold() != str(verifier.get(field) or "").casefold()
            ]
            if policy_mismatches:
                raise MeasurementTrustError(
                    "验证器版本不在在线批准策略内: " + ", ".join(policy_mismatches)
                )
            runtime = verifier.get("runtime") or {}
            runtime_mismatches = [
                field
                for field in (
                    "pythonVersion",
                    "platform",
                    "dependencyLockSha256",
                    "dependencyVersionsSha256",
                )
                if str(policy.get(field) or "").casefold()
                != str(runtime.get(field) or "").casefold()
            ]
            if runtime_mismatches:
                raise MeasurementTrustError(
                    "验证器运行时不在在线批准策略内: " + ", ".join(runtime_mismatches)
                )
            spec_checks.append(
                {
                    "id": "measurement-attestation-online",
                    "status": "pass",
                    "message": "证明在线状态有效且未撤销。",
                }
            )
        except (MeasurementTrustError, KeyError, TypeError, ValueError) as exc:
            spec_checks.append(
                {
                    "id": "measurement-attestation-online",
                    "status": "blocked",
                    "message": f"无法在线确认证明状态: {exc}",
                }
            )

    if attestation.get("decision") != "pass":
        spec_checks.append(
            {
                "id": "measurement-attestation-decision",
                "status": "blocked" if attestation.get("decision") == "blocked" else "fail",
                "message": f"受信验证器最终结论为 {attestation.get('decision')}。",
            }
        )
    else:
        spec_checks.append(
            {
                "id": "measurement-attestation-decision",
                "status": "pass",
                "message": "受信验证器最终结论为 pass。",
            }
        )

    return {"status": _aggregate_check_status(spec_checks), "checks": spec_checks}


__all__ = [
    "ATTESTATION_DOMAIN",
    "ATTESTATION_MAX_TTL",
    "ATTESTATION_SCHEMA",
    "ATTESTATION_STATUS_DOMAIN",
    "ATTESTATION_STATUS_SCHEMA",
    "BREP_EXTENSIONS",
    "DEFAULT_TOLERANCE_UM",
    "DIMENSION_SPEC_SCHEMA",
    "MeasurementTrustError",
    "canonical_json_bytes",
    "canonical_sha256",
    "dimension_spec_from_job",
    "evaluate_measurement_spec",
    "file_sha256",
    "load_trust_root",
    "lock_dimension_spec",
    "public_key_id",
    "requested_dimension_spec",
    "sign_document",
    "signing_payload",
    "validate_contract",
    "verify_measurement_evidence",
    "verify_signed_document",
]
