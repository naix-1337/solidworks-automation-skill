"""Native modeling preconditions; local process diagnostics, not dimensional attestation."""
from contextlib import contextmanager
import math

try:
    from .sw_connect import get_com_member
    from .sw_sketch_quality import fully_define_sketch
except ImportError:
    from sw_connect import get_com_member
    from sw_sketch_quality import fully_define_sketch


# swUserPreferenceToggle_e, verified against SW2024 swconst.tlb.
SW_INPUT_DIM_VAL_ON_CREATE = 10
# swSketchFullyDefineRelationType_e: Horizontal=2, Vertical=4, Coincident=512.
EXPLICIT_PROFILE_RELATIONS = 518


class ModelingPreconditionError(RuntimeError):
    """A dependent feature must wait until the recorded precondition is repaired."""

    def __init__(self, code, evidence):
        self.code = code
        self.evidence = evidence
        super().__init__(f"{code}: {evidence}")


@contextmanager
def dimension_input_guard(sw):
    """Restore the actual prior global preference even if dimension creation raises.

    Callers must serialize use of the shared SolidWorks instance. This guard does
    not dismiss dialogs, start instances, close documents, or retry COM mutations.
    """
    previous = bool(get_com_member(sw, "GetUserPreferenceToggle", SW_INPUT_DIM_VAL_ON_CREATE))

    def set_and_check(value):
        returned = get_com_member(sw, "SetUserPreferenceToggle", SW_INPUT_DIM_VAL_ON_CREATE, value)
        observed = bool(get_com_member(sw, "GetUserPreferenceToggle", SW_INPUT_DIM_VAL_ON_CREATE))
        if returned is False or observed != value:
            raise ModelingPreconditionError("DIMENSION_PREFERENCE_NOT_APPLIED", {"requested": value, "observed": observed})

    try:
        set_and_check(False)
        yield
    finally:
        set_and_check(previous)


def _numbers(values):
    result = tuple(float(value) for value in values)
    if not all(math.isfinite(value) for value in result):
        raise ModelingPreconditionError("NONFINITE_SKETCH_GEOMETRY", result)
    return result


def _point(point):
    return _numbers(get_com_member(point, name) for name in ("X", "Y", "Z"))


def _geometry(segments):
    """Read retained segment references so solver enumeration order cannot hide drift."""
    records = []
    for segment in segments:
        kind = int(get_com_member(segment, "GetType"))
        record = {"type": kind}
        if kind not in (0, 1):
            raise ModelingPreconditionError("UNSUPPORTED_GEOMETRY_GUARD", {"segment_type": kind})
        start = _point(get_com_member(segment, "GetStartPoint2"))
        end = _point(get_com_member(segment, "GetEndPoint2"))
        if kind == 1:
            record["center"] = _point(get_com_member(segment, "GetCenterPoint2"))
            record["radius"] = _numbers([get_com_member(segment, "GetRadius")])
        # A full circle has no geometric seam position to preserve.
        if kind == 0 or math.dist(start, end) > 1e-12:
            record.update(start=start, end=end)
        records.append(record)
    return records


def guarded_fully_define_sketch(model, *, tolerance_m, relations_to_apply=EXPLICIT_PROFILE_RELATIONS):
    """Fully define a line/arc/circle sketch and reject unintended solver movement.

    tolerance_m is an explicit numeric comparison tolerance, not a drawing fit or
    manufacturing tolerance. Add design tangency/equality relationships explicitly
    before calling. Other curve types require a task-specific invariant reader.
    A failure leaves the current sketch for diagnosis; it does not silently undo.
    """
    if isinstance(tolerance_m, bool) or not isinstance(tolerance_m, (int, float)) or not math.isfinite(tolerance_m) or tolerance_m <= 0:
        raise ValueError("tolerance_m must be finite and positive")
    active = get_com_member(model.SketchManager, "ActiveSketch")
    if active is None:
        raise ValueError("A sketch must be active")
    segments = list(get_com_member(active, "GetSketchSegments") or [])
    if not segments:
        raise ModelingPreconditionError("SKETCH_GEOMETRY_UNAVAILABLE", {})
    before = _geometry(segments)
    record = fully_define_sketch(model, relations_to_apply=relations_to_apply)
    after = _geometry(segments)
    count_after = len(get_com_member(active, "GetSketchSegments") or [])
    changes = []
    for index, (old, new) in enumerate(zip(before, after)):
        if old.keys() != new.keys() or old["type"] != new["type"]:
            changes.append({"segment": index, "reason": "geometry_kind_changed"})
            continue
        for field in old.keys() - {"type"}:
            delta = max(abs(a - b) for a, b in zip(old[field], new[field]))
            if delta > tolerance_m:
                changes.append({"segment": index, "field": field, "max_delta_m": delta})
    evidence = {"scope": "local_solver_geometry_preservation", "tolerance_m": tolerance_m,
                "relations_to_apply": relations_to_apply, "before": before, "after": after,
                "segment_count_before": len(segments), "segment_count_after": count_after,
                "changes": changes}
    if changes or count_after != len(segments):
        raise ModelingPreconditionError("SKETCH_GEOMETRY_CHANGED", evidence)
    record["geometry_preservation"] = evidence
    return record


def require_closed_contours(sketch, *, expected_count=None):
    """Check closure only, after leaving sketch edit mode and before solid features.

    This does not certify nesting, duplicate entities, intersections, or feature
    suitability. Do not apply to intentional open-profile thin/surface features.
    """
    if expected_count is not None and (isinstance(expected_count, bool) or not isinstance(expected_count, int) or expected_count < 1):
        raise ValueError("expected_count must be a positive integer")
    contours = list(get_com_member(sketch, "GetSketchContours") or [])
    closed = [bool(get_com_member(contour, "IsClosed")) for contour in contours]
    evidence = {"scope": "contour_closure_only", "count": len(contours), "closed": closed,
                "expected_count": expected_count, "nesting_and_intersections_checked": False}
    if not contours or not all(closed) or (expected_count is not None and len(contours) != expected_count):
        raise ModelingPreconditionError("CLOSED_CONTOUR_PRECONDITION_FAILED", evidence)
    return evidence
