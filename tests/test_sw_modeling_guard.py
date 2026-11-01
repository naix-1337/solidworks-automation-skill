"""Process-level regression checks; these tests do not certify CAD dimensions."""
from types import SimpleNamespace as NS

import pytest

from scripts import sw_modeling_guard as guard
from scripts.sw_sketch_quality import fully_define_sketch


class Preferences:
    def __init__(self, value=True):
        self.value = value
        self.history = []

    def GetUserPreferenceToggle(self, option):
        assert option == 10
        return self.value

    def SetUserPreferenceToggle(self, option, value):
        self.history.append(value)
        self.value = value
        return True


@pytest.mark.parametrize("initial", [False, True])
def test_dimension_input_preference_restores_original_on_failure(initial):
    app = Preferences(initial)
    with pytest.raises(RuntimeError, match="dimension operation failed"):
        with guard.dimension_input_guard(app):
            assert app.value is False
            raise RuntimeError("dimension operation failed")
    assert app.value is initial
    assert app.history == [False, initial]


def test_nested_input_guards_restore_each_prior_value():
    app = Preferences()
    with guard.dimension_input_guard(app):
        with guard.dimension_input_guard(app):
            assert app.value is False
        assert app.value is False
    assert app.value is True


def test_dimension_operation_never_runs_when_preference_cannot_be_disabled():
    app = Preferences()
    app.SetUserPreferenceToggle = lambda *args: False
    entered = []
    with pytest.raises(guard.ModelingPreconditionError):
        with guard.dimension_input_guard(app):
            entered.append(True)
    assert entered == []
    assert app.value is True


def test_restore_failure_is_reported():
    app = Preferences()
    original = app.SetUserPreferenceToggle
    app.SetUserPreferenceToggle = lambda option, value: False if value else original(option, value)
    with pytest.raises(guard.ModelingPreconditionError) as error:
        with guard.dimension_input_guard(app):
            pass
    assert error.value.code == "DIMENSION_PREFERENCE_NOT_APPLIED"


def point(x, y):
    return NS(X=x, Y=y, Z=0.0)


def line():
    return NS(GetType=lambda: 0, GetStartPoint2=point(0.0, 0.012),
              GetEndPoint2=point(0.018, 0.017))


def circle():
    seam = point(0.007, 0.03)
    return NS(GetType=lambda: 1, GetStartPoint2=seam, GetEndPoint2=seam,
              GetCenterPoint2=point(0, 0.03), GetRadius=0.007)


def model_for(*segments):
    sketch = NS(GetSketchSegments=lambda: list(segments))
    return NS(SketchManager=NS(ActiveSketch=sketch))


def test_guard_accepts_stable_geometry_and_passes_requested_relations(monkeypatch):
    seen = []
    monkeypatch.setattr(guard, "fully_define_sketch", lambda model, **kwargs: seen.append(kwargs) or {"status": "pass"})
    result = guard.guarded_fully_define_sketch(model_for(line(), circle()), tolerance_m=1e-8)
    assert result["status"] == "pass"
    assert result["geometry_preservation"]["changes"] == []
    assert seen == [{"relations_to_apply": 518}]


@pytest.mark.parametrize("field", ["line_endpoint", "circle_radius", "circle_center"])
def test_fully_constrained_state_cannot_hide_solver_geometry_changes(monkeypatch, field):
    segment = line() if field == "line_endpoint" else circle()
    def solve(model, **kwargs):
        if field == "line_endpoint":
            segment.GetStartPoint2.Y = 0.0125
        elif field == "circle_radius":
            segment.GetRadius += 0.0005
        else:
            segment.GetCenterPoint2.Y += 0.0005
        return {"status": "pass", "constrained_status": 3}
    monkeypatch.setattr(guard, "fully_define_sketch", solve)
    with pytest.raises(guard.ModelingPreconditionError) as error:
        guard.guarded_fully_define_sketch(model_for(segment), tolerance_m=1e-8)
    assert error.value.code == "SKETCH_GEOMETRY_CHANGED"
    assert error.value.evidence["changes"]


def test_full_circle_seam_rotation_is_not_geometry_drift(monkeypatch):
    segment = circle()
    def solve(model, **kwargs):
        segment.GetStartPoint2 = segment.GetEndPoint2 = point(0, 0.037)
        return {"status": "pass"}
    monkeypatch.setattr(guard, "fully_define_sketch", solve)
    guard.guarded_fully_define_sketch(model_for(segment), tolerance_m=1e-8)


def test_changed_segment_count_is_rejected(monkeypatch):
    model = model_for(line())
    def solve(model, **kwargs):
        model.SketchManager.ActiveSketch.GetSketchSegments = lambda: [line(), line()]
        return {"status": "pass"}
    monkeypatch.setattr(guard, "fully_define_sketch", solve)
    with pytest.raises(guard.ModelingPreconditionError, match="SKETCH_GEOMETRY_CHANGED"):
        guard.guarded_fully_define_sketch(model, tolerance_m=1e-8)


def test_unsupported_geometry_blocks_before_solver_mutation(monkeypatch):
    called = []
    monkeypatch.setattr(guard, "fully_define_sketch", lambda *args, **kwargs: called.append(True))
    with pytest.raises(guard.ModelingPreconditionError, match="UNSUPPORTED_GEOMETRY_GUARD"):
        guard.guarded_fully_define_sketch(model_for(NS(GetType=3)), tolerance_m=1e-8)
    assert called == []


@pytest.mark.parametrize("tolerance", [0, -1, float("nan"), float("inf"), True])
def test_invalid_tolerance_fails_before_solver(tolerance):
    with pytest.raises(ValueError):
        guard.guarded_fully_define_sketch(None, tolerance_m=tolerance)


@pytest.mark.parametrize("closed,expected", [([], None), ([False], None), ([True, False], 2), ([True], 2)])
def test_missing_open_or_unexpected_contours_block_dependent_feature(closed, expected):
    sketch = NS(GetSketchContours=lambda: [NS(IsClosed=value) for value in closed])
    with pytest.raises(guard.ModelingPreconditionError) as error:
        guard.require_closed_contours(sketch, expected_count=expected)
    assert error.value.code == "CLOSED_CONTOUR_PRECONDITION_FAILED"


def test_closed_contours_do_not_claim_nesting_or_intersection_verification():
    sketch = NS(GetSketchContours=lambda: [NS(IsClosed=True), NS(IsClosed=True)])
    result = guard.require_closed_contours(sketch, expected_count=2)
    assert result["count"] == 2
    assert result["nesting_and_intersections_checked"] is False


def test_fully_define_supports_dimension_only_without_changing_existing_default():
    dim = NS(GetNameForSelection=lambda: "D1@Sketch1")
    relation = NS(GetRelationType=lambda: 1, GetDisplayDimension=lambda: dim)
    active = NS(GetConstrainedStatus=lambda: 3, RelationManager=NS(GetRelations=lambda _: [relation]))
    calls = []
    model = NS(SketchManager=NS(ActiveSketch=active, FullyDefineSketch=lambda *args: calls.append(args) or 0),
               Extension=NS(SelectByID2=lambda *args: True), ClearSelection2=lambda _: None)
    fully_define_sketch(model)
    fully_define_sketch(model, relations_to_apply=0)
    assert calls[0][1:3] == (True, 1023)
    assert calls[1][1:3] == (False, 0)


@pytest.mark.parametrize("mask", [-1, 1024, True, "518"])
def test_invalid_relation_mask_rejected_before_model_mutation(mask):
    with pytest.raises(ValueError):
        fully_define_sketch(None, relations_to_apply=mask)
