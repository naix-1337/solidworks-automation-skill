"""@brief 受保护 Runner 的 OCCT 真实 STEP 自检，不依赖 Agent 产物。"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.cad_evidence_verifier import _shape_measurement  # noqa: E402


def main() -> int:
    try:
        from OCP.BRepAlgoAPI import BRepAlgoAPI_Cut
        from OCP.BRepPrimAPI import BRepPrimAPI_MakeBox, BRepPrimAPI_MakeCylinder
        from OCP.IFSelect import IFSelect_RetDone
        from OCP.STEPControl import STEPControl_AsIs, STEPControl_Writer
        from OCP.gp import gp_Ax2, gp_Dir, gp_Pnt

        box = BRepPrimAPI_MakeBox(
            gp_Pnt(-30.0, -20.0, -6.0),
            60.0,
            40.0,
            12.0,
        ).Shape()
        hole = BRepPrimAPI_MakeCylinder(
            gp_Ax2(gp_Pnt(0.0, 0.0, -20.0), gp_Dir(0.0, 0.0, 1.0)),
            5.0,
            40.0,
        ).Shape()
        cut = BRepAlgoAPI_Cut(box, hole)
        cut.Build()
        if not cut.IsDone():
            raise RuntimeError("OCCT 布尔切除失败")
        shape = cut.Shape()
        measured = _shape_measurement(shape)
        with tempfile.TemporaryDirectory(prefix="cad-occt-selftest-") as temporary:
            step_path = Path(temporary) / "selftest.step"
            writer = STEPControl_Writer()
            if writer.Transfer(shape, STEPControl_AsIs) != IFSelect_RetDone or writer.Write(str(step_path)) != IFSelect_RetDone:
                raise RuntimeError("OCCT STEP 写入失败")
            if not step_path.is_file() or step_path.stat().st_size <= 0:
                raise RuntimeError("OCCT STEP 产物为空")
        expected_envelope = [12000, 40000, 60000]
        expected_hole = any(
            abs(int(item["diameterUm"]) - 10000) <= 1
            and int(item["count"]) == 1
            for item in measured["holes"]
        )
        if sorted(measured["envelopeUm"]) != expected_envelope or not expected_hole or measured["validSolids"] < 1:
            raise RuntimeError(f"OCCT 自检测量不一致: {measured}")
        print(
            json.dumps(
                {
                    "status": "pass",
                    "envelopeUm": measured["envelopeUm"],
                    "holes": measured["holes"],
                    "geometryFingerprintSha256": measured["geometryFingerprintSha256"],
                },
                ensure_ascii=False,
            )
        )
        return 0
    except Exception as exc:  # noqa: BLE001 - Runner 自检必须 fail closed
        print(json.dumps({"status": "blocked", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
