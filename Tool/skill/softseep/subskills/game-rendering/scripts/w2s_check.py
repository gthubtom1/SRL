#!/usr/bin/env python3
"""Bounded offline world-to-screen geometry checker; standard library only."""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import sys

MAX_BYTES = 1048576
MAX_POINTS = 4096
EPS = 1e-9


def number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("coordinates and matrix entries must be numbers")
    if not math.isfinite(value) or abs(value) > 1e12:
        raise ValueError("number must be finite and abs <= 1e12")
    return float(value)


def reject_constant(value):
    raise ValueError("non-finite JSON constant: " + value)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def load(path):
    with Path(path).open("rb") as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("input exceeds 1 MiB")
    return json.loads(raw, parse_constant=reject_constant,
                      object_pairs_hook=unique_object), hashlib.sha256(raw).hexdigest()


def check(data):
    if not isinstance(data, dict):
        raise ValueError("root must be an object")
    required = {"project", "version", "run", "matrix", "layout", "vector",
                "clip_z", "viewport", "points"}
    if set(data) != required:
        raise ValueError("required keys: " + ", ".join(sorted(required)))
    for key in ("project", "version", "run"):
        value = data[key]
        if not isinstance(value, str) or not 1 <= len(value) <= 128 or not value.strip():
            raise ValueError(key + " must be a nonblank string of 1..128 characters")
    if data["layout"] not in ("row-major", "column-major"):
        raise ValueError("layout must be row-major or column-major")
    if data["vector"] not in ("column", "row"):
        raise ValueError("vector must be column or row")
    if data["clip_z"] not in ("zero-to-one", "minus-one-to-one"):
        raise ValueError("invalid clip_z")
    flat = data["matrix"]
    if not isinstance(flat, list) or len(flat) != 16:
        raise ValueError("matrix must contain exactly 16 numbers")
    flat = [number(v) for v in flat]
    matrix = [[flat[r * 4 + c] if data["layout"] == "row-major"
               else flat[c * 4 + r] for c in range(4)] for r in range(4)]
    vp = data["viewport"]
    if not isinstance(vp, dict) or set(vp) != {"x", "y", "width", "height", "origin"}:
        raise ValueError("viewport requires x,y,width,height,origin")
    x, y, width, height = [number(vp[k]) for k in ("x", "y", "width", "height")]
    if not 0 < width <= 1e6 or not 0 < height <= 1e6:
        raise ValueError("viewport width/height must be in (0, 1e6]")
    if vp["origin"] not in ("top-left", "bottom-left"):
        raise ValueError("invalid viewport origin")
    points = data["points"]
    if not isinstance(points, list) or not 1 <= len(points) <= MAX_POINTS:
        raise ValueError("points must contain 1..4096 xyz arrays")
    result = []
    for index, point in enumerate(points):
        if not isinstance(point, list) or len(point) != 3:
            raise ValueError("each point must contain exactly xyz")
        v = [number(value) for value in point] + [1.0]
        if data["vector"] == "column":
            clip = [sum(matrix[r][c] * v[c] for c in range(4)) for r in range(4)]
        else:
            clip = [sum(v[r] * matrix[r][c] for r in range(4)) for c in range(4)]
        if not all(math.isfinite(value) for value in clip):
            raise ValueError("non-finite clip result")
        cx, cy, cz, w = clip
        reasons, ndc, screen = [], None, None
        if abs(w) <= EPS:
            reasons.append("zero_or_near_zero_w")
        elif w < 0:
            reasons.append("behind_camera_negative_w")
        else:
            ndc = [cx / w, cy / w, cz / w]
            if cx < -w: reasons.append("left")
            if cx > w: reasons.append("right")
            if cy < -w: reasons.append("bottom")
            if cy > w: reasons.append("top")
            if cz < (0 if data["clip_z"] == "zero-to-one" else -w):
                reasons.append("z_below_clip_min")
            if cz > w: reasons.append("z_above_clip_max")
            sx = x + (ndc[0] + 1) * width / 2
            sy = y + ((1 - ndc[1]) if vp["origin"] == "top-left"
                      else (1 + ndc[1])) * height / 2
            screen = [sx, sy]
        result.append({"index": index, "clip": clip, "ndc": ndc,
                       "screen": screen, "visible": not reasons,
                       "behind": w < -EPS, "reasons": reasons})
    return {"project": data["project"], "version": data["version"], "run": data["run"],
            "scope": "geometry_only_no_occlusion_or_rendering", "results": result}


def example():
    return {"project": "synthetic", "version": "fixture-v1", "run": "geometry-01",
            "matrix": [1, 0, 0, .25, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1],
            "layout": "row-major", "vector": "column", "clip_z": "zero-to-one",
            "viewport": {"x": 0, "y": 0, "width": 800, "height": 600,
                         "origin": "top-left"}, "points": [[0, 0, .5]]}


def self_test():
    passed = []
    def expect(name, condition):
        if not condition:
            raise AssertionError(name)
        passed.append(name)
    def first(d):
        return check(d)["results"][0]
    base = example()
    expect("translated_point_500_300", first(base)["screen"] == [500, 300])
    transposed = [base["matrix"][c * 4 + r] for r in range(4) for c in range(4)]
    d = copy.deepcopy(base); d["matrix"] = transposed
    expect("wrong_transpose_changes_point", first(d)["screen"] != [500, 300])
    d["layout"] = "column-major"
    expect("column_major_equivalent", first(d)["screen"] == [500, 300])
    d["layout"] = "row-major"; d["vector"] = "row"
    expect("row_vector_equivalent", first(d)["screen"] == [500, 300])
    d = copy.deepcopy(base); d["viewport"].update(width=1600, height=1200)
    expect("resize_reprojects_1000_600", first(d)["screen"] == [1000, 600])
    d = copy.deepcopy(base); d["matrix"][15] = -1
    expect("negative_w_behind_no_screen", first(d)["behind"] and first(d)["screen"] is None)
    d["matrix"][15] = 0
    expect("zero_w_no_division", first(d)["reasons"] == ["zero_or_near_zero_w"])
    d = copy.deepcopy(base); d["points"] = [[2, 0, .5], [0, 0, -.5], [0, 0, 2]]
    rows = check(d)["results"]
    expect("right_clip", rows[0]["reasons"] == ["right"])
    expect("z_min_clip", rows[1]["reasons"] == ["z_below_clip_min"])
    expect("z_max_clip", rows[2]["reasons"] == ["z_above_clip_max"])
    d["clip_z"] = "minus-one-to-one"
    expect("minus_one_depth_accepts", check(d)["results"][1]["visible"])
    d = copy.deepcopy(base); d["points"] = [[0, .5, .5]]
    d["viewport"].update(x=10, y=20, origin="bottom-left")
    expect("bottom_left_with_offset", first(d)["screen"] == [510, 470])
    d = copy.deepcopy(base)
    d["matrix"] = [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, -1, 0, 0, 1, 0]
    d["points"] = [[1, 0, 2], [1, 0, 4], [0, 0, -2], [0, 0, 0]]
    rows = check(d)["results"]
    expect("perspective_distance_changes_screen", rows[0]["screen"] == [600, 300]
           and rows[1]["screen"] == [500, 300])
    expect("perspective_behind_and_camera_plane", rows[2]["behind"]
           and rows[3]["reasons"] == ["zero_or_near_zero_w"])
    for name, change in (
        ("nan_matrix_rejected", lambda d: d["matrix"].__setitem__(0, float("nan"))),
        ("infinite_point_rejected", lambda d: d["points"][0].__setitem__(0, float("inf"))),
        ("zero_viewport_rejected", lambda d: d["viewport"].update(width=0)),
        ("oversized_points_rejected", lambda d: d.update(points=[[0, 0, 0]] * 4097)),
        ("boolean_coordinate_rejected", lambda d: d["points"][0].__setitem__(0, True)),
    ):
        d = copy.deepcopy(base); change(d)
        try:
            check(d)
        except ValueError:
            passed.append(name)
        else:
            raise AssertionError(name)
    for raw in ('{"x":NaN}', '{"x":1,"x":2}'):
        try:
            json.loads(raw, parse_constant=reject_constant, object_pairs_hook=unique_object)
        except ValueError:
            passed.append("invalid_json_rejected:" + raw)
        else:
            raise AssertionError(raw)
    return {"passed": len(passed), "checks": passed,
            "scope": "synthetic geometry; no engine, hook, overlay, or device tested"}


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, '{"ok":false,"reason":"invalid arguments; use --help"}\n')


def main():
    parser = SafeParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--input", metavar="JSON", help="local JSON file, <=1 MiB, <=4096 points")
    action.add_argument("--self-test", action="store_true", help="run synthetic positive/negative checks")
    action.add_argument("--example", action="store_true", help="print a valid synthetic input")
    args = parser.parse_args()
    try:
        if args.self_test:
            output = self_test()
        elif args.example:
            output = example()
        else:
            data, digest = load(args.input)
            output = check(data)
            output["input_sha256"] = digest
        print(json.dumps(output, ensure_ascii=False, allow_nan=False, indent=2))
        return 0
    except (ValueError, TypeError, OverflowError, RecursionError, OSError, AssertionError) as error:
        print(json.dumps({"error": str(error), "status": "failed"}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
