#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""capability-gate.py -- 能力层注册表门禁。

回答一个问题：**`Tool/capabilities/*.json` 这张注册表还能不能直接拿来编排？**
判据：
  [1] 每个能力 id 唯一，且与文件名一致
  [2] schema 字段齐全（id/title/inputs/outputs/scripts/refs/maturity/compose）
  [3] maturity ∈ {probe, usable, battle-tested}；probe 必须带 note
  [4] scripts[] 与 refs[] 里的相对路径必须存在（缺失即失败）
  [5] compose[] 指向的 id 必须已注册
  [6] 覆盖矩阵每行必须覆盖全部任务族，取值 ∈ {full, partial, via-compose}

输出 covered / dangling：covered 是自洽可直接编排的能力；dangling 是缺文件、
缺 compose 目标或字段不全的能力（逐项列出缺失物）。

用法:
    python Tool/scripts/capability-gate.py
    python Tool/scripts/capability-gate.py --json
    python Tool/scripts/capability-gate.py --matrix Tool/config/capability-matrix.json
    python Tool/scripts/capability-gate.py --self-test
退出码：0 全绿 / 1 有 dangling 或 schema 错误 / 2 输入缺失。
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import tempfile

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

SCHEMA = "seep.capability-gate/1"
MATRIX_SCHEMA = "seep.capability-matrix/1"
MATURITIES = ("probe", "usable", "battle-tested")
MATRIX_VALUES = ("full", "partial", "via-compose")
REQUIRED = ("id", "title", "inputs", "outputs", "scripts", "refs", "maturity", "compose")
ABS_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\\\\\|/(?:home|Users|etc|var|tmp|opt|mnt|root|usr)/)")
DEFAULT_FAMILIES = ["account-automation", "site-rebuild", "client-license",
                    "reverse-mapping", "firmware", "forensics", "protocol",
                    "supply-chain", "plugin", "malware"]


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return os.path.basename(path)


def validate_capability(obj, stem: str, root: str, ids: set) -> dict:
    problems = []
    if not isinstance(obj, dict):
        return {"id": stem, "problems": ["顶层必须是 JSON 对象"]}
    missing_keys = [k for k in REQUIRED if k not in obj]
    if missing_keys:
        problems.append("缺字段: " + ",".join(missing_keys))
    cid = obj.get("id")
    if not isinstance(cid, str) or not cid.strip():
        problems.append("id 必须是非空字符串")
        cid = stem
    elif cid != stem:
        problems.append("id(%s) 与文件名(%s) 不一致" % (cid, stem))
    for key in ("inputs", "outputs", "scripts", "refs", "compose"):
        if key in obj and not isinstance(obj.get(key), list):
            problems.append("%s 必须是数组" % key)
    maturity = obj.get("maturity")
    if maturity not in MATURITIES:
        problems.append("maturity 必须 ∈ %s，实际 %r" % ("/".join(MATURITIES), maturity))
    if maturity == "probe" and not str(obj.get("note") or "").strip():
        problems.append("probe 能力必须带 note（写清待补脚本与当前手工路径）")

    missing_paths = []
    for key in ("scripts", "refs"):
        for entry in obj.get(key) or []:
            if not isinstance(entry, str) or not entry.strip():
                problems.append("%s[] 存在空项或非字符串" % key)
                continue
            if ABS_PATH_RE.match(entry):
                problems.append("%s 项必须是仓库相对路径: %s" % (key, entry))
                continue
            target = os.path.join(root, entry.replace("/", os.sep))
            if not os.path.isfile(target):
                missing_paths.append(entry)
    unknown_compose = []
    for target in obj.get("compose") or []:
        if not isinstance(target, str) or target not in ids:
            unknown_compose.append(str(target))
    if missing_paths:
        problems.append("缺失文件: " + ",".join(missing_paths))
    if unknown_compose:
        problems.append("compose 指向未注册 id: " + ",".join(unknown_compose))
    return {
        "id": cid,
        "maturity": maturity,
        "problems": problems,
        "missing_paths": missing_paths,
        "unknown_compose": unknown_compose,
    }


def validate_matrix(path: str, ids: set, root: str) -> dict:
    info = {"path": rel(path, root), "present": False, "rows": 0,
            "families": [], "coverage": {v: 0 for v in MATRIX_VALUES},
            "problems": [], "missing_cells": [], "unknown_rows": []}
    if not os.path.isfile(path):
        info["problems"].append("矩阵文件必须存在: %s" % rel(path, root))
        return info
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        info["problems"].append("矩阵读取/解析失败: %s" % str(exc)[:160])
        return info
    if not isinstance(data, dict):
        info["problems"].append("矩阵顶层必须是对象")
        return info
    info["present"] = True
    families = data.get("families")
    if not isinstance(families, list) or not families:
        info["problems"].append("families 必须是非空数组")
        families = DEFAULT_FAMILIES
    info["families"] = list(families)
    rows = data.get("capabilities")
    if not isinstance(rows, dict) or not rows:
        info["problems"].append("capabilities 必须是非空对象")
        return info
    info["rows"] = len(rows)
    for rid, cells in rows.items():
        if rid not in ids:
            info["unknown_rows"].append(rid)
        if not isinstance(cells, dict):
            info["problems"].append("%s 的覆盖值必须是对象" % rid)
            continue
        for family in families:
            if family not in cells:
                info["missing_cells"].append("%s/%s" % (rid, family))
                continue
            value = cells[family]
            if value not in MATRIX_VALUES:
                info["problems"].append("%s/%s 取值必须 ∈ %s，实际 %r"
                                        % (rid, family, "/".join(MATRIX_VALUES), value))
                continue
            info["coverage"][value] += 1
    return info


def run_gate(caps_dir: str, matrix_path: str, root: str) -> dict:
    result = {
        "ok": True,
        "schema": SCHEMA,
        "caps_dir": rel(caps_dir, root),
        "counts": {"capabilities": 0, "covered": 0, "dangling": 0},
        "covered": [],
        "dangling": [],
        "by_maturity": {m: 0 for m in MATURITIES},
        "errors": [],
        "matrix": {},
    }
    files = sorted(glob.glob(os.path.join(caps_dir, "*.json")))
    if not files:
        result["ok"] = False
        result["errors"].append("能力目录必须存在且含 *.json: %s" % rel(caps_dir, root))
        result["matrix"] = validate_matrix(matrix_path, set(), root)
        return result

    objects = []
    seen = {}
    for path in files:
        stem = os.path.splitext(os.path.basename(path))[0]
        try:
            with open(path, "r", encoding="utf-8") as fh:
                obj = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            result["errors"].append("%s 读取/解析失败: %s" % (rel(path, root), str(exc)[:160]))
            obj = None
        objects.append((path, stem, obj))
        if isinstance(obj, dict):
            cid = obj.get("id")
            if isinstance(cid, str):
                seen.setdefault(cid, []).append(rel(path, root))

    ids = set(seen)
    for cid, where in sorted(seen.items()):
        if len(where) > 1:
            result["errors"].append("id 重复: %s（%s）" % (cid, ", ".join(where)))

    result["counts"]["capabilities"] = len(objects)
    for path, stem, obj in objects:
        report = validate_capability(obj, stem, root, ids)
        maturity = report.get("maturity")
        if maturity in result["by_maturity"]:
            result["by_maturity"][maturity] += 1
        if report["problems"]:
            entry = {"id": report["id"], "file": rel(path, root),
                     "problems": report["problems"]}
            if report.get("missing_paths"):
                entry["missing"] = report["missing_paths"]
            if report.get("unknown_compose"):
                entry["unknown_compose"] = report["unknown_compose"]
            result["dangling"].append(entry)
        else:
            result["covered"].append(report["id"])

    result["counts"]["covered"] = len(result["covered"])
    result["counts"]["dangling"] = len(result["dangling"])
    result["matrix"] = validate_matrix(matrix_path, ids, root)
    if result["matrix"].get("problems") or result["matrix"].get("missing_cells") \
            or result["matrix"].get("unknown_rows"):
        result["errors"].extend(result["matrix"]["problems"])
        if result["matrix"].get("missing_cells"):
            result["errors"].append("矩阵缺格: %d 处" % len(result["matrix"]["missing_cells"]))
        if result["matrix"].get("unknown_rows"):
            result["errors"].append("矩阵含未注册能力: " + ",".join(result["matrix"]["unknown_rows"]))
    result["ok"] = not result["dangling"] and not result["errors"]
    return result


def render_text(res: dict) -> str:
    lines = ["capability-gate: %s" % ("PASS" if res["ok"] else "FAIL"),
             "能力 %d / covered %d / dangling %d" % (
                 res["counts"]["capabilities"], res["counts"]["covered"],
                 res["counts"]["dangling"])]
    maturity = ", ".join("%s=%d" % (k, v) for k, v in res["by_maturity"].items())
    lines.append("成熟度: " + maturity)
    for entry in res["dangling"]:
        lines.append("  DANGLING %s <- %s" % (entry["id"], "; ".join(entry["problems"])))
    for err in res["errors"]:
        lines.append("  FAIL %s" % err)
    matrix = res.get("matrix") or {}
    if matrix.get("present"):
        cov = matrix.get("coverage", {})
        lines.append("矩阵 %s: %d 行 × %d 族；%s" % (
            matrix["path"], matrix["rows"], len(matrix["families"]),
            ", ".join("%s=%d" % (k, cov.get(k, 0)) for k in MATRIX_VALUES)))
    return "\n".join(lines)


def self_test() -> int:
    """在临时目录里造夹具，覆盖 covered / dangling / 重复 id / 矩阵缺格。"""
    with tempfile.TemporaryDirectory() as tmp:
        caps = os.path.join(tmp, "capabilities")
        os.makedirs(caps)
        good_a = {"id": "cap-a", "title": "A", "inputs": [], "outputs": [],
                  "scripts": [], "refs": [], "maturity": "usable",
                  "compose": ["cap-b"]}
        good_b = {"id": "cap-b", "title": "B", "inputs": [], "outputs": [],
                  "scripts": [], "refs": [], "maturity": "usable", "compose": []}
        probe_c = {"id": "cap-c", "title": "C", "inputs": [], "outputs": [],
                   "scripts": [], "refs": [], "maturity": "probe",
                   "compose": [], "note": "待补脚本，当前手工完成"}
        dangling_d = {"id": "cap-d", "title": "D", "inputs": [], "outputs": [],
                      "scripts": ["Tool/scripts/does-not-exist.py"], "refs": [],
                      "maturity": "usable", "compose": ["cap-zzz"]}
        plain_e = {"id": "cap-e", "title": "E", "inputs": [], "outputs": [],
                      "scripts": [], "refs": [], "maturity": "usable", "compose": []}
        payloads = {"cap-a.json": good_a, "cap-b.json": good_b, "cap-c.json": probe_c,
                    "cap-d.json": dangling_d, "cap-e.json": plain_e}
        for name, obj in payloads.items():
            with open(os.path.join(caps, name), "w", encoding="utf-8") as fh:
                json.dump(obj, fh, ensure_ascii=False)
        # 重复 id：另建一个文件声明 cap-a
        with open(os.path.join(caps, "cap-a2.json"), "w", encoding="utf-8") as fh:
            json.dump(dict(good_a), fh, ensure_ascii=False)

        families = ["f1", "f2"]
        cells = {f: "full" for f in families}
        matrix = {"schema": MATRIX_SCHEMA, "families": families,
                  "capabilities": {"cap-a": dict(cells), "cap-b": dict(cells),
                                   "cap-d": dict(cells), "cap-e": dict(cells),
                                   "cap-c": {"f1": "partial"}}}
        matrix_path = os.path.join(tmp, "matrix.json")
        with open(matrix_path, "w", encoding="utf-8") as fh:
            json.dump(matrix, fh, ensure_ascii=False)

        res = run_gate(caps, matrix_path, tmp)
        checks = [
            (res["counts"]["capabilities"] == 6, "fixture count"),
            (res["counts"]["covered"] == 4, "covered set"),
            (set(res["covered"]) == {"cap-a", "cap-b", "cap-c", "cap-e"}, "covered ids"),
            (res["counts"]["dangling"] == 2, "dangling set"),
            (any("缺失文件" in "; ".join(e["problems"]) for e in res["dangling"]),
             "missing script reported"),
            (any("compose" in "; ".join(e["problems"]) for e in res["dangling"]),
             "unknown compose reported"),
            (any("id 重复" in e for e in res["errors"]), "duplicate id reported"),
            (res["by_maturity"]["probe"] == 1, "maturity tally"),
            (res["matrix"]["present"] is True, "matrix read"),
            (len(res["matrix"]["missing_cells"]) == 1, "matrix gap reported"),
            (res["ok"] is False, "gate fails on gaps"),
        ]

        # 干净夹具必须通过
        clean = os.path.join(tmp, "clean")
        os.makedirs(clean)
        for name, obj in (("cap-a.json", good_a), ("cap-b.json", good_b)):
            with open(os.path.join(clean, name), "w", encoding="utf-8") as fh:
                json.dump(obj, fh, ensure_ascii=False)
        clean_matrix = os.path.join(tmp, "clean-matrix.json")
        with open(clean_matrix, "w", encoding="utf-8") as fh:
            json.dump({"schema": MATRIX_SCHEMA, "families": families,
                       "capabilities": {"cap-a": dict(cells), "cap-b": dict(cells)}},
                      fh, ensure_ascii=False)
        clean_res = run_gate(clean, clean_matrix, tmp)
        checks.append((clean_res["ok"] is True, "clean fixture passes"))
        checks.append((render_text(clean_res).startswith("capability-gate: PASS"),
                       "text renderer"))

        for passed, label in checks:
            if not passed:
                print(json.dumps({"ok": False, "blocked_at": "self-test",
                                  "reason": "assertion failed: %s" % label},
                                 ensure_ascii=False))
                return 2
        print(json.dumps({"ok": True, "checks": len(checks),
                          "tool": "capability-gate.py",
                          "fixtures": {"dirty": 6, "clean": 2}}, ensure_ascii=False))
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="能力层注册表门禁：校验 scripts/refs 必须存在、id 唯一、compose 可解析、矩阵完整")
    root_default = repo_root()
    ap.add_argument("--root", default=None,
                    help="仓库根（默认按本脚本位置推断，通常无需指定）")
    ap.add_argument("--caps-dir", default=None, help="能力目录（默认 <root>/Tool/capabilities）")
    ap.add_argument("--matrix", default=None, help="覆盖矩阵（默认 <root>/Tool/config/capability-matrix.json）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--self-test", action="store_true", help="临时夹具自测")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    root = os.path.abspath(args.root) if args.root else root_default
    caps_dir = os.path.abspath(args.caps_dir) if args.caps_dir else os.path.join(root, "Tool", "capabilities")
    matrix = (os.path.abspath(args.matrix) if args.matrix
              else os.path.join(root, "Tool", "config", "capability-matrix.json"))
    if not os.path.isdir(caps_dir):
        msg = {"ok": False, "blocked_at": "caps-dir",
               "reason": "能力目录必须存在: %s" % rel(caps_dir, root)}
        print(json.dumps(msg, ensure_ascii=False) if args.json else msg["reason"])
        return 2
    res = run_gate(caps_dir, matrix, root)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(render_text(res))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
