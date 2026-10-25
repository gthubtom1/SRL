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
  [7] 每个能力 id 必须被 ≥1 份配方引用，或在 JSON 里显式标 `reserved: true`
      「被引用」拆三类报告（ok 判定不变）：
        referenced_by_id      配方 `用到的能力` 行里出现该 `capability id` 本身（精确匹配）
        referenced_by_script  只命中 `repo:<脚本stem>` 或脚本路径（脚本别名，非 id 引用）
        reserved              JSON 里 reserved:true（既未引用也没上线）
  [8] compose[] 必须构成 DAG（检测并报出环路径）

输出 covered / dangling：covered 是自洽可直接编排的能力；dangling 是缺文件、
缺 compose 目标、字段不全或既未被引用又未 reserved 的能力（逐项列出缺失物）。

矩阵不手填：`--emit-matrix` 会按能力自带 domain + compose 闭包重算 9 域矩阵。

用法:
    python Tool/skill/softseep/scripts/capability-gate.py
    python Tool/skill/softseep/scripts/capability-gate.py --json
    python Tool/skill/softseep/scripts/capability-gate.py --matrix Tool/config/capability-matrix.json
    python Tool/skill/softseep/scripts/capability-gate.py --emit-matrix
    python Tool/skill/softseep/scripts/capability-gate.py --self-test
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

# 9 个客户域（与 Tool/scripts/lib/domain_spec.py 的 DOMAINS 一致）。
# 旧名 ad-cloud / plugin-targets / site-clone 已迁出（不再是客户域），
# reverse 已并入 softseep（同一 skill / 同一路由包）。
DOMAIN_ORDER = ["apkseep", "firmware-iot", "web-pentest", "pwn-crypto",
                "protocol-plugin", "forensics-mobile", "malware-analysis",
                "supply-chain-security", "softseep"]
DEFAULT_FAMILIES = DOMAIN_ORDER

# 旧域名兼容（**逐份报出，不静默**）：
#   * DOMAIN_ALIASES：只是改名，归一后有客户域归宿（reverse → softseep）；
#   * LEGACY_DOMAINS：已整体迁出，客户域里没有归宿，但 Tool/capabilities/*.json
#     里仍有这些 domain 值（迁移不在本次改动范围内）。两者都接受，
#     但 run_gate 会列在 legacy_domains 里，render_text 也会打一行。
# 拼错/自造域名（既不在 9 域、也不在上面两张表）仍然判红。
DOMAIN_ALIASES = {"reverse": "softseep"}
LEGACY_DOMAINS = ("ad-cloud", "plugin-targets", "site-clone")

# 域间相邻关系：能力对本域=full，对相邻域=partial，其余=via-compose。
DOMAIN_ADJACENCY = {
    "apkseep": {"forensics-mobile", "softseep", "firmware-iot"},
    "firmware-iot": {"softseep", "forensics-mobile", "protocol-plugin", "apkseep"},
    "web-pentest": {"pwn-crypto", "protocol-plugin", "supply-chain-security", "softseep"},
    "pwn-crypto": {"web-pentest", "softseep", "protocol-plugin", "apkseep"},
    "protocol-plugin": {"web-pentest", "firmware-iot", "softseep", "pwn-crypto"},
    "forensics-mobile": {"malware-analysis", "softseep", "firmware-iot", "apkseep"},
    "malware-analysis": {"forensics-mobile", "softseep", "supply-chain-security"},
    "supply-chain-security": {"web-pentest", "softseep", "malware-analysis", "firmware-iot"},
    "softseep": {"protocol-plugin", "forensics-mobile", "malware-analysis",
                "pwn-crypto", "firmware-iot", "web-pentest",
                "supply-chain-security", "apkseep"},
}


def repo_root() -> str:
    """仓库根：向上找含 Tool/cases 的目录（S4 后位于 Tool/skill/<pack>/scripts/）。"""
    d = os.path.abspath(os.path.dirname(__file__))
    for _ in range(8):
        if os.path.isdir(os.path.join(d, "Tool", "cases")):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))


def compose_cycles(objects) -> list:
    """返回 compose 图里的环（每条环是 id 列表，首尾相同）。"""
    graph = {}
    for path, stem, obj in objects:
        if not isinstance(obj, dict):
            continue
        cid = obj.get("id") if isinstance(obj.get("id"), str) else stem
        graph[cid] = [t for t in (obj.get("compose") or []) if isinstance(t, str)]
    color = {}
    stack = []
    cycles = []
    seen = set()

    def dfs(node):
        color[node] = 1
        stack.append(node)
        for nxt in graph.get(node, []):
            if nxt not in graph:
                continue
            if color.get(nxt, 0) == 0:
                dfs(nxt)
            elif color.get(nxt) == 1:
                pos = stack.index(nxt)
                cycle = stack[pos:] + [nxt]
                key = tuple(cycle)
                if key not in seen:
                    seen.add(key)
                    cycles.append(cycle)
        stack.pop()
        color[node] = 2

    for node in graph:
        if color.get(node, 0) == 0:
            dfs(node)
    return cycles


def _playbook_texts(playbooks_dir: str):
    texts = []
    if os.path.isdir(playbooks_dir):
        for path in sorted(glob.glob(os.path.join(playbooks_dir, "*.md"))):
            if os.path.basename(path).lower() in ("index.md", "readme.md"):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    texts.append((os.path.basename(path), fh.read()))
            except OSError:
                continue
    return texts


NS_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*:")


def recipe_capability_refs(objects, playbooks_dir: str):
    """按「配方 `用到的能力` 行」分类引用（返回 (by_id, by_script)，无配方时 None）。

    血案：旧版拿脚本 basename 在整个配方正文里做子串匹配，步骤里提一句脚本就算
    “被引用”，47 个能力里真正按 id 被 `用到的能力` 行引用的只有 8 个，gate 却报 27。

    by_id:     `用到的能力` 行的反引号 token 中，裸 id 或 `<命名空间>:<id>` 的 id 部分精确等于能力 id。
    by_script: 同一行里命中 `repo:<脚本 stem>` 或命中脚本 stem（脚本别名，不是 id 引用）。
    两者互斥：命中 id 就只计 by_id（脚本别名不再重复计）。
    """
    texts = _playbook_texts(playbooks_dir)
    if not texts:
        # 没有配方目录（例如 forge 的临时 stage）：此时无从判断引用，不误杀。
        return None
    tokens = {}
    for name, text in texts:
        toks = []
        for line in text.splitlines():
            if "用到的能力" in line:
                toks.extend(re.findall(r"`([^`]+)`", line))
        tokens[name] = toks
    by_id, by_script = {}, {}
    for path, stem, obj in objects:
        if not isinstance(obj, dict):
            continue
        cid = obj.get("id") if isinstance(obj.get("id"), str) else stem
        stems = set()
        for script in obj.get("scripts") or []:
            if isinstance(script, str) and script.strip():
                stems.add(os.path.splitext(os.path.basename(script.replace("\\", "/")))[0])
        id_hits, script_hits = [], []
        for name, toks in tokens.items():
            bases = [t.split(":", 1)[1] if NS_RE.match(t) else t for t in toks]
            if cid in toks or cid in bases:
                id_hits.append(name)
            elif any(t.startswith("repo:") and t.split(":", 1)[1] in stems for t in toks) \
                    or any(st and st in t for t in toks for st in stems):
                script_hits.append(name)
        if id_hits:
            by_id[cid] = id_hits
        elif script_hits:
            by_script[cid] = script_hits
    return by_id, by_script


def recipe_references(objects, playbooks_dir: str) -> dict:
    """找出被 ≥1 份配方引用的能力 id（宽松口径，仅用于 ok 判定）。

    引用形态（任一即算）：
      * 配方里出现裸 id（词边界）；
      * 命名空间写法 repo:/apk:/tool:/mcp:<id>（裸 id 词边界已覆盖）；
      * 配方步骤里出现能力 scripts[] 的脚本 basename。
    分类统计用 recipe_capability_refs（只认 `用到的能力` 行，id 优先）。
    """
    texts = _playbook_texts(playbooks_dir)
    if not texts:
        return None
    refs = {}
    for path, stem, obj in objects:
        if not isinstance(obj, dict):
            continue
        cid = obj.get("id") if isinstance(obj.get("id"), str) else stem
        names = {cid}
        for script in obj.get("scripts") or []:
            if isinstance(script, str) and script.strip():
                names.add(os.path.splitext(os.path.basename(script.replace("\\", "/")))[0])
        hits = []
        for name, text in texts:
            for token in names:
                pat = r"(?<![a-z0-9_-])" + re.escape(token) + r"(?![a-z0-9_-])"
                if re.search(pat, text, re.IGNORECASE):
                    hits.append(name)
                    break
        if hits:
            refs[cid] = hits
    return refs


def reachable_domains(cid, caps: dict, memo: dict) -> set:
    if cid in memo:
        return memo[cid]
    memo[cid] = set()
    out = set()
    for nxt in (caps.get(cid) or {}).get("compose") or []:
        if nxt not in caps or nxt == cid:
            continue
        out.add((caps[nxt] or {}).get("domain"))
        out |= reachable_domains(nxt, caps, memo)
    memo[cid] = out
    return out


def emit_matrix(caps: dict, path: str) -> dict:
    """从能力自带 domain + compose 闭包生成 9 域覆盖矩阵（不手填）。"""
    memo = {}
    rows = {}
    tally = {v: 0 for v in MATRIX_VALUES}
    for cid in sorted(caps):
        obj = caps[cid] or {}
        dom = obj.get("domain")
        reach = reachable_domains(cid, caps, memo)
        cells = {}
        for family in DOMAIN_ORDER:
            if dom == family:
                value = "full"
            elif family in DOMAIN_ADJACENCY.get(dom, set()) \
                    or dom in DOMAIN_ADJACENCY.get(family, set()) \
                    or family in reach:
                value = "partial"
            else:
                value = "via-compose"
            cells[family] = value
            tally[value] += 1
        rows[cid] = cells
    data = {
        "schema": MATRIX_SCHEMA,
        "generated_at": "1970-01-01T00:00:00Z",
        "generator": "Tool/skill/softseep/scripts/capability-gate.py --emit-matrix",
        "source": "Tool/capabilities/*.json",
        "families": list(DOMAIN_ORDER),
        "values": list(MATRIX_VALUES),
        "notes": "full=能力本域直接覆盖；partial=相邻域或经 compose 可达；via-compose=需与其它能力组合后覆盖",
        "capabilities": rows,
    }
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return {"path": path, "rows": len(rows), "families": len(DOMAIN_ORDER),
            "cells": tally}


def rel(path: str, root: str) -> str:
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return os.path.basename(path)


def validate_capability(obj, stem: str, root: str, ids: set,
                        referenced: set | None = None) -> dict:
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
    for key in ("triggers", "aliases"):
        if key in obj and not isinstance(obj.get(key), list):
            problems.append("%s 必须是数组" % key)
    if "domain" in obj and obj.get("domain") not in DOMAIN_ORDER:
        # 旧名：改名（DOMAIN_ALIASES）与迁出（LEGACY_DOMAINS）都接受，但必须被报出。
        # 既不是 9 域也不是已知旧名 = 拼错/自造 → 仍然红。
        dom = obj.get("domain")
        if dom not in DOMAIN_ALIASES and dom not in LEGACY_DOMAINS:
            problems.append("domain 必须 ∈ %s，实际 %r"
                            % ("/".join(DOMAIN_ORDER), dom))
    if "version" in obj and not str(obj.get("version") or "").strip():
        problems.append("version 必须是非空字符串")
    if "reserved" in obj and not isinstance(obj.get("reserved"), bool):
        problems.append("reserved 必须是布尔值")
    if referenced is not None and cid not in referenced and obj.get("reserved") is not True:
        problems.append("未被任何配方引用且未标 reserved:true")

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
        "domain": obj.get("domain"),
        "domain_norm": DOMAIN_ALIASES.get(obj.get("domain"), obj.get("domain")),
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


def run_gate(caps_dir: str, matrix_path: str, root: str,
             playbooks_dir: str | None = None) -> dict:
    if playbooks_dir is None:
        playbooks_dir = os.path.join(root, "Tool", "playbooks")
    result = {
        "ok": True,
        "schema": SCHEMA,
        "caps_dir": rel(caps_dir, root),
        "counts": {"capabilities": 0, "covered": 0, "dangling": 0,
                   "referenced": 0, "referenced_by_id": 0,
                   "referenced_by_script": 0, "reserved": 0, "cycles": 0,
                   "legacy_domain": 0},
        "covered": [],
        "dangling": [],
        "by_maturity": {m: 0 for m in MATURITIES},
        "legacy_domains": {},
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
    refs = recipe_references(objects, playbooks_dir)
    result["references"] = ({cid: where for cid, where in sorted(refs.items())}
                            if refs is not None else {})
    cycles = compose_cycles(objects)
    result["counts"]["cycles"] = len(cycles)
    for cycle in cycles:
        result["errors"].append("compose 必须是 DAG，检测到环: " + " -> ".join(cycle))
    referenced = set(refs) if refs is not None else None
    result["counts"]["referenced"] = len(referenced or ())
    # 三类拆分：id 精确引用 / 脚本别名 / reserved（ok 判定仍只看 referenced ∪ reserved）。
    classified = recipe_capability_refs(objects, playbooks_dir)
    by_id, by_script = ({}, {}) if classified is None else classified
    if referenced is not None:
        by_id = {cid: where for cid, where in by_id.items() if cid in referenced}
        by_script = {cid: where for cid, where in by_script.items() if cid in referenced}
        for cid in referenced - set(by_id) - set(by_script):
            # 只在步骤正文里出现脚本名/路径（宽松口径已命中）→ 归脚本别名。
            by_script[cid] = list((refs or {}).get(cid) or [])
    result["references_by_id"] = {cid: where for cid, where in sorted(by_id.items())}
    result["references_by_script"] = {cid: where for cid, where in sorted(by_script.items())}
    result["counts"]["referenced_by_id"] = len(by_id)
    result["counts"]["referenced_by_script"] = len(by_script)
    result["counts"]["reserved"] = sum(
        1 for _, _, obj in objects
        if isinstance(obj, dict) and obj.get("reserved") is True)
    for path, stem, obj in objects:
        report = validate_capability(obj, stem, root, ids, referenced)
        maturity = report.get("maturity")
        if maturity in result["by_maturity"]:
            result["by_maturity"][maturity] += 1
        dom = report.get("domain")
        if isinstance(dom, str) and dom not in DOMAIN_ORDER \
                and (dom in DOMAIN_ALIASES or dom in LEGACY_DOMAINS):
            result["legacy_domains"][report["id"]] = dom
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
    result["legacy_domains"] = {k: v for k, v in sorted(result["legacy_domains"].items())}
    result["counts"]["legacy_domain"] = len(result["legacy_domains"])
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
    lines.append("被配方引用 %d（精确 id %d / 脚本别名 %d）/ reserved %d / compose 环 %d" % (
        res["counts"].get("referenced", 0),
        res["counts"].get("referenced_by_id", 0),
        res["counts"].get("referenced_by_script", 0),
        res["counts"].get("reserved", 0),
        res["counts"].get("cycles", 0)))
    maturity = ", ".join("%s=%d" % (k, v) for k, v in res["by_maturity"].items())
    lines.append("成熟度: " + maturity)
    legacy = res.get("legacy_domains") or {}
    if legacy:
        # 不静默：旧域名虽然被接受，但每份都点名（待迁移回 9 域）。
        lines.append("旧域名（已归一/已迁出，待迁移 %d 份）: %s" % (
            len(legacy), ", ".join("%s=%s" % (k, v) for k, v in legacy.items())))
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
    """临时夹具：covered / dangling / 重复 id / 矩阵缺格 / 配方引用 / reserved / DAG 环。"""
    with tempfile.TemporaryDirectory() as tmp:
        caps = os.path.join(tmp, "capabilities")
        os.makedirs(caps)
        pbdir = os.path.join(tmp, "playbooks")
        os.makedirs(pbdir)
        with open(os.path.join(pbdir, "ref.md"), "w", encoding="utf-8") as fh:
            fh.write("- 用到的能力（capability id）：`cap-a` `repo:cap-b`\n")
        good_a = {"id": "cap-a", "title": "A", "inputs": [], "outputs": [],
                  "scripts": [], "refs": [], "maturity": "usable",
                  "compose": ["cap-b"]}
        good_b = {"id": "cap-b", "title": "B", "inputs": [], "outputs": [],
                  "scripts": [], "refs": [], "maturity": "usable", "compose": []}
        probe_c = {"id": "cap-c", "title": "C", "inputs": [], "outputs": [],
                   "scripts": [], "refs": [], "maturity": "probe",
                   "compose": [], "note": "待补脚本，当前手工完成", "reserved": True}
        dangling_d = {"id": "cap-d", "title": "D", "inputs": [], "outputs": [],
                      "scripts": ["Tool/scripts/does-not-exist.py"], "refs": [],
                      "maturity": "usable", "compose": ["cap-zzz"], "reserved": True}
        plain_e = {"id": "cap-e", "title": "E", "inputs": [], "outputs": [],
                      "scripts": [], "refs": [], "maturity": "usable",
                      "compose": [], "reserved": True}
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

        res = run_gate(caps, matrix_path, tmp, pbdir)
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
            (res["counts"]["referenced"] == 2, "recipe reference tally"),
            (res["counts"]["referenced_by_id"] == 2, "reference-by-id tally"),
            (res["counts"]["referenced_by_script"] == 0, "reference-by-script tally"),
            (res["counts"]["referenced_by_id"]
             + res["counts"]["referenced_by_script"]
             == res["counts"]["referenced"], "reference split is a partition"),
            ("cap-a" in res["references_by_id"] and "cap-b" in res["references_by_id"],
             "references_by_id detail"),
            (res["counts"]["reserved"] == 3, "reserved tally"),
            (res["counts"]["cycles"] == 0, "clean compose is a DAG"),
            (res["ok"] is False, "gate fails on gaps"),
        ]

        # 环夹具：compose 必须被识别为 DAG 违规
        cycle_dir = os.path.join(tmp, "cycle")
        os.makedirs(cycle_dir)
        cycle_caps = {
            "cap-x.json": {"id": "cap-x", "title": "X", "inputs": [], "outputs": [],
                           "scripts": [], "refs": [], "maturity": "usable",
                           "compose": ["cap-y"], "reserved": True},
            "cap-y.json": {"id": "cap-y", "title": "Y", "inputs": [], "outputs": [],
                           "scripts": [], "refs": [], "maturity": "usable",
                           "compose": ["cap-x"], "reserved": True},
        }
        for name, obj in cycle_caps.items():
            with open(os.path.join(cycle_dir, name), "w", encoding="utf-8") as fh:
                json.dump(obj, fh, ensure_ascii=False)
        cycle_matrix = os.path.join(tmp, "cycle-matrix.json")
        with open(cycle_matrix, "w", encoding="utf-8") as fh:
            json.dump({"schema": MATRIX_SCHEMA, "families": families,
                       "capabilities": {"cap-x": dict(cells), "cap-y": dict(cells)}},
                      fh, ensure_ascii=False)
        cycle_res = run_gate(cycle_dir, cycle_matrix, tmp, pbdir)
        checks.append((cycle_res["counts"]["cycles"] >= 1, "compose cycle detected"))
        checks.append((any("DAG" in e for e in cycle_res["errors"]), "cycle error reported"))
        checks.append((cycle_res["ok"] is False, "cycle gate fails"))

        # 脚本别名夹具：`用到的能力` 行只有 repo:<脚本 stem>，能力 id 未出现 → 计 by_script
        alias = os.path.join(tmp, "alias")
        os.makedirs(alias)
        alias_caps = {"cap-g.json": {"id": "cap-g", "title": "G", "inputs": [],
                                      "outputs": [], "scripts": ["Tool/scripts/alias-impl.py"],
                                      "refs": [], "maturity": "usable", "compose": []}}
        for name, obj in alias_caps.items():
            with open(os.path.join(alias, name), "w", encoding="utf-8") as fh:
                json.dump(obj, fh, ensure_ascii=False)
        alias_pb = os.path.join(tmp, "alias-playbooks")
        os.makedirs(alias_pb)
        with open(os.path.join(alias_pb, "alias.md"), "w", encoding="utf-8") as fh:
            fh.write("- 用到的能力（capability id）：`repo:alias-impl`\n")
        alias_matrix = os.path.join(tmp, "alias-matrix.json")
        with open(alias_matrix, "w", encoding="utf-8") as fh:
            json.dump({"schema": MATRIX_SCHEMA, "families": families,
                       "capabilities": {"cap-g": dict(cells)}}, fh, ensure_ascii=False)
        alias_res = run_gate(alias, alias_matrix, tmp, alias_pb)
        checks.append((alias_res["counts"]["referenced_by_id"] == 0,
                       "script alias is not an id reference"))
        checks.append((alias_res["counts"]["referenced_by_script"] == 1,
                       "script alias tally"))
        checks.append((alias_res["counts"]["referenced"] == 1,
                       "script alias still counts as referenced"))

        # 未引用且未 reserved 的夹具必须红
        unref_dir = os.path.join(tmp, "unref")
        os.makedirs(unref_dir)
        with open(os.path.join(unref_dir, "cap-u.json"), "w", encoding="utf-8") as fh:
            json.dump({"id": "cap-u", "title": "U", "inputs": [], "outputs": [],
                       "scripts": [], "refs": [], "maturity": "usable",
                       "compose": []}, fh, ensure_ascii=False)
        unref_matrix = os.path.join(tmp, "unref-matrix.json")
        with open(unref_matrix, "w", encoding="utf-8") as fh:
            json.dump({"schema": MATRIX_SCHEMA, "families": families,
                       "capabilities": {"cap-u": dict(cells)}}, fh, ensure_ascii=False)
        unref_res = run_gate(unref_dir, unref_matrix, tmp, pbdir)
        checks.append((unref_res["ok"] is False, "unreferenced capability fails"))
        checks.append((any("未被任何配方引用" in "; ".join(e["problems"])
                           for e in unref_res["dangling"]),
                       "unreferenced capability reported"))

        # 旧域名夹具：reverse（改名为 softseep）与 ad-cloud（已迁出）接受但**必须报出**；
        # 自造域名仍然红（不得因为放宽旧名而把拼写错误一起放过）。
        legacy = os.path.join(tmp, "legacy")
        os.makedirs(legacy)
        legacy_caps = {
            "cap-l1.json": {"id": "cap-l1", "title": "L1", "inputs": [], "outputs": [],
                            "scripts": [], "refs": [], "maturity": "usable",
                            "compose": [], "domain": "reverse", "reserved": True},
            "cap-l2.json": {"id": "cap-l2", "title": "L2", "inputs": [], "outputs": [],
                            "scripts": [], "refs": [], "maturity": "usable",
                            "compose": [], "domain": "ad-cloud", "reserved": True},
        }
        for name, obj in legacy_caps.items():
            with open(os.path.join(legacy, name), "w", encoding="utf-8") as fh:
                json.dump(obj, fh, ensure_ascii=False)
        legacy_matrix = os.path.join(tmp, "legacy-matrix.json")
        with open(legacy_matrix, "w", encoding="utf-8") as fh:
            json.dump({"schema": MATRIX_SCHEMA, "families": list(DOMAIN_ORDER),
                       "capabilities": {cid: {f: "full" for f in DOMAIN_ORDER}
                                        for cid in ("cap-l1", "cap-l2")}},
                      fh, ensure_ascii=False)
        legacy_res = run_gate(legacy, legacy_matrix, tmp, pbdir)
        checks.append((legacy_res["ok"] is True, "legacy domain names accepted"))
        checks.append((legacy_res["legacy_domains"]
                       == {"cap-l1": "reverse", "cap-l2": "ad-cloud"},
                       "legacy domains reported"))
        checks.append(("旧域名" in render_text(legacy_res), "legacy domains rendered"))

        # 自造域名（既非 9 域、也非已知旧名）必须红
        baddom = os.path.join(tmp, "baddom")
        os.makedirs(baddom)
        with open(os.path.join(baddom, "cap-z.json"), "w", encoding="utf-8") as fh:
            json.dump({"id": "cap-z", "title": "Z", "inputs": [], "outputs": [],
                       "scripts": [], "refs": [], "maturity": "usable",
                       "compose": [], "domain": "not-a-domain", "reserved": True},
                      fh, ensure_ascii=False)
        baddom_matrix = os.path.join(tmp, "baddom-matrix.json")
        with open(baddom_matrix, "w", encoding="utf-8") as fh:
            json.dump({"schema": MATRIX_SCHEMA, "families": ["f1", "f2"],
                       "capabilities": {"cap-z": dict(cells)}}, fh, ensure_ascii=False)
        baddom_res = run_gate(baddom, baddom_matrix, tmp, pbdir)
        checks.append((baddom_res["ok"] is False, "invented domain fails"))

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
        clean_res = run_gate(clean, clean_matrix, tmp, pbdir)
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
                          "fixtures": {"dirty": 6, "clean": 2, "cycle": 2,
                                        "unref": 1, "alias": 1,
                                        "legacy": 2, "baddom": 1}},
                         ensure_ascii=False))
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="能力层注册表门禁：校验 scripts/refs 必须存在、id 唯一、compose 可解析、矩阵完整")
    root_default = repo_root()
    ap.add_argument("--root", default=None,
                    help="仓库根（默认按本脚本位置推断，通常无需指定）")
    ap.add_argument("--caps-dir", default=None, help="能力目录（默认 <root>/Tool/capabilities）")
    ap.add_argument("--matrix", default=None, help="覆盖矩阵（默认 <root>/Tool/config/capability-matrix.json）")
    ap.add_argument("--playbooks-dir", default=None, help="配方目录（默认 <root>/Tool/playbooks）")
    ap.add_argument("--emit-matrix", action="store_true",
                    help="从能力自带 domain + compose 闭包重算矩阵并回写（不手填）")
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
    playbooks_dir = (os.path.abspath(args.playbooks_dir) if args.playbooks_dir
                     else os.path.join(root, "Tool", "playbooks"))
    if args.emit_matrix:
        caps = {}
        errors = []
        for path in sorted(glob.glob(os.path.join(caps_dir, "*.json"))):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    obj = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                errors.append("%s: %s" % (rel(path, root), str(exc)[:120]))
                continue
            if isinstance(obj, dict) and isinstance(obj.get("id"), str):
                caps[obj["id"]] = obj
        if errors:
            msg = {"ok": False, "blocked_at": "emit-matrix", "errors": errors}
            print(json.dumps(msg, ensure_ascii=False) if args.json else "\n".join(errors))
            return 2
        summary = emit_matrix(caps, matrix)
        summary["path"] = rel(matrix, root)
        summary["ok"] = True
        print(json.dumps(summary, ensure_ascii=False, indent=2) if args.json
              else "矩阵已生成: %s（%d 行 × %d 域；%s）" % (
                  summary["path"], summary["rows"], summary["families"],
                  ", ".join("%s=%d" % (k, summary["cells"][k]) for k in MATRIX_VALUES)))
        return 0
    res = run_gate(caps_dir, matrix, root, playbooks_dir)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(render_text(res))
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
