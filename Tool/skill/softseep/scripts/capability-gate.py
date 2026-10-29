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

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
from seep_runtime import repo_root as _seep_repo_root


import argparse
import ast
import glob
import json
import os
import re
import subprocess
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
REQUIRED = ("id", "title", "domain", "inputs", "outputs", "scripts", "refs",
            "maturity", "compose")
ABS_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\\\\\|/(?:home|Users|etc|var|tmp|opt|mnt|root|usr)/)")

# 9 个客户域（与 Tool/scripts/lib/domain_spec.py 的 DOMAINS 一致）。
# 活动能力目录只接受这 9 个 domain；旧名只能出现在 _archived/ 的证据里，
# 或由 domain-aliases.json 在入口层显式归一，不能在活动能力声明中复活。
DOMAIN_ORDER = ["apkseep", "firmware-iot", "web-pentest", "pwn-crypto",
                "protocol-plugin", "forensics-mobile", "malware-analysis",
                "supply-chain-security", "softseep"]
DEFAULT_FAMILIES = DOMAIN_ORDER

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
    return _seep_repo_root(__file__)


def _declared_list(value):
    """Return only already-declared arrays; validation reports malformed values."""
    return value if isinstance(value, list) else []


def compose_cycles(objects) -> list:
    """返回 compose 图里的环（每条环是 id 列表，首尾相同）。"""
    graph = {}
    for path, stem, obj in objects:
        if not isinstance(obj, dict):
            continue
        cid = obj.get("id") if isinstance(obj.get("id"), str) else stem
        graph[cid] = [t for t in _declared_list(obj.get("compose")) if isinstance(t, str)]
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
TOKEN_RE = re.compile(r"^([a-z][a-z0-9-]*):([A-Za-z0-9_.-]+)$")
CAP_NAMESPACES = {"repo", "tool", "apk", "mcp", "probe", "reserved"}


def _canonical_stem(value: str) -> str:
    return os.path.splitext(str(value).replace("\\", "/"))[0].replace("_", "-").lower()


def _load_json_object(path: str):
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            return json.load(fh), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, str(exc)[:160]


def _apk_capability_ids(root: str) -> set:
    path = os.path.join(root, "Tool", "skill", "apkseep", "scripts", "capabilities.py")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
    except (OSError, SyntaxError, ValueError):
        return set()
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Dict):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "CAPABILITIES" for t in node.targets):
            continue
        return {k.value for k in node.value.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    return set()


def _repo_script_stems(root: str) -> dict:
    """repo: token -> real implementation paths.

    同时收录 Tool/scripts 和 Tool/skill/**/scripts（含 _pending implementation）。
    路径是否为当前正式交付由 gate/case 门禁另判；这里只回答“能否点名到真实脚本”。
    """
    out = {}
    bases = [os.path.join(root, "Tool", "scripts"),
             os.path.join(root, "Tool", "skill")]
    suffixes = {".py", ".ps1", ".js", ".ts", ".sh"}
    for base in bases:
        if not os.path.isdir(base):
            continue
        for current, dirs, files in os.walk(base):
            dirs[:] = sorted(d for d in dirs if d not in {"__pycache__", "node_modules"})
            for name in sorted(files):
                path = os.path.join(current, name)
                suffix = os.path.splitext(name)[1].lower()
                if suffix not in suffixes:
                    continue
                out.setdefault(_canonical_stem(name), []).append(path)
    return out


def _safe_repo_file(root: str, relative_path: str):
    """Resolve a repository-relative file while rejecting absolute/escaping aliases."""
    if not isinstance(relative_path, str) or not relative_path.strip():
        return ""
    if ABS_PATH_RE.match(relative_path) or os.path.isabs(relative_path):
        return ""
    root_real = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(
        root_real, *relative_path.replace("\\", "/").split("/")))
    try:
        if os.path.commonpath((root_real, candidate)) != root_real:
            return ""
    except ValueError:
        return ""
    return candidate if os.path.isfile(candidate) else ""


def validate_playbook_capabilities(playbooks_dir: str, root: str, ids: set,
                                   capability_state: dict | None = None) -> list:
    """把“用到的能力”行解析成真实命名空间，而不是只做全文字符串扫描。"""
    errors = []
    tool_data, tool_err = _load_json_object(
        os.path.join(root, "Tool", "config", "tool-capabilities.json"))
    mcp_data, mcp_err = _load_json_object(
        os.path.join(root, "Tool", "config", "mcp-servers.json"))
    alias_data, alias_err = _load_json_object(
        os.path.join(root, "Tool", "config", "playbook-capability-aliases.json"))
    tool_ids = set((tool_data or {}).get("tools") or {}) if isinstance(tool_data, dict) else set()
    mcp_ids = set((mcp_data or {}).get("servers") or {}) if isinstance(mcp_data, dict) else set()
    repo_aliases = ((alias_data or {}).get("repo") or {}
                    if isinstance(alias_data, dict) else {})
    apk_ids = _apk_capability_ids(root)
    repo_stems = _repo_script_stems(root)
    if tool_err:
        errors.append({"playbook": "tool-capabilities.json",
                       "token": "", "reason": "工具注册表不可读: " + tool_err})
    if mcp_err:
        errors.append({"playbook": "mcp-servers.json",
                       "token": "", "reason": "MCP 服务清单不可读: " + mcp_err})
    # 别名表是可选扩展；文件存在时必须可解析，具体条目逐项验文件。
    if alias_err and os.path.isfile(os.path.join(
            root, "Tool", "config", "playbook-capability-aliases.json")):
        errors.append({"playbook": "playbook-capability-aliases.json",
                       "token": "", "reason": "能力别名表不可读: " + alias_err})
    if not isinstance(repo_aliases, dict):
        errors.append({"playbook": "playbook-capability-aliases.json",
                       "token": "", "reason": "repo 别名必须是对象"})
        repo_aliases = {}
    for alias, target in sorted(repo_aliases.items()):
        if not isinstance(alias, str) or not alias.strip() \
                or not isinstance(target, str) or not target.strip():
            errors.append({"playbook": "playbook-capability-aliases.json",
                           "token": str(alias), "reason": "别名名和目标都必须是非空字符串"})
        elif not _safe_repo_file(root, target):
            errors.append({"playbook": "playbook-capability-aliases.json",
                           "token": str(alias),
                           "reason": "别名目标必须是仓库内真实普通文件: " + str(target)})
    if not apk_ids:
        errors.append({"playbook": "apkseep/capabilities.py",
                       "token": "", "reason": "APK 原子能力表不可读或为空"})

    for name, text in _playbook_texts(playbooks_dir):
        for lineno, line in enumerate(text.splitlines(), 1):
            if "用到的能力" not in line and "capability id" not in line.lower():
                continue
            tokens = re.findall(r"`([^`]+)`", line)
            if not tokens:
                errors.append({"playbook": name, "line": lineno, "token": "",
                               "reason": "能力行没有反引号 token"})
                continue
            seen = set()
            for token in tokens:
                if token in seen:
                    errors.append({"playbook": name, "line": lineno, "token": token,
                                   "reason": "能力 token 重复"})
                    continue
                seen.add(token)
                m = TOKEN_RE.fullmatch(token)
                if not m:
                    if token in ids:
                        state = (capability_state or {}).get(token) or {}
                        if state.get("reserved") is True:
                            errors.append({
                                "playbook": name, "line": lineno, "token": token,
                                "reason": "reserved 能力必须显式写 reserved:<id>，不能冒充自动工具"})
                        elif state.get("maturity") == "probe":
                            errors.append({
                                "playbook": name, "line": lineno, "token": token,
                                "reason": "probe 能力必须显式写 probe:<id>，不能冒充自动工具"})
                        continue
                    errors.append({"playbook": name, "line": lineno, "token": token,
                                   "reason": "裸能力 id 未注册或 token 格式非法"})
                    continue
                namespace, base = m.groups()
                if namespace not in CAP_NAMESPACES:
                    errors.append({"playbook": name, "line": lineno, "token": token,
                                   "reason": "未知 capability namespace: " + namespace})
                elif namespace == "tool" and base not in tool_ids:
                    errors.append({"playbook": name, "line": lineno, "token": token,
                                   "reason": "tool-capabilities.json 未登记该工具"})
                elif namespace == "apk" and base not in apk_ids:
                    errors.append({"playbook": name, "line": lineno, "token": token,
                                   "reason": "apkseep capabilities.py 未登记该原子能力"})
                elif namespace == "mcp" and base not in mcp_ids:
                    errors.append({"playbook": name, "line": lineno, "token": token,
                                   "reason": "mcp-servers.json 未登记该 MCP 服务"})
                elif namespace in ("probe", "reserved"):
                    state = (capability_state or {}).get(base)
                    if not state:
                        errors.append({"playbook": name, "line": lineno, "token": token,
                                       "reason": "能力状态命名空间引用未注册能力"})
                    elif namespace == "probe" and state.get("maturity") != "probe":
                        errors.append({"playbook": name, "line": lineno, "token": token,
                                       "reason": "probe: 只能标注 maturity=probe 的能力"})
                    elif namespace == "reserved" and state.get("reserved") is not True:
                        errors.append({"playbook": name, "line": lineno, "token": token,
                                       "reason": "reserved: 只能标注 reserved=true 的能力"})
                elif namespace == "repo" and _canonical_stem(base) not in repo_stems:
                    alias_target = _safe_repo_file(root, repo_aliases.get(base, ""))
                    if not alias_target:
                        # repo: 不借用能力 id 蒙混；无法自动解析时必须登记真实别名目标。
                        errors.append({"playbook": name, "line": lineno, "token": token,
                                       "reason": "未找到同名仓库脚本或有效显式别名"})
    return errors


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
        for script in _declared_list(obj.get("scripts")):
            if isinstance(script, str) and script.strip():
                stems.add(_canonical_stem(script))
        id_hits, script_hits = [], []
        for name, toks in tokens.items():
            bases = [t.split(":", 1)[1] if NS_RE.match(t) else t for t in toks]
            if cid in toks or cid in bases:
                id_hits.append(name)
            elif any(t.startswith("repo:") and _canonical_stem(t.split(":", 1)[1]) in stems
                     for t in toks) \
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
        for script in _declared_list(obj.get("scripts")):
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


def _auto_compose_eligible(obj: dict | None) -> bool:
    """Only usable/battle-tested, non-reserved capabilities are auto-composable."""
    return (
        isinstance(obj, dict)
        and obj.get("reserved") is not True
        and obj.get("maturity") in ("usable", "battle-tested")
    )


def reachable_domains(cid, caps: dict, memo: dict) -> set:
    if cid in memo:
        return memo[cid]
    memo[cid] = set()
    out = set()
    for nxt in _declared_list((caps.get(cid) or {}).get("compose")):
        if nxt not in caps or nxt == cid:
            continue
        target = caps[nxt]
        if not _auto_compose_eligible(target):
            continue
        target_domain = (target or {}).get("domain")
        if isinstance(target_domain, str) and target_domain in DOMAIN_ORDER:
            out.add(target_domain)
        out |= reachable_domains(nxt, caps, memo)
    memo[cid] = out
    return out


def emit_matrix(caps: dict, path: str) -> dict:
    """从**可自动编排的能力**生成 9 域矩阵（probe/reserved 不冒充覆盖）。"""
    memo = {}
    rows = {}
    tally = {v: 0 for v in MATRIX_VALUES}
    for cid in sorted(caps):
        obj = caps[cid] or {}
        if obj.get("reserved") is True or obj.get("maturity") == "probe":
            continue
        dom = obj.get("domain")
        if not isinstance(dom, str) or dom not in DOMAIN_ORDER:
            continue
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
        "formal_domains": list(DOMAIN_ORDER),
        "generated_at": "1970-01-01T00:00:00Z",
        "generator": "Tool/skill/softseep/scripts/capability-gate.py --emit-matrix",
        "source": "Tool/capabilities/*.json (reserved=false, maturity=usable|battle-tested)",
        "families": list(DOMAIN_ORDER),
        "values": list(MATRIX_VALUES),
        "notes": "仅收 reserved=false 且 maturity=usable|battle-tested 的能力；probe/reserved 是人工或待补路径，不计自动覆盖。full=本域直接覆盖；partial=相邻域或经 compose 可达；via-compose=需组合。",
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
    for key in ("inputs", "outputs", "scripts", "refs", "compose"):
        values = obj.get(key)
        if not isinstance(values, list):
            continue
        invalid = [repr(x) for x in values if not isinstance(x, str) or not x.strip()]
        if invalid:
            problems.append("%s[] 存在空项或非字符串: %s" % (key, ", ".join(invalid[:5])))
        strings = [x for x in values if isinstance(x, str) and x.strip()]
        duplicates = sorted({x for x in strings if strings.count(x) > 1})
        if duplicates:
            problems.append("%s[] 含重复项: %s" % (key, ", ".join(duplicates)))
    scripts = obj.get("scripts") if isinstance(obj.get("scripts"), list) else []
    refs = obj.get("refs") if isinstance(obj.get("refs"), list) else []
    if not refs:
        problems.append("refs[] 不能为空（能力必须有可追溯的判据或知识参考）")
    maturity = obj.get("maturity")
    if maturity not in MATURITIES:
        problems.append("maturity 必须 ∈ %s，实际 %r" % ("/".join(MATURITIES), maturity))
    if maturity == "probe" and not str(obj.get("note") or "").strip():
        problems.append("probe 能力必须带 note（写清待补脚本与当前手工路径）")
    if maturity in ("usable", "battle-tested") and not scripts:
        problems.append("%s 能力必须有至少一个可调用脚本；没有脚本时只能声明为 probe" % maturity)
    for key in ("triggers", "aliases"):
        if key in obj and not isinstance(obj.get(key), list):
            problems.append("%s 必须是数组" % key)
    dom = obj.get("domain")
    if dom not in DOMAIN_ORDER:
        problems.append("活动能力 domain 必须属于当前九域 %s，实际 %r；"
                        "历史域请移到 Tool/capabilities/_archived/" % ("/".join(DOMAIN_ORDER), dom))
    if obj.get("archived") is True:
        problems.append("archived:true 的能力不能留在活动目录；请移到 Tool/capabilities/_archived/")
    if "version" in obj and not str(obj.get("version") or "").strip():
        problems.append("version 必须是非空字符串")
    if "reserved" in obj and not isinstance(obj.get("reserved"), bool):
        problems.append("reserved 必须是布尔值")
    if referenced is not None and cid not in referenced and obj.get("reserved") is not True:
        problems.append("未被任何配方引用且未标 reserved:true")

    missing_paths = []
    for key in ("scripts", "refs"):
        for entry in _declared_list(obj.get(key)):
            if not isinstance(entry, str) or not entry.strip():
                continue
            if ABS_PATH_RE.match(entry):
                problems.append("%s 项必须是仓库相对路径: %s" % (key, entry))
                continue
            target = os.path.join(root, entry.replace("/", os.sep))
            if not os.path.isfile(target):
                missing_paths.append(entry)
    unknown_compose = []
    for target in _declared_list(obj.get("compose")):
        if not isinstance(target, str) or target not in ids:
            unknown_compose.append(str(target))
    if missing_paths:
        problems.append("缺失文件: " + ",".join(missing_paths))
    if unknown_compose:
        problems.append("compose 指向未注册 id: " + ",".join(unknown_compose))
    return {
        "id": cid,
        "maturity": maturity,
        "reserved": obj.get("reserved") is True,
        "domain": obj.get("domain"),
        "problems": problems,
        "missing_paths": missing_paths,
        "unknown_compose": unknown_compose,
    }


def validate_matrix(path: str, ids: set, root: str) -> dict:
    """矩阵只能声明当前九域和可自动编排的能力行。"""
    info = {"path": rel(path, root), "present": False, "rows": 0,
            "families": [], "coverage": {v: 0 for v in MATRIX_VALUES},
            "problems": [], "missing_cells": [], "unknown_rows": [],
            "missing_rows": [], "extra_cells": []}
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
    if data.get("schema") != MATRIX_SCHEMA:
        info["problems"].append("矩阵 schema 必须是 %s" % MATRIX_SCHEMA)
    families = data.get("families")
    if not isinstance(families, list) or not families:
        info["problems"].append("families 必须是非空数组")
        families = DEFAULT_FAMILIES
    info["families"] = list(families)
    if families != DOMAIN_ORDER:
        info["problems"].append("families 必须严格等于当前九域顺序: "
                                + "/".join(DOMAIN_ORDER))
    values = data.get("values")
    if values is not None and values != list(MATRIX_VALUES):
        info["problems"].append("values 必须严格等于 " + "/".join(MATRIX_VALUES))
    rows = data.get("capabilities")
    if not isinstance(rows, dict) or not rows:
        info["problems"].append("capabilities 必须是非空对象")
        return info
    info["rows"] = len(rows)
    info["missing_rows"] = sorted(ids - set(rows))
    if info["missing_rows"]:
        info["problems"].append("矩阵缺可自动编排能力行: " + ",".join(info["missing_rows"]))
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
        extra = sorted(set(cells) - set(families))
        if extra:
            info["extra_cells"].append("%s:%s" % (rid, ",".join(extra)))
    if info["extra_cells"]:
        info["problems"].append("矩阵含非当前域列: " + "; ".join(info["extra_cells"][:8]))
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
                   "probe": 0, "auto_eligible": 0, "archived": 0},
        "covered": [],
        "dangling": [],
        "by_maturity": {m: 0 for m in MATURITIES},
        "archived": [],
        "playbook_capability_errors": [],
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
        if isinstance(maturity, str) and maturity in result["by_maturity"]:
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
    result["counts"]["probe"] = result["by_maturity"].get("probe", 0)
    auto_ids = {
        cid for cid, obj in (
            (obj.get("id"), obj)
            for _, _, obj in objects if isinstance(obj, dict)
        )
        if isinstance(cid, str)
        and obj.get("reserved") is not True
        and obj.get("maturity") in ("usable", "battle-tested")
        and obj.get("domain") in DOMAIN_ORDER
    }
    result["counts"]["auto_eligible"] = len(auto_ids)
    capability_state = {
        obj.get("id"): {
            "maturity": obj.get("maturity"),
            "reserved": obj.get("reserved") is True,
        }
        for _, _, obj in objects
        if isinstance(obj, dict) and isinstance(obj.get("id"), str)
    }
    result["playbook_capability_errors"] = validate_playbook_capabilities(
        playbooks_dir, root, ids, capability_state)
    if result["playbook_capability_errors"]:
        result["errors"].append("配方能力命名空间有 %d 处不可解析"
                                % len(result["playbook_capability_errors"]))

    archive_dir = os.path.join(caps_dir, "_archived")
    for path in sorted(glob.glob(os.path.join(archive_dir, "*.json"))):
        obj, error = _load_json_object(path)
        if error:
            result["errors"].append("%s 读取/解析失败: %s" % (rel(path, root), error))
            continue
        cid = obj.get("id") if isinstance(obj, dict) else None
        if not isinstance(obj, dict) or not isinstance(cid, str) or not cid.strip():
            result["errors"].append("%s 归档项缺非空 id" % rel(path, root))
            continue
        if obj.get("archived") is not True:
            result["errors"].append("%s 归档项必须显式 archived:true" % rel(path, root))
        result["archived"].append({
            "id": cid,
            "file": rel(path, root),
            "domain": obj.get("domain"),
        })
    result["counts"]["archived"] = len(result["archived"])

    result["matrix"] = validate_matrix(matrix_path, auto_ids, root)
    if result["matrix"].get("problems") or result["matrix"].get("missing_cells") \
            or result["matrix"].get("unknown_rows") or result["matrix"].get("missing_rows"):
        result["errors"].extend(result["matrix"]["problems"])
        if result["matrix"].get("missing_cells"):
            result["errors"].append("矩阵缺格: %d 处" % len(result["matrix"]["missing_cells"]))
        if result["matrix"].get("unknown_rows"):
            result["errors"].append("矩阵含非自动编排行（probe/reserved/未知）: "
                                    + ",".join(result["matrix"]["unknown_rows"]))
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
    lines.append("自动编排 eligible %d / probe %d / reserved %d / archived %d" % (
        res["counts"].get("auto_eligible", 0),
        res["counts"].get("probe", 0),
        res["counts"].get("reserved", 0),
        res["counts"].get("archived", 0)))
    for entry in res["dangling"]:
        lines.append("  DANGLING %s <- %s" % (entry["id"], "; ".join(entry["problems"])))
    for entry in res.get("playbook_capability_errors", []):
        where = "%s:%s" % (entry.get("playbook"), entry.get("line", "-"))
        lines.append("  PLAYBOOK %s %s <- %s" % (
            where, entry.get("token", "-"), entry.get("reason")))
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
    """临时夹具：九域、归档隔离、自动资格、重复项、矩阵和命名空间负例。"""
    checks = []

    def expect(label, condition):
        checks.append((bool(condition), label))

    def write_json(path, value):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(value, fh, ensure_ascii=False, indent=2)

    def cap(cid, domain, maturity="usable", scripts=None, refs=None,
            reserved=False, compose=None, note=None, **extra):
        obj = {
            "id": cid,
            "title": cid,
            "domain": domain,
            "inputs": [],
            "outputs": [],
            "scripts": scripts if scripts is not None else ["Tool/scripts/alias.py"],
            "refs": refs if refs is not None else ["Tool/scripts/ref.md"],
            "maturity": maturity,
            "compose": compose or [],
        }
        if reserved:
            obj["reserved"] = True
        if note:
            obj["note"] = note
        obj.update(extra)
        return obj

    def matrix(rows, families=None, values=None):
        families = list(families or DOMAIN_ORDER)
        return {
            "schema": MATRIX_SCHEMA,
            "families": families,
            "values": list(values or MATRIX_VALUES),
            "capabilities": {
                rid: {family: "full" for family in families} for rid in rows
            },
        }

    with tempfile.TemporaryDirectory() as tmp:
        write_json(os.path.join(tmp, "Tool", "config", "tool-capabilities.json"),
                   {"tools": {"known": {}}})
        write_json(os.path.join(tmp, "Tool", "config", "mcp-servers.json"),
                   {"servers": {"seep": {}}})
        write_json(os.path.join(tmp, "Tool", "config",
                                "playbook-capability-aliases.json"),
                   {"repo": {"renamed": "Tool/scripts/alias.py"}})
        os.makedirs(os.path.join(tmp, "Tool", "scripts"), exist_ok=True)
        with open(os.path.join(tmp, "Tool", "scripts", "alias.py"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write("raise SystemExit(0)\n")
        with open(os.path.join(tmp, "Tool", "scripts", "ref.md"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write("# reference\n")
        write_json(os.path.join(tmp, "Tool", "skill", "apkseep", "scripts",
                                "capabilities.py"), {})
        with open(os.path.join(tmp, "Tool", "skill", "apkseep", "scripts",
                               "capabilities.py"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write("CAPABILITIES = {'x': {}}\n")

        pbdir = os.path.join(tmp, "playbooks")
        os.makedirs(pbdir)
        playbook = os.path.join(pbdir, "main.md")
        with open(playbook, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("- 用到的能力（capability id）：`cap-a` `repo:alias` "
                     "`repo:renamed` `tool:known` `apk:x` `mcp:seep` `probe:cap-c`\n")

        caps = os.path.join(tmp, "capabilities")
        payloads = {
            "cap-a.json": cap("cap-a", "softseep", compose=["cap-b"]),
            "cap-a2.json": cap("cap-a", "softseep"),
            "cap-b.json": cap("cap-b", "softseep", maturity="battle-tested"),
            "cap-c.json": cap("cap-c", "web-pentest", maturity="probe",
                              scripts=[], note="manually verified only"),
            "cap-d.json": cap("cap-d", "web-pentest", reserved=True),
            "cap-e.json": cap("cap-e", "pwn-crypto"),
            "cap-f.json": cap(
                "cap-f", "softseep", reserved=True,
                scripts=["Tool/scripts/alias.py", "Tool/scripts/alias.py"],
                refs=["Tool/scripts/ref.md", "Tool/scripts/ref.md"]),
            "cap-g.json": cap("cap-g", "reverse", reserved=True),
        }
        for name, obj in payloads.items():
            write_json(os.path.join(caps, name), obj)
        write_json(os.path.join(caps, "_archived", "old.json"),
                   cap("old", "ad-cloud", reserved=True, archived=True))

        compose_scope_caps = {
            "root": cap("root", "apkseep", compose=["reserved-mid", "probe-mid"]),
            "active-root": cap("active-root", "pwn-crypto", compose=["active-mid"]),
            "reserved-mid": cap(
                "reserved-mid", "softseep", reserved=True, compose=["protocol-leaf"]),
            "probe-mid": cap(
                "probe-mid", "firmware-iot", maturity="probe", compose=["firmware-leaf"]),
            "active-mid": cap(
                "active-mid", "protocol-plugin", compose=["active-leaf"]),
            "active-leaf": cap("active-leaf", "malware-analysis"),
            "protocol-leaf": cap("protocol-leaf", "protocol-plugin"),
            "firmware-leaf": cap("firmware-leaf", "firmware-iot"),
        }
        expect("compose traversal excludes reserved/probe capabilities",
               reachable_domains("root", compose_scope_caps, {}) == set())
        expect("compose traversal keeps active capabilities",
               reachable_domains("active-root", compose_scope_caps, {})
               == {"protocol-plugin", "malware-analysis"})

        dirty_matrix = matrix(["cap-a", "cap-b", "cap-e", "cap-c", "cap-d"])
        dirty_matrix["capabilities"]["cap-e"].pop(DOMAIN_ORDER[-1])
        matrix_path = os.path.join(tmp, "matrix.json")
        write_json(matrix_path, dirty_matrix)
        res = run_gate(caps, matrix_path, tmp, pbdir)

        expect("fixture count", res["counts"]["capabilities"] == 8)
        expect("archived is outside activity", res["counts"]["archived"] == 1)
        expect("archived id is not active", "old" not in res["covered"])
        expect("auto eligibility excludes probe/reserved",
               res["counts"]["auto_eligible"] == 3)
        expect("duplicate id reported",
               any("id 重复" in e for e in res["errors"]))
        expect("duplicate scripts/refs reported",
               any("scripts[] 含重复项" in "; ".join(x["problems"])
                   for x in res["dangling"]))
        expect("legacy active domain fails",
               any(x["id"] == "cap-g" and "当前九域" in "; ".join(x["problems"])
                   for x in res["dangling"]))
        expect("probe/reserved rows are rejected",
               {"cap-c", "cap-d"}.issubset(set(res["matrix"]["unknown_rows"])))
        expect("missing matrix cell reported",
               len(res["matrix"]["missing_cells"]) == 1)
        expect("dirty gate fails", res["ok"] is False)
        expect("playbook namespaces resolve",
               res["playbook_capability_errors"] == [])
        expect("valid repo alias resolves",
               not any(x.get("token") == "repo:renamed"
                       for x in res["playbook_capability_errors"]))

        with open(playbook, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("- 用到的能力（capability id）：`cap-a` `repo:alias` "
                     "`repo:missing-alias` `forensics:evidence_accept` `tool:amass`\n")
        bad_pb = run_gate(caps, matrix_path, tmp, pbdir)
        reasons = "; ".join(x["reason"] for x in bad_pb["playbook_capability_errors"])
        expect("invalid repo alias reported", "有效显式别名" in reasons)
        expect("unknown namespace reported", "未知 capability namespace" in reasons)
        expect("missing tool reported", "tool-capabilities.json 未登记" in reasons)

        with open(playbook, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("- 用到的能力（capability id）：`cap-a` `cap-c`\n")
        bare_probe = run_gate(caps, matrix_path, tmp, pbdir)
        expect("bare probe capability is rejected",
               any("probe 能力必须显式写" in x["reason"]
                   for x in bare_probe["playbook_capability_errors"]))

        with open(playbook, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("- 用到的能力（capability id）：`cap-a` `repo:alias` `cap-a`\n")
        dup_pb = run_gate(caps, matrix_path, tmp, pbdir)
        expect("duplicate capability token reported",
               any(x["reason"] == "能力 token 重复"
                   for x in dup_pb["playbook_capability_errors"]))

        baddom_matrix = matrix(["cap-a", "cap-b", "cap-e"])
        baddom_matrix["families"] += ["reverse"]
        baddom_matrix["capabilities"]["cap-a"]["reverse"] = "full"
        baddom_path = os.path.join(tmp, "baddom-matrix.json")
        write_json(baddom_path, baddom_matrix)
        baddom = run_gate(caps, baddom_path, tmp, pbdir)
        expect("matrix family drift fails",
               any("families 必须严格等于" in e for e in baddom["errors"]))

        cycle_dir = os.path.join(tmp, "cycle")
        write_json(os.path.join(cycle_dir, "cap-x.json"),
                   cap("cap-x", "softseep", compose=["cap-y"]))
        write_json(os.path.join(cycle_dir, "cap-y.json"),
                   cap("cap-y", "softseep", compose=["cap-x"]))
        cycle_pb = os.path.join(tmp, "cycle-playbooks")
        os.makedirs(cycle_pb)
        with open(os.path.join(cycle_pb, "cycle.md"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write("- 用到的能力（capability id）：`cap-x` `cap-y`\n")
        cycle_matrix = os.path.join(tmp, "cycle-matrix.json")
        write_json(cycle_matrix, matrix(["cap-x", "cap-y"]))
        cycle_res = run_gate(cycle_dir, cycle_matrix, tmp, cycle_pb)
        expect("compose cycle reported",
               any("DAG" in e for e in cycle_res["errors"]))

        clean = os.path.join(tmp, "clean")
        write_json(os.path.join(clean, "cap-a.json"),
                   cap("cap-a", "softseep", compose=["cap-b"]))
        write_json(os.path.join(clean, "cap-b.json"), cap("cap-b", "softseep"))
        clean_pb = os.path.join(tmp, "clean-playbooks")
        os.makedirs(clean_pb)
        with open(os.path.join(clean_pb, "clean.md"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write("- 用到的能力（capability id）：`cap-a` `repo:alias`\n")
        clean_matrix = os.path.join(tmp, "clean-matrix.json")
        write_json(clean_matrix, matrix(["cap-a", "cap-b"]))
        clean_res = run_gate(clean, clean_matrix, tmp, clean_pb)
        expect("clean fixture passes", clean_res["ok"] is True)
        expect("text renderer", render_text(clean_res).startswith(
            "capability-gate: PASS"))

        malformed_cases = [
            ("scripts", 3, "scripts"),
            ("refs", 3, "refs"),
            ("compose", 3, "compose"),
            ("domain", [], "domain"),
            ("maturity", [], "maturity"),
        ]
        for index, (field, value, marker) in enumerate(malformed_cases):
            case_root = os.path.join(tmp, "malformed-%d" % index)
            caps_dir = os.path.join(case_root, "capabilities")
            pb_dir = os.path.join(case_root, "playbooks")
            os.makedirs(os.path.join(case_root, "Tool", "scripts"), exist_ok=True)
            os.makedirs(caps_dir, exist_ok=True)
            os.makedirs(pb_dir, exist_ok=True)
            with open(os.path.join(case_root, "Tool", "scripts", "ref.md"), "w",
                      encoding="utf-8", newline="\n") as fh:
                fh.write("# reference\n")
            with open(os.path.join(pb_dir, "main.md"), "w",
                      encoding="utf-8", newline="\n") as fh:
                fh.write("- capability id: good\n")
            bad = cap("bad", "softseep")
            bad[field] = value
            write_json(os.path.join(caps_dir, "bad.json"), bad)
            write_json(os.path.join(caps_dir, "good.json"), cap("good", "softseep"))
            matrix_path = os.path.join(case_root, "matrix.json")
            write_json(matrix_path, matrix(["good"]))
            cli = subprocess.run([
                sys.executable, __file__, "--root", case_root,
                "--caps-dir", caps_dir, "--matrix", matrix_path,
                "--playbooks-dir", pb_dir, "--json",
            ], text=True, encoding="utf-8", errors="replace", capture_output=True)
            try:
                payload = json.loads(cli.stdout)
            except (TypeError, json.JSONDecodeError):
                payload = None
            dangling = (payload or {}).get("dangling") or []
            bad_entry = next((x for x in dangling if x.get("id") == "bad"), {})
            expect("%s scalar/type malformed declaration returns JSON failure" % field,
                   cli.returncode != 0 and payload is not None and payload.get("ok") is False)
            expect("%s malformed declaration retains validation error" % field,
                   any(marker in str(problem) for problem in bad_entry.get("problems") or []))

    failed = [label for passed, label in checks if not passed]
    print(json.dumps({
        "ok": not failed,
        "checks": len(checks),
        "failed": len(failed),
        "failures": failed,
        "tool": "capability-gate.py",
    }, ensure_ascii=False))
    return 0 if not failed else 2


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
        objects = []
        errors = []
        for path in sorted(glob.glob(os.path.join(caps_dir, "*.json"))):
            stem = os.path.splitext(os.path.basename(path))[0]
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    obj = json.load(fh)
            except (OSError, json.JSONDecodeError) as exc:
                errors.append("%s: %s" % (rel(path, root), str(exc)[:120]))
                continue
            objects.append((path, stem, obj))
            if isinstance(obj, dict) and isinstance(obj.get("id"), str):
                cid = obj["id"]
                if cid in caps:
                    errors.append("能力 id 重复，不能生成矩阵: " + cid)
                else:
                    caps[cid] = obj
        ids = set(caps)
        for path, stem, obj in objects:
            report = validate_capability(obj, stem, root, ids, referenced=None)
            if report.get("problems"):
                errors.append("%s: %s" % (
                    rel(path, root), "; ".join(report["problems"])))
        for cycle in compose_cycles(objects):
            errors.append("compose 必须是 DAG: " + " -> ".join(cycle))
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
