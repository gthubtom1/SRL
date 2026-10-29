#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline *static* contract checker for pack tools and MCP execution paths.

七个维度**分开报**，互不代偿（2026-10-27 审计 #7：旧实现把
`runtime_ok = catalog_matches or server_configured` 混成一个布尔，于是
「空目录表 + 假 server 命令 + 未解析依赖」也能 PASS）：

  1. transport_config      mcp-servers.json 里有没有这个服务器（只是配置，不代表能跑）
  2. method_registered     seep_mcp_server.py 的 @server.tool() 函数集合（AST，不 import）
  3. effect_registered     tool-effects.json 的五字段效果标注
  4. dependency_declared   Tool/config/mcp-tool-dependencies.json（schema 1）里有没有显式声明
  5. registry_closure      依赖声明的每一项能否在既有注册表里落地
                           （tool-runtimes / tool-capabilities / tool-install / os_cli_allowlist / 仓库文件）
  6. local_availability    **不判**：静态检查不证明能执行；--probe 只做只读发现，found != verified
  7. online_handshake      **不判**：离线不启动 MCP，一律 not_checked，不称 online

因此：`evidence_level=structural`、`runtime_verified=false`。
registry_gap 永远不是 pass —— 配置了 MCP server 也不能满足 rabin2/java/tshark 这类 CLI 运行依赖。
"""
from __future__ import print_function

import argparse
import ast
import glob
import json
import os
import shutil
import sys
import tempfile


SCHEMA = "seep.tool-contract-check/2"
DEPENDENCY_SCHEMA = "seep.mcp-tool-dependencies/1"
DEPENDENCY_REL = "Tool/config/mcp-tool-dependencies.json"
SERVER_REL = "Tool/mcp/seep_mcp_server.py"
EFFECT_FIELDS = (
    "writes_filesystem",
    "executes_foreign_code",
    "touches_network",
    "mutates_target",
    "may_discard_data",
)
DEPENDENCY_KINDS = (
    "builtin_module",
    "python_lib",
    "external_tool",
    "repo_asset",
    "repo_dir",
    "repo_module",
    "os_cli",
)
# 判定结果词汇：明确区分「结构上缺依赖注册」「本机没这个文件」「未检查」。
STATUS_OK = "ok"
STATUS_UNVERIFIED = "unverified_source"     # 声明了依赖但拿不到实现里的证据（可能是虚报）
STATUS_BAD_SOURCE = "source_mismatch"       # source.function/file/line 与真实 AST 锚点不符
STATUS_TRUNCATED = "evidence_truncated"     # helper 链超过审计深度：如实说「没验到」，不算 pass
STATUS_REGISTRY_GAP = "registry_gap"
STATUS_MISSING = "missing"
STATUS_UNDECLARED = "undeclared"
STATUS_UNKNOWN_KIND = "unknown_kind"
STATUS_NOT_CHECKED = "not_checked"

# 明确的 Python 标准库集合（py3.10+ 有 sys.stdlib_module_names；否则退回内置名）。
_STDLIB = set(getattr(sys, "stdlib_module_names", ())) or {
    "sys", "os", "re", "json", "glob", "zipfile", "hashlib", "shutil", "subprocess",
    "ctypes", "pathlib", "typing", "math", "time", "socket", "urllib", "base64",
    "struct", "binascii", "tempfile", "itertools", "collections", "random", "string",
}


def _repo_root():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _rel(root, path):
    return os.path.relpath(path, root).replace(os.sep, "/")


def _abs(root, relative):
    return os.path.join(root, relative.replace("/", os.sep))


def _server_tool_decorated(node):
    """Return whether an AST function has a server.tool() decorator."""
    for decorator in getattr(node, "decorator_list", ()):  # pragma: no branch
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        if (isinstance(target, ast.Attribute)
                and target.attr == "tool"
                and isinstance(target.value, ast.Name)
                and target.value.id == "server"):
            return True
    return False


def _read_server_tools(root, source_path):
    try:
        with open(source_path, "r", encoding="utf-8") as handle:
            source = handle.read()
        tree = ast.parse(source, filename=source_path)
    except Exception as exc:  # syntax and encoding failures are contract failures
        return set(), ["%s: %s" % (_rel(root, source_path), str(exc)[:180])]

    tools = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _server_tool_decorated(node):
            tools.add(node.name)
    return tools, []


# ---------------------------------------------------------------------------
# 来源证据（复用 AST，不做全文件字符串 contains 自证）
#
# 行的地位：`line` 只是**可推导的定位**（AST 给出的 def 行），**不是真理**。真理是
# 「函数名 + 文件 + 函数体（含已审 helper 链）里真的用到了这个依赖」。
# 所以：
#   * 只在函数**前后**增删空行/注释/无关代码 → 语义不变（不改判）。
#   * `line` 与 AST def 行不一致（落后/超前/指向别的 def/不存在）→ **不失败**：
#     记 `relocated=True` 并同时给出 `declared_line`/`anchor_line` 供审计。
#     （旧注释曾写“line 指到别的函数定义 → 必须失败”，与实现不符，已按实际行为更正；
#      不重引入“line == def 行”这种脆弱真理。）
#   * 函数不存在 / 函数名不符 / 文件不符 → 必须失败（source_mismatch）。
#   * 声明的依赖在实现（含已审 helper 链）里找不到使用证据 → 必须失败（unverified_source），
#     绝不当 pass。
#
# 已审 helper 链（明确边界，不做全模块遍历）：
#   * 同文件模块级函数 / 模块级常量赋值（递归，带深度上限）：必须真的在该链上才算用到；
#   * `evidence_via` 声明的 helper 必须**真实存在且被调用**：本文件模块级名字在链上，
#     或它被 import 进本文件且其 import 源头正好是声明的 `evidence_via.module`
#     （跨 alias 换模块/换成员 → 不成立）；`module` 必须在 `AUDITED_HELPER_MODULES`
#     或就是声明的依赖本身；被 import 的成员必须真在该模块 AST 里；
#   * 声明了 `evidence_via` 就**只有** helper 级证据算数 —— “模块已被 import”不
#     等于“它提供的 helper 被调用”（这也是 `kind == repo_module` 的硬要求）；
#   * 没有 `evidence_via` 时：`repo_module` 只能证到“实现使用了该模块”（模块级上限，
#     不冒充 helper 级证明）；路径/文件名字面量只算同级的弱证据；
#   * 超过 `EVIDENCE_DEPTH` 或超出上述范围 → `evidence_truncated`（如实说没验到，不算通过）。
# ---------------------------------------------------------------------------
EVIDENCE_DEPTH = 5
CONTRACT_MODULE_REL = "Tool/mcp/seep_contract.py"
EVIDENCE_MCP_MODULE_REL = "Tool/mcp/seep_mcp_server.py"
# 跨文件证据只允许下钻到这三份「已审计 helper 模块」；其余一律按路径/名称字面量锚定。
AUDITED_HELPER_MODULES = (
    "Tool/mcp/seep_contract.py",
    "Tool/mcp/tool_autodiscover.py",
    "Tool/mcp/seep_apk_contract.py",
    "Tool/mcp/seep_case_library.py",
)
_SOURCE_CACHE = {}
_DOCSTRING = ("first statement is a docstring: skipped, so editing docs cannot fake evidence")


def _strip_docstring(body):
    """Drop a leading docstring so prose can never be mistaken for usage evidence."""
    if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        return body[1:]
    return body


# 只认「真的会去跑它」的调用名；`which` / `isfile` 这类**只探测**的用法不算使用证据
# （否则删掉真正的 spawn 只留存在性检查，仍然会被判定为「用到了」）。
SPAWN_CALL_NAMES = frozenset((
    "_run_capture", "_run_cmd", "run", "Popen", "call", "check_call", "check_output", "getoutput",
    "getstatusoutput", "system", "popen", "spawn", "spawnv", "spawnve", "spawnl",
))


def _command_tokens(values, assignments):
    """Follow command arguments through simple assignments; never execute code."""
    refs, literals = set(), set()
    pending, visited = list(values), set()
    while pending:
        value = pending.pop()
        for inner in ast.walk(value):
            if isinstance(inner, ast.Name):
                refs.add(inner.id)
                if inner.id in assignments and inner.id not in visited:
                    visited.add(inner.id)
                    pending.append(assignments[inner.id])
            elif isinstance(inner, ast.Attribute):
                chain, cursor = [], inner
                while isinstance(cursor, ast.Attribute):
                    chain.append(cursor.attr)
                    cursor = cursor.value
                if isinstance(cursor, ast.Name):
                    chain.append(cursor.id)
                    refs.add(".".join(reversed(chain)))
                refs.add(inner.attr)
            elif isinstance(inner, ast.Constant) and isinstance(inner.value, str):
                literals.add(inner.value)
    return refs, literals


def _command_context(nodes):
    """Only actual spawn arguments and their simple assignments are evidence.

    An unused vector, error text or an existence check cannot prove execution.
    This is a bounded syntax check, not general data-flow or runtime proof.
    """
    assignments, values = {}, []
    for node in nodes:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Assign):
                for target in sub.targets:
                    if isinstance(target, ast.Name):
                        assignments[target.id] = sub.value
            elif isinstance(sub, ast.AnnAssign) and isinstance(sub.target, ast.Name) and sub.value:
                assignments[sub.target.id] = sub.value
            elif isinstance(sub, ast.Call):
                func = sub.func
                name = (func.id if isinstance(func, ast.Name)
                        else (func.attr if isinstance(func, ast.Attribute) else ""))
                if name not in SPAWN_CALL_NAMES:
                    continue
                if sub.args:
                    values.append(sub.args[0])
                else:
                    values.extend(k.value for k in sub.keywords if k.arg in ("args", "cmd", "command"))
    return _command_tokens(values, assignments)


def _evidence_tokens(nodes):
    """AST-only token picture of a set of nodes (no source-text substring matching).

    Returns dict of sets: names (identifiers), attrs (dotted + bare attribute names),
    strings (string literals), calls (callee bare names), imports (module names),
    imported_names (locally bound names from `from x import y`).
    """
    names, attrs, strings, calls = set(), set(), set(), set()
    for node in nodes:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name):
                names.add(sub.id)
            elif isinstance(sub, ast.Attribute):
                attrs.add(sub.attr)
                chain, cursor = [], sub
                while isinstance(cursor, ast.Attribute):
                    chain.append(cursor.attr)
                    cursor = cursor.value
                if isinstance(cursor, ast.Name):
                    chain.append(cursor.id)
                    attrs.add(".".join(reversed(chain)))
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                strings.add(sub.value)
            elif isinstance(sub, ast.Import):
                for alias in sub.names:
                    names.add(alias.asname or alias.name.split(".")[0])
            elif isinstance(sub, ast.ImportFrom):
                for alias in sub.names:
                    names.add(alias.asname or alias.name)
                if sub.module:
                    names.add(sub.module.split(".")[0])
            if isinstance(sub, ast.Call):
                func = sub.func
                if isinstance(func, ast.Name):
                    calls.add(func.id)
                elif isinstance(func, ast.Attribute):
                    calls.add(func.attr)
    command_refs, command_literals = _command_context(nodes)
    return {"names": names, "attrs": attrs, "strings": strings, "calls": calls,
            "command_refs": command_refs, "command_literals": command_literals}


class _ModuleView(object):
    """Read-only AST view of one Python file, reused within a check invocation."""

    def __init__(self, source, relative):
        self.relative = relative
        self.tree = ast.parse(source, filename=relative)
        self.top_level = {}
        self.functions = {}
        self.assigns = {}
        self.import_from = {}
        self.import_bindings = {}
        self.imported_modules = set()
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.top_level[node.name] = node
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.assigns[target.id] = node.value
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                self.assigns[node.target.id] = node.value
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions.setdefault(node.name, node)
            elif isinstance(node, ast.ImportFrom) and node.module:
                self.imported_modules.add(node.module)
                for alias in node.names:
                    self.import_from[alias.asname or alias.name] = (node.module, alias.name)
                    self.import_bindings[alias.asname or alias.name] = node.module
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self.imported_modules.add(alias.name.split(".")[0])
                    self.import_bindings[alias.asname or alias.name.split(".")[0]] = alias.name
        # module-wide string literals: only used inside explicitly white-listed modules
        self.strings = _evidence_tokens([node for node in self.tree.body])["strings"]


def _module_view(root, relative):
    key = (root, relative)
    if key not in _SOURCE_CACHE:
        path = _abs(root, relative)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                source = handle.read()
            _SOURCE_CACHE[key] = (_ModuleView(source, relative), None)
        except Exception as exc:  # missing / unparsable module is a hard evidence failure
            _SOURCE_CACHE[key] = (None, "%s: %s" % (relative, str(exc)[:180]))
    return _SOURCE_CACHE[key]


def _reachable(module, func_name, depth=None):
    """Token picture of `func_name` plus the bounded, audited helper chain it calls.

    Chain = module-level functions and module-level constant assignments of the same
    file, recursing at most `EVIDENCE_DEPTH` levels. Docstrings are stripped.
    Returns dict with names/attrs/strings/calls/imported/imported_modules/truncated.
    """
    depth = EVIDENCE_DEPTH if depth is None else depth
    result = {"names": set(), "attrs": set(), "strings": set(), "calls": set(),
              "command_refs": set(), "command_literals": set(),
              "imported": set(), "imported_modules": set(),
              "truncated": False, "visited": []}
    # 注意：**不**把模块级 import 名称直接当证据 —— 否则「模块导入了 X」就能给任意工具
    # 虚报 X 依赖。证据必须来自该实现（含 helper 链）自己的 Name/Attr/ImportFrom 节点。
    seen = set()
    queue = [(func_name, depth)]
    while queue:
        name, budget = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        # 只沿**模块级**名字走：嵌套闭包（如某工具内部的 `def run(...)`）不属于
        # 另一个工具的 helper 链，否则会把别的工具的命令串算成本工具的证据。
        if name in module.top_level:
            node = module.top_level[name]
            tokens = _evidence_tokens(list(_strip_docstring(node.body)) + list(node.decorator_list))
        elif name in module.assigns:
            tokens = _evidence_tokens([module.assigns[name]])
        else:
            continue
        result["visited"].append(name)
        for field in ("names", "attrs", "strings", "calls", "command_refs", "command_literals"):
            result[field] |= tokens[field]
        frontier = set(tokens["calls"]) | {n for n in tokens["names"]
                                           if n in module.top_level or n in module.assigns}
        frontier -= seen
        if not frontier:
            continue
        if budget <= 0:
            result["truncated"] = True
            continue
        for next_name in sorted(frontier):
            queue.append((next_name, budget - 1))
    result["imported"] = {source.split(".")[0] for name, source in module.import_bindings.items()
                          if name in result["names"]}
    result["imported_modules"] = {source for name, source in module.import_bindings.items()
                                  if name in result["names"]}
    # Module-level command vectors must also be reachable from an actual spawn.
    values = [module.assigns[name] for name in result["command_refs"] if name in module.assigns]
    refs, literals = _command_tokens(values, module.assigns)
    result["command_refs"] |= refs
    result["command_literals"] |= literals
    return result


# 外部工具在本服务实现里的符号名（模块级常量 / 解析函数 / 环境变量基线）。
# 这是**显式白名单**：新工具要在实现里用新符号名，必须在这里登记（并接受验收复核）。
EXTERNAL_TOOL_SYMBOLS = {
    "r2": ("R2_EXE", "radare2", "r2"),
    "rabin2": ("RABIN2_EXE", "rabin2"),
    "radiff2": ("RADIFF2_EXE", "radiff2"),
    "rasm2": ("RASM2_EXE", "rasm2"),
    "rahash2": ("RAHASH2_EXE", "rahash2"),
    "jadx": ("JADX_BAT", "jadx", "jadx.bat"),
    # _find_java 是解析器（JADX/apktool 自己起 java），所以只在「真的调用了解析器」时才算证据。
    "java": ("_find_java", "java_path", "JAVA_HOME", "java"),
    "apktool": ("APKTOOL_JAR", "APKTOOL_BAT", "apktool"),
    "tshark": ("tshark",),
}


def _called_resolver(module, reach, symbol):
    """A white-listed resolver function (e.g. `_find_java`) counts only when actually called."""
    if symbol not in module.functions:
        return False
    return symbol in reach["calls"]


def _external_symbols(catalogs, tool_id):
    """Symbols an external_tool id may appear as in the implementation (white-listed)."""
    symbols = set(EXTERNAL_TOOL_SYMBOLS.get(str(tool_id), ()))
    entry = catalogs.runtimes.get(tool_id) or catalogs.capabilities.get(tool_id) or {}
    for bucket in ((entry.get("probe") or {}).get("names"), entry.get("exe_candidates")):
        for name in bucket or []:
            symbols.add(str(name))
    return symbols


def _external_candidates(catalogs, tool_id):
    """Executable names a declared external_tool id is known by (from the registries)."""
    entry = catalogs.runtimes.get(tool_id) or catalogs.capabilities.get(tool_id) or {}
    probe = entry.get("probe") or {}
    names = {str(tool_id)}
    for bucket in (probe.get("names"), probe.get("exe_candidates"), entry.get("exe_candidates")):
        for name in bucket or []:
            names.add(str(name))
    for mode in entry.get("modes") or []:
        for name in (mode or {}).get("fallbackExe") or []:
            names.add(str(name))
    candidates = set()
    for name in names:
        name = name.strip()
        if not name:
            continue
        candidates.add(name)
        if name.lower().endswith(".exe"):
            candidates.add(name[:-4])
    return candidates


def _source_anchor(module, entry, tool):
    """Resolve the real AST anchor for a declared source. `line` is advisory only."""
    declared = entry.get("source")
    if not isinstance(declared, dict) or declared.get("function") != tool or declared.get("file") != SERVER_REL:
        return None, ["tools.%s.source 必须声明当前服务器文件和真实工具函数" % tool]
    if module is None:
        return None, ["%s 的 server AST 不可读" % SERVER_REL]
    node = module.top_level.get(tool)
    if node is None:
        return None, ["tools.%s.source.function %r 在 %s 的 AST 里不存在"
                      % (tool, declared.get("function"), module.relative)]
    try:
        declared_line = int(declared.get("line"))
    except (TypeError, ValueError):
        declared_line = None
    return {"file": module.relative, "function": tool, "anchor_line": node.lineno,
            "end_line": getattr(node, "end_lineno", node.lineno),
            "declared_line": declared_line,
            "relocated": declared_line is not None and declared_line != node.lineno}, []


def _module_symbols(view):
    """Names a module really provides (top-level defs / assignments), for binding checks."""
    return set(view.top_level) | set(view.assigns)


def _import_binding(module, name):
    """`{"module": ..., "name": imported_member}` if `name` is bound by an import in this file."""
    binding = module.import_from.get(name)
    if binding:
        return {"module": str(binding[0]), "name": str(binding[1])}
    for node in ast.walk(module.tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if (alias.asname or alias.name.split(".")[0]) == name:
                    return {"module": str(alias.name),
                            "name": str(alias.name).rsplit(".", 1)[-1]}
    return None


def _via_evidence(root, module, reach, via, declared_path, kind):
    """Verify one explicit `evidence_via` hop: implementation -> helper -> audited module -> literal.

    Bounded white-list hop, **not** program-wide reachability. Whatever the dependency
    `kind` is, the hop first proves the *helper-level* facts (the ones an import of the
    module alone can never establish):

      1. the declared `helper` really exists **now** and is used by this implementation:
         a same-file module-level function/constant inside the audited helper chain, or
         an imported name whose import target is exactly `evidence_via.module`;
      2. `evidence_via.module` is on `AUDITED_HELPER_MODULES` (or is the declared
         dependency itself) and exists on disk;
      3. the imported member really exists in that module's AST (no invented names) and
         `symbol` matches the declared dependency (no aliasing/冒名).

    Only then is the kind-specific evidence checked. In particular, for
    `kind == "repo_module"` whose `module` **is** the declared path, "the module is
    imported" is **not** accepted as proof — step 1 already had to prove that the
    declared helper is really reachable and used.
    """
    helper = str(via.get("helper") or "")
    if not helper:
        return False, "evidence_via.helper 缺失（白名单跳转必须写明 helper 名）"
    target = str(via.get("module") or "").replace("\\", "/")
    symbol = str(via.get("symbol") or "")
    base = declared_path.rsplit("/", 1)[-1]
    if symbol and symbol not in (declared_path, base):
        return False, ("evidence_via.symbol %r 与声明的依赖 %r 不一致（不许用别的文件冒名）"
                       % (symbol, declared_path))

    local = helper in module.top_level or helper in module.assigns
    binding = None if local else _import_binding(module, helper)
    if local:
        if helper not in reach["visited"]:
            return False, ("evidence_via.helper %r 是本文件模块级名字，但不在该实现的 "
                           "helper 链里（存在但没被用到）" % helper)
    elif binding is None:
        if helper in reach["names"] or helper in reach["calls"]:
            return False, ("evidence_via.helper %r 被引用但既不是本文件模块级名字，也没有"
                           "任何 import 绑定（无法证明它真的可调用）" % helper)
        return False, ("evidence_via.helper %r 在当前实现里不存在、也没有 import 绑定"
                       "（假函数名不能当证据；模块被 import ≠ 提供的 helper 被调用）" % helper)
    elif helper not in reach["names"]:
        # 导入了但实现里没用到：模块/成员存在也不能算 helper 被使用。
        return False, ("evidence_via.helper %r 只被 import，未在该实现（含 helper 链）里使用"
                       "（import 了模块 ≠ 它的 helper 被调用）" % helper)

    if not target:
        if symbol and symbol in reach["strings"]:
            return True, "helper %r 的实现里出现字面量 %r" % (helper, symbol)
        return False, "evidence_via 缺少 module（白名单跳转必须点名已审计 helper 模块）"
    if not os.path.isfile(_abs(root, target)):
        return False, "evidence_via.module %r 不存在" % target
    if not symbol:
        return False, "evidence_via.symbol 缺失（必须点名该模块里命中哪个字面量）"
    if local and target != module.relative:
        # 本文件 helper 要能代表另一个模块，它自己必须真的引用/加载那个模块
        # （否则就是拿同文件函数冒另一个模块的依赖）。
        base_t = os.path.basename(target)
        if target not in reach["strings"] and base_t not in reach["strings"]:
            return False, ("本文件模块级 helper %r 的链里没有引用/加载 %r，不能当作该模块"
                           "提供的 helper（跨 alias 冒名）" % (helper, target))
        if symbol not in reach["strings"] and symbol not in (declared_path, base):
            return False, "helper %r 的实现里没有出现依赖字面量 %r" % (helper, symbol)
        if kind == "repo_module" and target == declared_path:
            return True, ("helper %r 真的被调用，且它加载的正是声明的依赖模块 %s"
                          % (helper, target))
        return True, ("本文件 helper %r 真实使用（链内引用 %s），依赖 %r 由其采用"
                      % (helper, target, declared_path))
    if target not in AUDITED_HELPER_MODULES and target != declared_path:
        return False, ("evidence_via.module %r 既不在已审计 helper 模块白名单 %s 内，"
                       "也不是声明的依赖" % (target, list(AUDITED_HELPER_MODULES)))
    view, error = _module_view(root, target)
    if view is None:
        return False, "evidence_via 的已审计模块不可读：%s" % error

    if binding is not None:
        expected_mod = os.path.basename(target)
        expected_mod = expected_mod[:-3] if expected_mod.endswith(".py") else expected_mod
        source_mod = binding["module"].rsplit(".", 1)[-1]
        if source_mod != expected_mod:
            return False, ("helper %r 的 import 绑定来自 %r，与 evidence_via.module %s 不一致"
                           "（跨 alias/冒名，helper 级证据不成立）"
                           % (helper, source_mod, target))
        if binding["name"] not in _module_symbols(view):
            return False, ("%s 并不提供 import 绑定的成员 %r（声明/绑定不一致）"
                           % (target, binding["name"]))

    if kind == "repo_module" and target == declared_path:
        # helper 已在上面证明真实可达并被使用；模块自身也确认存在/可读。
        return True, ("helper %r 真的被调用/可达，且它来自声明的依赖模块 %s"
                      % (helper, target))
    if symbol not in view.strings:
        return False, "%s 的 AST 里找不到字面量 %r" % (target, symbol)
    return True, ("白名单受限跳转：helper %r → 已审计模块 %s，AST 命中字面量 %r"
                  % (helper, target, symbol))


def _imported_helper_reach(root, module, reach, via):
    """Resolve one explicitly declared cross-module helper and inspect its own body.

    Builtin modules and external executables are normally proven from the tool body.
    A refactor may move the real use into a small audited helper module; accepting the
    import alone would be too weak, so this follows the exact alias/member binding and
    evaluates the helper's own bounded call chain.
    """
    helper = str(via.get("helper") or "")
    target = str(via.get("module") or "").replace("\\", "/")
    if not helper:
        return None, None, None, "evidence_via.helper 缺失"
    binding = _import_binding(module, helper)
    if binding is None:
        return None, None, None, "evidence_via.helper 不是当前实现的 import 绑定"
    if helper not in reach["names"]:
        return None, None, None, "evidence_via.helper 已导入但当前实现没有调用"
    if target not in AUDITED_HELPER_MODULES:
        return None, None, None, "evidence_via.module 不在已审计 helper 白名单"
    if not os.path.isfile(_abs(root, target)):
        return None, None, None, "evidence_via.module 不存在"
    expected = os.path.basename(target)
    expected = expected[:-3] if expected.endswith(".py") else expected
    if binding["module"].rsplit(".", 1)[-1] != expected:
        return None, None, None, "helper import 来源与 evidence_via.module 不一致"
    view, error = _module_view(root, target)
    if view is None:
        return None, None, None, "evidence_via 的已审计模块不可读：%s" % error
    if binding["name"] not in _module_symbols(view):
        return None, None, None, "已审计模块不提供声明的 helper 成员"
    helper_reach = _reachable(view, binding["name"])
    if not helper_reach["visited"]:
        return None, None, None, "helper 成员没有可审计的函数体"
    return helper_reach, view, binding, ""


def _evidence_for_item(root, module, reach, item, catalogs):
    """Is this declared dependency actually used by the implementation? (AST only)"""
    kind = item.get("kind")
    declared_path = str(item.get("id") or item.get("path") or "")
    via = item.get("evidence_via") if isinstance(item.get("evidence_via"), dict) else None

    if kind in ("builtin_module", "python_lib"):
        base = declared_path.split(".")[0]
        if via:
            helper_reach, _helper_view, _binding, error = _imported_helper_reach(
                root, module, reach, via)
            if helper_reach is None:
                return False, error
            hit = (base in helper_reach["names"] or base in helper_reach["imported"]
                   or any(attr.split(".")[0] == base for attr in helper_reach["attrs"]))
            return hit, ("%s 在已审计 helper %r 的实现里被引用" % (base, via.get("helper"))
                         if hit else
                         "已审计 helper %r 没有引用声明依赖 %s" % (via.get("helper"), base))
        hit = (base in reach["names"] or base in reach["imported"]
               or any(attr.split(".")[0] == base for attr in reach["attrs"]))
        return hit, ("%s 在实现（含 helper 链）里被引用" % base if hit else
                     "实现（含 helper 链）没有引用 %s（声明了但用不到 = 虚报依赖）" % base)

    if kind == "external_tool":
        if via:
            helper_reach, helper_view, binding, error = _imported_helper_reach(
                root, module, reach, via)
            if helper_reach is None:
                return False, error
            candidates = _external_candidates(catalogs, declared_path)
            symbols = _external_symbols(catalogs, declared_path)
            literal_hits = sorted(name for name in candidates
                                  if name in helper_reach["command_literals"])
            symbol_hits = sorted(name for name in symbols
                                 if name in helper_reach["command_refs"]
                                 or name in helper_reach["command_literals"]
                                 or _called_resolver(helper_view, helper_reach, name))
            spawns = bool(SPAWN_CALL_NAMES.intersection(helper_reach["calls"]))
            helper_named_for_tool = declared_path.lower() in binding["name"].lower()
            mentions_tool = any(declared_path.lower() in str(value).lower()
                                for value in (helper_reach["names"] | helper_reach["strings"]))
            if literal_hits or symbol_hits or (spawns and helper_named_for_tool and mentions_tool):
                return True, ("已审计 helper %r 真实执行并绑定外部工具 %s"
                              % (via.get("helper"), declared_path))
            return False, ("已审计 helper %r 没有可核的 %s 执行证据"
                           % (via.get("helper"), declared_path))
        # 证据只来自「能进命令行的字面量」或「注册表里该 id 的可执行符号」：
        # 错误消息里提一句工具名、docstring 里写一句工具名，都不算使用。
        candidates = _external_candidates(catalogs, declared_path)
        symbols = _external_symbols(catalogs, declared_path)
        literal_hits = sorted(name for name in candidates if name in reach["command_literals"])
        symbol_hits = sorted(name for name in symbols
                             if name in reach["command_refs"] or name in reach["command_literals"]
                             or _called_resolver(module, reach, name))
        if literal_hits or symbol_hits:
            return True, "实现里以命令/已审解析器方式使用 %s" % ", ".join(
                (literal_hits + symbol_hits)[:4])
        return False, ("实现（含 helper 链）里没有把 %r 放进命令（可执行名 %s / 注册表符号 %s 都没有）"
                       % (declared_path, sorted(candidates)[:6], sorted(symbols)[:6]))

    if kind in ("repo_asset", "repo_dir"):
        base = declared_path.rsplit("/", 1)[-1]
        # evidence_via 是显式声明的 helper 级证明：声明了就**必须**走它，不能被
        # 实现里随便一个字面量提前满足（否则假 helper/错 module 会被字面量刷绿）。
        if via:
            return _via_evidence(root, module, reach, via, declared_path, kind)
        if declared_path in reach["strings"]:
            return True, "实现里直接出现路径 %r" % declared_path
        if base and base in reach["strings"]:
            return True, "实现里出现文件名 %r" % base
        return False, "实现（含 helper 链）里没有引用 %r（也没有 evidence_via 白名单跳转）" % declared_path

    if kind == "repo_module":
        base = declared_path.rsplit("/", 1)[-1]
        stem = base[:-3] if base.endswith(".py") else base
        # 同上：声明了 evidence_via 就走 helper 级证据（不是只看 import 或路径字面量）。
        if via:
            return _via_evidence(root, module, reach, via, declared_path, kind)
        if declared_path in reach["strings"] or base in reach["strings"]:
            return True, "实现里直接出现模块路径 %r" % declared_path
        for imported in sorted(reach["imported_modules"]):
            if imported != stem:
                continue
            candidate = "Tool/mcp/%s.py" % imported
            if candidate == declared_path and os.path.isfile(_abs(root, candidate)):
                return True, "实现里 `import %s` 正好指向 %s" % (imported, candidate)
        return False, "实现（含 helper 链）里没有加载 %r" % declared_path

    if kind == "os_cli":
        if declared_path in reach["command_literals"]:
            return True, "实现（含 helper 链）里以命令名 %r 调用" % declared_path
        return False, "实现（含 helper 链）里没有出现命令名 %r" % declared_path

    return False, "未知 kind=%r，无法给出使用证据（fail-closed）" % kind


def _evaluate_source_evidence(root, tool, entry, module, catalogs):
    """Return (evidence dict, unresolved entries) for one tool declaration."""
    evidence = {"file": SERVER_REL, "function": tool, "anchor_line": None, "end_line": None,
                "declared_line": None, "relocated": False, "ok": False, "truncated": False,
                "unverified": [], "detail": []}
    anchor, anchor_errors = _source_anchor(module, entry, tool)
    if anchor_errors:
        evidence["detail"].extend(anchor_errors)
        return evidence, [{"tool": tool, "group": "source", "kind": "source",
                           "id": tool, "status": STATUS_BAD_SOURCE, "detail": error}
                          for error in anchor_errors]
    evidence.update(anchor)
    reach = _reachable(module, tool)
    evidence["truncated"] = reach["truncated"]
    evidence["helpers"] = sorted(reach["visited"])[:24]
    requires = entry.get("requires")
    if (not isinstance(requires, dict) or any(not isinstance(requires.get(group, []), list)
                                            for group in ("all_of", "any_of"))):
        error = "requires 必须是包含 all_of/any_of 数组的对象"
        evidence["detail"].append(error)
        return evidence, [{"tool": tool, "group": "source", "kind": "source", "id": tool,
                           "status": STATUS_BAD_SOURCE, "detail": error}]
    unresolved = []
    all_items = [i for i in (requires.get("all_of") or []) if isinstance(i, dict)]
    any_items = [i for i in (requires.get("any_of") or []) if isinstance(i, dict)]
    failed = []
    for item in all_items:
        ok, detail = _evidence_for_item(root, module, reach, item, catalogs)
        ident = item.get("id") or item.get("path")
        evidence["detail"].append({"group": "all_of", "id": ident, "ok": ok, "detail": detail})
        if not ok:
            failed.append(("all_of", item, detail))
    if any_items:
        branch_failures = []
        for item in any_items:
            ok, detail = _evidence_for_item(root, module, reach, item, catalogs)
            ident = item.get("id") or item.get("path")
            evidence["detail"].append({"group": "any_of", "id": ident, "ok": ok, "detail": detail})
            if ok:
                branch_failures = []
                break
            branch_failures.append(("any_of", item, detail))
        failed.extend(branch_failures)
    if failed:
        status = STATUS_TRUNCATED if reach["truncated"] else STATUS_UNVERIFIED
        for group, item, detail in failed:
            ident = item.get("id") or item.get("path")
            evidence["unverified"].append(ident)
            # group 固定为 "source"：来源证据是**独立的维度**，不要混进 all_of/any_of 的
            # 注册闭包计数（否则同一缺口会被记两次，看不清到底是没登记还是没实现）。
            unresolved.append({"tool": tool, "group": "source", "declared_group": group,
                               "kind": item.get("kind"), "id": ident, "status": status,
                               "detail": detail})
        return evidence, unresolved
    evidence["ok"] = True
    return evidence, unresolved


def _load_packs(root):
    by_tool = {}
    pack_errors = []
    pack_count = 0
    pattern = os.path.join(root, "Tool", "skill", "*", "pack.json")
    for path in sorted(glob.glob(pattern)):
        pack_count += 1
        try:
            data = _read_json(path)
            pack_id = str(data.get("id") or os.path.basename(os.path.dirname(path)))
            tools = data.get("tools")
            if not isinstance(tools, list):
                raise ValueError("tools must be a list")
            for tool in tools:
                if not isinstance(tool, str) or not tool.strip():
                    raise ValueError("tools contains a non-empty string violation")
                by_tool.setdefault(tool, set()).add(pack_id)
        except Exception as exc:
            pack_errors.append("%s: %s" % (_rel(root, path), str(exc)[:180]))
    return by_tool, pack_count, pack_errors


def _load_catalog(root, relative, key):
    path = _abs(root, relative)
    try:
        data = _read_json(path)
        value = data.get(key, {})
        if not isinstance(value, dict):
            raise ValueError("%s must be an object" % key)
        return value, []
    except Exception as exc:
        return {}, ["%s: %s" % (relative, str(exc)[:180])]


def _load_effects(root):
    relative = "Tool/config/tool-effects.json"
    try:
        data = _read_json(_abs(root, relative))
        tools = data.get("tools", {})
        if not isinstance(tools, dict):
            raise ValueError("tools must be an object")
        return tools, []
    except Exception as exc:
        return {}, ["%s: %s" % (relative, str(exc)[:180])]


def _load_servers(root):
    relative = "Tool/config/mcp-servers.json"
    try:
        data = _read_json(_abs(root, relative))
        servers = data.get("servers", {})
        if not isinstance(servers, dict):
            raise ValueError("servers must be an object")
        return servers, []
    except Exception as exc:
        return {}, ["%s: %s" % (relative, str(exc)[:180])]


def _valid_effect(effect):
    if not isinstance(effect, dict):
        return False
    return all(field in effect and isinstance(effect[field], bool) for field in EFFECT_FIELDS)


def _load_dependency_config(root):
    """读显式依赖声明。文件缺失 / schema 不符 / tools 为空 → 一律 fail-closed。

    返回 (tools, os_cli_allowlist, errors)；只读一次，避免同一缺失文件重复报错。
    """
    path = _abs(root, DEPENDENCY_REL)
    try:
        data = _read_json(path)
    except Exception as exc:
        return {}, {}, ["%s: %s" % (DEPENDENCY_REL, str(exc)[:180])]

    errors = []
    if not isinstance(data, dict):
        return {}, {}, ["%s: 顶层必须是对象" % DEPENDENCY_REL]
    if data.get("schema") != DEPENDENCY_SCHEMA:
        errors.append("%s: schema 必须是 %s，实际 %r"
                      % (DEPENDENCY_REL, DEPENDENCY_SCHEMA, data.get("schema")))
    allow = data.get("os_cli_allowlist", {})
    if not isinstance(allow, dict):
        errors.append("%s: os_cli_allowlist 必须是对象" % DEPENDENCY_REL)
        allow = {}
    tools = data.get("tools")
    if not isinstance(tools, dict) or not tools:
        errors.append("%s: tools 缺失或为空映射（空映射不等于『没有依赖』，一律 fail-closed）"
                      % DEPENDENCY_REL)
        return {}, allow, errors

    for name, entry in sorted(tools.items()):
        if not isinstance(entry, dict):
            errors.append("%s: tools.%s 必须是对象" % (DEPENDENCY_REL, name))
            continue
        source = entry.get("source")
        if not isinstance(source, dict) or source.get("function") != name:
            errors.append("%s: tools.%s.source.function 必须等于工具名（来源函数证据缺失）"
                          % (DEPENDENCY_REL, name))
        elif str(source.get("file", "")) != SERVER_REL:
            errors.append("%s: tools.%s.source.file 必须指向 %s（实际 %r）"
                          % (DEPENDENCY_REL, name, SERVER_REL, source.get("file")))
        requires = entry.get("requires")
        if not isinstance(requires, dict):
            errors.append("%s: tools.%s.requires 必须是对象" % (DEPENDENCY_REL, name))
            continue
        if set(requires) - {"all_of", "any_of"}:
            errors.append("%s: tools.%s.requires 只允许 all_of/any_of（发现 %s）"
                          % (DEPENDENCY_REL, name, sorted(set(requires) - {"all_of", "any_of"})))
        for group in ("all_of", "any_of"):
            items = requires.get(group, [])
            if not isinstance(items, list):
                errors.append("%s: tools.%s.requires.%s 必须是数组" % (DEPENDENCY_REL, name, group))
                continue
            for item in items:
                if not isinstance(item, dict):
                    errors.append("%s: tools.%s.requires.%s 元素必须是对象" % (DEPENDENCY_REL, name, group))
                    continue
                if item.get("kind") not in DEPENDENCY_KINDS:
                    errors.append("%s: tools.%s.requires.%s 出现未知 kind=%r（允许：%s）"
                                  % (DEPENDENCY_REL, name, group, item.get("kind"),
                                     "/".join(DEPENDENCY_KINDS)))
                if not isinstance(item.get("id") or item.get("path"), str):
                    errors.append("%s: tools.%s.requires.%s 元素缺少 id/path"
                                  % (DEPENDENCY_REL, name, group))
        if not (requires.get("all_of") or requires.get("any_of")):
            errors.append("%s: tools.%s.requires 的 all_of 与 any_of 同时为空"
                          "（要么声明纯 builtin，要么声明真实依赖）" % (DEPENDENCY_REL, name))
    return tools, allow, errors


class Catalogs(object):
    """既有注册表的只读视图（本轮不改 tool-runtimes / tool-capabilities）。"""

    def __init__(self, root, os_cli=None):
        self.root = root
        self.runtimes, e1 = _load_catalog(root, "Tool/config/tool-runtimes.json", "tools")
        self.capabilities, e2 = _load_catalog(root, "Tool/config/tool-capabilities.json", "tools")
        self.installable, e3 = _load_catalog(root, "Tool/config/tool-install.json", "installable")
        self.os_cli = dict(os_cli or {})
        self.errors = e1 + e2 + e3

    def tool_registered(self, tool_id):
        """外部 CLI 的稳定 id 是否在既有工具注册表里（runtime 或 capability）。"""
        hits = []
        if tool_id in self.runtimes:
            hits.append("tool-runtimes.json#tools")
        if tool_id in self.capabilities:
            hits.append("tool-capabilities.json#tools")
        return hits

    def python_lib_registered(self, lib_id):
        return lib_id in self.installable


def _resolve_requirement(root, item, catalogs):
    """单个依赖项的注册闭包判定（纯静态）。返回 (status, detail)。"""
    if not isinstance(item, dict):
        return STATUS_UNKNOWN_KIND, "依赖项必须是对象，实际 %r" % (item,)
    kind = item.get("kind")
    if kind == "builtin_module":
        module = str(item.get("id"))
        if module in _STDLIB:
            return STATUS_OK, "标准库模块，无需 CLI"
        return STATUS_UNDECLARED, "不是已知标准库模块：%s（假 builtin 会让纯阅读型工具失效）" % module

    if kind == "python_lib":
        lib = str(item.get("id"))
        if catalogs.python_lib_registered(lib):
            return STATUS_OK, "tool-install.json#installable 已登记"
        return STATUS_REGISTRY_GAP, "tool-install.json#installable 未登记 %s" % lib

    if kind == "external_tool":
        tool_id = str(item.get("id"))
        hits = catalogs.tool_registered(tool_id)
        if hits:
            return STATUS_OK, "注册于 %s" % " + ".join(hits)
        return STATUS_REGISTRY_GAP, (
            "tool-runtimes.json#tools 与 tool-capabilities.json#tools 都没有 %r 这个 id"
            "（不许用别的工具名兜底）" % tool_id)

    if kind in ("repo_asset", "repo_dir", "repo_module"):
        path = str(item.get("path"))
        full = _abs(root, path)
        exists = os.path.isdir(full) if kind == "repo_dir" else os.path.isfile(full)
        if exists:
            return STATUS_OK, "%s 存在" % path
        return STATUS_MISSING, "%s 不存在：%s" % (kind, path)

    if kind == "os_cli":
        cli = str(item.get("id"))
        if cli in catalogs.os_cli:
            return STATUS_OK, "mcp-tool-dependencies.json#os_cli_allowlist 已声明"
        return STATUS_UNDECLARED, "os_cli_allowlist 未声明系统命令 %r（未登记即 fail-closed）" % cli

    return STATUS_UNKNOWN_KIND, "未知 kind=%r" % kind


def _evaluate_requires(root, tool, requires, catalogs):
    """all_of 全满足 + any_of 至少一支满足。返回 (resolved, unresolved_entries)。"""
    unresolved = []
    all_items = requires.get("all_of") or []
    any_items = requires.get("any_of") or []

    for group, items in (("all_of", all_items),):
        for item in items:
            if not isinstance(item, dict):
                unresolved.append({"tool": tool, "group": group, "kind": "malformed",
                                   "id": repr(item)[:60], "status": STATUS_UNKNOWN_KIND,
                                   "detail": "依赖项必须是对象"})
                continue
            status, detail = _resolve_requirement(root, item, catalogs)
            if status != STATUS_OK:
                unresolved.append({"tool": tool, "group": group, "kind": item.get("kind"),
                                   "id": item.get("id") or item.get("path"),
                                   "status": status, "detail": detail})

    if any_items:
        branch_failures = []
        for item in any_items:
            if not isinstance(item, dict):
                branch_failures.append({"tool": tool, "group": "any_of", "kind": "malformed",
                                        "id": repr(item)[:60], "status": STATUS_UNKNOWN_KIND,
                                        "detail": "依赖项必须是对象"})
                continue
            status, detail = _resolve_requirement(root, item, catalogs)
            if status == STATUS_OK:
                branch_failures = []
                break
            branch_failures.append({"tool": tool, "group": "any_of", "kind": item.get("kind"),
                                    "id": item.get("id") or item.get("path"),
                                    "status": status, "detail": detail})
        if branch_failures:
            unresolved.extend(branch_failures)
            unresolved.append({
                "tool": tool, "group": "any_of", "kind": "any_of",
                "id": " | ".join(str(b["id"]) for b in branch_failures),
                "status": STATUS_REGISTRY_GAP,
                "detail": "any_of 的所有分支都未闭合（至少一支必须注册通过）",
            })
    return (not unresolved), unresolved


def _probe_dependency(root, item, catalogs):
    """只读发现（不 spawn 任何软件）。found != verified，不改变 structural 判定。"""
    kind = item.get("kind")
    record = {"kind": kind, "id": item.get("id") or item.get("path"),
              "discovery": "not_applicable", "verified": False}
    if kind == "external_tool":
        tool_id = str(item.get("id"))
        entry = catalogs.runtimes.get(tool_id) or catalogs.capabilities.get(tool_id) or {}
        probe_meta = (entry.get("probe") or {})
        names = [str(n) for n in (list(probe_meta.get("names") or [])
                                  + list(entry.get("exe_candidates") or []))]
        if not names:
            names = [tool_id]
        hits = []
        for name in dict.fromkeys(names):
            found = shutil.which(name)
            if found and found not in hits:
                hits.append(found)
        for rel_path in (probe_meta.get("repoPaths") or []):
            candidate = _abs(root, str(rel_path))
            if os.path.isfile(candidate) and candidate not in hits:
                hits.append(candidate)
        # 一个 id 可能覆盖多个可执行名（r2 条目同时列了 rabin2/radare2）：
        # 不替人猜「哪一个才是」，全部如实列出。
        record["discovery"] = "found" if hits else "not_found"
        record["found_paths"] = [(_rel(root, h) if os.path.abspath(h).startswith(root + os.sep) else h)
                                 for h in hits]
        record["path"] = record["found_paths"][0] if record["found_paths"] else None
        record["note"] = (("found != verified：只做了文件/PATH 只读发现，没有执行；"
                           "命中 %d 个候选路径" % len(hits))
                          if entry else
                          "found != verified；且该 id 无注册表条目，无 probe 元数据可查（registry_gap）")
    elif kind == "python_lib":
        try:
            from importlib.machinery import PathFinder
            # find_spec('parent.child') would import parent. Walk package specs
            # using their search paths instead, without invoking any loader.
            spec, search_path, prefix = None, None, []
            for part in str(item.get("id")).split("."):
                prefix.append(part)
                spec = PathFinder.find_spec(".".join(prefix), search_path)
                if spec is None:
                    break
                search_path = spec.submodule_search_locations
                if search_path is None and len(prefix) < len(str(item.get("id")).split(".")):
                    spec = None
                    break
        except Exception:
            spec = None
        record["discovery"] = "found" if spec else "not_found"
        record["note"] = "found != verified：只查询模块路径，未导入父包或调用模块"
    elif kind in ("repo_asset", "repo_dir", "repo_module"):
        full = _abs(root, str(item.get("path")))
        exists = os.path.isdir(full) if kind == "repo_dir" else os.path.isfile(full)
        record["discovery"] = "found" if exists else "not_found"
        record["note"] = "静态存在性检查，仍是 structural"
    else:
        record["note"] = "os_cli 只能靠执行才能确认，静态阶段一律 not_checked（未 spawn）"
        record["discovery"] = "not_checked"
    return record


def check(root=None, probe=False):
    # A caller may edit a fixture or source and recheck in this same process.
    _SOURCE_CACHE.clear()
    root = os.path.abspath(root or _repo_root())
    declared, pack_count, pack_errors = _load_packs(root)
    server_path = _abs(root, SERVER_REL)
    registered, server_errors = _read_server_tools(root, server_path)
    effects, effect_errors = _load_effects(root)
    dep_map, os_cli_allowlist, dependency_errors = _load_dependency_config(root)
    catalogs = Catalogs(root, os_cli=os_cli_allowlist)
    servers, server_config_errors = _load_servers(root)
    server_module, server_module_error = _module_view(root, SERVER_REL)

    source_errors = (pack_errors + server_errors + effect_errors + dependency_errors
                     + catalogs.errors + server_config_errors)

    server_name = "seep"
    server_entry = servers.get(server_name)
    server_configured = isinstance(server_entry, dict) and bool(server_entry)
    transport = {
        "server": server_name,
        "configured": server_configured,
        "transport": (server_entry or {}).get("transport") if server_configured else None,
        "status": STATUS_OK if server_configured else STATUS_MISSING,
        "note": "transport 配置只说明『安装时会写进 mcp.json』，不代表 CLI 依赖可用、也不代表已握手",
    }

    rows = []
    gaps = []
    unresolved = []
    probes = []

    # 目标集合 = pack.tools ∪ @server.tool()。只扫 pack 会漏掉已注册但尚无 pack 引用的
    # 工具（如 seep_ensure_tool），那样「20 个 MCP 工具逐项声明」就有洞。
    targets = sorted(set(declared) | set(registered))

    for tool in targets:
        entry = dep_map.get(tool)
        declaration = entry if isinstance(entry, dict) else None
        raw_requires = (declaration or {}).get("requires")
        requires = ({group: items for group, items in raw_requires.items()
                     if group in ("all_of", "any_of") and isinstance(items, list)}
                    if isinstance(raw_requires, dict) else {})
        declared_deps = bool(declaration) and bool(requires.get("all_of") or requires.get("any_of"))

        if declared_deps:
            resolved, tool_unresolved = _evaluate_requires(root, tool, requires, catalogs)
            unresolved.extend(tool_unresolved)
        else:
            resolved, tool_unresolved = False, [{
                "tool": tool, "group": "declaration", "kind": "dependency_declared",
                "id": tool, "status": STATUS_MISSING,
                "detail": "未在 %s 声明依赖（未知新工具必须补映射，不许默认通过）" % DEPENDENCY_REL,
            }]
            unresolved.extend(tool_unresolved)

        # 来源证据（函数名 + 文件 + 实现里真实使用），line 只做可推导定位。
        source_evidence = None
        source_ok = False
        if declaration:
            source_evidence, source_unresolved = _evaluate_source_evidence(
                root, tool, declaration, server_module, catalogs)
            if server_module is None:
                source_unresolved = [{"tool": tool, "group": "source", "kind": "source",
                                      "id": tool, "status": STATUS_BAD_SOURCE,
                                      "detail": server_module_error or "server AST 不可读"}]
                source_evidence["detail"].append(server_module_error or "server AST 不可读")
            unresolved.extend(source_unresolved)
            source_ok = bool(source_evidence.get("ok"))
            tool_unresolved = list(tool_unresolved) + list(source_unresolved)

        registered_ok = tool in registered
        effect_ok = _valid_effect(effects.get(tool))
        row = {
            "tool": tool,
            "packs": sorted(declared.get(tool) or ()),
            "server": server_name,
            "declared": tool in declared,
            "transport_configured": server_configured,
            "method_registered": registered_ok,
            "effect_registered": effect_ok,
            "dependency_declared": declared_deps,
            "requires": requires,
            "registry_closure": resolved,
            "source_evidence": source_evidence,
            "source_verified": source_ok,
            "structural_ok": bool(registered_ok and effect_ok and declared_deps and resolved
                                  and (source_ok or source_evidence is None)),
            "local_availability": STATUS_NOT_CHECKED,
            "runtime_verified": False,
            "online_handshake": STATUS_NOT_CHECKED,
            "gaps": [],
        }
        if not registered_ok:
            row["gaps"].append("method_registered: %s 未在 @server.tool() 函数中注册" % tool)
        if not effect_ok:
            row["gaps"].append("effect_registered: %s 缺失或字段不完整" % tool)
        for item in tool_unresolved:
            row["gaps"].append("%s %s(%s): %s" % (item["status"], item["group"],
                                                  item["id"], item["detail"]))
        if row["gaps"]:
            gaps.extend("%s: %s" % (tool, gap) for gap in row["gaps"])
        rows.append(row)

        if probe and declaration:
            for group in ("all_of", "any_of"):
                for item in requires.get(group) or []:
                    if not isinstance(item, dict):
                        continue
                    record = _probe_dependency(root, item, catalogs)
                    record["tool"] = tool
                    record["group"] = group
                    probes.append(record)

    if not declared:
        gaps.append("declared: 没有读取到任何 pack.tools")
    if not server_configured:
        gaps.append("transport_config: mcp-servers.json 缺少 servers.%s（只影响传输配置这一维）"
                    % server_name)
    if source_errors:
        gaps.extend("source: " + error for error in source_errors)

    server_only = sorted(registered - set(declared))
    unreferenced_effects = sorted(set(effects) - set(declared) - registered)
    dependency_orphans = sorted(set(dep_map) - set(declared) - registered)

    # registry_gap 不能当 pass：单列出来，方便主 Agent 派最小修复。
    registry_gaps = [item for item in unresolved if item["status"] == STATUS_REGISTRY_GAP]
    missing = [item for item in unresolved if item["status"] == STATUS_MISSING]
    undeclared = [item for item in unresolved if item["status"] == STATUS_UNDECLARED]
    unknown_kind = [item for item in unresolved if item["status"] == STATUS_UNKNOWN_KIND]
    source_unverified = [item for item in unresolved
                         if item["status"] in (STATUS_UNVERIFIED, STATUS_BAD_SOURCE, STATUS_TRUNCATED)]

    ok = bool(rows) and not gaps
    result = {
        "schema": SCHEMA,
        "dependency_schema": DEPENDENCY_SCHEMA,
        "ok": ok,
        "mode": "static-offline",
        "evidence_level": "structural",
        "runtime_verified": False,
        "dimensions": {
            "transport_config": {"status": transport["status"],
                                 "note": "配置了 server 不满足 CLI 运行依赖"},
            "method_registered": {"status": STATUS_OK if registered else STATUS_MISSING,
                                  "source": SERVER_REL, "count": len(registered)},
            "effect_registered": {"status": STATUS_OK if effects else STATUS_MISSING,
                                  "source": "Tool/config/tool-effects.json", "count": len(effects)},
            "dependency_declared": {"status": STATUS_OK if dep_map else STATUS_MISSING,
                                    "source": DEPENDENCY_REL, "count": len(dep_map)},
            "source_evidence": {
                "status": (STATUS_OK if (rows and all(row["source_verified"] for row in rows))
                           else (STATUS_UNVERIFIED if source_unverified else STATUS_MISSING)),
                "source": SERVER_REL,
                "verified": sum(1 for row in rows if row.get("source_verified")),
                "count": len(rows),
                "rule": "真理 = 函数名 + 文件 + 实现（含已审 helper 链）里真实使用；"
                        "source.line 只是可推导定位（行位移不失败，错函数/错文件/虚假依赖必失败）；"
                        "声明 evidence_via 时只认 helper 级证据（模块已被 import ≠ 其 helper 被调用），"
                        "无 evidence_via 时 repo_module 只证到模块级使用（不冒充 helper 级证明）",
            },
            "registry_closure": {
                "status": (STATUS_OK if (targets and not unresolved)
                           else (STATUS_REGISTRY_GAP if unresolved else STATUS_MISSING)),
                "sources": ["Tool/config/tool-runtimes.json#tools",
                                             "Tool/config/tool-capabilities.json#tools",
                                             "Tool/config/tool-install.json#installable",
                                             DEPENDENCY_REL + "#os_cli_allowlist",
                                             "仓库内文件存在性"]},
            "local_availability": {"status": STATUS_NOT_CHECKED, "verified": False,
                                   "note": "静态检查不证明能执行；--probe 只做只读发现，found != verified"},
            "online_handshake": {"status": STATUS_NOT_CHECKED, "checked": False, "required": False,
                                 "note": "离线不启动 MCP，不称 online；握手由独立 smoke/preflight 负责"},
        },
        "packs": pack_count,
        "transport": transport,
        "server": {
            "name": server_name,
            "source": _rel(root, server_path),
            "registered_tools": sorted(registered),
            "configured": server_configured,
        },
        "catalog": {
            "runtime_tools": sorted(catalogs.runtimes),
            "capability_tools": sorted(catalogs.capabilities),
            "installable_python": sorted(catalogs.installable),
            "os_cli_allowlist": sorted(catalogs.os_cli),
            "rule": "依赖必须在声明里逐项写出，且每项能落到上述注册表之一；配置 server 不代偿",
        },
        "counts": {
            "target_tools": len(targets),
            "declared_tools": len(declared),
            "method_registered": sum(1 for row in rows if row["method_registered"]),
            "effect_registered": sum(1 for row in rows if row["effect_registered"]),
            "dependency_declared": sum(1 for row in rows if row["dependency_declared"]),
            "structural_resolved": sum(1 for row in rows if row["structural_ok"]),
            "source_verified": sum(1 for row in rows if row.get("source_verified")),
            "unresolved_items": len(unresolved),
        },
        "tools": rows,
        "unresolved": unresolved,
        "missing": missing,
        "registry_gaps": registry_gaps,
        "source_unverified": source_unverified,
        "source_evidence": [row["source_evidence"] for row in rows if row.get("source_evidence")],
        "undeclared": undeclared,
        "unknown_kind": unknown_kind,
        "not_checked": [
            {"dimension": "local_availability", "status": STATUS_NOT_CHECKED,
             "note": "不凭 which/find_spec 证明能执行；需要实跑由独立 smoke 负责"},
            {"dimension": "online_handshake", "status": STATUS_NOT_CHECKED,
             "note": "离线静态检查不建立 MCP 会话"},
        ],
        "server_only_tools": server_only,
        "unreferenced_effects": unreferenced_effects,
        "dependency_orphans": dependency_orphans,
        "source_errors": source_errors,
        "gaps": gaps,
    }
    if probe:
        result["probe"] = {
            "mode": "read-only-discovery",
            "spawned_software": False,
            "note": "found != verified：本轮只做只读发现；不改变 structural 判定，runtime_verified 仍为 false",
            "items": probes,
        }
    return result


def _write_json(path, value):
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=True, indent=2)


def _fixture(root, effect_tools, server_source, pack_tools, dependency_tools,
             runtime_tools=None, capability_tools=None, server_names=None,
             installable=None, os_cli=None, extra_files=None):
    _write_json(os.path.join(root, "Tool", "skill", "pack-a", "pack.json"),
                {"schema": "seep.pack/1", "id": "pack-a", "tools": pack_tools})
    _write_json(os.path.join(root, "Tool", "config", "tool-effects.json"),
                {"schema": "seep.tool-effects/1", "tools": effect_tools})
    _write_json(os.path.join(root, "Tool", "config", "tool-runtimes.json"),
                {"schemaVersion": 2, "tools": runtime_tools or {}})
    _write_json(os.path.join(root, "Tool", "config", "tool-capabilities.json"),
                {"schemaVersion": "1.0", "tools": capability_tools or {}})
    _write_json(os.path.join(root, "Tool", "config", "tool-install.json"),
                {"schemaVersion": "2.0", "installable": installable or {}})
    _write_json(os.path.join(root, "Tool", "config", "mcp-servers.json"),
                {"schemaVersion": 1, "servers": server_names or {"seep": {"command": "python"}}})
    _write_json(os.path.join(root, "Tool", "config", "mcp-tool-dependencies.json"), {
        "schema": DEPENDENCY_SCHEMA,
        "os_cli_allowlist": os_cli or {},
        "tools": dependency_tools,
    })
    with open(os.path.join(root, "Tool", "mcp", "seep_mcp_server.py"), "w", encoding="utf-8") as handle:
        handle.write(server_source)
    for relative, content in (extra_files or {}).items():
        full = os.path.join(root, relative.replace("/", os.sep))
        parent = os.path.dirname(full)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        if isinstance(content, bytes):
            with open(full, "wb") as handle:
                handle.write(content)
        else:
            with open(full, "w", encoding="utf-8") as handle:
                handle.write(content)


def _dep_entry(name, requires, line=1):
    return {name: {"source": {"function": name, "file": SERVER_REL, "line": line},
                   "evidence": "fixture",
                   "requires": requires}}


def _all(status, tool):
    return [item for item in status["unresolved"] if item["tool"] == tool]


def _row(status, tool):
    return next((row for row in status["tools"] if row["tool"] == tool), {})


def self_test():
    """隔离夹具正向/负向自测。每个用例都跑真实 check()，不复制判定实现。"""
    rows = []
    temp = tempfile.mkdtemp(prefix="seep-tool-contract-")
    effect = {"writes_filesystem": False, "executes_foreign_code": False,
              "touches_network": False, "mutates_target": False,
              "may_discard_data": False}
    try:
        for path in ("Tool/skill/pack-a", "Tool/config", "Tool/mcp"):
            os.makedirs(os.path.join(temp, path))

        # 夹具必须让声明的依赖**真的被实现用到**（否则来源证据维度会正确地拒）：
        # seep_known 用 builtin json + `['rabin2', ...]` 命令；seep_builtin 用 builtin re。
        source = ("import json\n"
                  "import re\n"
                  "from somewhere import server\n"
                  "def _run_cmd(cmd):\n"
                  "    return ''\n"
                  "@server.tool()\n"
                  "def seep_known():\n"
                  "    return json.dumps({'cmd': _run_cmd(['rabin2', '-I', 'x'])})\n"
                  "@server.tool()\n"
                  "def seep_builtin():\n"
                  "    return re.sub('a', 'b', 'aa')\n")
        builtin_dep = {"all_of": [{"kind": "builtin_module", "id": "json"}]}
        # seep_builtin 的实现用的是 re（不是 json）：声明与实现必须一致。
        builtin_re_dep = {"all_of": [{"kind": "builtin_module", "id": "re"}]}
        external_dep = {"all_of": [{"kind": "external_tool", "id": "rabin2"}]}
        pack_tools = ["seep_known", "seep_builtin"]
        effects = {"seep_known": effect, "seep_builtin": effect}

        # 1) 纯 builtin 工具：无任何 CLI / 注册表条目也必须通过（不需要 java/rabin2）。
        _fixture(temp, effects, source, pack_tools,
                 dict(list(_dep_entry("seep_known", builtin_dep).items())
                      + list(_dep_entry("seep_builtin", builtin_re_dep).items())))
        good = check(temp)
        rows.append({"name": "builtin-only-passes", "ok": good["ok"],
                     "detail": "纯 builtin 依赖不需要 CLI，也不需要运行时注册表条目"})

        # 2) server 已配置 + 外部依赖未注册 → 必须失败（旧实现此时 PASS）。
        _fixture(temp, effects, source, pack_tools,
                 dict(list(_dep_entry("seep_known", external_dep).items())
                      + list(_dep_entry("seep_builtin", builtin_re_dep).items())))
        configured_only = check(temp)
        gap_rows = _all(configured_only, "seep_known")
        known_row = _row(configured_only, "seep_known")
        rows.append({"name": "configured-server-does-not-satisfy-cli-dependency",
                     "ok": (not configured_only["ok"]
                            and configured_only["transport"]["configured"]
                            and any(item["status"] == STATUS_REGISTRY_GAP for item in gap_rows)
                            and known_row.get("registry_closure") is False),
                     "detail": "server 已配置 + rabin2 未注册 → registry_gap，且不得算 pass"})

        # 3) all_of 缺一项 → 失败。
        partial = {"all_of": [{"kind": "builtin_module", "id": "json"},
                              {"kind": "external_tool", "id": "rabin2"}]}
        _fixture(temp, effects, source, pack_tools,
                 dict(list(_dep_entry("seep_known", partial).items())
                      + list(_dep_entry("seep_builtin", builtin_re_dep).items())))
        missing_one = check(temp)
        rows.append({"name": "all_of-missing-one-fails",
                     "ok": (not missing_one["ok"]
                            and bool(_all(missing_one, "seep_known"))
                            and _row(missing_one, "seep_known").get("registry_closure") is False),
                     "detail": "all_of 任一项未闭合即失败"})

        # 4) any_of 有一支注册通过 → 通过。
        any_dep = {"all_of": [{"kind": "builtin_module", "id": "json"}],
                   "any_of": [{"kind": "external_tool", "id": "rabin2"},
                              {"kind": "python_lib", "id": "pefile"}]}
        _fixture(temp, effects, source, pack_tools,
                 dict(list(_dep_entry("seep_known", any_dep).items())
                      + list(_dep_entry("seep_builtin", builtin_re_dep).items())),
                 installable={"pefile": {"methods": [{"type": "pip", "pkg": "pefile"}]}})
        any_ok = check(temp)
        rows.append({"name": "any_of-one-registered-passes", "ok": any_ok["ok"],
                     "detail": "any_of 至少一支注册通过即闭合"})

        # 5) 缺 effect → 失败。
        _fixture(temp, {"seep_builtin": effect}, source, pack_tools,
                 dict(list(_dep_entry("seep_known", builtin_dep).items())
                      + list(_dep_entry("seep_builtin", builtin_re_dep).items())))
        missing_effect = check(temp)
        rows.append({"name": "missing-effect-fails",
                     "ok": (not missing_effect["ok"]
                            and any("effect_registered" in gap for gap in missing_effect["gaps"])),
                     "detail": "缺效果标注是显式 gap"})

        # 6) 缺 @server.tool() 注册 → 失败。
        _fixture(temp, effects, "from somewhere import server\n", pack_tools,
                 dict(list(_dep_entry("seep_known", builtin_dep).items())
                      + list(_dep_entry("seep_builtin", builtin_re_dep).items())))
        missing_server = check(temp)
        rows.append({"name": "missing-server-registration-fails",
                     "ok": (not missing_server["ok"]
                            and any("method_registered" in gap for gap in missing_server["gaps"])),
                     "detail": "缺装饰器/函数注册是显式 gap"})

        # 7) pack 里的未知新工具（依赖表里没有）→ 失败并要求补映射。
        _fixture(temp, dict(list(effects.items()) + [("seep_unknown", effect)]), source,
                 ["seep_known", "seep_builtin", "seep_unknown"],
                 dict(list(_dep_entry("seep_known", builtin_dep).items())
                      + list(_dep_entry("seep_builtin", builtin_re_dep).items())))
        unknown_pack = check(temp)
        unknown_row = next((r for r in unknown_pack["tools"] if r["tool"] == "seep_unknown"), {})
        rows.append({"name": "unknown-pack-tool-fails",
                     "ok": (not unknown_pack["ok"] and unknown_row.get("dependency_declared") is False
                            and any("补映射" in gap for gap in unknown_pack["gaps"])),
                     "detail": "未知新工具必须补 mcp-tool-dependencies.json 映射，不能默认放过"})

        # 8) 伪可执行命令不等于 ready：--probe 找到文件也不改变 structural / runtime_verified。
        fake_bin = os.path.join(temp, "Tool", "mcp", "Tool", "safe", "radare2", "bin", "rabin2.exe")
        os.makedirs(os.path.dirname(fake_bin))
        with open(fake_bin, "wb") as handle:
            handle.write(b"")
        _fixture(temp, effects, source, pack_tools,
                 dict(list(_dep_entry("seep_known", external_dep).items())
                      + list(_dep_entry("seep_builtin", builtin_re_dep).items())),
                 runtime_tools={"rabin2": {"probe": {
                     "repoPaths": ["Tool/mcp/Tool/safe/radare2/bin/rabin2.exe"]}}})
        probed = check(temp, probe=True)
        probe_row = next((r for r in probed["tools"] if r["tool"] == "seep_known"), {})
        probe_found = [item for item in probed.get("probe", {}).get("items", [])
                       if item["tool"] == "seep_known" and item["discovery"] == "found"]
        rows.append({"name": "fake-executable-is-not-ready",
                     "ok": (probe_found
                            and probed["runtime_verified"] is False
                            and probed["evidence_level"] == "structural"
                            and probe_row.get("local_availability") == STATUS_NOT_CHECKED
                            and all(item["verified"] is False for item in probe_found)),
                     "detail": "probe 命中文件只报 found，不叫 verified，也不改 structural 判定"})

        # 9) 空依赖映射 → fail-closed（空表不等于没有依赖）。
        _fixture(temp, effects, source, pack_tools, {})
        empty_map = check(temp)
        rows.append({"name": "empty-dependency-map-fails-closed",
                     "ok": (not empty_map["ok"]
                            and any("空映射" in error for error in empty_map["source_errors"])),
                     "detail": "依赖表为空映射时直接报 source error，绝不 PASS"})
    finally:
        shutil.rmtree(temp, ignore_errors=True)

    ok = bool(rows) and all(row["ok"] for row in rows)
    return {"schema": SCHEMA, "ok": ok, "mode": "self-test",
            "evidence_level": "structural", "runtime_verified": False, "cases": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Static dependency-closure checker: pack.tools -> @server.tool() -> effects "
                    "-> dependency declaration -> registry closure. "
                    "Local availability and online handshake stay not_checked.")
    parser.add_argument("--json", action="store_true", help="emit structured JSON")
    parser.add_argument("--self-test", action="store_true",
                        help="run isolated positive and negative fixture tests")
    parser.add_argument("--probe", action="store_true",
                        help="read-only discovery only (no software is spawned); found != verified")
    parser.add_argument("--root", default=None, help="repository root (defaults to this checkout)")
    args = parser.parse_args(argv)

    if args.self_test:
        result = self_test()
    else:
        result = check(args.root, probe=args.probe)

    if args.json or args.self_test:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=False))
    else:
        print("tool-contract-check: %s" % ("PASS" if result.get("ok") else "FAIL"))
        print("evidence_level=%s runtime_verified=%s"
              % (result.get("evidence_level"), result.get("runtime_verified")))
        print("tools=%d unresolved=%d registry_gap=%d not_checked=%d"
              % (len(result.get("tools", [])), len(result.get("unresolved", [])),
                 len(result.get("registry_gaps", [])), len(result.get("not_checked", []))))
        for gap in result.get("gaps", [])[:16]:
            print("- " + gap)
        print("not_checked: %s" % ", ".join(
            item["dimension"] for item in result.get("not_checked", [])))
        if result.get("probe"):
            found = [item for item in result["probe"]["items"]
                     if item.get("discovery") in ("found", "not_found")]
            print("probe(read-only, spawned_software=%s): %d 项可发现性；found != verified"
                  % (result["probe"]["spawned_software"], len(found)))
        if result.get("registry_gaps"):
            print("最小下一步（registry_gap，本轮不改 capabilities/runtimes）：")
            for item in result["registry_gaps"][:8]:
                print("  * %s: 给 %r 补一条 tool-runtimes.json#tools 或 "
                      "tool-capabilities.json#tools 条目（或删掉声明）"
                      % (item["tool"], item["id"]))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
