#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regression tests for the real `Tool/scripts/tool-contract-check.py`.

Run: python -B Tool/scripts/test_tool_dependencies.py

Every case drives the *real* checker (`check()` / `self_test()`) against fixtures in a
temporary directory; no judgement logic is copied here. Assertions focus on the property
that broke in the 2026-10-27 audit: a configured MCP server must never substitute for a
missing CLI dependency registration, and "found on disk" is never "verified".

Nothing is executed, installed, deployed or networked by this file. The only subprocesses
are `python -B` invocations of the checker itself (to cover the --json/--self-test/--probe
entry points); no external tool and no target is ever spawned.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CHECKER_PATH = HERE / "tool-contract-check.py"
SERVER_REL = "Tool/mcp/seep_mcp_server.py"
DEPENDENCY_REL = "Tool/config/mcp-tool-dependencies.json"


def _load_checker():
    spec = importlib.util.spec_from_file_location("seep_tool_contract_check", CHECKER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = _load_checker()

EFFECT = {
    "writes_filesystem": False,
    "executes_foreign_code": False,
    "touches_network": False,
    "mutates_target": False,
    "may_discard_data": False,
}

# 夹具实现必须让声明的依赖**真的出现在实现里**：来源证据是独立判据（AST，不是全文件
# contains 自证）。fixture 如果只 `return ''`，声明 builtin_module json 会被正确地判成
# `unverified_source`。因此 `seep_known` 里真实使用 json / rabin2 / tasklist / ps / pefile
# （只用于 AST，不执行），`seep_builtin` 里真实使用 re。
SERVER_SOURCE = (
    "import json\n"
    "import re\n"
    "from somewhere import server\n"
    "def _run_cmd(cmd):\n"
    "    return ''\n"
    "@server.tool()\n"
    "def seep_known():\n"
    "    import pefile\n"
    "    _run_cmd(['rabin2', '-I', 'x'])\n"
    "    _run_cmd(['tasklist'])\n"
    "    _run_cmd(['ps'])\n"
    "    return json.dumps({'sections': len(pefile.PE('x').sections)})\n"
    "@server.tool()\n"
    "def seep_builtin():\n"
    "    return re.sub('a', 'b', 'aa')\n"
)


def _write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


class FixtureCase(unittest.TestCase):
    """Shared fixture writer: a minimal repo where every input is explicit."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-tool-deps-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pack_tools = ["seep_known", "seep_builtin"]
        self.effects = {"seep_known": dict(EFFECT), "seep_builtin": dict(EFFECT)}
        self.deps = {
            "seep_known": self._dep("seep_known", {
                "all_of": [{"kind": "builtin_module", "id": "json"}]}),
            "seep_builtin": self._dep("seep_builtin", {
                "all_of": [{"kind": "builtin_module", "id": "re"}]}),
        }
        self.server_source = SERVER_SOURCE
        self.runtimes = {}
        self.capabilities = {}
        self.installable = {}
        self.os_cli = {}
        self.server_names = {"seep": {"command": "python", "transport": "stdio"}}
        self.extra_files = {}

    @staticmethod
    def _dep(name, requires):
        return {
            "source": {"function": name, "file": SERVER_REL, "line": 1},
            "evidence": "fixture",
            "requires": requires,
        }

    def materialise(self):
        _write_json(self.root / "Tool/skill/pack-a/pack.json",
                    {"schema": "seep.pack/1", "id": "pack-a", "tools": self.pack_tools})
        _write_json(self.root / "Tool/config/tool-effects.json",
                    {"schema": "seep.tool-effects/1", "tools": self.effects})
        _write_json(self.root / "Tool/config/tool-runtimes.json",
                    {"schemaVersion": 2, "tools": self.runtimes})
        _write_json(self.root / "Tool/config/tool-capabilities.json",
                    {"schemaVersion": "1.0", "tools": self.capabilities})
        _write_json(self.root / "Tool/config/tool-install.json",
                    {"schemaVersion": "2.0", "installable": self.installable})
        _write_json(self.root / "Tool/config/mcp-servers.json",
                    {"schemaVersion": 1, "servers": self.server_names})
        _write_json(self.root / DEPENDENCY_REL, {
            "schema": checker.DEPENDENCY_SCHEMA,
            "os_cli_allowlist": self.os_cli,
            "tools": self.deps,
        })
        server_path = self.root / SERVER_REL
        server_path.parent.mkdir(parents=True, exist_ok=True)
        server_path.write_text(self.server_source, encoding="utf-8")
        for relative, content in self.extra_files.items():
            full = self.root / relative
            full.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                full.write_bytes(content)
            else:
                full.write_text(content, encoding="utf-8")

    def run_check(self, probe=False):
        self.materialise()
        return checker.check(str(self.root), probe=probe)

    @staticmethod
    def row(result, tool):
        return next((r for r in result["tools"] if r["tool"] == tool), {})


class StructuralSeparationTests(FixtureCase):
    def test_configured_server_never_satisfies_external_cli_dependency(self):
        """The audit defect: server_configured used to make runtime_ok True."""
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "external_tool", "id": "rabin2"}]})
        result = self.run_check()
        self.assertTrue(result["transport"]["configured"])
        self.assertFalse(result["ok"])
        row = self.row(result, "seep_known")
        self.assertFalse(row["registry_closure"])
        self.assertFalse(row["structural_ok"])
        gap_ids = {(g["tool"], g["id"], g["status"]) for g in result["registry_gaps"]}
        self.assertIn(("seep_known", "rabin2", "registry_gap"), gap_ids)

    def test_builtin_only_tool_passes_without_any_cli_or_registry_entry(self):
        result = self.run_check()
        self.assertEqual(result["unresolved"], [])
        self.assertTrue(result["ok"])
        self.assertEqual(self.row(result, "seep_builtin")["requires"]["all_of"][0]["kind"],
                         "builtin_module")

    def test_missing_transport_config_is_its_own_dimension_only(self):
        self.server_names = {"other": {"command": "python"}}
        result = self.run_check()
        self.assertFalse(result["transport"]["configured"])
        self.assertEqual(result["dimensions"]["transport_config"]["status"], "missing")
        # dependency closure for builtin tools is untouched by the transport dimension
        self.assertTrue(self.row(result, "seep_builtin")["registry_closure"])


class RequirementGroupTests(FixtureCase):
    def test_all_of_fails_when_one_branch_unregistered(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "builtin_module", "id": "json"},
                       {"kind": "external_tool", "id": "rabin2"}]})
        result = self.run_check()
        self.assertFalse(result["ok"])
        row = self.row(result, "seep_known")
        self.assertFalse(row["registry_closure"])
        failing = [u for u in result["unresolved"]
                   if u["tool"] == "seep_known" and u["group"] == "all_of"]
        self.assertEqual([u["id"] for u in failing], ["rabin2"])

    def test_all_of_fails_when_repo_asset_absent(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "repo_asset", "path": "Tool/mcp/Tool/safe/apktool/apktool.jar"}]})
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertEqual([u["status"] for u in result["missing"]], ["missing"])

    def test_any_of_passes_with_one_registered_branch(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "builtin_module", "id": "json"}],
            "any_of": [{"kind": "external_tool", "id": "rabin2"},
                       {"kind": "python_lib", "id": "pefile"}]})
        self.installable = {"pefile": {"methods": [{"type": "pip", "pkg": "pefile"}]}}
        result = self.run_check()
        self.assertTrue(result["ok"], result["gaps"])
        self.assertTrue(self.row(result, "seep_known")["registry_closure"])

    def test_any_of_fails_when_no_branch_registered(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "builtin_module", "id": "json"}],
            "any_of": [{"kind": "external_tool", "id": "rabin2"},
                       {"kind": "python_lib", "id": "pefile"}]})
        result = self.run_check()
        self.assertFalse(result["ok"])
        branches = [u for u in result["unresolved"]
                    if u["tool"] == "seep_known" and u["group"] == "any_of"]
        self.assertTrue(any(u["kind"] == "any_of" for u in branches))

    def test_unregistered_python_lib_is_registry_gap(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "python_lib", "id": "requests"}]})
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertEqual([u["id"] for u in result["registry_gaps"]], ["requests"])

    def test_unlisted_os_cli_is_flagged(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "builtin_module", "id": "json"}],
            "any_of": [{"kind": "os_cli", "id": "tasklist"},
                       {"kind": "os_cli", "id": "ps"}]})
        self.os_cli = {"tasklist": "fixture"}
        result = self.run_check()
        self.assertTrue(result["ok"], result["gaps"])
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "builtin_module", "id": "json"}],
            "any_of": [{"kind": "os_cli", "id": "nmap"}]})
        self.os_cli = {}
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertEqual([u["status"] for u in result["undeclared"]], ["undeclared"])

    def test_bogus_builtin_module_is_not_silently_accepted(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "builtin_module", "id": "definitely_not_stdlib_xyz"}]})
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertEqual([u["status"] for u in result["undeclared"]], ["undeclared"])


class RegistrationTests(FixtureCase):
    def test_missing_effect_fails(self):
        del self.effects["seep_known"]
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertFalse(self.row(result, "seep_known")["effect_registered"])
        self.assertTrue(any("effect_registered" in g for g in result["gaps"]))

    def test_missing_server_registration_fails(self):
        self.server_source = "from somewhere import server\n"
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertTrue(any("method_registered" in g for g in result["gaps"]))

    def test_unknown_pack_tool_needs_a_mapping(self):
        self.pack_tools = ["seep_known", "seep_builtin", "seep_newcomer"]
        self.effects["seep_newcomer"] = dict(EFFECT)
        self.server_source = SERVER_SOURCE + (
            "@server.tool()\n"
            "def seep_newcomer():\n"
            "    return ''\n")
        result = self.run_check()
        self.assertFalse(result["ok"])
        row = self.row(result, "seep_newcomer")
        self.assertFalse(row["dependency_declared"])
        self.assertFalse(row["structural_ok"])
        self.assertTrue(any("补映射" in g for g in result["gaps"]))

    def test_registered_tool_without_pack_is_still_audited(self):
        """20 个 MCP 方法里有的没被任何 pack 引用；它们也必须逐项声明依赖。"""
        self.server_source = SERVER_SOURCE + (
            "@server.tool()\n"
            "def seep_orphan():\n"
            "    return ''\n")
        self.effects["seep_orphan"] = dict(EFFECT)
        result = self.run_check()
        self.assertFalse(result["ok"])
        row = self.row(result, "seep_orphan")
        self.assertEqual(row["packs"], [])
        self.assertFalse(row["dependency_declared"])


class SourceEvidenceTests(FixtureCase):
    """来源事实的真值：行位移不失败，错函数/错文件/虚假依赖必须失败。

    这些用例都不靠“全文件字符串 contains”：checker 必须从 AST 得到证据，
    否则改一个 docstring / 错误消息就能伪造依赖。
    """

    def rows(self, result):
        return {row["tool"]: row for row in result["tools"]}

    def test_rechecking_same_root_reads_changed_source(self):
        self.materialise()
        self.assertTrue(checker.check(str(self.root))["ok"])
        source = self.root / SERVER_REL
        source.write_text(self.server_source.replace(
            "    return json.dumps({'sections': len(pefile.PE('x').sections)})",
            "    return ''"), encoding="utf-8")
        result = checker.check(str(self.root))
        self.assertFalse(result["ok"])
        self.assertFalse(self.row(result, "seep_known")["source_verified"])

    def test_unused_command_vector_does_not_prove_external_use(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "external_tool", "id": "rabin2"}]})
        self.runtimes = {"rabin2": {"probe": {"names": ["rabin2"]}}}
        self.server_source = SERVER_SOURCE.replace(
            "    _run_cmd(['rabin2', '-I', 'x'])", "    unused = ['rabin2', '-I', 'x']")
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertFalse(self.row(result, "seep_known")["source_verified"])

    def test_run_capture_is_an_audited_execution_boundary(self):
        """A structured-capture helper that really spawns is valid command evidence."""
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "external_tool", "id": "rabin2"}]})
        self.runtimes = {"rabin2": {"probe": {"names": ["rabin2"]}}}
        self.server_source = SERVER_SOURCE.replace(
            "def _run_cmd(cmd):\n    return ''\n",
            "def _run_cmd(cmd):\n"
            "    return _run_capture(cmd)\n"
            "def _run_capture(cmd):\n"
            "    return subprocess.run(cmd)\n",
        ).replace(
            "    _run_cmd(['rabin2', '-I', 'x'])",
            "    _run_capture(['rabin2', '-I', 'x'])",
        )
        result = self.run_check()
        self.assertTrue(result["ok"], result["gaps"])
        self.assertTrue(self.row(result, "seep_known")["source_verified"])

    def test_unused_from_import_does_not_prove_library_use(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "builtin_module", "id": "hashlib"}]})
        self.server_source = "from hashlib import sha256\n" + SERVER_SOURCE
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertFalse(self.row(result, "seep_known")["source_verified"])

    def test_used_import_alias_proves_library_use(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "builtin_module", "id": "hashlib"}]})
        self.server_source = ("from hashlib import sha256 as digest\n" + SERVER_SOURCE.replace(
            "    return json.dumps({'sections': len(pefile.PE('x').sections)})",
            "    return digest(b'x').hexdigest()"))
        result = self.run_check()
        self.assertTrue(result["ok"], result["gaps"])

    def test_line_shift_from_inserted_lines_does_not_fail(self):
        """正对照：在函数前后/体内加空行与注释（语义不变）不得判失败。"""
        self.materialise()
        server_path = self.root / SERVER_REL
        original = server_path.read_text(encoding="utf-8")
        baseline = checker.check(str(self.root))
        self.assertTrue(baseline["ok"], baseline["gaps"][:4])
        for shifted in ("\n\n\n" + original,
                        original.replace("def seep_known():",
                                         "# reviewed\n\ndef seep_known():", 1),
                        original.replace("    return json.dumps",
                                         "\n\n    return json.dumps", 1)):
            server_path.write_text(shifted, encoding="utf-8")
            result = checker.check(str(self.root))
            self.assertTrue(result["ok"], result["gaps"][:6])
            self.assertTrue(self.rows(result)["seep_known"]["source_verified"])
            import ast
            anchor = next(n.lineno for n in ast.parse(shifted).body
                          if isinstance(n, ast.FunctionDef) and n.name == "seep_known")
            self.assertEqual(self.rows(result)["seep_known"]["source_evidence"]["anchor_line"], anchor)

    def test_declared_line_behind_the_function_is_relocated_not_failed(self):
        """行号落后（旧值）时按 AST 重定位；不因“line != def 行”而失败。"""
        self.deps["seep_known"]["source"]["line"] = 1
        result = self.run_check()
        self.assertTrue(result["ok"], result["gaps"][:6])
        evidence = self.rows(result)["seep_known"]["source_evidence"]
        self.assertIs(evidence["relocated"], True)
        self.assertEqual(evidence["declared_line"], 1)
        self.assertIn("def seep_known(",
                      (self.root / SERVER_REL).read_text(encoding="utf-8").splitlines()
                      [evidence["anchor_line"] - 1])

    def test_line_pointing_at_another_def_is_still_ok_because_ast_is_the_truth(self):
        """line 指到别的函数定义：不作为真理（AST 仍能定位），但绝不因此虚报通过。"""
        self.deps["seep_known"]["source"]["line"] = 999
        result = self.run_check()
        row = self.rows(result)["seep_known"]
        self.assertTrue(row["source_verified"])
        self.assertIs(row["source_evidence"]["relocated"], True)

    def test_renamed_function_fails(self):
        """改函数名（声明还在）→ 必须失败（source 锚点不存在）。"""
        self.server_source = SERVER_SOURCE.replace("def seep_known():",
                                                   "def seep_known_renamed():", 1)
        result = self.run_check()
        self.assertFalse(result["ok"])
        statuses = {item["status"] for item in result["unresolved"]
                    if item["tool"] == "seep_known" and item["group"] == "source"}
        self.assertEqual(statuses, {"source_mismatch"})

    def test_missing_function_entirely_fails(self):
        self.server_source = "from somewhere import server\n\n@server.tool()\ndef seep_builtin():\n    return ''\n"
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertTrue(any(item["tool"] == "seep_known" and item["status"] == "source_mismatch"
                            for item in result["unresolved"]))

    def test_wrong_source_file_fails_closed(self):
        self.deps["seep_known"]["source"]["file"] = "Tool/mcp/other_server.py"
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertTrue(any("source.file" in error for error in result["source_errors"]))

    def test_removing_the_real_call_fails(self):
        """删真实调用：即使还留着 `json` 这个名字的字符串也不行。"""
        self.server_source = SERVER_SOURCE.replace(
            "    return json.dumps({'sections': len(pefile.PE('x').sections)})",
            "    return ''", 1)
        result = self.run_check()
        self.assertFalse(result["ok"])
        row = self.rows(result)["seep_known"]
        self.assertFalse(row["source_verified"])
        statuses = {item["status"] for item in result["unresolved"]
                    if item["tool"] == "seep_known" and item["group"] == "source"}
        self.assertEqual(statuses, {"unverified_source"})

    def test_docstring_or_error_message_mention_is_not_evidence(self):
        """只在 docstring / 错误消息里提一下依赖，不算使用证据（不许全文件 contains 自证）。"""
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "builtin_module", "id": "hashlib"}]})
        self.server_source = SERVER_SOURCE.replace(
            "def seep_known():\n",
            "def seep_known():\n    \"\"\"hashlib 相关：只是文档里提一句。\"\"\"\n    # hashlib 也写在注释里\n"
            "    msg = 'hashlib is not imported here'\n", 1)
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertEqual({item["status"] for item in result["unresolved"]
                          if item["tool"] == "seep_known" and item["group"] == "source"},
                         {"unverified_source"})

    def test_fake_external_dependency_fails(self):
        """声明一个实现里根本没调用的外部工具 → 必须失败，不得静默 pass。"""
        # 前提：rabin2 在注册表里已登记（否则只是 registry_gap，测不到“用不到”这条）
        self.runtimes = {"rabin2": {"probe": {"names": ["rabin2"]}}}
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "external_tool", "id": "tshark"}]})
        result = self.run_check()
        self.assertFalse(result["ok"])
        row = self.rows(result)["seep_known"]
        self.assertIs(row["source_verified"], False)
        self.assertTrue(any(item["tool"] == "seep_known" and item["status"] == "unverified_source"
                            for item in result["unresolved"]))

    def test_evidence_via_outside_whitelist_or_wrong_symbol_fails(self):
        """helper 跳转是白名单：模块不在白名单 / symbol 不符 / helper 没被调用 都要失败。"""
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "repo_asset", "path": "Tool/config/kb-synonyms.json"}]})
        self.extra_files = {"Tool/config/kb-synonyms.json": "{}",
                            "Tool/mcp/seep_contract.py": (ROOT / "Tool/mcp/seep_contract.py")
                            .read_text(encoding="utf-8")}
        base = {"helper": "_run_cmd", "module": "Tool/mcp/seep_contract.py",
                "symbol": "kb-synonyms.json"}
        for index, broken in enumerate((dict(base, module="Tool/scripts/case_state.py"),
                                       dict(base, symbol="apktool.jar"),
                                       dict(base, helper="_never_called_helper"))):
            with self.subTest(variant=index):
                self.deps["seep_known"]["requires"]["all_of"][0]["evidence_via"] = broken
                result = self.run_check()
                self.assertFalse(result["ok"], broken)
                self.assertIs(self.rows(result)["seep_known"]["source_verified"], False)


# 跨文件 helper 夹具：seep_mod 真调用 `from seep_contract import ...` 的成员；模块被
# import 本身不是证据。（`seep_contract.py` 是 checker 白名单里的已审 helper 模块。）
CONTRACT_SOURCE = (
    "def pcap_params(mode, port, rows, host):\n"
    "    return {'mode': mode}\n"
    "def pcap_status(records, rows, returned=None):\n"
    "    return 'ok', 'ok'\n"
    "def pcap_rows(field, text, host='', max_rows=0):\n"
    "    return [], 0, 0\n"
    "PCAP_POLICY = 'kb-synonyms.json'\n"
)
HELPER_SOURCE = (
    "import json\n"
    "from somewhere import server\n"
    "from seep_contract import pcap_params as _pcap_params, pcap_status as _pcap_status\n"
    "\n"
    "@server.tool()\n"
    "def seep_mod(path: str = 'x'):\n"
    "    params, reason = _pcap_params('summary', 0, 40, '')\n"
    "    return json.dumps(params) + str(reason)\n"
    "\n"
    "@server.tool()\n"
    "def seep_other(path: str = 'x'):\n"
    "    return json.dumps(list(_pcap_status([], 0)))\n"
)
VIA = {"helper": "_pcap_params", "module": "Tool/mcp/seep_contract.py",
       "symbol": "seep_contract.py"}


class HelperEvidenceViaTests(FixtureCase):
    """`evidence_via` 必须证到 helper 级；模块已 import 不等于它的 helper 被调用。

    这是 `kind == repo_module && module == path` 那条路径的直接回归：旧实现只要
    实现 import 了该模块就提前 return True，于是假 helper / 错 module / 错 symbol
    都能刷绿。这里全部走真实 checker（`check()`），不复制判定逻辑。
    """

    def setUp(self):
        super().setUp()
        self.server_source = HELPER_SOURCE
        self.extra_files = {"Tool/mcp/seep_contract.py": CONTRACT_SOURCE}
        self.pack_tools = ["seep_mod", "seep_other"]
        self.effects = {"seep_mod": dict(EFFECT), "seep_other": dict(EFFECT)}
        self.deps = {
            "seep_mod": self._dep("seep_mod", {
                "all_of": [{"kind": "repo_module", "path": "Tool/mcp/seep_contract.py",
                            "evidence_via": dict(VIA)}]}),
            "seep_other": self._dep("seep_other", {
                "all_of": [{"kind": "builtin_module", "id": "json"}]}),
        }

    def via(self, **patch):
        doc = self.deps["seep_mod"]["requires"]["all_of"][0]
        doc["evidence_via"] = dict(VIA, **patch)

    def test_baseline_helper_via_passes(self):
        result = self.run_check()
        self.assertTrue(result["ok"], result["gaps"][:6])
        self.assertTrue(self.row(result, "seep_mod")["source_verified"])

    def test_moving_blank_lines_does_not_change_the_verdict(self):
        """空行/注释位移不影响 helper 级判据（不重引入行号真理）。"""
        self.materialise()
        path = self.root / SERVER_REL
        original = path.read_text(encoding="utf-8")
        for shifted in ("\n\n" + original,
                        original.replace("def seep_mod(path: str = 'x'):",
                                         "# reviewed\n\ndef seep_mod(path: str = 'x'):", 1),
                        original.replace("    params, reason = _pcap_params",
                                         "\n\n    params, reason = _pcap_params", 1)):
            path.write_text(shifted, encoding="utf-8")
            result = checker.check(str(self.root))
            self.assertTrue(result["ok"], result["gaps"][:6])
            self.assertTrue(self.row(result, "seep_mod")["source_verified"])

    def test_fake_helper_fails_even_though_the_module_is_imported(self):
        """核心回归：模块已 import + 假 helper 名 → 必须 fail（旧短路会 pass）。"""
        self.via(helper="_pcap_fake_helper")
        result = self.run_check()
        self.assertFalse(result["ok"], "假 helper 不能因为模块被 import 就通过")
        row = self.row(result, "seep_mod")
        self.assertIs(row["source_verified"], False)
        detail = " ".join(str(d.get("detail")) for d in row["source_evidence"]["detail"])
        self.assertIn("不存在", detail)

    def test_helper_imported_but_never_called_fails(self):
        """存在（且已 import）但实现里没调用的 helper → 必须 fail。"""
        self.via(helper="_pcap_status")
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertIs(self.row(result, "seep_mod")["source_verified"], False)

    def test_wrong_module_for_the_same_symbol_fails(self):
        self.via(module="Tool/mcp/tool_autodiscover.py")
        self.extra_files["Tool/mcp/tool_autodiscover.py"] = "def discover():\n    return None\n"
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertIs(self.row(result, "seep_mod")["source_verified"], False)

    def test_wrong_symbol_fails(self):
        for symbol in ("pcap_contract.py", "Tool/mcp/other.py", ""):
            with self.subTest(symbol=symbol):
                self.setUp()
                self.via(symbol=symbol)
                result = self.run_check()
                self.assertFalse(result["ok"], symbol)
                self.assertIs(self.row(result, "seep_mod")["source_verified"], False)

    def test_cross_alias_helper_fails(self):
        """用另一模块的（真）helper 冒本依赖：跨 alias 必须 fail。"""
        self.server_source = HELPER_SOURCE.replace(
            "from seep_contract import pcap_params as _pcap_params, pcap_status as _pcap_status",
            "from tool_autodiscover import find_tool as _pcap_params\n"
            "from seep_contract import pcap_status as _pcap_status", 1)
        self.extra_files["Tool/mcp/tool_autodiscover.py"] = "def find_tool():\n    return None\n"
        result = self.run_check()
        self.assertFalse(result["ok"], "跨 alias 拿别的模块的 helper 冒名必须失败")
        self.assertIs(self.row(result, "seep_mod")["source_verified"], False)

    def test_removing_the_helper_chain_fails(self):
        """helper 链被删（函数还在但不再被实现调用）→ 依赖证据失效。"""
        self.server_source = HELPER_SOURCE.replace(
            "    params, reason = _pcap_params('summary', 0, 40, '')",
            "    params, reason = {}, ''", 1)
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertIs(self.row(result, "seep_mod")["source_verified"], False)

    def test_repo_module_without_via_only_proves_module_level_use(self):
        """无 evidence_via 时 repo_module 只证到“用了该模块”（不冒充 helper 级证明）。"""
        del self.deps["seep_mod"]["requires"]["all_of"][0]["evidence_via"]
        result = self.run_check()
        self.assertTrue(result["ok"], result["gaps"][:6])
        evidence = self.row(result, "seep_mod")["source_evidence"]
        detail = " ".join(str(d.get("detail")) for d in evidence["detail"])
        self.assertIn("import", detail)
        self.assertNotIn("helper", detail)


class FailClosedTests(FixtureCase):
    def test_invalid_server_ast_returns_structured_failure(self):
        self.server_source = "def broken(:\n"
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertFalse(self.row(result, "seep_known")["source_verified"])
        self.assertTrue(result["source_errors"])

    def test_missing_server_returns_structured_failure(self):
        self.materialise()
        (self.root / SERVER_REL).unlink()
        result = checker.check(str(self.root))
        self.assertFalse(result["ok"])
        self.assertFalse(self.row(result, "seep_known")["source_verified"])

    def test_malformed_dependency_shapes_return_structured_failure(self):
        for patch in ({"requires": "bad"}, {"requires": {"all_of": 1}},
                      {"requires": {"any_of": {"kind": "builtin_module", "id": "json"}}},
                      {"source": "bad"}):
            with self.subTest(patch=patch):
                self.deps["seep_known"] = dict(self._dep("seep_known", {
                    "all_of": [{"kind": "builtin_module", "id": "json"}]}), **patch)
                result = self.run_check(probe=True)
                self.assertFalse(result["ok"])
                self.assertFalse(self.row(result, "seep_known")["source_verified"])
                self.assertTrue(result["source_errors"])

    def test_missing_declaration_does_not_report_source_dimension_ok(self):
        del self.deps["seep_known"]
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertNotEqual(result["dimensions"]["source_evidence"]["status"], "ok")

    def test_empty_dependency_map_fails_closed(self):
        self.deps = {}
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertTrue(any("空映射" in e for e in result["source_errors"]))

    def test_wrong_dependency_schema_fails_closed(self):
        self.materialise()
        doc = json.loads((self.root / DEPENDENCY_REL).read_text(encoding="utf-8"))
        doc["schema"] = "seep.mcp-tool-dependencies/0"
        _write_json(self.root / DEPENDENCY_REL, doc)
        result = checker.check(str(self.root))
        self.assertFalse(result["ok"])
        self.assertTrue(any("schema 必须是" in e for e in result["source_errors"]))

    def test_unknown_dependency_kind_fails_closed(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "magic_pixie", "id": "json"}]})
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertTrue(any("未知 kind" in e for e in result["source_errors"]))

    def test_empty_requires_fails_closed(self):
        self.deps["seep_known"] = self._dep("seep_known", {"all_of": [], "any_of": []})
        result = self.run_check()
        self.assertFalse(result["ok"])
        self.assertTrue(any("同时为空" in e for e in result["source_errors"]))

    def test_malformed_dependency_item_fails_closed_without_crashing(self):
        """配置写错（字符串代替对象）不能把 checker 搞崩，也不能算通过。"""
        self.deps["seep_known"] = self._dep("seep_known", {"all_of": ["rabin2"]})
        result = self.run_check(probe=True)
        self.assertFalse(result["ok"])
        self.assertTrue(any("元素必须是对象" in e for e in result["source_errors"]))
        self.assertEqual([u["status"] for u in result["unknown_kind"]], ["unknown_kind"])

    def test_missing_dependency_config_file_fails_closed(self):
        self.materialise()
        (self.root / DEPENDENCY_REL).unlink()
        result = checker.check(str(self.root))
        self.assertFalse(result["ok"])
        self.assertTrue(any(DEPENDENCY_REL in e for e in result["source_errors"]))
        self.assertFalse(self.row(result, "seep_known")["dependency_declared"])


class ProbeAndEvidenceLevelTests(FixtureCase):
    def test_dotted_library_probe_does_not_import_parent_package(self):
        package = "seep_probe_parent_fixture"
        self.extra_files = {
            package + "/__init__.py": "raise RuntimeError('parent package was imported')\n",
            package + "/child.py": "VALUE = 1\n"}
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "python_lib", "id": package + ".child"}]})
        self.installable = {package + ".child": {}}
        self.materialise()
        sys.path.insert(0, str(self.root))
        try:
            result = checker.check(str(self.root), probe=True)
        finally:
            sys.path.remove(str(self.root))
        row = next(p for p in result["probe"]["items"] if p["tool"] == "seep_known")
        self.assertEqual(row["discovery"], "found")
        self.assertNotIn(package, sys.modules)

    def test_probe_finds_file_but_reports_found_not_verified(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "external_tool", "id": "rabin2"}]})
        self.runtimes = {"rabin2": {"probe": {
            "repoPaths": ["Tool/mcp/Tool/safe/radare2/bin/rabin2.exe"]}}}
        # a zero-byte file is enough for read-only discovery; it proves nothing about running it
        self.extra_files = {"Tool/mcp/Tool/safe/radare2/bin/rabin2.exe": b""}
        result = self.run_check(probe=True)
        found = [p for p in result["probe"]["items"]
                 if p["tool"] == "seep_known" and p["discovery"] == "found"]
        self.assertTrue(found)
        self.assertTrue(all(p["verified"] is False for p in found))
        self.assertFalse(result["probe"]["spawned_software"])
        # structural closure is satisfied by the registry entry, but nothing is verified
        row = self.row(result, "seep_known")
        self.assertTrue(row["registry_closure"])
        self.assertEqual(row["local_availability"], "not_checked")
        self.assertIs(row["runtime_verified"], False)
        self.assertIs(result["runtime_verified"], False)

    def test_probe_hit_does_not_mask_an_unregistered_dependency(self):
        """A found executable must not hide the rest of the all_of set."""
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "external_tool", "id": "rabin2"},
                       {"kind": "python_lib", "id": "requests"}]})
        self.runtimes = {"rabin2": {"probe": {
            "repoPaths": ["Tool/mcp/Tool/safe/radare2/bin/rabin2.exe"]}}}
        self.extra_files = {"Tool/mcp/Tool/safe/radare2/bin/rabin2.exe": b""}
        result = self.run_check(probe=True)
        self.assertTrue(any(p["discovery"] == "found" for p in result["probe"]["items"]))
        self.assertFalse(result["ok"])
        self.assertEqual([u["id"] for u in result["registry_gaps"]], ["requests"])
        self.assertFalse(self.row(result, "seep_known")["registry_closure"])

    def test_probe_lists_every_candidate_instead_of_guessing_one(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "external_tool", "id": "r2"}]})
        self.runtimes = {"r2": {"probe": {
            "names": ["rabin2", "radare2"],
            "repoPaths": ["Tool/safe/rabin2.exe", "Tool/safe/radare2.exe"]}}}
        self.extra_files = {"Tool/safe/rabin2.exe": b"", "Tool/safe/radare2.exe": b""}
        result = self.run_check(probe=True)
        record = next(p for p in result["probe"]["items"] if p["tool"] == "seep_known")
        self.assertEqual(record["discovery"], "found")
        self.assertEqual(sorted(record["found_paths"]),
                         ["Tool/safe/rabin2.exe", "Tool/safe/radare2.exe"])
        self.assertIs(record["verified"], False)

    def test_probe_reports_not_checked_for_os_cli(self):
        self.deps["seep_known"] = self._dep("seep_known", {
            "all_of": [{"kind": "builtin_module", "id": "json"}],
            "any_of": [{"kind": "os_cli", "id": "tasklist"},
                       {"kind": "os_cli", "id": "ps"}]})
        self.os_cli = {"tasklist": "fixture", "ps": "fixture"}
        result = self.run_check(probe=True)
        os_rows = [p for p in result["probe"]["items"] if p["kind"] == "os_cli"]
        self.assertEqual(len(os_rows), 2)
        self.assertTrue(all(p["discovery"] == "not_checked" for p in os_rows))
        self.assertTrue(all(p["verified"] is False for p in os_rows))

    def test_evidence_level_and_local_status_are_explicit(self):
        result = self.run_check()
        self.assertEqual(result["evidence_level"], "structural")
        self.assertIs(result["runtime_verified"], False)
        for row in result["tools"]:
            self.assertEqual(row["local_availability"], "not_checked")
            self.assertEqual(row["online_handshake"], "not_checked")
            self.assertIs(row["runtime_verified"], False)
        dims = result["dimensions"]
        self.assertEqual(dims["local_availability"]["status"], "not_checked")
        self.assertEqual(dims["online_handshake"]["status"], "not_checked")
        self.assertIs(dims["online_handshake"]["checked"], False)

    def test_self_test_entry_point_passes(self):
        """`--self-test` must exercise the real checker, and stay a real pass."""
        result = checker.self_test()
        self.assertTrue(result["ok"], [c for c in result["cases"] if not c["ok"]])
        names = {c["name"] for c in result["cases"]}
        self.assertIn("configured-server-does-not-satisfy-cli-dependency", names)
        self.assertIn("fake-executable-is-not-ready", names)


class CliEntryPointTests(unittest.TestCase):
    """兼容已有 --json / --self-test / 新增 --probe 入口，且退出码与 ok 字段一致。"""

    @staticmethod
    def _run(*args):
        import subprocess
        return subprocess.run(
            [sys.executable, "-B", "-X", "utf8", str(CHECKER_PATH), "--json"] + list(args),
            cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=120)

    def test_self_test_cli_exits_zero(self):
        done = self._run("--self-test")
        self.assertEqual(done.returncode, 0, done.stderr[-800:])
        payload = json.loads(done.stdout)
        self.assertTrue(payload["ok"])
        self.assertIs(payload["runtime_verified"], False)

    def test_repo_check_cli_exit_code_matches_ok(self):
        done = self._run()
        payload = json.loads(done.stdout)
        self.assertEqual(payload["evidence_level"], "structural")
        self.assertIs(payload["runtime_verified"], False)
        self.assertEqual(done.returncode, 0 if payload["ok"] is True else 1)
        # 真实仓库的已知缺口（java / rabin2）必须还在，不许为了让套件变绿而消失
        self.assertTrue({g["id"] for g in payload["registry_gaps"]} <= {"java", "rabin2"})

    def test_probe_cli_does_not_spawn_software(self):
        done = self._run("--probe")
        payload = json.loads(done.stdout)
        probe = payload["probe"]
        self.assertFalse(probe["spawned_software"])
        self.assertEqual(probe["mode"], "read-only-discovery")
        self.assertTrue(probe["items"])
        self.assertTrue(all(item["verified"] is False for item in probe["items"]))
        self.assertIs(payload["runtime_verified"], False)


class RealRepositoryTests(unittest.TestCase):
    """Read-only assertions on this checkout; never relaxes a real gap."""

    def setUp(self):
        self.result = checker.check(str(ROOT))
        self.dependency_doc = json.loads(
            (ROOT / DEPENDENCY_REL).read_text(encoding="utf-8"))

    def test_dependency_declarations_cover_every_registered_server_tool(self):
        registered = set(self.result["server"]["registered_tools"])
        declared = set(self.dependency_doc["tools"])
        self.assertGreaterEqual(len(registered), 20)
        self.assertEqual(sorted(registered - declared), [])

    def test_every_declared_tool_carries_source_evidence(self):
        """来源事实锚定真实 AST 函数名 + 文件 + 实现里真实使用；行号只做可推导定位。

        **不再**把 `source.line - 1 == def 行` 当真理（2026-10-27 审计：20 条因行位移全红，
        而实现本身没有任何依赖变化）。这里断言的是：
          1. `source.function` == 工具名，且该函数在 server AST 里**真的存在**；
          2. `source.file` 指向真实 server 文件；
          3. `source.line` 如果是 `def <name>(` 就接受，否则 checker 必须给出 AST
             真实 def 行做重定位（relocated）；**行位移本身不是失败**；
          4. 声明依赖在实现（含已审 helper 链）里找得到使用证据（`source_verified`）。
        """
        import ast as _ast
        source_text = (ROOT / SERVER_REL).read_text(encoding="utf-8")
        server_source = source_text.splitlines()
        tree = _ast.parse(source_text)
        anchors = {node.name: node.lineno for node in tree.body
                   if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef))}
        rows = {row["tool"]: row for row in self.result["tools"]}
        for name, entry in self.dependency_doc["tools"].items():
            with self.subTest(tool=name):
                self.assertEqual(entry["source"]["function"], name)
                self.assertEqual(entry["source"]["file"], SERVER_REL)
                self.assertIn(name, anchors, "%s 在 %s 的 AST 里不存在" % (name, SERVER_REL))
                line = int(entry["source"]["line"])
                if line == anchors[name]:
                    self.assertIn("def %s(" % name, server_source[line - 1])
                else:
                    # 行号落后于实现：AST 仍是真理，line 只是可推导定位（允许位移）
                    self.assertLess(line, anchors[name] + 1)
                self.assertTrue(entry.get("evidence"))
                requires = entry["requires"]
                self.assertTrue(requires.get("all_of") or requires.get("any_of"))
                row = rows.get(name) or {}
                self.assertTrue(row.get("source_verified"),
                                "%s 声明的依赖在实现里没有使用证据：%s"
                                % (name, (row.get("source_evidence") or {}).get("unverified")))
                evidence = row.get("source_evidence") or {}
                self.assertEqual(evidence.get("anchor_line"), anchors[name])

    def test_declared_line_is_already_the_real_def_line(self):
        """配置里的 line 必须已归位到当前 AST def 行（不能留着旧值靠重定位糊着）。"""
        import ast as _ast
        tree = _ast.parse((ROOT / SERVER_REL).read_text(encoding="utf-8"))
        anchors = {node.name: node.lineno for node in tree.body
                   if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef))}
        for name, entry in self.dependency_doc["tools"].items():
            with self.subTest(tool=name):
                self.assertEqual(int(entry["source"]["line"]), anchors[name])
                row = next(r for r in self.result["tools"] if r["tool"] == name)
                self.assertIs(row["source_evidence"]["relocated"], False)

    def test_structural_status_never_claims_runtime_verification(self):
        self.assertEqual(self.result["evidence_level"], "structural")
        self.assertIs(self.result["runtime_verified"], False)
        for row in self.result["tools"]:
            self.assertIs(row["runtime_verified"], False)
            self.assertEqual(row["local_availability"], "not_checked")

    def test_registry_gaps_are_reported_not_passed(self):
        gaps = self.result["registry_gaps"]
        self.assertEqual({(g["tool"], g["id"]) for g in gaps},
                         {(g["tool"], g["id"]) for g in self.result["unresolved"]
                          if g["status"] == "registry_gap"})
        if gaps:
            self.assertFalse(self.result["ok"])
            for gap in gaps:
                row = next(r for r in self.result["tools"] if r["tool"] == gap["tool"])
                self.assertFalse(row["structural_ok"])
                self.assertFalse(row["registry_closure"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
