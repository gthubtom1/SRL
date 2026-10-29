#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_runtime_registration.py —— 运行时注册表（rabin2 / java）与效果表校准的回归测试。

背景（上一轮 tool-dependencies-repair.md 的 5 条 registry_gap）：
    `mcp-tool-dependencies.json` 如实声明 seep_r2_info / seep_r2_strings / seep_auto_triage 要
    `rabin2`、seep_apk_decompile / seep_apk_unpack 要 `java`，但 `tool-runtimes.json` 与
    `tool-capabilities.json` 里都没有这两个 id，于是静态契约永远 FAIL。本轮补了**两条独立条目**
    （没有把 `r2` / `jadx` 的条目改个名字冒充）。

这个测试只做一件事：把「配置是不是真的能让消费端用起来」钉成可回归的断言。
它**不**执行被注册的工具（不跑目标、不联网、不安装），只：
  1. 真解析三个 JSON（不 mock 文件内容）；
  2. 调真实消费端（tool-contract-check 的 check()、tool-readiness 的 probe()/verify()、
     tool_autodiscover 的层级函数、seep_contract 的 audit_tool_effects）验证字段兼容；
  3. 断言「独立依赖没有被别的条目兜底」（rabin2 ≠ r2、java ≠ jadx/apktool）；
  4. 断言效果字段与 seep_ensure_tool 的真实实现边界一致（只读本仓库源码，不执行它）。

跑法：
    python -B -X utf8 Tool/scripts/test_runtime_registration.py
退出码 0 = 全部通过。
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
ROOT = os.path.dirname(TOOL)

RUNTIMES_REL = "Tool/config/tool-runtimes.json"
CAPABILITIES_REL = "Tool/config/tool-capabilities.json"
EFFECTS_REL = "Tool/config/tool-effects.json"
DEPENDENCIES_REL = "Tool/config/mcp-tool-dependencies.json"
SERVER_REL = "Tool/mcp/seep_mcp_server.py"
CONTRACT_CHECK = os.path.join(HERE, "tool-contract-check.py")
READINESS = os.path.join(HERE, "tool-readiness.py")
AUTODISCOVER = os.path.join(TOOL, "mcp", "tool_autodiscover.py")
CONTRACT = os.path.join(TOOL, "mcp", "seep_contract.py")

# 本轮登记的两个独立运行时 + 它们**不允许**被谁兜底
INDEPENDENT = {
    "rabin2": {"must_be_distinct_from": ["r2"],
               "used_by": ["seep_r2_info", "seep_r2_strings", "seep_auto_triage"]},
    "java": {"must_be_distinct_from": ["jadx", "apktool"],
             "used_by": ["seep_apk_decompile", "seep_apk_unpack"]},
}

EFFECT_FIELDS = ("writes_filesystem", "executes_foreign_code", "touches_network",
                 "mutates_target", "may_discard_data")


def _load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _module(name, path):
    """按路径加载真实模块（同一个文件，不复制判定逻辑）。"""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _server_source():
    return _read(os.path.join(ROOT, SERVER_REL))


class ConfigParsesTests(unittest.TestCase):
    """三个文件必须能真解析，且顶层结构就是消费端读的那个键。"""

    def test_runtimes_and_capabilities_parse(self):
        runtimes = _load(os.path.join(ROOT, RUNTIMES_REL))
        caps = _load(os.path.join(ROOT, CAPABILITIES_REL))
        self.assertIsInstance(runtimes.get("tools"), dict)
        self.assertIsInstance(caps.get("tools"), dict)
        self.assertTrue(runtimes["tools"], "tool-runtimes.json#tools 不能为空")

    def test_every_runtime_id_is_also_a_capability(self):
        """preflight.py:371-374 的交叉覆盖判据：runtimes ⊆ capabilities。"""
        runtimes = _load(os.path.join(ROOT, RUNTIMES_REL))["tools"]
        caps = _load(os.path.join(ROOT, CAPABILITIES_REL))["tools"]
        missing = sorted(set(runtimes) - set(caps))
        self.assertEqual(missing, [], "runtimes 里有、capabilities 里没有：%s" % missing)

    def test_effects_file_shape(self):
        doc = _load(os.path.join(ROOT, EFFECTS_REL))
        self.assertEqual(doc.get("schema"), "seep.tool-effects/1")
        tools = doc.get("tools")
        self.assertIsInstance(tools, dict)
        for name, effect in tools.items():
            with self.subTest(tool=name):
                self.assertEqual(set(effect), set(EFFECT_FIELDS))
                for field in EFFECT_FIELDS:
                    self.assertIsInstance(effect[field], bool, "%s.%s 必须是 bool"
                                          % (name, field))


class AgentRootInvariantTests(unittest.TestCase):
    def test_i8_reads_selected_agent_root_instead_of_real_home(self):
        invariants = _module("seep_invariants_agent_root", os.path.join(HERE, "invariants.py"))
        source = os.path.join(ROOT, "Tool", "skill", "softseep")
        for env_key in ("PI_CODING_AGENT_DIR", "PI_AGENT_DIR"):
            with self.subTest(env_key=env_key), tempfile.TemporaryDirectory(
                    prefix="seep-invariant-agent-root-") as td:
                agent = os.path.join(td, "selected-agent")
                with mock.patch.dict(os.environ, {env_key: agent}, clear=True):
                    self.assertFalse(invariants.check("softseep")["I8"][0])
                    deployed = os.path.join(agent, "skills", "softseep")
                    os.makedirs(deployed)
                    import shutil
                    for name in ("SKILL.md", "pack.json"):
                        shutil.copy2(os.path.join(source, name), os.path.join(deployed, name))
                    ok, detail = invariants.check("softseep")["I8"]
                self.assertTrue(ok, detail)


class IndependentEntryTests(unittest.TestCase):
    """rabin2 / java 必须有**自己的**条目，字段齐全，且不靠别的 id 兜底。"""

    def setUp(self):
        self.runtimes = _load(os.path.join(ROOT, RUNTIMES_REL))["tools"]
        self.caps = _load(os.path.join(ROOT, CAPABILITIES_REL))["tools"]

    def test_entries_exist_in_both_registries(self):
        for tool_id in INDEPENDENT:
            with self.subTest(tool=tool_id):
                self.assertIn(tool_id, self.runtimes, "%s 未在 tool-runtimes.json 登记" % tool_id)
                self.assertIn(tool_id, self.caps, "%s 未在 tool-capabilities.json 登记" % tool_id)

    def test_entry_carries_own_executable_name(self):
        """条目的 probe.names / exe_candidates 必须点名自己，不能只写别的工具名。"""
        for tool_id in INDEPENDENT:
            entry = self.runtimes[tool_id]
            names = [str(n).lower() for n in (entry.get("probe") or {}).get("names") or []]
            self.assertTrue(names, "%s.probe.names 为空" % tool_id)
            stem = tool_id.lower()
            self.assertTrue(any(os.path.splitext(n)[0] == stem for n in names),
                            "%s.probe.names 里没有自己的可执行名（实际 %s）" % (tool_id, names))
            cands = [str(c).lower() for c in self.caps[tool_id].get("exe_candidates") or []]
            self.assertTrue(any(os.path.splitext(c)[0] == stem for c in cands),
                            "%s.exe_candidates 里没有自己的可执行名（实际 %s）" % (tool_id, cands))

    def test_no_borrowed_registration(self):
        """独立条目不许靠别的 id 兜底：删掉自己的条目，就必须变成 registry_gap。

        做法：用**真实的** checker.Catalogs 读两份注册表，分别放在「有 rabin2 / 无 rabin2」
        两个临时根下，断言后者不再把 rabin2 判为已登记。旧实现把 rabin2 列在 r2 条目的
        probe.names 里，那种「名字在别人条目里」恰恰是**不能**当登记用的 —— 这里直接钉死。
        """
        checker = _module("seep_contract_check_catalog_independence", CONTRACT_CHECK)
        runtimes = _load(os.path.join(ROOT, RUNTIMES_REL))
        caps = _load(os.path.join(ROOT, CAPABILITIES_REL))
        import tempfile
        temp = tempfile.mkdtemp(prefix="seep-runtime-registration-")
        try:
            cfg = os.path.join(temp, "Tool", "config")
            os.makedirs(cfg)

            def write(runtimes_tools, cap_tools):
                with open(os.path.join(cfg, "tool-runtimes.json"), "w", encoding="utf-8") as fh:
                    json.dump({"schemaVersion": runtimes.get("schemaVersion", 2),
                               "tools": runtimes_tools}, fh)
                with open(os.path.join(cfg, "tool-capabilities.json"), "w", encoding="utf-8") as fh:
                    json.dump({"schemaVersion": caps.get("schemaVersion", "1.0"),
                               "tools": cap_tools}, fh)
                with open(os.path.join(cfg, "tool-install.json"), "w", encoding="utf-8") as fh:
                    json.dump({"schemaVersion": "2.0", "installable": {}}, fh)

            for tool_id, rule in INDEPENDENT.items():
                with self.subTest(tool=tool_id):
                    self.assertNotIn(self.runtimes[tool_id],
                                     [self.runtimes[o] for o in rule["must_be_distinct_from"]],
                                     "%s 的条目与依赖它的工具完全相同（等于没独立登记）" % tool_id)
                    write(runtimes["tools"], caps["tools"])
                    self.assertTrue(checker.Catalogs(temp).tool_registered(tool_id),
                                    "%s 删不得：真实注册表里应当命中" % tool_id)
                    trimmed_runtimes = {k: v for k, v in runtimes["tools"].items() if k != tool_id}
                    trimmed_caps = {k: v for k, v in caps["tools"].items() if k != tool_id}
                    write(trimmed_runtimes, trimmed_caps)
                    self.assertEqual(checker.Catalogs(temp).tool_registered(tool_id), [],
                                     "%s 被别的条目兜底了：删掉自己的条目仍判已登记" % tool_id)
        finally:
            import shutil
            shutil.rmtree(temp, ignore_errors=True)

    def test_path_discovery_is_portable(self):
        """路径发现必须复用既有稳定机制：env 变量、PATH 名、仓库相对路径、占位符 glob。

        断言的是「没有写死机器路径」，不是「猜对了某个人的目录」：
        - 每条 repoPaths 都是仓库相对路径（不是 C:/D: 绝对路径）；
        - globs 只用 tool-readiness 支持的占位符；
        - names 里同时有 Windows 名与 POSIX 名（跨平台）；
        - 至少一条 env 变量入口（等价于 tool_autodiscover 的 SEEP_<ID>_PATH 层级）。
        """
        allowed_placeholders = {"home", "repo", "localappdata", "appdata",
                                "programfiles", "programfilesx86", "drive"}
        drive_path = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z]:[\\/]")
        for tool_id in INDEPENDENT:
            entry = self.runtimes[tool_id]
            probe = entry.get("probe") or {}
            with self.subTest(tool=tool_id, aspect="no-hardcoded-machine-path"):
                for rel in probe.get("repoPaths") or []:
                    self.assertIsNone(drive_path.search(rel),
                                      "repoPaths 写死了机器路径：%s" % rel)
                    self.assertFalse(os.path.isabs(rel), "repoPaths 必须是仓库相对路径：%s" % rel)
                for pattern in list(probe.get("globs") or []) + list(probe.get("repoPaths") or []):
                    for placeholder in re.findall(r"\{([a-z]+)\}", pattern):
                        self.assertIn(placeholder, allowed_placeholders,
                                      "未知占位符 {%s}（tool-readiness._placeholders 不认）：%s"
                                      % (placeholder, pattern))
            with self.subTest(tool=tool_id, aspect="cross-platform-names"):
                names = [str(n).lower() for n in probe.get("names") or []]
                self.assertTrue(any(n.endswith(".exe") for n in names),
                                "%s 缺 Windows 可执行名" % tool_id)
                self.assertTrue(any(not n.endswith((".exe", ".bat", ".cmd")) for n in names),
                                "%s 缺 POSIX 可执行名" % tool_id)
            with self.subTest(tool=tool_id, aspect="env-entry"):
                self.assertTrue(probe.get("envVars"), "%s 缺 envVars（八层发现的第一层）" % tool_id)
                self.assertIn("PATH", json.dumps(entry, ensure_ascii=False).upper(),
                              "%s 的发现链没有提到 PATH 兜底" % tool_id)

    def test_verify_is_a_target_free_version_probe(self):
        """自检只能是无目标 L0 探针（版本），绝不能是「跑目标文件」。"""
        forbidden_args = {"-jar", "-c", "-f", "-A", "-d", "--decompile", "-r"}
        for tool_id in INDEPENDENT:
            verify = self.runtimes[tool_id].get("verify") or {}
            with self.subTest(tool=tool_id):
                self.assertEqual(str(verify.get("kind") or "exec").lower(), "exec")
                args = [str(a) for a in verify.get("args") or []]
                self.assertTrue(args, "%s.verify.args 为空（没有可复现的自检）" % tool_id)
                self.assertFalse(set(args) & forbidden_args,
                                 "%s.verify.args 含执行目标的参数：%s" % (tool_id, args))
                self.assertTrue(verify.get("expect"), "%s.verify.expect 缺失：无法判读输出" % tool_id)
                self.assertIn(0, verify.get("allowRc") or [], "%s.verify.allowRc 不含 0" % tool_id)
                self.assertNotIn("{target}", " ".join(args), "自检不许吃目标文件")
                # 自检文案必须显式声明「无目标」
                self.assertIn("无目标", json.dumps(verify, ensure_ascii=False))

    def test_java_verify_does_not_execute_arbitrary_code(self):
        """java 的自检必须是 -version：`java -jar <任意jar>` 等于执行外来代码。"""
        verify = self.runtimes["java"]["verify"]
        self.assertEqual([str(a) for a in verify.get("args") or []], ["-version"])
        self.assertIn("openjdk", verify.get("expect", "").lower())
        self.assertIn("java", verify.get("expect", "").lower())

    def test_rabin2_verify_detects_renamed_radare2(self):
        """历史坑：rabin2.exe 其实是 radare2.exe 改名。expect 必须点名 rabin2。"""
        verify = self.runtimes["rabin2"]["verify"]
        self.assertIn("rabin2", verify.get("expect", "").lower())
        self.assertEqual(verify.get("identityProbe"), "rabin2")


class ConsumerCompatibilityTests(unittest.TestCase):
    """消费端三处（contract-check / readiness / autodiscover）读到的是同一份字段。"""

    def test_contract_checker_resolves_both_ids(self):
        checker = _module("seep_contract_check_regression", CONTRACT_CHECK)
        payload = checker.check(str(ROOT))
        self.assertTrue(payload["ok"], [g for g in payload["gaps"]][:8])
        self.assertEqual(payload["registry_gaps"], [])
        # 独立依赖必须真的被声明用上（不是「登记了但没人引用」）
        deps = _load(os.path.join(ROOT, DEPENDENCIES_REL))["tools"]
        for tool_id, rule in INDEPENDENT.items():
            for user in rule["used_by"]:
                with self.subTest(tool=tool_id, user=user):
                    requires = deps[user]["requires"]
                    ids = {str(item.get("id")) for group in ("all_of", "any_of")
                           for item in requires.get(group) or []}
                    self.assertIn(tool_id, ids)

    def test_builtin_dependency_accepts_only_the_called_audited_helper(self):
        checker = _module("seep_contract_check_helper_regression", CONTRACT_CHECK)
        server_rel = "Tool/mcp/seep_mcp_server.py"
        helper_rel = "Tool/mcp/seep_apk_contract.py"
        for helper_body, expected in (
            ("import zipfile\ndef inspect_apk():\n    return zipfile.ZipFile\n", True),
            ("def inspect_apk():\n    return None\n", False),
        ):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory(
                    prefix="seep-contract-helper-") as base:
                server = os.path.join(base, server_rel)
                helper = os.path.join(base, helper_rel)
                os.makedirs(os.path.dirname(server), exist_ok=True)
                with open(server, "w", encoding="utf-8") as handle:
                    handle.write("from seep_apk_contract import inspect_apk as _inspect_apk\n"
                                 "def seep_apk_info():\n"
                                 "    return _inspect_apk()\n")
                with open(helper, "w", encoding="utf-8") as handle:
                    handle.write(helper_body)
                checker._SOURCE_CACHE.clear()
                module, error = checker._module_view(base, server_rel)
                self.assertIsNone(error)
                reach = checker._reachable(module, "seep_apk_info")
                item = {
                    "kind": "builtin_module", "id": "zipfile",
                    "evidence_via": {
                        "helper": "_inspect_apk",
                        "module": helper_rel,
                        "symbol": "zipfile",
                    },
                }
                ok, _reason = checker._evidence_for_item(
                    base, module, reach, item, mock.Mock(runtimes={}, capabilities={}))
                self.assertIs(ok, expected)

    def test_tool_readiness_probe_reads_our_probe_block(self):
        readiness = _module("seep_tool_readiness_regression", READINESS)
        runtimes = _load(os.path.join(ROOT, RUNTIMES_REL))["tools"]
        for tool_id in INDEPENDENT:
            with self.subTest(tool=tool_id):
                hits, _truncated = readiness.probe(runtimes[tool_id]["probe"], budget=5.0)
                # 不要求本机一定装了：只要求 probe 字段被真实消费（结构可走通）
                self.assertIsInstance(hits, list)
                for hit in hits:
                    self.assertTrue(os.path.isfile(hit["path"]))
                    self.assertIn(hit["via"], ("env", "PATH", "repo", "dir"))

    def test_autodiscover_uses_our_exe_candidates(self):
        discover_mod = _module("seep_tool_autodiscover_regression", AUTODISCOVER)
        for tool_id in INDEPENDENT:
            with self.subTest(tool=tool_id):
                names = discover_mod._exe_candidates(tool_id)
                self.assertTrue(names, "%s 在能力表里没有 exe_candidates，八层发现会退化" % tool_id)
                self.assertIn(tool_id, [os.path.splitext(str(n).lower())[0] for n in names]
                              + [str(n).lower() for n in names])

    def test_env_layer_honours_the_declared_env_var(self):
        """第一层发现是 SEEP_<ID>_PATH；条目里声明的 envVars 必须能被它命中。"""
        discover_mod = _module("seep_tool_autodiscover_env_regression", AUTODISCOVER)
        runtimes = _load(os.path.join(ROOT, RUNTIMES_REL))["tools"]
        for tool_id in INDEPENDENT:
            expected = "SEEP_" + "".join(ch if ch.isalnum() else "_" for ch in tool_id.upper()) + "_PATH"
            declared = runtimes[tool_id]["probe"].get("envVars") or []
            with self.subTest(tool=tool_id):
                self.assertIn(expected, declared,
                              "%s.probe.envVars 与 tool_autodiscover 的 env 层不兼容：%s"
                              % (tool_id, declared))
                # 真跑一次 env 层（指向一个临时文件，只读、不执行）
                probe_file = os.path.join(HERE, "test_runtime_registration.py")
                old = os.environ.get(expected)
                os.environ[expected] = probe_file
                try:
                    hit = discover_mod._layer_env(tool_id, [tool_id])
                finally:
                    if old is None:
                        os.environ.pop(expected, None)
                    else:
                        os.environ[expected] = old
                self.assertIsNotNone(hit, "%s 的 env 层没认 SEEP_*_PATH" % tool_id)
                self.assertEqual(hit.get("via"), "env")


class EffectsCalibrationTests(unittest.TestCase):
    """effects 必须按实现取上界，且不能盖过判据（闸规则不改）。"""

    def setUp(self):
        self.effects = _load(os.path.join(ROOT, EFFECTS_REL))["tools"]
        self.source = _server_source()

    def test_ensure_tool_declares_network_and_installer_execution(self):
        """seep_ensure_tool 默认 allow_install=True → propose_install(execute=True)。

        联网：portable_zip 走 urllib 下载、pip/winget/npm/go 联网取包；
        写盘：落 ~/.seep/tools；执行外来代码：拉起安装器/pip/winget；可能覆盖：重装同名目录。
        """
        effect = self.effects["seep_ensure_tool"]
        self.assertIs(effect["touches_network"], True,
                      "自动安装会联网：touches_network 不能记 false")
        self.assertIs(effect["writes_filesystem"], True)
        self.assertIs(effect["executes_foreign_code"], True)
        self.assertIs(effect["may_discard_data"], True)
        self.assertIs(effect["mutates_target"], False,
                      "装工具不修改被分析的目标文件")
        # 实现证据：默认参数与真实调用点必须还在（否则这条效应该重判）
        self.assertIn("allow_install: bool = True", self.source)
        self.assertIn("propose_install(tid, execute=True)", self.source)

    def test_network_claim_is_backed_by_actual_downloader_or_package_manager(self):
        """touches_network=true 必须有实现依据，不是「拿不准就填 true」的拍脑袋。"""
        discover_source = _read(AUTODISCOVER)
        self.assertIn("urllib.request", discover_source)
        self.assertIn("pip", discover_source)
        self.assertIn("winget", discover_source)

    def test_pcap_extract_is_local_only(self):
        """tshark -r 读已存在的 pcap：不是联网动作（旧值 true 会误标 openWorld）。"""
        effect = self.effects["seep_pcap_extract"]
        self.assertIs(effect["touches_network"], False)
        self.assertIs(effect["executes_foreign_code"], True, "它真的起 tshark 子进程")
        self.assertIs(effect["writes_filesystem"], False)
        body = self.source.split("def seep_pcap_extract(", 1)[1].split("@server.tool()", 1)[0]
        self.assertNotRegex(body, r"urllib|requests\.|socket\.",
                            "seep_pcap_extract 里出现联网调用 → 这条 effect 要重判")

    def test_r2_cmd_keeps_mutates_target_as_upper_bound(self):
        """命令串由调用方给，只按前缀拦写入 → 按上界保留 mutates_target=true。"""
        effect = self.effects["seep_r2_cmd"]
        self.assertIs(effect["mutates_target"], True)
        self.assertIs(effect["writes_filesystem"], False)
        self.assertIn("_r2_write_tokens", self.source)

    def test_apk_unpack_persists_output(self):
        """apktool d -o <dir> 落盘：writes_filesystem 必须是 true。"""
        self.assertIs(self.effects["seep_apk_unpack"]["writes_filesystem"], True)

    def test_tool_discover_writes_local_state_and_spawns_probes(self):
        """record() 落 ~/.seep/tools.local.json；discover() 会起 shell 侧探测。"""
        effect = self.effects["seep_tool_discover"]
        self.assertIs(effect["writes_filesystem"], True)
        self.assertIs(effect["executes_foreign_code"], True)
        self.assertIs(effect["touches_network"], False, "发现是本机动作，不联网")
        self.assertIn("def record(", _read(AUTODISCOVER))

    def test_effects_set_matches_registered_tools_exactly(self):
        """seep_contract.audit_tool_effects 要求严格相等：多一条也拒启动。

        所以运行时工具（rabin2 / java）**不能**塞进 effects —— 它们不是 MCP 工具。
        """
        contract = _module("seep_contract_regression", CONTRACT)
        names = re.findall(r"^def (seep_[a-z0-9_]+)\(", self.source, re.M)
        annotations = contract.audit_tool_effects(names, os.path.join(ROOT, EFFECTS_REL))
        self.assertEqual(set(annotations), set(names))
        for tool_id in INDEPENDENT:
            self.assertNotIn(tool_id, self.effects,
                             "%s 不是 @server.tool()：进 effects 会让 server 起不来" % tool_id)

    def test_effect_annotations_are_consistent_with_fields(self):
        """readOnly/destructive/openWorld 三个 hint 必须由字段推导出来，不允许各写一套。"""
        contract = _module("seep_contract_regression2", CONTRACT)
        names = re.findall(r"^def (seep_[a-z0-9_]+)\(", self.source, re.M)
        annotations = contract.audit_tool_effects(names, os.path.join(ROOT, EFFECTS_REL))
        for name, effect in self.effects.items():
            with self.subTest(tool=name):
                ann = annotations[name]
                self.assertEqual(ann["openWorldHint"], bool(effect["touches_network"]))
                self.assertEqual(ann["readOnlyHint"],
                                 not (effect["writes_filesystem"] or effect["mutates_target"]
                                      or effect["may_discard_data"]))
                self.assertEqual(ann["destructiveHint"],
                                 bool(effect["mutates_target"] or effect["may_discard_data"]))


class RegistrationClosureTests(unittest.TestCase):
    """端到端：静态契约全绿，且仍是 structural（不许冒充「可用」）。"""

    def test_contract_check_reports_structural_not_runtime(self):
        checker = _module("seep_contract_check_closure", CONTRACT_CHECK)
        payload = checker.check(str(ROOT))
        self.assertEqual(payload["evidence_level"], "structural")
        self.assertIs(payload["runtime_verified"], False)
        for row in payload["tools"]:
            self.assertIs(row["runtime_verified"], False)
            self.assertEqual(row["local_availability"], "not_checked")
        self.assertEqual(payload["dimensions"]["local_availability"]["status"], "not_checked")

    def test_registry_closure_covers_every_declared_external_tool(self):
        """依赖表里出现的每个 external_tool id，都必须能在注册表里落地。"""
        runtimes = _load(os.path.join(ROOT, RUNTIMES_REL))["tools"]
        caps = _load(os.path.join(ROOT, CAPABILITIES_REL))["tools"]
        deps = _load(os.path.join(ROOT, DEPENDENCIES_REL))["tools"]
        for name, entry in deps.items():
            for group in ("all_of", "any_of"):
                for item in entry["requires"].get(group) or []:
                    if item.get("kind") != "external_tool":
                        continue
                    with self.subTest(tool=name, dep=item.get("id")):
                        self.assertTrue(item["id"] in runtimes or item["id"] in caps,
                                        "%s 依赖的 %r 未在任一注册表登记" % (name, item["id"]))


class NativeLauncherTests(unittest.TestCase):
    """Cached Unix launchers must resolve to shipped Windows siblings."""

    def test_windows_cached_launcher_prefers_native_sibling(self):
        module = _module("seep_native_launcher_regression", AUTODISCOVER)
        with tempfile.TemporaryDirectory() as directory:
            command = os.path.join(directory, "jadx")
            for name in (command, command + ".bat"):
                with open(name, "w", encoding="utf-8") as stream:
                    stream.write("synthetic launcher; never executed")
            hit = {"command": command, "via": "cache"}
            with mock.patch.object(module.os, "name", "nt"), mock.patch.object(module, "_cache_put") as put:
                result = module._discover_result("jadx", "jadx", {}, None, [], hit, [("cache", hit)])
            self.assertEqual(result["command"], command + ".bat")
            put.assert_called_once_with("jadx", command + ".bat", "cache", None)
            with mock.patch.object(module.os, "name", "posix"), mock.patch.object(module, "_cache_put") as put:
                result = module._discover_result("jadx", "jadx", {}, None, [], hit, [("cache", hit)])
            self.assertEqual(result["command"], command)
            put.assert_not_called()

    def test_extensionless_without_native_sibling_is_preserved(self):
        module = _module("seep_unix_launcher_regression", AUTODISCOVER)
        with tempfile.TemporaryDirectory() as directory:
            command = os.path.join(directory, "custom-tool")
            with open(command, "w", encoding="utf-8") as stream:
                stream.write("synthetic launcher; never executed")
            hit = {"command": command, "via": "cache"}
            with mock.patch.object(module.os, "name", "nt"), mock.patch.object(module, "_cache_put") as put:
                result = module._discover_result("custom-tool", "custom-tool", {}, None, [], hit, [])
            self.assertEqual(result["command"], command)
            put.assert_not_called()


class DocumentationCommandTests(unittest.TestCase):
    """Newlines separate commands; unsupported arguments still fail."""

    def test_adjacent_command_lines_are_not_subcommands(self):
        module = _module("seep_doc_commands_regression", os.path.join(HERE, "lib", "doc_commands.py"))
        text = "python Tool/scripts/check.py\npython Tool/scripts/check.py --strict\n"
        ok, detail = module.check_doc_commands(text, ROOT)
        self.assertTrue(ok, detail)
        ok, detail = module.check_doc_commands("python Tool/scripts/check.py --not-a-real-option", ROOT)
        self.assertFalse(ok, detail)
        self.assertIn("not-a-real-option", detail)

    def test_forwarding_handoff_requires_both_real_targets(self):
        module = _module("seep_handoff_forwarding_regression", os.path.join(HERE, "preflight.py"))
        with tempfile.TemporaryDirectory() as directory:
            os.mkdir(os.path.join(directory, "docs"))
            for name, text in (("REQUIREMENTS.md", "current requirements"),
                               ("docs/CURRENT-STATE.md", "current state"),
                               ("docs/HANDOFF.md", "本页只作接续入口。[需求](../REQUIREMENTS.md) [状态](CURRENT-STATE.md)")):
                with open(os.path.join(directory, name), "w", encoding="utf-8") as stream:
                    stream.write(text)
            module.ROOT = directory
            module.results = []
            module.check_handoff_fresh()
            self.assertTrue(module.results[-1]["ok"], module.results)
            os.unlink(os.path.join(directory, "docs", "CURRENT-STATE.md"))
            module.check_handoff_fresh()
            self.assertFalse(module.results[-1]["ok"], module.results)


if __name__ == "__main__":
    suite = unittest.main(verbosity=2, exit=False)
    sys.exit(0 if suite.result.wasSuccessful() else 1)
