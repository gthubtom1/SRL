"""Preflight must inspect the selected AgentRoot, never an assumed user HOME."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("preflight_under_test", HERE / "preflight.py")
assert SPEC and SPEC.loader
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


class PreflightRootTests(unittest.TestCase):
    def test_readme_installation_links_replace_development_status_requirement(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-doc-entry-") as td:
            root = Path(td)
            targets = ("Tool/docs/BOOTSTRAP.md", "Tool/docs/MCP-SETUP.md")
            for target in targets:
                path = root / target
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# Installation guide\n", encoding="utf-8")
            for rel in ("README.md", "README.zh.md", "README.en.md"):
                (root / rel).write_text("\n".join(
                    "[guide](" + target + ")" for target in targets), encoding="utf-8")
            for rel in ("Tool/prompts/AGENTS.md", "Tool/prompts/SEEP.md",
                        "Tool/prompts/contracts/AGENTS.md", "docs/HANDOFF.md"):
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("REQUIREMENTS.md CURRENT-STATE.md\n", encoding="utf-8")
            with patch.object(preflight, "ROOT", str(root)):
                preflight.results.clear()
                preflight.check_document_cutover()
                self.assertTrue(preflight.results[-1]["ok"], preflight.results)
                readme = root / "README.md"
                readme.write_text(readme.read_text(encoding="utf-8") + "\nPM-SPEC.md", encoding="utf-8")
                preflight.results.clear()
                preflight.check_document_cutover()
                self.assertFalse(preflight.results[-1]["ok"], preflight.results)
                self.assertIn("PM-SPEC.md", preflight.results[-1]["detail"])
                (root / targets[0]).unlink()
                preflight.results.clear()
                preflight.check_document_cutover()
                self.assertFalse(preflight.results[-1]["ok"], preflight.results)
                self.assertIn("BOOTSTRAP.md", preflight.results[-1]["detail"])

    def test_operational_checkers_require_documented_exit_codes(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-operations-") as td:
            root = Path(td)
            tool = root / "Tool"
            for rel in ("scripts/mcp-doctor.py", "mcp/seep_mcp_server.py",
                        "skill/softseep/scripts/mcp-guard.py"):
                path = tool / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("# fixture\n", encoding="utf-8")
            for code, expected in ((7, False), (0, True), (1, False)):
                with self.subTest(code=code):
                    preflight.results.clear()
                    def child(argv, **kwargs):
                        body = {"ok": True, "info": {}} if "mcp-guard.py" in str(argv[1]) else {"servers": []}
                        return SimpleNamespace(returncode=code, stdout=json.dumps(body), stderr="")
                    with patch.object(preflight, "ROOT", str(root)), \
                            patch.object(preflight, "TOOL", str(tool)), \
                            patch.object(preflight, "agent_root_path", return_value=root / "agent"), \
                            patch.object(preflight, "_mcp_stdio_handshake", return_value=(True, 1, "tools", "")), \
                            patch.object(preflight.subprocess, "run", side_effect=child):
                        preflight.check_newtools()
                    guard = next(r for r in preflight.results if "mcp-guard" in r["name"])
                    doctor = next(r for r in preflight.results if "mcp-doctor 不崩" in r["name"])
                    self.assertEqual(guard["ok"], expected, guard)
                    self.assertEqual(doctor["ok"], code in (0, 1), doctor)

    def test_failed_powershell_parser_cannot_pass_with_empty_stdout(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-parser-") as td:
            preflight.results.clear()
            with patch.object(preflight, "ROOT", td), \
                    patch.object(preflight.shutil, "which", return_value="fixture-powershell"), \
                    patch.object(preflight.subprocess, "run", return_value=SimpleNamespace(
                        returncode=7, stdout="", stderr="fixture parser failed")):
                preflight.check_ps_encoding()
        self.assertFalse(preflight.results[-1]["ok"], preflight.results)

    def test_mcp_handshake_rejects_process_failure_after_responses(self):
        code = (
            "import json,sys;sys.stdin.read();"
            "print(json.dumps({'jsonrpc':'2.0','id':1,'result':{}}));"
            "print(json.dumps({'jsonrpc':'2.0','id':2,'result':{'tools':[{'name':'fixture'}]}}));"
            "sys.exit(7)"
        )
        result = preflight._mcp_stdio_handshake(command=sys.executable, args=["-B", "-c", code])
        self.assertFalse(result[0], result)
        self.assertIn("7", result[-1])

    def test_route_asset_check_requires_successful_complete_result(self):
        healthy = {"packs": 9, "routes": 60, "dead": 0, "problems": []}
        samples = [
            (1, healthy, False),
            (0, {}, False),
            (0, {**healthy, "problems": None}, False),
            (0, {**healthy, "dead": 1}, False),
            (0, {**healthy, "routes": 0}, False),
            (0, healthy, True),
        ]
        for code, body, expected in samples:
            with self.subTest(code=code, body=body):
                preflight.results.clear()
                child = SimpleNamespace(returncode=code, stdout=json.dumps(body), stderr="")
                with patch.object(preflight, "load", return_value={}), \
                        patch.object(preflight.subprocess, "run", return_value=child):
                    preflight.check_assets()
                row = next(r for r in preflight.results if "路由自洽" in r["name"])
                self.assertEqual(row["ok"], expected, row)

    @staticmethod
    def _write_entry_fixture(base: Path) -> tuple[Path, Path]:
        source = base / "source"
        tool = source / "Tool"
        prompts = tool / "prompts"
        manual = source / "MANUAL"
        playbooks = tool / "playbooks"
        pending = tool / "skill" / "_pending"
        for path in (prompts, manual, playbooks, pending / "example-skill"):
            path.mkdir(parents=True, exist_ok=True)
        (prompts / "AGENTS.md").write_text(
            "Read `Tool/skill/_pending/INDEX.md` for archived skills.\n",
            encoding="utf-8",
        )
        (prompts / "SEEP.md").write_text("# SEEP\n", encoding="utf-8")
        (manual / "README.md").write_text(
            "[playbooks](../Tool/playbooks/README.md)\n",
            encoding="utf-8",
        )
        (playbooks / "README.md").write_text(
            "[example](example.md)\n",
            encoding="utf-8",
        )
        (playbooks / "example.md").write_text("# Example\n", encoding="utf-8")
        (pending / "INDEX.md").write_text(
            "`Tool/skill/_pending/" + "example-skill/`\n",
            encoding="utf-8",
        )
        (pending / "example-skill" / "SKILL.md").write_text(
            "# Example skill\n",
            encoding="utf-8",
        )
        return source, tool

    def test_entry_reachability_uses_reachable_directory_indexes(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-entry-") as td:
            source, tool = self._write_entry_fixture(Path(td))
            with patch.object(preflight, "ROOT", str(source)), \
                    patch.object(preflight, "TOOL", str(tool)):
                preflight.results.clear()
                self.assertTrue(preflight.check_entry_reachable())
                self.assertTrue(all(item["ok"] for item in preflight.results),
                                preflight.results)

    def test_entry_reachability_rejects_unreachable_directory_index(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-entry-negative-") as td:
            source, tool = self._write_entry_fixture(Path(td))
            (source / "MANUAL" / "README.md").write_text(
                "# Manuals\n",
                encoding="utf-8",
            )
            with patch.object(preflight, "ROOT", str(source)), \
                    patch.object(preflight, "TOOL", str(tool)):
                preflight.results.clear()
                self.assertFalse(preflight.check_entry_reachable())
                index_result = next(item for item in preflight.results
                                    if item["name"].startswith("资产索引可从顶层入口到达"))
                self.assertFalse(index_result["ok"], index_result)
                self.assertIn("Tool/playbooks/README.md", index_result["detail"])

    def test_selected_agent_root_drives_extension_checks(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-root-") as td:
            base = Path(td)
            source = base / "source"
            agent = base / "agent"
            src_ext = source / "prompts" / "extensions"
            dst_ext = agent / "extensions"
            src_ext.mkdir(parents=True)
            dst_ext.mkdir(parents=True)
            (src_ext / "guard.ts").write_text("export const value = 1;\n", encoding="utf-8")
            (dst_ext / "guard.ts").write_text("export const value = 1;\n", encoding="utf-8")

            preflight.results.clear()
            with patch.object(preflight, "TOOL", str(source)), \
                    patch.dict(os.environ, {"PI_CODING_AGENT_DIR": str(agent)}, clear=True):
                self.assertEqual(preflight.agent_root_path(), agent.resolve())
                preflight.check_extension_deploy()
                self.assertTrue(preflight.results[-1]["ok"], preflight.results[-1])

                (dst_ext / "guard.ts").write_text("export const value = 2;\n", encoding="utf-8")
                preflight.results.clear()
                preflight.check_extension_deploy()
                self.assertFalse(preflight.results[-1]["ok"], preflight.results[-1])

    def test_agent_dir_alias_is_honored(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-alias-") as td:
            with patch.dict(os.environ, {"PI_AGENT_DIR": td}, clear=True):
                self.assertEqual(preflight.agent_root_path(), Path(td).resolve())

    def test_mcp_doctor_uses_selected_agent_root(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-mcp-root-") as td:
            base = Path(td)
            tool = base / "Tool"
            scripts = tool / "scripts"
            mcp = tool / "mcp"
            agent = base / "selected-agent"
            scripts.mkdir(parents=True)
            mcp.mkdir(parents=True)
            agent.mkdir()
            (scripts / "mcp-doctor.py").write_text("# fixture\n", encoding="utf-8")
            (mcp / "seep_mcp_server.py").write_text("# fixture\n", encoding="utf-8")
            calls = []

            def fake_run(argv, **_kwargs):
                calls.append(argv)
                if "--quick" in argv:
                    body = '{"servers": []}'
                else:
                    body = ('{"servers": [{"server": "fixture", "stage": "ready",'
                            ' "tools": 1, "ok": true}]}')
                return SimpleNamespace(returncode=0, stdout=body, stderr="")

            preflight.results.clear()
            with patch.object(preflight, "TOOL", str(tool)), \
                    patch.dict(os.environ, {"PI_CODING_AGENT_DIR": str(agent)}, clear=True), \
                    patch.object(preflight, "subprocess") as subprocess_module, \
                    patch.object(preflight, "_mcp_stdio_handshake",
                                 return_value=(True, 1, "tools", "")):
                subprocess_module.run.side_effect = fake_run
                preflight.check_newtools()

            expected = str((agent / "mcp.json").resolve())
            doctor_calls = [argv for argv in calls
                            if str(scripts / "mcp-doctor.py") in argv]
            self.assertEqual(len(doctor_calls), 2, calls)
            for argv in doctor_calls:
                self.assertIn("--file", argv)
                self.assertEqual(argv[argv.index("--file") + 1], expected)
            self.assertTrue(all(item["ok"] for item in preflight.results[:2]),
                            preflight.results[:2])

    def test_trigger_route_contract_checks_the_complete_domain_set(self):
        hits = [
            {"pack": "primary", "fallback": False},
            {"pack": "aux", "fallback": False},
            {"pack": "blocked", "fallback": False},
        ]
        probe = {
            "expect_route": ["primary", "alternate"],
            "expect_aux": ["aux", "wrong"],
            "expect_ambiguity": False,
            "forbid": ["blocked"],
        }
        failures = preflight._trigger_route_failures(
            probe, hits, ["primary", "aux", "blocked"])
        self.assertTrue(any("辅助域" in item for item in failures), failures)
        self.assertTrue(any("歧义" in item for item in failures), failures)
        self.assertTrue(any("禁止域" in item for item in failures), failures)

        failures = preflight._trigger_route_failures(
            {"expect_route": "primary", "expect_aux": ["aux"],
             "expect_ambiguity": True},
            hits[:2], ["primary", "aux"])
        self.assertEqual(failures, [])

        fallback_first = [{"pack": "seep-router", "fallback": True}] + hits[:2]
        failures = preflight._trigger_route_failures(
            {"expect_route": "primary", "expect_aux": ["aux"],
             "expect_ambiguity": True},
            fallback_first, ["primary", "aux"])
        self.assertTrue(any("兜底域" in item for item in failures), failures)

    def test_domain_gate_subprocess_failure_cannot_be_reduced_to_green_buckets(self):
        with tempfile.TemporaryDirectory(prefix="seep-preflight-domain-reject-") as td:
            root = Path(td)
            tool = root / "Tool"
            scripts = tool / "scripts"
            skill = tool / "skill" / "fixture-domain"
            scripts.mkdir(parents=True)
            skill.mkdir(parents=True)
            (skill / "pack.json").write_text('{"id":"fixture-domain"}\n', encoding="utf-8")
            fake_gate = scripts / "domain-gate.py"
            fake_gate.write_text(
                "import json\n"
                "rows = [\n"
                " {'domain':'fixture-domain','name':'clean child row','ok':True,'detail':'local pass'},\n"
                " {'domain':'全局','name':'链接图','ok':True,'detail':'local pass'},\n"
                " {'domain':'全局','name':'路由串味测试集','ok':True,'detail':'local pass'},\n"
                " {'domain':'全局','name':'清理','ok':True,'detail':'local pass'},\n"
                " {'domain':'全局','name':'案例索引','ok':True,'detail':'local pass'},\n"
                "]\n"
                "print(json.dumps({'results':rows,'fails':1,'uncovered':[{'domain':'fixture-domain','reason':'global failure'}],'green':False}))\n"
                "raise SystemExit(1)\n",
                encoding="utf-8",
            )
            preflight.results.clear()
            with patch.object(preflight, "ROOT", str(root)), \
                    patch.object(preflight, "TOOL", str(tool)):
                preflight.check_domain_depth()
            rows = [row for row in preflight.results if row["section"] == "11 深度"]
            self.assertTrue(rows)
            self.assertTrue(all(row["ok"] is False for row in rows), rows)
            detail = "\n".join(row["detail"] for row in rows)
            for token in ("rc=1", "green=False", "fails=1", "global failure"):
                self.assertIn(token, detail)


if __name__ == "__main__":
    unittest.main(verbosity=2)
