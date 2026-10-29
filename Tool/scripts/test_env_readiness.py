"""Environment readiness must test the deployed command and managed payloads."""
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
spec = importlib.util.spec_from_file_location("env_readiness", HERE / "env-check.py")
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)

from lib.runtime_root import make_registration


class EnvironmentReadinessTests(unittest.TestCase):
    def test_agent_root_alias_and_priority_match_installer(self):
        with tempfile.TemporaryDirectory() as td:
            alias, primary = str(Path(td) / "alias"), str(Path(td) / "primary")
            with patch.dict(os.environ, {"PI_AGENT_DIR": alias}, clear=True):
                self.assertEqual(E.agent_dir(), alias)
            with patch.dict(os.environ, {"PI_AGENT_DIR": alias, "PI_CODING_AGENT_DIR": primary}, clear=True):
                self.assertEqual(E.agent_dir(), primary)

    def test_non_object_settings_and_auth_result_are_not_ready(self):
        with tempfile.TemporaryDirectory() as td:
            settings = Path(td) / "settings.json"
            for value in ([], "invalid", 7, None):
                with self.subTest(settings=value):
                    settings.write_text(json.dumps(value), encoding="utf-8")
                    self.assertFalse(E._model_credential_probe(td)["configured"])
            settings.write_text(json.dumps({"defaultProvider": "fixture", "defaultModel": "fixture"}), encoding="utf-8")
            for value in ([], "invalid", 7, None):
                with self.subTest(result=value), patch("shutil.which", return_value=sys.executable), \
                        patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout=json.dumps(value))):
                    self.assertFalse(E._model_credential_probe(td)["configured"])

    def test_configured_missing_command_cannot_borrow_source_handshake(self):
        r = E._mcp_service_probe(config={"command": "seep-nonexistent-command-31337",
                                       "args": [E.MCP_SERVER]})
        self.assertFalse(r["available"])
        self.assertFalse(r["handshake_ok"])
        self.assertEqual(r["stage"], "config")

    def test_real_configured_seep_handshake(self):
        r = E._mcp_service_probe(config={"command": sys.executable,
                                       "args": [E.MCP_SERVER],
                                       "env": {"PYTHONIOENCODING": "utf-8"}})
        self.assertTrue(r["available"], r)
        self.assertEqual(r["probe_target"], "configured")
        self.assertGreaterEqual(r["handshake_tools"], E.MCP_MIN_TOOLS)

    def test_wrong_server_and_configured_env_cwd(self):
        with tempfile.TemporaryDirectory(prefix="seep-env-probe-") as td:
            script = Path(td) / "server.py"
            script.write_text(
                "import json, os, sys\n"
                "assert os.environ['SEEP_TEST_SENTINEL'] == 'configured'\n"
                "assert os.path.isfile('cwd.marker')\n"
                "for line in sys.stdin:\n"
                " r=json.loads(line)\n"
                " if r.get('id') == 1: print(json.dumps({'id':1,'result':{}}),flush=True)\n"
                " if r.get('id') == 2: print(json.dumps({'id':2,'result':{'tools':"
                "[{'name':'wrong_'+str(i)} for i in range(25)]}}),flush=True)\n",
                encoding="utf-8")
            (Path(td) / "cwd.marker").touch()
            config = {"command": sys.executable, "args": [str(script)], "cwd": td,
                      "env": {"SEEP_TEST_SENTINEL": "configured"}}
            r = E._mcp_service_probe(config=config)
            self.assertEqual(r["stage"], "identity", r)
            self.assertFalse(r["available"])
            config["env"] = {}
            r = E._mcp_service_probe(config=config)
            self.assertIn(r["stage"], ("initialize", "exit"), r)
            self.assertFalse(r["available"])

    def test_empty_or_stale_managed_payload_is_not_installed(self):
        with tempfile.TemporaryDirectory(prefix="seep-env-files-") as td:
            base = Path(td)
            source, agent = base / "Tool", base / "agent"
            for p in [source / "skill/example/scripts", agent / "skills/example"]:
                p.mkdir(parents=True)
            (source / "skill/example/SKILL.md").write_text("skill", encoding="utf-8")
            (source / "skill/example/scripts/helper.py").write_text("pass\n", encoding="utf-8")
            for n in ("SEEP.md", "AGENTS.md"):
                (agent / n).write_text("managed prompt", encoding="utf-8")
                (source / "prompts").mkdir(exist_ok=True)
                (source / "prompts" / n).write_text("managed prompt", encoding="utf-8")
            (agent / "mcp.json").write_text(json.dumps({"mcpServers": {
                "seep": {"command": sys.executable, "args": []}}}), encoding="utf-8")
            # Register the read-only source checkout in this temporary AgentRoot;
            # deployed payloads and all registration mutations stay in the fixture.
            origin = agent / "seep-runtime.json"
            registration = make_registration(E.ROOT, agent_root=agent)
            registered_bytes = json.dumps(registration).encode("utf-8")
            origin.write_bytes(registered_bytes)
            with patch.object(E, "TOOL", str(source)), patch.object(E, "agent_dir", return_value=str(agent)), \
                 patch.dict(os.environ, {"SEEP_RUNTIME_ROOT": E.ROOT}), \
                 patch.object(E, "_mcp_service_probe", return_value={"available": True}), \
                 patch.object(E, "_model_credential_probe", return_value={"configured": True}), \
                 patch("shutil.which", return_value=sys.executable), \
                 patch("subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="v22.19.0")):
                r = E.check()
                self.assertFalse(r["installed"], r)
                self.assertIn("example", r["checks"]["skills"]["missing"])
                import shutil
                shutil.copytree(source / "skill/example", agent / "skills/example", dirs_exist_ok=True)
                self.assertTrue(E.check()["installed"])
                bad_hash = json.loads(registered_bytes)
                entry = next(iter(bad_hash["entry_sha256"]))
                bad_hash["entry_sha256"][entry] = "0" * 64
                for label, payload, code in (
                    ("missing", None, "runtime_missing"),
                    ("malformed-json", b"{broken", "runtime_mismatch"),
                    ("invalid-shape", b"[]", "runtime_mismatch"),
                    ("hash-drift", json.dumps(bad_hash).encode("utf-8"), "runtime_mismatch"),
                ):
                    with self.subTest(registration=label):
                        if payload is None:
                            origin.unlink()
                        else:
                            origin.write_bytes(payload)
                        rejected = E.check()
                        self.assertFalse(rejected["installed"], rejected)
                        runtime = rejected["checks"]["runtime_registration"]
                        self.assertFalse(runtime["ok"], runtime)
                        self.assertEqual(runtime["code"], code, runtime)
                        self.assertEqual(len(rejected["missing"]), 1, rejected)
                origin.write_bytes(registered_bytes)
                self.assertTrue(E.check()["installed"])
                (agent / "AGENTS.md").write_text("outdated rules", encoding="utf-8")
                self.assertFalse(E.check()["installed"])
                (agent / "AGENTS.md").write_text(
                    "user addition\n<!-- seep:managed:begin -->\nmanaged prompt\n<!-- seep:managed:end -->\n", encoding="utf-8")
                self.assertTrue(E.check()["installed"])
                with patch.object(E, "_model_credential_probe", return_value={
                        "configured": False, "detail": "fixture host requires login"}):
                    auth = E.check()
                    self.assertFalse(auth["installed"])
                    self.assertEqual(len(auth["missing"]), 1)
                    actions = "\n".join(auth["next_actions"])
                    self.assertIn(str(agent), actions)
                    self.assertIn(E.MODEL_CRED_ACTION, actions)
                    self.assertNotIn("install.ps1", actions)
                    self.assertNotIn("install.sh", actions)
                    self.assertNotIn("--fix", actions)
                (agent / "skills/example/scripts/helper.py").write_text("old", encoding="utf-8")
                self.assertFalse(E.check()["installed"])

    def test_malformed_final_configuration_is_reported(self):
        for entry in (None, [], {"command": sys.executable, "args": "wrong"},
                      {"command": sys.executable, "env": {"A": 1}},
                      {"command": sys.executable, "cwd": "seep-missing-dir"}):
            with self.subTest(entry=entry):
                self.assertTrue(E._mcp_config_problems(entry))
        self.assertFalse(E._mcp_service_probe(config={"url": "http://localhost/mcp"})["available"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
