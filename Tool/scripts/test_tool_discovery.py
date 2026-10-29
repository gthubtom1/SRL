"""Real interpreter imports and install/recheck behavior, without network/package installs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "Tool/mcp"))
import tool_autodiscover as T
import seep_mcp_server as S


class LibraryDiscoveryTests(unittest.TestCase):
    def test_importable_libraries_do_not_install(self):
        with tempfile.TemporaryDirectory(prefix="seep-library-probe-") as td:
            for name in ("pefile", "zstandard", "curl_cffi"):
                (Path(td) / (name + ".py")).write_text("__version__='fixture'\n", encoding="utf-8")
            real_run = T.process_tree.run
            def no_install(argv, **kw):
                self.assertNotIn("pip", argv, "an importable library must not reinstall")
                return real_run(argv, **kw)
            with patch.dict(os.environ, {"PYTHONPATH": td}), \
                 patch.object(S, "_autodiscover", return_value=T), \
                 patch.object(T.process_tree, "run", side_effect=no_install):
                for name in ("pefile", "zstandard", "curl_cffi"):
                    for _ in range(2):
                        r = json.loads(S.seep_ensure_tool(name))
                        self.assertEqual(r["status"], "ready", r)
                        self.assertEqual(r["kind"], "python_lib")
                        self.assertEqual(r["interpreter"], sys.executable)
                    self.assertEqual(T.plan_control(name)["how_to_control"]["mode"], "python_lib")

    def install_case(self, pip_rc, create_module):
        with tempfile.TemporaryDirectory(prefix="seep-library-install-") as td:
            name = "seep_audit_" + uuid.uuid4().hex
            table = {"installable": {name: {"kind": "python_lib", "module": name,
                      "method": "pip", "pkg": name}}, "auto_allow_methods": ["pip"]}
            real_run, pip_calls = T.process_tree.run, []
            def simulate_pip(argv, **kw):
                if argv[1:4] == ["-m", "pip", "install"]:
                    pip_calls.append(argv)
                    if create_module:
                        (Path(td) / (name + ".py")).write_text("VALUE=42\n", encoding="utf-8")
                    return SimpleNamespace(returncode=pip_rc, stdout="fixture pip", stderr="")
                return real_run(argv, **kw)
            with patch.dict(os.environ, {"PYTHONPATH": td}), \
                 patch.object(T, "_install_table", return_value=table), \
                 patch.object(S, "_autodiscover", return_value=T), \
                 patch.object(T.process_tree, "run", side_effect=simulate_pip):
                first = json.loads(S.seep_ensure_tool(name))
                if create_module:
                    second = json.loads(S.seep_ensure_tool(name))
                    self.assertEqual(second["status"], "ready", second)
            self.assertTrue(all(argv[0] == sys.executable for argv in pip_calls))
            return first, pip_calls

    def test_install_rechecks_in_a_fresh_process_and_stops_reinstalling(self):
        r, calls = self.install_case(0, True)
        self.assertEqual(r["status"], "ready", r)
        self.assertEqual(len(calls), 1)

    def test_successful_pip_without_import_is_not_ready(self):
        r, calls = self.install_case(0, False)
        self.assertEqual(r["status"], "missing", r)
        self.assertFalse(r["install_attempt"]["recheck"]["available"])
        self.assertEqual(len(calls), 1)

    def test_failed_install_stays_missing(self):
        r, calls = self.install_case(1, False)
        self.assertEqual(r["status"], "missing", r)
        self.assertEqual(r["install_attempt"]["returncode"], 1)
        self.assertEqual(len(calls), 2)  # declared mirror retry

    def test_cli_still_requires_an_executable(self):
        with patch.object(T, "_cache_get", return_value=None), \
             patch.object(T, "_layer_env", return_value=None), \
             patch.object(T, "_layer_path", return_value={"command": "fixture-frida", "via": "PATH"}), \
             patch.object(T, "_cache_put"):
            r = T.discover("frida")
            self.assertTrue(r["available"])
            self.assertEqual(r["command"], "fixture-frida")
            self.assertNotEqual(r.get("kind"), "python_lib")


if __name__ == "__main__":
    unittest.main(verbosity=2)
