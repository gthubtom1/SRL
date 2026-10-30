"""Historical plugin acceptance requires the original recorded repository location.

This remains part of complete local acceptance. Public contracts live in
 test_r10a_contracts.py; no historical evidence or path rejection is changed.
"""
import json
from pathlib import Path
import unittest
from test_r10a_contracts import ROOT, PROTOCOL, child, command_scripts


class HistoricalPluginAcceptance(unittest.TestCase):
    def test_plugin_cases_are_active_protocol_domain_and_accept_passes(self):
        expected = ("plugin02", "plugin03", "plugin04", "plugin05", "plugin06")
        for name in expected:
            case_dir = ROOT / "Tool" / "cases" / name
            path = case_dir / "case.json"
            case = json.loads(path.read_text(encoding="utf-8-sig"))
            self.assertEqual(case["domain"], "protocol-plugin", name)
            repro = case["repro"]
            self.assertEqual(repro["status"], "recorded", name)
            self.assertEqual(repro["cwd"], ".", name)
            self.assertEqual(repro["rc"], 0, name)
            repro_base = (ROOT / repro["cwd"]).resolve()
            scripts = command_scripts(repro["command"], repro_base)
            self.assertTrue(scripts, name)
            self.assertTrue(all(path.is_file() for path in scripts), name)

            run = json.loads(
                (case_dir / "artifacts" / "run.json").read_text(encoding="utf-8-sig"))
            run_cwd = Path(run.get("cwd") or ROOT)
            if not run_cwd.is_absolute():
                run_cwd = ROOT / run_cwd
            for row in run["runs"]:
                self.assertIsInstance(row["rc"], int, name)
                run_scripts = command_scripts(row["cmd"], run_cwd.resolve())
                self.assertTrue(run_scripts, name)
                self.assertTrue(all(path.is_file() for path in run_scripts), name)
            for artifact in case_dir.rglob("*"):
                if artifact.is_file() and artifact.suffix.lower() in (
                        ".json", ".md", ".txt", ".yml", ".yaml"):
                    text = artifact.read_text(encoding="utf-8", errors="ignore")
                    self.assertNotIn("plugin-targets/scripts/", text, str(artifact))
        proc = child([PROTOCOL / "proto-accept.py", "--json"])
        result = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(result["ok"])
        pack = json.loads((ROOT / "Tool/skill/protocol-plugin/pack.json")
                          .read_text(encoding="utf-8-sig"))
        self.assertEqual(pack["cases"], ["protocol05"])
        self.assertEqual(pack["cases"], pack["case_roles"]["witness"])
        self.assertEqual(result["declared_cases"], pack["cases"])
        self.assertEqual(result["case_count"], len(pack["cases"]))
        self.assertEqual([row["case"] for row in result["cases"]], pack["cases"])
        self.assertTrue(all(row["ok"] for row in result["cases"]))
        self.assertEqual(result["case_roles"], pack["case_roles"])

        # Historical protocol/plugin methods remain eligible for local checks;
        # selecting them never extends the pack's current witness declaration.
        old_methods = ["protocol01", "protocol02", "protocol03", "protocol04", *expected]
        flags = [part for name in old_methods
                 for part in ("--case", ROOT / "Tool/cases" / name)]
        proc = child([PROTOCOL / "proto-accept.py", "--json", *flags])
        limited = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(limited["declared_cases"], pack["cases"])
        self.assertEqual(limited["case_count"], len(old_methods))
        self.assertTrue(all(row["ok"] for row in limited["cases"]))
        self.assertTrue(all("witness" not in row["roles"] for row in limited["cases"]))

        proc = child([PROTOCOL / "plugin-accept.py", "--root", ROOT, "--json"])
        plugin_result = json.loads(proc.stdout)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(plugin_result["ok"])
        self.assertEqual(plugin_result["case_count"], 5)
        self.assertTrue(all(row["ok"] for row in plugin_result["cases"]))



if __name__ == "__main__":
    unittest.main()
