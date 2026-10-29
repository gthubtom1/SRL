"""Installed helper scripts must use the registered runtime from a neutral cwd."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
from lib.runtime_root import make_registration


class SkillDeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-deployed-skill-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.agent = self.base / "agent with spaces"
        self.neutral = self.base / "neutral"
        self.neutral.mkdir()
        for domain, names in {
            "softseep": ["seep_runtime.py", "mcp-guard.py", "skill-route-probe.py"],
            "web-pentest": ["kb-query.py"],
        }.items():
            destination = self.agent / "skills" / domain / "scripts"
            destination.mkdir(parents=True)
            for name in names:
                shutil.copy2(ROOT / "Tool/skill" / domain / "scripts" / name, destination / name)
        self.registration = make_registration(ROOT, self.agent)
        self.origin = self.agent / "seep-runtime.json"
        self.write_registration()

    def write_registration(self):
        self.origin.write_text(json.dumps(self.registration), encoding="utf-8")

    def run_script(self, relative, args, *, source=False, explicit_agent=True, runtime=None):
        root = ROOT / "Tool/skill" if source else self.agent / "skills"
        env = {k: v for k, v in os.environ.items()
               if k not in {"SEEP_RUNTIME_ROOT", "PI_CODING_AGENT_DIR", "PI_AGENT_DIR", "PYTHONPATH"}}
        env.update(PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
        if explicit_agent:
            env["PI_CODING_AGENT_DIR"] = str(self.agent)
        if runtime is not None:
            env["SEEP_RUNTIME_ROOT"] = str(runtime)
        return subprocess.run([sys.executable, "-B", str(root / relative), *args],
                              cwd=self.neutral, env=env, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=120)

    def test_source_and_deployed_queries_and_mcp_checks_agree(self):
        for relative, args in [
            ("web-pentest/scripts/kb-query.py", ["--board", "__seep_empty_board__", "--limit", "1"]),
            ("softseep/scripts/mcp-guard.py", ["--json"]),
            ("softseep/scripts/skill-route-probe.py", ["--json"]),
        ]:
            with self.subTest(relative=relative):
                source = self.run_script(relative, args, source=True)
                deployed = self.run_script(relative, args)
                self.assertEqual(source.returncode, 0, source.stdout + source.stderr)
                self.assertEqual(deployed.returncode, 0, deployed.stdout + deployed.stderr)
                self.assertEqual(json.loads(source.stdout), json.loads(deployed.stdout))

    def test_deployed_path_can_locate_its_own_registration_without_env(self):
        r = self.run_script("softseep/scripts/mcp-guard.py", ["--json"], explicit_agent=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_invalid_or_missing_registration_returns_repair_hint(self):
        for data in (None, "{broken", json.dumps({**self.registration, "schema": "wrong/1"}),
                     json.dumps({**self.registration, "entry_sha256": {
                         "Tool/skill/softseep/pack.json": "0" * 64}})):
            with self.subTest(data=data):
                if data is None:
                    self.origin.unlink(missing_ok=True)
                else:
                    self.origin.write_text(data, encoding="utf-8")
                r = self.run_script("softseep/scripts/mcp-guard.py", ["--json"])
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
                result = json.loads(r.stdout)
                self.assertFalse(result["ok"])
                self.assertTrue(result["hint"])
                self.assertNotIn("Traceback", r.stderr)

    def test_explicit_runtime_overrides_stale_registration_but_never_falls_back(self):
        self.origin.write_text("{broken", encoding="utf-8")
        good = self.run_script("softseep/scripts/mcp-guard.py", ["--json"], runtime=ROOT)
        self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
        bad = self.run_script("softseep/scripts/mcp-guard.py", ["--json"], runtime=self.base / "missing")
        self.assertEqual(bad.returncode, 2, bad.stdout + bad.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
