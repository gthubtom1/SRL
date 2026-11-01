"""Prompt budget uses the selected installation and the requested threshold."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("budget.py")


class PromptBudgetTests(unittest.TestCase):
    def test_reminder_budget_tracks_selected_loader_and_disable_switch(self):
        with tempfile.TemporaryDirectory() as td:
            agent = Path(td) / 'agent'
            extensions = agent / 'extensions'
            extensions.mkdir(parents=True)
            loader = extensions / 'load-system-prompt.ts'
            env = dict(os.environ, PI_CODING_AGENT_DIR=str(agent),
                       HOME=td, USERPROFILE=td, PYTHONIOENCODING='utf-8')
            env.pop('SEEP_CAPABILITY_GUIDANCE', None)
            for source, switch, enabled in (("// old installed loader", None, False),
                                            ('export const CAPABILITY_GUIDE = `fixture reminder`;', None, True),
                                            ('export const CAPABILITY_GUIDE = `fixture reminder`;', '0', False)):
                loader.write_text(source, encoding='utf-8')
                if switch is None:
                    env.pop('SEEP_CAPABILITY_GUIDANCE', None)
                else:
                    env['SEEP_CAPABILITY_GUIDANCE'] = switch
                run = subprocess.run([sys.executable, '-X', 'utf8', str(SCRIPT), '--prompt', '--json'],
                                     env=env, capture_output=True, text=True, encoding='utf-8', timeout=20)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                row = next(r for r in json.loads(run.stdout)['layers']
                           if r['layer'].startswith('seep-capability-guide'))
                self.assertEqual(row['tokens'] > 0, enabled)
                if switch is None:
                    self.assertEqual(Path(row['path']), loader)

    def test_selected_agent_root_and_custom_ceiling(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            selected = root / "selected"
            selected.mkdir()
            (selected / "AGENTS.md").write_text("测" * 4000, encoding="utf-8")
            env = dict(os.environ)
            env.pop("PI_CODING_AGENT_DIR", None)
            env.update(HOME=str(root / "home"), USERPROFILE=str(root / "home"),
                       PI_AGENT_DIR=str(selected), PYTHONDONTWRITEBYTECODE="1")
            for ceiling, rc in ((None, 1), (3000, 1), (8000, 0)):
                with self.subTest(ceiling=ceiling):
                    cmd = [sys.executable, "-B", "-X", "utf8", str(SCRIPT),
                           "--prompt", "--json"]
                    if ceiling is not None:
                        cmd.extend(["--ceiling", str(ceiling)])
                    got = subprocess.run(cmd, env=env, capture_output=True,
                                         text=True, encoding="utf-8", timeout=20)
                    self.assertEqual(got.returncode, rc, got.stdout + got.stderr)
                    data = json.loads(got.stdout)
                    rules = next(r for r in data["layers"]
                                 if r["layer"].startswith("AGENTS.md"))
                    self.assertEqual(Path(rules["path"]), selected / "AGENTS.md")
                    self.assertEqual(rules["tokens"], 4000)
                    self.assertEqual(data["controllable_ceiling"], ceiling or 3500)
                    self.assertEqual(data["over_by"], max(
                        0, data["controllable_tokens"] - (ceiling or 3500)))

            # Both installers give PI_CODING_AGENT_DIR precedence.
            preferred = root / "preferred"
            preferred.mkdir()
            env["PI_CODING_AGENT_DIR"] = str(preferred)
            got = subprocess.run([sys.executable, "-B", "-X", "utf8", str(SCRIPT),
                                  "--prompt", "--json"], env=env, capture_output=True,
                                 text=True, encoding="utf-8", timeout=20)
            self.assertEqual(got.returncode, 0, got.stdout + got.stderr)
            rules = next(r for r in json.loads(got.stdout)["layers"]
                         if r["layer"].startswith("AGENTS.md"))
            self.assertEqual(Path(rules["path"]), preferred / "AGENTS.md")


if __name__ == "__main__":
    unittest.main()
