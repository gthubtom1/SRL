"""Run bounded offline capability controls and CLI output-safety regressions."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = (
    'web-pentest/subskills/asset-discovery/scripts/nmap-normalize.py',
    'web-pentest/subskills/oauth-oidc/scripts/oauth-review.py',
    'web-pentest/subskills/source-review/scripts/source_review.py',
    'softseep/subskills/game-runtime/scripts/snapshot_candidates.py',
    'softseep/subskills/game-rendering/scripts/w2s_check.py',
)


class OfflineCapabilities(unittest.TestCase):
    def invoke(self, script, args, cwd):
        return subprocess.run([sys.executable, '-B', '-X', 'utf8',
            str(ROOT / 'Tool/skill' / script), *args], cwd=cwd,
            capture_output=True, text=True, encoding='utf-8', timeout=45,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))

    def test_real_offline_positive_and_negative_controls(self):
        with tempfile.TemporaryDirectory(prefix='seep-capability-') as cwd:
            for script in SCRIPTS:
                with self.subTest(script=script):
                    result = self.invoke(script, ['--self-test'], cwd)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    data = json.loads(result.stdout)
                    self.assertTrue(data.get('ok') is True or data.get('self_test') == 'passed'
                                    or isinstance(data.get('passed'), int) and data['passed'] > 0)

    def test_bad_arguments_never_echo_the_supplied_value(self):
        marker = 'SENTINEL-CLI-VALUE-MUST-NOT-BE-ECHOED'
        with tempfile.TemporaryDirectory(prefix='seep-capability-') as cwd:
            for script in SCRIPTS:
                with self.subTest(script=script):
                    result = self.invoke(script, ['--unknown-argument', marker], cwd)
                    self.assertEqual(result.returncode, 2)
                    self.assertNotIn(marker, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
