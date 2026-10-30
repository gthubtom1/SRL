"""Local counterexamples for HTTP output and command lifecycle boundaries."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import seep_mcp_server as S
import seep_http_security as H
import seep_apk_contract as A


class HttpOutputAudit(unittest.TestCase):
    def replay(self, text, response_headers=None, **kwargs):
        response = SimpleNamespace(status_code=200, headers=response_headers or {}, text=text,
                                   cookies=SimpleNamespace(get_dict=lambda: {}))
        client = SimpleNamespace(request=lambda *a, **k: response)
        with patch.dict(sys.modules, {'curl_cffi': SimpleNamespace(requests=client)}):
            return S.seep_http_replay('http://fixture.invalid', **kwargs)

    def test_cookie_header_values_are_scrubbed_when_echoed_individually(self):
        raw = self.replay('echo FIXTURE_COOKIE_A FIXTURE_COOKIE_B',
                          response_headers={'Set-Cookie': 'sid=FIXTURE_COOKIE_B; Path=/; HttpOnly'},
                          **{'headers': json.dumps({'Cookie': 'sid=FIXTURE_COOKIE_A; mode=light'})})
        self.assertNotIn('FIXTURE_COOKIE_A', raw)
        self.assertNotIn('FIXTURE_COOKIE_B', raw)

    def test_preview_cut_cannot_expose_a_secret_prefix(self):
        raw = self.replay('x' * 1994 + 'FIXTURE_LONG_COOKIE',
                          cookies=json.dumps({'sid': 'FIXTURE_LONG_COOKIE'}))
        self.assertNotIn('FIXTUR', raw)

    def test_error_does_not_echo_url_userinfo(self):
        def fail(*a, **k):
            raise ConnectionError('failed http://FIXTURE_USER:FIXTURE_PASS@fixture.invalid')
        with patch.dict(sys.modules, {'curl_cffi': SimpleNamespace(
                requests=SimpleNamespace(request=fail))}):
            raw = S.seep_http_replay('http://FIXTURE_USER:FIXTURE_PASS@fixture.invalid')
        self.assertNotIn('FIXTURE_USER', raw)
        self.assertNotIn('FIXTURE_PASS', raw)

    def test_url_redaction_covers_encoded_path_and_fragment_echoes(self):
        url = 'http://fixture.invalid/FIXTURE_URL_TOKEN#FIXTURE_URL_TOKEN'
        clean = H._redact_url(url, ['FIXTURE_URL_TOKEN'])
        self.assertNotIn('FIXTURE_URL_TOKEN', clean)


class CommandLifecycleAudit(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Windows batch argument handling')
    def test_apk_batch_arguments_are_literal(self):
        with tempfile.TemporaryDirectory() as td:
            batch = Path(td) / 'probe.cmd'
            batch.write_text('@echo off\n@echo "%~1"\n', encoding='ascii')
            for value in ('x&ver', '%SEEP_AUDIT_LITERAL%', 'x!literal!^test'):
                with self.subTest(value=value), patch.dict(os.environ, {'SEEP_AUDIT_LITERAL': 'EXPANDED'}):
                    result = A.run_command([str(batch), value], timeout=5)
                self.assertEqual(result['returncode'], 0)
                self.assertEqual(result['stdout'].strip(), '"' + value + '"')

    def test_timeout_kills_descendant_before_it_can_write(self):
        for runner in (S._run_capture, A.run_command):
            with self.subTest(runner=runner.__name__):
                self.check_timeout(runner)

    def check_timeout(self, runner):
        with tempfile.TemporaryDirectory() as td:
            marker = Path(td) / 'late.marker'
            child = ('import time; from pathlib import Path; time.sleep(.8); '
                     'Path(%r).write_text("unexpected")' % str(marker))
            parent = ('import subprocess,sys,time; '
                      'subprocess.Popen([sys.executable,"-c",%r]); time.sleep(10)' % child)
            result = runner([sys.executable, '-c', parent], timeout=.3)
            self.assertIsNone(result['returncode'])
            self.assertTrue(result.get('timed_out') or 'timeout' in result.get('error', ''))
            time.sleep(.9)
            self.assertFalse(marker.exists(), 'timed-out tool left a live descendant')


if __name__ == '__main__':
    unittest.main(verbosity=2)
