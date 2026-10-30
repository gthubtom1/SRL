"""Identity and MCP diagnostic counterexamples; fixtures never scan or install."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / 'mcp'))
from lib import tool_identity as I, mcp_http
import seep_tool_verify as V

spec = importlib.util.spec_from_file_location('audit_doctor', HERE / 'mcp-doctor.py')
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)
spec = importlib.util.spec_from_file_location('audit_acquire', HERE / 'tool-acquire.py')
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


class IdentityAudit(unittest.TestCase):
    BANNERS = {'nmap': 'Nmap version 7.98 ( https://nmap.org )\n',
               'nuclei': '[INF] Nuclei Engine Version: v3.6.2\n'}

    def test_version_probe_identity_and_no_target_arguments(self):
        for tid, banner in self.BANNERS.items():
            with self.subTest(tool=tid), patch.object(I, '_run', return_value=(banner, 0)) as run:
                result = I.probe(tid, sys.executable)
                self.assertTrue(result['ok'], result)
                self.assertTrue(result['verified'])
                self.assertEqual(run.call_args.args[0], [sys.executable,
                                 '--version' if tid == 'nmap' else '-version'])

    def test_generic_same_name_and_failed_banner_are_not_verified(self):
        for tid, banner in self.BANNERS.items():
            for out, rc in [('Version 3.6.2', 0), ('unrelated ' + tid, 0), (banner, 1), ('', 0)]:
                with self.subTest(tool=tid, rc=rc), patch.object(I, '_run', return_value=(out, rc)):
                    result = I.probe(tid, sys.executable)
                    self.assertIs(result['ok'], False)
                    self.assertFalse(result['verified'])

    def test_ansi_nuclei_banner_and_stderr_are_supported(self):
        completed = subprocess.CompletedProcess([], 0, '',
                     '\x1b[34m[INF]\x1b[0m Nuclei Engine Version: v3.6.2\n')
        with patch.object(I.process_tree, 'run', return_value=completed) as run:
            result = I.probe('nuclei', sys.executable)
        self.assertTrue(result['ok'], result)
        self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
        self.assertLessEqual(run.call_args.kwargs['timeout'], 20)

    def test_timeout_is_failed_and_does_not_echo_partial_output(self):
        with patch.object(I.process_tree, 'run', side_effect=subprocess.TimeoutExpired(
                'fixture', .1, output='FIXTURE_PARTIAL_SECRET')):
            result = I.probe('nmap', sys.executable)
        self.assertFalse(result['ok'])
        self.assertEqual(result['returncode'], -9)
        self.assertNotIn('FIXTURE_PARTIAL_SECRET', json.dumps(result))

    def test_identity_module_is_importable_by_its_file_path(self):
        code = ('import runpy; data=runpy.run_path(%r); '
                'assert "nmap" in data["PROBES"]' % str(HERE / 'lib/tool_identity.py'))
        result = subprocess.run([sys.executable, '-B', '-c', code],
                                cwd=HERE.parents[1], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)

    def test_failed_probe_output_is_not_republished(self):
        with patch.object(I, '_run', return_value=('FIXTURE_DIAGNOSTIC_SECRET', 2)):
            result = I.probe('python', sys.executable)
        self.assertNotIn('FIXTURE_DIAGNOSTIC_SECRET', json.dumps(result))

    def test_real_same_name_programs_and_failed_version_commands_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            for tid, banner in self.BANNERS.items():
                path = Path(td) / (tid + ('.cmd' if os.name == 'nt' else ''))
                for output, rc in [('Version 3.6.2', 0), (banner.strip(), 7)]:
                    if os.name == 'nt':
                        path.write_text('@echo off\n@echo ' + output + '\n@exit /b %d\n' % rc,
                                        encoding='ascii')
                    else:
                        path.write_text('#!/bin/sh\nprintf "%s\\n" ' + repr(output) +
                                        '\nexit %d\n' % rc, encoding='ascii')
                        path.chmod(0o700)
                    result = I.probe(tid, str(path))
                    self.assertFalse(result['ok'])
                    self.assertFalse(result['verified'])
                    self.assertEqual(result['returncode'], rc)

    def test_mcp_and_acquire_share_identity_without_claiming_task_execution(self):
        for tid, banner in self.BANNERS.items():
            with self.subTest(tool=tid), patch.object(I, '_run', return_value=(banner, 0)), \
                    patch.object(V, '_tool_identity_module', return_value=I):
                result = V.verify_tool(tid, sys.executable)
                self.assertTrue(result['verified'], result)
                acquired = A._assess_available(tid, [{'exe': sys.executable}], 'L0')
                self.assertEqual(acquired['verdict'], 'USABLE')
                self.assertFalse(acquired['runtime_verified'])
                self.assertFalse(acquired['session_verified'])


class McpDiagnosticAudit(unittest.TestCase):
    def test_apktool_identity_probes_the_discovered_launcher(self):
        with patch.object(V, '_tool_identity_module', return_value=I), \
                patch.object(I, '_run', return_value=('2.12.0\n', 0)) as run:
            result = V.verify_tool('apktool', sys.executable, 'unrelated-bundled.jar')
        self.assertTrue(result['verified'], result)
        self.assertEqual(run.call_args.args[0], [sys.executable, '--version'])

    def test_r2_arch_substring_without_valid_json_is_not_analysis_evidence(self):
        for output in ['not JSON: "arch": "x86"', '{"arch": null}', '{"arch": ""}']:
            with self.subTest(output=output), patch.object(V.process_tree, 'run', return_value=
                    subprocess.CompletedProcess([], 0, output, '')):
                result = V.verify_tool('r2', sys.executable)
                self.assertFalse(result['verified'], result)

    def test_r2_valid_analysis_is_verified_but_errors_do_not_echo_raw_data(self):
        with patch.object(V.process_tree, 'run', return_value=subprocess.CompletedProcess(
                [], 0, '{"arch":"x86","bits":64}', '')):
            self.assertTrue(V.verify_tool('r2', sys.executable)['verified'])
        for failure in [subprocess.CompletedProcess([], 7, 'FIXTURE_TOOL_SECRET', ''),
                        OSError('FIXTURE_TOOL_SECRET')]:
            kw = {'side_effect': failure} if isinstance(failure, Exception) else {'return_value': failure}
            with patch.object(V.process_tree, 'run', **kw):
                result = V.verify_tool('r2', sys.executable)
            self.assertFalse(result['verified'])
            self.assertNotIn('FIXTURE_TOOL_SECRET', json.dumps(result))

    def test_malformed_rpc_diagnostics_do_not_echo_remote_body(self):
        raw = b'data: FIXTURE_REMOTE_SECRET\n\n'
        with self.assertRaises(mcp_http.McpProbeError) as caught:
            mcp_http.rpc_result(raw, {'Content-Type': 'text/event-stream'}, 1, 'initialize')
        self.assertNotIn('FIXTURE_REMOTE_SECRET', str(caught.exception))

    def test_stdio_exception_does_not_echo_child_or_environment_values(self):
        fake = SimpleNamespace(handshake_stdio=lambda cfg: (_ for _ in ()).throw(
            ValueError('FIXTURE_STDIO_SECRET')))
        with patch.object(D.importlib.util, 'module_from_spec', return_value=fake), \
                patch('importlib.machinery.SourceFileLoader.exec_module'):
            result = D.probe_stdio({'command': sys.executable})
        self.assertFalse(result['ok'])
        self.assertNotIn('FIXTURE_STDIO_SECRET', json.dumps(result))


if __name__ == '__main__':
    unittest.main(verbosity=2)
