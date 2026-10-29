"""Check command failures and HTTP delivery boundaries without external traffic."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tool' / 'mcp'))
import seep_mcp_server as server
import tool_autodiscover as discovery
template_entry = discovery._mcp_entry_for


def response():
    return SimpleNamespace(status_code=200, headers={}, text='fixture response',
                           cookies=SimpleNamespace(get_dict=lambda: {}))


class McpExecutionTests(unittest.TestCase):
    def test_r2_modes_preserve_errors_before_filtering_or_headers(self):
        with tempfile.TemporaryDirectory() as td:
            binary = Path(td) / 'sample.bin'
            binary.write_bytes(b'fixture')
            for tool, modes in ((server.seep_r2_disasm, ('full', 'branch', 'summary')),
                                (server.seep_r2_decompile, ('full', 'fold', 'summary'))):
                for output in ('[ERROR code 7]: failed\npartial data',
                               'INFO: analysis completed\nERROR: Invalid address',
                               'partial data\n[STDERR]: ERROR: Invalid address'):
                    for mode in modes:
                        with self.subTest(tool=tool.__name__, mode=mode, output=output), \
                                mock.patch.object(server, '_run_cmd', return_value=output):
                            result = json.loads(tool(str(binary), output_mode=mode))
                            self.assertFalse(result['ok'])
                            self.assertEqual(result['error'], 'empty_output')

    def test_r2_headers_do_not_turn_empty_or_filtered_output_into_results(self):
        with tempfile.TemporaryDirectory() as td:
            binary = Path(td) / 'sample.bin'
            binary.write_bytes(b'fixture')
            for tool, mode, output in ((server.seep_r2_disasm, 'branch', '0x10 mov eax, 1'),
                                       (server.seep_r2_decompile, 'fold', 'eax = 1;'),
                                       (server.seep_r2_disasm, 'summary', ''),
                                       (server.seep_r2_decompile, 'summary', '')):
                with self.subTest(mode=mode, output=output), \
                        mock.patch.object(server, '_run_cmd', return_value=output):
                    result = json.loads(tool(str(binary), output_mode=mode))
                    self.assertFalse(result['ok'])
                    self.assertEqual(result['error'], 'empty_output')

    def test_r2_summary_keeps_complete_text_and_honors_budget(self):
        with tempfile.TemporaryDirectory() as td:
            binary = Path(td) / 'sample.bin'
            binary.write_bytes(b'fixture')
            output = 'function details ' + 'x' * 1500 + ' END_OF_DETAILS'
            for tool in (server.seep_r2_disasm, server.seep_r2_decompile):
                with self.subTest(tool=tool.__name__), \
                        mock.patch.object(server, '_run_cmd', return_value=output):
                    self.assertIn('END_OF_DETAILS', tool(str(binary), output_mode='summary', limit_tokens=0))
                    result = json.loads(tool(str(binary), output_mode='summary', limit_tokens=100))
                    self.assertEqual(result['error'], 'resource_constraint')
                    self.assertTrue(result['continuation'])

    def test_nonzero_command_with_stdout_remains_an_error(self):
        output = server._run_cmd([sys.executable, '-c',
                                  'import sys; print("partial result"); sys.exit(7)'])
        self.assertIn('[ERROR code 7]', output)
        self.assertIn('partial result', output)

    def test_failed_post_is_not_resent_through_a_second_backend(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                seen.append(self.rfile.read(int(self.headers['Content-Length'])))
                self.send_response(200)
                self.send_header('Content-Length', '0')
                self.end_headers()

        listener = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=listener.serve_forever, daemon=True).start()
        self.addCleanup(listener.server_close)
        self.addCleanup(listener.shutdown)
        url = f'http://127.0.0.1:{listener.server_port}/update'

        def delivered_then_failed(method, url, **kwargs):
            with urllib.request.urlopen(urllib.request.Request(
                    url, data=kwargs['data'].encode(), method=method), timeout=2):
                pass
            raise ConnectionError('response lost after server processed POST')

        fallback = mock.Mock(return_value=response())
        with mock.patch.dict(sys.modules, {
                'curl_cffi': SimpleNamespace(requests=SimpleNamespace(request=delivered_then_failed)),
                'requests': SimpleNamespace(request=fallback)}):
            result = server.seep_http_replay(url, method='POST', body='one update')
        self.assertIn('ERROR', result)
        self.assertEqual(seen, [b'one update'])
        fallback.assert_not_called()

    def test_fallback_is_allowed_when_preferred_backend_is_not_installed(self):
        fallback = mock.Mock(return_value=response())
        with mock.patch.dict(sys.modules, {'curl_cffi': None,
                                          'requests': SimpleNamespace(request=fallback)}):
            result = json.loads(server.seep_http_replay('http://fixture.invalid', method='DELETE', body='delete me'))
        self.assertEqual(result['status'], 200)
        self.assertEqual(fallback.call_args.kwargs.get('data'), 'delete me')

    def test_invalid_request_parameters_stop_before_network_or_snapshot_write(self):
        with tempfile.TemporaryDirectory() as td:
            snapshot = Path(td) / 'snapshot.json'
            request = mock.Mock(return_value=response())
            bad_params = ({'headers': '[]'}, {'cookies': '[]'}, {'timeout': 0},
                          {'method': 'POST\r\ninvalid'}, {'headers': '{"bad":[]}'})
            with mock.patch.dict(sys.modules, {
                    'curl_cffi': SimpleNamespace(requests=SimpleNamespace(request=request))}):
                for params in bad_params:
                    with self.subTest(params=params):
                        result = server.seep_http_replay('http://fixture.invalid',
                                                        session_file=str(snapshot), **params)
                        self.assertIn('ERROR', result)
                        self.assertFalse(snapshot.exists())
            request.assert_not_called()


class McpRegistrationTests(unittest.TestCase):
    def test_registration_template_preserves_runtime_context(self):
        template = {'command': 'python', 'args': ['server.py'], 'env': {'FIXTURE': 'yes'},
                    'cwd': 'fixture-root', 'headers': {'Authorization': 'Bearer fixture'}}
        with mock.patch.object(discovery, '_capabilities_table', return_value={
                'mcp_ecosystem': {'fixture': template}}):
            self.assertEqual(template_entry('fixture'), template)

    def test_preflight_rejects_directories_and_malformed_argument_containers(self):
        with tempfile.TemporaryDirectory() as td:
            for entry in ({'command': td}, {'command': sys.executable, 'args': 'server.py'},
                          {'command': sys.executable, 'args': [False]},
                          {'command': sys.executable, 'env': []}):
                with self.subTest(entry=entry):
                    self.assertFalse(discovery._mcp_entry_preflight(entry)['ok'])

    def test_preflight_resolves_script_against_server_cwd(self):
        with tempfile.TemporaryDirectory() as td:
            Path(td, 'server.py').write_text('# fixture', encoding='utf-8')
            entry = {'command': sys.executable, 'args': ['./server.py'], 'cwd': td}
            self.assertTrue(discovery._mcp_entry_preflight(entry)['ok'])

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='seep-mcp-registration-')
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'mcp.json'
        self.entry = {'command': sys.executable, 'args': ['-c', 'pass']}
        patcher = mock.patch.dict('os.environ', {'SEEP_AGENT_MCP': str(self.path)})
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(discovery, '_mcp_entry_for', return_value=self.entry)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_bom_config_preserves_user_entries_and_metadata(self):
        self.path.write_text(json.dumps({'user': 'keep', 'mcpServers': {
            'user': {'command': 'user-runtime'}}}), encoding='utf-8-sig')
        result = discovery.register_mcp('fixture', apply=True)
        self.assertTrue(result['registered'], result)
        saved = json.loads(self.path.read_text(encoding='utf-8-sig'))
        self.assertEqual(saved['user'], 'keep')
        self.assertIn('user', saved['mcpServers'])

    def test_bad_config_is_not_replaced_with_empty_defaults(self):
        for before in (b'{broken', b'[]', b'{"mcpServers":[]}', b'{"mcpServers":{"user":[]}}'):
            with self.subTest(before=before):
                self.path.write_bytes(before)
                result = discovery.register_mcp('fixture', apply=True)
                self.assertFalse(result['registered'], result)
                self.assertEqual(self.path.read_bytes(), before)

    def test_same_name_user_service_is_not_overwritten(self):
        before = b'{"mcpServers":{"fixture":{"command":"user-service"}}}'
        self.path.write_bytes(before)
        result = discovery.register_mcp('fixture', apply=True)
        self.assertFalse(result['registered'], result)
        self.assertEqual(self.path.read_bytes(), before)

    def test_registration_prunes_old_backups(self):
        self.path.write_text('{"mcpServers":{}}', encoding='utf-8')
        for index in range(5):
            backup = Path(str(self.path) + '.bak-%06d' % index)
            backup.write_text('old', encoding='utf-8')
            os.utime(backup, (index + 1, index + 1))
        result = discovery.register_mcp('fixture', apply=True)
        self.assertTrue(result['registered'], result)
        backups = list(Path(self.tmp.name).glob('mcp.json.bak-*'))
        self.assertEqual(len(backups), 3)

    def test_failed_atomic_replace_preserves_original(self):
        before = b'{"mcpServers":{"user":{"command":"user-service"}}}'
        self.path.write_bytes(before)
        with mock.patch.object(discovery.os, 'replace', side_effect=OSError('fixture write locked')):
            result = discovery.register_mcp('fixture', apply=True)
        self.assertFalse(result['registered'], result)
        self.assertEqual(self.path.read_bytes(), before)

    def test_bad_secondary_target_stops_before_primary_write(self):
        tool_dir = Path(self.tmp.name) / 'Tool'
        tool_dir.mkdir()
        secondary = Path(self.tmp.name) / '.mcp.json'
        secondary.write_bytes(b'{broken secondary')
        before = b'{"mcpServers":{"user":{"command":"user-service"}}}'
        self.path.write_bytes(before)
        with mock.patch.object(discovery, '_TOOL_DIR', str(tool_dir)), \
                mock.patch.object(discovery, '_root_mcp_sync_enabled', return_value=True):
            result = discovery.register_mcp('fixture', apply=True)
        self.assertFalse(result['registered'], result)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(secondary.read_bytes(), b'{broken secondary')


if __name__ == '__main__':
    unittest.main(verbosity=2)
