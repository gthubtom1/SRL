"""Exercise MCP health reports against isolated configurations and HTTP servers."""
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Tool' / 'scripts'))


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


doctor = load('Tool/scripts/mcp-doctor.py', 'review_mcp_doctor')
handshake = load('Tool/skill/softseep/scripts/mcp-handshake.py', 'review_mcp_handshake')
launcher = load('Tool/scripts/mcp-launch.py', 'review_mcp_launcher')
bridge = load('Tool/scripts/mcp-bridge-x64dbg.py', 'review_mcp_bridge')
acquire = load('Tool/scripts/tool-acquire.py', 'review_tool_acquire')


class McpLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='seep-mcp-lifecycle-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def handshake_main(self, servers, *flags):
        config = self.root / 'mcp.json'
        config.write_text(json.dumps({'mcpServers': servers}), encoding='utf-8')
        output = io.StringIO()
        with redirect_stdout(output):
            rc = handshake.main(['--mcp-json', str(config), '--out', str(self.root / 'baseline.json'),
                                 '--json', '--no-write', *flags])
        return rc, json.loads(output.getvalue())

    def test_first_handshake_unreachable_is_partial_and_no_write_is_truthful(self):
        with mock.patch.object(handshake, 'probe_one', return_value={
                'state': 'unreachable', 'reason': 'fixture offline'}):
            rc, result = self.handshake_main({'offline': {'command': 'missing'}})
        self.assertEqual(rc, 2, result)
        self.assertEqual(result['verdict'], 'PARTIAL')
        self.assertIn('offline', result['unreachable'])
        self.assertFalse((self.root / 'baseline.json').exists())

    def test_healthy_first_preview_does_not_claim_written(self):
        with mock.patch.object(handshake, 'probe_one', return_value={'state': 'ok'}):
            rc, result = self.handshake_main({'healthy': {'command': 'fixture'}})
        self.assertEqual(rc, 0, result)
        self.assertEqual(result['verdict'], 'BASELINE_PREVIEW')

    def test_bad_server_entry_cannot_disappear_from_report(self):
        rc, result = self.handshake_main({'broken': []})
        self.assertNotEqual(rc, 0, result)
        self.assertIn('broken', result['servers'])
        self.assertEqual(result['servers']['broken']['state'], 'unreachable')

    def test_doctor_rejects_invalid_initialize_and_tools_shape(self):
        valid_init = {'jsonrpc': '2.0', 'id': 1, 'result': {
            'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}},
            'serverInfo': {'name': 'fixture', 'version': '1'}}}
        for init, listed in ((None, {'result': {'tools': []}}),
                             (valid_init, {'jsonrpc': '2.0', 'id': 2, 'result': {}})):
            with self.subTest(init=init), mock.patch.object(doctor, '_port_open', return_value=True):
                replies = iter([(200, {'Content-Type': 'application/json'}, json.dumps(init)),
                                (202, {}, ''),
                                (200, {'Content-Type': 'application/json'}, json.dumps(listed))])
                with mock.patch.object(doctor, '_post', side_effect=lambda *a, **k: next(replies)):
                    self.assertFalse(doctor.probe_http({'url': 'http://127.0.0.1/mcp'})['ok'])

    def test_corrupt_existing_baseline_is_preserved(self):
        config = self.root / 'mcp.json'
        config.write_text('{"mcpServers":{"fixture":{"command":"fixture"}}}', encoding='utf-8')
        baseline = self.root / 'baseline.json'
        baseline.write_bytes(b'{existing broken user data')
        with mock.patch.object(handshake, 'probe_one', return_value={'state': 'ok'}), redirect_stdout(io.StringIO()):
            rc = handshake.main(['--mcp-json', str(config), '--out', str(baseline), '--json'])
        self.assertNotEqual(rc, 0)
        self.assertEqual(baseline.read_bytes(), b'{existing broken user data')

    def test_filtered_handshake_preserves_unselected_baseline_servers(self):
        config = self.root / 'mcp.json'
        config.write_text(json.dumps({'mcpServers': {
            'selected': {'command': 'fixture'}, 'other': {'command': 'fixture'}}}), encoding='utf-8')
        baseline = self.root / 'baseline.json'
        before = {'state': 'ok', 'serverInfo': {'version': '1'}, 'toolsCount': 2, 'codeHash': 'fixture'}
        baseline.write_text(json.dumps({'user': {'keep': True}, 'mcp_handshake': {
            'servers': {'selected': before, 'other': before}}}), encoding='utf-8')
        with mock.patch.object(handshake, 'probe_one', return_value=before), redirect_stdout(io.StringIO()):
            rc = handshake.main(['--mcp-json', str(config), '--out', str(baseline), '--only', 'selected', '--json'])
        self.assertEqual(rc, 0)
        saved = json.loads(baseline.read_text(encoding='utf-8'))
        self.assertEqual(saved['mcp_handshake']['servers']['other'], before)
        self.assertEqual(saved['user'], {'keep': True})

    def test_doctor_empty_mapping_is_not_a_server_named_mcpservers(self):
        config = self.root / 'empty.json'
        config.write_text('\ufeff{"mcpServers": {}}', encoding='utf-8')
        self.assertEqual(doctor._load_servers(config), {})

    def test_doctor_bad_url_is_reported_in_session_and_fix_modes(self):
        config = self.root / 'bad-url.json'
        config.write_text('{"mcpServers":{"x64dbg":{"url":"http://localhost:bad/mcp"}}}', encoding='utf-8')
        for flags in (['--session'], ['--fix']):
            output = io.StringIO()
            with self.subTest(flags=flags), \
                    mock.patch.object(sys, 'argv', ['doctor', '--file', str(config), '--json', *flags]), \
                    mock.patch.object(doctor.subprocess, 'run') as run, redirect_stdout(output):
                result = doctor.main()
            payload = json.loads(output.getvalue())
            self.assertIsInstance(payload, dict)
            if '--session' in flags:
                self.assertEqual(payload['servers'][0]['status'], 'config_error')
            else:
                self.assertEqual(result, 1)
            run.assert_not_called()

    def test_remote_service_never_uses_local_pid_or_local_autostart(self):
        cfg = {'url': 'https://remote.invalid:8080/mcp'}
        with mock.patch.object(doctor, '_port_open', return_value=True), \
                mock.patch.object(doctor, '_listening_pid', return_value=42) as pid, \
                mock.patch.object(doctor, '_runtime_tools', return_value={'x64dbg'}), \
                mock.patch.object(doctor.subprocess, 'run') as run:
            row = doctor._session_judge('x64dbg', cfg, time.time())
            fixed = doctor._try_fix('x64dbg', cfg)
        pid.assert_not_called()
        run.assert_not_called()
        self.assertEqual(row['status'], 'registration_unverified')
        self.assertFalse(fixed['attempted'])

    def test_doctor_reprobes_stdio_after_fix(self):
        config = self.root / 'fix-stdio.json'
        config.write_text('{"mcpServers":{"fixture":{"command":"fixture"}}}', encoding='utf-8')
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', ['doctor', '--file', str(config), '--fix', '--json']), \
                mock.patch.object(doctor, 'probe_stdio', side_effect=[
                    {'ok': False, 'stage': 'handshake', 'error': 'offline'},
                    {'ok': True, 'stage': 'tools', 'tools': 2}]) as probe, \
                mock.patch.object(doctor, '_try_fix', return_value={'status': 'READY'}), redirect_stdout(output):
            rc = doctor.main()
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(rc, 0, output.getvalue())
        self.assertEqual(json.loads(output.getvalue())['servers'][0]['tools'], 2)

    def test_nonzero_launcher_result_does_not_claim_fix_success(self):
        with mock.patch.object(doctor, '_runtime_tools', return_value={'fixture'}), \
                mock.patch.object(doctor.subprocess, 'run', return_value=subprocess.CompletedProcess(
                    [], 7, '{"status":"READY"}', 'fixture failed')):
            result = doctor._try_fix('fixture')
        self.assertEqual(result['status'], 'FAILED')
        self.assertEqual(result['returncode'], 7)

    def test_doctor_disabled_server_supports_text_output_without_probing(self):
        config = self.root / 'disabled.json'
        config.write_text('{"mcpServers":{"disabled":{"enabled":false}}}', encoding='utf-8')
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', ['doctor', '--file', str(config)]), \
                mock.patch.object(doctor, 'probe_stdio') as probe, redirect_stdout(output):
            self.assertEqual(doctor.main(), 0)
        probe.assert_not_called()
        self.assertIn('disabled', output.getvalue())

    def test_baseline_offline_interval_does_not_erase_last_known_identity(self):
        config = self.root / 'mcp.json'
        config.write_text('{"mcpServers":{"fixture":{"command":"fixture"}}}', encoding='utf-8')
        baseline = self.root / 'baseline.json'
        args = ['--mcp-json', str(config), '--out', str(baseline), '--json']
        good = {'state': 'ok', 'serverInfo': {'version': '1'}, 'toolsCount': 2, 'codeHash': 'one'}
        for observation, expected in ((good, 0), ({'state': 'unreachable', 'reason': 'offline'}, 2),
                                      ({**good, 'codeHash': 'two'}, 1)):
            with mock.patch.object(handshake, 'probe_one', return_value=observation), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(handshake.main(args), expected)

    def test_invalid_baseline_record_is_reported_without_probe_or_overwrite(self):
        config = self.root / 'mcp.json'
        config.write_text('{"mcpServers":{"fixture":{"command":"fixture"}}}', encoding='utf-8')
        baseline = self.root / 'baseline.json'
        before = b'{"mcp_handshake":{"servers":{"fixture":[]}}}'
        baseline.write_bytes(before)
        with mock.patch.object(handshake, 'probe_one') as probe, redirect_stdout(io.StringIO()):
            rc = handshake.main(['--mcp-json', str(config), '--out', str(baseline), '--json'])
        self.assertEqual(rc, 1)
        self.assertEqual(baseline.read_bytes(), before)
        probe.assert_not_called()

    def test_explicit_ida_server_must_exist_before_launch(self):
        with mock.patch.dict('os.environ', {'SEEP_IDA_PYTHON': sys.executable,
                                           'SEEP_IDA_MCP_SERVER': str(self.root / 'missing.py')}):
            with self.assertRaises(SystemExit) as failed:
                launcher.resolve_ida()
        self.assertEqual(failed.exception.code, 2)

    def test_identity_directory_discovery_never_executes_target_binary(self):
        with mock.patch.dict('os.environ', {'SEEP_LOCAL_STATE_DIR': str(self.root)}), \
                mock.patch.object(handshake, '_env_dirs', return_value=[]), \
                mock.patch.object(handshake.shutil, 'which', return_value=None), \
                mock.patch.object(handshake.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'')) as run:
            handshake.server_dirs('fixture-not-installed')
        self.assertNotIn(['fixture-not-installed.exe'], [c.args[0] for c in run.call_args_list])

    def test_agent_root_env_selects_mcp_json_without_using_user_home(self):
        with mock.patch.dict('os.environ', {'PI_CODING_AGENT_DIR': str(self.root / 'agent')}):
            self.assertEqual(Path(handshake.agent_mcp_json()),
                             self.root / 'agent' / 'mcp.json')
            self.assertEqual(Path(doctor.default_mcp_path()),
                             self.root / 'agent' / 'mcp.json')

    def test_unknown_transport_fails_closed_without_starting_stdio(self):
        config = self.root / 'bad-transport.json'
        config.write_text(json.dumps({'mcpServers': {
            'typo': {'transport': 'htp', 'command': 'must-not-run'}}}), encoding='utf-8')
        output = io.StringIO()
        with mock.patch.object(handshake, 'handshake_stdio') as stdio, redirect_stdout(output):
            rc = handshake.main(['--mcp-json', str(config), '--out',
                                 str(self.root / 'baseline.json'), '--json', '--no-write'])
        result = json.loads(output.getvalue())
        self.assertEqual(rc, 2, result)
        self.assertEqual(result['servers']['typo']['transport'], 'invalid')
        self.assertIn('未知 MCP transport', result['servers']['typo']['reason'])
        stdio.assert_not_called()

    def test_doctor_unknown_transport_fails_closed_without_starting_stdio(self):
        config = self.root / 'doctor-bad-transport.json'
        config.write_text(json.dumps({'mcpServers': {
            'typo': {'transport': 'htp', 'command': 'must-not-run'}}}), encoding='utf-8')
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', ['doctor', '--file', str(config), '--json']), \
                mock.patch.object(doctor, 'probe_stdio') as stdio, redirect_stdout(output):
            rc = doctor.main()
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, 1)
        self.assertEqual(payload['servers'][0]['stage'], 'config')
        self.assertIn('拒绝猜测', payload['servers'][0]['detail'])
        stdio.assert_not_called()

    def test_doctor_stdio_quick_probe_does_not_raise_unbound_local(self):
        result = doctor.probe_stdio({'command': sys.executable}, True)
        self.assertFalse(result['ok'])
        self.assertEqual(result['stage'], 'offline')

    def test_doctor_http_uses_one_handshake_deadline(self):
        class SlowHandler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *args):
                pass

            def do_POST(self):
                time.sleep(0.08)
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                body = json.dumps({
                    'jsonrpc': '2.0', 'id': payload.get('id'),
                    'result': {
                        'protocolVersion': '2025-06-18',
                        'capabilities': {'tools': {}},
                        'serverInfo': {'name': 'slow', 'version': '1'},
                        'tools': [],
                    } if payload.get('method') == 'tools/list' else {
                        'protocolVersion': '2025-06-18',
                        'capabilities': {'tools': {}},
                        'serverInfo': {'name': 'slow', 'version': '1'},
                    },
                }).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), SlowHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        started = time.monotonic()
        result = doctor.probe_http({
            'url': f'http://127.0.0.1:{server.server_port}/mcp', 'timeout': 0.15})
        elapsed = time.monotonic() - started
        self.assertFalse(result['ok'], result)
        self.assertLess(elapsed, 0.55, result)

    def test_stdio_identity_resolves_script_against_server_cwd(self):
        target = self.root / 'server.py'
        target.write_text('# fixture', encoding='utf-8')
        self.assertEqual(Path(handshake._stdio_target({'command': sys.executable,
                         'args': ['server.py'], 'cwd': str(self.root)})), target)

    def start_server(self, sse=False):
        seen = []
        release = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            protocol_version = 'HTTP/1.1'

            def log_message(self, *args):
                pass

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                method = payload['method']
                seen.append((payload, dict(self.headers)))
                if self.headers.get('Authorization') != 'Bearer fixture-test-token':
                    self.reply(401, {'error': 'auth'})
                    return
                if method == 'initialize':
                    self.reply(200, {'jsonrpc': '2.0', 'id': payload['id'], 'result': {
                        'protocolVersion': '2025-06-18', 'capabilities': {'tools': {}},
                        'serverInfo': {'name': 'fixture', 'version': '1'}}},
                        {'mcp-session-id': 'fixture-session'})
                    return
                if self.headers.get('Mcp-Session-Id') != 'fixture-session' or \
                        self.headers.get('MCP-Protocol-Version') != '2025-06-18':
                    self.reply(400, {'error': 'missing negotiated session or version'})
                    return
                if method == 'notifications/initialized':
                    self.reply(202, None)
                    return
                page = payload.get('params', {}).get('cursor')
                result = {'tools': [{'name': 'second' if page else 'first',
                                     'inputSchema': {'type': 'object'}}]}
                if not page:
                    result['nextCursor'] = 'page-two'
                self.reply(200, {'jsonrpc': '2.0', 'id': payload['id'], 'result': result})

            def reply(self, status, payload, headers=None):
                body = json.dumps(payload).encode() if payload is not None else b''
                self.send_response(status)
                self.send_header('Content-Type', 'text/event-stream' if sse and body else 'application/json')
                if not (sse and body):
                    self.send_header('Content-Length', str(len(body)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                if sse and body:
                    self.wfile.write(b'data: {"jsonrpc":"2.0","method":"notifications/progress"}\n\n')
                    self.wfile.write(b'data: ' + body + b'\n\n')
                    self.wfile.flush()
                    release.wait(1)
                    self.close_connection = True
                else:
                    self.wfile.write(body)

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(release.set)
        return f'http://127.0.0.1:{server.server_port}/mcp', seen

    def test_http_handshake_honors_headers_session_version_and_pagination(self):
        url, seen = self.start_server()
        cfg = {'url': url, 'headers': {'Authorization': 'Bearer fixture-test-token'}}
        result = handshake.probe_one('fixture', cfg)
        self.assertEqual(result['state'], 'ok', result)
        self.assertEqual(result['toolsCount'], 2, result)
        self.assertEqual(result['toolNames'], ['first', 'second'])
        self.assertEqual([r[0]['method'] for r in seen],
                         ['initialize', 'notifications/initialized', 'tools/list', 'tools/list'])

    def test_http_doctor_honors_headers_session_version_and_pagination(self):
        url, seen = self.start_server()
        result = doctor.probe_http({'url': url, 'headers': {'Authorization': 'Bearer fixture-test-token'}})
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['tools'], 2)

    def test_acquire_uses_initialized_session_and_all_tool_pages(self):
        url, seen = self.start_server()
        result = acquire.mcp_probe(url, 'Authorization', 'fixture-test-token')
        self.assertTrue(result['ok'], result)
        self.assertEqual(result['tools'], 2)
        self.assertFalse(result['session_verified'])

    def test_acquire_launcher_error_cannot_be_hidden_by_ready_text(self):
        with mock.patch.object(acquire.subprocess, 'run', return_value=subprocess.CompletedProcess(
                [], 7, b'{"status":"READY"}', b'fixture failed')):
            self.assertFalse(acquire.l1_start('fixture')['ok'])

    def test_sse_response_does_not_wait_for_persistent_stream_to_close(self):
        url, _ = self.start_server(sse=True)
        cfg = {'url': url, 'headers': {'Authorization': 'Bearer fixture-test-token'}}
        started = time.monotonic()
        checked = doctor.probe_http(cfg)
        self.assertTrue(checked['ok'], checked)
        self.assertLess(time.monotonic() - started, 0.7)
        started = time.monotonic()
        checked = handshake.probe_one('fixture', cfg)
        self.assertEqual(checked['state'], 'ok', checked)
        self.assertLess(time.monotonic() - started, 0.7)
        with mock.patch.object(bridge, 'UPSTREAM', url), mock.patch.object(
                bridge, '_auth_token', return_value='fixture-test-token'):
            started = time.monotonic()
            checked = bridge.forward({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}})
            self.assertIn('result', checked)
            self.assertLess(time.monotonic() - started, 0.7)

    def test_http_response_id_boolean_cannot_match_numeric_request(self):
        with self.assertRaises(ValueError):
            doctor.mcp_http.parse_rpc('{"jsonrpc":"2.0","id":true,"result":{}}',
                                      'application/json', 1)

    def test_bridge_keeps_negotiated_session_and_handles_notification_202(self):
        url, seen = self.start_server()
        with mock.patch.object(bridge, 'UPSTREAM', url), mock.patch.object(
                bridge, '_auth_token', return_value='fixture-test-token'):
            init = bridge.forward({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                'protocolVersion': '2025-06-18', 'capabilities': {},
                'clientInfo': {'name': 'fixture-client', 'version': '1'}}})
            self.assertIn('result', init)
            notified = bridge.forward({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
            self.assertIsNone(notified)
            listed = bridge.forward({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
            self.assertIn('result', listed, listed)

    def test_bridge_failed_initialize_must_not_become_success(self):
        incoming = io.StringIO(json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                                          'params': {'protocolVersion': '2025-06-18'}}) + '\n')
        output = io.StringIO()
        failure = {'jsonrpc': '2.0', 'id': 1, 'error': {'code': -32000, 'message': 'fixture auth failed'}}
        with mock.patch.object(bridge, 'ensure_upstream', return_value={'status': 'ready'}), \
                mock.patch.object(bridge, 'forward', return_value=failure), \
                mock.patch.object(sys, 'stdin', incoming), redirect_stdout(output):
            bridge.serve(False)
        response = json.loads(output.getvalue())
        self.assertIn('error', response)
        self.assertNotIn('result', response)

    def test_bridge_retries_initialize_after_initial_unavailability(self):
        incoming = io.StringIO(json.dumps({'jsonrpc': '2.0', 'id': 8, 'method': 'initialize',
                                          'params': {'protocolVersion': '2025-06-18'}}) + '\n')
        output = io.StringIO()
        reply = {'jsonrpc': '2.0', 'id': 8, 'result': {'protocolVersion': '2025-06-18',
                 'serverInfo': {'name': 'fixture', 'version': '1'}, 'capabilities': {'tools': {}}}}
        with mock.patch.object(bridge, 'ensure_upstream', side_effect=[
                {'status': 'launch_failed'}, {'status': 'ready'}]), \
                mock.patch.object(bridge, 'forward', return_value=reply) as forward, \
                mock.patch.object(sys, 'stdin', incoming), redirect_stdout(output):
            bridge.serve(False)
        forward.assert_called_once()
        self.assertIn('result', json.loads(output.getvalue()))

    def test_bridge_refuses_call_until_initialization_succeeds(self):
        incoming = io.StringIO(json.dumps({'jsonrpc': '2.0', 'id': 9, 'method': 'tools/call',
                                          'params': {'name': 'fixture'}}) + '\n')
        output = io.StringIO()
        with mock.patch.object(bridge, 'ensure_upstream', return_value={'status': 'ready'}), \
                mock.patch.object(bridge, 'forward', return_value={'jsonrpc': '2.0', 'id': 9, 'result': {}}) as forward, \
                mock.patch.object(sys, 'stdin', incoming), redirect_stdout(output):
            bridge.serve(False)
        forward.assert_not_called()
        self.assertIn('error', json.loads(output.getvalue()))

    def test_bridge_does_not_advertise_unimplemented_bidirectional_capabilities(self):
        init = {'jsonrpc': '2.0', 'id': 1, 'result': {'protocolVersion': '2025-06-18',
                'serverInfo': {'name': 'fixture', 'version': '1'}, 'capabilities': {
                    'tools': {'listChanged': True}, 'resources': {'subscribe': True, 'listChanged': True},
                    'logging': {}, 'experimental': {'fixture': {}}}}}
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {
                   'protocolVersion': '2025-06-18', 'capabilities': {'sampling': {}, 'roots': {}}}}
        before = json.loads(json.dumps(request))
        with mock.patch.object(bridge, '_post', return_value=(200, 'application/json',
                              {'raw': json.dumps(init).encode()})) as post:
            result = bridge.forward(request)
        self.assertEqual(request, before)
        self.assertEqual(post.call_args.args[0]['params']['capabilities'], {})
        caps = result['result']['capabilities']
        self.assertFalse(caps['tools'].get('listChanged', False))
        self.assertFalse(caps['resources'].get('subscribe', False))
        self.assertNotIn('logging', caps)
        self.assertNotIn('experimental', caps)

    def test_bridge_sse_selects_response_id_after_progress_notification(self):
        reply = {'jsonrpc': '2.0', 'id': 9, 'result': {'tools': []}}
        raw = ('data: ' + json.dumps(reply) + '\n\n' +
               'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n').encode()
        with mock.patch.object(bridge, '_post', return_value=(200, 'text/event-stream', {'raw': raw})):
            result = bridge.forward({'jsonrpc': '2.0', 'id': 9, 'method': 'tools/list'})
        self.assertEqual(result, reply)

    def test_stdio_health_runs_real_handshake_and_reads_all_pages(self):
        server = self.root / 'stdio_fixture.py'
        server.write_text('''import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg["method"]
    if method == "initialize":
        result = {"protocolVersion": msg["params"]["protocolVersion"],
                  "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fixture", "version": "1"}}
    elif method == "tools/list":
        page = msg.get("params", {}).get("cursor")
        result = {"tools": [{"name": "second" if page else "first",
                            "inputSchema": {"type": "object"}}]}
        if not page:
            result["nextCursor"] = "second-page"
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
''', encoding='utf-8')
        cfg = {'command': sys.executable, 'args': [str(server)]}
        result = handshake.probe_one('fixture', cfg)
        self.assertEqual(result['state'], 'ok', result)
        self.assertEqual(result['toolsCount'], 2, result)
        checked = doctor.probe_stdio(cfg)
        self.assertTrue(checked['ok'], checked)
        self.assertEqual(checked['tools'], 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
