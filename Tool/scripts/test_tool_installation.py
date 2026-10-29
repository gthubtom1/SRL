"""Isolated installation, discovery and execution checks; no external downloads."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import importlib.util
import json
import os
import queue
from concurrent.futures import ThreadPoolExecutor
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import threading
import unittest
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import tool_autodiscover as discovery
from lib import tool_identity


def archive(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as zipped:
        for name, value in files.items():
            zipped.writestr(name, value)
    return out.getvalue()


class AcquisitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('acquire_review', Path(__file__).with_name('tool-acquire.py'))
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_unprobed_executable_cannot_claim_usable(self):
        with mock.patch.object(self.module, 'l0', return_value={
                'level': 'L0', 'kind': 'cli', 'ok': True, 'exe': sys.executable}), \
                mock.patch.object(tool_identity, 'probe', return_value={'ok': None, 'verified': False}):
            result = self.module.acquire('fixture', allow_start=False)
        self.assertEqual(result['verdict'], 'FOUND_NO_VERIFY')
        self.assertFalse(result['runtime_verified'])

    def test_known_identity_failure_is_visible_to_api_callers(self):
        with mock.patch.object(self.module, 'l0', return_value={
                'level': 'L0', 'kind': 'cli', 'ok': True, 'exe': sys.executable}), \
                mock.patch.object(tool_identity, 'probe', return_value={'ok': False, 'why': 'wrong tool'}):
            result = self.module.acquire('fixture', allow_start=False)
        self.assertEqual(result['verdict'], 'USABLE_BUT_BROKEN')

    def test_existing_protocol_connection_does_not_need_executable_identity(self):
        with mock.patch.object(self.module, 'l0', return_value={
                'level': 'L0', 'kind': 'mcp', 'ok': True, 'tools': 2}), \
                mock.patch.object(tool_identity, 'probe') as probe:
            result = self.module.acquire('fixture', allow_start=False)
        self.assertEqual(result['verdict'], 'USABLE')
        self.assertFalse(result['session_verified'])
        probe.assert_not_called()

    def test_authorized_install_is_attempted_and_rechecked(self):
        states = [{'level': 'L0', 'kind': 'cli', 'ok': False, 'detail': 'not found'},
                  {'level': 'L0', 'kind': 'cli', 'ok': True, 'exe': sys.executable}]
        with mock.patch.object(self.module, 'l0', side_effect=states), \
                mock.patch.object(self.module, 'l3_install', return_value={'level': 'L3', 'ok': False, 'auto': True, 'plan': {}}), \
                mock.patch.object(discovery, 'propose_install', return_value={'success': True}) as install, \
                mock.patch.object(tool_identity, 'probe', return_value={'ok': True, 'verified': True}):
            result = self.module.acquire('fixture', allow_start=False, allow_install=True)
        install.assert_called_once_with('fixture', execute=True)
        self.assertEqual(result['verdict'], 'USABLE')

    def test_failed_automatic_path_does_not_force_a_user_choice(self):
        with mock.patch.object(self.module, 'l0', return_value={
                'level': 'L0', 'kind': 'cli', 'ok': False, 'detail': 'missing'}), \
                mock.patch.object(self.module, 'l1_start', return_value={'level': 'L1', 'ok': False, 'detail': 'failed'}), \
                mock.patch.object(self.module, 'l3_install', return_value={'level': 'L3', 'ok': False, 'auto': True, 'plan': {}}):
            result = self.module.acquire('fixture', allow_start=True)
        self.assertNotEqual(result['verdict'], 'NEED_USER')
        self.assertFalse(any(step.get('ask') for step in result['steps']))

    def test_malformed_tool_catalog_returns_structured_failure(self):
        for document in ({'tools': []}, {'tools': {'fixture': 'bad'}},
                         {'tools': {'fixture': {'modes': ['bad']}}}):
            with self.subTest(document=document), mock.patch.object(self.module, 'load_json', return_value=document):
                result = self.module.acquire('fixture', allow_start=False)
            self.assertEqual(result['verdict'], 'CONFIG_ERROR')

    def test_importable_library_does_not_require_an_executable_or_reinstall(self):
        with tempfile.TemporaryDirectory(prefix='seep-acquire-library-') as td, \
                mock.patch.dict(os.environ, {'PYTHONPATH': td}), \
                mock.patch.object(discovery, 'propose_install') as install:
            (Path(td) / 'pefile.py').write_text('VALUE=42\n', encoding='utf-8')
            result = self.module.acquire('pefile', allow_start=False, allow_install=True)
        self.assertEqual(result['verdict'], 'USABLE')
        self.assertTrue(result['import_verified'])
        self.assertEqual(result['module'], 'pefile')
        self.assertFalse(result['runtime_verified'])
        install.assert_not_called()

    def test_list_json_is_one_machine_readable_document(self):
        result = subprocess.run(
            [sys.executable, '-B', '-X', 'utf8',
             str(Path(__file__).with_name('tool-acquire.py')), '--list', '--json'],
            cwd=Path(__file__).resolve().parents[2],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertIs(payload['ok'], True)
        self.assertEqual(payload['schema'], 'seep.tool-catalog/1')
        self.assertEqual(payload['tool_count'], len(payload['tools']))
        self.assertGreater(payload['tool_count'], 0)
        self.assertFalse(result.stderr, result.stderr)

    def test_list_json_failure_keeps_stdout_parseable_and_diagnostic_on_stderr(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(self.module, 'tool_catalog',
                               side_effect=ValueError('fixture catalog error')), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            rc = self.module.list_tools(json_output=True)
        self.assertEqual(rc, 2)
        payload = json.loads(stdout.getvalue())
        self.assertIs(payload['ok'], False)
        self.assertEqual(payload['error'], 'fixture catalog error')
        self.assertIn('fixture catalog error', stderr.getvalue())

    def test_mcp_registration_uses_selected_agent_root_and_no_repo_fallback(self):
        with tempfile.TemporaryDirectory(prefix='seep-agent-root-registration-') as td:
            base = Path(td)
            repo = base / 'repo'
            tool_dir = repo / 'Tool'
            tool_dir.mkdir(parents=True)
            root_config = repo / '.mcp.json'
            root_bytes = b'{"mcpServers":{"user":{"command":"fixture"}}}\n'
            root_config.write_bytes(root_bytes)
            agent = base / 'selected-agent'
            entry = {'command': sys.executable, 'args': ['-c', 'pass']}
            env = {'PI_CODING_AGENT_DIR': str(agent)}
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(discovery, '_TOOL_DIR', str(tool_dir)), \
                    mock.patch.object(discovery, '_mcp_entry_for', return_value=entry):
                self.assertEqual(Path(discovery._agent_mcp_json_path()),
                                 agent / 'mcp.json')
                result = discovery.register_mcp('fixture', apply=True)
            self.assertTrue(result['registered'], result)
            self.assertEqual(result['targets'], [str(agent / 'mcp.json')])
            saved = json.loads((agent / 'mcp.json').read_text(encoding='utf-8'))
            self.assertEqual(saved['mcpServers']['fixture'], entry)
            self.assertEqual(root_config.read_bytes(), root_bytes)


@contextmanager
def endpoint_fixture(transport):
    messages, stopped = queue.Queue(), threading.Event()
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.end_headers()
            try:
                self.wfile.write(b'event: endpoint\ndata: /messages?session_id=fixture\n\n')
                self.wfile.flush()
                while not stopped.is_set():
                    try:
                        event = messages.get(timeout=.1)
                    except queue.Empty:
                        continue
                    self.wfile.write(b'event: message\ndata: ' + event + b'\n\n')
                    self.wfile.flush()
            except (ConnectionError, OSError):
                pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            requests.append((payload, dict(self.headers)))
            if transport == 'html':
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'<html>unrelated service</html>')
                return
            method = payload['method']
            if method == 'initialize':
                result = {'protocolVersion': payload['params']['protocolVersion'],
                          'serverInfo': {'name': 'fixture', 'version': '1'}, 'capabilities': {'tools': {}}}
            elif method == 'tools/list':
                result = {'tools': [{'name': 'fixture_' + ('second' if payload.get('params', {}).get('cursor') else 'first'),
                                     'inputSchema': {'type': 'object'}}]}
                if not payload.get('params', {}).get('cursor'):
                    result['nextCursor'] = 'next'
            elif method == 'notifications/initialized':
                self.send_response(202)
                self.end_headers()
                return
            else:
                self.send_response(400)
                self.end_headers()
                return
            raw = json.dumps({'jsonrpc': '2.0', 'id': payload['id'], 'result': result}).encode()
            self.send_response(202 if transport == 'sse' else 200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Mcp-Session-Id', 'fixture-session')
            self.end_headers()
            if transport == 'sse':
                messages.put(raw)
            else:
                self.wfile.write(raw)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, requests
    finally:
        stopped.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class PortableInstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='seep-install-tests-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name) / 'tools'
        self.base.mkdir()
        patcher = mock.patch.object(discovery, '_install_base', return_value=str(self.base))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch.object(discovery, '_detect_local_proxy_port', return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)

    def install(self, files, target='fixture', verify='tool.exe'):
        opener = mock.Mock()
        opener.open.side_effect = lambda *_a, **_k: io.BytesIO(archive(files))
        with mock.patch('urllib.request.build_opener', return_value=opener):
            return discovery._download_and_extract_portable(['https://fixture.invalid/tool.zip'], target, verify)

    def test_missing_expected_executable_does_not_succeed_or_replace_old_tool(self):
        old = self.base / 'fixture'
        old.mkdir()
        (old / 'tool.exe').write_bytes(b'previous tool')
        result = self.install({'readme.txt': 'x' * 1500})
        self.assertFalse(result['success'], result)
        self.assertEqual((old / 'tool.exe').read_bytes(), b'previous tool')
        self.assertFalse((old / 'readme.txt').exists())

    def test_outside_install_target_is_rejected_before_any_write(self):
        result = self.install({'tool.exe': 'x' * 1500}, target='../outside')
        self.assertFalse(result['success'], result)
        self.assertFalse((self.base.parent / 'outside').exists())

    def test_unsafe_archive_is_rejected_without_installing_partial_contents(self):
        result = self.install({'tool.exe': 'x' * 1500, '../outside.txt': 'bad'})
        self.assertFalse(result['success'], result)
        self.assertFalse((self.base / 'fixture').exists())
        self.assertFalse((self.base / 'outside.txt').exists())

    def test_failed_promotion_restores_previous_installation(self):
        old = self.base / 'fixture'
        old.mkdir()
        (old / 'tool.exe').write_bytes(b'previous tool')
        real_replace = discovery.os.replace

        def fail_new_directory(source, destination):
            if Path(destination) == old and Path(source).name == 'unpacked':
                raise OSError('fixture promotion failed')
            return real_replace(source, destination)

        with mock.patch.object(discovery.os, 'replace', side_effect=fail_new_directory):
            result = self.install({'tool.exe': 'x' * 1500})
        self.assertFalse(result['success'], result)
        self.assertEqual((old / 'tool.exe').read_bytes(), b'previous tool')

    def test_success_returns_existing_executable_and_download_fingerprint(self):
        result = self.install({'release/tool.exe': 'x' * 1500})
        self.assertTrue(result['success'], result)
        self.assertTrue(Path(result['exe']).is_file())
        self.assertEqual(Path(result['exe']).read_text(), 'x' * 1500)
        self.assertEqual(len(result['sha256']), 64)
        self.assertEqual(result['source'], 'https://fixture.invalid/tool.zip')
        self.assertFalse(any(p.suffix == '.zip' for p in self.base.rglob('*')))

    def test_concurrent_reinstall_serializes_download_and_promotion(self):
        active = maximum = 0
        counter = threading.Lock()
        content = archive({'tool.exe': 'x' * 1500})
        class Download(io.BytesIO):
            def __enter__(stream):
                nonlocal active, maximum
                with counter:
                    active += 1
                    maximum = max(maximum, active)
                time.sleep(.03)
                return super().__enter__()
            def __exit__(stream, *args):
                nonlocal active
                with counter:
                    active -= 1
                return super().__exit__(*args)
        opener = mock.Mock()
        opener.open.side_effect = lambda *_a, **_k: Download(content)
        with mock.patch('urllib.request.build_opener', return_value=opener), ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: discovery._download_and_extract_portable(
                ['https://fixture.invalid/tool.zip'], 'fixture', 'tool.exe'), range(2)))
        self.assertTrue(all(r['success'] for r in results), results)
        self.assertEqual(maximum, 1)
        self.assertTrue(Path(results[1]['exe']).is_file())


class InstallerFailureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='seep-installer-failure-')
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        for field, value in (('LOCAL_STATE_DIR', str(root)),
                             ('LOCAL_STATE_PATH', str(root / 'tools.local.json')),
                             ('_PATH_CACHE_FILE', str(root / 'tool-paths.json'))):
            patcher = mock.patch.object(discovery, field, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_malformed_install_catalog_fails_without_starting_an_installer(self):
        cases = [[], {'installable': []},
                 {'auto_allow_methods': 'pip', 'installable': {'fixture': {'method': 'pip', 'pkg': 'fixture'}}},
                 {'auto_allow_methods': [True], 'installable': {'fixture': {'method': 'pip', 'pkg': 'fixture'}}},
                 {'installable': {'fixture': {'method': 'pip', 'pkg': ['fixture']}}},
                 {'installable': {'fixture': {'methods': [{'type': 'pip', 'pkg': 'fixture', 'platforms': 'windows'}]}}}]
        for config in cases:
            with self.subTest(config=config), mock.patch.object(discovery, '_install_table', return_value=config), \
                    mock.patch.object(discovery, '_run_tool_process') as run:
                result = discovery.propose_install('fixture', execute=True)
            self.assertFalse(result['has_plan'], result)
            self.assertFalse(result['success'], result)
            run.assert_not_called()

    def test_wrong_platform_method_is_not_an_install_fallback(self):
        config = {'auto_allow_methods': ['portable_zip'], 'installable': {'fixture': {'methods': [
            {'type': 'portable_zip', 'platforms': ['windows'], 'urls': ['https://fixture.invalid/win.zip'],
             'target_sub': 'fixture', 'verify_exe': 'tool.exe'}]}}}
        with mock.patch.object(discovery, '_install_table', return_value=config), \
                mock.patch.object(discovery.sys, 'platform', 'linux'), \
                mock.patch.object(discovery, '_download_and_extract_portable') as download:
            result = discovery.propose_install('fixture', execute=True)
        download.assert_not_called()
        self.assertFalse(result['has_plan'], result)

    def test_disallowed_primary_does_not_hide_an_allowed_fallback(self):
        config = {'auto_allow_methods': ['pip'], 'installable': {'fixture': {'methods': [
            {'type': 'manual', 'url': 'https://fixture.invalid'}, {'type': 'pip', 'pkg': 'fixture'}]}}}
        with mock.patch.object(discovery, '_install_table', return_value=config), \
                mock.patch.object(discovery, '_run_tool_process', return_value=subprocess.CompletedProcess([], 0, '', '')) as run, \
                mock.patch.object(discovery, 'discover', return_value={'available': True}):
            result = discovery.propose_install('fixture', execute=True)
        self.assertTrue(result['success'], result)
        self.assertEqual(run.call_count, 1)

    def test_go_install_rechecks_persisted_custom_gobin(self):
        with tempfile.TemporaryDirectory(prefix='seep-go-install-') as td:
            base = Path(td)
            binary = base / ('fixture.exe' if os.name == 'nt' else 'fixture')
            binary.touch()
            config = {'auto_allow_methods': ['go'], 'installable': {'fixture': {
                'method': 'go', 'pkg': 'example.invalid/fixture@v1'}}}
            results = [subprocess.CompletedProcess([], 0, '', ''),
                       subprocess.CompletedProcess([], 0, json.dumps({'GOBIN': td, 'GOPATH': ''}), '')]
            with mock.patch.object(discovery, '_install_table', return_value=config), \
                    mock.patch.object(discovery, '_PATH_CACHE_FILE', str(base / 'cache/tool-paths.json')), \
                    mock.patch.object(discovery, '_capabilities_table', return_value={'tools': {'fixture': {
                        'exe_candidates': ['fixture']}}}), \
                    mock.patch.object(discovery, '_run_tool_process', side_effect=results):
                result = discovery.propose_install('fixture', execute=True)
            self.assertTrue(result['success'], result)
            self.assertEqual(result['recheck']['command'], str(binary))

    def test_empty_allowlist_prevents_installation_and_empty_methods_have_no_plan(self):
        for config in ({'auto_allow_methods': [], 'installable': {'fixture': {'method': 'pip', 'pkg': 'fixture'}}},
                       {'installable': {'fixture': {'methods': []}}}):
            with self.subTest(config=config), mock.patch.object(discovery, '_install_table', return_value=config), \
                    mock.patch.object(discovery.subprocess, 'run') as run:
                result = discovery.propose_install('fixture', execute=True)
            run.assert_not_called()
            self.assertFalse(result['success'])

    def test_timeout_is_a_reported_failure(self):
        plan = {'tool_id': 'fixture', 'has_plan': True, 'auto_allowed': True,
                'method': 'pip', 'package': 'fixture-package', 'active_method': {}}
        with mock.patch.object(discovery, 'install_plan', return_value=plan), \
                mock.patch.object(discovery.subprocess, 'run', side_effect=subprocess.TimeoutExpired('pip', 600)):
            result = discovery.propose_install('fixture', execute=True)
        self.assertFalse(result['success'])
        self.assertTrue(result['error'])

    def test_fallback_must_also_be_allowlisted(self):
        config = {'auto_allow_methods': ['winget'], 'installable': {'fixture': {'methods': [
                  {'type': 'winget', 'pkg': 'fixture.package'},
                  {'type': 'portable_zip', 'urls': ['https://fixture.invalid/tool.zip'],
                   'target_sub': 'fixture', 'verify_exe': 'tool.exe'}]}}}
        with mock.patch.object(discovery, '_install_table', return_value=config), \
                mock.patch.object(discovery.shutil, 'which', return_value='fixture-winget'), \
                mock.patch.object(discovery.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'failed')), \
                mock.patch.object(discovery, 'discover', return_value={'available': False}), \
                mock.patch.object(discovery, '_download_and_extract_portable', return_value={'success': True}) as download:
            result = discovery.propose_install('fixture', execute=True)
        download.assert_not_called()
        self.assertFalse(result['success'])

    def test_success_requires_a_successful_recheck(self):
        config = {'auto_allow_methods': ['pip'], 'installable': {'fixture': {'method': 'pip', 'pkg': 'fixture'}}}
        with mock.patch.object(discovery, '_install_table', return_value=config), \
                mock.patch.object(discovery.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')), \
                mock.patch.object(discovery, 'discover', return_value={'available': False}):
            result = discovery.propose_install('fixture', execute=True)
        self.assertFalse(result['success'])
        self.assertIn('recheck', result)


class DiscoveryStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='seep-discovery-tests-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for field, value in (('LOCAL_STATE_DIR', str(self.root)),
                             ('LOCAL_STATE_PATH', str(self.root / 'tools.local.json')),
                             ('_PATH_CACHE_FILE', str(self.root / 'tool-paths.json'))):
            patcher = mock.patch.object(discovery, field, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_httpx_rejects_wrong_same_name_then_checks_next_path(self):
        first, second = self.root / 'python', self.root / 'go'
        first.mkdir()
        second.mkdir()
        name = 'httpx.exe' if os.name == 'nt' else 'httpx'
        wrong, correct = first / name, second / name
        wrong.touch()
        correct.touch()
        caps = {'tools': {'httpx': {'exe_candidates': ['httpx'], 'identityProbe': 'httpx'}}}
        with mock.patch.object(discovery, '_capabilities_table', return_value=caps), \
                mock.patch.object(discovery.os, 'get_exec_path', return_value=[str(first), str(second)]), \
                mock.patch.object(discovery.shutil, 'which', side_effect=lambda _n, path: str(Path(path) / name)), \
                mock.patch.dict(os.environ, {'SEEP_HTTPX_PATH': str(wrong)}), \
                mock.patch.object(tool_identity, 'probe', side_effect=lambda _t, p: {'ok': p == str(correct)}) as probe:
            discovery._cache_put('httpx', str(wrong), 'PATH')
            result = discovery.discover('httpx', use_registry=False)
        self.assertEqual(result['command'], str(correct))
        self.assertTrue(result['identity_verified'])
        self.assertEqual(probe.call_count, 2)

    def test_go_environment_install_directories_are_discoverable(self):
        with mock.patch.dict(os.environ, {'GOBIN': str(self.root / 'go-bin'),
                                         'GOPATH': str(self.root / 'go-one') + os.pathsep + str(self.root / 'go-two')}):
            roots = discovery.candidate_roots(include_missing=True)
        self.assertIn(str(self.root / 'go-bin'), roots)
        self.assertIn(str(self.root / 'go-one' / 'bin'), roots)
        self.assertIn(str(self.root / 'go-two' / 'bin'), roots)

    def test_concurrent_discovery_records_preserve_all_tools(self):
        def record(index):
            return discovery.record('fixture-' + str(index), {'available': True, 'command': 'fixture', 'via': 'fixture'})
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(record, range(16)))
        self.assertTrue(all(r['state_saved'] for r in results), results)
        self.assertEqual(len(discovery.load_state()['tools']), 16)

    def test_corrupt_discovery_state_is_preserved_and_save_failure_reported(self):
        path = Path(discovery.LOCAL_STATE_PATH)
        original = b'{corrupt-state'
        path.write_bytes(original)
        result = discovery.record('fixture', {'available': True, 'command': 'fixture', 'via': 'fixture'})
        self.assertFalse(result['state_saved'])
        self.assertEqual(path.read_bytes(), original)

    def test_failed_state_replacement_preserves_previous_data(self):
        first = discovery.record('first', {'available': True, 'command': 'fixture', 'via': 'fixture'})
        self.assertTrue(first['state_saved'])
        path = Path(discovery.LOCAL_STATE_PATH)
        original = path.read_bytes()
        with mock.patch.object(discovery.os, 'replace', side_effect=OSError('fixture failure')):
            result = discovery.record('second', {'available': True, 'command': 'fixture', 'via': 'fixture'})
        self.assertFalse(result['state_saved'])
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse(list(self.root.glob('.seep-state-*')))

    def test_explicit_environment_overrides_cached_executable(self):
        old, selected = self.root / 'old.exe', self.root / 'selected.exe'
        old.touch()
        selected.touch()
        discovery._cache_put('fixture', str(old), 'scan')
        with mock.patch.dict(os.environ, {'SEEP_FIXTURE_PATH': str(selected)}):
            result = discovery.discover('fixture', use_registry=False)
        self.assertEqual(result['command'], str(selected))
        self.assertEqual(result['via'], 'env')

    def test_cache_does_not_override_target_architecture(self):
        old, selected = self.root / 'x64dbg.exe', self.root / 'x32dbg.exe'
        old.touch()
        selected.touch()
        discovery._cache_put('x64dbg', str(old), 'scan', 'x64')
        with mock.patch.object(discovery, 'read_pe_machine', return_value='x86'), \
                mock.patch.object(discovery, '_layer_env', return_value=None), \
                mock.patch.object(discovery, '_layer_path', return_value={'command': str(selected), 'via': 'PATH'}):
            result = discovery.discover('x64dbg', target=str(old))
        self.assertEqual(result['command'], str(selected))

    def test_mode_candidates_resolve_headless_sibling_instead_of_gui(self):
        gui, headless = self.root / 'ida.exe', self.root / 'idat.exe'
        gui.touch()
        headless.touch()
        with mock.patch.dict(os.environ, {'SEEP_IDA_PATH': str(gui)}):
            result = discovery.discover('ida', exe_candidates=['idat.exe'])
        self.assertEqual(result['command'], str(headless))

    def test_backups_and_staging_are_not_discovered(self):
        for name in ('.seep-previous-fixture', '.seep-install-fixture'):
            folder = self.root / name
            folder.mkdir()
            (folder / 'fixture.exe').touch()
        with mock.patch.object(discovery, '_COMMON_ROOTS', [str(self.root)]):
            self.assertIsNone(discovery._layer_scan('fixture', ['fixture']))

    def test_custom_install_directory_is_a_discovery_root(self):
        with mock.patch.dict(os.environ, {'SEEP_TOOL_INSTALL_DIR': str(self.root)}):
            self.assertIn(str(self.root), discovery.candidate_roots())

    def test_filtered_candidate_does_not_hide_later_installation(self):
        wrong, good = self.root / 'python-client', self.root / 'projectdiscovery'
        for folder in (wrong, good):
            folder.mkdir()
            (folder / 'httpx.exe').touch()
        caps = {'exclude_paths': ['python-client']}
        with mock.patch.object(discovery, '_COMMON_ROOTS', [str(wrong), str(good)]):
            result = discovery._layer_common_dirs(['httpx'], caps=caps)
        self.assertEqual(result['command'], str(good / 'httpx.exe'))

    def test_corrupt_cache_is_preserved_on_write(self):
        cache = Path(discovery._PATH_CACHE_FILE)
        for raw in ('{broken', '[]', '{"tools": []}'):
            cache.write_text(raw, encoding='utf-8')
            self.assertFalse(discovery._cache_put('fixture', 'tool.exe', 'manual'))
            self.assertEqual(cache.read_text(encoding='utf-8'), raw)

    def test_concurrent_cache_writes_retain_all_entries(self):
        original_read = discovery._cache_read
        def slow_read(*args, **kwargs):
            value = original_read(*args, **kwargs)
            time.sleep(.005)
            return value
        with mock.patch.object(discovery, '_cache_read', side_effect=slow_read), ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda i: discovery._cache_put('fixture-%d' % i, 'tool.exe', 'manual'), range(16)))
        self.assertTrue(all(results))
        self.assertEqual(len(discovery._cache_read()['tools']), 16)


class ToolIdentityTests(unittest.TestCase):
    def test_matching_output_with_failed_exit_is_not_verified(self):
        with mock.patch.object(tool_identity.os.path, 'isfile', return_value=True), \
                mock.patch.object(tool_identity, '_run', return_value=('radare2 5.9.8', 1)):
            result = tool_identity.probe('radare2', 'fixture.exe')
        self.assertFalse(result['ok'])
        self.assertEqual(result['returncode'], 1)

    def test_r2_alias_uses_the_radare2_probe(self):
        with mock.patch.object(tool_identity.os.path, 'isfile', return_value=True), \
                mock.patch.object(tool_identity, '_run', return_value=('wrong tool', 0)) as run:
            result = tool_identity.probe('r2', 'fixture.exe')
        run.assert_called_once()
        self.assertFalse(result['ok'])

    def test_unknown_tool_cannot_claim_verified_identity(self):
        result = tool_identity.probe('fixture-unknown', 'fixture.exe')
        self.assertIsNone(result['ok'])
        self.assertFalse(result['verified'])


class ReadinessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('readiness_review', Path(__file__).with_name('tool-readiness.py'))
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_pe_header_may_be_beyond_first_kilobyte(self):
        with tempfile.TemporaryDirectory(prefix='seep-pe-check-') as td:
            path = Path(td) / 'fixture.exe'
            data = bytearray(0x900)
            data[:2] = b'MZ'
            data[0x3c:0x40] = (0x800).to_bytes(4, 'little')
            data[0x800:0x806] = b'PE\0\0\x64\x86'
            path.write_bytes(data)
            self.assertTrue(self.module._pe_info(str(path))['ok'])

    def test_file_format_alone_cannot_claim_runtime_ready(self):
        spec = {'install': {'primary': {'cmd': 'fixture-install'}}, 'probe': {'names': ['fixture']},
                'verify': {'kind': 'pe'}}
        with mock.patch.object(self.module, 'probe', return_value=([{'path': 'fixture.exe', 'via': 'env', 'viaDetail': ''}], False)), \
                mock.patch.object(self.module, '_pe_info', return_value={'ok': True, 'machine': 'AMD64', 'size': 4096}):
            result = self.module.inspect('fixture', spec)
        self.assertEqual(result['status'], 'FOUND_NO_VERIFY')

    def test_required_identity_probe_failure_cannot_be_ignored(self):
        spec = {'install': {'primary': {'cmd': 'fixture-install'}}, 'probe': {'names': ['fixture']},
                'verify': {'kind': 'exec', 'identityProbe': 'fixture'}}
        with mock.patch.object(self.module, 'probe', return_value=([{'path': 'fixture.exe', 'via': 'env', 'viaDetail': ''}], False)), \
                mock.patch.object(self.module, 'verify', return_value={'ok': True, 'line': 'fixture version'}), \
                mock.patch.object(self.module, 'identity', return_value={'ok': None, 'why': 'fixture probe error'}):
            result = self.module.inspect('fixture', spec)
        self.assertEqual(result['status'], 'FOUND_NO_VERIFY')

    def test_readiness_reports_the_executable_it_actually_verified(self):
        spec = {'install': {'primary': {'cmd': 'fixture-install'}}, 'probe': {'names': ['fixture']},
                'verify': {'kind': 'exec', 'exe': 'actual.exe'}}
        with mock.patch.object(self.module, 'probe', return_value=([{
                'path': 'candidate.exe', 'via': 'env', 'viaDetail': 'fixture'}], False)), \
                mock.patch.object(self.module, 'verify', return_value={'ok': True, 'line': 'version', 'exe': 'actual.exe'}):
            result = self.module.inspect('fixture', spec)
        self.assertEqual(result['path'], 'actual.exe')

    def test_readiness_checks_past_the_first_three_candidates(self):
        spec = {'install': {'primary': {'cmd': 'fixture-install'}}, 'probe': {'names': ['fixture']},
                'verify': {'kind': 'exec'}}
        hits = [{'path': 'candidate%d.exe' % index, 'via': 'dir', 'viaDetail': 'fixture'}
                for index in range(4)]
        failures = [{'ok': False, 'why': 'wrong candidate', 'line': 'wrong'} for _ in range(3)]
        success = {'ok': True, 'why': 'fixture version matched', 'line': 'fixture version'}
        with mock.patch.object(self.module, 'probe', return_value=(hits, False)), \
                mock.patch.object(self.module, 'verify', side_effect=failures + [success]) as verify:
            result = self.module.inspect('fixture', spec)
        self.assertEqual(result['status'], 'READY')
        self.assertEqual(result['path'], 'candidate3.exe')
        self.assertEqual(verify.call_count, 4)

    def test_plan_uses_the_same_installer_as_execution(self):
        spec = {'install': {'primary': {'cmd': 'old-installer'}, 'requiresNetwork': True}}
        plan = {'has_plan': True, 'method': 'pip', 'auto_allowed': True, 'note': 'fixture'}
        with mock.patch.object(discovery, 'install_plan', return_value=plan):
            result = self.module.install_plan(spec, 'fixture')
        self.assertIn('tool-acquire.py', result['cmd'])
        self.assertIn('--install', result['cmd'])
        self.assertNotIn('old-installer', result['cmd'])


@unittest.skipUnless(os.name == 'nt', 'Windows batch required')
class BatchArgumentTests(unittest.TestCase):
    def test_batch_preserves_metacharacters_without_expanding_the_argument(self):
        with tempfile.TemporaryDirectory(prefix='seep-batch-') as td:
            batch = Path(td) / 'echo-test.cmd'
            batch.write_text('@echo off\n@echo "%~1"\n', encoding='ascii')
            value = 'a & echo injected %PATH% ! ^ (file)'
            process = discovery._run_tool_process([str(batch), value], capture_output=True,
                                                   text=True, timeout=10)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(process.stdout.strip(), '"' + value + '"')


@unittest.skipUnless(os.name == 'nt' and shutil.which('powershell'), 'Windows PowerShell required')
class WindowsLibraryTests(unittest.TestCase):
    def run_library(self, script, extra_env=None):
        env = dict(os.environ, SEEP_REVIEW_LIB=str(Path(__file__).with_name('lib') / 'ToolDiscovery.ps1'))
        env.update(extra_env or {})
        result = subprocess.run(['powershell', '-NoProfile', '-Command',
            '. $env:SEEP_REVIEW_LIB; ' + script], env=env, capture_output=True,
            text=True, encoding='utf-8', errors='replace', timeout=40)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def test_function_alias_is_not_an_executable(self):
        result = self.run_library("function fixtureShadow { 'wrong' }; "
            "@{ found = ($null -ne (Resolve-ReverseCommandCandidate -Name fixtureShadow)) } | ConvertTo-Json -Compress")
        self.assertFalse(result['found'])

    def test_directory_is_not_an_executable_fallback(self):
        with tempfile.TemporaryDirectory(prefix='seep-library-') as td:
            result = self.run_library("function Get-ReverseToolDefinition { param($Name) "
                "[pscustomobject]@{ Name=$Name; Skill='fixture'; Purpose='fixture'; VersionArgs=@(); "
                "Fallbacks=@([pscustomobject]@{ Type='path'; Value=$env:SEEP_REVIEW_DIR }) } }; "
                "Resolve-ReverseToolSpec -Name fixture | ConvertTo-Json -Compress", {'SEEP_REVIEW_DIR': td})
        self.assertFalse(result['Available'])

    def test_declared_version_cannot_replace_executed_version(self):
        result = self.run_library("$spec = [pscustomobject]@{ Available=$true; Command=$env:SEEP_REVIEW_PY; "
            "VersionArgs=@('-c', 'print(12345)'); FixedVersion='fake-fixed-version' }; "
            "@{ version=(Get-ReverseToolVersion -Spec $spec) } | ConvertTo-Json -Compress",
            {'SEEP_REVIEW_PY': sys.executable})
        self.assertEqual(result['version'], '12345')

    def test_legacy_http_helper_rejects_plain_html(self):
        with endpoint_fixture('html') as (port, _requests):
            result = self.run_library("@{ verified=(Test-ReverseMcpHttp -Port ([int]$env:SEEP_REVIEW_PORT)) } | ConvertTo-Json -Compress",
                {'SEEP_REVIEW_PORT': str(port)})
        self.assertFalse(result['verified'])

    def test_registration_and_port_do_not_replace_protocol_verification(self):
        result = self.run_library("function Get-ReverseBootstrapDefinition { param($Name) "
            "[pscustomobject]@{ name=$Name; bootstrapKind='npm-mcp'; canAutoInstall=$true; docsUrl=''; "
            "mcpNames=@('fixture'); servicePort=12345; verificationMode='service-and-registration' } }; "
            "function Get-ReverseMcpServerNames { 'fixture' }; function Test-ReverseTcpPort { $true }; "
            "function Test-ReverseMcpHttp { $false }; "
            "function Resolve-ReverseToolSpec { [pscustomobject]@{ Available=$true } }; "
            "Get-ReverseCapabilityState -Name fixture | ConvertTo-Json -Compress")
        self.assertTrue(result['Registered'])
        self.assertTrue(result['ServiceOnline'])
        self.assertFalse(result['Ready'])


@unittest.skipUnless(os.name == 'nt' and shutil.which('powershell'), 'Windows PowerShell required')
class WindowsRunnerDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-runner-O'Brien-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        source = Path(__file__).resolve().parents[2]
        for name in ('Tool/scripts/tool-run.ps1', 'Tool/mcp/tool_autodiscover.py',
                     'Tool/scripts/lib/project_lock.py', 'Tool/scripts/lib/mcp_http.py',
                     'Tool/scripts/lib/runtime_root.py', 'Tool/scripts/lib/process_tree.py'):
            dest = self.root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / name, dest)
        self.config = self.root / 'Tool/config/tool-runtimes.json'
        self.config.parent.mkdir()
        self.config.write_text(json.dumps({'tools': {'fixture': {'modes': [
            {'id': 'cli', 'kind': 'cli', 'command': '"{exeDir}/{exeName}"', 'fallbackExe': ['fixture']}]}}}), encoding='utf-8')
        (self.config.parent / 'tool-capabilities.json').write_text('{"tools": {}}', encoding='utf-8')
        self.selected = self.root / 'fixture.exe'
        self.selected.touch()
        old = self.root / 'old.exe'
        old.touch()
        state = self.root / '.seep'
        state.mkdir()
        (state / 'tool-paths.json').write_text(json.dumps({'fixture': {'exe': str(old)}}), encoding='utf-8')
        self.env = dict(os.environ, USERPROFILE=str(self.root), HOME=str(self.root),
                        SEEP_FIXTURE_PATH=str(self.selected), PYTHONIOENCODING='utf-8')

    def run_tool(self, *args):
        process = subprocess.run(['powershell', '-NoProfile', '-File', str(self.root / 'Tool/scripts/tool-run.ps1'),
                                  '-Tool', 'fixture', *args], env=self.env, capture_output=True,
                                 text=True, encoding='utf-8', errors='replace', timeout=30)
        return process, json.loads(process.stdout.strip().splitlines()[-1])

    def test_real_runner_handles_quote_in_root_and_honors_environment(self):
        process, result = self.run_tool()
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(result['exe'], str(self.selected))
        self.assertEqual(result['via'], 'env')
        cache = json.loads((self.root / '.seep/tool-paths.json').read_text(encoding='utf-8-sig'))
        self.assertEqual(cache['fixture']['exe'], str(self.selected))

    def test_invalid_config_is_a_structured_failure(self):
        self.config.write_text('{broken', encoding='utf-8')
        process, result = self.run_tool()
        self.assertEqual(process.returncode, 2)
        self.assertEqual(result['stage'], 'config')

    def test_explicit_directory_is_rejected(self):
        process, result = self.run_tool('-Use', str(self.root))
        self.assertEqual(process.returncode, 2)
        self.assertEqual(result['stage'], 'discover')

    def test_execution_preserves_target_as_one_argument(self):
        config = json.loads(self.config.read_text(encoding='utf-8'))
        config['tools']['fixture']['modes'][0]['argv'] = ['-c',
            'import json,sys;print(json.dumps(sys.argv[1:]))', '{target}']
        self.config.write_text(json.dumps(config), encoding='utf-8')
        target = self.root / 'a & echo unexpected %PATH% {script}.bin'
        target.touch()
        process, result = self.run_tool('-Use', sys.executable, '-Target', str(target), '-Run')
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(json.loads(result['output'].strip()), [str(target)])
        self.assertEqual(result['tool'], 'fixture')
        self.assertEqual(result['mode'], 'cli')
        self.assertEqual(result['exe'], sys.executable)
        self.assertTrue(Path(result['workDir']).is_dir())

    def test_execution_uses_the_declared_work_directory(self):
        config = json.loads(self.config.read_text(encoding='utf-8'))
        config['tools']['fixture']['modes'][0]['argv'] = ['-c', 'import os;print(os.getcwd())']
        self.config.write_text(json.dumps(config), encoding='utf-8')
        work_dir = self.root / 'custom-work-dir'
        process, result = self.run_tool('-Use', sys.executable, '-WorkDir', str(work_dir), '-Run')
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(Path(result['output'].strip()).resolve(), work_dir.resolve())

    def test_relative_target_is_resolved_before_changing_tool_directory(self):
        config = json.loads(self.config.read_text(encoding='utf-8'))
        config['tools']['fixture']['modes'][0]['argv'] = ['-c',
            'import pathlib,sys;print(pathlib.Path(sys.argv[1]).is_file())', '{target}']
        self.config.write_text(json.dumps(config), encoding='utf-8')
        target = self.root / 'target.bin'
        target.touch()
        relative = os.path.relpath(target)
        process, result = self.run_tool('-Use', sys.executable, '-Target', relative, '-Run')
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(result['output'].strip(), 'True')

    def test_bad_mode_argv_is_structured_and_does_not_execute(self):
        for argv in ('not-an-array', [1], ['{unknown_placeholder}']):
            with self.subTest(argv=argv):
                config = json.loads(self.config.read_text(encoding='utf-8'))
                config['tools']['fixture']['modes'][0]['argv'] = argv
                self.config.write_text(json.dumps(config), encoding='utf-8')
                process, result = self.run_tool('-Use', sys.executable, '-Run')
                self.assertEqual(process.returncode, 2, process.stdout + process.stderr)
                self.assertEqual(result['stage'], 'config')

    def test_preview_lists_missing_inputs_without_creating_work_directory(self):
        config = json.loads(self.config.read_text(encoding='utf-8'))
        config['tools']['fixture']['modes'][0].update(argv=['{target}', '{script}'], scriptKind='file')
        self.config.write_text(json.dumps(config), encoding='utf-8')
        process, result = self.run_tool('-Use', sys.executable)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(len(result['missing_inputs']), 2)
        self.assertFalse(result['runtime_verified'])
        self.assertFalse((self.root / 'work').exists())

    def endpoint_mode(self, port, transport):
        self.config.write_text(json.dumps({'tools': {'fixture': {'modes': [{
            'id': 'mcp', 'kind': 'mcp-' + transport, 'start': {'toolId': 'fixture'},
            'ready': {'port': port, 'timeoutSec': 2},
            'endpoint': {'url': f'http://127.0.0.1:{port}/' + ('sse' if transport == 'sse' else 'mcp'),
                         'transport': transport}}]}}}), encoding='utf-8')

    def test_unrelated_http_listener_cannot_report_ready(self):
        with endpoint_fixture('html') as (port, _requests):
            self.endpoint_mode(port, 'http')
            process, result = self.run_tool('-Use', sys.executable)
        self.assertNotEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(result['stage'], 'handshake')

    def test_http_ready_requires_initialize_session_and_all_tool_pages(self):
        with endpoint_fixture('http') as (port, requests):
            self.endpoint_mode(port, 'http')
            process, result = self.run_tool('-Use', sys.executable)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(result['status'], 'ALREADY_READY')
        self.assertEqual(result['handshake']['tools'], 2)
        self.assertFalse(result['session_verified'])
        self.assertEqual([p['method'] for p, _h in requests],
                         ['initialize', 'notifications/initialized', 'tools/list', 'tools/list'])
        headers = {k.lower(): v for k, v in requests[-1][1].items()}
        self.assertEqual(headers['mcp-session-id'], 'fixture-session')
        self.assertEqual(headers['mcp-protocol-version'], '2025-06-18')

    def test_legacy_sse_ready_uses_real_sdk_and_tool_pagination(self):
        with endpoint_fixture('sse') as (port, _requests):
            self.endpoint_mode(port, 'sse')
            process, result = self.run_tool('-Use', sys.executable)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(result['handshake']['tools'], 2)
        self.assertFalse(result['session_verified'])

    def test_failed_execution_returns_actual_exit(self):
        config = json.loads(self.config.read_text(encoding='utf-8'))
        config['tools']['fixture']['modes'][0]['argv'] = ['-c', 'import sys;print("fixture failure");sys.exit(7)']
        self.config.write_text(json.dumps(config), encoding='utf-8')
        process, result = self.run_tool('-Use', sys.executable, '-Run')
        self.assertEqual(process.returncode, 7, process.stdout + process.stderr)
        self.assertEqual(result['exit'], 7)
        self.assertEqual(result['status'], 'FAILED')

    def test_missing_target_fails_before_execution(self):
        config = json.loads(self.config.read_text(encoding='utf-8'))
        config['tools']['fixture']['modes'][0]['argv'] = ['{target}']
        self.config.write_text(json.dumps(config), encoding='utf-8')
        process, result = self.run_tool('-Use', sys.executable, '-Run')
        self.assertEqual(process.returncode, 2, process.stdout + process.stderr)
        self.assertEqual(result['stage'], 'parameters')


if __name__ == '__main__':
    unittest.main(verbosity=2)
