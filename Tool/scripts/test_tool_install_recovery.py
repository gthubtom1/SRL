"""Isolated readiness regressions; no external installations or host probes."""
import importlib.util
import ast
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mcp'))
import tool_autodiscover as discovery
from lib import tool_identity

spec = importlib.util.spec_from_file_location('readiness_recovery', Path(__file__).with_name('tool-readiness.py'))
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)
acquire_spec = importlib.util.spec_from_file_location('acquire_catalog_recovery', Path(__file__).with_name('tool-acquire.py'))
acquire = importlib.util.module_from_spec(acquire_spec)
acquire_spec.loader.exec_module(acquire)


class InstallCatalogIsolationTests(unittest.TestCase):
    def test_invalid_catalog_is_structured_and_blocks_all_install_paths(self):
        cases = ('{broken', json.dumps({'installable': [], 'auto_allow_methods': ['pip']}),
                 json.dumps({'installable': {'fixture': {'method': 'manual', 'url': 'file:///bad'}},
                             'auto_allow_methods': ['pip']}))
        server_path = Path(__file__).resolve().parents[1] / 'mcp' / 'seep_mcp_server.py'
        tree = ast.parse(server_path.read_text(encoding='utf-8'))
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'seep_ensure_tool')
        function.decorator_list = []
        namespace = {'json': json, '_autodiscover': lambda: discovery, '_TOOL_INSTALL_HINTS': {}}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(server_path), 'exec'), namespace)
        ensure = namespace['seep_ensure_tool']
        for content in cases:
            with self.subTest(content=content), tempfile.TemporaryDirectory(prefix='seep-catalog-') as td:
                root = Path(td); catalog = root / 'install.json'; catalog.write_text(content, encoding='utf-8')
                with mock.patch.object(discovery, '_INSTALL_FILE', str(catalog)), \
                     mock.patch.object(discovery, '_install_base', return_value=str(root / 'tools')), \
                     mock.patch.object(discovery, '_run_tool_process') as run, \
                     mock.patch.object(discovery, '_download_and_extract_portable') as download, \
                     mock.patch.object(acquire, 'load_json', return_value={'tools': {'fixture': {}}}), \
                     mock.patch.object(acquire, 'autodiscover', side_effect=lambda tid: discovery.discover(tid)), \
                     mock.patch.object(acquire, '_discovery_module', return_value=discovery):
                    disc = discovery.discover('fixture')
                    plan = discovery.install_plan('fixture')
                    installed = discovery.propose_install('fixture', execute=True)
                    got = acquire.acquire('fixture', allow_start=False, allow_install=True)
                    lifecycle = json.loads(ensure('fixture', allow_install=True))
                self.assertTrue(disc.get('config_error'), disc)
                self.assertTrue(plan.get('config_error'), plan)
                self.assertTrue(installed.get('config_error'), installed)
                self.assertEqual(got['verdict'], 'CONFIG_ERROR', got)
                self.assertTrue(lifecycle.get('config_error'), lifecycle)
                self.assertFalse(plan.get('has_plan'))
                self.assertFalse(installed.get('executed'))
                run.assert_not_called(); download.assert_not_called()

    def test_valid_manual_is_not_configuration_error(self):
        content = {'installable': {'fixture': {'method': 'manual', 'url': 'https://example.invalid/install',
                                               'note': 'manual steps'}}, 'auto_allow_methods': ['pip']}
        with tempfile.TemporaryDirectory(prefix='seep-manual-') as td:
            catalog = Path(td) / 'install.json'; catalog.write_text(json.dumps(content), encoding='utf-8')
            with mock.patch.object(discovery, '_INSTALL_FILE', str(catalog)):
                plan = discovery.install_plan('fixture')
        self.assertTrue(plan['has_plan'], plan)
        self.assertFalse(plan['auto_allowed'])
        self.assertFalse(plan.get('config_error'))
        self.assertEqual(plan['note'], 'manual steps')


class ReadinessIsolationTests(unittest.TestCase):
    def test_candidate_is_verified_without_substitution(self):
        for sibling_exists in (False, True):
            with self.subTest(sibling_exists=sibling_exists), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                candidate, sibling, other = root / 'selected.exe', root / 'desired.exe', root / 'elsewhere' / 'desired.exe'
                candidate.touch()
                if sibling_exists:
                    sibling.touch()
                other.parent.mkdir()
                other.touch()
                hits = [{'path': str(candidate), 'via': 'env', 'viaDetail': 'selected'}]
                config = {'probe': {'names': ['selected']}, 'verify': {
                    'exe': 'desired.exe', 'args': ['--version'], 'expect': 'desired'},
                    'install': {'primary': {'note': 'manual'}}}

                def run(argv, **_kwargs):
                    return subprocess.CompletedProcess(argv, 0, 'wrong' if argv[0] == str(candidate) else 'desired', '')

                with mock.patch.object(readiness, 'probe', return_value=(hits, False)), \
                     mock.patch.object(readiness.shutil, 'which', return_value=str(other)), \
                     mock.patch.object(readiness.process_tree, 'run', side_effect=run) as run_mock:
                    row = readiness.inspect('fixture', config)
                self.assertEqual(row['status'], 'FOUND_NO_VERIFY', row)
                self.assertEqual(run_mock.call_args.args[0][0], str(candidate))

    def test_selected_candidate_can_pass(self):
        with tempfile.TemporaryDirectory() as td:
            selected = Path(td) / 'selected.exe'
            selected.touch()
            with mock.patch.object(readiness.process_tree, 'run', return_value=subprocess.CompletedProcess([], 0, 'desired 1.0', '')) as run:
                result = readiness.verify({'exe': 'desired.exe', 'expect': 'desired'}, str(selected))
            self.assertTrue(result['ok'])
            self.assertEqual(result['exe'], str(selected))
            self.assertEqual(run.call_args.args[0][0], str(selected))

    def test_invalid_install_catalog_is_reported_even_with_manual_note(self):
        config = {'probe': {'names': ['fixture']}, 'verify': {'kind': 'exec'},
                  'install': {'primary': {'note': 'manual instructions'}}}
        for content in ('{broken', json.dumps({'installable': [], 'auto_allow_methods': []})):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as td:
                catalog = Path(td) / 'tool-install.json'
                catalog.write_text(content, encoding='utf-8')
                with mock.patch.object(discovery, '_INSTALL_FILE', str(catalog)), \
                     mock.patch.object(readiness, 'probe', return_value=([], False)):
                    row = readiness.inspect('fixture', config)
                self.assertTrue(any('安装配置无效' in item for item in row['problems']), row)
                self.assertIn('manual instructions', row['install']['note'])

    def test_readiness_exit_reports_invalid_catalog(self):
        spec = {'probe': {'names': ['fixture']}, 'verify': {'kind': 'exec'},
                'install': {'primary': {'note': 'manual instructions'}}}
        with tempfile.TemporaryDirectory() as td:
            runtime = Path(td) / 'runtime.json'
            runtime.write_text(json.dumps({'tools': {'fixture': spec}}), encoding='utf-8')
            catalog = Path(td) / 'install.json'
            catalog.write_text('{broken', encoding='utf-8')
            output = io.StringIO()
            with mock.patch.object(discovery, '_INSTALL_FILE', str(catalog)), \
                 mock.patch.object(readiness, 'RUNTIMES', str(runtime)), \
                 mock.patch.object(readiness, 'TOOLS', ('fixture',)), \
                 mock.patch.object(readiness, 'probe', return_value=([], False)), \
                 mock.patch.object(sys, 'argv', ['readiness', '--json']), \
                 mock.patch.object(sys, 'stdout', output):
                code = readiness.main()
            payload = json.loads(output.getvalue())
        self.assertEqual(code, 1)
        self.assertFalse(payload['ok'])
        self.assertTrue(any('安装配置无效' in p for p in payload['problems']))

    def test_valid_catalog_preserves_manual_guidance(self):
        config = {'probe': {'names': ['fixture']}, 'verify': {'kind': 'exec'},
                  'install': {'primary': {'note': 'manual instructions'}}}
        with tempfile.TemporaryDirectory() as td:
            catalog = Path(td) / 'install.json'
            catalog.write_text(json.dumps({'installable': {}, 'auto_allow_methods': []}), encoding='utf-8')
            with mock.patch.object(discovery, '_INSTALL_FILE', str(catalog)), \
                 mock.patch.object(readiness, 'probe', return_value=([], False)):
                row = readiness.inspect('fixture', config)
        self.assertEqual(row['problems'], [])
        self.assertEqual(row['install']['note'], 'manual instructions')


class PortableRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.real_discover = discovery.discover
        temp = tempfile.TemporaryDirectory(prefix='seep-portable-recovery-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.base = self.root / 'tools'
        self.base.mkdir()
        self.final = self.base / 'fixture'
        self.state = self.root / 'state'
        self.state.mkdir()
        self.config = {'auto_allow_methods': ['portable_zip'], 'installable': {'fixture': {'methods': [
            {'type': 'portable_zip', 'urls': ['https://fixture.invalid/test.zip'],
             'target_sub': 'fixture', 'verify_exe': 'tool.exe'}]}}}
        self.data = io.BytesIO()
        with zipfile.ZipFile(self.data, 'w') as archive:
            archive.writestr('tool.exe', b'new')
        opener = mock.Mock()
        opener.open.side_effect = lambda *_a, **_kw: io.BytesIO(self.data.getvalue())
        patches = [mock.patch.object(discovery, '_install_base', return_value=str(self.base)),
                   mock.patch.object(discovery, '_install_table', side_effect=lambda: self.config),
                   mock.patch.object(discovery, '_capabilities_table', return_value={'tools': {'fixture': {
                       'exe_candidates': ['tool.exe'], 'identityProbe': 'fixture'}}}),
                   mock.patch.object(discovery, '_detect_local_proxy_port', return_value=None),
                   mock.patch.object(discovery, '_COMMON_ROOTS', []),
                   mock.patch.object(discovery, 'discover', return_value={'available': False}),
                   mock.patch.object(discovery, 'LOCAL_STATE_PATH', str(self.state / 'tools.local.json')),
                   mock.patch.object(discovery, '_PATH_CACHE_FILE', str(self.state / 'tool-paths.json')),
                   mock.patch('urllib.request.build_opener', return_value=opener)]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def old_install(self):
        self.final.mkdir()
        (self.final / 'tool.exe').write_bytes(b'old')
        discovery.record('fixture', {'available': True, 'command': str(self.final / 'tool.exe'), 'via': 'old'})
        discovery._cache_put('fixture', str(self.final / 'tool.exe'), 'old')
        return ((self.state / 'tools.local.json').read_bytes(), (self.state / 'tool-paths.json').read_bytes())

    def test_identity_failure_restores_old_install_and_preserves_state(self):
        state, cache = self.old_install()
        with mock.patch.object(tool_identity, 'probe', return_value={'ok': False, 'why': 'wrong identity'}) as probe:
            result = discovery.propose_install('fixture', execute=True)
        self.assertFalse(result['success'], result)
        self.assertEqual((self.final / 'tool.exe').read_bytes(), b'old')
        self.assertEqual((self.state / 'tools.local.json').read_bytes(), state)
        self.assertEqual((self.state / 'tool-paths.json').read_bytes(), cache)
        self.assertEqual(probe.call_args.args[1], str(self.final / 'tool.exe'))

    def test_identity_failure_on_first_install_removes_new_install(self):
        with mock.patch.object(tool_identity, 'probe', return_value={'ok': False, 'why': 'wrong identity'}):
            result = discovery.propose_install('fixture', execute=True)
        self.assertFalse(result['success'], result)
        self.assertFalse(self.final.exists())
        self.assertFalse((self.state / 'tools.local.json').exists())
        self.assertFalse((self.state / 'tool-paths.json').exists())

    def test_success_verifies_new_executable_and_publishes_under_install_lock(self):
        self.old_install()
        from lib import project_lock as lock_module
        original_record, original_cache = discovery.record, discovery._cache_put
        lock_key = os.path.normcase(str(self.base.resolve()))
        events = []
        def check_locked(name, func):
            def call(*args, **kwargs):
                self.assertIn(lock_key, lock_module._HELD.roots)
                events.append(name)
                return func(*args, **kwargs)
            return call
        def identity(_tool, path):
            self.assertIn(lock_key, lock_module._HELD.roots)
            self.assertEqual(Path(path).read_bytes(), b'new')
            events.append('identity')
            return {'ok': True, 'verified': True}
        with mock.patch.object(tool_identity, 'probe', side_effect=identity), \
             mock.patch.object(discovery, 'record', side_effect=check_locked('record', original_record)), \
             mock.patch.object(discovery, '_cache_put', side_effect=check_locked('cache', original_cache)), \
             mock.patch.object(discovery, 'discover') as global_discovery:
            result = discovery.propose_install('fixture', execute=True)
        self.assertTrue(result['success'], result)
        global_discovery.assert_not_called()
        self.assertEqual(events, ['identity', 'cache', 'record'])
        self.assertEqual((self.final / 'tool.exe').read_bytes(), b'new')
        self.assertEqual(discovery._cache_read()['tools']['fixture']['command'], str(self.final / 'tool.exe'))
        self.assertEqual(discovery.load_state()['tools']['fixture']['command'], str(self.final / 'tool.exe'))
        self.assertTrue(result['recheck']['identity_verified'])

    def test_failed_restore_stops_fallback_and_reports_backup(self):
        self.old_install()
        self.config['auto_allow_methods'].append('pip')
        self.config['installable']['fixture']['methods'].append({'type': 'pip', 'pkg': 'fixture'})
        replace = discovery.os.replace
        def fail_restore(src, dst):
            if Path(src).name.startswith('.seep-previous-') and Path(dst) == self.final:
                raise OSError('injected restore failure')
            return replace(src, dst)
        with mock.patch.object(tool_identity, 'probe', return_value={'ok': False, 'why': 'wrong identity'}), \
             mock.patch.object(discovery.os, 'replace', side_effect=fail_restore), \
             mock.patch.object(discovery, '_run_tool_process') as fallback:
            result = discovery.propose_install('fixture', execute=True)
        self.assertFalse(result['success'])
        self.assertTrue(result['download_result']['recovery_required'], result)
        self.assertEqual((Path(result['download_result']['backup_dir']) / 'tool.exe').read_bytes(), b'old')
        fallback.assert_not_called()
        # A later entry retries recovery before it may attempt another method.
        with mock.patch.object(discovery.os, 'replace', side_effect=fail_restore), \
             mock.patch.object(discovery, '_run_tool_process') as fallback:
            blocked = discovery.propose_install('fixture', execute=True)
        self.assertTrue(blocked['recovery_required'], blocked)
        fallback.assert_not_called()
        self.retry_with_failed_download()
        self.assertEqual((self.final / 'tool.exe').read_bytes(), b'old')
        self.assertFalse((self.base / discovery._PORTABLE_JOURNAL).exists())

    def test_successful_restore_allows_fallback(self):
        self.old_install()
        self.config['auto_allow_methods'].append('pip')
        self.config['installable']['fixture']['methods'].append({'type': 'pip', 'pkg': 'fixture'})
        def fallback(*args, **kwargs):
            self.assertEqual((self.final / 'tool.exe').read_bytes(), b'old')
            return subprocess.CompletedProcess(args, 0, '', '')
        with mock.patch.object(tool_identity, 'probe', return_value={'ok': False, 'why': 'wrong identity'}), \
             mock.patch.object(discovery, '_run_tool_process', side_effect=fallback), \
             mock.patch.object(discovery, 'discover', return_value={'available': True}):
            result = discovery.propose_install('fixture', execute=True)
        self.assertTrue(result['success'], result)
        self.assertEqual(len(result['attempts']), 2)

    def test_unavailable_identity_probe_does_not_claim_verified(self):
        caps = {'tools': {'fixture': {'exe_candidates': ['tool.exe']}}}
        with mock.patch.object(discovery, '_capabilities_table', return_value=caps), \
             mock.patch.object(tool_identity, 'probe', return_value={'ok': None, 'verified': False}):
            result = discovery.propose_install('fixture', execute=True)
        self.assertTrue(result['success'], result)
        self.assertFalse(result['recheck']['identity_verified'])

    def test_required_identity_probe_unavailable_restores_old_install(self):
        self.old_install()
        with mock.patch.object(tool_identity, 'probe', return_value={'ok': None, 'why': 'probe unavailable'}):
            result = discovery.propose_install('fixture', execute=True)
        self.assertFalse(result['success'], result)
        self.assertEqual((self.final / 'tool.exe').read_bytes(), b'old')

    def test_state_write_failures_are_reported_without_claiming_saved(self):
        with mock.patch.object(tool_identity, 'probe', return_value={'ok': True, 'verified': True}), \
             mock.patch.object(discovery, '_cache_put', return_value=False), \
             mock.patch.object(discovery, 'record', return_value={'state_saved': False}):
            result = discovery.propose_install('fixture', execute=True)
        self.assertFalse(result['success'], result)
        self.assertTrue(result['recovery_required'])
        self.assertTrue((self.base / discovery._PORTABLE_JOURNAL).exists())
        self.assertEqual((self.final / 'tool.exe').read_bytes(), b'new')
        self.retry_with_failed_download()
        self.assertFalse((self.base / discovery._PORTABLE_JOURNAL).exists())
        self.assertEqual(discovery._cache_read()['tools']['fixture']['via'], 'portable_zip')
        self.assertEqual(discovery.load_state()['tools']['fixture']['via'], 'portable_zip')

    def test_other_install_waits_until_identity_verification_finishes(self):
        entered, release, second_download = threading.Event(), threading.Event(), threading.Event()
        download_count = 0
        guard = threading.Lock()
        opener = mock.Mock()
        def open_archive(*_args, **_kwargs):
            nonlocal download_count
            with guard:
                download_count += 1
                if download_count == 2:
                    second_download.set()
            return io.BytesIO(self.data.getvalue())
        opener.open.side_effect = open_archive
        def identity(_tool, _path):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('fixture timed out')
            return {'ok': True, 'verified': True}
        with mock.patch('urllib.request.build_opener', return_value=opener), \
             mock.patch.object(tool_identity, 'probe', side_effect=identity), \
             ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(discovery.propose_install, 'fixture', True)
            try:
                self.assertTrue(entered.wait(5))
                second = pool.submit(discovery.propose_install, 'fixture', True)
                self.assertFalse(second_download.wait(.2), 'second install entered during identity verification')
            finally:
                release.set()
            self.assertTrue(first.result(timeout=5)['success'])
            self.assertTrue(second.result(timeout=5)['success'])
        self.assertTrue(second_download.is_set())

    def crash_install(self, point):
        code = r'''
import io, json, os, sys, zipfile
from pathlib import Path
from unittest import mock
root = Path(sys.argv[1]); base = root / 'tools'; state = root / 'state'; point = sys.argv[2]
sys.path.insert(0, sys.argv[3])
import tool_autodiscover as d
from lib import tool_identity
config = {'auto_allow_methods':['portable_zip'], 'installable':{'fixture':{'methods':[
    {'type':'portable_zip','urls':['https://fixture.invalid/a.zip'],'target_sub':'fixture','verify_exe':'tool.exe'}]}}}
content = io.BytesIO()
with zipfile.ZipFile(content, 'w') as z: z.writestr('tool.exe', b'new')
opener = mock.Mock(); opener.open.side_effect = lambda *_a, **_k: io.BytesIO(content.getvalue())
d._install_base = lambda: str(base)
d._install_table = lambda: config
d._capabilities_table = lambda: {'tools': {'fixture': {'identityProbe': 'fixture'}}}
d._detect_local_proxy_port = lambda: None
d._COMMON_ROOTS = []
d._PATH_CACHE_FILE = str(state / 'tool-paths.json')
d.LOCAL_STATE_PATH = str(state / 'tools.local.json')
def probe(*_a):
    if point == 'identity': os._exit(71)
    return {'ok': True, 'verified': True}
tool_identity.probe = probe
real_replace = os.replace
def replace(src, dst):
    real_replace(src, dst)
    if point == 'old_moved' and Path(dst).name.startswith('.seep-previous-'): os._exit(71)
    if point == 'promoted' and Path(dst) == base / 'fixture' and Path(src).name == 'unpacked': os._exit(71)
d.os.replace = replace
real_journal = d._portable_write_journal
def journal(base, data):
    if point == 'identity_passed' and data['phase'] == 'committed': os._exit(71)
    real_journal(base, data)
    if point == 'committed' and data['phase'] == 'committed': os._exit(71)
d._portable_write_journal = journal
real_cache = d._cache_put
def cache(*a, **k):
    result = real_cache(*a, **k)
    if point == 'cache_written': os._exit(71)
    return result
d._cache_put = cache
real_record = d.record
def record(*a, **k):
    result = real_record(*a, **k)
    if point == 'state_written': os._exit(71)
    return result
d.record = record
with mock.patch('urllib.request.build_opener', return_value=opener):
    d.propose_install('fixture', execute=True)
os._exit(72)
'''
        process = subprocess.run([sys.executable, '-B', '-X', 'utf8', '-c', code,
                                  str(self.root), point, str(Path(discovery.__file__).parent)],
                                 capture_output=True, text=True, timeout=20)
        self.assertEqual(process.returncode, 71, process.stderr)

    def retry_with_failed_download(self):
        # The next install entry must recover before attempting this invalid ZIP.
        bad = mock.Mock()
        bad.open.return_value = io.BytesIO(b'not a zip')
        with mock.patch('urllib.request.build_opener', return_value=bad):
            return discovery._download_and_extract_portable(
                ['https://fixture.invalid/a.zip'], 'fixture', 'tool.exe', tool_id='fixture')

    def test_process_exit_before_commit_restores_previous_install(self):
        for point in ('old_moved', 'promoted', 'identity', 'identity_passed'):
            with self.subTest(point=point), tempfile.TemporaryDirectory(prefix='seep-crash-case-') as td:
                # Use a fresh isolated fixture per crash point.
                with mock.patch.object(self, 'root', Path(td)):
                    self.base = self.root / 'tools'; self.base.mkdir()
                    self.state = self.root / 'state'; self.state.mkdir()
                    self.final = self.base / 'fixture'
                    with mock.patch.object(discovery, '_install_base', return_value=str(self.base)), \
                         mock.patch.object(discovery, 'LOCAL_STATE_PATH', str(self.state / 'tools.local.json')), \
                         mock.patch.object(discovery, '_PATH_CACHE_FILE', str(self.state / 'tool-paths.json')):
                        state, cache = self.old_install()
                        self.crash_install(point)
                        self.retry_with_failed_download()
                        self.assertEqual((self.state / 'tools.local.json').read_bytes(), state)
                        self.assertEqual((self.state / 'tool-paths.json').read_bytes(), cache)
                    self.assertEqual((self.final / 'tool.exe').read_bytes(), b'old')

    def test_process_exit_first_install_before_commit_removes_new(self):
        self.crash_install('promoted')
        self.retry_with_failed_download()
        self.assertFalse(self.final.exists())

    def test_process_exit_after_commit_finishes_state_publication(self):
        for point in ('committed', 'cache_written', 'state_written'):
            with self.subTest(point=point), tempfile.TemporaryDirectory(prefix='seep-commit-case-') as td:
                with mock.patch.object(self, 'root', Path(td)):
                    self.base = self.root / 'tools'; self.base.mkdir()
                    self.state = self.root / 'state'; self.state.mkdir()
                    self.final = self.base / 'fixture'
                    with mock.patch.object(discovery, '_install_base', return_value=str(self.base)), \
                         mock.patch.object(discovery, 'LOCAL_STATE_PATH', str(self.state / 'tools.local.json')), \
                         mock.patch.object(discovery, '_PATH_CACHE_FILE', str(self.state / 'tool-paths.json')):
                        self.old_install()
                        self.crash_install(point)
                        self.retry_with_failed_download()
                        self.assertEqual((self.final / 'tool.exe').read_bytes(), b'new')
                        self.assertEqual(discovery._cache_read()['tools']['fixture']['via'], 'portable_zip')
                        self.assertEqual(discovery.load_state()['tools']['fixture']['via'], 'portable_zip')

    def test_process_exit_during_recovery_is_retried(self):
        code = r'''
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[2])
import tool_autodiscover as d
root = Path(sys.argv[1]); base = root / 'tools'; state = root / 'state'
d._PATH_CACHE_FILE = str(state / 'tool-paths.json')
d.LOCAL_STATE_PATH = str(state / 'tools.local.json')
real = os.replace
def replace(src, dst):
    real(src, dst)
    if sys.argv[3] == 'discarded' and Path(dst).name == 'unpacked': os._exit(71)
    if sys.argv[3] == 'restored' and Path(src).name.startswith('.seep-previous-'): os._exit(71)
d.os.replace = replace
with d.project_lock(base, timeout=20): d._portable_recover_locked(base)
os._exit(72)
'''
        for point in ('discarded', 'restored'):
            with self.subTest(point=point), tempfile.TemporaryDirectory(prefix='seep-recovery-case-') as td:
                with mock.patch.object(self, 'root', Path(td)):
                    self.base = self.root / 'tools'; self.base.mkdir()
                    self.state = self.root / 'state'; self.state.mkdir()
                    self.final = self.base / 'fixture'
                    with mock.patch.object(discovery, '_install_base', return_value=str(self.base)), \
                         mock.patch.object(discovery, 'LOCAL_STATE_PATH', str(self.state / 'tools.local.json')), \
                         mock.patch.object(discovery, '_PATH_CACHE_FILE', str(self.state / 'tool-paths.json')):
                        self.old_install()
                        self.crash_install('promoted')
                        child = subprocess.run([sys.executable, '-B', '-X', 'utf8', '-c', code,
                                                str(self.root), str(Path(discovery.__file__).parent), point],
                                               capture_output=True, text=True, timeout=20)
                        self.assertEqual(child.returncode, 71, child.stderr)
                        self.retry_with_failed_download()
                        self.assertEqual((self.final / 'tool.exe').read_bytes(), b'old')
                        self.assertFalse((self.base / discovery._PORTABLE_JOURNAL).exists())

    def test_bad_journal_blocks_other_methods_and_preserves_files(self):
        self.old_install()
        journal = self.base / discovery._PORTABLE_JOURNAL
        journal.write_text('{bad', encoding='utf-8')
        self.config['auto_allow_methods'] = ['pip']
        self.config['installable']['fixture']['methods'] = [{'type': 'pip', 'pkg': 'fixture'}]
        with mock.patch.object(discovery, '_run_tool_process') as fallback:
            result = discovery.propose_install('fixture', execute=True)
        self.assertTrue(result['recovery_required'], result)
        fallback.assert_not_called()
        self.assertEqual(journal.read_text(encoding='utf-8'), '{bad')
        self.assertEqual((self.final / 'tool.exe').read_bytes(), b'old')

    def test_next_propose_recovers_before_nonportable_method(self):
        self.old_install()
        self.crash_install('promoted')
        self.config['auto_allow_methods'] = ['pip']
        self.config['installable']['fixture']['methods'] = [{'type': 'pip', 'pkg': 'fixture'}]
        def run(*args, **kwargs):
            self.assertEqual((self.final / 'tool.exe').read_bytes(), b'old')
            self.assertFalse((self.base / discovery._PORTABLE_JOURNAL).exists())
            return subprocess.CompletedProcess(args, 0, '', '')
        with mock.patch.object(discovery, '_run_tool_process', side_effect=run) as fallback, \
             mock.patch.object(discovery, 'discover', return_value={'available': True}):
            result = discovery.propose_install('fixture', execute=True)
        self.assertTrue(result['success'], result)
        fallback.assert_called_once()

    def test_discovery_reports_pending_recovery(self):
        self.crash_install('promoted')
        # setUp patches discover; call the underlying function in isolation.
        result = self.real_discover('fixture')
        self.assertFalse(result['available'], result)
        self.assertTrue(result['recovery_required'], result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
