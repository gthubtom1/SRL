"""Broken declarations must be reported; routing must retain auxiliary domains."""
import json
import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import project_workflow as workflow
import route

PROBE_PATH = Path(route.__file__).parents[1] / 'skill/softseep/scripts/skill-route-probe.py'
ROUTER_SKILL = Path(route.__file__).parents[1] / 'skill/seep-router/SKILL.md'
WEB_SKILL = Path(route.__file__).parents[1] / 'skill/web-pentest/SKILL.md'
CONFIG_DIR = Path(route.__file__).parents[1] / 'config'
spec = importlib.util.spec_from_file_location('route_probe', PROBE_PATH)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class RouteIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='seep-route-integrity-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.skills = self.root / 'Tool/skill'
        self.skills.mkdir(parents=True)
        self.pack = self.add_pack('primary', [
            {'label': 'primary', 'must': ['mixed'], 'priority': 100}])

    def add_pack(self, name, routes):
        folder = self.skills / name
        folder.mkdir()
        (folder / 'SKILL.md').write_text('fixture skill', encoding='utf-8')
        path = folder / 'pack.json'
        path.write_text(json.dumps({'schema': 'seep.pack/1', 'id': name,
                                   'routes': routes, 'tools': []}), encoding='utf-8')
        return path

    def cli(self, *args):
        return subprocess.run([sys.executable, '-X', 'utf8', route.__file__,
                               '--skill-dir', str(self.skills), '--json', *args],
                              capture_output=True, text=True, encoding='utf-8', timeout=15)

    def test_malformed_routes_fail_in_check_index_and_resolve_without_traceback(self):
        for field, value in (('priority', 'bad'), ('priority', True),
                             ('must', 7), ('must', ['[']), ('must', [42]),
                             ('label', {})):
            with self.subTest(field=field, value=value):
                raw = {'schema': 'seep.pack/1', 'id': 'primary', 'routes': [
                    {'label': 'primary', 'must': ['mixed'], 'priority': 100}]}
                raw['routes'][0][field] = value
                self.pack.write_text(json.dumps(raw), encoding='utf-8')
                for args in (('--check',), ('--index',), ('--resolve', 'mixed')):
                    result = self.cli(*args)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
                    self.assertTrue(json.loads(result.stdout)['problems'])

    def test_bad_json_missing_entry_or_namespace_does_not_silently_classify(self):
        valid = self.pack.read_bytes()
        cases = ('bad-json', 'missing-skill', 'bad-namespace')
        for case in cases:
            with self.subTest(case=case):
                self.pack.write_bytes(valid)
                skill = self.pack.with_name('SKILL.md')
                skill.write_text('fixture', encoding='utf-8')
                if case == 'bad-json':
                    self.pack.write_bytes(b'{broken')
                elif case == 'missing-skill':
                    skill.unlink()
                else:
                    config = self.root / 'Tool/config/domain-aliases.json'
                    config.parent.mkdir()
                    config.write_bytes(b'{broken')
                result = self.cli('--resolve', 'mixed')
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertTrue(json.loads(result.stdout)['problems'])
                with self.assertRaises(workflow.WorkflowError) as failed:
                    workflow.classify('mixed', str(self.skills))
                self.assertEqual(failed.exception.stage, 'classify')
                self.assertTrue(failed.exception.extra['pack_problems'])

    def test_classify_retains_aux_domain_after_many_primary_route_hits(self):
        raw = json.loads(self.pack.read_text(encoding='utf-8'))
        raw['routes'] = [{'label': f'primary {i}', 'must': ['mixed'], 'priority': 100 - i}
                         for i in range(6)]
        self.pack.write_text(json.dumps(raw), encoding='utf-8')
        self.add_pack('auxiliary', [{'label': 'aux', 'must': ['mixed'], 'priority': 10}])
        result = workflow.classify('mixed', str(self.skills))
        self.assertEqual(result['primary_candidate'], 'primary')
        self.assertEqual(result['aux_candidates'], ['auxiliary'])
        self.assertTrue(result['requires_main_agent_decision'])

    def test_shipped_wireless_capture_and_web_protocol_inputs(self):
        for text, expected in (('IEEE 802.11', 'firmware-iot'),
                               ('IEEE 802.15.4', 'firmware-iot'),
                               ('分析 capture.pcap', 'forensics-mobile'),
                               ('分析 capture.pcapng', 'forensics-mobile')):
            with self.subTest(text=text):
                self.assertIn(expected, {h['pack'] for h in route.resolve(text, limit=None)})
        result = workflow.classify('前端 JS 签名算法还原，并分析抓包中的 HTTP 请求协议')
        self.assertEqual(result['primary_candidate'], 'softseep')
        self.assertIn('protocol-plugin', result['aux_candidates'])

    def test_cli_returns_all_hits_unless_the_caller_sets_a_limit(self):
        raw = json.loads(self.pack.read_text(encoding='utf-8'))
        raw['routes'] = [
            {'label': 'route %d' % index, 'must': ['mixed'], 'priority': 100 - index}
            for index in range(8)
        ]
        self.pack.write_text(json.dumps(raw), encoding='utf-8')

        result = self.cli('--resolve', 'mixed')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)['hits']), 8)

        limited = self.cli('--resolve', 'mixed', '--limit', '3')
        self.assertEqual(limited.returncode, 0, limited.stderr)
        self.assertEqual(len(json.loads(limited.stdout)['hits']), 3)

        invalid = self.cli('--resolve', 'mixed', '--limit', '0')
        self.assertNotEqual(invalid.returncode, 0)
        self.assertNotIn('Traceback', invalid.stderr)

    def test_probe_rejects_a_forbidden_auxiliary_domain(self):
        probe_record = {
            'expect_skill': 'firmware-iot/SKILL.md',
            'expect_aux': ['web-pentest/SKILL.md'],
            'expect_ambiguity': True,
            'forbid': ['web-pentest/SKILL.md'],
        }
        facts = {
            'primary_skill': 'firmware-iot/SKILL.md',
            'domains': ['firmware-iot', 'web-pentest'],
        }
        # The former first-hit-only judge returned [] for this exact shape.
        bad = probe.judge(probe_record, facts)
        self.assertTrue(bad, bad)
        self.assertTrue(any('禁止域' in item for item in bad), bad)

        missing_aux = probe.judge(
            {'expect_skill': 'apkseep/SKILL.md', 'expect_aux': ['softseep/SKILL.md'],
             'expect_ambiguity': True},
            {'primary_skill': 'apkseep/SKILL.md', 'domains': ['apkseep']},
        )
        self.assertTrue(any('辅助技能' in item for item in missing_aux), missing_aux)

    def test_router_carrier_table_matches_authoritative_route_examples(self):
        router_text = ROUTER_SKILL.read_text(encoding='utf-8-sig')
        web_text = WEB_SKILL.read_text(encoding='utf-8-sig')
        self.assertIn('`.bin` 单独出现', router_text)
        self.assertIn('不能按后缀判域', router_text)
        self.assertIn('`.js`、前端 JS 混淆/签名算法', router_text)
        self.assertIn('主域交接给 `softseep`', web_text)

        examples = (
            ('前端JS找签名算法，逆向登录加密', 'softseep'),
            ('网站渗透测试，先做信息收集和目录爆破', 'web-pentest'),
            ('抓包复刻私有协议', 'protocol-plugin'),
            ('路由器固件 .bin 解包后分析文件系统', 'firmware-iot'),
            ('分析这个 .bin 可执行程序的 IAT', 'softseep'),
        )
        for text, expected in examples:
            with self.subTest(text=text):
                _hits, domains = route.resolved_domains(text)
                self.assertTrue(domains, text)
                self.assertEqual(domains[0], expected)

    def test_custom_branch_follow_routes_are_precise_and_apk_aware(self):
        domains_config = json.loads(
            (CONFIG_DIR / 'playbook-domains.json').read_text(encoding='utf-8-sig'))
        self.assertEqual(domains_config['map']['version-migrate'],
                         ['softseep', 'apkseep'])

        probes = json.loads(
            (CONFIG_DIR / 'intent-probes.json').read_text(encoding='utf-8-sig'))['probes']
        positive = [p for p in probes if p['id'].startswith('ver-follow-')]
        negative = [p for p in probes if p['id'].startswith('route-neg-')]
        self.assertEqual(len(positive), 9)
        self.assertEqual(len(negative), 3)

        migration_packs = set(domains_config['map']['version-migrate'])
        apk_follow_ids = {'ver-follow-07', 'ver-follow-08', 'ver-follow-09'}
        for row in positive:
            with self.subTest(id=row['id']):
                hits = route.resolve(row['text'])
                migration_hits = [h for h in hits if '追版' in h['label']]
                self.assertTrue(migration_hits, hits)
                hit_packs = {h['pack'] for h in migration_hits}
                self.assertTrue(hit_packs)
                self.assertLessEqual(hit_packs, migration_packs)
                if row['id'] in apk_follow_ids:
                    self.assertIn('apkseep', hit_packs)

        for row in negative:
            with self.subTest(id=row['id']):
                hits = route.resolve(row['text'])
                self.assertFalse(any('追版' in h['label'] for h in hits), hits)

    def probe_main(self, *args):
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', [str(PROBE_PATH), '--json', *args]), redirect_stdout(output):
            rc = probe.main()
        return rc, json.loads(output.getvalue())

    def test_probe_runs_python_router_without_powershell(self):
        with mock.patch('shutil.which', return_value=None):
            rc, result = self.probe_main('--only', 'web-js')
        self.assertEqual(rc, 0, result)
        self.assertGreater(result['probes'], 0)
        self.assertEqual(result['failed'], 0)

    def test_probe_empty_selection_does_not_pass(self):
        rc, result = self.probe_main('--only', 'does-not-exist')
        self.assertEqual(rc, 2, result)
        self.assertFalse(result['ok'])

    def test_probe_transport_failures_are_reported_even_for_unclassified(self):
        input_file = self.root / 'probes.json'
        input_file.write_text(json.dumps({'probes': [
            {'id': 'outside', 'text': 'hello', 'expect_skill': ''}]}), encoding='utf-8')
        for failure in ('timeout', 'bad-json'):
            with self.subTest(failure=failure):
                kwargs = ({'side_effect': subprocess.TimeoutExpired(['router'], 60)}
                          if failure == 'timeout' else
                          {'return_value': subprocess.CompletedProcess(['router'], 0, b'not-json', b'')})
                with mock.patch.object(probe.subprocess, 'run', **kwargs):
                    rc, result = self.probe_main('--probes', str(input_file))
                self.assertEqual(rc, 1, result)
                self.assertFalse(result['ok'])
                self.assertTrue(result['fails'][0]['bad'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
