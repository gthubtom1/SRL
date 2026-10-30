"""Configuration merging must preserve user files and report incomplete installs."""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SCRIPT = Path(__file__).with_name("merge_agent_config.py")
REAL_PERSONA_PKG = SCRIPT.resolve().parent.parent / "Tool/prompts/packages/pi-seep-ext"
spec = importlib.util.spec_from_file_location("merge_config_review", SCRIPT)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


class MergeConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep config ")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "workbench"
        (self.root / "Tool/config").mkdir(parents=True)
        self.manifest = self.root / "Tool/config/mcp-servers.json"
        self.manifest.write_text(json.dumps({"servers": {"seep": {
            "command": "python", "args": ["{ROOT_POSIX}/Tool/mcp/server.py"]}}}), encoding="utf-8")
        # 安装器会把随仓库分发的原包副本同步进 AgentRoot；夹具里必须有这份源。
        shutil.copytree(REAL_PERSONA_PKG, self.root / "Tool/prompts/packages/pi-seep-ext",
                        ignore=shutil.ignore_patterns("__pycache__"))
        self.agent = Path(self.tmp.name) / "agent"

    def cli(self, *args):
        return subprocess.run([sys.executable, "-X", "utf8", str(SCRIPT), "--root", str(self.root),
                               "--agent-dir", str(self.agent), *args],
                              capture_output=True, text=True, encoding="utf-8", timeout=15)

    def settings_args(self):
        return SimpleNamespace(agent_dir=str(self.agent), dry_run=False, print_only=False)

    def test_preview_does_not_create_agent_root(self):
        for flag in ("--dry-run", "--print"):
            with self.subTest(flag=flag):
                result = self.cli(flag)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(self.agent.exists())

    def test_missing_source_manifest_is_failure_without_destination_write(self):
        self.manifest.unlink()
        result = self.cli()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.agent / "mcp.json").exists())

    def test_retry_only_change_is_saved(self):
        self.agent.mkdir()
        settings = self.agent / "settings.json"
        settings.write_text(json.dumps({"packages": M.WORKBENCH_PACKAGES, "user": "keep"}), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            M.merge_settings_json(self.settings_args())
        saved = json.loads(settings.read_text())
        self.assertIn("retry", saved)
        self.assertEqual(saved["user"], "keep")

    def test_object_package_entry_is_preserved(self):
        self.agent.mkdir()
        settings = self.agent / "settings.json"
        custom = {"source": "npm:custom-package", "extensions": []}
        settings.write_text(json.dumps({"packages": [custom]}), encoding="utf-8")
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(custom, json.loads(settings.read_text())["packages"])

    def test_pair_only_reinstall_preserves_custom_packages_and_cards(self):
        self.agent.mkdir()
        settings = self.agent / "settings.json"
        custom = ["npm:user-one", {"source": "npm:pi-open-tui", "extensions": []}]
        original = {"packages": custom, "retry": {"maxRetries": 2}, "user": {"keep": True}}
        settings.write_text(json.dumps(original), encoding="utf-8")
        cards = self.agent / "personas"
        cards.mkdir()
        card = cards / "synthetic.md"
        card.write_bytes(b"synthetic persona\r\n")
        for _ in range(2):
            result = self.cli("--persona-rewind-only")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        expected = dict(original, packages=custom + [M.PERSONA_REWIND_PACKAGE])
        self.assertEqual(json.loads(settings.read_text()), expected)
        self.assertEqual(card.read_bytes(), b"synthetic persona\r\n")
        self.assertFalse((self.agent / "mcp.json").exists())
        self.assertFalse((self.agent / "personas.json").exists())
        # The full installation uses the same declaration and retains the filters.
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        saved = json.loads(settings.read_text())
        self.assertEqual(saved["packages"].count(M.PERSONA_REWIND_PACKAGE), 1)
        self.assertEqual(saved["packages"].count(custom[1]), 1)
        self.assertNotIn("npm:pi-open-tui", saved["packages"])
        self.assertEqual(saved["retry"], original["retry"])

    def test_bad_package_objects_fail_before_mcp_changes(self):
        self.agent.mkdir()
        settings = self.agent / "settings.json"
        mcp = self.agent / "mcp.json"
        mcp.write_bytes(b'{"mcpServers":{"user":{"command":"keep"}}}')
        before = mcp.read_bytes()
        bad = [{"source": 123}, {"source": "npm:custom", "extensions": "*.ts"},
               {"source": "npm:custom", "themes": [1]}]
        for item in bad:
            with self.subTest(item=item):
                raw = json.dumps({"packages": [item]}).encode()
                settings.write_bytes(raw)
                result = self.cli()
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(settings.read_bytes(), raw)
                self.assertEqual(mcp.read_bytes(), before)

    def test_uninstall_handles_managed_object_and_preserves_custom_object(self):
        self.agent.mkdir()
        settings = self.agent / "settings.json"
        custom = {"source": "npm:user-package", "extensions": []}
        settings.write_text(json.dumps({"packages": M.WORKBENCH_PACKAGES + [custom]}), encoding="utf-8")
        self.cli("--persona-rewind-only")
        self.assertTrue((self.agent / "packages/pi-seep-ext/package.json").is_file())
        result = self.cli("--remove-packages")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(settings.read_text())["packages"], [custom])
        self.assertFalse((self.agent / "packages/pi-seep-ext").exists(), "卸载必须同时清掉包目录")
        self.assertTrue(any(self.agent.glob("packages/pi-seep-ext.bak-*")), "清理前必须留备份")

    def test_pair_deploys_vendored_package_into_agent_root(self):
        self.agent.mkdir()
        settings = self.agent / "settings.json"
        # 用户已按对象形式声明过同一个本地包：不得再追加一条字符串声明
        settings.write_text(json.dumps({"packages": [{"source": M.PERSONA_REWIND_PACKAGE}]}), encoding="utf-8")
        result = self.cli("--persona-rewind-only")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(settings.read_text())["packages"], [{"source": M.PERSONA_REWIND_PACKAGE}])
        deployed = self.agent / "packages/pi-seep-ext"
        manifest = json.loads((deployed / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(manifest["pi"]["extensions"]), ["./extensions/persona.ts", "./extensions/rewind.ts"])
        self.assertTrue((deployed / "extensions/persona.ts").is_file())
        self.assertTrue((deployed / "extensions/rewind.ts").is_file())
        self.assertFalse((deployed / "extensions/remote.ts").exists())
        # 用户在包目录里自建的文件不受影响，重装也不产生第二份声明
        (deployed / "USER-NOTES.md").write_text("keep" + chr(10), encoding="utf-8")
        result = self.cli("--persona-rewind-only")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((deployed / "USER-NOTES.md").read_text(encoding="utf-8"), "keep" + chr(10))
        self.assertEqual(json.loads(settings.read_text())["packages"], [{"source": M.PERSONA_REWIND_PACKAGE}])
    def test_missing_vendored_package_fails_before_writing(self):
        self.agent.mkdir()
        settings = self.agent / "settings.json"
        settings.write_text(json.dumps({"packages": ["npm:keep"]}), encoding="utf-8")
        before = settings.read_bytes()
        missing = self.root / "Tool/prompts/packages/pi-seep-ext"
        shutil.move(str(missing), str(missing) + ".away")
        try:
            result = self.cli("--persona-rewind-only")
        finally:
            shutil.move(str(missing) + ".away", str(missing))
        self.assertNotEqual(result.returncode, 0, "缺少原包副本必须失败，而不是装出一个少两个扩展的环境")
        self.assertEqual(settings.read_bytes(), before)

    def test_invalid_nested_mcp_configuration_is_preserved(self):
        self.agent.mkdir()
        mcp = self.agent / "mcp.json"
        original = b'{"mcpServers": ["user malformed entry"]}\n'
        mcp.write_bytes(original)
        result = self.cli()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(mcp.read_bytes(), original)

    def test_invalid_settings_does_not_partially_update_mcp(self):
        self.agent.mkdir()
        mcp = self.agent / "mcp.json"
        original = b'{"mcpServers": {"user": {"command": "custom"}}}\n'
        mcp.write_bytes(original)
        (self.agent / "settings.json").write_text('{"packages": "invalid"}', encoding="utf-8")
        result = self.cli()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(mcp.read_bytes(), original)

    def test_backup_names_do_not_collide_within_one_second(self):
        self.agent.mkdir()
        path = self.agent / "settings.json"
        path.write_text("first", encoding="utf-8")
        first = M.backup(str(path))
        path.write_text("second", encoding="utf-8")
        second = M.backup(str(path))
        self.assertNotEqual(first, second)
        self.assertEqual(Path(first).read_text(), "first")
        self.assertEqual(Path(second).read_text(), "second")

    def test_failed_atomic_replace_leaves_original_intact(self):
        self.agent.mkdir()
        path = self.agent / "settings.json"
        path.write_bytes(b'{"user":"original"}')
        with mock.patch.object(M.os, "replace", side_effect=OSError("fixture locked")):
            with self.assertRaises(OSError):
                M.write_json(str(path), {"new": True})
        self.assertEqual(path.read_bytes(), b'{"user":"original"}')

    def test_root_expansion_preserves_json_escaping(self):
        raw = self.manifest.read_text()
        with mock.patch("builtins.open", return_value=io.StringIO(raw)):
            entries = M.build_mcp_entries('/tmp/a "quoted" root', {}, False)
        expected = M.posix(os.path.abspath('/tmp/a "quoted" root')) + "/Tool/mcp/server.py"
        self.assertEqual(entries["seep"]["args"], [expected])

    def test_install_validation_is_read_only_and_rejects_prompt_boundary_errors(self):
        prompts = self.root / 'Tool/prompts'
        prompts.mkdir(exist_ok=True)  # setUp 已建出 Tool/prompts/packages
        for name in ('AGENTS.md', 'SEEP.md'):
            (prompts / name).write_text('source rules', encoding='utf-8')
        result = self.cli('--validate-only')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.agent.exists())
        self.agent.mkdir()
        bad = self.agent / 'AGENTS.md'
        bad.write_text('<!-- seep:managed:begin -->unfinished', encoding='utf-8')
        before = bad.read_bytes()
        result = self.cli('--validate-only')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(bad.read_bytes(), before)
        self.assertEqual(len(list(self.agent.iterdir())), 1)

    def test_remove_prompts_validates_both_real_sources_before_writing_either(self):
        prompts = self.root / 'Tool/prompts'
        for name in ('AGENTS.md', 'SEEP.md'):
            shutil.copy2(SCRIPT.parent.parent / 'Tool/prompts' / name, prompts / name)
        self.agent.mkdir()
        begin, end = '<!-- seep:managed:begin -->', '<!-- seep:managed:end -->'
        for name in ('AGENTS.md', 'SEEP.md'):
            source = (prompts / name).read_text(encoding='utf-8')
            (self.agent / name).write_text(begin + '\n' + source + '\n' + end + '\nUSER TAIL\n', encoding='utf-8')
        source = (prompts / 'SEEP.md').read_text(encoding='utf-8')
        block = begin + source + end
        for bad in (block + block, begin + source, source + end, end + source + begin,
                    '<!-- seep:managed:broken -->' + source + end,
                    block + '<!-- seep:managed:broken -->'):
            with self.subTest(boundary=bad[:60]):
                (self.agent / 'SEEP.md').write_text(bad + '\nUSER TAIL\n', encoding='utf-8')
                before = {p.name: p.read_bytes() for p in self.agent.iterdir()}
                result = self.cli('--remove-prompts-only')
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('invalid managed prompt boundary: SEEP.md', result.stdout)
                self.assertEqual({p.name: p.read_bytes() for p in self.agent.iterdir()}, before)

    def test_prompt_publish_failure_restores_other_prompt_package_and_ownership(self):
        for name in ('AGENTS.md', 'SEEP.md'):
            (self.root / 'Tool/prompts' / name).write_text('original source', encoding='utf-8')
        installed = self.cli('--prompts-only')
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        for name in ('AGENTS.md', 'SEEP.md'):
            with (self.agent / name).open('ab') as handle:
                handle.write(b'\r\nUSER TAIL\r\n')
            (self.root / 'Tool/prompts' / name).write_text('updated source', encoding='utf-8')
        license_path = self.root / M.PERSONA_PACKAGE_SOURCE_DIR / 'LICENSE'
        license_path.write_bytes(license_path.read_bytes() + b'\nupdated')
        for action in ('--prompts-only', '--remove-prompts-only'):
            with self.subTest(action=action):
                before = self.live_snapshot()
                actual = M.os.replace
                failed = False
                def fail_second_prompt(src, dst):
                    nonlocal failed
                    if Path(dst) == self.agent / 'SEEP.md' and not failed:
                        failed = True
                        raise OSError('synthetic second prompt publish failure')
                    return actual(src, dst)
                with mock.patch.object(M.os, 'replace', side_effect=fail_second_prompt):
                    with contextlib.redirect_stdout(io.StringIO()):
                        rc = M.main(['--root', str(self.root), '--agent-dir', str(self.agent), action])
                self.assertTrue(failed, 'must exercise a failure after the first prompt changes')
                self.assertEqual(rc, 1)
                self.assertEqual(self.live_snapshot(), before)

    def test_uninstall_atomic_failure_preserves_original(self):
        self.agent.mkdir()
        path = self.agent / 'settings.json'
        original = json.dumps({'packages': M.WORKBENCH_PACKAGES + [{'source': 'npm:custom'}]})
        path.write_text(original, encoding='utf-8')
        with mock.patch.object(M.os, 'replace', side_effect=OSError('fixture locked')):
            with contextlib.redirect_stdout(io.StringIO()):
                rc = M.main(['--root', str(self.root), '--agent-dir', str(self.agent), '--remove-packages'])
        self.assertEqual(rc, 1)
        self.assertEqual(path.read_text(encoding='utf-8'), original)

    def package_args(self):
        return SimpleNamespace(root=str(self.root), agent_dir=str(self.agent),
                               dry_run=False, print_only=False)

    def live_snapshot(self):
        return {p.relative_to(self.agent).as_posix(): p.read_bytes()
                for p in self.agent.rglob("*") if p.is_file()
                and not any(".bak-" in part for part in p.relative_to(self.agent).parts)}

    def install_package(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(M.main(["--root", str(self.root), "--agent-dir", str(self.agent),
                                     "--persona-rewind-only"]), 0)

    def test_each_missing_managed_dependency_fails_before_any_install_write(self):
        source = self.root / M.PERSONA_PACKAGE_SOURCE_DIR
        for rel, path in M._persona_package_files(str(source)):
            original = Path(path).read_bytes()
            Path(path).unlink()
            try:
                for flags in (("--persona-rewind-only",), ()):
                    with self.subTest(file=rel, flags=flags):
                        result = self.cli(*flags)
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        self.assertFalse(self.agent.exists())
            finally:
                Path(path).write_bytes(original)

    def test_pair_bad_settings_and_target_conflicts_are_read_only(self):
        self.agent.mkdir()
        settings = self.agent / "settings.json"
        for raw in (b'{broken', b'{"packages":{}}',
                    b'{"packages":[{"source":"./packages/pi-seep-ext","extensions":2}]}'):
            settings.write_bytes(raw)
            before = self.live_snapshot()
            result = self.cli("--persona-rewind-only")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(self.live_snapshot(), before)
            self.assertFalse((self.agent / "packages").exists())
        settings.write_text('{}', encoding='utf-8')
        blocked = self.agent / "packages"
        blocked.write_bytes(b'user file')
        before = self.live_snapshot()
        self.assertNotEqual(self.cli().returncode, 0)
        self.assertEqual(self.live_snapshot(), before)

    def test_unknown_or_user_modified_package_is_never_overwritten_or_claimed(self):
        target = self.agent / M.PERSONA_PACKAGE_TARGET_DIR
        target.mkdir(parents=True)
        original = target / 'LICENSE'
        original.write_bytes(b'user content')
        before = self.live_snapshot()
        self.assertNotEqual(self.cli('--persona-rewind-only').returncode, 0)
        self.assertEqual(self.live_snapshot(), before)
        original.write_bytes((self.root / M.PERSONA_PACKAGE_SOURCE_DIR / 'LICENSE').read_bytes())
        self.install_package()
        manifest = json.loads((self.agent / 'seep-install-manifest.json').read_text())
        self.assertNotIn(M.PERSONA_PACKAGE_TARGET_DIR + '/LICENSE', manifest['managed_files'])
        (target / 'extensions/persona.ts').write_bytes(b'USER EDIT')
        before = self.live_snapshot()
        self.assertNotEqual(self.cli('--persona-rewind-only').returncode, 0)
        self.assertEqual(self.live_snapshot(), before)
        result = self.cli('--remove-packages')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(original.exists(), 'same source bytes without ownership must survive')
        self.assertEqual((target / 'extensions/persona.ts').read_bytes(), b'USER EDIT')

    def test_second_package_write_failure_restores_all_original_locations(self):
        self.install_package()
        target = self.agent / M.PERSONA_PACKAGE_TARGET_DIR
        (target / 'USER-NOTES.md').write_bytes(b'USER DATA')
        before = self.live_snapshot()
        source = self.root / M.PERSONA_PACKAGE_SOURCE_DIR
        for name in ('LICENSE', 'UPSTREAM.json'):
            path = source / name
            path.write_bytes(path.read_bytes() + b'\n')
        actual = M.os.replace
        calls = []
        def fail_second(src, dst):
            calls.append(str(dst))
            if len(calls) == 2:
                raise OSError('synthetic second-write failure')
            return actual(src, dst)
        with mock.patch.object(M.os, 'replace', side_effect=fail_second):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(OSError):
                    M.deploy_persona_package(self.package_args())
        self.assertGreaterEqual(len(calls), 3, 'must actually restore the first write')
        self.assertEqual(self.live_snapshot(), before)
        self.assertTrue(list(target.parent.glob('pi-seep-ext.bak-*')))

    def test_config_publish_failure_rolls_back_package_config_and_ownership(self):
        # First install, and an update with an existing declaration, both roll back.
        for installed in (False, True):
            if installed:
                self.install_package()
                path = self.root / M.PERSONA_PACKAGE_SOURCE_DIR / 'LICENSE'
                path.write_bytes(path.read_bytes() + b'\nupdated')
            before = self.live_snapshot()
            with mock.patch.object(M, 'merge_settings_json', side_effect=OSError('settings locked')):
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = M.main(['--root', str(self.root), '--agent-dir', str(self.agent),
                                 '--persona-rewind-only'])
            self.assertEqual(rc, 1)
            self.assertEqual(self.live_snapshot(), before)

    def test_rollback_failure_is_explicit_and_keeps_recovery_evidence(self):
        self.install_package()
        source = self.root / M.PERSONA_PACKAGE_SOURCE_DIR
        for name in ('LICENSE', 'UPSTREAM.json'):
            path = source / name
            path.write_bytes(path.read_bytes() + b'\n')
        actual = M.os.replace
        calls = []
        def fail_publish_and_restore(src, dst):
            calls.append(str(dst))
            if len(calls) >= 2:
                raise OSError('synthetic persistent lock')
            return actual(src, dst)
        with mock.patch.object(M.os, 'replace', side_effect=fail_publish_and_restore):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                rc = M.main(['--root', str(self.root), '--agent-dir', str(self.agent),
                             '--persona-rewind-only'])
        self.assertEqual(rc, 1)
        self.assertIn('rollback incomplete; evidence:', output.getvalue())
        backups = list((self.agent / 'packages').glob('pi-seep-ext.bak-*'))
        self.assertTrue(any((p / M.PERSONA_PACKAGE_TARGET_DIR / 'LICENSE').is_file() for p in backups))
        markers = [p / 'ROLLBACK-INCOMPLETE.json' for p in backups if (p / 'ROLLBACK-INCOMPLETE.json').exists()]
        self.assertTrue(markers)
        self.assertEqual(json.loads(markers[-1].read_text())['status'], 'rollback-incomplete')

    def test_failed_restore_marks_writable_shared_manifest_incomplete(self):
        self.install_package()
        manifest = self.agent / 'seep-install-manifest.json'
        cfg = json.loads(manifest.read_text())
        cfg['status'] = 'complete'
        manifest.write_text(json.dumps(cfg), encoding='utf-8')
        source = self.root / M.PERSONA_PACKAGE_SOURCE_DIR
        for name in ('LICENSE', 'UPSTREAM.json'):
            path = source / name
            path.write_bytes(path.read_bytes() + b'\n')
        actual = M.os.replace
        license_writes = []
        def lock_package_only(src, dst):
            dst = Path(dst)
            if dst.name == 'LICENSE':
                license_writes.append(dst)
                if len(license_writes) > 1:
                    raise PermissionError('restore locked')
            if dst.name == 'UPSTREAM.json':
                raise PermissionError('second write locked')
            return actual(src, dst)
        with mock.patch.object(M.os, 'replace', side_effect=lock_package_only):
            with contextlib.redirect_stdout(io.StringIO()):
                rc = M.main(['--root', str(self.root), '--agent-dir', str(self.agent),
                             '--persona-rewind-only'])
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(manifest.read_text())['status'], 'incomplete')

    def test_uninstall_delete_failure_restores_files_and_declarations(self):
        self.install_package()
        before = self.live_snapshot()
        actual = Path.unlink
        def deny_second_file(path, *args, **kwargs):
            if path == self.agent / M.PERSONA_PACKAGE_TARGET_DIR / 'UPSTREAM.json':
                raise PermissionError('synthetic delete lock')
            return actual(path, *args, **kwargs)
        with mock.patch.object(Path, 'unlink', deny_second_file):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                rc = M.main(['--root', str(self.root), '--agent-dir', str(self.agent), '--remove-packages'])
        self.assertEqual(rc, 1)
        self.assertEqual(self.live_snapshot(), before)
        self.assertNotIn('[OK] package operation complete', output.getvalue())

    def test_uninstall_survives_missing_source_and_preserves_local_filters_until_removal(self):
        self.agent.mkdir()
        local = {'source': M.PERSONA_REWIND_PACKAGE, 'extensions': [], 'autoload': False}
        other = {'source': 'npm:pi-open-tui', 'extensions': []}
        path = self.agent / 'settings.json'
        path.write_text(json.dumps({'packages': [local, other]}), encoding='utf-8')
        self.install_package()
        self.assertEqual(json.loads(path.read_text())['packages'], [local, other])
        shutil.rmtree(self.root / M.PERSONA_PACKAGE_SOURCE_DIR)
        self.manifest.unlink()
        result = self.cli('--remove-packages')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(path.read_text())['packages'], [other])
        self.assertFalse((self.agent / M.PERSONA_PACKAGE_TARGET_DIR).exists())

    def test_dependency_escape_and_manifest_target_escape_fail_before_writes(self):
        source = self.root / M.PERSONA_PACKAGE_SOURCE_DIR
        entry = source / 'extensions/persona.ts'
        original = entry.read_bytes()
        entry.write_text(entry.read_text(encoding='utf-8') + '\nimport "../../../outside.ts";\n', encoding='utf-8')
        self.assertNotEqual(self.cli('--persona-rewind-only').returncode, 0)
        self.assertFalse(self.agent.exists())
        entry.write_bytes(original)
        self.agent.mkdir()
        manifest = {'schema': 'seep-agent-install/1', 'source_root': str(self.root.resolve()),
                    'managed_files': {'packages/pi-seep-ext/../../../outside': '0' * 64}}
        (self.agent / 'seep-install-manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
        before = self.live_snapshot()
        self.assertNotEqual(self.cli('--remove-packages').returncode, 0)
        self.assertEqual(self.live_snapshot(), before)

    def test_full_merge_manifest_publish_failure_restores_mcp_settings_and_package(self):
        self.install_package()
        (self.agent / 'mcp.json').write_bytes(b'{"mcpServers":{"custom":{"command":"keep"}}}')
        source = self.root / M.PERSONA_PACKAGE_SOURCE_DIR / 'LICENSE'
        source.write_bytes(source.read_bytes() + b'\nupdated')
        before = self.live_snapshot()
        actual = M.os.replace
        manifest = self.agent / 'seep-install-manifest.json'
        def deny_manifest(src, dst):
            if Path(dst) == manifest:
                raise PermissionError('manifest publication locked')
            return actual(src, dst)
        with mock.patch.object(M.os, 'replace', side_effect=deny_manifest):
            with contextlib.redirect_stdout(io.StringIO()):
                rc = M.main(['--root', str(self.root), '--agent-dir', str(self.agent)])
        self.assertEqual(rc, 1)
        self.assertEqual(self.live_snapshot(), before)

    def test_backup_failure_does_not_publish_package_or_config(self):
        self.install_package()
        source = self.root / M.PERSONA_PACKAGE_SOURCE_DIR / 'LICENSE'
        source.write_bytes(source.read_bytes() + b'\nupdated')
        before = self.live_snapshot()
        actual = Path.write_bytes
        def deny_backup(path, data):
            if any('.bak-' in part for part in path.parts):
                raise PermissionError('backup locked')
            return actual(path, data)
        with mock.patch.object(Path, 'write_bytes', deny_backup):
            with contextlib.redirect_stdout(io.StringIO()):
                rc = M.main(['--root', str(self.root), '--agent-dir', str(self.agent),
                             '--persona-rewind-only'])
        self.assertEqual(rc, 1)
        self.assertEqual(self.live_snapshot(), before)

    def test_target_junction_is_rejected_before_changes(self):
        if os.name != 'nt':
            self.skipTest('Windows junction probe')
        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        (outside / 'LICENSE').write_bytes(b'outside user data')
        link = self.agent / 'packages'
        self.agent.mkdir()
        result = subprocess.run(['cmd', '/d', '/c', 'mklink', '/J', str(link), str(outside)],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        try:
            result = self.cli('--persona-rewind-only')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((outside / 'LICENSE').read_bytes(), b'outside user data')
            self.assertFalse((outside / 'pi-seep-ext').exists())
        finally:
            link.rmdir()

    def test_conflicting_action_flags_fail_without_writing(self):
        self.agent.mkdir()
        path = self.agent / 'settings.json'
        original = json.dumps({'packages': M.WORKBENCH_PACKAGES, 'user': 'keep'})
        path.write_text(original, encoding='utf-8')
        for flags in (('--validate-only', '--remove-packages'),
                      ('--validate-configs-only', '--remove-packages'),
                      ('--agents-only', '--prompts-only')):
            with self.subTest(flags=flags):
                result = self.cli(*flags)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(path.read_text(encoding='utf-8'), original)
                self.assertEqual(list(self.agent.iterdir()), [path])


if __name__ == "__main__":
    unittest.main()
