"""Configuration merging must preserve user files and report incomplete installs."""
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

SCRIPT = Path(__file__).with_name("merge_agent_config.py")
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
        prompts.mkdir()
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
