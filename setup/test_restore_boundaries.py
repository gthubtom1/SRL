"""Restore entrypoints must validate a complete backup before writing anything."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from Tool.scripts import test_runtime_install_delivery as ps
from Tool.scripts import test_runtime_shell_delivery as sh


class RestoreBoundaries(unittest.TestCase):
    def setUp(self):
        scratch = Path(__file__).resolve().parents[1] / "tmp/sol-final-audit"
        scratch.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="restore-", dir=scratch)
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def run_entry(self, platform, wb, agent, backup, dry_run=False):
        env = ps.isolated_environment(self.base)
        if platform == "powershell":
            return ps.run_ps(wb / "setup/uninstall.ps1", "-AgentRoot", str(agent),
                             "-Restore", str(backup), *(["-DryRun"] if dry_run else []), env=env)
        return sh.run_bash(wb / "setup/uninstall.sh", "--agent-root", str(agent),
                           "--restore", str(backup), *(["--dry-run"] if dry_run else []), env=env)

    def link_directory(self, path, target):
        if os.name == "nt":
            result = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(path), str(target)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            path.symlink_to(target, target_is_directory=True)

    def assert_link_rejected(self, platform, *, source=False):
        wb = (ps.build_workbench if platform == "powershell" else sh.build_fixture)(self.base)
        agent, backup, outside = (self.base / name for name in ("agent", "backup", "outside"))
        for directory in (agent, backup, outside):
            directory.mkdir()
        (agent / "a-safe.txt").write_bytes(b"original live file")
        (backup / "a-safe.txt").write_bytes(b"backup file")
        (outside / "user.txt").write_bytes(b"external user data")
        if source:
            link = backup / "z-linked"
            self.link_directory(link, outside)
        else:
            (backup / "z-linked").mkdir()
            (backup / "z-linked/user.txt").write_bytes(b"must not escape")
            link = agent / "z-linked"
            self.link_directory(link, outside)
        try:
            result = self.run_entry(platform, wb, agent, backup)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((outside / "user.txt").read_bytes(), b"external user data")
            self.assertEqual((agent / "a-safe.txt").read_bytes(), b"original live file")
            if source:
                self.assertFalse((agent / "z-linked/user.txt").exists())
        finally:
            if os.name == "nt":
                link.rmdir()
            else:
                link.unlink()

    def test_powershell_rejects_linked_destination_before_any_writes(self):
        self.assert_link_rejected("powershell")

    def test_bash_rejects_linked_destination_before_any_writes(self):
        self.assert_link_rejected("bash")

    def test_powershell_rejects_linked_backup_before_any_writes(self):
        self.assert_link_rejected("powershell", source=True)

    def test_bash_rejects_linked_backup_before_any_writes(self):
        self.assert_link_rejected("bash", source=True)

    def test_both_entrypoints_restore_relative_unicode_backup_and_preview_is_read_only(self):
        for platform in ("powershell", "bash"):
            with self.subTest(platform=platform):
                base = self.base / platform
                base.mkdir()
                wb = (ps.build_workbench if platform == "powershell" else sh.build_fixture)(base)
                agent = base / "agent"
                backup = wb / "备份 with spaces"
                (backup / "empty").mkdir(parents=True)
                (backup / "extensions").mkdir()
                payload = b"original\r\n\x00binary\xff"
                (backup / "extensions/fixture.ts").write_bytes(payload)
                result = self.run_entry(platform, wb, agent, Path(backup.name), dry_run=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(agent.exists())
                result = self.run_entry(platform, wb, agent, Path(backup.name))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((agent / "extensions/fixture.ts").read_bytes(), payload)
                self.assertTrue((agent / "empty").is_dir())


if __name__ == "__main__":
    unittest.main()
