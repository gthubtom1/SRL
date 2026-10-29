#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Seep Reverse Lab — 上游定点隔离同步与防外溢机制单元测试
"""

import os
import sys
import unittest
import contextlib
import io
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(__file__))
import importlib.util

spec = importlib.util.spec_from_file_location(
    "sync_upstream",
    os.path.join(os.path.dirname(__file__), "sync-upstream.py")
)
sync_upstream_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sync_upstream_mod)

SpilloverSecurityViolation = sync_upstream_mod.SpilloverSecurityViolation
assert_within_boundary = sync_upstream_mod.assert_within_boundary
load_rules = sync_upstream_mod.load_rules
matches_any_pattern = sync_upstream_mod.matches_any_pattern


class TestSyncUpstreamBoundary(unittest.TestCase):
    def setUp(self):
        self.root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    def test_within_boundary_allowed(self):
        # 正常同目录写入
        boundary = "Tool/upstream/apk-reverse"
        valid_file = "Tool/upstream/apk-reverse/src/main.py"
        # 应该正常通过，不抛出异常
        try:
            assert_within_boundary(valid_file, boundary, self.root_dir)
        except SpilloverSecurityViolation:
            self.fail("assert_within_boundary raised SpilloverSecurityViolation unexpectedly!")

    def test_spillover_to_sibling_blocked(self):
        # 试图从 A 溢出写入到 B 目录
        boundary = "Tool/upstream/apk-reverse"
        sibling_file = "Tool/upstream/open-tgtylab/hacked.txt"
        with self.assertRaises(SpilloverSecurityViolation):
            assert_within_boundary(sibling_file, boundary, self.root_dir)

    def test_spillover_path_traversal_blocked(self):
        # 试图通过 ../ 跨越目录
        boundary = "Tool/upstream/apk-reverse"
        traversal_file = "Tool/upstream/apk-reverse/../../cases/evil.py"
        with self.assertRaises(SpilloverSecurityViolation):
            assert_within_boundary(traversal_file, boundary, self.root_dir)

    def test_spillover_to_root_blocked(self):
        # 试图写入根目录文件
        boundary = "Tool/upstream/apk-reverse"
        root_file = "README.md"
        with self.assertRaises(SpilloverSecurityViolation):
            assert_within_boundary(root_file, boundary, self.root_dir)

    def test_pattern_matching(self):
        excludes = [".git/**", ".github/**", "**/node_modules/**", "**/*.pyc"]
        self.assertTrue(matches_any_pattern(".git/config", excludes))
        self.assertTrue(matches_any_pattern(".github/workflows/ci.yml", excludes))
        self.assertTrue(matches_any_pattern("lib/node_modules/pkg/index.js", excludes))
        self.assertTrue(matches_any_pattern("src/__pycache__/foo.cpython-311.pyc", excludes))
        self.assertFalse(matches_any_pattern("src/main.py", excludes))

    def test_rules_manifest_integrity(self):
        rules_path = os.path.join(os.path.dirname(__file__), "upstream-rules.json")
        rules = load_rules(rules_path)
        self.assertIn("upstreams", rules)
        for key, conf in rules["upstreams"].items():
            self.assertIn("repo", conf)
            self.assertIn("target_dir", conf)
            self.assertIn("allowed_boundary", conf)
            self.assertEqual(conf["target_dir"], conf["allowed_boundary"],
                             f"Target dir and boundary should match for sandboxing in {key}")


class TestSyncExecution(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-sync-test-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "workbench with spaces"
        (self.root / "setup").mkdir(parents=True)
        self.source = self.base / "local upstream"
        self.source.mkdir()
        for args in (("init", "-b", "main"), ("config", "user.email", "fixture@example.invalid"),
                     ("config", "user.name", "Fixture")):
            self.git(*args)
        (self.source / "payload.txt").write_text("upstream payload\n", encoding="utf-8")
        (self.source / "README.md").write_text("upstream readme\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-m", "fixture")
        self.rule = {"repo": str(self.source), "branch": "main",
                     "target_dir": "Tool/upstream/fixture", "allowed_boundary": "Tool/upstream/fixture",
                     "preserve_local": ["README.md"]}

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.source, capture_output=True,
                              text=True, encoding="utf-8", timeout=15, check=True).stdout.strip()

    def run_main(self, rules=None, *args):
        (self.root / "setup/upstream-rules.json").write_text(
            json.dumps({"upstreams": rules or {"fixture": self.rule}}), encoding="utf-8")
        out = io.StringIO()
        with mock.patch.object(sync_upstream_mod, "get_root_dir", return_value=str(self.root)), \
                mock.patch.object(sync_upstream_mod, "detect_proxy", return_value=None), \
                mock.patch.object(sys, "argv", ["sync-upstream.py", *args]), contextlib.redirect_stdout(out):
            try:
                sync_upstream_mod.main()
            except SystemExit as exc:
                return exc.code, out.getvalue()
        return 0, out.getvalue()

    def test_clone_failure_is_failure_and_does_not_write_cache(self):
        self.rule["repo"] = str(self.base / "missing-repository")
        code, output = self.run_main()
        self.assertEqual(code, 1, output)
        self.assertFalse((self.root / "setup/.upstream-shas.json").exists())

    def test_check_only_query_failure_is_not_update_available(self):
        self.rule["repo"] = str(self.base / "missing-repository")
        code, output = self.run_main(None, "--check-only")
        self.assertEqual(code, 1, output)
        self.assertNotIn("检测到上游仓库有新版本发布", output)

    def test_manual_source_is_skipped_without_network_or_clone(self):
        self.rule.update(sync="manual", repo="(vendored copy)",
                         target_dir="Tool/mcp/Tool/reverselab", allowed_boundary="Tool/mcp/Tool/reverselab")
        with mock.patch.object(sync_upstream_mod, "get_remote_head_sha") as remote:
            code, output = self.run_main()
        self.assertEqual(code, 0, output)
        remote.assert_not_called()

    def test_rule_cannot_choose_boundary_outside_upstream_before_any_write(self):
        outside = self.base / "outside"
        self.rule.update(target_dir=str(outside), allowed_boundary=str(outside))
        code, output = self.run_main()
        self.assertNotEqual(code, 0, output)
        self.assertFalse(outside.exists(), output)

    def test_matching_cached_sha_does_not_hide_missing_local_payload(self):
        (self.root / "setup/.upstream-shas.json").write_text(
            json.dumps({"fixture": self.git("rev-parse", "HEAD")}), encoding="utf-8")
        code, output = self.run_main()
        self.assertEqual(code, 0, output)
        self.assertEqual((self.root / "Tool/upstream/fixture/payload.txt").read_text(), "upstream payload\n")

    def test_cache_records_cloned_revision_and_preserves_local_readme(self):
        target = self.root / "Tool/upstream/fixture"
        target.mkdir(parents=True)
        (target / "README.md").write_text("local customization\n", encoding="utf-8")
        with mock.patch.object(sync_upstream_mod, "get_remote_head_sha", return_value="0" * 40):
            code, output = self.run_main()
        self.assertEqual(code, 0, output)
        cache = json.loads((self.root / "setup/.upstream-shas.json").read_text())
        self.assertEqual(cache["fixture"], self.git("rev-parse", "HEAD"))
        self.assertEqual((target / "README.md").read_text(), "local customization\n")

    def test_pr_body_does_not_invent_validation_results(self):
        out = self.base / "body.md"
        sync_upstream_mod.write_pr_body(str(out), "fixture")
        body = out.read_text(encoding="utf-8")
        self.assertNotIn("100%", body)
        self.assertNotIn("✅ 已执行", body)


class TestSyncDrivers(unittest.TestCase):
    def run_driver(self, shell, engine_code=0, check_code=19, *args):
        with tempfile.TemporaryDirectory(prefix="seep sync driver ") as tmp:
            root = Path(tmp)
            setup = root / "setup"
            scripts = root / "Tool/scripts"
            setup.mkdir()
            scripts.mkdir(parents=True)
            name = "sync-upstream." + ("ps1" if shell == "powershell" else "sh")
            shutil.copy2(Path(__file__).parent / name, setup / name)
            (setup / "sync-upstream.py").write_text(f"raise SystemExit({engine_code})\n", encoding="utf-8")
            (setup / "clean-format.py").write_text(
                "raise RuntimeError('sync must not rewrite unrelated files')\n", encoding="utf-8")
            (scripts / "check.py").write_text(
                "from pathlib import Path\nimport sys\n"
                "assert sys.argv[1:] == ['--env']\n"
                "Path(__file__).with_name('ran').write_text('checked')\n"
                f"raise SystemExit({check_code})\n", encoding="utf-8")
            if shell == "powershell":
                cmd = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]
            else:
                bash = shutil.which("bash")
                if not bash and os.name == "nt" and shutil.which("git"):
                    bash = str(Path(shutil.which("git")).resolve().parent.parent / "bin/bash.exe")
                if not bash or not Path(bash).is_file():
                    self.skipTest("Bash unavailable")
                cmd = [bash]
            result = subprocess.run([*cmd, str(setup / name), *args], cwd=root,
                                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=25)
            return result, (scripts / "ran").exists()

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell driver")
    def test_powershell_runs_check_and_propagates_its_failure(self):
        result, checked = self.run_driver("powershell")
        self.assertTrue(checked, result.stdout + result.stderr)
        self.assertEqual(result.returncode, 19, result.stdout + result.stderr)

    def test_shell_runs_check_and_propagates_its_failure(self):
        result, checked = self.run_driver("bash")
        self.assertTrue(checked, result.stdout + result.stderr)
        self.assertEqual(result.returncode, 19, result.stdout + result.stderr)

    def test_shell_check_only_preserves_update_available_status(self):
        result, checked = self.run_driver("bash", 2, 0, "--check-only")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(checked)


if __name__ == "__main__":
    unittest.main()
