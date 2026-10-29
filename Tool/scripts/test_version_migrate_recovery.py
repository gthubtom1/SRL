#!/usr/bin/env python3
"""Reverse-baseline transactions: synthetic files, real writes and process exits."""
from __future__ import annotations

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
from unittest import mock

import test_version_migrate_delivery as D


class VersionMigrateRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-reverse-recovery-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base / "source.bin"
        self.source.write_bytes(b"A\x10\x20\x30B")
        self.new = self.base / "new.bin"
        self.new.write_bytes(b"C\x10\x20\x30D")
        spec = importlib.util.spec_from_file_location("reverse_recovery_test", D.REAL_SCRIPT)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.assertIsNone(self.module._BOOTSTRAP_ERROR)

    def files(self, root):
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*")
                if p.is_file() and p.name != ".project.lock"}

    def directories(self, root):
        return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_dir()}

    def arguments(self, operation, case):
        common = ["--case", str(case)]
        if operation == "init":
            return ["init", *common, "--version", "1.0", "--file", str(self.source)]
        if operation == "legacy":
            return ["add-site", *common, "--version", "1.0", "--file", str(self.source),
                    "--id", "site", "--sem", "synthetic", "--aob", "10 20 30"]
        return ["align", *common, "--old", "1.0", "--new", str(self.new), "--new-version", "1.1"]

    def prepare(self, operation, case):
        case.mkdir()
        (case / "keep.txt").write_bytes(b"unrelated project data")
        if operation == "legacy":
            path = case / "versions/1.0/manifest.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps({"schema": self.module.LEGACY_SCHEMA, "version": "1.0",
                                        "binary": self.module.fingerprint(str(self.source)), "sites": []}),
                            encoding="utf-8")
        elif operation == "align":
            result = D.init_version(case, "1.0", self.source)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = D.run_cli(D.REAL_SCRIPT, "add-site", "--case", str(case), "--version", "1.0",
                               "--file", str(self.source), "--id", "site", "--sem", "synthetic",
                               "--aob", "10 20 30")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = D.run_cli(D.REAL_SCRIPT, *self.arguments(operation, case))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            # A previous orphan is restored on failure rather than silently lost.
            path = case / "versions/1.0/reverse-target/source.bin"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"previous orphan")

    def invoke(self, args):
        output = io.StringIO()
        with mock.patch.object(sys, "argv", [str(D.REAL_SCRIPT), *args]), contextlib.redirect_stdout(output):
            code = self.module.main()
        return code, output.getvalue()

    def test_write_failure_in_each_operation_restores_bytes_and_directories_and_allows_retry(self):
        for operation, stages in (("init", ("copy", "baseline")),
                                  ("legacy", ("copy", "baseline")),
                                  ("align", ("revision", "latest"))):
            seed = self.base / (operation + "-seed")
            self.prepare(operation, seed)
            for stage in stages:
                with self.subTest(operation=operation, stage=stage):
                    case = self.base / (operation + "-" + stage)
                    shutil.copytree(seed, case)
                    before, directories = self.files(case), self.directories(case)
                    name = "atomic_copy" if stage == "copy" else "save_json"
                    real = getattr(self.module, name)
                    def interrupt(*args, stage=stage, real=real, **kwargs):
                        real(*args, **kwargs)
                        path = Path(args[1] if stage == "copy" else args[0])
                        if (stage in ("copy", "baseline") or stage == "revision" and path.parent.name == "align-revisions"
                                or stage == "latest" and path.name == "align.json"):
                            raise OSError("synthetic interruption after real write")
                    with mock.patch.object(self.module, name, side_effect=interrupt):
                        code, output = self.invoke(self.arguments(operation, case))
                    self.assertEqual(code, 2, output)
                    self.assertEqual(self.files(case), before, operation + "/" + stage)
                    self.assertEqual(self.directories(case), directories)
                    code, output = self.invoke(self.arguments(operation, case))
                    self.assertEqual(code, 0, output)
                    self.assertNotIn(".project-transaction.json", self.files(case))
                    if operation == "legacy":
                        self.assertEqual((case / "versions/1.0/manifest.json").read_bytes(),
                                         before["versions/1.0/manifest.json"])

    def test_process_exit_then_read_refusal_and_same_command_retry_for_all_three_operations(self):
        code = """import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("interrupted_reverse", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
real = m.save_json
def interrupt(*args, **kwargs):
    real(*args, **kwargs)
    os._exit(76)
m.save_json = interrupt
sys.argv = sys.argv[1:]
raise SystemExit(m.main())
"""
        for operation in ("init", "legacy", "align"):
            with self.subTest(operation=operation):
                case = self.base / (operation + "-exit")
                self.prepare(operation, case)
                result = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", code,
                                         str(D.REAL_SCRIPT), *self.arguments(operation, case)],
                                        env=D.child_env(), capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 76, result.stderr)
                interrupted = self.files(case)
                self.assertIn(".project-transaction.json", interrupted)
                result = D.run_cli(D.REAL_SCRIPT, "report", "--case", str(case),
                                   "--old", "1.0", "--new-version", "1.1")
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(self.files(case), interrupted)
                result = D.run_cli(D.REAL_SCRIPT, *self.arguments(operation, case))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn(".project-transaction.json", self.files(case))
                if operation == "align":
                    self.assertEqual(len(list((case / "versions/1.1/align-revisions").glob("*.json"))), 2)
                    latest = (case / "versions/1.1/align.json").read_bytes()
                    self.assertIn(latest, [p.read_bytes() for p in
                                          (case / "versions/1.1/align-revisions").glob("*.json")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
