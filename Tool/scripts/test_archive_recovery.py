#!/usr/bin/env python3
"""Real process exits around archive publication; all project data is synthetic."""
from __future__ import annotations

import contextlib
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

import test_project_archive as F


class ArchiveRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = F.ArchiveFixture()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.base = self.fixture.base
        self.project = self.fixture.make_project("pending")

    def files(self, root):
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*")
                if p.is_file() and p.name != ".project.lock"}

    def child(self, mode, stage, archive, destination):
        code = """import os, sys
sys.path.insert(0, sys.argv[1])
import project_archive as A
mode, stage, archive, destination = sys.argv[2:]
name = {"extract": "_extract_to_staging", "validate": "_validate_staging",
        "publish": "rename" if mode == "import" else "_publish_new_file"}[stage]
owner = A.os if mode == "import" and stage == "publish" else A
real = getattr(owner, name)
def interrupt(*args, **kwargs):
    real(*args, **kwargs)
    os._exit(78)
setattr(owner, name, interrupt)
args = A.argparse.Namespace()
if mode == "import":
    A.import_archive(archive, destination, args)
else:
    A.export_archive(destination, archive, args)
"""
        return subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", code,
                               str(F.ARCHIVE.parent), mode, stage, str(archive), str(destination)],
                              env=F.ENV, capture_output=True, timeout=45)

    def test_import_exit_before_and_after_publish_preserves_source_and_safe_retry(self):
        archive = self.base / "transport.zip"
        code, payload, _ = F.invoke(F.ARCHIVE, "export", "--project", self.project, "--out", archive)
        self.assertEqual(code, 0, payload)
        original = self.files(self.project)
        for stage in ("extract", "validate", "publish"):
            with self.subTest(stage=stage):
                parent = self.base / stage
                parent.mkdir()
                destination = parent / "restored"
                result = self.child("import", stage, archive, destination)
                self.assertEqual(result.returncode, 78, result.stderr)
                self.assertEqual(self.files(self.project), original)
                residual = {p.name: self.files(p) for p in parent.glob(".seep-archive-staging-*")}
                code, payload, _ = F.invoke(F.ARCHIVE, "import", "--archive", archive,
                                            "--project", destination)
                self.assertEqual(code, 2 if stage == "publish" else 0, payload)
                # Unknown abandoned directories are never reused or automatically deleted.
                self.assertEqual({p.name: self.files(p) for p in parent.glob(".seep-archive-staging-*")}, residual)
                self.assertEqual(bool(residual), stage != "publish")
                code, payload, _ = F.invoke(F.STATE, "resume", "--project", destination)
                self.assertEqual(code, 0, payload)
                code, payload, _ = F.invoke(F.REPORT, "status", "--project", destination)
                self.assertEqual(code, 0, payload)

    def test_import_implicit_parent_io_failure_cleans_staging_and_allows_short_retry(self):
        import project_archive as A
        from unittest.mock import patch
        archive = self.fixture.export(self.project)
        # Older archives can omit the directories list. Force the mkdir that
        # belongs to a file's implicit parent, rather than declared directories.
        def omit_directories(manifest, entries):
            manifest.pop("directories", None)
        archive = self.fixture.rewrite(archive, "implicit-parents.zip", omit_directories)
        archive_before = archive.read_bytes()
        source_before = self.files(self.project)
        real_mkdir = Path.mkdir
        for error_number in (2, 36):  # legacy long paths may appear as ENOENT
            with self.subTest(errno=error_number):
                parent = self.base / ("io-failure-%d" % error_number)
                parent.mkdir()
                destination = parent / "restored"
                touched = []
                def fail_parent(path, *args, **kwargs):
                    if path.name == "capture" and A.STAGING_PREFIX in str(path):
                        touched.append(str(path))
                        raise OSError(error_number, "synthetic directory failure")
                    return real_mkdir(path, *args, **kwargs)
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(Path, "mkdir", new=fail_parent), \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    code = A.main(["import", "--archive", str(archive),
                                   "--project", str(destination)])
                payload = json.loads(stdout.getvalue())
                self.assertEqual(code, 2, payload)
                self.assertFalse(payload["ok"])
                self.assertIn("ZIP 成员展开失败", payload["reason"])
                self.assertEqual(stderr.getvalue(), "")
                self.assertTrue(touched)
                self.assertFalse(destination.exists())
                self.assertFalse(list(parent.glob(A.STAGING_PREFIX + "*")))
                code, payload, _ = self.fixture.import_bundle(archive, destination)
                self.assertEqual(code, 0, payload)
                self.fixture.state(destination, "resume")
                self.fixture.report(destination, "status")
        self.assertEqual(archive.read_bytes(), archive_before)
        self.assertEqual(self.files(self.project), source_before)

    def test_planned_staging_collision_preserves_unknown_tree_and_retries_safely(self):
        import project_archive as A
        from unittest.mock import patch
        archive = self.fixture.export(self.project)
        parent = self.base / "collision"
        parent.mkdir()
        unknown = parent / (A.STAGING_PREFIX + "deadbeef")
        unknown.mkdir()
        sentinel = unknown / "keep.bin"
        sentinel.write_bytes(b"unknown staging data must survive")
        destination = parent / "restored"
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(A.secrets, "token_hex", return_value="deadbeef"), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = A.main(["import", "--archive", str(archive), "--project", str(destination)])
        self.assertEqual(code, 2, stdout.getvalue())
        self.assertFalse(json.loads(stdout.getvalue())["ok"])
        self.assertEqual(stderr.getvalue(), "")
        self.assertFalse(destination.exists())
        self.assertEqual(sentinel.read_bytes(), b"unknown staging data must survive")
        code, payload, _ = self.fixture.import_bundle(archive, destination)
        self.assertEqual(code, 0, payload)
        self.assertEqual(sentinel.read_bytes(), b"unknown staging data must survive")
        self.fixture.state(destination, "resume")

    def test_export_exit_after_publish_leaves_valid_archive_and_refuses_overwrite(self):
        archive = self.base / "published.zip"
        original = self.files(self.project)
        result = self.child("export", "publish", archive, self.project)
        self.assertEqual(result.returncode, 78, result.stderr)
        before = archive.read_bytes()
        self.assertEqual(self.files(self.project), original)
        code, payload, _ = F.invoke(F.ARCHIVE, "verify", "--archive", archive)
        self.assertEqual(code, 0, payload)
        code, payload, _ = F.invoke(F.ARCHIVE, "export", "--project", self.project, "--out", archive)
        self.assertEqual(code, 2, payload)
        self.assertEqual(archive.read_bytes(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
