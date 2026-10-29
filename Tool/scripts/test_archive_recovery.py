#!/usr/bin/env python3
"""Real process exits around archive publication; all project data is synthetic."""
from __future__ import annotations

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
