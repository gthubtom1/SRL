"""Isolated metadata rollback, interrupted-process recovery and journal boundary tests."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lib import project_transaction as T
from lib.project_lock import project_lock


class ProjectTransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="seep-transaction-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir()
        self.old = self.root / "old.json"
        self.old.write_bytes(b"original bytes\x00\xff")

    def snapshot(self):
        return {p.relative_to(self.root).as_posix(): p.read_bytes()
                for p in self.root.rglob("*") if p.is_file() and p.name != ".project.lock"}

    def test_ordinary_failure_rolls_back_exact_bytes_and_created_directories(self):
        before = self.snapshot()
        with project_lock(self.root), self.assertRaisesRegex(OSError, "synthetic"):
            with T.file_transaction(self.root, ["old.json", "new/deep/value.json"]):
                self.old.write_bytes(b"changed")
                child = self.root / "new/deep/value.json"
                child.parent.mkdir(parents=True)
                child.write_bytes(b"new")
                raise OSError("synthetic")
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / "new").exists())

    def test_success_is_committed_and_no_recovery_remains(self):
        with project_lock(self.root), T.file_transaction(self.root, ["old.json"]):
            self.old.write_bytes(b"committed")
        self.assertEqual(self.old.read_bytes(), b"committed")
        self.assertFalse(T.pending(self.root))
        self.assertFalse(T.recover(self.root))

    def test_file_ancestor_conflict_is_refused_before_publishing_journal(self):
        before = self.snapshot()
        for refs in (["new", "new/child.json"], ["new/child.json", "new"],
                     ["Node", "node/child.json"], [T.JOURNAL + "/child.json"]):
            with self.subTest(refs=refs):
                with self.assertRaises(ValueError):
                    with T.file_transaction(self.root, refs):
                        self.fail("an impossible file write set must never be entered")
                self.assertEqual(self.snapshot(), before)

    def test_conflicting_journal_file_topology_is_rejected_before_any_restore(self):
        data = T._snapshot(self.root, ["old.json"])
        image = dict(data["files"][0])
        data["files"] += [dict(image, path="new"), dict(image, path="new/child.json")]
        (self.root / T.JOURNAL).write_text(json.dumps(data), encoding="utf-8")
        self.old.write_bytes(b"interrupted write")
        before = self.snapshot()
        with mock.patch.object(T, "_replace", wraps=T._replace) as restore:
            with self.assertRaises(ValueError):
                T.recover(self.root)
            restore.assert_not_called()
        self.assertEqual(self.snapshot(), before)

    def test_hard_exit_pending_blocks_readers_and_next_writer_restores_exact_before_image(self):
        before = self.snapshot()
        code = """import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from lib.project_transaction import file_transaction
from lib.project_lock import project_lock
root = Path(sys.argv[2])
with project_lock(root), file_transaction(root, ["old.json", "new.json"]):
    (root / "old.json").write_bytes(b"interrupted")
    (root / "new.json").write_bytes(b"new")
    os._exit(71)
"""
        result = subprocess.run([sys.executable, "-B", "-c", code,
                                 str(Path(__file__).parent), str(self.root)],
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 71, result.stderr)
        interrupted = self.snapshot()
        with self.assertRaisesRegex(ValueError, "interrupted"), project_lock(self.root):
            self.fail("pending transaction must block")
        self.assertEqual(self.snapshot(), interrupted)
        with project_lock(self.root, recover=True):
            self.assertEqual(self.snapshot(), before)

    def test_failed_rollback_retains_journal_and_can_resume(self):
        before = self.snapshot()
        real = T._replace
        def fail_restore(path, payload):
            if path == self.old:
                raise OSError("rollback failed")
            return real(path, payload)
        with project_lock(self.root):
            with mock.patch.object(T, "_replace", side_effect=fail_restore):
                with self.assertRaisesRegex(OSError, "rollback failed"):
                    with T.file_transaction(self.root, ["old.json"]):
                        self.old.write_bytes(b"changed")
                        raise RuntimeError("synthetic original failure")
            self.assertTrue(T.pending(self.root))
            self.assertEqual(self.old.read_bytes(), b"changed")
            self.assertTrue(T.recover(self.root))
            self.assertEqual(self.snapshot(), before)

    def test_invalid_last_row_is_rejected_before_any_restore(self):
        with project_lock(self.root):
            payload = T._snapshot(self.root, ["old.json"])
            payload["files"].append({"path": "../outside", "before": None, "sha256": None})
            (self.root / T.JOURNAL).write_text(json.dumps(payload), encoding="utf-8")
            self.old.write_bytes(b"changed")
            before = self.snapshot()
            with self.assertRaises(ValueError):
                T.recover(self.root)
            self.assertEqual(self.snapshot(), before)

    def test_bad_backup_hash_and_reserved_destinations_do_not_write(self):
        for ref in ("old.json", ".project.lock", ".PROJECT.LOCK", T.JOURNAL, T.JOURNAL.upper()):
            with self.subTest(ref=ref):
                data = T._snapshot(self.root, ["old.json"])
                data["files"][0]["path"] = ref
                if ref == "old.json":
                    data["files"][0]["sha256"] = "0" * 64
                (self.root / T.JOURNAL).write_text(json.dumps(data), encoding="utf-8")
                before = self.snapshot()
                with self.assertRaises(ValueError):
                    T.recover(self.root)
                self.assertEqual(self.snapshot(), before)
                (self.root / T.JOURNAL).unlink()

    def test_case_aliases_cannot_restore_the_same_file_twice(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            with T.file_transaction(self.root, ["old.json", "OLD.JSON"]):
                self.fail("case aliases accepted")
        self.assertEqual(self.snapshot(), before)
        data = T._snapshot(self.root, ["old.json"])
        data["files"].append(dict(data["files"][0], path="OLD.JSON"))
        (self.root / T.JOURNAL).write_text(json.dumps(data), encoding="utf-8")
        before = self.snapshot()
        with self.assertRaises(ValueError):
            T.recover(self.root)
        self.assertEqual(self.snapshot(), before)

    def test_snapshot_limit_and_preexisting_directory_refuse_before_journal(self):
        before = self.snapshot()
        with mock.patch.object(T, "MAX_BYTES", 2), self.assertRaises(ValueError):
            with T.file_transaction(self.root, ["old.json"]):
                self.fail("oversized snapshot accepted")
        self.assertEqual(self.snapshot(), before)
        with self.assertRaises(ValueError):
            with T.file_transaction(self.root, ["."]):
                self.fail("directory accepted")
        self.assertFalse(T.pending(self.root))

    def test_existing_external_link_is_not_backed_up_or_restored(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        external = outside / "data.json"
        external.write_bytes(b"untouched")
        link = self.root / "linked"
        if os.name == "nt":
            import _winapi
            _winapi.CreateJunction(str(outside), str(link))
        else:
            link.symlink_to(outside, target_is_directory=True)
        self.addCleanup(link.rmdir if os.name == "nt" else link.unlink)
        with self.assertRaises(ValueError):
            with T.file_transaction(self.root, ["linked/data.json"]):
                self.fail("external link accepted")
        self.assertEqual(external.read_bytes(), b"untouched")
        self.assertFalse(T.pending(self.root))


class DirectoryTransactionTests(unittest.TestCase):
    setUp = ProjectTransactionTests.setUp
    snapshot = ProjectTransactionTests.snapshot
    def test_explicit_empty_directories_are_removed_on_rollback(self):
        before = self.snapshot()
        with project_lock(self.root), self.assertRaisesRegex(OSError, "synthetic"):
            with T.file_transaction(self.root, ["old.json"], directories=["run/capture", "run/artifacts"]):
                (self.root / "run/capture").mkdir(parents=True)
                (self.root / "run/artifacts").mkdir()
                self.old.write_bytes(b"changed")
                raise OSError("synthetic")
        self.assertEqual(self.snapshot(), before)
        self.assertFalse((self.root / "run").exists())

    def test_existing_empty_directory_is_preserved_and_unexpected_contents_block_cleanup(self):
        existing = self.root / "existing"
        existing.mkdir()
        with project_lock(self.root):
            with self.assertRaisesRegex(OSError, "not empty|non-empty|目录不是空的"):
                with T.file_transaction(self.root, ["old.json"], directories=["existing", "new"]):
                    (self.root / "new").mkdir()
                    (self.root / "new/user.txt").write_bytes(b"keep")
                    raise RuntimeError("synthetic")
            self.assertTrue(T.pending(self.root))
            self.assertTrue(existing.is_dir())
            self.assertEqual((self.root / "new/user.txt").read_bytes(), b"keep")
            (self.root / "new/user.txt").unlink()
            self.assertTrue(T.recover(self.root))
            self.assertTrue(existing.is_dir())

    def test_explicit_directory_alias_and_file_conflicts_are_rejected_before_writing(self):
        for directories in (["old.json"], ["new", "NEW"], ["../outside"], ["nested/file/child"]):
            with self.subTest(directories=directories):
                refs = ["old.json", "nested/file"]
                before = self.snapshot()
                with project_lock(self.root), self.assertRaises(ValueError):
                    with T.file_transaction(self.root, refs, directories=directories):
                        self.fail("invalid directory write set accepted")
                self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
