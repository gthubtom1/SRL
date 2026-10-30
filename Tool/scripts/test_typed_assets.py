#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Behaviour tests for ``lib/typed_assets.py`` (batch #42-1).

Run: python -B -X utf8 Tool/scripts/test_typed_assets.py

Everything happens under a TemporaryDirectory with self-made text fixtures.
No real repo tree/sample, no user directory, no credential, no network, no
target execution, no install, no git commit.  The test asserts, not just
mirrors, that: source bytes are untouched by a snapshot; a tampered/missing/
extra tree entry is rejected and restored; a URL descriptor is never treated as
a remote-content hash; and no socket is opened while describing URLs.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from lib import typed_assets as ta  # noqa: E402

PROJECT = "projects/demo"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-typed-asset-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "proj"
        (self.root / "assets").mkdir(parents=True)
        (self.root / "project.json").write_text(
            json.dumps({"schema": "seep-project/1", "project_id": "demo"}),
            encoding="utf-8")
        self.src = self.base / "src"
        self.src.mkdir()

    def write(self, path: Path, data: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode("utf-8"))
        return path

    def tree(self, extra: bool = True) -> Path:
        self.write(self.src / "a.txt", "alpha\n")
        self.write(self.src / "sub" / "b.bin", "beta\x00\x01\n")
        if extra:
            (self.src / "empty").mkdir(exist_ok=True)
        return self.src

    def digest_tree(self, root: Path, snap: dict) -> str:
        hasher = hashlib.sha256()
        for entry in snap["entries"]:
            hasher.update(entry["path"].encode("utf-8"))
            hasher.update(entry["type"].encode("utf-8"))
            if entry["type"] == "file":
                hasher.update((root / entry["path"]).read_bytes())
        return hasher.hexdigest()


class FileAssetTests(Base):
    def test_file_keeps_raw_sha_semantics_and_detects_change(self):
        target = self.write(self.root / "assets" / "main.bin", "PE-fixture\n")
        record = ta.file_identity(self.root, "assets/main.bin")
        self.assertEqual(record["kind"], "file")
        self.assertEqual(record["sha256"], hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertEqual(record["size"], target.stat().st_size)
        self.assertEqual(record["algorithm"], ta.FILE_ALGO)
        before = target.read_bytes()
        verified = ta.verify_target(self.root, record)
        self.assertEqual(verified["kind"], "file")
        self.assertEqual(target.read_bytes(), before)
        target.write_bytes(b"changed\n")
        with self.assertRaises(ValueError):
            ta.verify_target(self.root, record)

    def test_file_asset_rejects_escape_and_symlink(self):
        for bad in ("../outside.bin", "/etc/passwd", "C:/x", ""):
            with self.assertRaises(ValueError):
                ta.file_identity(self.root, bad)
        real = self.write(self.base / "outside.bin", "outside\n")
        link = self.root / "assets" / "link.bin"
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            self.skipTest("host cannot create symlinks; symlink case unverified")
        with self.assertRaises(ta.TypedAssetError):
            ta.file_identity(self.root, "assets/link.bin")


class DirectoryStabilityTests(Base):
    def test_repeat_snapshot_stable_then_rename_changes_identity(self):
        tree = self.tree()
        first = ta.directory_identity(tree)
        second = ta.directory_identity(tree)
        self.assertEqual(first["sha256"], second["sha256"])
        record = ta.prepare_snapshot(tree, self.root, PROJECT)
        self.assertEqual(record["identity"]["sha256"], first["sha256"])
        # no machine-absolute path is ever written into the identity record
        self.assertNotIn(str(self.base).replace("\\", "/"), json.dumps(record))
        self.assertNotIn(str(self.base).replace("\\", "/"),
                         (self.root / PROJECT / "manifest.json").read_text(encoding="utf-8"))
        # the record survives a JSON round trip unchanged (one persisted schema)
        self.assertEqual(json.loads(json.dumps(record)), record)
        self.assertEqual(ta.verify_target(self.root, record)["kind"], "directory")
        body = self.digest_tree(self.root / PROJECT / "tree", first)
        # rename inside the tree => different tree identity
        os.replace(tree / "a.txt", tree / "renamed.txt")
        third = ta.directory_identity(tree)
        self.assertNotEqual(first["sha256"], third["sha256"])
        # the registered snapshot is unaffected by later source changes
        self.assertEqual(ta.verify_target(self.root, record)["ok"], True)
        self.assertEqual(self.digest_tree(self.root / PROJECT / "tree", first), body)
        # empty directory is part of tree identity
        (tree / "empty2").mkdir()
        self.assertNotEqual(third["sha256"], ta.directory_identity(tree)["sha256"])
        # add / delete both change identity
        (tree / "extra.txt").write_bytes(b"x")
        with_extra = ta.directory_identity(tree)
        (tree / "extra.txt").unlink()
        self.assertNotEqual(with_extra["sha256"], ta.directory_identity(tree)["sha256"])

    def test_snapshot_is_copy_only_and_never_overwrites(self):
        tree = self.tree()
        src_bytes = {p: p.read_bytes() for p in tree.rglob("*") if p.is_file()}
        record = ta.prepare_snapshot(tree, self.root, PROJECT)
        after = {p: p.read_bytes() for p in tree.rglob("*") if p.is_file()}
        self.assertEqual(src_bytes, after)          # source bytes untouched
        copied = {p.relative_to(self.root / PROJECT / "tree"): p.read_bytes()
                  for p in (self.root / PROJECT / "tree").rglob("*") if p.is_file()}
        self.assertEqual(sorted(v for v in copied.values()), sorted(src_bytes.values()))
        # snapshot tree is a materialization, not a link back to the source
        shutil.rmtree(tree)
        self.assertTrue(ta.verify_target(self.root, record)["ok"])
        # second snapshot into the same slot must refuse
        fresh = self.base / "src2"
        self.write(fresh / "a.txt", "other\n")
        with self.assertRaises(ta.TypedAssetError):
            ta.prepare_snapshot(fresh, self.root, PROJECT)
        self.assertEqual(ta.verify_target(self.root, record)["ok"], True)

    def test_empty_source_tree_is_identity_not_an_error(self):
        empty = self.base / "src-empty"
        empty.mkdir()
        identity = ta.directory_identity(empty)
        self.assertEqual((identity["entry_count"], identity["size"]), (0, 0))
        record = ta.prepare_snapshot(empty, self.root, "projects/empty")
        self.assertTrue(ta.verify_target(self.root, record)["ok"])
        (self.root / "projects" / "empty" / "tree" / "new.txt").write_bytes(b"x")
        with self.assertRaises(ValueError) as caught:
            ta.verify_target(self.root, record)
        self.assertIn("extra files: new.txt", str(caught.exception))

    def test_unicode_tree_survives_parent_relocation(self):
        src = self.base / "src-unicode"
        (src / "中文 目录").mkdir(parents=True)
        (src / "中文 目录" / "文件.txt").write_bytes("内容\n".encode("utf-8"))
        (src / "spaced dir").mkdir()
        record = ta.prepare_snapshot(src, self.root, "projects/unicode")
        self.assertIn("中文 目录/文件.txt",
                      [entry["path"] for entry in ta.directory_identity(
                          self.root / "projects" / "unicode" / "tree")["entries"]])
        moved = self.base / "moved" / "proj"
        (self.base / "moved").mkdir()
        shutil.move(str(self.root), str(moved))
        # refs are project-relative: the same record verifies at the new location
        self.assertTrue(ta.verify_target(moved, record)["ok"])

    def test_snapshot_ref_must_stay_inside_project(self):
        tree = self.tree()
        for ref in ("../escape", "/tmp/abs", "C:/tmp/x", ""):
            with self.assertRaises(ValueError):
                ta.prepare_snapshot(tree, self.root, ref)
        self.assertFalse((self.base / "escape").exists())


class DirectoryTamperTests(Base):
    def setUp(self):
        super().setUp()
        self.tree()
        self.record = ta.prepare_snapshot(self.src, self.root, PROJECT)
        self.tree_root = self.root / PROJECT / "tree"
        self.manifest = self.root / PROJECT / "manifest.json"
        self.saved = {p.relative_to(self.tree_root): p.read_bytes()
                      for p in self.tree_root.rglob("*") if p.is_file()}
        self.manifest_bytes = self.manifest.read_bytes()

    def restore(self):
        shutil.rmtree(self.tree_root)
        for rel, data in self.saved.items():
            (self.tree_root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.tree_root / rel).write_bytes(data)
        (self.tree_root / "empty").mkdir(parents=True, exist_ok=True)
        self.manifest.write_bytes(self.manifest_bytes)

    def assert_rejected(self, pattern: str):
        with self.assertRaises(ValueError) as caught:
            ta.verify_target(self.root, self.record)
        self.assertIn(pattern, str(caught.exception))
        self.assertNotIn(str(self.base), str(caught.exception),
                         "errors must not leak machine absolute paths")

    def test_tampered_bytes_rejected_then_restore_passes(self):
        (self.tree_root / "a.txt").write_bytes(b"tampered\n")
        self.assert_rejected("tampered")
        self.restore()
        self.assertTrue(ta.verify_target(self.root, self.record)["ok"])

    def test_missing_entry_rejected_then_restore_passes(self):
        (self.tree_root / "sub" / "b.bin").unlink()
        self.assert_rejected("missing entries: sub/b.bin")
        self.restore()
        self.assertTrue(ta.verify_target(self.root, self.record)["ok"])

    def test_extra_file_rejected_then_restore_passes(self):
        (self.tree_root / "sub" / "sneaky.txt").write_bytes(b"sneaky\n")
        self.assert_rejected("extra files")
        self.restore()
        self.assertTrue(ta.verify_target(self.root, self.record)["ok"])

    def test_forged_manifest_and_escape_and_missing_dir_rejected(self):
        forged = json.loads(self.manifest_bytes)
        forged["entries"][0]["sha256"] = "0" * 64
        self.manifest.write_text(json.dumps(forged), encoding="utf-8")
        self.assert_rejected("manifest")
        self.restore()
        escaping = json.loads(self.manifest_bytes)
        escaping["entries"].append({"path": "../../etc/x", "type": "file",
                                    "sha256": "0" * 64, "size": 1})
        escaping["entries"].sort(key=lambda entry: entry["path"])
        sha = hashlib.sha256(json.dumps(
            {"schema": ta.TREE_SCHEMA, "entries": escaping["entries"]},
            ensure_ascii=False, sort_keys=True,
            separators=(",", ":")).encode("utf-8")).hexdigest()
        escaping["identity"]["sha256"] = sha          # even a self-consistent forgery
        self.record["identity"]["sha256"] = sha       # ... cannot smuggle a path escape
        self.manifest.write_text(json.dumps(escaping), encoding="utf-8")
        self.assert_rejected("manifest entry path")
        self.restore()
        del self.record["identity"]["sha256"]
        self.assert_rejected("missing sha256")
        self.record["identity"]["sha256"] = self.manifest_sha()

    def manifest_sha(self) -> str:
        return json.loads(self.manifest_bytes)["identity"]["sha256"]

    def test_garbage_or_oversized_manifest_rejected(self):
        self.manifest.write_bytes(b"\xff\xfe not json")
        self.assert_rejected("not valid UTF-8 JSON")
        self.restore()
        self.manifest.write_bytes(b"[" + b"0" * (ta.MAX_MANIFEST_BYTES + 1))
        self.assert_rejected("manifest too large")
        self.restore()
        broken = json.loads(self.manifest_bytes)
        file_entry = [entry for entry in broken["entries"] if entry["type"] == "file"][0]
        file_entry["sha256"] = "not-a-hash"
        self.manifest.write_text(json.dumps(broken), encoding="utf-8")
        self.assert_rejected("invalid sha256")
        self.restore()
        record = dict(self.record, identity=dict(self.record["identity"], algorithm="md5"))
        with self.assertRaises(ta.TypedAssetError) as caught:
            ta.verify_target(self.root, record)
        self.assertIn("unknown directory identity algorithm", str(caught.exception))
        self.assertTrue(ta.verify_target(self.root, self.record)["ok"])

    def test_restore_then_missing_tree_directory_is_flagged(self):
        self.restore()
        (self.tree_root / "empty").rmdir()
        self.assert_rejected("missing entries: empty")
        self.restore()
        shutil.rmtree(self.tree_root / "sub")
        self.assert_rejected("missing entries: sub")


class DirectoryEscapeAndLimitsTests(Base):
    def test_entry_limit_stops_enumeration_before_materializing_unbounded_listing(self):
        self.tree()
        real_scandir = os.scandir
        yielded = []

        class BoundedScan:
            def __enter__(inner):
                inner.scan = real_scandir(self.src)
                return inner

            def __exit__(inner, *args):
                inner.scan.close()

            def __iter__(inner):
                for entry in inner.scan:
                    yielded.append(entry.name)
                    if len(yielded) > 2:
                        raise AssertionError("directory was enumerated past max_entries + 1")
                    yield entry

        with patch.object(ta.os, "scandir", return_value=BoundedScan()):
            with self.assertRaises(ta.LimitExceeded):
                ta.directory_identity(self.src, ta.DirectoryLimits(max_entries=1))
        self.assertEqual(len(yielded), 2)

    def test_manifest_actual_read_is_bounded_even_when_size_precheck_is_stale(self):
        manifest = self.root / "manifest-fixture.json"
        manifest.write_bytes(b"{}" + b" " * 30)
        from types import SimpleNamespace
        with patch.object(ta, "MAX_MANIFEST_BYTES", 16), \
                patch.object(Path, "stat", return_value=SimpleNamespace(st_size=2)):
            with self.assertRaisesRegex(ta.TypedAssetError, "too large"):
                ta._load_manifest(manifest)

    def test_symlink_escape_is_rejected_without_following(self):
        outside = self.base / "outside-secret.txt"
        outside.write_bytes(b"OUTSIDE\n")
        self.write(self.src / "a.txt", "alpha\n")
        link = self.src / "escape.txt"
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError):
            self.skipTest("host cannot create symlinks; escape case unverified")
        link_state = link.is_symlink()
        with self.assertRaises(ta.TypedAssetError):
            ta.directory_identity(self.src)
        self.assertTrue(link_state)
        self.assertEqual(outside.read_bytes(), b"OUTSIDE\n")
        # a symlinked root is refused too
        root_link = self.base / "rootlink"
        os.symlink(self.src, root_link)
        with self.assertRaises(ta.TypedAssetError):
            ta.directory_identity(root_link)

    @unittest.skipIf(os.name != "nt", "junctions are a Windows-only reparse point")
    def test_junction_escape_is_rejected(self):
        self.write(self.src / "a.txt", "alpha\n")
        junction = self.src / "junction"
        os.system('cmd /c mklink /J "%s" "%s" >nul 2>&1' % (junction, self.base))
        if not junction.exists():
            self.skipTest("host could not create a junction; case unverified")
        with self.assertRaises(ta.TypedAssetError):
            ta.directory_identity(self.src)

    def test_limits_rejected_and_no_usable_partial_left(self):
        self.write(self.src / "a.txt", "alpha\n")
        self.write(self.src / "b.txt", "beta\n")
        (self.src / "sub").mkdir()
        self.write(self.src / "sub" / "c.txt", "gamma\n")
        cases = [ta.DirectoryLimits(max_entries=2),        # 2 files + 1 dir + 1 file = 4
                 ta.DirectoryLimits(max_bytes=4),          # 5+ bytes total
                 ta.DirectoryLimits(max_file_bytes=3),     # "alpha" is 6 bytes
                 ta.DirectoryLimits(max_depth=0),          # sub/ needs depth 1
                 ta.DirectoryLimits(max_path_chars=8)]     # "sub/c.txt" is 9
        for limits in cases:
            with self.assertRaises(ta.LimitExceeded):
                ta.directory_identity(self.src, limits)
            with self.assertRaises(ta.LimitExceeded):
                ta.prepare_snapshot(self.src, self.root, "projects/limit", limits)
            self.assertFalse((self.root / "projects" / "limit").exists())
            leftover = [p.name for p in (self.root / "projects").glob(".typed-staging-*")] \
                if (self.root / "projects").exists() else []
            self.assertEqual(leftover, [])
        # the same tree passes with the default bounds (limits are the only cause)
        self.assertTrue(ta.directory_identity(self.src)["entry_count"] > 0)

    def test_mid_copy_failure_leaves_no_usable_partial(self):
        self.write(self.src / "a.txt", "alpha\n")
        self.write(self.src / "sub" / "b.bin", "beta\n")
        calls = {"n": 0}
        real = ta.atomic_copy

        def flaky(source, destination, sha256, size):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError("simulated disk failure")
            return real(source, destination, sha256, size)

        with patch.object(ta, "atomic_copy", flaky):
            with self.assertRaises(OSError):
                ta.prepare_snapshot(self.src, self.root, PROJECT)
        self.assertFalse((self.root / PROJECT).exists())
        self.assertEqual(list((self.root / "projects").glob(".typed-staging-*")), [])

    def test_source_change_during_copy_is_detected(self):
        self.write(self.src / "a.txt", "alpha\n")
        self.write(self.src / "b.txt", "beta\n")
        real = ta.atomic_copy
        state = {"n": 0}

        def mutate_after_copy(source, destination, sha256, size):
            result = real(source, destination, sha256, size)
            state["n"] += 1
            if state["n"] == 1:
                (self.src / "b.txt").write_bytes(b"CHANGED\n")
            return result

        with patch.object(ta, "atomic_copy", mutate_after_copy):
            with self.assertRaises(ta.ConcurrentChange):
                ta.prepare_snapshot(self.src, self.root, PROJECT)
        self.assertFalse((self.root / PROJECT).exists())


class UrlDescriptorTests(Base):
    def test_descriptor_positive_fragment_and_query_preserved(self):
        value = "https://Example.COM:443/a/b?z=1&a=2#Frag"
        record = ta.url_descriptor(value)
        self.assertEqual(record["kind"], "url_descriptor")
        self.assertEqual(record["url"], "https://example.com/a/b?z=1&a=2#Frag")
        self.assertEqual(record["identity"]["algorithm"], ta.URL_ALGO)
        self.assertIs(record["remote_content_verified"], False)
        self.assertEqual(record["identity"]["sha256"],
                         hashlib.sha256(ta._canonical(record["descriptor"])).hexdigest())
        self.assertEqual(ta.verify_target(self.root, record)["kind"], "url_descriptor")
        # query order and fragment are user semantics: not silently sorted or dropped
        reordered = ta.url_descriptor("https://example.com/a/b?a=2&z=1#Frag")
        self.assertNotEqual(reordered["identity"]["sha256"], record["identity"]["sha256"])
        self.assertEqual(reordered["descriptor"]["query"], "a=2&z=1")
        bare = ta.url_descriptor("https://example.com/a/b?z=1&a=2")
        self.assertNotEqual(bare["identity"]["sha256"], record["identity"]["sha256"])
        # Manager's exact public numeric query keys stay usable (same predicate, reused)
        self.assertEqual(ta.url_descriptor("https://example.com/?limit_tokens=5")["url"],
                         "https://example.com/?limit_tokens=5")
        # non-web schemes are refused, no silent file fallback
        for bad in ("file:///etc/passwd", "ftp://x/y", "javascript:alert(1)", "",
                    "https://", "http://a b/"):
            with self.assertRaises(ta.TypedAssetError):
                ta.url_descriptor(bad)

    def test_sensitive_inputs_rejected_without_echo_or_network(self):
        markers = {
            "userinfo": "https://svc:%s@example.com/x" % ("SENTINEL_PW"),
            "query": "https://example.com/x?%s=%s" % ("access_" + "token", "SENTINEL_Q"),
            "encoded": "https://example.com/x?access%5Ftoken=SENTINEL_E",
            "bearer": "https://example.com/x?q=Bearer%20SENTINEL_B",
        }
        for label, value in markers.items():
            with self.assertRaises(ta.TypedAssetError) as caught:
                ta.url_descriptor(value)
            message = str(caught.exception)
            for secret in ("SENTINEL_PW", "SENTINEL_Q", "SENTINEL_E", "SENTINEL_B"):
                self.assertNotIn(secret, message)
            self.assertFalse(caught.exception.__cause__ is not None
                             and "SENTINEL" in str(caught.exception.__cause__),
                             "cause must not carry the secret (%s)" % label)

    def test_zero_network_and_remote_claim_rejected(self):
        real_connect = socket.socket.connect
        real_create = socket.create_connection
        calls = []

        def spy_connect(self, *args, **kwargs):
            calls.append(args)
            return real_connect(self, *args, **kwargs)

        with patch.object(socket.socket, "connect", spy_connect), \
                patch.object(socket, "create_connection",
                             lambda *a, **k: calls.append(a)):
            record = ta.url_descriptor("http://127.0.0.1:8080/fixture?x=1#f")
            ta.verify_target(self.root, record)
        self.assertEqual(calls, [], "describing a URL must not open a connection")

        fake = json.loads(json.dumps(record))
        fake["response_sha256"] = "f" * 64
        with self.assertRaises(ta.TypedAssetError) as caught:
            ta.verify_target(self.root, fake)
        self.assertIn("remote observation field", str(caught.exception))
        fake2 = json.loads(json.dumps(record))
        fake2["remote_content_verified"] = True
        with self.assertRaises(ta.TypedAssetError):
            ta.verify_target(self.root, fake2)
        fake3 = json.loads(json.dumps(record))
        fake3["identity"]["sha256"] = "a" * 64
        with self.assertRaises(ta.TypedAssetError) as caught:
            ta.verify_target(self.root, fake3)
        self.assertIn("sha mismatch", str(caught.exception))
        fake4 = json.loads(json.dumps(record))
        fake4["url"] = "http://127.0.0.1:8080/FIXTURE?x=1#f"
        with self.assertRaises(ta.TypedAssetError):
            ta.verify_target(self.root, fake4)


class SelectionTests(Base):
    def records(self):
        self.write(self.root / "assets" / "main.exe", "MZ-main\n")
        main = ta.file_identity(self.root, "assets/main.exe")
        main["asset_id"] = "main-pe"
        self.tree()
        aux = ta.prepare_snapshot(self.src, self.root, "projects/directory")
        aux["asset_id"] = "aux-tree"
        url = ta.url_descriptor("https://example.com/api?q=1")
        url["asset_id"] = "url-desc"
        return main, aux, url

    def test_primary_and_auxiliary_bind_by_own_identity(self):
        main, aux, url = self.records()
        self.assertNotEqual(main["identity_sha256"] if "identity_sha256" in main
                            else main["sha256"], aux["identity"]["sha256"])
        snapshot = ta.build_snapshot([main, aux, url], primary_asset_id="main-pe",
                                     auxiliary_asset_ids=["aux-tree"],
                                     action_target_asset_id="main-pe")
        picked = ta.validate_selection(snapshot, "main-pe", "primary")
        self.assertEqual(picked["identity_sha256"], main["sha256"])
        picked_aux = ta.validate_selection(snapshot, "aux-tree", "auxiliary")
        self.assertEqual(picked_aux["identity_sha256"], aux["identity"]["sha256"])
        self.assertNotEqual(picked["identity_sha256"], picked_aux["identity_sha256"])
        # binding the auxiliary id as primary is refused: no cross-swap of hashes
        with self.assertRaises(ta.TypedAssetError):
            ta.validate_selection(snapshot, "aux-tree", "primary")
        with self.assertRaises(ta.TypedAssetError):
            ta.validate_selection(snapshot, "main-pe", "auxiliary")
        # an undeclared/unknown id never falls back to another asset
        for bogus in ("nope", "", "aux-tre"):
            with self.assertRaises(ta.TypedAssetError):
                ta.validate_selection(snapshot, bogus, "primary")

    def test_no_implicit_primary_and_kind_gated_dispatch(self):
        main, aux, url = self.records()
        snapshot = ta.build_snapshot([main, aux, url],
                                     auxiliary_asset_ids=["aux-tree"])
        with self.assertRaises(ta.TypedAssetError) as caught:
            ta.validate_selection(snapshot, "main-pe", "primary")
        self.assertIn("declares no primary", str(caught.exception))
        # a file parser must refuse a directory/url descriptor up front
        with self.assertRaises(ta.TypedAssetError):
            ta.validate_selection(snapshot, "aux-tree", "auxiliary",
                                  allowed_kinds=("file",))
        with self.assertRaises(ta.TypedAssetError):
            ta.validate_selection(snapshot, "url-desc", "auxiliary",
                                  allowed_kinds=("file", "directory"))
        self.assertEqual(ta.validate_selection(snapshot, "aux-tree", "auxiliary",
                                               allowed_kinds=("directory",))["kind"],
                         "directory")
        # unknown kind / duplicate id / bad role are rejected explicitly
        broken = dict(main, asset_id="odd", kind="volume")
        with self.assertRaises(ta.TypedAssetError):
            ta.build_snapshot([broken])
        with self.assertRaises(ta.TypedAssetError):
            ta.build_snapshot([main, main])
        with self.assertRaises(ta.TypedAssetError):
            ta.validate_selection(snapshot, "main-pe", "sidecar")
        with self.assertRaises(ta.TypedAssetError) as caught:
            ta.verify_target(self.root, {"kind": "volume"})
        self.assertIn("unknown asset kind", str(caught.exception))

    def test_mixed_directory_is_carrier_only_not_a_domain_decision(self):
        self.tree()
        record = ta.prepare_snapshot(self.src, self.root, "projects/mixed")
        record["asset_id"] = "mixed"
        snapshot = ta.build_snapshot([record], primary_asset_id="mixed")
        self.assertEqual(snapshot["domain_scope"], "undeclared")
        self.assertEqual(record["domain_scope"], "undeclared")
        self.assertNotIn("domain", json.dumps(record["identity"]))


class BoundaryGuardTests(Base):
    """F1/F2 from typed-assets-independent.md: anchors and slot containment."""

    def test_f1_anchor_refused_by_metadata_without_listing(self):
        seen = []

        def spy(*args, **kwargs):
            seen.append(args)
            raise AssertionError("filesystem touched for an anchor: %r" % (args,))

        anchors = [Path(os.path.abspath(os.sep)), Path(os.path.abspath(os.sep)).anchor]
        unc = Path("//server/share")
        if unc.anchor and Path(unc.anchor) == Path(os.path.abspath(str(unc))):
            anchors.append(unc)
        with patch.object(os, "scandir", spy), patch.object(os, "lstat", spy):
            for anchor in anchors:
                with self.assertRaises(ta.RootPathError):
                    ta.directory_identity(Path(anchor))
        self.assertEqual(seen, [], "anchor must be refused before scandir/lstat")
        # prepare_snapshot refuses the same way, and resource limits are not the cause:
        with patch.object(os, "scandir", spy):
            with self.assertRaises(ta.RootPathError) as caught:
                ta.prepare_snapshot(anchors[0], self.root, PROJECT)
        self.assertNotIsInstance(caught.exception, ta.LimitExceeded)
        self.assertIn("anchor", str(caught.exception))
        self.assertNotIn(str(anchors[0]), str(caught.exception))

    def test_f2_source_equal_to_slot_and_mutual_containment(self):
        tree = self.tree()
        # (A) slot inside the source tree, source == the container root itself
        project_before = ta.directory_identity(self.root)
        self.assertIs(type(self.boundary(self.root, self.root, "projects/t")),
                      ta.SnapshotBoundaryError)
        self.assertFalse((self.root / "projects").exists(),
                         "a refused attempt must not create anything in the source")
        self.assertEqual(ta.directory_identity(self.root), project_before,
                         "source entries/identity must be unchanged (RootChanged closed)")
        # (B) destination parent is the source (dest inside source)
        tree_before = ta.directory_identity(tree)
        self.assertIs(type(self.boundary(tree, tree, "slotparent/snap")),
                      ta.SnapshotBoundaryError)
        self.assertFalse((tree / "slotparent").exists())
        self.assertEqual(ta.directory_identity(tree), tree_before,
                         "source tree identity/entries must be byte-identical")
        # (C) source == the final slot, literally
        equal = self.root / "projects" / "eq"
        self.write(equal / "a.txt", "alpha\n")
        equal_before = ta.directory_identity(equal)
        with self.assertRaises(ta.SnapshotBoundaryError) as caught:
            ta.prepare_snapshot(equal, self.root, "projects/eq")
        self.assertIn("source root itself", str(caught.exception))
        self.assertEqual(ta.directory_identity(equal), equal_before)
        self.assertEqual(sorted(p.name for p in equal.iterdir()), ["a.txt"])
        # (D) reverse containment: slot is an ancestor of the source
        outer = self.root / "projects" / "outer"
        self.write(outer / "deep" / "a.txt", "alpha\n")
        self.assertIs(type(self.boundary(outer / "deep", self.root, "projects/outer")),
                      ta.SnapshotBoundaryError)
        self.assertEqual(sorted(p.name for p in outer.iterdir()), ["deep"])
        # (E) an escaping ref stays a plain path error, not a containment error
        with self.assertRaises(ValueError) as escaped:
            ta.prepare_snapshot(tree, self.root, "../nothing")
        self.assertIs(type(escaped.exception), ta.TypedAssetError)
        self.assertEqual(ta.directory_identity(tree), tree_before)

    def boundary(self, source, container, ref):
        try:
            ta.prepare_snapshot(source, container, ref)
        except ta.TypedAssetError as exc:
            return exc
        self.fail("expected a rejection for ref %r" % ref)

    def test_f2_sibling_slot_inside_project_still_allowed(self):
        uploads = self.root / "uploads"
        self.write(uploads / "a.txt", "alpha\n")
        record = ta.prepare_snapshot(uploads, self.root, "projects/uploads-snap")
        self.assertEqual(record["snapshot_ref"], "projects/uploads-snap")
        self.assertTrue(ta.verify_target(self.root, record)["ok"])
        # the source is untouched and is not the snapshot location
        self.assertEqual((uploads / "a.txt").read_bytes(), b"alpha\n")
        self.assertEqual(sorted(p.name for p in uploads.iterdir()), ["a.txt"])
        self.assertFalse((uploads / "projects").exists())


class IdentityConsistencyTests(Base):
    def file_record(self):
        self.write(self.root / "assets/main.bin", "original")
        return ta.file_identity(self.root, "assets/main.bin")

    def test_file_identity_representations_must_agree(self):
        import project_state as core
        record = self.file_record()
        mutations = (("identity", "sha256", "0" * 64),
                     ("identity", "size", record["size"] + 1),
                     ("identity", "algorithm", ta.URL_ALGO),
                     (None, "target_sha256", "0" * 64),
                     (None, "target_size", True),
                     (None, "identity", ["invalid"]))
        for parent, key, value in mutations:
            broken = json.loads(json.dumps(record))
            (broken[parent] if parent else broken)[key] = value
            for name, verify in (("typed", ta.verify_target), ("core", core.verify_target)):
                with self.subTest(key=key, parent=parent, entry=name):
                    with self.assertRaises(ValueError):
                        verify(self.root, broken)
            with self.subTest(key=key, parent=parent, entry="fields"):
                with self.assertRaises(ValueError):
                    core.target_identity_fields(broken)
        legacy = {key: record[key] for key in ("local_path", "sha256", "size")}
        self.assertEqual(core.verify_target(self.root, legacy)["sha256"], record["sha256"])
        self.assertEqual(ta.verify_target(self.root, dict(legacy, kind="file"))["identity_sha256"],
                         record["sha256"])

    def test_directory_full_identity_and_manifest_statistics_are_verified(self):
        self.tree()
        record = ta.prepare_snapshot(self.src, self.root, PROJECT)
        for key, value in (("file_count", 99), ("entry_count", True), ("size", -1),
                           ("algorithm", ta.FILE_ALGO)):
            broken = json.loads(json.dumps(record))
            broken["identity"][key] = value
            with self.subTest(location="record", key=key):
                with self.assertRaises(ValueError):
                    ta.verify_target(self.root, broken)
        manifest = self.root / record["manifest_ref"]
        original = manifest.read_bytes()
        for key, value in (("file_count", 99), ("entry_count", 99), ("size", 99),
                           ("algorithm", ta.FILE_ALGO)):
            broken = json.loads(original)
            broken["identity"][key] = value
            manifest.write_text(json.dumps(broken), encoding="utf-8")
            with self.subTest(location="manifest", key=key):
                with self.assertRaises(ValueError):
                    ta.verify_target(self.root, record)
        manifest.write_bytes(original)
        self.assertTrue(ta.verify_target(self.root, record)["ok"])

    def test_url_description_and_size_cannot_disagree_with_verified_text(self):
        record = ta.url_descriptor("https://example.invalid/a?q=1#f")
        for key, value in (("descriptor", dict(record["descriptor"], path="/other")),
                           ("identity_scope", "remote-content"),
                           ("remote_content_verified", "false")):
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    ta.verify_target(self.root, dict(record, **{key: value}))
        broken = json.loads(json.dumps(record))
        broken["identity"]["size"] += 1
        with self.assertRaises(ValueError):
            ta.verify_target(self.root, broken)

    def test_verified_file_rejects_in_project_symlink(self):
        record = self.file_record()
        link = self.root / "assets/link.bin"
        try:
            os.symlink(self.root / record["local_path"], link)
        except (OSError, NotImplementedError):
            self.skipTest("host cannot create symlink; case unverified")
        with self.assertRaises(ValueError):
            ta.verify_target(self.root, dict(record, local_path="assets/link.bin"))

    def test_file_changed_during_verification_cannot_keep_old_identity(self):
        record = self.file_record()
        real = ta.digest
        def change_after_hash(path):
            before = path.stat()
            result = real(path)
            path.write_bytes(b"modified")  # same length as original
            # Reproduce a coarse/delayed filesystem timestamp deterministically.
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            return result
        with patch.object(ta, "digest", change_after_hash):
            with self.assertRaises(ta.ConcurrentChange):
                ta.verify_target(self.root, record)
        self.assertEqual((self.root / record["local_path"]).read_bytes(), b"modified")

    def test_snapshot_selection_revalidates_untrusted_shape_and_duplicate_ids(self):
        record = dict(self.file_record(), asset_id="main")
        snapshot = ta.build_snapshot([record], primary_asset_id="main")
        cases = []
        for assets in ([record, record], ["bad"], {"main": record}):
            cases.append(dict(snapshot, assets=assets))
        broken = json.loads(json.dumps(snapshot))
        broken["assets"][0]["identity"]["sha256"] = "0" * 64
        cases.append(broken)
        for case in cases:
            with self.subTest(assets=case["assets"]):
                with self.assertRaises(ValueError):
                    ta.validate_selection(case, "main", "primary")
        for assets in (["bad"], {"main": record}, None):
            with self.subTest(build=assets):
                with self.assertRaises(ValueError):
                    ta.build_snapshot(assets)


if __name__ == "__main__":
    unittest.main(verbosity=2)
