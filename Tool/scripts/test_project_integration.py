#!/usr/bin/env python3
"""Synthetic lifecycle regression across the two real CLIs; never executes a target.

Run: python -B Tool/scripts/test_project_integration.py
All project files, receipts, and subprocess lock probes live in TemporaryDirectory.
"""
from __future__ import annotations

import concurrent.futures
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "Tool/scripts/project_state.py"
REVERSE = ROOT / "Tool/skill/softseep/scripts/version-migrate.py"
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
PATTERN = "85 C0 74 ??"
OLD = b"AAAA\x85\xc0\x74\x12BBBB"
NEXT = b"ZZZZZZ\x85\xc0\x74\x22CCCC"
LAST = b"Q\x85\xc0\x74\x32DDDDD"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def cli(script, *args):
    result = subprocess.run([sys.executable, "-B", str(script), *map(str, args)],
                            cwd=ROOT, env=ENV, capture_output=True, text=True,
                            encoding="utf-8", timeout=30)
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        raise AssertionError((result.returncode, result.stdout[-2000:], result.stderr[-2000:]))
    if result.stderr:
        raise AssertionError(result.stderr[-2000:])
    return result.returncode, payload


class LifecycleIntegration(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seep-lifecycle-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.old = self.base / "old.bin"
        self.new = self.base / "new.bin"
        self.last = self.base / "last.bin"
        self.old.write_bytes(OLD)
        self.new.write_bytes(NEXT)
        self.last.write_bytes(LAST)
        self.ok(self.p("init", "--project-id", "synthetic", "--target", self.old))
        self.ok(self.v("init", "--version", "1.0", "--file", self.old))

    def p(self, command, *args):
        return cli(PROJECT, command, "--project", self.project, *args)

    def v(self, command, *args):
        return cli(REVERSE, command, "--case", self.project, *args)

    def ok(self, result):
        self.assertEqual(result[0], 0, result)
        self.assertTrue(result[1]["ok"], result)
        return result[1]

    def rejected(self, result):
        self.assertEqual(result[0], 2, result)
        self.assertFalse(result[1]["ok"], result)
        return result[1]

    def version(self, version="1.1", parent="1.0", file=None):
        self.ok(self.p("version", "--version", version, "--parent", parent,
                       "--target", file or self.new))

    def site(self, version="1.0", file=None, site_id="gate", **kwargs):
        args = ["add-site", "--version", version, "--file", file or self.old,
                "--id", site_id, "--sem", "synthetic branch candidate"]
        kwargs.setdefault("aob", PATTERN)
        for key, value in kwargs.items():
            args.extend(("--" + key, str(value)))
        return self.v(*args)

    def align(self, old="1.0", new="1.1", file=None):
        return self.v("align", "--old", old, "--new-version", new, "--new", file or self.new)

    def migration(self, status="partial", align=None, source="1.0", target="1.1", **kwargs):
        args = ["--source", source, "--target", target, "--status", status]
        if align is not None:
            args.extend(("--align", align))
        for key, value in kwargs.items():
            args.extend(("--" + key.replace("_", "-"), str(value)))
        return self.p("migration", *args)

    def prepared_align(self):
        self.version()
        self.ok(self.site(offset="4", original="85 C0 74 12"))
        self.ok(self.align())
        return self.project / "versions/1.1/align.json"

    def test_chain_10_11_12_and_full_migration_revisions(self):
        canonical = (self.project / "versions/1.0/manifest.json").read_bytes()
        align11 = self.prepared_align()
        self.ok(self.migration(align=align11, migration_id="upgrade", note="first complete detail"))
        first = read(self.project / "versions/1.1/migration.json")
        self.ok(self.migration(align=align11, migration_id="upgrade", note="second complete detail"))
        second = read(self.project / "versions/1.1/migration.json")
        revisions = [read(p) for p in (self.project / "versions/1.1/migrations").glob("*.json")]
        self.assertEqual(len(revisions), 2)
        self.assertIn(first, revisions)
        self.assertIn(second, revisions)
        self.assertNotEqual(first["revision_id"], second["revision_id"])
        self.assertEqual(first["align"], read(align11))
        self.ok(self.v("init", "--version", "1.1", "--parent", "1.0", "--file", self.new))
        self.ok(self.site(version="1.1", file=self.new, offset="6"))
        self.version("1.2", "1.1", self.last)
        self.ok(self.v("init", "--version", "1.2", "--parent", "1.1", "--file", self.last))
        self.ok(self.align("1.1", "1.2", self.last))
        self.ok(self.migration(align=self.project / "versions/1.2/align.json", source="1.1", target="1.2"))
        handoff = self.ok(self.p("resume"))["handoff"]
        self.assertEqual(handoff["current_version_id"], "1.2")
        self.assertEqual(len(handoff["migrations"]), 3)
        self.assertEqual(handoff["migration"]["source_sha256"], hashlib.sha256(NEXT).hexdigest())
        self.assertEqual(canonical, (self.project / "versions/1.0/manifest.json").read_bytes())
        self.assertEqual(read(self.project / "versions/1.1/manifest.json")["schema"], "seep-version-manifest/1")

    def test_reverse_first_then_project_init(self):
        alternate = self.base / "reverse-first"
        self.ok(cli(REVERSE, "init", "--case", alternate, "--version", "1.0", "--file", self.old))
        before = (alternate / "versions/1.0/reverse-baseline.json").read_bytes()
        self.ok(cli(PROJECT, "init", "--project", alternate, "--project-id", "reverse-first", "--target", self.old))
        self.assertEqual(before, (alternate / "versions/1.0/reverse-baseline.json").read_bytes())
        self.assertEqual(read(alternate / "versions/1.0/manifest.json")["schema"], "seep-version-manifest/1")
        conflict = self.base / "reverse-conflict"
        self.ok(cli(REVERSE, "init", "--case", conflict, "--version", "1.0", "--file", self.old))
        self.rejected(cli(PROJECT, "init", "--project", conflict, "--project-id", "conflict", "--target", self.new))
        self.assertFalse((conflict / "project.json").exists())

    def test_parent_inherited_in_both_cli_orders_and_conflicts_rejected(self):
        self.version()
        self.ok(self.v("init", "--version", "1.1", "--file", self.new))
        reverse11 = self.project / "versions/1.1/reverse-baseline.json"
        self.assertEqual(read(reverse11)["parent_version"], "1.0")
        self.ok(self.v("init", "--version", "1.2", "--parent", "1.1", "--file", self.last))
        self.ok(self.p("version", "--version", "1.2", "--target", self.last))
        canonical12 = self.project / "versions/1.2/version.json"
        self.assertEqual(read(canonical12)["parent_version_id"], "1.1")
        before = canonical12.read_bytes()
        self.rejected(self.p("version", "--version", "1.2", "--target", self.last, "--parent", "1.0"))
        self.assertEqual(before, canonical12.read_bytes())
        self.ok(self.p("resume"))

    def test_repeat_version_preserves_identity_parent_and_metadata(self):
        self.version()
        version = self.project / "versions/1.1/version.json"
        before = version.read_bytes()
        self.ok(self.p("version", "--version", "1.1"))
        self.ok(self.p("version", "--version", "1.1", "--target", self.new, "--parent", "1.0"))
        self.assertEqual(before, version.read_bytes())
        self.rejected(self.p("version", "--version", "1.1", "--target", self.last))
        self.rejected(self.p("version", "--version", "1.1", "--parent", "1.1"))
        self.assertEqual(before, version.read_bytes())
        self.assertEqual((self.project / read(version)["local_path"]).read_bytes(), NEXT)

    def test_force_cannot_destroy_scope_acceptance_manifest_or_history(self):
        align = self.prepared_align()
        self.ok(self.migration(align=align, note="immutable history"))
        scope = self.project / "scope.md"
        scope.write_text("synthetic user scope\n", encoding="utf-8")
        acceptance = self.project / "versions/1.1/acceptance.json"
        content = read(acceptance)
        content["items"] = [{"id": "preserve-me", "status": "pending", "detail": {"value": 7}}]
        write(acceptance, content)
        paths = [scope, acceptance, self.project / "versions/1.1/manifest.json",
                 self.project / "versions/1.1/version.json", self.project / "versions/1.0/reverse-baseline.json"]
        paths += list((self.project / "versions/1.1/migrations").glob("*.json"))
        before = {p: p.read_bytes() for p in paths}
        self.rejected(self.p("init", "--project-id", "replacement", "--force"))
        self.rejected(self.p("version", "--version", "1.1", "--force"))
        self.rejected(self.v("init", "--version", "1.0", "--file", self.last, "--force"))
        self.assertEqual(before, {p: p.read_bytes() for p in paths})

    def test_copy_directory_delete_sources_resume_and_continue_both_clis(self):
        align = self.prepared_align()
        self.ok(self.migration(align=align))
        self.ok(self.v("init", "--version", "1.1", "--parent", "1.0", "--file", self.new))
        moved = self.base / "copied"
        shutil.copytree(self.project, moved)
        shutil.rmtree(self.project)
        for path in (self.old, self.new, self.last):
            path.unlink()
        self.project = moved
        handoff = self.ok(self.p("resume"))["handoff"]
        current = moved / handoff["current_version"]["local_path"]
        self.assertEqual(current.read_bytes(), NEXT)
        baseline = read(moved / "versions/1.1/reverse-baseline.json")
        local = moved / baseline["binary"]["local_path"]
        self.ok(self.p("version", "--version", "1.1"))
        self.ok(self.site(version="1.1", file=local, offset="6"))
        self.ok(self.align(file=current))
        self.ok(self.migration(align=moved / "versions/1.1/align.json"))
        asset = read(moved / "assets/asset-main/asset.json")
        self.assertEqual((moved / asset["local_path"]).read_bytes(), OLD)

    def test_tampered_and_missing_assets_targets_and_reverse_copy_block_resume(self):
        self.version()
        records = [read(self.project / "assets/asset-main/asset.json"),
                   read(self.project / "versions/1.1/version.json"),
                   read(self.project / "versions/1.0/reverse-baseline.json")["binary"]]
        for record in records:
            path = self.project / record["local_path"]
            original = path.read_bytes()
            for replacement in (b"X" * len(original), None):
                with self.subTest(path=record["local_path"], missing=replacement is None):
                    if replacement is None:
                        path.unlink()
                    else:
                        path.write_bytes(replacement)
                    data = self.rejected(self.p("resume"))
                    self.assertEqual(data["handoff"]["status"], "blocked")
                    self.assertTrue(data["handoff"]["state_errors"])
                    self.assertEqual(read(self.project / "handoff.json")["status"], "blocked")
                    path.write_bytes(original)
                    self.ok(self.p("resume"))

    def test_registration_recomputes_aob_despite_explicit_offset(self):
        before = (self.project / "versions/1.0/reverse-baseline.json").read_bytes()
        for fields in ({"aob": "41", "offset": "0"},
                       {"aob": "FF", "offset": "0"},
                       {"aob": PATTERN, "offset": "3"},
                       {"aob": "?? ??", "offset": "4"},
                       {"aob": "", "offset": "-1"},
                       {"aob": "", "offset": str(len(OLD))},
                       {"aob": "", "offset": str(len(OLD) - 1), "original": "42 42"}):
            with self.subTest(fields=fields):
                self.rejected(self.site(**fields))
                self.assertEqual(before, (self.project / "versions/1.0/reverse-baseline.json").read_bytes())
        result = self.ok(self.site(offset="4", original="85 C0 74 12"))
        self.assertEqual(result["site"]["self_check"]["hits_in_own_binary"], 1)
        self.assertTrue(result["site"]["self_check"]["unique"])

    def test_foreign_file_and_changed_baseline_rejected(self):
        self.rejected(self.site(file=self.new, offset="6"))
        baseline = read(self.project / "versions/1.0/reverse-baseline.json")
        path = self.project / baseline["binary"]["local_path"]
        path.write_bytes(b"Q" * len(OLD))
        self.rejected(self.site(offset="4"))
        self.rejected(self.align())
        self.assertEqual(read(self.project / "versions/1.0/reverse-baseline.json")["sites"], [])

    def test_three_state_alignment_and_project_rejects_failed_results(self):
        self.ok(self.site(offset="4"))
        for version, data, expected in (("unique", NEXT, "unique"),
                                        ("missing", b"no branch here", "missing"),
                                        ("multi", NEXT + NEXT, "multi")):
            with self.subTest(status=expected):
                target = self.base / (version + ".bin")
                target.write_bytes(data)
                self.version(version, "1.0", target)
                result = self.align(new=version, file=target)
                self.assertEqual(result[0], 0 if expected == "unique" else 2)
                self.assertEqual(result[1]["summary"][expected], 1)
                align = self.project / "versions" / version / "align.json"
                row = read(align)["sites"][0]
                self.assertEqual(row["matches"], {"unique": 1, "missing": 0, "multi": 2}[expected])
                migration = self.migration(align=align, target=version)
                if expected == "unique":
                    self.ok(migration)
                else:
                    self.rejected(migration)
                    self.assertFalse((align.parent / "migration.json").exists())

    def test_empty_and_manual_alignment_are_not_success(self):
        self.version()
        empty = self.align()
        self.rejected(empty)
        path = self.project / "versions/1.1/align.json"
        self.assertEqual(read(path)["sites"], [])
        self.rejected(self.migration(align=path))
        site = self.ok(self.site(aob="", offset="4", original="85 C0"))["site"]
        self.assertFalse(site["self_check"]["unique"])
        self.rejected(self.align())
        self.assertEqual(read(path)["summary"]["needs_manual"], 1)
        self.rejected(self.migration(align=path))
        self.assertFalse((path.parent / "migration.json").exists())

    def test_forged_summary_hash_version_and_offset_rejected(self):
        align = self.prepared_align()
        original = read(align)
        mutations = []
        for key in ("old_version", "new_version"):
            value = copy.deepcopy(original)
            value[key] = "wrong-version"
            mutations.append(value)
        for key in ("old_binary", "new_binary"):
            value = copy.deepcopy(original)
            value[key]["sha256"] = "0" * 64
            mutations.append(value)
        for summary in ({}, {"unique": 1, "missing": 1, "multi": 0, "needs_manual": 0},
                        {"unique": True, "missing": 0, "multi": 0, "needs_manual": 0}):
            value = copy.deepcopy(original)
            value["summary"] = summary
            mutations.append(value)
        for key in ("manual", "missing", "multi", "needs_manual"):
            value = copy.deepcopy(original)
            value[key] = 1
            mutations.append(value)
        for state in ("manual", "missing", "multi", "unknown"):
            value = copy.deepcopy(original)
            value["sites"][0]["status"] = state
            mutations.append(value)
        value = copy.deepcopy(original)
        value["sites"][0]["hits"][0]["offset"] = "0"
        mutations.append(value)
        value = copy.deepcopy(original)
        value["sites"] = []
        mutations.append(value)
        for i, value in enumerate(mutations):
            with self.subTest(mutation=i):
                write(align, value)
                self.rejected(self.migration(align=align))
                self.assertFalse((align.parent / "migration.json").exists())
                self.assertEqual(list((align.parent / "migrations").glob("*.json")), [])
        write(align, original)
        self.ok(self.migration(align=align))

    def test_changed_reverse_baseline_identity_blocks_migration_and_resume(self):
        align = self.prepared_align()
        path = self.project / "versions/1.0/reverse-baseline.json"
        before = read(path)
        for key, value in (("version", "foreign"), ("binary", {"sha256": "0" * 64, "size": len(OLD)})):
            with self.subTest(field=key):
                changed = copy.deepcopy(before)
                changed[key] = value
                write(path, changed)
                self.rejected(self.migration(align=align))
                self.assertEqual(self.rejected(self.p("resume"))["handoff"]["status"], "blocked")
                self.assertFalse((align.parent / "migration.json").exists())
        write(path, before)
        self.ok(self.migration(align=align))

    def test_completed_unavailable_for_empty_or_unverifiable_acceptance(self):
        align = self.prepared_align()
        acceptance = self.project / "versions/1.1/acceptance.json"
        for items in ([], [{"id": "fake", "status": "passed", "evidence": "absent.log"}],
                      [{"id": "wrong-target", "status": "passed", "sha256": "0" * 64, "version_id": "1.0"}]):
            data = read(acceptance)
            data["items"] = items
            write(acceptance, data)
            self.rejected(self.migration("completed", align=align))
            self.assertFalse((align.parent / "migration.json").exists())
            self.assertFalse((align.parent / "migrations").exists())
        self.ok(self.migration("partial", align=align))
        previous = (align.parent / "migration.json").read_bytes()
        self.rejected(self.migration("completed"))
        self.assertEqual(previous, (align.parent / "migration.json").read_bytes())
        self.ok(self.p("run", "--version", "1.1", "--run-id", "unaccepted"))
        self.rejected(self.p("finish-run", "--version", "1.1", "--run-id", "unaccepted", "--status", "completed"))
        run = read(align.parent / "runs/unaccepted/run.json")
        self.assertEqual(run["status"], "active")
        self.assertIsNone(run["finished_at"])

    def test_legacy_baseline_read_and_upgrade_never_overwrite_manifest(self):
        legacy_root = self.base / "legacy"
        fp = {"path": str(self.old), "sha256": hashlib.sha256(OLD).hexdigest(), "size": len(OLD)}
        manifest = legacy_root / "versions/1.0/manifest.json"
        write(manifest, {"schema": "seep-migration/1", "version": "1.0", "binary": fp,
                         "source_exe": str(self.old), "sites": [{"id": "old", "aob": PATTERN, "offset": "0x4"}]})
        before = manifest.read_bytes()
        self.ok(cli(REVERSE, "align", "--case", legacy_root, "--old", "1.0", "--new-version", "1.1", "--new", self.new))
        self.assertEqual(before, manifest.read_bytes())
        self.ok(cli(REVERSE, "add-site", "--case", legacy_root, "--version", "1.0", "--file", self.old,
                    "--id", "new", "--sem", "synthetic", "--aob", "41 41 41 41", "--offset", "0"))
        self.assertEqual(before, manifest.read_bytes())
        baseline = read(manifest.with_name("reverse-baseline.json"))
        self.assertEqual(len(baseline["sites"]), 2)
        self.assertEqual((legacy_root / baseline["binary"]["local_path"]).read_bytes(), OLD)
        self.old.unlink()
        # The upgraded baseline is portable even though one pattern now misses.
        result = cli(REVERSE, "align", "--case", legacy_root, "--old", "1.0", "--new-version", "1.2", "--new", self.new)
        self.rejected(result)
        self.assertEqual(result[1]["summary"]["missing"], 1)
        self.assertEqual(result[1]["summary"]["unique"], 1)

    def test_legacy_migration_read_only_and_archived_before_revision(self):
        """历史兼容 = 可读，不是自动认证（主 Agent 规范 C）。

        记录仍逐字节读取、永不被覆盖；但无可复核 closure 的 completed
        migration 声明会让项目 blocked（rc=2），不会被报告为 ok/已验证。
        这是主 Agent 明确收紧的负例，不是删除负例。
        """
        self.version()
        path = self.project / "versions/1.1/migration.json"
        old = {"schema": "seep-migration/1", "migration_id": "historic", "project_id": "synthetic",
               "from_version": "1.0", "to_version": "1.1", "status": "completed",
               "created_at": "2000-01-01T00:00:00Z", "note": "old detailed receipt", "align": {"legacy": True}}
        write(path, old)
        result = self.p("resume")
        self.assertEqual(result[0], 2, result)
        self.assertFalse(result[1]["ok"], "legacy completion must not be ok=true")
        handoff = result[1]["handoff"]          # 可读但 blocked
        self.assertEqual(handoff["status"], "blocked")
        self.assertEqual([x["id"] for x in handoff["closure_legacy"]], ["historic"])
        self.assertFalse(handoff["closure_legacy"][0]["verified"])
        self.assertFalse(handoff["acceptance_complete"])
        self.assertEqual(read(path), old)
        self.ok(self.migration(note="new partial receipt"))
        archives = [read(p) for p in (path.parent / "migrations").glob("*.json")]
        self.assertEqual(len(archives), 2)
        self.assertIn(old, archives)
        self.assertIn(read(path), archives)

    def test_real_process_concurrent_same_run_has_exactly_one_success(self):
        self.version()
        workers = 8
        barrier = threading.Barrier(workers)
        def start(index):
            barrier.wait(timeout=15)
            return self.p("run", "--version", "1.0" if index % 2 else "1.1", "--run-id", "same-run")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(start, range(workers)))
        self.assertEqual(sorted(rc for rc, _ in results), [0] + [2] * (workers - 1), results)
        runs = list((self.project / "versions").glob("*/runs/same-run/run.json"))
        self.assertEqual(len(runs), 1)
        events = [json.loads(line) for line in (self.project / "facts.jsonl").read_text(encoding="utf-8").splitlines()]
        starts = [e for e in events if e.get("type") == "run_started"]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0]["version_id"], read(runs[0])["version_id"])
        self.assertEqual(self.ok(self.p("resume"))["handoff"]["active_runs"], ["same-run"])

    def test_both_cli_commands_obey_shared_transaction_lock(self):
        # A separate process holds the public API lock, then releases via stdin.
        # Both real CLI processes must remain pending until that release.
        code = ("import sys; from pathlib import Path; "
                "sys.path.insert(0, sys.argv[1]); from lib.project_lock import project_lock; "
                "\nwith project_lock(Path(sys.argv[2])):\n print('locked', flush=True)\n sys.stdin.readline()\n")
        holder = subprocess.Popen([sys.executable, "-B", "-c", code, str(PROJECT.parent), str(self.project)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, encoding="utf-8", env=ENV)
        children = []
        try:
            self.assertEqual(holder.stdout.readline().strip(), "locked")
            commands = ([sys.executable, "-B", str(PROJECT), "version", "--project", str(self.project), "--version", "1.0"],
                        [sys.executable, "-B", str(REVERSE), "add-site", "--case", str(self.project), "--version", "1.0",
                         "--file", str(self.old), "--id", "lock-site", "--sem", "synthetic", "--aob", PATTERN])
            children = [subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                         encoding="utf-8", env=ENV, cwd=ROOT) for cmd in commands]
            time.sleep(0.4)
            self.assertEqual([child.poll() for child in children], [None, None])
            self.assertEqual(read(self.project / "versions/1.0/reverse-baseline.json")["sites"], [])
            holder.communicate("release\n", timeout=10)
            self.assertEqual(holder.returncode, 0)
            for child in children:
                stdout, stderr = child.communicate(timeout=20)
                self.assertEqual(child.returncode, 0, (stdout, stderr))
                self.assertTrue(json.loads(stdout)["ok"])
        finally:
            for child in children + [holder]:
                if child.poll() is None:
                    child.kill()
                    child.communicate(timeout=10)

    def test_run_directory_reserved_exclusively(self):
        reserved = self.project / "versions/1.0/runs/interrupted"
        reserved.mkdir()
        self.rejected(self.p("run", "--version", "1.0", "--run-id", "interrupted"))
        self.assertFalse((reserved / "run.json").exists())

    def test_pe32_and_pe32plus_image_base_from_synthetic_headers(self):
        spec = importlib.util.spec_from_file_location("lifecycle_reverse", REVERSE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for magic, expected in ((0x10B, 0x400000), (0x20B, 0x140000000)):
            with self.subTest(magic=magic):
                data = bytearray(512)
                data[:2] = b"MZ"
                struct.pack_into("<I", data, 0x3C, 0x80)
                data[0x80:0x84] = b"PE\0\0"
                struct.pack_into("<HHIIIHH", data, 0x84, 0x14C if magic == 0x10B else 0x8664, 0, 0, 0, 0, 0xE0, 0)
                opt = 0x80 + 24
                struct.pack_into("<H", data, opt, magic)
                struct.pack_into("<I", data, opt + 16, 0x1234)
                if magic == 0x10B:
                    struct.pack_into("<I", data, opt + 24, 0xDEAD)  # BaseOfData, not ImageBase.
                    struct.pack_into("<I", data, opt + 28, expected)
                else:
                    struct.pack_into("<Q", data, opt + 24, expected)
                self.assertEqual(module.pe_info(bytes(data))["image_base"], hex(expected))
                self.assertEqual(module.pe_info(bytes(data))["entry_rva"], "0x1234")


if __name__ == "__main__":
    unittest.main(verbosity=2)
