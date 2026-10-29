#!/usr/bin/env python3
"""Acceptance-integrity regression: replay the independent audit's bypasses.

Every case drives the real ``project_state.py`` CLI in a TemporaryDirectory, and
each negative case is paired with a positive control on the *same* fixture so a
pass can never come from a broken fixture.  Nothing here interprets a real log
or executes a target: witnesses are synthetic text, so the strongest claim is
``structural+recorded_witness``.

Replayed audit items (work/goal-recovery/control-acceptance-verification.md):
  B7  hand-written ``items[].status = pass`` without any ``acceptance-record``
  B8  closure written for a checklist that has no record chain
  B9  edited ``acceptance.json.target_sha256`` accepted by resume
  C1  checklist edited after completion (``description``/``how``/``revision``)
  C2  ``closure.evidence_sha256`` rewritten
  C3  ``acceptance_snapshot``'s own hashes rewritten
  D2  rewritten post-completion checklist not reported as stale
  D4  deleted ``acceptance-revisions`` entry not reported
  N15 stripped ``revision_history``/``revisions``/``archive_index``
  N16 resume silent after the history was stripped
Plus the laundering variant: tamper first, then try to re-record so the tampered
bytes would be archived as a legitimate revision.

Run: python -B -X utf8 Tool/scripts/test_acceptance_integrity.py
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "Tool/scripts/project_state.py"
ENV = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
OLD = b"AAAA\x85\xc0\x74\x12BBBB"
NEXT = b"ZZZZZZ\x85\xc0\x74\x22CCCC"
WITNESS = b"synthetic witness\n"


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n",
                          encoding="utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def cli(*args):
    result = subprocess.run([sys.executable, "-B", str(PROJECT), *map(str, args)],
                            cwd=ROOT, env=ENV, capture_output=True, text=True,
                            encoding="utf-8", timeout=90)
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        raise AssertionError((result.returncode, result.stdout[-2000:], result.stderr[-2000:]))
    if result.stderr:
        raise AssertionError(result.stderr[-2000:])
    return result.returncode, payload


class IntegrityBase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seep-integrity-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.project = self.base / "project"
        self.old = self.base / "old.bin"
        self.new = self.base / "new.bin"
        self.old.write_bytes(OLD)
        self.new.write_bytes(NEXT)
        self.ok(self.p("init", "--project-id", "synthetic-integrity", "--target", self.old))
        self.ok(self.p("version", "--version", "1.1", "--parent", "1.0", "--target", self.new))
        self.target = read(self.project / "versions/1.1/version.json")["sha256"]
        self.witness = self.project / "versions/1.1/artifacts/probe.log"
        self.witness.parent.mkdir(parents=True, exist_ok=True)
        self.witness.write_bytes(WITNESS)
        self.acceptance = self.project / "versions/1.1/acceptance.json"
        self.run_json = self.project / "versions/1.1/runs/run-1/run.json"
        self.revisions = self.project / "versions/1.1/acceptance-revisions"

    # ---- helpers -------------------------------------------------------
    def p(self, command, *args):
        return cli(command, "--project", self.project, *args)

    def ok(self, result):
        self.assertEqual(result[0], 0, result)
        self.assertTrue(result[1]["ok"], result)
        return result[1]

    def rejected(self, result):
        self.assertEqual(result[0], 2, result)
        self.assertFalse(result[1]["ok"], result)
        return result[1]

    def start(self, run="run-1"):
        return self.p("run", "--version", "1.1", "--run-id", run, "--executor", "test")

    def register(self, evidence_id="ev-1", run="run-1"):
        relative = self.witness.relative_to(self.project).as_posix()
        return self.p("evidence", "--version", "1.1", "--run-id", run,
                      "--evidence-id", evidence_id,
                      "--target-sha256", self.target, "--path", relative,
                      "--sha256", digest(WITNESS), "--size", len(WITNESS),
                      "--source", relative, "--how", "synthetic", "--recorded-by", "test")

    def define(self, *items):
        args = ["--version", "1.1"]
        for item in items or ("probe:synthetic probe executed",):
            args.extend(("--item", item))
        return self.p("acceptance-define", *args)

    def record(self, item_id="probe", result="pass", evidence_ids="ev-1",
               verifier="test harness", how="ran synthetic probe", run="run-1"):
        return self.p("acceptance-record", "--version", "1.1", "--item-id", item_id,
                      "--result", result, "--evidence-ids", evidence_ids,
                      "--verifier", verifier, "--how", how, "--run", run)

    def complete(self, run="run-1"):
        return self.p("finish-run", "--version", "1.1", "--run-id", run,
                      "--status", "completed", "--note", "synthetic")

    def resume(self):
        return self.p("resume")

    def completed_project(self):
        """Positive control: the only legal route to a completed run."""
        self.ok(self.start())
        self.ok(self.define())
        self.ok(self.register())
        self.ok(self.record())
        self.ok(self.complete())
        handoff = self.ok(self.resume())["handoff"]
        self.assertTrue(handoff["acceptance_complete"])
        self.assertEqual(handoff["closure_errors"], [])
        self.assertEqual(handoff["acceptance_errors"], [])
        return handoff

    def handoff(self):
        return read(self.project / "handoff.json")

    def refresh(self):
        """Run resume (expecting rc=2) and return the refreshed, persisted handoff."""
        self.rejected(self.resume())
        return self.handoff()

    def errors(self, handoff):
        return json.dumps([handoff.get("state_errors"), handoff.get("acceptance_errors"),
                           handoff.get("closure_errors")], ensure_ascii=False)

    def chain_files(self):
        return sorted(self.revisions.glob("rev-*.json"))

    def assert_reported(self, needle):
        handoff = self.refresh()
        self.assertFalse(handoff["acceptance_complete"], handoff["acceptance_complete"])
        self.assertIn(needle, self.errors(handoff))
        return handoff


class ChainProvenance(IntegrityBase):
    """B7/B8/B9: a pass must come from a real acceptance-record, not hand edits."""

    def test_handwritten_pass_without_record_cannot_complete(self):
        self.ok(self.start())
        self.ok(self.define())
        self.ok(self.register())
        original = self.acceptance.read_bytes()
        data = read(self.acceptance)
        data["items"][0].update({"status": "pass", "result": "pass",
                                 "evidence_ids": ["ev-1"], "verifier": "hand",
                                 "how": "hand edit", "revision": 1,
                                 "origin": {"version_id": "1.1", "run_id": "run-1",
                                            "target_sha256": self.target}})
        write(self.acceptance, data)
        self.rejected(self.complete())
        run = read(self.run_json)
        self.assertEqual(run["status"], "active")
        self.assertNotIn("closure", run)
        handoff = self.refresh()
        self.assertFalse(handoff["acceptance_complete"])
        # The individual witness row may look fine; the *chain* is what fails.
        self.assertTrue(handoff["acceptance"]["chain_problems"])
        self.assertIn("写链日志", self.errors(handoff))
        self.assertEqual(handoff["acceptance_stale"], [])
        # Positive control on the same fixture: the legal record path still works.
        self.acceptance.write_bytes(original)
        self.ok(self.record())
        self.ok(self.complete())
        self.assertEqual(read(self.run_json)["closure"]["target_sha256"], self.target)

    def test_handwritten_pass_rejects_even_with_fabricated_history_fields(self):
        self.ok(self.start())
        self.ok(self.define())
        self.ok(self.register())
        original = self.acceptance.read_bytes()
        data = read(self.acceptance)
        data["items"][0].update({"status": "pass", "result": "pass",
                                 "evidence_ids": ["ev-1"], "verifier": "hand",
                                 "how": "hand edit", "revision": 1,
                                 "origin": {"version_id": "1.1", "run_id": "run-1",
                                            "target_sha256": self.target}})
        data["revisions"] = 1
        data["revision_history"] = ["f" * 64]
        data["archive_index"] = ["e" * 64]
        write(self.acceptance, data)
        self.rejected(self.complete())
        self.rejected(self.resume())
        self.assertEqual(read(self.run_json)["status"], "active")
        self.acceptance.write_bytes(original)
        self.ok(self.record())
        self.ok(self.complete())

    def test_pass_requires_run_bound_provenance_fields(self):
        self.ok(self.start())
        self.ok(self.define())
        self.ok(self.register())
        self.ok(self.record())
        original = self.acceptance.read_bytes()
        for mutation in ("empty-verifier", "empty-how", "no-revision", "no-origin",
                         "foreign-run", "foreign-target", "zero-revision"):
            with self.subTest(mutation=mutation):
                data = json.loads(original.decode("utf-8"))
                item = data["items"][0]
                if mutation == "empty-verifier":
                    item["verifier"] = ""
                elif mutation == "empty-how":
                    item["how"] = "   "
                elif mutation == "no-revision":
                    item.pop("revision", None)
                elif mutation == "no-origin":
                    item.pop("origin", None)
                elif mutation == "foreign-run":
                    item["origin"]["run_id"] = "run-other"
                elif mutation == "foreign-target":
                    item["origin"]["target_sha256"] = "0" * 64
                else:
                    item["revision"] = 0
                write(self.acceptance, data)
                self.rejected(self.complete())
                handoff = self.refresh()
                self.assertFalse(handoff["acceptance_complete"])
                self.assertEqual(handoff["acceptance_stale"], ["probe"])
                self.assertEqual(read(self.run_json)["status"], "active")
        self.acceptance.write_bytes(original)
        self.ok(self.complete())

    def test_checklist_target_sha_must_match_version(self):
        self.ok(self.start())
        self.ok(self.define())
        self.ok(self.register())
        self.ok(self.record())
        original = self.acceptance.read_bytes()
        data = json.loads(original.decode("utf-8"))
        data["target_sha256"] = "3" * 64
        write(self.acceptance, data)
        self.rejected(self.complete())
        handoff = self.refresh()
        self.assertFalse(handoff["acceptance_complete"])
        self.assertIn("target_sha256", self.errors(handoff))
        self.assertEqual(handoff["acceptance_stale"], [])
        self.acceptance.write_bytes(original)
        self.ok(self.complete())


class RevisionChain(IntegrityBase):
    """D4/N15/N16: the immutable revision chain cannot be pruned or stripped."""

    def test_deleted_revision_file_is_reported(self):
        self.completed_project()
        files = self.chain_files()
        self.assertGreaterEqual(len(files), 2)
        removed = files[0]
        removed_bytes = removed.read_bytes()
        removed.unlink()
        self.assert_reported("缺少不可覆盖修订文件")
        self.rejected(self.complete())
        self.assertEqual(read(self.run_json)["status"], "completed")
        removed.write_bytes(removed_bytes)
        self.ok(self.resume())

    def test_extra_unregistered_revision_is_reported(self):
        self.completed_project()
        extra = self.revisions / ("rev-" + "a" * 64 + ".json")
        extra.write_bytes(b"{}\n")
        self.assert_reported("未登记修订")
        extra.unlink()
        self.ok(self.resume())

    def test_stripped_history_fields_fail_closed(self):
        self.completed_project()
        original = self.acceptance.read_bytes()
        for keys in (("revision_history",), ("revision_history", "revisions"),
                     ("revision_history", "revisions", "archive_index")):
            with self.subTest(stripped=list(keys)):
                data = json.loads(original.decode("utf-8"))
                for key in keys:
                    data.pop(key, None)
                write(self.acceptance, data)
                self.rejected(self.complete())
                handoff = self.refresh()
                self.assertFalse(handoff["acceptance_complete"])
                self.assertTrue(handoff["acceptance_errors"])
                self.assertTrue(handoff["acceptance"]["chain_problems"])
                self.assertIn("修订链", self.errors(handoff))
                self.assertEqual(read(self.run_json)["status"], "completed")
        self.acceptance.write_bytes(original)
        self.ok(self.resume())

    def test_tamper_then_rerecord_cannot_launder_edited_bytes(self):
        self.completed_project()
        before = self.acceptance.read_bytes()
        files_before = [p.name for p in self.chain_files()]
        data = json.loads(before.decode("utf-8"))
        data["items"][0].update({"status": "fail", "result": "fail",
                                 "how": "rewritten by hand"})
        write(self.acceptance, data)
        # Ruling 1 tightens this case: the run is closed, so *any* further record
        # is refused before the chain is even consulted (nothing is written).
        record = self.rejected(self.record(result="pass"))
        self.assertIn("已收尾 run 的验收不可再修改", record["reason"])
        self.assertEqual(read(self.run_json)["status"], "completed")
        self.assert_reported("完成后当前清单已变")
        # The anti-laundering rule itself is preserved: on a fresh active run the
        # hand-edited head is still refused because the chain cannot be recomputed.
        self.ok(self.start(run="run-2"))
        laundering = self.rejected(self.record(result="unknown", run="run-2"))
        self.assertIn("验收修订链已损坏", laundering["reason"])
        self.assertEqual(data, read(self.acceptance))
        self.assertEqual(files_before, [p.name for p in self.chain_files()])
        self.acceptance.write_bytes(before)
        self.assertEqual(files_before, [p.name for p in self.chain_files()])
        self.ok(self.resume())

    def test_revision_archive_content_must_hash_to_its_name(self):
        self.completed_project()
        target = self.chain_files()[0]
        original = target.read_bytes()
        data = json.loads(original.decode("utf-8"))
        data["note"] = "rewritten inside an immutable revision"
        target.write_bytes(json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"))
        self.assert_reported("修订归档内容与文件名哈希不符")
        self.assertEqual(read(self.run_json)["status"], "completed")
        self.rejected(self.record(result="unknown"))
        target.write_bytes(original)
        self.ok(self.resume())

    def test_deleted_chain_log_is_reported(self):
        self.completed_project()
        log = self.revisions / "chain.jsonl"
        saved = log.read_bytes()
        log.unlink()
        self.assert_reported("缺少验收写链日志")
        log.write_bytes(saved)
        self.ok(self.resume())


class ClosureRecompute(IntegrityBase):
    """C1-C3/D2: closure hashes are recomputed, never trusted as the expectation."""

    def test_checklist_edit_after_completion_is_stale(self):
        self.completed_project()
        original = self.acceptance.read_bytes()
        closure = read(self.run_json)["closure"]
        for mutation in ("description", "how", "evidence-ids", "verifier", "revision"):
            with self.subTest(mutation=mutation):
                data = json.loads(original.decode("utf-8"))
                item = data["items"][0]
                if mutation == "description":
                    item["description"] = "rewritten after completion"
                elif mutation == "how":
                    item["how"] = "rewritten after completion"
                elif mutation == "evidence-ids":
                    item["evidence_ids"] = ["ev-1", "ev-1"]
                elif mutation == "verifier":
                    item["verifier"] = "someone else"
                else:
                    item["revision"] = 9
                write(self.acceptance, data)
                self.rejected(self.complete())
                handoff = self.refresh()
                self.assertFalse(handoff["acceptance_complete"])
                self.assertTrue(handoff["closure_errors"])
                self.assertIn("完成后当前清单已变", self.errors(handoff))
        self.acceptance.write_bytes(original)
        self.ok(self.resume())
        self.assertEqual(read(self.run_json)["closure"], closure)

    def test_recomputed_closure_cannot_be_resealed_by_editing_hashes(self):
        self.completed_project()
        data = read(self.acceptance)
        data["items"][0]["description"] = "rewritten after completion"
        write(self.acceptance, data)
        forged = digest(self.acceptance.read_bytes())
        run = read(self.run_json)
        run["closure"]["acceptance_sha256"] = forged
        run["acceptance_snapshot"]["acceptance_sha256"] = forged
        write(self.run_json, run)
        # The forged hash matches the current file but not the revision chain.
        handoff = self.refresh()
        self.assertFalse(handoff["acceptance_complete"])
        self.assertIn("非不可覆盖链上的修订", self.errors(handoff))
        self.assertIn("验收快照修订链不可复算", self.errors(handoff))
        self.rejected(self.complete())

    def test_closure_evidence_hash_is_recomputed(self):
        self.completed_project()
        run = read(self.run_json)
        run["closure"]["evidence_sha256"] = {"ev-1": "f" * 64}
        write(self.run_json, run)
        self.assertIn("证据哈希与真实证据索引不符", self.errors(self.refresh()))

    def test_snapshot_internals_are_recomputed(self):
        self.completed_project()
        original = self.run_json.read_bytes()
        for mutation in ("evidence-sha", "acceptance-sha", "required-count",
                         "target-sha", "run-id", "counts"):
            with self.subTest(mutation=mutation):
                run = json.loads(original.decode("utf-8"))
                snapshot = run["acceptance_snapshot"]
                if mutation == "evidence-sha":
                    snapshot["evidence_sha256"] = {"ev-1": "e" * 64}
                elif mutation == "acceptance-sha":
                    snapshot["acceptance_sha256"] = "a" * 64
                elif mutation == "required-count":
                    snapshot["required_count"] = 7
                elif mutation == "target-sha":
                    snapshot["target_sha256"] = "b" * 64
                elif mutation == "run-id":
                    snapshot["run_id"] = "run-other"
                else:
                    snapshot["counts"] = {"pending": 0, "pass": 2, "fail": 0,
                                          "unknown": 0, "skipped": 0}
                write(self.run_json, run)
                handoff = self.refresh()
                self.assertTrue(handoff["closure_errors"])
                self.assertIn("验收快照与当前验收/证据不符", self.errors(handoff))
        self.run_json.write_bytes(original)
        self.ok(self.resume())

    def test_snapshot_witness_row_is_recomputed(self):
        self.completed_project()
        run = read(self.run_json)
        run["acceptance_snapshot"]["required"][0]["evidence"][0]["sha256"] = "c" * 64
        write(self.run_json, run)
        handoff = self.refresh()
        self.assertFalse(handoff["acceptance_complete"])
        # Whole-object comparison names the offending field instead of a
        # hand-written whitelist message.
        self.assertIn("验收快照与当前验收/证据不符", self.errors(handoff))
        self.assertIn('"fields": ["required"]', self.errors(handoff))

    def test_closure_target_sha_is_recomputed(self):
        self.completed_project()
        run = read(self.run_json)
        run["closure"]["target_sha256"] = "d" * 64
        write(self.run_json, run)
        self.assertIn("目标哈希已变", self.errors(self.refresh()))

    def test_recorded_closure_still_opens_for_unchanged_state(self):
        """Negative cases must be paired with a positive control."""
        self.completed_project()
        run = read(self.run_json)
        self.assertEqual(run["closure"]["target_sha256"], self.target)
        self.assertEqual(run["closure"]["evidence_sha256"], {"ev-1": digest(WITNESS)})
        snapshot = run["acceptance_snapshot"]
        self.assertEqual(snapshot["acceptance_sha256"],
                         digest(self.acceptance.read_bytes()))
        self.assertEqual(snapshot["acceptance_chain"][-1],
                         digest(self.acceptance.read_bytes()))
        self.assertEqual(snapshot["run_id"], "run-1")
        events = [json.loads(line) for line in
                  (self.project / "facts.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len([e for e in events if e.get("type") == "run_finished"]), 1)


class CompletionConcurrency(IntegrityBase):
    """Concurrent completion must still succeed exactly once."""

    def test_concurrent_completion_has_exactly_one_success(self):
        self.ok(self.start())
        self.ok(self.define())
        self.ok(self.register())
        self.ok(self.record())
        workers = 6
        barrier = threading.Barrier(workers)

        def finish(_):
            barrier.wait(timeout=20)
            return self.complete()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(finish, range(workers)))
        self.assertEqual(sorted(rc for rc, _ in results), [0] + [2] * (workers - 1), results)
        run = read(self.run_json)
        self.assertEqual(run["status"], "completed")
        self.assertIn("closure", run)
        events = [json.loads(line) for line in
                  (self.project / "facts.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len([e for e in events if e.get("type") == "run_finished"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
