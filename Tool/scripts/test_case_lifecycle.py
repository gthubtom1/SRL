"""Failure and restart tests for case lifecycle records, in isolated directories."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import case_state as C


class CaseLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-case-life-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "case"
        self.root.mkdir()
        self.home = self.base / "home"
        self.home.mkdir()
        patch = mock.patch.dict(os.environ, {"HOME": str(self.home), "USERPROFILE": str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)
        self.target = self.base / "target.bin"
        self.target.write_bytes(b"fixture target")

    def call(self, function, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                result = function(argparse.Namespace(case=str(self.root), **kwargs))
                code = result if type(result) is int else 0
            except SystemExit as exc:
                code = exc.code
        return code, output.getvalue()

    def init(self, **kwargs):
        options = dict(target=str(self.target), force=False, evidence_kind="fixture", domain="softseep")
        options.update(kwargs)
        return self.call(C.cmd_init, **options)

    def ask(self, **kwargs):
        options = dict(stuck="Pick the required input", option=["A supply input", "B stop"],
                       monitor="", guarantee="", expect="")
        options.update(kwargs)
        return self.call(C.cmd_ask, **options)

    def test_init_metadata_failure_leaves_no_partial_case(self):
        with mock.patch.object(C, "_ensure_case_meta", side_effect=OSError("metadata unavailable")):
            try:
                code, _ = self.init()
            except OSError:
                code = 2
        self.assertEqual(code, 2)
        self.assertFalse((self.root / "facts.jsonl").exists(), "failed init published a state row")
        self.assertFalse((self.root / "case.json").exists())
        self.assertFalse((self.home / ".seep/current-case").exists())
        self.assertEqual(self.init()[0], 0)

    def test_force_cannot_split_metadata_target_from_state(self):
        self.assertEqual(self.init()[0], 0)
        before = (self.root / "facts.jsonl").read_bytes()
        metadata = (self.root / "case.json").read_bytes()
        other = self.base / "other.bin"
        other.write_bytes(b"other target")
        self.assertEqual(self.init(target=str(other), force=True)[0], 2)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)
        self.assertEqual((self.root / "case.json").read_bytes(), metadata)
        self.assertEqual(self.init(target="", force=True)[0], 0)
        self.assertEqual(C.load_state(str(self.root))["target"], str(self.target))

    def test_force_preserves_pending_question_and_selected_route(self):
        self.assertEqual(self.init()[0], 0)
        self.assertEqual(self.ask()[0], 0)
        plan = [
            {"level": "L1", "route": "inspect", "p": 0.7, "chosen": True},
            {"level": "L2", "route": "patch", "p": 0.4, "chosen": False},
        ]
        C.save_plan(str(self.root), plan)
        state = dict(C.load_state(str(self.root)), goal_level="L1", goal_route="inspect")
        C.save_state(str(self.root), state)
        self.assertEqual(self.init(force=True)[0], 0)
        current = C.load_state(str(self.root))
        self.assertEqual(current["awaiting_human"]["stuck"], "Pick the required input")
        self.assertEqual(current["goal_level"], "L1")
        self.assertEqual(C.load_plan(str(self.root)), plan)

    def test_force_cannot_replace_legacy_target_files_identity(self):
        initial = self.base / "legacy.bin"
        initial.write_bytes(b"legacy target")
        digest = C._fingerprint_target(str(initial))["sha256"]
        (self.root / "case.json").write_text(json.dumps({
            "id": "case",
            "target_files": [{"path": str(initial), "sha256": digest, "size": 13}],
        }), encoding="utf-8")
        other = self.base / "other.bin"
        other.write_bytes(b"other target")
        before = (self.root / "case.json").read_bytes()
        code, output = self.init(target=str(other), force=True)
        self.assertEqual(code, 2, output)
        self.assertEqual((self.root / "case.json").read_bytes(), before)
        self.assertFalse((self.root / "facts.jsonl").exists())

    def test_choose_failure_cannot_publish_only_the_chosen_plan(self):
        self.assertEqual(self.init()[0], 0)
        C.save_plan(str(self.root), [{"level": "L1", "route": "inspect", "p": 0.7, "chosen": False}])
        before = (self.root / "facts.jsonl").read_bytes()
        original = C._atomic_append_line

        def fail_state(path, line):
            if '"kind": "state"' in line:
                raise OSError("state write failure")
            return original(path, line)

        with mock.patch.object(C, "_atomic_append_line", side_effect=fail_state):
            self.assertEqual(self.call(C.cmd_choose, level="L1", route="inspect")[0], 2)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)

    def test_downgrade_cannot_upgrade_or_omit_reason(self):
        self.assertEqual(self.init()[0], 0)
        C.save_state(str(self.root), dict(C.load_state(str(self.root)), max_level="M2"))
        before = (self.root / "facts.jsonl").read_bytes()
        for level, reason in (("M4", "upgrade"), ("M1", "  "), ("invented", "unknown")):
            with self.subTest(level=level, reason=reason):
                self.assertEqual(self.call(C.cmd_downgrade, to=level, reason=reason)[0], 2)
                self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)

    def test_ask_state_failure_preserves_existing_card_and_ledger(self):
        self.assertEqual(self.init()[0], 0)
        self.assertEqual(self.ask()[0], 0)
        cards = {p.name: p.read_bytes() for p in (self.root / "ask").glob("*.md")}
        before = (self.root / "facts.jsonl").read_bytes()
        with mock.patch.object(C, "_atomic_append_line", side_effect=OSError("state failure")):
            self.assertEqual(self.ask(stuck="different question")[0], 2)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)
        self.assertEqual({p.name: p.read_bytes() for p in (self.root / "ask").glob("*.md")}, cards)

    def test_duplicate_option_keys_do_not_overwrite_choice(self):
        self.assertEqual(self.init()[0], 0)
        before = (self.root / "facts.jsonl").read_bytes()
        self.assertEqual(self.ask(option=["A first", "A second"])[0], 2)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)

    def test_handoff_reads_the_actual_pending_ask(self):
        self.assertEqual(self.init()[0], 0)
        self.assertEqual(self.ask()[0], 0)
        code, output = self.call(C.cmd_handoff)
        self.assertEqual(code, 0)
        self.assertIn("Pick the required input", output)
        self.assertNotIn("无未决 ASK", output)

    def test_ack_requires_exact_choice_and_reports_marker_failure(self):
        self.assertEqual(self.init()[0], 0)
        self.assertEqual(self.ask()[0], 0)
        self.assertEqual(self.call(C.cmd_ack, ack="Anything")[0], 2)
        with mock.patch.object(C, "_write_run_ack", return_value=""):
            self.assertEqual(self.call(C.cmd_ack, ack="A")[0], 2)
        self.assertEqual(C.load_state(str(self.root))["awaiting_human"]["ack"], "A")
        self.assertEqual(self.call(C.cmd_ack, ack="A")[0], 0)
        before = (self.root / "facts.jsonl").read_bytes()
        self.assertEqual(self.call(C.cmd_ack, ack="B")[0], 2)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)

    def test_ack_binds_the_system_command_challenge(self):
        self.assertEqual(self.init()[0], 0)
        self.assertEqual(self.ask()[0], 0)
        challenge = "a" * 64
        self.assertEqual(self.call(C.cmd_ack, ack="A", challenge=challenge)[0], 0)
        marker = json.loads((self.home / ".seep/run-ack.json").read_text(encoding="utf-8"))
        self.assertEqual(marker["challenge"], challenge)
        self.assertEqual(marker["letter"], "A")

    def test_new_ask_invalidates_previous_host_ack(self):
        self.assertEqual(self.init()[0], 0)
        self.assertEqual(self.ask()[0], 0)
        self.assertEqual(self.call(C.cmd_ack, ack="A")[0], 0)
        marker = self.home / ".seep/run-ack.json"
        self.assertTrue(marker.exists())
        self.assertEqual(self.ask(stuck="A newer question")[0], 0)
        self.assertFalse(marker.exists())
        current = C.load_state(str(self.root))
        self.assertIsNone(current["awaiting_human"]["ack"])
        self.assertEqual(current["awaiting_human"]["stuck"], "A newer question")

    def test_new_ask_does_not_publish_if_old_marker_cannot_be_invalidated(self):
        self.assertEqual(self.init()[0], 0)
        self.assertEqual(self.ask()[0], 0)
        cards = {p.name: p.read_bytes() for p in (self.root / "ask").glob("*.md")}
        before = (self.root / "facts.jsonl").read_bytes()
        with mock.patch.object(C, "_invalidate_run_ack", side_effect=OSError("marker busy")):
            self.assertEqual(self.ask(stuck="must not publish")[0], 2)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)
        self.assertEqual({p.name: p.read_bytes() for p in (self.root / "ask").glob("*.md")}, cards)

    def test_block_write_failure_is_not_success(self):
        self.assertEqual(self.init()[0], 0)
        table = C._jd("blockers.json")
        with mock.patch.object(C, "save_state", side_effect=OSError("write failure")):
            code, _ = self.call(C.cmd_block, list=False, code=table["codes"][0]["code"],
                                detail="fixture", why="fixture", got="fixture")
        self.assertEqual(code, 2)

    def crash(self, command, hook):
        driver = self.base / "crash.py"
        driver.write_text(
            "import os,sys\nfrom pathlib import Path\n"
            f"sys.path.insert(0, {str(HERE)!r})\nimport case_state as C\n" + hook +
            f"\nsys.argv=['case_state.py']+{command!r}\nC.main()\n", encoding="utf-8")
        result = subprocess.run([sys.executable, "-B", "-X", "utf8", str(driver)],
                                capture_output=True, text=True, encoding="utf-8", timeout=12)
        self.assertEqual(result.returncode, 73, result.stdout + result.stderr)

    def test_real_exit_during_init_refuses_reads_then_retry_recovers(self):
        self.crash(["init", "--case", str(self.root), "--target", str(self.target),
                    "--evidence-kind", "fixture"],
                   "original=C._atomic_append_line\n"
                   "def stop(path,line):\n original(path,line)\n os._exit(73)\n"
                   "C._atomic_append_line=stop\n")
        self.assertTrue((self.root / ".project-transaction.json").exists())
        self.assertEqual(self.call(C.cmd_show)[0], 2)
        self.assertEqual(self.init()[0], 0)
        self.assertFalse((self.root / ".project-transaction.json").exists())
        self.assertEqual(len(C.load_ledger(str(self.root))), 1)
        self.assertEqual(C.load_state(str(self.root))["target"], str(self.target))

    def test_real_exit_during_force_restores_old_bytes(self):
        self.assertEqual(self.init()[0], 0)
        before = {name: (self.root / name).read_bytes() for name in ("facts.jsonl", "case.json", "scope.md")}
        self.crash(["init", "--force", "--case", str(self.root), "--target", str(self.target)],
                   "original=C._ensure_case_meta\n"
                   "def stop(*args,**kwargs):\n original(*args,**kwargs)\n os._exit(73)\n"
                   "C._ensure_case_meta=stop\n")
        from lib.project_lock import project_lock
        with project_lock(self.root, recover=True):
            self.assertFalse((self.root / ".project-transaction.json").exists())
        self.assertEqual({name: (self.root / name).read_bytes() for name in before}, before)
        self.assertEqual(self.init(force=True)[0], 0)

    def test_real_exit_after_question_card_is_recovered_on_retry(self):
        self.assertEqual(self.init()[0], 0)
        self.assertEqual(self.ask()[0], 0)
        original_cards = {p.name: p.read_bytes() for p in (self.root / "ask").glob("*.md")}
        self.crash(["ask", "--case", str(self.root), "--stuck", "interrupted", "--option", "A one",
                    "--option", "B two"],
                   "original=C._atomic_write_text\n"
                   "def stop(path,text):\n original(path,text)\n"
                   " if Path(path).parent.name=='ask': os._exit(73)\n"
                   "C._atomic_write_text=stop\n")
        self.assertEqual(self.call(C.cmd_show)[0], 2)
        self.assertEqual(self.ask(stuck="retry question")[0], 0)
        cards = {p.name: p.read_bytes() for p in (self.root / "ask").glob("*.md")}
        self.assertEqual(len(cards), 2)
        for name, payload in original_cards.items():
            self.assertEqual(cards[name], payload)
        self.assertFalse(any(b"interrupted" in data for data in cards.values()))

    def test_new_questions_in_same_second_keep_both_original_cards(self):
        self.assertEqual(self.init()[0], 0)
        with mock.patch.object(C, "now", return_value="2026-10-29T12:00:00"):
            self.assertEqual(self.ask(stuck="first")[0], 0)
            self.assertEqual(self.ask(stuck="second")[0], 0)
        self.assertEqual(len(list((self.root / "ask").glob("*.md"))), 2)

    def test_downgrade_write_failure_preserves_state_and_notice_together(self):
        self.assertEqual(self.init()[0], 0)
        C.save_state(str(self.root), dict(C.load_state(str(self.root)), max_level="M2"))
        before = (self.root / "facts.jsonl").read_bytes()
        original = C._atomic_append_line

        def fail_notice(path, line):
            if '"kind": "downgrade"' in line:
                raise OSError("notice failure")
            return original(path, line)

        with mock.patch.object(C, "_atomic_append_line", side_effect=fail_notice):
            self.assertEqual(self.call(C.cmd_downgrade, to="M1", reason="no runtime")[0], 2)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)

    def test_force_does_not_rebase_a_changed_target(self):
        self.assertEqual(self.init()[0], 0)
        self.target.write_bytes(b"changed target")
        before = (self.root / "facts.jsonl").read_bytes()
        self.assertEqual(self.init(force=True)[0], 2)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)

    def test_late_target_binding_rejects_metadata_redirect(self):
        missing = self.base / "not-yet.bin"
        self.assertEqual(self.init(target=str(missing))[0], 0)
        attacker = self.base / "attacker.bin"
        attacker.write_bytes(b"attacker bytes")
        meta_path = self.root / "case.json"
        metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        metadata["target"]["path"] = str(attacker)
        meta_path.write_text(json.dumps(metadata), encoding="utf-8")
        facts_before = (self.root / "facts.jsonl").read_bytes()
        metadata_before = meta_path.read_bytes()
        code, output = self.call(
            C.cmd_claim, id="C-001", text="unsafe late binding", status="hypothesis",
            evidence="", how="", ttl="", by="", confidence="", authority="")
        self.assertEqual(code, 2, output)
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), facts_before)
        self.assertEqual(meta_path.read_bytes(), metadata_before)

    def test_late_target_binding_updates_metadata_and_target_files(self):
        missing = self.base / "appears-later.bin"
        self.assertEqual(self.init(target=str(missing))[0], 0)
        missing.write_bytes(b"late fixture")
        code, output = self.call(
            C.cmd_claim, id="C-001", text="late target is available", status="hypothesis",
            evidence="", how="", ttl="", by="", confidence="", authority="")
        self.assertEqual(code, 0, output)
        metadata = json.loads((self.root / "case.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["target"]["size"], len(b"late fixture"))
        self.assertEqual(metadata["target_files"][0]["path"], str(missing))

    def test_answer_marker_binds_registered_target_and_never_swallows_write_failure(self):
        self.assertEqual(self.init()[0], 0)
        marker = C._write_answer_pass(str(self.root))
        payload = json.loads(Path(marker).read_text(encoding="utf-8"))
        self.assertEqual(payload["target_sha256"],
                         C._fingerprint_target(str(self.target))["sha256"])
        Path(marker).unlink()
        with mock.patch.object(C, "_atomic_write_json", side_effect=OSError("marker read-only")):
            with self.assertRaises(OSError):
                C._write_answer_pass(str(self.root))
        self.assertFalse(Path(marker).exists())

    def test_answer_command_returns_nonzero_if_marker_cannot_be_written(self):
        self.assertEqual(self.init()[0], 0)
        answer = self.base / "answer.json"
        answer.write_text(json.dumps({
            "judgment": "PE32+，无壳，本地常量比较",
            "ceiling": "能改到能用",
            "missing": ["卡密有没有", "要不要复现证据"],
            "effort": "2-4 小时；依据：判定点已定位",
            "asks": [{"id": "Q1", "options": [
                {"key": "A", "consequence": "走在线对比，能到更高一档"},
                {"key": "B", "consequence": "只离线判定，最多只能看懂结构"},
            ]}],
        }), encoding="utf-8")
        with mock.patch.object(C, "_write_answer_pass", side_effect=OSError("marker read-only")):
            code, output = self.call(
                C.cmd_answer, template=False, check=True, file=str(answer), selftest=False,
                adhoc="")
        self.assertEqual(code, 2, output)
        self.assertIn("放行标记没有写成", output)


if __name__ == "__main__":
    unittest.main()
