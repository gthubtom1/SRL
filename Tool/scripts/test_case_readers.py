"""Case projections must consume the same validated ledger and case boundary."""
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


class CaseReaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-case-read-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "cases" / "sample"
        self.root.mkdir(parents=True)
        self.meta = {"id": "sample", "target_files": []}
        (self.root / "case.json").write_text(json.dumps(self.meta), encoding="utf-8")
        self.facts = self.root / "facts.jsonl"

    def call(self, function, **kwargs):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            try:
                result = function(argparse.Namespace(case=str(self.root), **kwargs))
                code = result if type(result) is int else 0
            except SystemExit as exc:
                code = exc.code
        return code, output.getvalue()

    def test_recheck_reads_compact_json_and_labels_unverified_history(self):
        self.facts.write_text(json.dumps({"kind": "repro", "id": "E-001", "cmd": "historical command",
                                         "expect": "ok", "runs": 2, "digests": []},
                                        separators=(",", ":")), encoding="utf-8")
        code, output = self.call(C.cmd_recheck)
        self.assertEqual(code, 0, output)
        report = (self.root / "recheck.md").read_text(encoding="utf-8")
        self.assertIn("E-001", report)
        self.assertIn("未通过当前捕获复验", report)

    def test_recheck_refuses_corruption_and_pending_without_replacing_old_report(self):
        old = self.root / "recheck.md"
        old.write_text("preserve previous report", encoding="utf-8")
        for invalid in ("{broken", '[1,2]\n', '{"kind":"repro","id":"E-001"}\n' * 2):
            with self.subTest(invalid=invalid):
                self.facts.write_text(invalid, encoding="utf-8")
                self.assertEqual(self.call(C.cmd_recheck)[0], 2)
                self.assertEqual(old.read_text(encoding="utf-8"), "preserve previous report")
        self.facts.write_text("", encoding="utf-8")
        (self.root / ".project-transaction.json").write_text("{}", encoding="utf-8")
        self.assertEqual(self.call(C.cmd_recheck)[0], 2)
        self.assertEqual(old.read_text(encoding="utf-8"), "preserve previous report")

    def test_failed_recheck_atomic_replace_keeps_old_report(self):
        self.facts.write_text("", encoding="utf-8")
        report = self.root / "recheck.md"
        report.write_text("prior report", encoding="utf-8")
        original = C._replace_retry

        def fail_report(temporary, path, *args, **kwargs):
            if Path(path) == report:
                raise OSError("replace refused")
            return original(temporary, path, *args, **kwargs)

        with mock.patch.object(C, "_replace_retry", side_effect=fail_report):
            self.assertEqual(self.call(C.cmd_recheck)[0], 2)
        self.assertEqual(report.read_text(encoding="utf-8"), "prior report")

    def test_recheck_distinguishes_real_capture_from_deleted_output(self):
        target = self.root / "target.bin"
        target.write_bytes(b"reader fixture")
        observer = self.root / "observe.py"
        observer.write_text("import pathlib,sys\nprint(pathlib.Path(sys.argv[1]).read_text())\n", encoding="utf-8")
        import hashlib
        metadata = dict(self.meta, target={"path": str(target), "size": target.stat().st_size,
                                         "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
        (self.root / "case.json").write_text(json.dumps(metadata), encoding="utf-8")
        C.save_state(str(self.root), {"target": str(target)})
        args = [sys.executable, "-B", str(observer), str(target)]
        if os.name == "nt":
            command = subprocess.list2cmdline(args)
        else:
            import shlex
            command = shlex.join(args)
        code, output = self.call(C.cmd_repro, id="E-001", cmd=command, expect="reader fixture",
                                 runs=2, timeout=10, also_cmd="", out="", adhoc="")
        self.assertEqual(code, 0, output)
        self.assertEqual(self.call(C.cmd_recheck)[0], 0)
        report = self.root / "recheck.md"
        self.assertIn("当前捕获复验通过", report.read_text(encoding="utf-8"))
        record = next(row for row in C.load_ledger(str(self.root)) if row.get("kind") == "repro")
        (self.root / record["artifacts"][0]["path"]).unlink()
        self.assertEqual(self.call(C.cmd_recheck)[0], 0)
        self.assertIn("未通过当前捕获复验", report.read_text(encoding="utf-8"))

    def test_index_refuses_pending_case_metadata(self):
        (self.root / ".project-transaction.json").write_text("{}", encoding="utf-8")
        entries, problems = C.scan_cases(str(self.root.parent))
        self.assertTrue(problems)
        self.assertEqual(entries, [])

    def test_index_and_verify_all_reject_linked_case_and_keep_external_bytes(self):
        external = self.base / "outside"
        external.mkdir()
        (external / "case.json").write_text(json.dumps(dict(self.meta, id="linked")), encoding="utf-8")
        (external / "facts.jsonl").write_text("", encoding="utf-8")
        before = {p.name: p.read_bytes() for p in external.iterdir()}
        linked = self.root.parent / "linked"
        if os.name == "nt":
            result = subprocess.run(["cmd", "/c", "mklink", "/J", str(linked), str(external)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            linked.symlink_to(external, target_is_directory=True)
        self.addCleanup(lambda: os.rmdir(linked) if os.name == "nt" else linked.unlink())
        entries, problems = C.scan_cases(str(self.root.parent))
        self.assertTrue(any("link" in str(p).lower() or "reparse" in str(p).lower() for p in problems), problems)
        self.assertFalse(any(e["dir"] == "linked" for e in entries))
        with mock.patch.object(C, "cases_root", return_value=str(self.root.parent)):
            code, output = self.call(C.cmd_verify, all=True, json=True)
        self.assertNotEqual(code, 0, output)
        self.assertEqual({p.name: p.read_bytes() for p in external.iterdir()}, before)


    def test_report_recheck_rejects_invalid_or_linked_case_metadata(self):
        report = ["## 5 怎么复查", "- recheck.md"]
        for invalid in ("[]", '{"target_files":"not-a-list"}',
                        '{"target_files":[],"target_files":[{"sha256":"aaaaaaaaaaaaaaaa"}]}'):
            with self.subTest(invalid=invalid):
                (self.root / "case.json").write_text(invalid, encoding="utf-8")
                problem = C._recheck_section_problem(report, str(self.root))
                self.assertIn("case.json", problem)

        external = self.base / "external-case"
        external.mkdir()
        (external / "case.json").write_text(
            json.dumps({"target_files": [{"sha256": "a" * 64}]}), encoding="utf-8")
        before = (external / "case.json").read_bytes()
        linked = self.base / "linked-case"
        if os.name == "nt":
            result = subprocess.run(["cmd", "/c", "mklink", "/J", str(linked), str(external)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            linked.symlink_to(external, target_is_directory=True)
        self.addCleanup(lambda: os.rmdir(linked) if os.name == "nt" else linked.unlink())
        problem = C._recheck_section_problem(report, str(linked))
        self.assertIn("case.json", problem)
        self.assertEqual((external / "case.json").read_bytes(), before)

    def test_template_exemption_uses_real_repository_prompts_root(self):
        fake_root = self.base / "Tool" / "prompts"
        fake_root.mkdir(parents=True)
        fake = fake_root / "fake.md"
        fake.write_text("fake", encoding="utf-8")
        self.assertFalse(C._is_template_path(fake))

        tool = self.base / "repo" / "Tool"
        prompts = tool / "prompts"
        prompts.mkdir(parents=True)
        with mock.patch.object(C, "_TOOL", str(tool)):
            self.assertTrue(C._is_template_path(prompts / "template.md"))
            self.assertFalse(C._is_template_path(self.base / "other" / "template.md"))

if __name__ == "__main__":
    unittest.main()

