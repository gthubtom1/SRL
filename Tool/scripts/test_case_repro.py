"""Real benign subprocesses for case replay evidence; never uses host init markers."""
from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
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
sys.path.insert(0, str(Path(__file__).resolve().parent))
import case_state as C


class CaseReproTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="seep-repro-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / "input.bin"
        self.target.write_bytes(b"benign audit fixture")
        self.script = self.root / "observe.py"
        self.script.write_text(
            "import pathlib,sys,time\n"
            "p=pathlib.Path(sys.argv[1]); data=p.read_bytes()\n"
            "if sys.argv[3]=='mutate': p.write_bytes(b'x'*len(data))\n"
            "if sys.argv[3]=='vary':\n"
            " q=p.with_suffix('.counter'); n=int(q.read_text())+1 if q.exists() else 1\n"
            " q.write_text(str(n)); print(n)\n"
            "if sys.argv[3]=='wait': time.sleep(3)\n"
            "print('PASS fixture read')\n"
            "sys.exit(int(sys.argv[2]))\n", encoding="utf-8")
        self.meta = {"id": self.root.name, "target": {
            "path": str(self.target), "sha256": hashlib.sha256(self.target.read_bytes()).hexdigest(),
            "size": self.target.stat().st_size}}
        (self.root / "case.json").write_text(json.dumps(self.meta), encoding="utf-8")
        C.save_state(str(self.root), {"schema": "seep-case/1", "target": str(self.target),
                                   "depth": {}, "stage": "0a", "verdict": "可赢", "max_level": "M4"})

    def command(self, code=0, variant="first"):
        args = [sys.executable, "-B", "-X", "utf8", str(self.script), str(self.target), str(code), variant]
        if os.name == "nt":
            return subprocess.list2cmdline(args)
        import shlex
        return shlex.join(args)

    def args(self, **changes):
        result = argparse.Namespace(case=str(self.root), id="E-001", cmd=self.command(),
                                    expect="PASS fixture read", runs=2, timeout=10,
                                    also_cmd="", out=str(self.root / "capture"), adhoc="")
        vars(result).update(changes)
        return result

    def invoke(self, **changes):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = C.cmd_repro(self.args(**changes))
        rows = [r for r in C.load_ledger(str(self.root)) if r.get("kind") == "repro"]
        return rc, rows, output.getvalue()

    def project_cli(self, *args):
        script = Path(C.__file__).with_name("project_state.py")
        result = subprocess.run(
            [sys.executable, "-B", "-X", "utf8", str(script), *map(str, args)],
            cwd=script.parents[1].parent,
            env=dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1"),
            capture_output=True, text=True, encoding="utf-8", timeout=30)
        payload = json.loads(result.stdout)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertTrue(payload["ok"], payload)
        return payload

    def completed_project(self, name="acceptance-project", target=None,
                          complete=True):
        project = self.root / name
        raw_target = str(target or self.target)
        target = raw_target if raw_target.lower().startswith(("http://", "https://")) \
            else Path(raw_target)
        self.project_cli("init", "--project", project, "--project-id", name,
                         "--target", target)
        self.project_cli("run", "--project", project, "--version", "1.0",
                         "--run-id", "acceptance-run", "--executor", "test")
        self.project_cli("acceptance-define", "--project", project, "--version", "1.0",
                         "--item", "feature:synthetic feature works")
        witness = project / "versions/1.0/artifacts/witness.log"
        witness.parent.mkdir(parents=True, exist_ok=True)
        witness.write_bytes(b"synthetic recorded witness\n")
        target_sha = json.loads(
            (project / "versions/1.0/version.json").read_text(encoding="utf-8")
        )["sha256"]
        self.project_cli(
            "evidence", "--project", project, "--version", "1.0",
            "--run-id", "acceptance-run", "--evidence-id", "ev-e4",
            "--target-sha256", target_sha,
            "--path", witness.relative_to(project).as_posix(),
            "--sha256", hashlib.sha256(witness.read_bytes()).hexdigest(),
            "--size", witness.stat().st_size,
            "--source", witness.relative_to(project).as_posix(),
            "--how", "synthetic acceptance check", "--recorded-by", "test")
        self.project_cli(
            "acceptance-record", "--project", project, "--version", "1.0",
            "--item-id", "feature", "--result", "pass",
            "--evidence-ids", "ev-e4", "--verifier", "test",
            "--how", "checked synthetic witness", "--run", "acceptance-run")
        if complete:
            self.project_cli(
                "finish-run", "--project", project, "--version", "1.0",
                "--run-id", "acceptance-run", "--status", "completed",
                "--note", "synthetic completion")
        self.project_cli("handoff", "--project", project)
        return project

    def deliver(self, level, project=None, version=None, evidence="E-001"):
        args = argparse.Namespace(
            case=str(self.root), level=level, evidence=evidence, note="",
            acceptance_project=str(project or ""),
            acceptance_version=str(version or ""))
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            try:
                rc = C.cmd_deliver(args)
            except SystemExit as exc:
                rc = exc.code
        return rc or 0, output.getvalue(), errors.getvalue()

    def test_nonzero_primary_cannot_be_repeatable_evidence(self):
        rc, rows, _ = self.invoke(cmd=self.command(7))
        self.assertEqual(rc, 1)
        self.assertEqual(rows[-1]["grade"], "E1")
        self.assertEqual(rows[-1]["returncodes"], [7, 7])
        self.assertFalse(C._is_complete_repro(rows[-1]))

    def test_nonzero_secondary_never_becomes_e3(self):
        rc, rows, _ = self.invoke(also_cmd=self.command(9, "second"))
        self.assertEqual(rc, 0)
        self.assertEqual(rows[-1]["grade"], "E2")
        self.assertEqual(rows[-1]["also_returncodes"], [9, 9])
        self.assertFalse(C._is_complete_e3(rows[-1]))

    def test_single_run_and_inconsistent_output_remain_e1(self):
        for changes in ({"runs": 1}, {"cmd": self.command(0, "vary")}):
            with self.subTest(changes=changes):
                rc, rows, _ = self.invoke(id="E-" + str(len(C.load_ledger(str(self.root)))), **changes)
                self.assertEqual(rc, 1)
                self.assertEqual(rows[-1]["grade"], "E1")
                self.assertFalse(C._is_complete_repro(rows[-1]))

    def test_two_routes_persist_outputs_and_pass_delivery(self):
        rc, rows, _ = self.invoke(also_cmd=self.command(0, "second"))
        row = rows[-1]
        self.assertEqual(rc, 0)
        self.assertTrue(C._is_complete_repro(row))
        self.assertTrue(C._is_complete_e3(row))
        self.assertEqual(len(row["also_digests"]), 2)
        self.assertEqual({a["route"] for a in row["artifacts"]}, {"primary", "secondary"})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            C.cmd_deliver(argparse.Namespace(case=str(self.root), level="M3", evidence="E-001", note=""))
        self.assertEqual(C.load_state(str(self.root))["deliveries"][-1]["level"], "M3")

    def test_m4_binds_completed_project_e4_and_e3_to_same_target(self):
        rc, rows, _ = self.invoke(also_cmd=self.command(0, "second"))
        self.assertEqual(rc, 0)
        self.assertEqual(rows[-1]["grade"], "E3")
        project = self.completed_project()

        rc, _, _ = self.deliver("M4")
        self.assertEqual(rc, 2)
        self.assertFalse(C.load_state(str(self.root)).get("deliveries"))
        rc, _, _ = self.deliver("M4", project=project, version="9.9")
        self.assertEqual(rc, 2)
        self.assertFalse(C.load_state(str(self.root)).get("deliveries"))

        incomplete = self.completed_project("incomplete-project", complete=False)
        rc, _, _ = self.deliver("M4", project=incomplete, version="1.0")
        self.assertEqual(rc, 2)
        self.assertFalse(C.load_state(str(self.root)).get("deliveries"))

        other = self.root / "other.bin"
        other.write_bytes(b"different acceptance target")
        mismatched = self.completed_project("mismatched-project", target=other)
        rc, _, _ = self.deliver("M4", project=mismatched, version="1.0")
        self.assertEqual(rc, 2)
        self.assertFalse(C.load_state(str(self.root)).get("deliveries"))

        rc, _, _ = self.deliver("M4", project=project, version="1.0")
        self.assertEqual(rc, 0)
        delivery = C.load_state(str(self.root))["deliveries"][-1]
        binding = delivery["end_to_end_acceptance"]
        self.assertEqual(binding["schema"], "seep-case-e4-project/1")
        self.assertEqual(binding["identity_match"], "file-sha256+size")
        self.assertEqual(binding["last_run_status"], "completed")
        self.assertEqual(binding["last_run_id"], "acceptance-run")
        self.assertEqual(binding["case_target_sha256"], rows[-1]["target"]["sha256"])
        self.assertEqual(binding["target_sha256"], rows[-1]["target"]["sha256"])
        self.assertEqual(len(binding["handoff_sha256"]), 64)
        self.assertEqual(len(binding["facts_sha256"]), 64)

    def test_m4_url_binding_uses_normalized_descriptor_identity(self):
        url = "https://example.invalid/review-fixture"
        self.meta["target"] = {"path": url, "sha256": None, "size": None}
        (self.root / "case.json").write_text(json.dumps(self.meta), encoding="utf-8")
        script = self.root / "url.py"
        script.write_text("import sys; print('PASS',sys.argv[1])", encoding="utf-8")
        if os.name == "nt":
            command = subprocess.list2cmdline([sys.executable, "-B", str(script), url])
            secondary = subprocess.list2cmdline(
                [sys.executable, "-B", "-X", "utf8", str(script), url])
        else:
            import shlex
            command = shlex.join([sys.executable, "-B", str(script), url])
            secondary = shlex.join(
                [sys.executable, "-B", "-X", "utf8", str(script), url])
        rc, rows, _ = self.invoke(cmd=command, also_cmd=secondary, expect="PASS")
        self.assertEqual(rc, 0)
        self.assertEqual(rows[-1]["grade"], "E3")
        project = self.completed_project(target=url)
        rc, _, _ = self.deliver("M4", project=project, version="1.0")
        self.assertEqual(rc, 0)
        binding = C.load_state(str(self.root))["deliveries"][-1]["end_to_end_acceptance"]
        self.assertEqual(binding["identity_match"], "normalized-url-descriptor")
        self.assertEqual(binding["target_identity_scope"], "descriptor-only")
        self.assertEqual(binding["case_target_identity_scope"], "url-reference-only")

    def test_tampered_structure_is_not_complete(self):
        _, rows, _ = self.invoke(also_cmd=self.command(0, "second"))
        row = rows[-1]
        changes = [{"consistent": False}, {"digests": ["a" * 64, "b" * 64]},
                   {"runs": "2"}, {"runs": True}, {"returncodes": [False, 0]},
                   {"also_returncodes": [0, 4]}, {"also_digests": []},
                   {"also_cmd": "  " + "  ".join(row["cmd"].split())},
                   {"target": {**row["target"], "sha256": "cd" * 32}}]
        for change in changes:
            with self.subTest(change=change):
                bad = copy.deepcopy(row)
                bad.update(change)
                self.assertFalse(C._is_complete_e3(bad, row["target"]))

    def test_target_drift_before_and_during_execution_never_commits(self):
        before = (self.root / "facts.jsonl").read_bytes()
        original = self.target.read_bytes()
        self.target.write_bytes(b"x" * len(original))
        rc, rows, _ = self.invoke()
        self.assertEqual(rc, 2)
        self.assertEqual(rows, [])
        self.target.write_bytes(original)
        rc, rows, _ = self.invoke(cmd=self.command(0, "mutate"))
        self.assertEqual(rc, 2)
        self.assertEqual(rows, [])
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)
        self.assertFalse((self.root / "capture").exists())

    def test_bad_ledger_does_not_run_command_or_get_ignored_by_delivery(self):
        ledger = self.root / "facts.jsonl"
        ledger.write_bytes(ledger.read_bytes() + b"\n{broken\n")
        before = ledger.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                rc = C.cmd_repro(self.args(cmd=self.command(0, "mutate")))
            except SystemExit as exc:
                rc = exc.code
        self.assertEqual(rc, 2)
        self.assertEqual(ledger.read_bytes(), before)
        self.assertEqual(self.target.read_bytes(), b"benign audit fixture")
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            C._repro_records(str(self.root))

    def test_e3_cannot_satisfy_e4_and_changed_artifacts_reject_delivery(self):
        _, rows, _ = self.invoke(also_cmd=self.command(0, "second"))
        row = rows[-1]
        before = (self.root / "facts.jsonl").read_bytes()
        for level in ("M4",):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                C.cmd_deliver(argparse.Namespace(case=str(self.root), level=level, evidence="E-001", note=""))
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)
        log = Path(row["artifacts"][0]["path"])
        if not log.is_absolute():
            log = self.root / log
        log.write_bytes(b"changed output")
        for level in ("M2", "M3"):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                C.cmd_deliver(argparse.Namespace(case=str(self.root), level=level, evidence="E-001", note=""))
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)

    def test_secondary_inconsistent_and_same_command_do_not_upgrade(self):
        for alternate in (self.command(0, "vary"), self.command()):
            rc, rows, _ = self.invoke(id="E-" + str(len(C.load_ledger(str(self.root)))), also_cmd=alternate)
            self.assertEqual(rc, 0)
            self.assertEqual(rows[-1]["grade"], "E2")
            self.assertFalse(C._is_complete_e3(rows[-1]))

    def test_default_logs_and_duplicate_id_preserve_prior_evidence(self):
        rc, rows, _ = self.invoke(out="")
        self.assertEqual(rc, 0)
        self.assertEqual(len(rows[-1]["artifacts"]), 2)
        before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        rc, _, _ = self.invoke(out="", cmd=self.command(7))
        self.assertEqual(rc, 2)
        for path, content in before.items():
            self.assertEqual(path.read_bytes(), content)

    def test_log_and_ledger_write_failures_restore_all_files(self):
        before = (self.root / "facts.jsonl").read_bytes()
        original = C._atomic_write_text
        def fail_after(path, content):
            original(path, content)
            raise OSError("injected after actual log replace")
        with mock.patch.object(C, "_atomic_write_text", side_effect=fail_after):
            rc, rows, _ = self.invoke()
        self.assertEqual(rc, 2)
        self.assertEqual(rows, [])
        self.assertFalse((self.root / "capture").exists())
        original_append = C._atomic_append_line
        def fail_append(path, line):
            original_append(path, line)
            raise OSError("injected after actual ledger replace")
        with mock.patch.object(C, "_atomic_append_line", side_effect=fail_append):
            rc, rows, _ = self.invoke()
        self.assertEqual(rc, 2)
        self.assertEqual(rows, [])
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)
        self.assertFalse((self.root / "capture").exists())

    def test_out_junction_rejected_without_writing_target(self):
        ordinary = self.root / "ordinary"
        ordinary.mkdir()
        link = self.root / "capture"
        if os.name == "nt":
            p = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(ordinary)], capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
        else:
            link.symlink_to(ordinary, target_is_directory=True)
        self.addCleanup(lambda: link.rmdir() if os.name == "nt" else link.unlink())
        rc, rows, _ = self.invoke()
        self.assertEqual(rc, 2)
        self.assertEqual(rows, [])
        self.assertEqual(list(ordinary.iterdir()), [])

    def test_timeout_and_wrong_expectation_do_not_become_strong_evidence(self):
        before = (self.root / "facts.jsonl").read_bytes()
        rc, rows, _ = self.invoke(cmd=self.command(0, "wait"), timeout=1)
        self.assertEqual(rc, 2)
        self.assertEqual(rows, [])
        self.assertEqual((self.root / "facts.jsonl").read_bytes(), before)
        rc, rows, _ = self.invoke(expect="absent expectation")
        self.assertEqual(rc, 1)
        self.assertFalse(C._is_complete_repro(rows[-1]))

    def cli(self, identifier="E-cli"):
        return [sys.executable, "-B", "-X", "utf8", str(Path(C.__file__)), "repro",
                "--case", str(self.root), "--id", identifier, "--cmd", self.command(),
                "--expect", "PASS fixture read", "--runs", "2"]

    def test_real_process_exit_after_commit_write_is_recovered_by_cli_retry(self):
        child = self.root / "crash.py"
        child.write_text(
            "import argparse,os,sys\n"
            f"sys.path.insert(0,{str(Path(C.__file__).parent)!r})\n"
            "import case_state as C\n"
            "original=C._atomic_append_line\n"
            "def crash(path,line):\n original(path,line); os._exit(81)\n"
            "C._atomic_append_line=crash\n"
            f"args=argparse.Namespace(**{vars(self.args(out=''))!r})\n"
            "C.cmd_repro(args)\n", encoding="utf-8")
        before = (self.root / "facts.jsonl").read_bytes()
        process = subprocess.run([sys.executable, "-B", "-X", "utf8", str(child)], capture_output=True)
        self.assertEqual(process.returncode, 81, process.stderr)
        self.assertTrue((self.root / ".project-transaction.json").exists())
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit):
            C._repro_records(str(self.root))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(C.cmd_deliver(argparse.Namespace(
                case=str(self.root), level="M2", evidence="E-001", note="")), 2)
        process = subprocess.run(self.cli("E-001"), capture_output=True)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertFalse((self.root / ".project-transaction.json").exists())
        self.assertTrue((self.root / "facts.jsonl").read_bytes().startswith(before))
        rows = C._repro_records(str(self.root))
        self.assertEqual(len(rows), 1)
        self.assertTrue(C._is_complete_repro(rows[0], C._case_target_info(str(self.root)), str(self.root)))
        self.assertEqual(len(list((self.root / "capture").rglob("*.json"))), 2)

    def test_two_real_cli_writers_preserve_both_record_sets(self):
        first = subprocess.Popen(self.cli("E-one"), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        second = subprocess.Popen(self.cli("E-two"), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for process in (first, second):
            stdout, stderr = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, stdout + stderr)
        rows = C._repro_records(str(self.root))
        self.assertEqual({r["id"] for r in rows}, {"E-one", "E-two"})
        for row in rows:
            self.assertTrue(C._is_complete_repro(row, C._case_target_info(str(self.root)), str(self.root)))

    def test_url_reference_is_explicit_and_does_not_claim_remote_identity(self):
        url = "https://example.invalid/review-fixture"
        self.meta["target"] = {"path": url, "sha256": None, "size": None}
        (self.root / "case.json").write_text(json.dumps(self.meta), encoding="utf-8")
        # A local script only prints the URL; it deliberately never makes a request.
        script = self.root / "url.py"
        script.write_text("import sys; print('PASS',sys.argv[1])", encoding="utf-8")
        cmd = subprocess.list2cmdline([sys.executable, str(script), url]) if os.name == "nt" else None
        if cmd is None:
            import shlex
            cmd = shlex.join([sys.executable, str(script), url])
        rc, rows, _ = self.invoke(cmd=cmd, expect="PASS")
        self.assertEqual(rc, 0)
        self.assertEqual(rows[-1]["target"]["identity_scope"], "url-reference-only")
        self.assertEqual(rows[-1]["target"]["sha256"], hashlib.sha256(url.encode()).hexdigest())
        self.assertTrue(C._is_complete_repro(rows[-1], C._case_target_info(str(self.root)), str(self.root)))


if __name__ == "__main__":
    unittest.main()
