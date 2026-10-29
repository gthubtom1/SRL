#!/usr/bin/env python3
"""Evidence, checklist and closure recovery over real project writes."""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import project_state as P
import test_project_report as F


class ProjectWriteRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = F.ReportChain()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.start_run("1.1", "run-a")
        self.seed = self.fixture.project

    def files(self, root):
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*")
                if p.is_file() and p.name != ".project.lock"}

    def arguments(self, operation, root):
        common = ["--project", str(root), "--version", "1.1"]
        if operation == "evidence":
            raw = root / "versions/1.1/capture/probe.log"
            version = json.loads((root / "versions/1.1/version.json").read_text(encoding="utf-8"))
            return [operation, *common, "--run-id", "run-a", "--evidence-id", "ev-1",
                    "--target-sha256", version["sha256"], "--path", "versions/1.1/capture/probe.log",
                    "--sha256", F.sha(raw), "--size", str(raw.stat().st_size),
                    "--source", "versions/1.1/capture/source.txt", "--how", "synthetic probe"]
        if operation == "acceptance-define":
            return [operation, *common, "--item", "probe:synthetic evidence"]
        if operation == "acceptance-record":
            return [operation, *common, "--item-id", "probe", "--result", "pass", "--evidence-ids", "ev-1",
                    "--verifier", "synthetic", "--how", "read synthetic bytes", "--run", "run-a"]
        return ["finish-run", *common, "--run-id", "run-a", "--status", "completed"]

    def invoke(self, operation, root):
        output = io.StringIO()
        with mock.patch.object(sys, "argv", [str(F.STATE), *self.arguments(operation, root)]), \
                contextlib.redirect_stdout(output):
            code = P.main()
        return code, output.getvalue()

    def prepare(self, operation, name):
        root = self.fixture.base / name
        shutil.copytree(self.seed, root)
        if operation in ("acceptance-record", "finish-run"):
            for prerequisite in ("evidence", "acceptance-define"):
                code, output = self.invoke(prerequisite, root)
                self.assertEqual(code, 0, output)
        if operation == "finish-run":
            code, output = self.invoke("acceptance-record", root)
            self.assertEqual(code, 0, output)
        return root

    def test_each_real_write_failure_restores_exact_files_and_retry_succeeds(self):
        stages = {"evidence": ("record", "manifest", "facts", "handoff"),
                  "acceptance-define": ("archive", "live", "log", "facts", "handoff"),
                  "acceptance-record": ("archive", "live", "log", "facts", "handoff"),
                  "finish-run": ("run", "facts", "handoff")}
        for operation, points in stages.items():
            prepared = self.prepare(operation, operation + "-seed")
            for stage in points:
                with self.subTest(operation=operation, stage=stage):
                    root = self.fixture.base / (operation + "-" + stage)
                    shutil.copytree(prepared, root)
                    before = self.files(root)
                    name = {"record": "atomic_json", "manifest": "atomic_json", "run": "atomic_json",
                            "archive": "_archive_acceptance", "live": "write_acceptance",
                            "log": "_append_chain_log", "facts": "write_event", "handoff": "write_handoff"}[stage]
                    real = getattr(P, name)
                    def interrupt(*args, real=real, stage=stage, **kwargs):
                        result = real(*args, **kwargs)
                        if stage in ("record", "manifest", "run"):
                            wanted = {"record": "ev-1.json", "manifest": "manifest.json", "run": "run.json"}[stage]
                            if Path(args[0]).name != wanted:
                                return result
                        raise OSError("synthetic interruption after real project write")
                    with mock.patch.object(P, name, side_effect=interrupt):
                        code, output = self.invoke(operation, root)
                    self.assertEqual(code, 2, output)
                    self.assertEqual(self.files(root), before, operation + "/" + stage)
                    code, output = self.invoke(operation, root)
                    self.assertEqual(code, 0, output)
                    self.assertNotIn(".project-transaction.json", self.files(root))

    def test_exit_after_facts_blocks_resume_then_same_command_recovers_without_duplicate_events(self):
        code = """import os, sys
sys.path.insert(0, sys.argv[1])
import project_state as P
real = P.write_event
def interrupt(*args, **kwargs):
    real(*args, **kwargs)
    os._exit(79)
P.write_event = interrupt
sys.argv = ["project_state.py", *sys.argv[2:]]
raise SystemExit(P.main())
"""
        for operation in ("evidence", "acceptance-define", "acceptance-record", "finish-run"):
            with self.subTest(operation=operation):
                root = self.prepare(operation, operation + "-exit")
                result = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", code,
                                         str(F.STATE.parent), *self.arguments(operation, root)],
                                        env=F.ENV, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 79, result.stderr)
                interrupted = self.files(root)
                self.assertIn(".project-transaction.json", set(interrupted))
                result = F.cli(F.STATE, "resume", "--project", root)
                self.assertEqual(result[0], 2, result)
                self.assertEqual(self.files(root), interrupted)
                code_value, output = self.invoke(operation, root)
                self.assertEqual(code_value, 0, output)
                self.assertNotIn(".project-transaction.json", self.files(root))
                events = [json.loads(line) for line in (root / "facts.jsonl").read_text(encoding="utf-8").splitlines()]
                wanted = {"evidence": "evidence_registered", "acceptance-define": "acceptance_defined",
                          "acceptance-record": "acceptance_recorded", "finish-run": "run_finished"}[operation]
                self.assertEqual(sum(e.get("type") == wanted for e in events), 1)
                result = F.cli(F.STATE, "resume", "--project", root)
                self.assertEqual(result[0], 0, result)


class MissingRunWitnessTests(unittest.TestCase):
    def test_completed_run_record_cannot_disappear_after_switching_versions(self):
        fixture = F.ReportChain()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.complete_run()
        fixture.ok(fixture.p("version", "--version", "1.2", "--parent", "1.1", "--target", fixture.last))
        fixture.start_run("1.2", "run-b")
        (fixture.project / "versions/1.1/runs/run-a/run.json").unlink()
        for command in ("resume", "handoff"):
            with self.subTest(command=command):
                code, payload = fixture.p(command)
                self.assertEqual(code, 2, payload)
                handoff = payload["handoff"]
                self.assertFalse(handoff["acceptance_complete"])
                self.assertTrue(any("run-a" in item["reason"]
                                    for item in handoff["closure_errors"]), handoff)
        before = {p.relative_to(fixture.project).as_posix(): p.read_bytes()
                  for p in fixture.project.rglob("*") if p.is_file() and p.name != ".project.lock"}
        code, payload = fixture.p("finish-run", "--version", "1.2", "--run-id", "run-b", "--status", "blocked")
        self.assertEqual(code, 2, payload)
        after = {p.relative_to(fixture.project).as_posix(): p.read_bytes()
                 for p in fixture.project.rglob("*") if p.is_file() and p.name != ".project.lock"}
        self.assertEqual(after, before)


class LifecycleWriteRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = F.ReportChain()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    def files(self, root):
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*")
                if p.is_file() and p.name != ".project.lock"}

    def arguments(self, operation, root):
        common = ["--project", str(root), "--version", "1.1"]
        if operation == "run":
            return ["run", *common, "--run-id", "run-new"]
        return ["event", *common, "--type", "observation", "--message", "synthetic observation"]

    def invoke(self, operation, root):
        output = io.StringIO()
        with mock.patch.object(sys, "argv", [str(F.STATE), *self.arguments(operation, root)]), \
                contextlib.redirect_stdout(output):
            code = P.main()
        return code, output.getvalue()

    def test_each_write_failure_rolls_back_files_and_empty_run_directories(self):
        for operation, points in (("run", ("run", "facts", "handoff")), ("event", ("facts", "handoff"))):
            for stage in points:
                with self.subTest(operation=operation, stage=stage):
                    root = self.fixture.base / (operation + "-" + stage)
                    shutil.copytree(self.fixture.project, root)
                    before = self.files(root)
                    name = {"run": "atomic_json", "facts": "write_event", "handoff": "write_handoff"}[stage]
                    real = getattr(P, name)
                    def interrupt(*args, real=real, stage=stage, **kwargs):
                        value = real(*args, **kwargs)
                        if stage == "run" and Path(args[0]).name != "run.json":
                            return value
                        raise OSError("synthetic interruption after lifecycle write")
                    with mock.patch.object(P, name, side_effect=interrupt):
                        code, output = self.invoke(operation, root)
                    self.assertEqual(code, 2, output)
                    self.assertEqual(self.files(root), before)
                    self.assertFalse((root / "versions/1.1/runs/run-new").exists())
                    code, output = self.invoke(operation, root)
                    self.assertEqual(code, 0, output)
                    if operation == "run":
                        for name in ("capture", "artifacts"):
                            self.assertTrue((root / "versions/1.1/runs/run-new" / name).is_dir())

    def test_process_exit_blocks_readers_and_retry_commits_one_event(self):
        script = """import os, sys
sys.path.insert(0, sys.argv[1])
import project_state as P
real = P.write_event
def interrupt(*args, **kwargs):
    real(*args, **kwargs)
    os._exit(77)
P.write_event = interrupt
sys.argv = ["project_state.py", *sys.argv[2:]]
raise SystemExit(P.main())
"""
        for operation in ("run", "event"):
            with self.subTest(operation=operation):
                root = self.fixture.base / (operation + "-exit")
                shutil.copytree(self.fixture.project, root)
                before_count = len((root / "facts.jsonl").read_bytes().splitlines())
                child = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", script,
                    str(F.STATE.parent), *self.arguments(operation, root)], capture_output=True, timeout=30)
                self.assertEqual(child.returncode, 77, child.stderr)
                interrupted = self.files(root)
                self.assertIn(".project-transaction.json", interrupted)
                code, payload, _ = F.cli(F.STATE, "resume", "--project", root)
                self.assertEqual(code, 2, payload)
                self.assertEqual(self.files(root), interrupted)
                code, output = self.invoke(operation, root)
                self.assertEqual(code, 0, output)
                self.assertNotIn(".project-transaction.json", self.files(root))
                self.assertEqual(len((root / "facts.jsonl").read_bytes().splitlines()), before_count + 1)

    def test_foreign_version_is_rejected_before_creating_a_run(self):
        root = self.fixture.project
        path = root / "versions/1.1/version.json"
        data = F.read(path)
        data["project_id"] = "another-project"
        F.write(path, data)
        before = self.files(root)
        code, output = self.invoke("run", root)
        self.assertEqual(code, 2, output)
        self.assertEqual(self.files(root), before)

    def test_foreign_run_and_version_are_not_accepted_by_handoff(self):
        self.fixture.start_run("1.1", "run-a")
        root = self.fixture.project
        for relative, field, wrong in (("versions/1.1/runs/run-a/run.json", "project_id", "foreign"),
                ("versions/1.1/runs/run-a/run.json", "version_id", "1.0"),
                ("versions/1.1/version.json", "project_id", "foreign")):
            with self.subTest(relative=relative, field=field):
                path = root / relative
                original = path.read_bytes()
                data = F.read(path)
                data[field] = wrong
                F.write(path, data)
                try:
                    code, payload = self.fixture.p("resume")
                    self.assertEqual(code, 2, payload)
                    self.assertTrue(payload["handoff"]["state_errors"], payload)
                finally:
                    path.write_bytes(original)


class InitializationRecoveryTests(unittest.TestCase):
    def test_real_exit_during_publication_is_recoverable_with_user_material_preserved(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix="seep-init-recovery-") as temporary:
            base = Path(temporary)
            source = base / "source"
            source.mkdir()
            # Exceed the old metadata-only transaction's 128-file bound.
            for index in range(135):
                (source / ("sample-%03d.bin" % index)).write_bytes(("fixture-%d" % index).encode())
            script = """import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import project_state as P
root = Path(sys.argv[2])
stage = sys.argv[4]
real = P.os.replace
def interrupt(source, destination):
    result = real(source, destination)
    destination = Path(destination)
    if destination.is_relative_to(root) and destination.name == stage:
        os._exit(80)
    return result
P.os.replace = interrupt
sys.argv = ["project_state.py", "init", "--project", str(root), "--project-id", "synthetic",
            "--target", sys.argv[3]]
raise SystemExit(P.main())
"""
            for stage in ("facts.jsonl", "project.json"):
                with self.subTest(stage=stage):
                    root = base / stage.replace(".", "-")
                    root.mkdir()
                    note = root / "user-note.txt"
                    note.write_bytes(b"existing user material")
                    child = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", script,
                        str(F.STATE.parent), str(root), str(source), stage], capture_output=True, timeout=30)
                    self.assertEqual(child.returncode, 80, child.stderr)
                    self.assertTrue((root / ".project-transaction.json").is_file())
                    interrupted = {p.relative_to(root).as_posix(): p.read_bytes()
                                   for p in root.rglob("*") if p.is_file() and p.name != ".project.lock"}
                    code, payload, _ = F.cli(F.STATE, "resume", "--project", root)
                    self.assertEqual(code, 2, payload)
                    self.assertEqual({p.relative_to(root).as_posix(): p.read_bytes()
                        for p in root.rglob("*") if p.is_file() and p.name != ".project.lock"}, interrupted)
                    code, payload, _ = F.cli(F.STATE, "init", "--project", root,
                        "--project-id", "synthetic", "--target", source)
                    self.assertEqual(code, 0, payload)
                    self.assertEqual(note.read_bytes(), b"existing user material")
                    self.assertFalse((root / ".project-transaction.json").exists())
                    self.assertEqual(len(list((root / "assets/asset-main/snapshot/tree").glob("sample-*.bin"))), 135)
                    code, payload, _ = F.cli(F.STATE, "resume", "--project", root)
                    self.assertEqual(code, 0, payload)


class RegistrationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = F.ReportChain()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.directory = self.fixture.base / "directory-input"
        (self.directory / "empty").mkdir(parents=True)
        (self.directory / "nested").mkdir()
        (self.directory / "nested/sample.bin").write_bytes(b"synthetic directory target")

    def files(self, root):
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*")
                if p.is_file() and p.name != ".project.lock"}

    def arguments(self, mode, root):
        target = (str(self.directory) if mode.endswith("directory") else
                  "https://example.invalid/fixture" if mode.endswith("url") else str(self.fixture.last))
        if mode.startswith("asset"):
            version = "1.2" if mode == "asset-new-version" else "1.1"
            role = "primary" if mode == "asset-new-version" else "auxiliary"
            return ["asset", "--project", str(root), "--version", version,
                    "--asset-id", "asset-extra", "--role", role, "--target", target]
        return ["version", "--project", str(root), "--version", "1.2", "--parent", "1.1", "--target", target]

    def prepare(self, mode, name):
        root = self.fixture.base / name
        shutil.copytree(self.fixture.project, root)
        if mode == "bind-file":
            code, payload, _ = F.cli(F.STATE, "version", "--project", root,
                                    "--version", "1.2", "--parent", "1.1")
            self.assertEqual(code, 0, payload)
        return root

    def invoke(self, mode, root):
        output = io.StringIO()
        with mock.patch.object(sys, "argv", [str(F.STATE), *self.arguments(mode, root)]), \
                contextlib.redirect_stdout(output):
            code = P.main()
        return code, output.getvalue()

    def test_metadata_failures_restore_files_directories_and_retry(self):
        modes = ("version-file", "version-directory", "version-url", "bind-file",
                 "asset-file", "asset-directory", "asset-url", "asset-new-version")
        for mode in modes:
            for stage in ("metadata", "facts", "handoff"):
                with self.subTest(mode=mode, stage=stage):
                    root = self.prepare(mode, mode + "-" + stage)
                    before = self.files(root)
                    directories = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_dir()}
                    name = {"metadata": "atomic_json", "facts": "write_event", "handoff": "write_handoff"}[stage]
                    real = getattr(P, name)
                    def interrupt(*args, real=real, stage=stage, **kwargs):
                        result = real(*args, **kwargs)
                        if stage == "metadata" and Path(args[0]).name != "version.json":
                            return result
                        raise OSError("synthetic interruption after registration write")
                    with mock.patch.object(P, name, side_effect=interrupt):
                        code, output = self.invoke(mode, root)
                    self.assertEqual(code, 2, output)
                    self.assertEqual(self.files(root), before)
                    self.assertEqual({p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_dir()}, directories)
                    code, output = self.invoke(mode, root)
                    self.assertEqual(code, 0, output)
                    self.assertFalse((root / ".project-transaction.json").exists())
                    code, payload, _ = F.cli(F.STATE, "resume", "--project", root)
                    self.assertEqual(code, 0, payload)

    def test_process_exit_after_registration_blocks_readers_and_retry_commits_once(self):
        script = """import os, sys
sys.path.insert(0, sys.argv[1])
import project_state as P
real = P.write_event
def interrupt(*args, **kwargs):
    real(*args, **kwargs)
    os._exit(81)
P.write_event = interrupt
sys.argv = ["project_state.py", *sys.argv[2:]]
raise SystemExit(P.main())
"""
        for mode in ("version-file", "version-directory", "bind-file", "asset-directory", "asset-new-version"):
            with self.subTest(mode=mode):
                root = self.prepare(mode, mode + "-exit")
                count = len((root / "facts.jsonl").read_bytes().splitlines())
                child = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", script,
                    str(F.STATE.parent), *self.arguments(mode, root)], capture_output=True, timeout=30)
                self.assertEqual(child.returncode, 81, child.stderr)
                interrupted = self.files(root)
                self.assertIn(".project-transaction.json", interrupted)
                code, payload, _ = F.cli(F.STATE, "resume", "--project", root)
                self.assertEqual(code, 2, payload)
                self.assertEqual(self.files(root), interrupted)
                code, output = self.invoke(mode, root)
                self.assertEqual(code, 0, output)
                self.assertEqual(len((root / "facts.jsonl").read_bytes().splitlines()), count + 1)
                self.assertFalse((root / ".project-transaction.json").exists())

    def test_publication_failure_or_exit_restores_new_material_before_retry(self):
        script = """import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import project_state as P
root = Path(sys.argv[2])
real = P.os.replace
def interrupt(source, destination):
    value = real(source, destination)
    path = Path(destination)
    if path.is_relative_to(root) and path.name in ("last.bin", "sample.bin"):
        os._exit(82)
    return value
P.os.replace = interrupt
sys.argv = ["project_state.py", *sys.argv[3:]]
raise SystemExit(P.main())
"""
        for mode in ("version-file", "version-directory", "asset-file", "asset-directory"):
            for failure in ("exception", "exit"):
                with self.subTest(mode=mode, failure=failure):
                    root = self.prepare(mode, mode + "-publish-" + failure)
                    before = self.files(root)
                    directories = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_dir()}
                    if failure == "exception":
                        real = P.os.replace
                        def interrupt(source, destination):
                            result = real(source, destination)
                            path = Path(destination)
                            if path.is_relative_to(root) and path.name in ("last.bin", "sample.bin"):
                                raise OSError("synthetic interruption after publishing material")
                            return result
                        with mock.patch.object(P.os, "replace", side_effect=interrupt):
                            code, output = self.invoke(mode, root)
                        self.assertEqual(code, 2, output)
                        self.assertEqual(self.files(root), before)
                        self.assertEqual({p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_dir()}, directories)
                    else:
                        child = subprocess.run([sys.executable, "-B", "-X", "utf8", "-c", script,
                            str(F.STATE.parent), str(root), *self.arguments(mode, root)],
                            capture_output=True, timeout=30)
                        self.assertEqual(child.returncode, 82, child.stderr + child.stdout)
                        interrupted = self.files(root)
                        code, payload, _ = F.cli(F.STATE, "resume", "--project", root)
                        self.assertEqual(code, 2, payload)
                        self.assertEqual(self.files(root), interrupted)
                    remnants = {p: self.files(p) for p in root.parent.glob(".seep-registration-*")}
                    code, output = self.invoke(mode, root)
                    self.assertEqual(code, 0, output)
                    for path, content in remnants.items():
                        self.assertTrue(path.is_dir())
                        self.assertEqual(self.files(path), content)
                    self.assertFalse((root / ".project-transaction.json").exists())
                    self.assertEqual(len(list(root.glob(".seep-registration-*"))), 0)

    def test_changed_source_cannot_publish_files_outside_the_prepared_write_set(self):
        root = self.prepare("version-directory", "source-change")
        before = self.files(root)
        real = P.metadata_transaction
        @contextlib.contextmanager
        def change_source(*args, **kwargs):
            with real(*args, **kwargs):
                (self.directory / "new-unplanned-file.bin").write_bytes(b"changed source")
                yield
        with mock.patch.object(P, "metadata_transaction", side_effect=change_source):
            code, output = self.invoke("version-directory", root)
        self.assertEqual(code, 2, output)
        self.assertEqual(self.files(root), before)
        self.assertFalse((root / "versions/1.2").exists())

    def test_version_snapshot_can_be_registered_as_an_auxiliary_asset(self):
        root = self.prepare("version-directory", "in-project-input")
        code, output = self.invoke("version-directory", root)
        self.assertEqual(code, 0, output)
        source = root / "versions/1.2/target/tree"
        original = self.files(source)
        code, payload, _ = F.cli(F.STATE, "asset", "--project", root, "--version", "1.2",
            "--asset-id", "asset-extra", "--role", "auxiliary", "--target", source)
        self.assertEqual(code, 0, payload)
        self.assertEqual(self.files(source), original)
        self.assertEqual(self.files(root / "assets/asset-extra/snapshot/tree"), original)
        code, payload, _ = F.cli(F.STATE, "resume", "--project", root)
        self.assertEqual(code, 0, payload)

    def test_foreign_existing_version_is_refused_without_registering_an_asset(self):
        for mode in ("version-file", "asset-file"):
            with self.subTest(mode=mode):
                root = self.prepare(mode, mode + "-foreign")
                version = "1.2" if mode.startswith("version") else "1.1"
                if version == "1.2":
                    code, payload, _ = F.cli(F.STATE, "version", "--project", root,
                                            "--version", version, "--parent", "1.1")
                    self.assertEqual(code, 0, payload)
                path = root / "versions" / version / "version.json"
                data = F.read(path)
                data["project_id"] = "foreign-project"
                F.write(path, data)
                before = self.files(root)
                code, output = self.invoke(mode, root)
                self.assertEqual(code, 2, output)
                self.assertEqual(self.files(root), before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
