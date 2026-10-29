#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Delivery-only acceptance for the real version-migrate CLI.

All fixtures are synthetic bytes in a task-local temporary directory.  The
subprocesses run this repository's own CLI only; no customer target is run,
there is no network/install step, and no old staging fixture is read.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
REAL_SCRIPT = ROOT / "Tool" / "skill" / "softseep" / "scripts" / "version-migrate.py"
REAL_RUNTIME_ROOT = ROOT / "Tool" / "scripts" / "lib" / "runtime_root.py"
REAL_LOCK = ROOT / "Tool" / "scripts" / "lib" / "project_lock.py"
REAL_PACK = ROOT / "Tool" / "skill" / "softseep" / "pack.json"
REAL_VERSION = ROOT / "VERSION"
TMP_ROOT = ROOT / "work" / "final-delivery" / "tmp"


def load_runtime_root():
    spec = importlib.util.spec_from_file_location("delivery_runtime_root", REAL_RUNTIME_ROOT)
    if spec is None or spec.loader is None:
        raise AssertionError("runtime_root helper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def child_env(**updates):
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    for key in ("SEEP_RUNTIME_ROOT", "PI_CODING_AGENT_DIR", "PI_AGENT_DIR"):
        env.pop(key, None)
    env.update({key: str(value) for key, value in updates.items()})
    return env


def run_cli(script: Path, *args: str, env=None):
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=str(ROOT),
        env=env or child_env(),
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=55,
    )


def output_json(proc):
    text = proc.stdout.strip()
    if not text:
        raise AssertionError("CLI emitted no JSON; stderr=%r" % proc.stderr[:240])
    try:
        return json.loads(text)
    except ValueError as exc:
        raise AssertionError("CLI output is not JSON: %r; stderr=%r" %
                             (text[:500], proc.stderr[:240])) from exc


def copy_runtime(destination: Path) -> Path:
    """Build a public runtime only from current repository source files."""
    (destination / "Tool" / "scripts" / "lib").mkdir(parents=True)
    (destination / "Tool" / "skill" / "softseep" / "scripts").mkdir(parents=True)
    (destination / "Tool" / "cases").mkdir(parents=True)
    shutil.copy2(REAL_RUNTIME_ROOT, destination / "Tool" / "scripts" / "lib" / "runtime_root.py")
    shutil.copy2(REAL_LOCK, destination / "Tool" / "scripts" / "lib" / "project_lock.py")
    shutil.copy2(HERE / "lib/project_transaction.py", destination / "Tool/scripts/lib/project_transaction.py")
    shutil.copy2(REAL_PACK, destination / "Tool" / "skill" / "softseep" / "pack.json")
    shutil.copy2(REAL_SCRIPT, destination / "Tool" / "skill" / "softseep" / "scripts" / "version-migrate.py")
    shutil.copy2(REAL_VERSION, destination / "VERSION")
    return destination


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_core_version(case: Path, version: str, source: Path, parent: str | None = None):
    relative = "versions/%s/core.bin" % version
    target = case / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    record = {
        "schema": "seep-version/1",
        "version_id": version,
        "parent_version_id": parent,
        "local_path": relative,
        "sha256": sha256(target),
        "size": target.stat().st_size,
    }
    (case / "versions" / version / "version.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def init_version(case: Path, version: str, source: Path, parent: str = ""):
    args = ["init", "--case", str(case), "--version", version, "--file", str(source)]
    if parent:
        args += ["--parent", parent]
    return run_cli(REAL_SCRIPT, *args)


class VersionMigrateDeliveryTests(unittest.TestCase):
    def setUp(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="version-migrate-delivery-", dir=TMP_ROOT)
        self.base = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def test_real_deployed_copy_resolves_verified_runtime_and_fails_safe(self):
        runtime = copy_runtime(self.base / "runtime")
        agent = self.base / "agent"
        deployed = agent / "skills" / "softseep" / "scripts" / "version-migrate.py"
        deployed.parent.mkdir(parents=True)
        shutil.copy2(REAL_SCRIPT, deployed)

        explicit = child_env(SEEP_RUNTIME_ROOT=runtime)
        help_proc = run_cli(deployed, "--help", env=explicit)
        self.assertEqual(help_proc.returncode, 0, help_proc.stderr)
        self.assertIn("usage:", help_proc.stdout.lower())
        self_test = run_cli(deployed, "--self-test", env=explicit)
        self.assertEqual(self_test.returncode, 0, self_test.stderr)

        rr = load_runtime_root()
        registration = rr.make_registration(runtime, agent)
        agent.mkdir(parents=True, exist_ok=True)
        (agent / "seep-runtime.json").write_text(
            json.dumps(registration, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        registered = run_cli(deployed, "--self-test", env=child_env(PI_CODING_AGENT_DIR=agent))
        self.assertEqual(registered.returncode, 0, registered.stderr)

        # A named bad root is hard and must not fall through to a valid registration.
        bad_root = self.base / "missing-runtime"
        hard_fail = run_cli(
            deployed, "--self-test",
            env=child_env(SEEP_RUNTIME_ROOT=bad_root, PI_CODING_AGENT_DIR=agent),
        )
        self.assertEqual(hard_fail.returncode, 2)
        hard_json = output_json(hard_fail)
        self.assertEqual(hard_json["blocked_at"], "runtime")
        self.assertEqual(hard_json["ok"], False)
        self.assertNotIn("Traceback", hard_fail.stderr + hard_fail.stdout)

        # Registration hash drift is rejected by the public helper, not bypassed.
        pack = runtime / "Tool" / "skill" / "softseep" / "pack.json"
        pack.write_bytes(pack.read_bytes() + b"\n")
        stale = run_cli(deployed, "--self-test", env=child_env(PI_CODING_AGENT_DIR=agent))
        self.assertEqual(stale.returncode, 2)
        stale_json = output_json(stale)
        self.assertEqual(stale_json["blocked_at"], "runtime")
        self.assertIn("runtime_mismatch", stale_json["reason"])
        self.assertNotIn("Traceback", stale.stderr + stale.stdout)

        no_registration_agent = self.base / "no-registration-agent"
        missing = run_cli(
            deployed, "--self-test",
            env=child_env(PI_AGENT_DIR=no_registration_agent),
        )
        self.assertEqual(missing.returncode, 2)
        missing_json = output_json(missing)
        self.assertEqual(missing_json["blocked_at"], "runtime")
        self.assertIn("runtime_missing", missing_json["reason"])
        self.assertNotIn("Traceback", missing.stderr + missing.stdout)

    def alignment_fixture(self):
        case = self.base / "case-boundary"
        old = self.base / "old.bin"
        new = self.base / "new.bin"
        old.write_bytes(b"A\x10\x20\x30B")
        new.write_bytes(b"C\x10\x20\x30D")
        proc = init_version(case, "1.0", old)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        proc = run_cli(REAL_SCRIPT, "add-site", "--case", str(case), "--version", "1.0",
                       "--file", str(old), "--id", "site", "--sem", "synthetic",
                       "--aob", "10 20 30", "--original", "10 20 30", "--new", "11 20 30")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return case, old, new

    def test_alignment_and_report_refuse_project_paths_through_external_links(self):
        case, old, new = self.alignment_fixture()
        outside = self.base / "outside"
        outside.mkdir()
        target_version = case / "versions/1.1"
        try:
            target_version.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("host cannot create symlinks; boundary unverified")
        try:
            proc = run_cli(REAL_SCRIPT, "align", "--case", str(case), "--old", "1.0",
                           "--new", str(new), "--new-version", "1.1")
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertEqual(list(outside.iterdir()), [])
        finally:
            target_version.unlink()
        proc = run_cli(REAL_SCRIPT, "align", "--case", str(case), "--old", "1.0",
                       "--new", str(new), "--new-version", "1.1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        sentinel = outside / "keep.md"
        sentinel.write_bytes(b"keep external bytes")
        report = target_version / "migrate-report.md"
        report.symlink_to(sentinel)
        proc = run_cli(REAL_SCRIPT, "report", "--case", str(case), "--old", "1.0",
                       "--new-version", "1.1")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(sentinel.read_bytes(), b"keep external bytes")

    def test_report_rechecks_alignment_input_before_overwriting_output(self):
        case, old, new = self.alignment_fixture()
        proc = run_cli(REAL_SCRIPT, "align", "--case", str(case), "--old", "1.0",
                       "--new", str(new), "--new-version", "1.1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        args = ("report", "--case", str(case), "--old", "1.0", "--new-version", "1.1")
        proc = run_cli(REAL_SCRIPT, *args)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = case / "versions/1.1/migrate-report.md"
        before = report.read_bytes()
        new.write_bytes(b"C\x10\x20\x31D")
        proc = run_cli(REAL_SCRIPT, *args)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(report.read_bytes(), before)

    def test_report_uses_core_copy_and_refuses_its_drift_without_external_fallback(self):
        case, old, new = self.alignment_fixture()
        write_core_version(case, "1.0", old)
        write_core_version(case, "1.1", new, parent="1.0")
        proc = run_cli(REAL_SCRIPT, "align", "--case", str(case), "--old", "1.0",
                       "--new", str(new), "--new-version", "1.1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        new.unlink()
        args = ("report", "--case", str(case), "--old", "1.0", "--new-version", "1.1")
        proc = run_cli(REAL_SCRIPT, *args)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = case / "versions/1.1/migrate-report.md"
        before = report.read_bytes()
        new.write_bytes(b"C\x10\x20\x30D")
        (case / "versions/1.1/core.bin").write_bytes(b"C\x10\x20\x31D")
        proc = run_cli(REAL_SCRIPT, *args)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(report.read_bytes(), before)
        (case / "versions/1.1/core.bin").write_bytes(new.read_bytes())
        (case / "versions/1.1/version.json").unlink()
        proc = run_cli(REAL_SCRIPT, *args)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(report.read_bytes(), before)

    def test_report_rejects_changed_alignment_results_and_baseline(self):
        case, old, new = self.alignment_fixture()
        proc = run_cli(REAL_SCRIPT, "align", "--case", str(case), "--old", "1.0",
                       "--new", str(new), "--new-version", "1.1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        args = ("report", "--case", str(case), "--old", "1.0", "--new-version", "1.1")
        proc = run_cli(REAL_SCRIPT, *args)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = case / "versions/1.1/migrate-report.md"
        before = report.read_bytes()
        path = case / "versions/1.1/align.json"
        original = path.read_bytes()
        data = json.loads(original)
        data["sites"][0]["hits"][0]["offset"] = "0x999"
        path.write_text(json.dumps(data), encoding="utf-8")
        proc = run_cli(REAL_SCRIPT, *args)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(report.read_bytes(), before)
        path.write_bytes(original)
        baseline = case / "versions/1.0/reverse-baseline.json"
        data = json.loads(baseline.read_text(encoding="utf-8"))
        data["sites"][0]["sem"] = "changed after alignment"
        baseline.write_text(json.dumps(data), encoding="utf-8")
        proc = run_cli(REAL_SCRIPT, *args)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertEqual(report.read_bytes(), before)

    def test_report_write_failure_preserves_previous_report(self):
        import contextlib
        import io
        from unittest.mock import patch
        case, old, new = self.alignment_fixture()
        proc = run_cli(REAL_SCRIPT, "align", "--case", str(case), "--old", "1.0",
                       "--new", str(new), "--new-version", "1.1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        proc = run_cli(REAL_SCRIPT, "report", "--case", str(case), "--old", "1.0", "--new-version", "1.1")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = case / "versions/1.1/migrate-report.md"
        before = report.read_bytes()
        spec = importlib.util.spec_from_file_location("migration_atomic_test", REAL_SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertIsNone(module._BOOTSTRAP_ERROR)
        args = module.argparse.Namespace(case=str(case), old="1.0", new_version="1.1")
        with patch.object(module.os, "replace", side_effect=PermissionError("synthetic write failure")), \
                contextlib.redirect_stdout(io.StringIO()):
            code = module.cmd_report(args)
        self.assertEqual(code, 2)
        self.assertEqual(report.read_bytes(), before)
        self.assertFalse(list(report.parent.glob(".seep-reverse-*")))

    def test_d09_real_cli_fixture_keeps_alignment_below_acceptance(self):
        case = self.base / "case"
        old = self.base / "old-1.0.bin"
        new = self.base / "new-1.1.bin"
        old_data = bytearray(b"\x00" * 160)
        old_data[8:12] = bytes.fromhex("10 20 30 40")       # unique in new
        old_data[24:28] = bytes.fromhex("50 60 70 80")      # missing in new
        old_data[40:44] = bytes.fromhex("90 A0 B0 C0")      # multi in new
        old_data[112:116] = bytes.fromhex("DE AD BE EF")    # no AOB/manual
        old.write_bytes(old_data)
        new_data = bytearray(b"\x00" * 180)
        new_data[16:20] = bytes.fromhex("10 20 30 99")
        new_data[48:52] = bytes.fromhex("90 A0 B0 C1")
        new_data[80:84] = bytes.fromhex("90 A0 B0 C2")
        new.write_bytes(new_data)

        # These are the Core's typed version records; the migration CLI only consumes them.
        write_core_version(case, "1.0", old)
        write_core_version(case, "1.1", new, parent="1.0")
        for version, source, parent in (("1.0", old, ""), ("1.1", new, "1.0")):
            proc = init_version(case, version, source, parent)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue((case / "versions/1.0/version.json").is_file())
        self.assertTrue((case / "versions/1.1/version.json").is_file())

        def add(site_id, aob="", offset="", original="", replacement=""):
            proc = run_cli(
                REAL_SCRIPT, "add-site", "--case", str(case), "--version", "1.0",
                "--file", str(old), "--id", site_id, "--sem", site_id,
                "--aob", aob, "--offset", offset, "--original", original,
                "--new", replacement,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            return output_json(proc)

        add("unique", "10 20 30 ??", "", "10 20 30 40", "10 20 30 41")
        add("missing", "50 60 70 ??", "", "50 60 70 80", "50 60 70 81")
        add("multi", "90 A0 B0 ??", "", "90 A0 B0 C0", "90 A0 B0 C1")
        add("manual", "", "0x70", "DE AD BE EF", "DE AD BF EF")
        duplicate = run_cli(
            REAL_SCRIPT, "add-site", "--case", str(case), "--version", "1.0",
            "--file", str(old), "--id", "unique", "--sem", "duplicate",
            "--aob", "10 20 30 ??", "--original", "10 20 30 40", "--new", "10 20 30 41",
        )
        self.assertEqual(duplicate.returncode, 2)
        self.assertIn("site id", output_json(duplicate)["reason"])
        self.assertIn("unique", output_json(duplicate)["reason"])

        wrong_target = run_cli(
            REAL_SCRIPT, "add-site", "--case", str(case), "--version", "1.0",
            "--file", str(new), "--id", "wrong-target", "--sem", "wrong",
            "--aob", "10 20 30 ??", "--original", "10 20 30 40", "--new", "10 20 30 41",
        )
        self.assertEqual(wrong_target.returncode, 2)
        self.assertIn("不属于该基线", output_json(wrong_target)["reason"])
        self.assertIn("哈希", output_json(wrong_target)["reason"])

        same_bytes = run_cli(
            REAL_SCRIPT, "add-site", "--case", str(case), "--version", "1.0",
            "--file", str(old), "--id", "same-bytes", "--sem", "invalid",
            "--aob", "10 20 30 ??", "--original", "10 20 30 40", "--new", "10 20 30 40",
        )
        self.assertEqual(same_bytes.returncode, 2)
        self.assertIn("不能相同", output_json(same_bytes)["reason"])

        # Alignment must use the verified project copy, not the removed source input.
        old.unlink()
        aligned = run_cli(
            REAL_SCRIPT, "align", "--case", str(case), "--old", "1.0",
            "--new", str(new), "--new-version", "1.1",
        )
        self.assertEqual(aligned.returncode, 2)
        aligned_json = output_json(aligned)
        self.assertEqual(aligned_json["summary"], {
            "unique": 1, "missing": 1, "multi": 1, "needs_manual": 1,
        })
        align_file = case / "versions/1.1/align.json"
        align_data = json.loads(align_file.read_text(encoding="utf-8"))
        statuses = {row["id"]: row["status"] for row in align_data["sites"]}
        self.assertEqual(statuses, {
            "unique": "unique", "missing": "missing", "multi": "multi",
            "manual": "needs_manual",
        })
        self.assertEqual(align_data["meaning"], "unique is a positioning candidate, not acceptance")
        self.assertEqual(align_data["sites"][0].get("patch"), None)

        report = run_cli(
            REAL_SCRIPT, "report", "--case", str(case), "--old", "1.0", "--new-version", "1.1",
        )
        self.assertEqual(report.returncode, 0, report.stdout + report.stderr)
        report_text = (case / "versions/1.1/migrate-report.md").read_text(encoding="utf-8")
        self.assertIn("unique 仅表示字节定位候选", report_text)
        self.assertNotIn("verified", report_text.lower())

        wrong_report_source = run_cli(
            REAL_SCRIPT, "report", "--case", str(case), "--old", "1.1", "--new-version", "1.1",
        )
        self.assertEqual(wrong_report_source.returncode, 2)
        self.assertIn("align 来源版本", output_json(wrong_report_source)["reason"])
        self.assertIn("报告参数", output_json(wrong_report_source)["reason"])

        # A changed internal old copy is an old-hash failure, not a new success.
        internal_old = case / "versions/1.0/reverse-target/old-1.0.bin"
        internal_old.write_bytes(internal_old.read_bytes() + b"x")
        old_hash = run_cli(
            REAL_SCRIPT, "align", "--case", str(case), "--old", "1.0",
            "--new", str(new), "--new-version", "1.1",
        )
        self.assertEqual(old_hash.returncode, 2)
        self.assertIn("mismatch", old_hash.stdout.lower())
        self.assertNotIn("Traceback", old_hash.stderr + old_hash.stdout)


if __name__ == "__main__":
    unittest.main()
