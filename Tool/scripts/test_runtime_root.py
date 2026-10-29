#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regressions for lib/runtime_root.py (agent root + public runtime root).

Run: python -B Tool/scripts/test_runtime_root.py

Every fixture is a temporary directory.  Real repository files are only read
and, where a "deployed" layout is needed, copied (never modified).  The shared
lock code in the fixtures is the *real* Tool/scripts/lib/project_lock.py -- no
stub lock is ever created, because "tools found" must not be proven by a
lookalike.  No installer, download, network, HOME change or target execution
happens here; subprocesses exercise the deployed shared lock and actual
version-migrate ``--help``/``--self-test`` runs.
"""
from __future__ import annotations

import hashlib
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

sys.path.insert(0, str(HERE / "lib"))
sys.path.insert(0, str(HERE))
import runtime_root as RR  # noqa: E402  (Tool/scripts/lib/runtime_root.py)

REAL_MIGRATE = ROOT / "Tool" / "skill" / "softseep" / "scripts" / "version-migrate.py"
REAL_LOCK = ROOT / "Tool" / "scripts" / "lib" / "project_lock.py"
REAL_PACK = ROOT / "Tool" / "skill" / "softseep" / "pack.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def build_runtime(dest: Path, *, with_lock=True, with_pack=True,
                  with_cases=True, with_entry=True) -> Path:
    """A canonical runtime built from *real* repo files (copies, never symlinks)."""
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "VERSION").write_bytes((ROOT / "VERSION").read_bytes())
    lib = dest / "Tool" / "scripts" / "lib"
    lib.mkdir(parents=True)
    for name in ("runtime_root.py", "project_lock.py", "project_transaction.py",
                 "source_inventory.py", "typed_assets.py"):
        shutil.copy2(ROOT / "Tool" / "scripts" / "lib" / name, lib / name)
    if not with_lock:
        (lib / "project_lock.py").unlink()
    scripts = dest / "Tool" / "skill" / "softseep" / "scripts"
    scripts.mkdir(parents=True)
    if with_entry:
        shutil.copy2(REAL_MIGRATE, scripts / "version-migrate.py")
    pack = dest / "Tool" / "skill" / "softseep" / "pack.json"
    if with_pack:
        shutil.copy2(REAL_PACK, pack)
    if with_cases:
        (dest / "Tool" / "cases").mkdir()  # structural marker only
    return dest


class RuntimeRootTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="seep-runtime-root-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.home = self.base / "home"
        self.home.mkdir()
        self.agent = self.base / "agent dir"
        self.runtime = self.base / "runtime ünïcode 空格"
        build_runtime(self.runtime)
        self.env = {}

    # ---------------- helpers ----------------
    def write_origin(self, data, agent=None):
        agent = Path(agent or self.agent)
        agent.mkdir(parents=True, exist_ok=True)
        (agent / RR.ORIGIN_FILE).write_text(json.dumps(data, ensure_ascii=False),
                                           encoding="utf-8")

    def register(self, runtime=None, agent=None):
        self.write_origin(RR.make_registration(runtime or self.runtime, agent or self.agent),
                          agent)

    # ---------------- agent root ----------------
    def test_agent_root_priority_explicit_then_env_then_default(self):
        env = {"PI_CODING_AGENT_DIR": str(self.base / "coding"),
               "PI_AGENT_DIR": str(self.base / "plain")}
        self.assertEqual(RR.resolve_agent_root(self.base / "explicit", env, self.home),
                         (self.base / "explicit").resolve())
        self.assertEqual(RR.resolve_agent_root(None, env, self.home),
                         (self.base / "coding").resolve())
        self.assertEqual(RR.resolve_agent_root(None, {"PI_AGENT_DIR": str(self.base / "plain")},
                                               self.home), (self.base / "plain").resolve())
        self.assertEqual(RR.resolve_agent_root(None, {}, self.home),
                         (self.home / ".pi" / "agent").resolve())
        # blank values are not configuration and must not shadow the next source
        self.assertEqual(
            RR.resolve_agent_root(None, {"PI_CODING_AGENT_DIR": "  ", "PI_AGENT_DIR": " "},
                                  self.home), (self.home / ".pi" / "agent").resolve())

    def test_agent_root_is_read_only_and_rejects_empty_or_drive_root(self):
        before = sorted(os.environ)
        target = self.base / "never created"
        self.assertEqual(RR.resolve_agent_root(target, {}, self.home), target.resolve())
        self.assertFalse(target.exists(), "resolver must not mkdir")
        for bad in ("", "   ", "\x00bad"):
            with self.subTest(bad=bad), self.assertRaises(RR.RuntimeRootError) as ctx:
                RR.resolve_agent_root(bad, {}, self.home)
            self.assertEqual(ctx.exception.code, "agent_root_invalid")
        drive = Path(os.path.abspath(os.sep))
        with self.assertRaises(RR.RuntimeRootError) as ctx:
            RR.resolve_agent_root(drive, {}, self.home)
        self.assertEqual(ctx.exception.code, "agent_root_invalid")
        self.assertEqual(sorted(os.environ), before, "environment must not be touched")

    # ---------------- runtime root locators ----------------
    def test_repo_structure_from_script_ignores_cwd(self):
        cwd = os.getcwd()
        try:
            os.chdir(self.base)  # a non-repo cwd; must not matter
            got = RR.resolve_runtime_root(script_path=REAL_MIGRATE, agent_root=self.agent,
                                          env={})
        finally:
            os.chdir(cwd)
        self.assertEqual(got["source_kind"], "repo")
        self.assertEqual(Path(got["runtime_root"]), ROOT.resolve())

    def test_source_candidate_beats_stale_ambient_registration(self):
        stale = self.base / "stale install"
        build_runtime(stale, with_lock=False)  # broken lookalike
        self.write_origin(RR.make_registration(self.runtime, self.agent))
        (self.agent / RR.ORIGIN_FILE).write_text(json.dumps({  # stale, points at breakage
            "schema": RR.ORIGIN_SCHEMA, "runtime_id": RR.RUNTIME_ID,
            "source_root": str(stale), "entry_sha256": {}}), encoding="utf-8")
        got = RR.resolve_runtime_root(source_candidate=self.runtime, agent_root=self.agent,
                                      env={})
        self.assertEqual((got["source_kind"], Path(got["runtime_root"])),
                         ("source", self.runtime.resolve()))
        with self.assertRaises(RR.RuntimeRootError) as ctx:  # without the candidate it fails
            RR.resolve_runtime_root(agent_root=self.agent, env={})
        self.assertEqual(ctx.exception.code, "runtime_missing")

    def test_explicit_and_env_candidates_fail_loudly_without_fallback(self):
        self.register()  # a perfectly valid registration exists ...
        broken = self.base / "no markers"
        broken.mkdir()
        with self.assertRaises(RR.RuntimeRootError) as ctx:
            RR.resolve_runtime_root(broken, agent_root=self.agent, env={})
        self.assertEqual(ctx.exception.code, "runtime_missing")
        ok = RR.resolve_runtime_root(self.runtime, agent_root=self.agent, env={})
        self.assertEqual(ok["source_kind"], "explicit")
        with self.assertRaises(RR.RuntimeRootError) as ctx:  # broken source candidate:
            RR.resolve_runtime_root(source_candidate=broken,  # must not fall back either
                                    agent_root=self.agent, env={})
        self.assertEqual(ctx.exception.code, "runtime_missing")
        with self.assertRaises(RR.RuntimeRootError) as ctx:
            RR.resolve_runtime_root(agent_root=self.agent,
                                    env={"SEEP_RUNTIME_ROOT": str(broken)})
        self.assertEqual(ctx.exception.code, "runtime_missing")
        env_ok = RR.resolve_runtime_root(agent_root=self.agent,
                                        env={"SEEP_RUNTIME_ROOT": str(self.runtime)})
        self.assertEqual(env_ok["source_kind"], "env")

    # ---------------- registration ----------------
    def test_malformed_version_contract_is_typed_runtime_failure(self):
        path = self.runtime / RR.PACK_REL
        original = json.loads(path.read_text(encoding="utf-8"))
        for value in (["invalid"], "invalid", 7, None):
            with self.subTest(value=value):
                path.write_text(json.dumps(dict(original, version_contract=value)), encoding="utf-8")
                with self.assertRaises(RR.RuntimeRootError) as ctx:
                    RR.resolve_runtime_root(self.runtime, agent_root=self.agent, env={})
                self.assertEqual(ctx.exception.code, "runtime_mismatch")

    def test_deployed_layout_registration_closure_uses_real_shared_lock(self):
        self.register()
        deployed = self.agent / "skills" / "softseep" / "scripts"
        deployed.mkdir(parents=True)
        shutil.copy2(REAL_MIGRATE, deployed / "version-migrate.py")
        got = RR.resolve_runtime_root(script_path=deployed / "version-migrate.py",
                                      agent_root=self.agent, env={})
        self.assertEqual((got["source_kind"], Path(got["runtime_root"])),
                         ("registration", self.runtime.resolve()))
        self.assertEqual(sha256(self.runtime / RR.LOCK_REL), sha256(REAL_LOCK))
        # A fresh interpreter proves the deployed import independently of any
        # repository lib modules already loaded by the surrounding test suite.
        code = """import json, sys
from pathlib import Path
runtime, fixture = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(runtime / "Tool/scripts"))
import lib.project_lock as lock
assert Path(lock.__file__).resolve().is_relative_to(runtime.resolve())
with lock.project_lock(fixture):
    assert (fixture / ".project.lock").is_file()
print(json.dumps({"ok": True}))
"""
        result = subprocess.run([sys.executable, "-I", "-B", "-c", code, str(self.runtime),
                                 str(self.base / "lock-fixture")], capture_output=True,
                                text=True, encoding="utf-8", timeout=30)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertTrue(json.loads(result.stdout)["ok"])

    def test_deployed_layout_inside_checkout_does_not_claim_enclosing_repo(self):
        self.register()
        local_tmp = ROOT / "tmp"
        local_tmp.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="seep-deployed-in-checkout-",
                                         dir=local_tmp) as tmp:
            deployed = Path(tmp) / "agent/skills/softseep/scripts"
            deployed.mkdir(parents=True)
            shutil.copy2(REAL_MIGRATE, deployed / "version-migrate.py")
            got = RR.resolve_runtime_root(
                script_path=deployed / "version-migrate.py",
                agent_root=self.agent,
                env={},
            )
        self.assertEqual((got["source_kind"], Path(got["runtime_root"])),
                         ("registration", self.runtime.resolve()))

    def test_registration_missing_version_or_hash_drift_is_rejected(self):
        self.register()
        self.assertEqual(RR.resolve_runtime_root(agent_root=self.agent, env={})["source_kind"],
                         "registration")
        pack = self.runtime / RR.PACK_REL
        original = pack.read_bytes()
        pack.write_bytes(original + b"\n")  # still valid JSON, different bytes
        with self.assertRaises(RR.RuntimeRootError) as ctx:
            RR.resolve_runtime_root(agent_root=self.agent, env={})
        self.assertEqual(ctx.exception.code, "runtime_mismatch")
        pack.write_bytes(original)
        (self.runtime / "VERSION").write_text("9.9.9", encoding="utf-8")
        with self.assertRaises(RR.RuntimeRootError) as ctx:
            RR.resolve_runtime_root(agent_root=self.agent, env={})
        self.assertEqual(ctx.exception.code, "runtime_mismatch")
        (self.runtime / "VERSION").write_text((ROOT / "VERSION").read_text(encoding="utf-8"),
                                              encoding="utf-8")
        (self.runtime / RR.LOCK_REL).unlink()  # cache/helper missing
        with self.assertRaises(RR.RuntimeRootError) as ctx:
            RR.resolve_runtime_root(agent_root=self.agent, env={})
        self.assertEqual(ctx.exception.code, "runtime_missing")
        shutil.rmtree(self.runtime)  # source gone entirely
        with self.assertRaises(RR.RuntimeRootError) as ctx:
            RR.resolve_runtime_root(agent_root=self.agent, env={})
        self.assertEqual(ctx.exception.code, "runtime_missing")

    def test_moved_source_needs_reregistration(self):
        self.register()
        moved = self.base / "moved runtime"
        shutil.move(str(self.runtime), str(moved))
        with self.assertRaises(RR.RuntimeRootError) as ctx:
            RR.resolve_runtime_root(agent_root=self.agent, env={})
        self.assertEqual(ctx.exception.code, "runtime_missing")
        self.register(runtime=moved)  # explicit re-registration repairs the locator
        got = RR.resolve_runtime_root(agent_root=self.agent, env={})
        self.assertEqual(Path(got["runtime_root"]), moved.resolve())

    def test_registration_schema_errors_do_not_echo_unknown_values(self):
        self.write_origin({"schema": "other/9", "runtime_id": RR.RUNTIME_ID,
                           "secret_token": "SUPERSECRET", "source_root": "SUPERSECRET"})
        with self.assertRaises(RR.RuntimeRootError) as ctx:
            RR.resolve_runtime_root(agent_root=self.agent, env={})
        self.assertEqual(ctx.exception.code, "runtime_mismatch")
        self.assertNotIn("SUPERSECRET", str(ctx.exception))
        self.write_origin({"schema": RR.ORIGIN_SCHEMA, "runtime_id": RR.RUNTIME_ID,
                           "relative_root": "../../escape"})
        with self.assertRaises(RR.RuntimeRootError) as ctx:
            RR.resolve_runtime_root(agent_root=self.agent, env={})
        self.assertEqual(ctx.exception.code, "runtime_mismatch")
        (self.agent / RR.ORIGIN_FILE).write_text("{not json", encoding="utf-8")
        with self.assertRaises(RR.RuntimeRootError) as ctx:
            RR.resolve_runtime_root(agent_root=self.agent, env={})
        self.assertEqual(ctx.exception.code, "runtime_mismatch")

    def test_stub_lock_without_shared_api_is_not_accepted(self):
        # A lookalike file named project_lock.py must not fake a public runtime.
        lock = self.runtime / RR.LOCK_REL
        lock.write_text("def unlock():\n    return None\n", encoding="utf-8")
        with self.assertRaises(RR.RuntimeRootError) as ctx:
            RR.resolve_runtime_root(self.runtime, agent_root=self.agent, env={})
        self.assertEqual(ctx.exception.code, "runtime_missing")
        self.assertIn("shared lock missing: project_lock", ctx.exception.detail)

    def test_make_registration_is_pure_data(self):
        agent = self.base / "untouched agent"
        record = RR.make_registration(self.runtime, agent)
        self.assertFalse(agent.exists(), "registration helper must not write")
        self.assertEqual(record["schema"], RR.ORIGIN_SCHEMA)
        self.assertEqual(record["runtime_id"], RR.RUNTIME_ID)
        self.assertEqual(Path(record["source_root"]), self.runtime.resolve())
        self.assertEqual(record["relative_root"], "")
        self.assertEqual(set(record["entry_sha256"]),
                         {RR.SCRIPT_REL, RR.LOCK_REL, RR.TRANSACTION_REL, RR.PACK_REL})
        self.assertEqual(record["entry_sha256"][RR.SCRIPT_REL], sha256(REAL_MIGRATE))
        self.assertEqual(record["ownership"]["project"], "seep-reverse-lab")
        self.assertNotIn("token", json.dumps(record).lower())
        inner = self.agent / "nested runtime"
        build_runtime(inner)
        self.assertEqual(RR.make_registration(inner, self.agent)["relative_root"],
                         "nested runtime")

    # ---------------- actual deployed bootstrap + CLI ----------------
    def test_bootstrap_uses_shared_lock_implementation(self):
        import ast
        tree = ast.parse(REAL_MIGRATE.read_text(encoding="utf-8"))
        definitions = {n.name for n in ast.walk(tree)
                       if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        for name in ("project_lock", "atomic_copy", "verify_file"):
            self.assertNotIn(name, definitions)

    def test_deployed_cli_help_and_self_test(self):
        self.register()
        deployed = self.agent / "skills" / "softseep" / "scripts"
        deployed.mkdir(parents=True)
        target = deployed / "version-migrate.py"
        shutil.copy2(REAL_MIGRATE, target)
        env = {k: v for k, v in os.environ.items()
               if k not in ("PYTHONPATH", "SEEP_RUNTIME_ROOT", "PI_AGENT_DIR")}
        env["PI_CODING_AGENT_DIR"] = str(self.agent)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"  # keep the child's stdout decodable on any console
        cwd = self.base / "neutral cwd"
        cwd.mkdir()
        before = (sha256(REAL_MIGRATE), sha256(REAL_LOCK))
        for args, expect in ((["--help"], 0), (["--self-test"], 0)):
            with self.subTest(args=args):
                proc = subprocess.run([sys.executable, "-B", str(target)] + args,
                                      cwd=str(cwd), env=env, capture_output=True, text=True,
                                      encoding="utf-8", errors="replace", timeout=180)
                self.assertEqual(proc.returncode, expect, (proc.stdout[-800:], proc.stderr[-800:]))
                self.assertNotIn("ModuleNotFoundError", proc.stderr)
                if args == ["--self-test"]:
                    self.assertIn('"ok": true', proc.stdout)
        self.assertEqual((sha256(REAL_MIGRATE), sha256(REAL_LOCK)), before,
                         "main-route source bytes must not change")
        self.assertFalse((self.runtime / "Tool" / "scripts" / "lib" / "__pycache__").exists())

    def test_deployed_cli_reports_typed_error_when_runtime_is_gone(self):
        self.register()
        deployed = self.agent / "skills" / "softseep" / "scripts"
        deployed.mkdir(parents=True)
        target = deployed / "version-migrate.py"
        shutil.copy2(REAL_MIGRATE, target)
        shutil.rmtree(self.runtime)
        env = {k: v for k, v in os.environ.items()
               if k not in ("PYTHONPATH", "SEEP_RUNTIME_ROOT", "PI_AGENT_DIR")}
        env["PI_CODING_AGENT_DIR"] = str(self.agent)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        proc = subprocess.run([sys.executable, "-B", str(target), "--self-test"],
                              cwd=str(self.base), env=env, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=180)
        self.assertEqual(proc.returncode, 2, proc.stderr[-500:])
        self.assertIn("runtime_missing", proc.stdout)
        self.assertNotIn("Traceback", proc.stderr)


    def test_deployed_cli_refuses_a_runtime_missing_transaction_dependency(self):
        self.register()
        (self.runtime / "Tool/scripts/lib/project_transaction.py").unlink()
        deployed = self.agent / "skills/softseep/scripts"
        deployed.mkdir(parents=True)
        target = deployed / "version-migrate.py"
        shutil.copy2(REAL_MIGRATE, target)
        env = {k: v for k, v in os.environ.items()
               if k not in ("PYTHONPATH", "SEEP_RUNTIME_ROOT", "PI_AGENT_DIR")}
        env.update(PI_CODING_AGENT_DIR=str(self.agent), PYTHONDONTWRITEBYTECODE="1",
                   PYTHONIOENCODING="utf-8")
        proc = subprocess.run([sys.executable, "-B", str(target), "--self-test"],
            cwd=str(self.base), env=env, capture_output=True, text=True,
            encoding="utf-8", timeout=30)
        self.assertEqual(proc.returncode, 2, (proc.stdout, proc.stderr))
        result = json.loads(proc.stdout)
        self.assertFalse(result["ok"])
        self.assertIn("runtime_missing", proc.stdout)
        self.assertNotIn("Traceback", proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
