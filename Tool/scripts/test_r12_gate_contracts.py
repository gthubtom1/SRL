"""R12 contracts for runtime aggregation, strict exit semantics and CI wiring."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("check_under_test", HERE / "check.py")
assert SPEC and SPEC.loader
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)

PRE_UPLOAD_SPEC = importlib.util.spec_from_file_location(
    "pre_upload_under_test", HERE / "pre-upload-check.py"
)
assert PRE_UPLOAD_SPEC and PRE_UPLOAD_SPEC.loader
pre_upload = importlib.util.module_from_spec(PRE_UPLOAD_SPEC)
PRE_UPLOAD_SPEC.loader.exec_module(pre_upload)

DOC_COMMANDS_SPEC = importlib.util.spec_from_file_location(
    "doc_commands_under_test", HERE / "lib" / "doc_commands.py"
)
assert DOC_COMMANDS_SPEC and DOC_COMMANDS_SPEC.loader
doc_commands = importlib.util.module_from_spec(DOC_COMMANDS_SPEC)
DOC_COMMANDS_SPEC.loader.exec_module(doc_commands)


class RuntimeGateContractTests(unittest.TestCase):
    def test_runtime_discovers_every_first_party_python_test_file(self):
        suites = {name: argv for name, argv, _fast, _why in check.runtime_suites()}
        discovered = {argv[0].replace("\\", "/") for argv in suites.values()}
        expected = set()
        for relative in ("Tool/scripts", "setup", ".github/tests", "Tool/mcp"):
            expected.update(
                path.relative_to(ROOT).as_posix()
                for path in sorted((ROOT / relative).glob("test_*.py"))
            )
        self.assertEqual(expected - discovered, set())
        self.assertIn("relay-tests", suites)
        self.assertGreaterEqual(
            len(list((ROOT / "Tool/scripts/compliance-relay/tests").glob("test_*.py"))),
            1,
        )

    def test_runtime_explicitly_contains_real_aggregate_and_quality_gates(self):
        suites = {name: argv for name, argv, _fast, _why in check.runtime_suites()}
        self.assertEqual(suites["unit"], ["Tool/scripts/gate.py", "--all"])
        self.assertEqual(suites["e2e"], ["Tool/scripts/domain-gate.py", "--all"])
        self.assertEqual(suites["pre-upload"], ["Tool/scripts/pre-upload-check.py"])
        self.assertEqual(suites["invariants"], ["Tool/scripts/invariants.py", "--check"])
        self.assertGreaterEqual(
            sum(1 for entry in suites.values() if entry[0].startswith("Tool/scripts/test_")),
            14,
        )

    def test_expensive_runtime_suites_have_distinct_time_budgets(self):
        self.assertGreater(check.runtime_timeout("e2e"), check.runtime_timeout("unknown"))
        self.assertGreater(check.runtime_timeout("unit"), check.runtime_timeout("unknown"))
        self.assertEqual(check.runtime_timeout("pre-upload"), 600)
        self.assertEqual(check.runtime_timeout("invariants"), 900)

    def test_strict_turns_warn_or_skip_into_exit_one(self):
        warn_result = ("unit", True, "warn", 0.1, 3, "")
        with patch.object(sys, "argv", ["check.py", "--runtime", "--strict", "--json"]), \
                patch.object(check, "runtime_suites", return_value=[
                    ("unit", ["Tool/scripts/gate.py", "--all"], True, "unit"),
                ]), \
                patch.object(check, "run_one", return_value=warn_result), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(check.main(), 1)
        payload = json.loads(output.getvalue())
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["exit_code"], 1)
        self.assertEqual(payload["summary"]["warn"], 1)

    def test_ci_runs_two_platforms_with_isolated_install_and_runtime(self):
        workflow = (ROOT / ".github" / "workflows" / "gates.yml").read_text(encoding="utf-8")
        for token in (
                "runs-on: ubuntu-latest",
                "runs-on: windows-latest",
                ".github/scripts/check_ci_install.py",
                "@earendil-works/pi-coding-agent@1.4.0",
                "node setup/test_persona_rewind_sdk.mjs",
                "PI_CODING_AGENT_DIR",
                ".github/scripts/check_public_source.py --list",
                ".github/scripts/check_public_source.py",
                "public source verification",
                "Tool/mcp/test_seep_mcp.py",
                "Tool/mcp/test_apk_contract.py",
                "timeout-minutes: 45",
                "if: always()",
                "Enforce all gate outcomes",
        ):
            self.assertIn(token, workflow)
        self.assertGreaterEqual(workflow.count("continue-on-error: true"), 10)

    def test_public_scope_is_explicit_and_full_runtime_keeps_private_gates(self):
        spec = importlib.util.spec_from_file_location("public_ci", ROOT / ".github/scripts/check_public_source.py")
        ci = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ci)
        manifest = json.loads((ROOT / ".github/public-suites.json").read_text(encoding="utf-8"))
        ci.inventory(manifest, check.runtime_suites())
        self.assertIn("domain-task-delivery", manifest["included"])
        self.assertIn("unit", manifest["excluded"])
        self.assertIn("e2e", manifest["excluded"])
        self.assertIn("preflight", manifest["outside_runtime"])
        self.assertTrue({"unit", "e2e"}.issubset({s[0] for s in check.runtime_suites()}))
        with self.assertRaises(ValueError):
            ci.inventory(manifest, check.runtime_suites() + [("new-unreviewed", ["new.py"], True, "new")])
        bad = json.loads(json.dumps(manifest))
        bad["excluded"]["unit"] = ""
        with self.assertRaises(ValueError):
            ci.inventory(bad, check.runtime_suites())

    def test_ci_install_requires_only_explicit_auth_rejection(self):
        spec = importlib.util.spec_from_file_location("ci_install", ROOT / ".github/scripts/check_ci_install.py")
        ci = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ci)
        result = {
            "installed": False, "missing": ["宿主认证未就绪：synthetic not signed in"],
            "checks": {
                "pi": True, "node": True, "runtime_registration": {"ok": True},
                "mcp": {"service": {"available": True}},
                "model_credential": {"configured": False, "stage": "host-auth-check", "detail": "synthetic not signed in"},
            },
        }
        ci.validate_results(1, 1, result)
        ci.validate_results(0, 1, result, windows=True)
        for path in ("pi", "node", "runtime_registration", "mcp"):
            bad = json.loads(json.dumps(result))
            bad["checks"][path] = False if path in ("pi", "node") else {}
            with self.subTest(missing=path), self.assertRaises(ValueError):
                ci.validate_results(1, 1, bad)
        for mutation in (
            {"missing": result["missing"] + ["damaged skill"]},
            {"missing": []}, {"installed": True},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                ci.validate_results(1, 1, dict(result, **mutation))
        for install_code, ready_code in ((0, 1), (1, 0), (2, 1), (1, 2)):
            with self.subTest(codes=(install_code, ready_code)), self.assertRaises(ValueError):
                ci.validate_results(install_code, ready_code, result)


class FailClosedContractTests(unittest.TestCase):
    def test_pre_upload_missing_git_manifest_blocks_upload(self):
        output = io.StringIO()
        with patch.object(pre_upload, "_git", return_value=None), \
                patch.object(pre_upload, "check_local", return_value=([], [], False)), \
                contextlib.redirect_stdout(output):
            rc = pre_upload.main(["--json"])
        payload = json.loads(output.getvalue())
        self.assertEqual(rc, 1)
        self.assertFalse(payload["git"])
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["rc"], 1)

    def test_doc_command_missing_help_is_not_a_pass(self):
        with tempfile.TemporaryDirectory(prefix="seep-r12-doc-help-") as root:
            ok, detail = doc_commands.check_doc_commands(
                "python Tool/scripts/check.py --fast", root
            )
        self.assertFalse(ok)
        self.assertIn("无法读取 --help", detail)


@unittest.skipUnless(os.name == "nt", "check.ps1 argument forwarding is Windows-specific")
class DetailedCheckArgumentContractTests(unittest.TestCase):
    def test_fast_is_forwarded_to_suite_list(self):
        powershell = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
        if not powershell:
            self.skipTest("PowerShell is unavailable")
        with tempfile.TemporaryDirectory(prefix="seep-r12-check-ps-") as temp:
            temp_path = Path(temp)
            script = temp_path / "check.ps1"
            shutil.copyfile(ROOT / "check.ps1", script)
            bin_dir = temp_path / "bin"
            bin_dir.mkdir()
            fake_python = bin_dir / "python.cmd"
            trace = temp_path / "python-args.txt"
            fake_python.write_text(
                '@echo off\r\necho %*>>"%PY_TRACE%"\r\nexit /b 0\r\n',
                encoding="ascii",
            )
            home = temp_path / "home"
            home.mkdir()
            env = os.environ.copy()
            env.update({
                "HOME": str(home),
                "USERPROFILE": str(home),
                "TEMP": str(temp_path),
                "TMP": str(temp_path),
                "PY_TRACE": str(trace),
                "PATH": str(bin_dir) + os.pathsep + env.get("PATH", ""),
            })
            result = subprocess.run(
                [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                 str(script), "-Fast", "-Detailed"],
                cwd=temp_path, env=env, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            calls = trace.read_text(encoding="utf-8").splitlines()
            self.assertGreaterEqual(len(calls), 2)
            self.assertIn("--fast --list", calls[0])
            self.assertIn("--fast", calls[1])
            self.assertNotIn("--list", calls[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
