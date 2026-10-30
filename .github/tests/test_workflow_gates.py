"""Exercise the real YAML run blocks with synthetic commands, never customer targets.

Run: python .github/tests/test_workflow_gates.py
Requires PyYAML (installed by gates.yml). No network or git mutations.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = Path(os.environ.get("SEEP_TEST_GATES_PATH", ROOT / ".github/workflows/gates.yml"))
JOBS = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
MCP_TESTS = (
    "Tool/mcp/test_seep_mcp.py", "Tool/mcp/test_ext_assets.py",
    "Tool/mcp/test_pcap_contract.py", "Tool/mcp/test_apk_contract.py",
    "Tool/mcp/test_readonly_parameters.py",
)


def shell_path(shell):
    path = shutil.which(shell)
    if not path and shell == "bash" and os.name == "nt":
        git = shutil.which("git")
        if git:
            candidate = Path(git).resolve().parent.parent / "bin/bash.exe"
            if candidate.is_file():
                path = str(candidate)
    return path


class WorkflowGates(unittest.TestCase):
    def setUp(self):
        parent = ROOT / "tmp/sol-github-audit"
        parent.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix="workflow-", dir=parent)
        self.addCleanup(self.tmp.cleanup)

    def run_block(self, job, script, extra_env=None, stub=False):
        shell = job.get("defaults", {}).get("run", {}).get("shell", "bash")
        executable = shell_path(shell)
        if not executable:
            self.fail(f"{shell} unavailable; both Bash and pwsh are required for workflow regressions")
        env = dict(os.environ, **(extra_env or {}))
        if shell == "pwsh":
            prefix = "$ErrorActionPreference = 'stop'\n"
            if stub:
                prefix += """function python {
  Write-Output ('stub: ' + ($args -join ' '))
  $global:LASTEXITCODE = 0
  if ($args -contains $env:SEEP_FAIL_TEST) { $global:LASTEXITCODE = 29 }
}
"""
            # GitHub Actions' pwsh wrapper propagates only the last native code.
            suffix = "\nif (Test-Path variable:\\LASTEXITCODE) { exit $LASTEXITCODE }\n"
            path = Path(self.tmp.name) / "step.ps1"
            cmd = [executable, "-NoProfile", "-NonInteractive", "-File", str(path)]
        else:
            prefix = ""
            if stub:
                prefix += """python() {
  echo "stub: $*"
  for arg in "$@"; do
    if [[ "$arg" == "$SEEP_FAIL_TEST" ]]; then return 29; fi
  done
  return 0
}
"""
            suffix = ""
            path = Path(self.tmp.name) / "step.sh"
            cmd = [executable, "--noprofile", "--norc", "-e", "-o", "pipefail", str(path)]
        path.write_text(prefix + script + suffix, encoding="utf-8", newline="\n")
        return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True,
                              text=True, encoding="utf-8", errors="replace", timeout=20)

    def test_each_mcp_failure_reaches_step_outcome(self):
        for name, job in JOBS.items():
            for target in MCP_TESTS:
                with self.subTest(job=name, failing=target):
                    steps = [s for s in job["steps"] if target in s.get("run", "")]
                    self.assertEqual(len(steps), 1)
                    result = self.run_block(job, steps[0]["run"], {"SEEP_FAIL_TEST": target}, stub=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_successful_mcp_commands_pass(self):
        for name, job in JOBS.items():
            for step in job["steps"]:
                if any(t in step.get("run", "") for t in MCP_TESTS):
                    with self.subTest(job=name, step=step["id"]):
                        result = self.run_block(job, step["run"], {"SEEP_FAIL_TEST": "none"}, stub=True)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_final_enforcement_rejects_each_unsuccessful_outcome(self):
        for name, job in JOBS.items():
            final = job["steps"][-1]
            self.assertEqual(final["if"], "always()")
            outcomes = final["env"]
            referenced = {re.fullmatch(r"\$\{\{ steps\.([\w-]+)\.outcome \}\}", v)[1]
                          for v in outcomes.values()}
            deferred = {s["id"] for s in job["steps"] if s.get("continue-on-error")}
            self.assertEqual(referenced, deferred)
            success = dict.fromkeys(outcomes, "success")
            result = self.run_block(job, final["run"], success)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for key in outcomes:
                for state in ("failure", "skipped", "cancelled", ""):
                    with self.subTest(job=name, outcome=key, state=state):
                        result = self.run_block(job, final["run"], dict(success, **{key: state}))
                        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_upstream_pr_errors_propagate_and_new_prs_are_drafts(self):
        upstream_path = WORKFLOW.with_name("upstream-sync.yml")
        upstream = yaml.safe_load(upstream_path.read_text(encoding="utf-8"))
        job = upstream["jobs"]["check-and-sync"]
        script = next(s["run"] for s in job["steps"] if s.get("name") == "Process Upstream Targets")
        # Execute only the real PR block. Never execute checkout, commit or push.
        begin = script.index("  EXISTING_PR=")
        end = script.index("\n  git checkout main", begin)
        stub = """gh() {
  case "$1 $2" in
    'pr list')
      if [[ "$SEEP_GH_LIST_EXIT" != 0 ]]; then return "$SEEP_GH_LIST_EXIT"; fi
      printf '%s' "$SEEP_GH_EXISTING"
      ;;
    'pr create'|'pr edit') echo "write: $*"; return "$SEEP_GH_WRITE_EXIT" ;;
    *) return 98 ;;
  esac
}
BRANCH_NAME=fixture
PR_BODY=fixture.md
COMMIT_MSG=fixture
"""
        for list_code, existing, write_code, expected in (
            (17, "", 0, 17), (0, "", 0, 0), (0, "42", 0, 0),
            (0, "", 23, 23), (0, "42", 23, 23),
        ):
            with self.subTest(list_code=list_code, existing=existing, write_code=write_code):
                result = self.run_block(job, stub + script[begin:end], {
                    "SEEP_GH_LIST_EXIT": str(list_code), "SEEP_GH_EXISTING": existing,
                    "SEEP_GH_WRITE_EXIT": str(write_code),
                })
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                if list_code:
                    self.assertNotIn("write:", result.stdout)
                elif not existing:
                    self.assertIn("--draft", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
