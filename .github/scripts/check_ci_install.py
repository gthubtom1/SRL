"""Verify deployment and the expected unauthenticated readiness rejection in CI.

This runs the real installer and env-check, without changing their exit semantics.
Only a single, explicit authentication failure is accepted as a negative test;
missing hosts, invalid deployments, bad MCP handshakes and other failures fail CI.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def validate_results(install_code, readiness_code, result, windows=False):
    expected_install_code = 0 if windows else 1
    if install_code != expected_install_code or readiness_code != 1:
        raise ValueError("installer/readiness exit codes do not match the unauthenticated fixture")
    checks = result.get("checks", {})
    auth = checks.get("model_credential", {})
    if (result.get("installed") is not False or auth.get("configured") is not False
            or auth.get("stage") != "host-auth-check" or not auth.get("detail")):
        raise ValueError("expected an explicit unauthenticated result, never fake readiness")
    if result.get("missing") != ["宿主认证未就绪：" + auth["detail"]]:
        raise ValueError("deployment has failures beyond the expected authentication rejection: "
                         + json.dumps(result.get("missing"), ensure_ascii=True))
    if (checks.get("pi") is not True or checks.get("node") is not True
            or checks.get("runtime_registration", {}).get("ok") is not True
            or checks.get("mcp", {}).get("service", {}).get("available") is not True):
        raise ValueError("host, runtime registration and real MCP handshake must pass")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--shell", choices=("bash", "pwsh"), default="pwsh" if os.name == "nt" else "bash")
    args = parser.parse_args()
    agent = Path(os.environ["PI_CODING_AGENT_DIR"]).resolve()
    home = Path(os.environ["SEEP_CI_HOME"]).resolve()
    # An empty, explicit CI root is essential: never inspect a user's credentials.
    if agent == home or agent == ROOT or any(agent.iterdir()):
        raise ValueError("CI AgentRoot must be an empty, dedicated directory")
    windows = args.shell == "pwsh"
    if windows:
        command = ["pwsh", "-NoProfile", "-NonInteractive", "-File",
                   str(ROOT / "setup/install-pi.ps1"), "-AgentRoot", str(agent), "-SkipPackages"]
    else:
        command = ["bash", "setup/install.sh", "--agent-root", str(agent), "--skip-packages"]
    install = subprocess.run(command, cwd=ROOT, timeout=300)
    readiness = subprocess.run([sys.executable, "-B", "-X", "utf8", "Tool/scripts/env-check.py"],
                               cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=90)
    result = json.loads(readiness.stdout)
    validate_results(install.returncode, readiness.returncode, result, windows)
    print("PASS: deployed files, Pi/Node, runtime registration and real MCP handshake verified")
    print("PASS: unauthenticated installation remains not ready; no user credentials required by source CI")


if __name__ == "__main__":
    main()
