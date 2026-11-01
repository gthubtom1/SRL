"""Optional bounded Windows launch flow, reusing the existing instance observer.

Limits new launch requests, not packets or subsequent GUI actions. A returned
window/process does not resolve the retained operation or prove business success.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from .runtime_risk import RiskError, RiskStore


def _invoke(target, mode, wait_seconds, instance_pid):
    launcher = Path(__file__).resolve().parents[1] / "launch-gui.ps1"
    ps = shutil.which("powershell")
    if not ps:
        raise RiskError("powershell_unavailable")
    args = [ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(launcher),
            "-Target", str(target), "-Mode", mode, "-WaitSeconds", str(wait_seconds), "-Json"]
    if instance_pid:
        args += ["-InstancePid", str(instance_pid)]
    run = subprocess.run(args, capture_output=True, encoding="utf-8-sig", errors="replace",
                         timeout=wait_seconds + 30,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        payload = json.loads(run.stdout)
    except (ValueError, TypeError):
        raise RiskError("launcher_observation_unavailable") from None
    if not isinstance(payload, dict):
        raise RiskError("launcher_observation_unavailable")
    return run.returncode, payload


def launch_flow(target, url, subject_ref, scope_id, wait_seconds=3, instance_pid=0):
    if os.name != "nt":
        raise RiskError("windows_flow_only")
    if type(wait_seconds) is not int or not 0 <= wait_seconds <= 30:
        raise RiskError("invalid_wait_seconds")
    if type(instance_pid) is not int or instance_pid < 0:
        raise RiskError("invalid_instance_pid")
    path = Path(target).expanduser().resolve(strict=True)
    if not path.is_file() or path.suffix.lower() not in {".exe", ".com"}:
        raise RiskError("invalid_executable_target")
    try:
        code, observation = _invoke(path, "attach", 0, instance_pid)
    except (OSError, RiskError, subprocess.SubprocessError):
        return {"ok": False, "error": "existing_instance_observation_unavailable",
                "new_launch_requested": False, "coverage": "flow_only", "network_request_count": None}
    if code == 0 and observation.get("reusedExisting"):
        return {"ok": True, "launch": observation, "new_launch_requested": False,
                "coverage": "observation_only_existing_flow_not_admitted",
                "functionality_verified": False, "network_request_count": None}
    if code != 4 or observation.get("status") != "NOT_FOUND" or not observation.get("observationComplete") or instance_pid:
        return {"ok": False, "error": "resolve_existing_instance_before_launch", "launch": observation,
                "new_launch_requested": False, "coverage": "flow_only", "network_request_count": None}
    store = RiskStore()
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else ""
    if not digest:
        h = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1 << 20), b""):
                h.update(block)
        digest = h.hexdigest()
    fingerprint = store.digest(json.dumps([str(path), digest, "windows-shell-flow"]))
    operation = store.reserve(url, fingerprint, scope_id, subject_ref, required=True)
    store.begin(operation, fingerprint)
    try:
        code, observation = _invoke(path, "shell", wait_seconds, 0)
    except (OSError, RiskError, subprocess.SubprocessError):
        store.finish(operation, "outcome_unknown")
        return {"ok": False, "error": "launch_outcome_unknown", "operation_id": operation,
                "new_launch_requested": None, "coverage": "flow_only", "network_request_count": None}
    # Do not release a lease just because the launcher returned. The target
    # may still send heartbeats, so reconciliation is explicit and never refunds.
    return {"ok": code == 0 and observation.get("launched") is True,
            "launch": observation, "operation_id": operation, "operation_retained": True,
            "new_launch_requested": observation.get("launchRequested"),
            "coverage": "flow_only_not_request_level", "network_request_count": None,
            "functionality_verified": False,
            "next_step": "observe exact instance and reconcile only after checking the old execution chain"}
