"""Case replay capture and verification.

Command text is a target-reference heuristic, not proof that a process read a
file or that two commands use independent implementations. Captures prove the
recorded exit codes and normalized UTF-8 stdout/stderr, with local integrity
checks; the user's acceptance criteria still determine semantic correctness.
"""
from __future__ import annotations

import hashlib
import functools
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import uuid

from .project_lock import project_file, project_lock
from .project_transaction import file_transaction, pending
from .typed_assets import file_identity

SCHEMA = "seep-case-repro/2"
LOG_SCHEMA = "seep-case-repro-output/1"
SHA = re.compile(r"[0-9a-f]{64}\Z")


def _plain(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        try:
            mode = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode.st_mode) or getattr(mode, "st_file_attributes", 0) & 1024:
            raise ValueError("repro path must not traverse a symlink/reparse point")
    return path


def _local(root: Path, reference: str) -> Path:
    if not isinstance(reference, str) or "\x00" in reference:
        raise ValueError("invalid repro file reference")
    return _plain(project_file(root, reference))


def case_locked(function):
    """Validate the case boundary before creating its shared OS lock file."""
    @functools.wraps(function)
    def invoke(args):
        try:
            root = _plain(Path(args.case))
            if not root.is_dir():
                raise ValueError("case directory is missing")
            with project_lock(root):
                return function(args)
        except (OSError, ValueError, TypeError, TimeoutError) as exc:
            print("[ERR] case operation refused: %s" % exc)
            return 2
    return invoke


def target_identity(case, fallback="") -> dict:
    """Verify registered local bytes; a URL identity covers the reference only."""
    root = _plain(Path(case))
    metadata = _local(root, "case.json")
    registered = {}
    if metadata.exists():
        data = json.loads(metadata.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("target"), (dict, str)):
            raise ValueError("invalid case target metadata")
        registered = data["target"]
    if isinstance(registered, str):
        registered = {"path": registered}
    path = registered.get("path") or fallback
    if not isinstance(path, str) or not path.strip():
        raise ValueError("case target path is missing")
    if re.match(r"^https?://", path, re.I):
        payload = path.encode("utf-8")
        return {"path": path, "name": path, "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload), "identity_scope": "url-reference-only"}
    source = _plain(Path(path))
    actual = file_identity(source.parent, source.name)
    sha, size = registered.get("sha256"), registered.get("size")
    if sha is not None and sha != "":
        if not isinstance(sha, str) or not SHA.fullmatch(sha.lower()) or sha.lower() != actual["sha256"]:
            raise ValueError("registered target sha256 does not match current bytes")
    if size is not None and (type(size) is not int or size != actual["size"]):
        raise ValueError("registered target size does not match current bytes")
    return {"path": str(source), "name": source.name, "sha256": actual["sha256"],
            "size": actual["size"], "identity_scope": "file-bytes"}


def _identity_ok(info):
    return (isinstance(info, dict) and isinstance(info.get("path"), str) and bool(info["path"])
            and isinstance(info.get("sha256"), str) and bool(SHA.fullmatch(info["sha256"]))
            and type(info.get("size")) is int and info["size"] >= 0
            and info.get("identity_scope") in ("file-bytes", "url-reference-only"))


def _same_target(left, right):
    return _identity_ok(left) and _identity_ok(right) and all(
        left[key] == right[key] for key in ("path", "sha256", "size", "identity_scope"))


def _output_digest(stdout, stderr):
    # Preserve stream boundaries; concatenating stdout+stderr creates collisions.
    payload = json.dumps([stdout, stderr], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _route_ok(row, prefix=""):
    runs = row.get("runs")
    if type(runs) is not int or runs < 2:
        return False
    digests, codes = row.get(prefix + "digests"), row.get(prefix + "returncodes")
    return (isinstance(digests, list) and len(digests) == runs
            and all(isinstance(d, str) and SHA.fullmatch(d) for d in digests)
            and len(set(digests)) == 1
            and isinstance(codes, list) and len(codes) == runs
            and all(type(code) is int and code == 0 for code in codes)
            and row.get(prefix + "consistent") is True and row.get(prefix + "expect_ok") is True)


def complete_record(row, *, binder, target=None, case=None, cross=False):
    """Structure alone is not execution proof; delivery also verifies each capture."""
    if not isinstance(row, dict) or row.get("schema") != SCHEMA or row.get("kind") != "repro":
        return False
    if row.get("grade") not in (("E3",) if cross else ("E2", "E3")):
        return False
    info = row.get("target")
    if not _identity_ok(info) or target is not None and not _same_target(info, target):
        return False
    cmd, expect = row.get("cmd"), row.get("expect")
    if not isinstance(cmd, str) or not cmd.strip() or not isinstance(expect, str) or not expect.strip():
        return False
    if not _route_ok(row) or not binder(cmd, info):
        return False
    if cross:
        also = row.get("also_cmd")
        if (not isinstance(also, str) or not also.strip()
                or " ".join(also.split()) == " ".join(cmd.split())
                or not binder(also, info) or not _route_ok(row, "also_")):
            return False
    if case is not None:
        try:
            _verify_captures(Path(case), row, cross, target)
        except (OSError, ValueError, TypeError, KeyError, IndexError):
            return False
    return True


def _verify_captures(root, row, cross, current_target=None):
    root = _plain(root)
    if pending(root):
        raise ValueError("interrupted replay transaction requires recovery")
    fallback = current_target.get("path", "") if isinstance(current_target, dict) else ""
    if not _same_target(row["target"], target_identity(root, fallback)):
        raise ValueError("target changed since replay")
    artifacts = row.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("missing replay output captures")
    seen, paths = set(), set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("invalid replay output capture")
        route, run = artifact.get("route"), artifact.get("run")
        if route not in ("primary", "secondary") or type(run) is not int or not 1 <= run <= row["runs"]:
            raise ValueError("invalid replay route/run")
        key = (route, run)
        path = _local(root, artifact["path"])
        if key in seen or os.path.normcase(str(path)) in paths:
            raise ValueError("duplicate replay output capture")
        seen.add(key)
        paths.add(os.path.normcase(str(path)))
        actual = file_identity(root, artifact["path"])
        if (type(artifact.get("size")) is not int or artifact["size"] != actual["size"]
                or artifact.get("sha256") != actual["sha256"]):
            raise ValueError("replay capture fingerprint changed")
        log = json.loads(path.read_text(encoding="utf-8"))
        prefix = "also_" if route == "secondary" else ""
        if (not isinstance(log, dict) or log.get("schema") != LOG_SCHEMA
                or log.get("route") != route or log.get("run") != run
                or log.get("cmd") != row["also_cmd" if prefix else "cmd"]
                or log.get("expect") != row["expect"]
                or type(log.get("returncode")) is not int
                or not isinstance(log.get("stdout"), str) or not isinstance(log.get("stderr"), str)
                or log["returncode"] != row[prefix + "returncodes"][run - 1]
                or _output_digest(log["stdout"], log["stderr"]) != row[prefix + "digests"][run - 1]):
            raise ValueError("replay capture does not match record")
        # Failed optional secondary runs cannot invalidate a valid primary route.
        if (route == "primary" or cross) and (log["returncode"] != 0
                or row["expect"] not in log["stdout"] + log["stderr"]):
            raise ValueError("replay capture did not meet expectations")
    required = {(route, run) for route in (("primary", "secondary") if cross else ("primary",))
                for run in range(1, row["runs"] + 1)}
    if not required.issubset(seen):
        raise ValueError("missing replay output capture")


def _ledger(root, api, identifier):
    _local(root, "facts.jsonl")
    rows = api.load_ledger(str(root))
    ids = set()
    for row in rows:
        if not isinstance(row, dict) or "kind" in row and not isinstance(row["kind"], str):
            raise ValueError("invalid case ledger row")
        if api._entry_kind(row) == "repro":
            key = row.get("id")
            if not isinstance(key, str) or not key.strip() or key in ids:
                raise ValueError("invalid/duplicate replay record id")
            ids.add(key)
    if identifier in ids:
        raise ValueError("replay id already exists; use a new id to preserve history")


def run_repro(args, api):
    """Execute outside the commit lock; recheck identity before atomic registration."""
    case = str(args.case or "").strip()
    try:
        root = _plain(Path(case)) if case else None
        if not isinstance(args.cmd, str) or not args.cmd.strip():
            raise ValueError("--cmd is required")
        if type(args.runs) is not int or args.runs < 1 or type(args.timeout) is not int or args.timeout < 1:
            raise ValueError("--runs and --timeout must be positive integers")
        identifier = str(args.id or "")
        if case and not re.fullmatch(r"[A-Za-z0-9_.-]+", identifier):
            raise ValueError("--case requires a nonempty --id containing letters, digits, ._- only")
        if not case and args.out:
            raise ValueError("--out requires --case")
        out = None
        if case:
            if not root.is_dir():
                raise ValueError("case directory is missing")
            with project_lock(root, recover=True):
                api.lease_guard(case)
                _ledger(root, api, identifier)
                target = target_identity(root, api.load_state(case).get("target", ""))
                problem = api._cmd_evidence_problem(args.cmd, target)
                if problem:
                    raise ValueError(problem)
                out = Path(os.path.abspath(args.out)) if args.out else root / "capture" / "repro"
                out = _local(root, out.relative_to(root).as_posix())
                if out.exists() and not out.is_dir():
                    raise ValueError("repro output path is not a directory")
        else:
            target = {}
            print("[ADHOC] 未绑目标，不得用于交付")
        row = {"schema": SCHEMA, "kind": "repro", "id": identifier, "cmd": args.cmd,
               "also_cmd": str(args.also_cmd or "").strip(), "expect": args.expect,
               "runs": args.runs, "target": target, "grade": "E1", "ts": api.now(),
               "artifacts": [], "env": {"python": platform.python_version(),
                                        "os": platform.platform(), "cwd": os.getcwd()}}
        captures = []
        for route, prefix, command in (("primary", "", args.cmd), ("secondary", "also_", row["also_cmd"])):
            row[prefix + "digests"], row[prefix + "returncodes"] = [], []
            row[prefix + "consistent"], row[prefix + "expect_ok"] = False, False
            if not command:
                continue
            if route == "secondary" and (" ".join(command.split()) == " ".join(args.cmd.split())
                    or case and not api._cmd_binds_target(command, target)):
                continue
            outputs = []
            for run in range(1, args.runs + 1):
                result = subprocess.run(command, shell=True, capture_output=True, text=True,
                                        encoding="utf-8", errors="replace", timeout=args.timeout)
                stdout, stderr = result.stdout or "", result.stderr or ""
                row[prefix + "digests"].append(_output_digest(stdout, stderr))
                row[prefix + "returncodes"].append(result.returncode)
                outputs.append(stdout + stderr)
                captures.append({"schema": LOG_SCHEMA, "route": route, "run": run,
                                 "cmd": command, "expect": args.expect, "returncode": result.returncode,
                                 "stdout": stdout, "stderr": stderr})
            row[prefix + "consistent"] = len(set(row[prefix + "digests"])) == 1
            row[prefix + "expect_ok"] = bool(args.expect) and all(args.expect in output for output in outputs)
        if case and _route_ok(row):
            row["grade"] = "E2"
            row["grade"] = "E3"  # The same validator decides promotion and later acceptance.
            if not complete_record(row, binder=api._cmd_binds_target, cross=True):
                row["grade"] = "E2"
        if case:
            with project_lock(root, recover=True):
                api.lease_guard(case)
                _ledger(root, api, identifier)
                if not _same_target(target, target_identity(root, api.load_state(case).get("target", ""))):
                    raise ValueError("case target changed while replay was running")
                batch = uuid.uuid4().hex
                writes = []
                for log in captures:
                    path = out / ("repro-%s-%s-%s-%d.json" % (identifier, batch, log["route"], log["run"]))
                    reference = path.relative_to(root).as_posix()
                    _local(root, reference)
                    body = json.dumps(log, ensure_ascii=False, indent=2) + "\n"
                    row["artifacts"].append({"route": log["route"], "run": log["run"], "path": reference,
                                             "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                                             "size": len(body.encode("utf-8"))})
                    writes.append((path, body))
                refs = [path.relative_to(root).as_posix() for path, _ in writes] + ["facts.jsonl"]
                with file_transaction(root, refs):
                    for path, body in writes:
                        path.parent.mkdir(parents=True, exist_ok=True)
                        api._atomic_write_text(str(path), body)
                    ledger = root / "facts.jsonl"
                    separator = "\n" if ledger.exists() and ledger.stat().st_size and not ledger.read_bytes().endswith(b"\n") else ""
                    api._atomic_append_line(str(ledger), separator + json.dumps(row, ensure_ascii=False))
        print("[repro] grade=%s；runs=%d；primary exits=%s；secondary exits=%s"
              % (row["grade"], row["runs"], row["returncodes"], row["also_returncodes"]))
        return 0 if row["grade"] in ("E2", "E3") else 1
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as exc:
        print("[ERR] repro 未登记：%s" % exc)
        return 2
