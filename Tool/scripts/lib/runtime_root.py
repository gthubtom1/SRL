#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Single source of truth for the agent root and the public runtime root.

Read-only resolution only: nothing in this module creates a directory, writes a
config file or touches a user profile.  Consumers (bootstrap shims, installers,
CLI tools) are expected to delegate here instead of computing their own roots.

Priority (every value is only ever *read*):

``resolve_agent_root``
    explicit argument -> ``PI_CODING_AGENT_DIR`` -> ``PI_AGENT_DIR`` ->
    ``<home>/.pi/agent``.

``resolve_runtime_root``
    explicit ``runtime`` argument -> explicit verified ``source_candidate`` ->
    supported ``SEEP_RUNTIME_ROOT`` -> repo structure proven from
    ``script_path`` -> ``<agent_root>/seep-runtime.json`` registration.

Two different questions, two different answers:

* *Where does the deployment live?*  ``resolve_agent_root`` -- derived from
  user/parent configuration, never guessed.
* *Which code is the public runtime?*  ``resolve_runtime_root`` -- only a root
  that passes ``inspect_runtime`` (public markers, the shared
  ``lib/project_lock.py`` API, the softseep pack binding) is returned.

An explicitly named candidate (``runtime``, ``source_candidate``,
``SEEP_RUNTIME_ROOT``) is *hard*: if it fails verification the call raises
``RuntimeRootError`` and **never** silently loads another version.  That is
deliberate -- a caller that names a root has a reason, and a stale lookalike is
worse than an honest ``runtime_missing``.

A caller that is itself running from a valid repo source layout should pass the
root it proved from its own ``__file__`` as ``source_candidate``: a stale
ambient installation registration (written by an older installer run) must not
capture a developer checkout.  When only ``script_path`` is given, the repo
structure proven from that script is preferred over the registration for the
same reason.  Deployed copies keep no repo structure at all, so they fall
through to ``SEEP_RUNTIME_ROOT``/registration -- the only two locators an
installation product is allowed to supply.

``make_registration`` returns *pure data* for a future installer to write to
``<agent_root>/seep-runtime.json``.  It writes nothing itself.  Absolute local
locators are allowed in that install product; source code and distribution
manifests must not hard-code machine paths.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

__all__ = [
    "CASES_REL", "LOCK_REL", "TRANSACTION_REL", "PACK_REL", "SCRIPT_REL", "ORIGIN_FILE",
    "ORIGIN_SCHEMA", "RUNTIME_ID", "RuntimeRootError",
    "resolve_agent_root", "resolve_runtime_root", "resolve_cli_runtime",
    "repo_root_from_script", "inspect_runtime", "make_registration",
    "read_runtime_origin", "runtime_origin_path",
]

CASES_REL = "Tool/cases"
LOCK_REL = "Tool/scripts/lib/project_lock.py"
TRANSACTION_REL = "Tool/scripts/lib/project_transaction.py"
PACK_REL = "Tool/skill/softseep/pack.json"
SCRIPT_REL = "Tool/skill/softseep/scripts/version-migrate.py"
ENV_KEYS = ("PI_CODING_AGENT_DIR", "PI_AGENT_DIR")
RUNTIME_ENV_KEY = "SEEP_RUNTIME_ROOT"
ORIGIN_FILE = "seep-runtime.json"
ORIGIN_SCHEMA = "seep-runtime-origin/1"
RUNTIME_ID = "seep-reverse-lab/softseep"
PACK_SCHEMA = "seep.pack/1"
PACK_ID = "softseep"
#: The shared lock functions deployed scripts must be able to import.
LOCK_API = ("def project_lock", "def project_file", "def verify_file",
            "def atomic_copy")
TRANSACTION_API = ("def file_transaction",)


class RuntimeRootError(Exception):
    """Typed, safe failure: ``code`` is a stable token, ``detail`` is scrubbed."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = _display_text(detail)
        super().__init__("%s: %s" % (code, self.detail) if self.detail else code)

    def as_dict(self) -> dict:
        return {"ok": False, "code": self.code, "detail": self.detail}


def _display_text(value) -> str:
    text = "".join(ch if ch.isprintable() else "?" for ch in str(value or ""))
    return text[:240]


def _as_path(value) -> Path:
    text = str(value).strip()
    if not text or "\x00" in text:
        raise ValueError("unusable path")
    return Path(os.path.abspath(os.path.expanduser(text)))


def _is_fs_root(path: Path) -> bool:
    return path.parent == path


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _read_text(path: Path, limit: int = 1 << 20) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


# --------------------------------------------------------------------------
# agent root
# --------------------------------------------------------------------------
def resolve_agent_root(explicit=None, env=None, home=None) -> Path:
    """Resolve the deployment root. Read-only; never creates the directory."""
    env = os.environ if env is None else env
    home_dir = Path(home) if home is not None else Path(os.path.expanduser("~"))
    if explicit is not None:
        raw, origin = explicit, "explicit argument"
    else:
        raw, origin = None, None
        for key in ENV_KEYS:
            value = str(env.get(key) or "").strip()
            if value:
                raw, origin = value, key
                break
        if raw is None:
            raw, origin = os.path.join(str(home_dir), ".pi", "agent"), "default"
    try:
        path = _as_path(raw)
    except Exception:
        raise RuntimeRootError("agent_root_invalid", "%s is empty or unusable" % origin)
    if _is_fs_root(path):
        raise RuntimeRootError("agent_root_invalid",
                               "filesystem root is not a deployable agent root (%s)" % origin)
    return path


# --------------------------------------------------------------------------
# runtime inspection (shared by every locator)
# --------------------------------------------------------------------------
def _runtime_version(root: Path):
    text = _read_text(root / "VERSION", 256).strip()
    return text or None


def inspect_runtime(root) -> dict:
    """Inspect a candidate root. ``problems`` is empty only for a public runtime."""
    root = Path(root)
    report = {"root": _display_text(root), "problems": [], "runtime_version": None,
              "entry_sha256": {}, "pack_schema": None, "pack_id": None}
    problems = report["problems"]
    if not root.is_dir():
        problems.append(("runtime_missing", "root is not a directory"))
        return report
    if not (root / CASES_REL).is_dir():
        problems.append(("runtime_missing", "missing marker: " + CASES_REL))
    for rel in (LOCK_REL, TRANSACTION_REL, PACK_REL, SCRIPT_REL):
        if not (root / rel).is_file():
            problems.append(("runtime_missing", "missing marker: " + rel))
    lock_text = _read_text(root / LOCK_REL)
    for signature in LOCK_API:
        if signature not in lock_text:
            problems.append(("runtime_missing",
                             "shared lock missing: " + signature[len("def "):]))
    transaction_text = _read_text(root / TRANSACTION_REL)
    for signature in TRANSACTION_API:
        if signature not in transaction_text:
            problems.append(("runtime_missing",
                             "shared transaction missing: " + signature[len("def "):]))
    pack_text = _read_text(root / PACK_REL)
    pack = {}
    if pack_text:
        try:
            pack = json.loads(pack_text)
        except ValueError:
            problems.append(("runtime_mismatch", "pack.json is not valid JSON"))
    elif (root / PACK_REL).is_file():
        problems.append(("runtime_mismatch", "pack.json is unreadable"))
    if isinstance(pack, dict) and pack:
        report["pack_schema"] = pack.get("schema")
        report["pack_id"] = pack.get("id")
        if pack.get("schema") != PACK_SCHEMA or pack.get("id") != PACK_ID:
            problems.append(("runtime_mismatch", "pack identity mismatch"))
        elif (not isinstance(pack.get("version_contract"), dict)
              or pack["version_contract"].get("reverse_migration") != SCRIPT_REL):
            problems.append(("runtime_mismatch",
                             "version_contract does not bind " + SCRIPT_REL))
    elif pack_text:
        problems.append(("runtime_mismatch", "pack.json is an empty object"))
    script_text = _read_text(root / SCRIPT_REL)
    if script_text and "lib.project_lock" not in script_text:
        problems.append(("runtime_mismatch",
                         "entry does not consume the shared lock module"))
    report["runtime_version"] = _runtime_version(root)
    for rel in (SCRIPT_REL, LOCK_REL, TRANSACTION_REL, PACK_REL):
        if (root / rel).is_file():
            report["entry_sha256"][rel] = _digest(root / rel)
    return report


def repo_root_from_script(script_path):
    """Structural repo root of a script, proven by markers (never a layer guess)."""
    start = Path(script_path)
    start = start.parent if start.suffix or start.is_file() else start
    seen = [start] + list(start.parents)[:8]
    for candidate in seen:
        try:
            relative = start.relative_to(candidate)
        except ValueError:
            continue
        # An installed copy may be temporarily nested under a checkout (for
        # example repository-local isolated HOME/TEMP).  Walking past its
        # agent directory would let the enclosing checkout mask the installed
        # runtime registration and its hash checks.
        if not relative.parts or relative.parts[0] != "Tool":
            continue
        if ((candidate / CASES_REL).is_dir()
                and (candidate / LOCK_REL).is_file()
                and (candidate / TRANSACTION_REL).is_file()
                and (candidate / PACK_REL).is_file()
                and (candidate / SCRIPT_REL).is_file()):
            return candidate
    return None


# --------------------------------------------------------------------------
# runtime-origin registration (install product, read-only here)
# --------------------------------------------------------------------------
def runtime_origin_path(agent_root) -> Path:
    return Path(agent_root) / ORIGIN_FILE


def _origin_root(data: dict, agent_root) -> Path:
    source = data.get("source_root")
    if isinstance(source, str) and source.strip():
        try:
            return _as_path(source)
        except ValueError:
            raise RuntimeRootError("runtime_missing", "source_root is unusable")
    relative = data.get("relative_root")
    if isinstance(relative, str) and relative.strip():
        rel = Path(relative.strip().replace("\\", "/"))
        if rel.is_absolute() or ".." in rel.parts:
            raise RuntimeRootError("runtime_mismatch", "relative_root escapes the agent root")
        return Path(agent_root) / rel
    raise RuntimeRootError("runtime_missing", "registration has no source_root/relative_root")


def read_runtime_origin(agent_root):
    """Read and validate ``<agent_root>/seep-runtime.json``; ``None`` if absent."""
    path = runtime_origin_path(agent_root)
    if not path.is_file():
        return None
    text = _read_text(path, 1 << 16)
    try:
        data = json.loads(text)
    except ValueError:
        raise RuntimeRootError("runtime_mismatch", "runtime-origin is not valid JSON")
    if not isinstance(data, dict):
        raise RuntimeRootError("runtime_mismatch", "runtime-origin is not an object")
    if data.get("schema") != ORIGIN_SCHEMA:
        raise RuntimeRootError("runtime_mismatch", "unexpected runtime-origin schema")
    if data.get("runtime_id") not in (None, RUNTIME_ID):
        raise RuntimeRootError("runtime_mismatch", "runtime-origin belongs to another runtime")
    hashes = data.get("entry_sha256") or {}
    if not isinstance(hashes, dict):
        raise RuntimeRootError("runtime_mismatch", "entry_sha256 must be an object")
    return {"path": path, "root": _origin_root(data, agent_root),
            "runtime_id": data.get("runtime_id") or RUNTIME_ID,
            "runtime_version": (data.get("runtime_version") or None),
            "entry_sha256": {str(k): str(v) for k, v in hashes.items()}}


# --------------------------------------------------------------------------
# runtime root
# --------------------------------------------------------------------------
def _result(root: Path, source_kind: str, agent_root: Path, script_path,
            report: dict) -> dict:
    return {"ok": True, "schema": ORIGIN_SCHEMA, "source_kind": source_kind,
            "runtime_id": RUNTIME_ID, "runtime_root": str(root.resolve()),
            "runtime_version": report["runtime_version"],
            "entry_sha256": dict(sorted(report["entry_sha256"].items())),
            "agent_root": str(agent_root),
            "script_path": str(script_path) if script_path else None}


def _accept(root: Path, source_kind: str, agent_root: Path, script_path) -> dict:
    report = inspect_runtime(root)
    if report["problems"]:
        raise RuntimeRootError(*report["problems"][0])
    return _result(root, source_kind, agent_root, script_path, report)


def _accept_registration(origin: dict, agent_root: Path, script_path) -> dict:
    root = origin["root"]
    report = inspect_runtime(root)
    if report["problems"]:
        code, detail = report["problems"][0]
        raise RuntimeRootError(code, "registered runtime: " + detail)
    for rel, recorded in sorted(origin["entry_sha256"].items()):
        actual = report["entry_sha256"].get(rel)
        if actual is None:
            raise RuntimeRootError("runtime_missing", "registered entry is not present: " + rel)
        if actual != recorded:
            raise RuntimeRootError("runtime_mismatch", "registered hash drift: " + rel)
    if origin["runtime_version"] and report["runtime_version"] != origin["runtime_version"]:
        raise RuntimeRootError("runtime_mismatch", "registered runtime version drift")
    return _result(root, "registration", agent_root, script_path, report)


def _named_root(value, label: str) -> Path:
    try:
        return _as_path(value)
    except ValueError:
        raise RuntimeRootError("runtime_missing", label + " is empty or unusable")


def resolve_runtime_root(explicit_runtime=None, source_candidate=None,
                         script_path=None, agent_root=None, env=None) -> dict:
    """Resolve the verified public runtime root (see module docstring)."""
    env = os.environ if env is None else env
    agent = resolve_agent_root(agent_root, env)
    script = None
    if script_path is not None:
        try:
            script = _as_path(script_path)
        except ValueError:
            raise RuntimeRootError("runtime_missing", "script_path is empty or unusable")
    if explicit_runtime is not None:
        return _accept(_named_root(explicit_runtime, "explicit runtime"),
                       "explicit", agent, script)
    if source_candidate is not None:
        return _accept(_named_root(source_candidate, "source candidate"),
                       "source", agent, script)
    env_root = str(env.get(RUNTIME_ENV_KEY) or "").strip()
    if env_root:
        return _accept(_named_root(env_root, RUNTIME_ENV_KEY), "env", agent, script)
    repo = repo_root_from_script(script) if script is not None else None
    if repo is not None:
        return _accept(repo, "repo", agent, script)
    origin = read_runtime_origin(agent)
    if origin is not None:
        return _accept_registration(origin, agent, script)
    raise RuntimeRootError("runtime_missing",
                           "no verified runtime: no SEEP_RUNTIME_ROOT, no repo structure "
                           "at script_path, no runtime-origin registration")


def resolve_cli_runtime(script_path=None, env=None) -> dict:
    """Deployed-copy entry: same helper, locators only (no source_candidate)."""
    return resolve_runtime_root(script_path=script_path, env=env)


# --------------------------------------------------------------------------
# registration data (pure; a future installer writes it)
# --------------------------------------------------------------------------
def _relative_root(root: Path, agent_root) -> str:
    if agent_root is None:
        return ""
    try:
        rel = root.resolve().relative_to(Path(agent_root).resolve())
    except ValueError:
        return ""
    text = rel.as_posix()
    return "" if text in (".", "") else text


def make_registration(runtime_root, agent_root=None, managed=None) -> dict:
    """Return the runtime-origin record for ``runtime_root``; writes nothing."""
    root = _named_root(runtime_root, "runtime_root")
    report = inspect_runtime(root)
    if report["problems"]:
        raise RuntimeRootError(*report["problems"][0])
    return {
        "schema": ORIGIN_SCHEMA,
        "runtime_id": RUNTIME_ID,
        "runtime_version": report["runtime_version"],
        "source_root": str(root.resolve()),
        "relative_root": _relative_root(root, agent_root),
        "entry_sha256": dict(sorted(report["entry_sha256"].items())),
        "ownership": {
            "project": "seep-reverse-lab",
            "managed": sorted(managed or [SCRIPT_REL, LOCK_REL, TRANSACTION_REL, PACK_REL]),
            "config_only": True,
        },
    }
