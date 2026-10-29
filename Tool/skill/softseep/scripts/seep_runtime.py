"""Locate the shared runtime for source and copied softseep entry points.

The helper is intentionally small: it finds the canonical
``Tool/scripts/lib/runtime_root.py`` implementation, then delegates all trust
checks to that implementation.  Source checkouts resolve from their own
``__file__``; installed skills use ``SEEP_RUNTIME_ROOT`` or the hash-checked
``seep-runtime.json`` registration written by the installer.
"""
from __future__ import annotations

import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
from contextlib import redirect_stdout

ORIGIN_SCHEMA = "seep-runtime-origin/1"
RUNTIME_ID = "seep-reverse-lab/softseep"


def _env_text(env, key: str) -> str:
    return str((os.environ if env is None else env).get(key) or "").strip()


def _source_candidate(script: Path):
    for parent in script.parents:
        if script.is_relative_to(parent / "Tool/skill") \
                and (parent / "Tool/scripts/lib/runtime_root.py").is_file():
            return parent
    return None


def _agent_root(script: Path, env) -> Path:
    configured = (_env_text(env, "PI_CODING_AGENT_DIR")
                  or _env_text(env, "PI_AGENT_DIR"))
    if configured:
        return Path(configured).expanduser().resolve()
    # Installed layout: <agent>/skills/softseep/scripts/<entry>.py
    if len(script.parents) >= 4 and script.parents[2].name == "skills":
        return script.parents[3]
    return (Path.home() / ".pi/agent").resolve()


def _origin_helper_root(agent: Path) -> Path:
    """Find the helper source through a minimally validated origin record.

    The final hash and runtime identity checks still happen inside the canonical
    helper. These early checks only decide which helper file is safe to load.
    """
    origin_path = agent / "seep-runtime.json"
    if not origin_path.is_file():
        raise ValueError("runtime_missing: no runtime-origin registration")
    with origin_path.open("r", encoding="utf-8-sig") as stream:
        data = json.load(stream)
    if not isinstance(data, dict):
        raise ValueError("runtime_mismatch: runtime-origin is not an object")
    if data.get("schema") != ORIGIN_SCHEMA:
        raise ValueError("runtime_mismatch: unexpected runtime-origin schema")
    if data.get("runtime_id") not in (None, RUNTIME_ID):
        raise ValueError("runtime_mismatch: runtime-origin belongs to another runtime")
    source = data.get("source_root")
    if isinstance(source, str) and source.strip():
        return Path(source).expanduser().resolve()
    relative = data.get("relative_root")
    if not isinstance(relative, str) or not relative.strip():
        raise ValueError("runtime_missing: no registered root")
    relative_path = Path(relative.replace("\\", "/"))
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError("runtime_mismatch: relative root escapes agent")
    return (agent / relative_path).resolve()


def _load_helper(path: Path):
    if not path.is_file():
        raise ValueError("runtime_missing: runtime helper not present")
    spec = importlib.util.spec_from_file_location("_seep_skill_runtime_root", path)
    if spec is None or spec.loader is None:
        raise ValueError("runtime_mismatch: runtime helper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def repo_root(script_path, env=None) -> str:
    """Return one verified public runtime root or fail with JSON."""
    try:
        script = Path(script_path).resolve()
        explicit = _env_text(env, "SEEP_RUNTIME_ROOT")
        source = _source_candidate(script)
        agent = _agent_root(script, env)
        if explicit:
            helper_root = Path(explicit).expanduser().resolve()
        elif source is not None:
            helper_root = source
        else:
            helper_root = _origin_helper_root(agent)
        helper = _load_helper(helper_root / "Tool/scripts/lib/runtime_root.py")
        result = helper.resolve_runtime_root(
            explicit_runtime=explicit or None,
            source_candidate=source if not explicit else None,
            script_path=script,
            agent_root=agent,
            env=os.environ if env is None else env,
        )
        return result["runtime_root"]
    except Exception as exc:
        code = getattr(exc, "code", "runtime_missing")
        if isinstance(exc, ValueError) and str(exc).startswith("runtime_mismatch:"):
            code = "runtime_mismatch"
        print(json.dumps({
            "ok": False,
            "blocked_at": code,
            "reason": "技能运行目录缺失或注册失效",
            "hint": "重新运行安装器，或设置 SEEP_RUNTIME_ROOT 指向有效源码目录",
        }, ensure_ascii=True))
        raise SystemExit(2)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _make_runtime_fixture(root: Path, helper_source: Path) -> None:
    (root / "Tool/cases").mkdir(parents=True, exist_ok=True)
    _write(root / "VERSION", "selftest\n")
    _write(root / "Tool/scripts/lib/project_lock.py",
           "def project_lock(): pass\n"
           "def project_file(): pass\n"
           "def verify_file(): pass\n"
           "def atomic_copy(): pass\n")
    _write(root / "Tool/scripts/lib/project_transaction.py",
           "def file_transaction(): pass\n")
    _write(root / "Tool/skill/softseep/pack.json", json.dumps({
        "schema": "seep.pack/1",
        "id": "softseep",
        "version_contract": {
            "reverse_migration": "Tool/skill/softseep/scripts/version-migrate.py",
        },
    }, ensure_ascii=False, indent=2) + "\n")
    _write(root / "Tool/skill/softseep/scripts/version-migrate.py",
           "import lib.project_lock  # runtime marker\n")
    helper_target = root / "Tool/scripts/lib/runtime_root.py"
    helper_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(helper_source, helper_target)


def self_test() -> dict:
    """Exercise source, env, registration, and tamper-detection branches."""
    checks = 0
    failures = []

    def check(label, condition):
        nonlocal checks
        checks += 1
        if not condition:
            failures.append(label)

    source_helper = None
    current = Path(__file__).resolve()
    for parent in current.parents:
        candidate = parent / "Tool/scripts/lib/runtime_root.py"
        if candidate.is_file():
            source_helper = candidate
            break
    if source_helper is None:
        try:
            source_helper = (Path(repo_root(current, env=os.environ))
                             / "Tool/scripts/lib/runtime_root.py")
        except SystemExit:
            source_helper = None

    check("canonical runtime helper is available",
          bool(source_helper and source_helper.is_file()))
    if not source_helper or not source_helper.is_file():
        return {"ok": False, "tool": "seep_runtime.py", "checks": checks,
                "failures": failures}

    with tempfile.TemporaryDirectory(prefix="seep-runtime-selftest-") as tmp:
        base = Path(tmp)
        runtime = base / "runtime"
        agent = base / "agent"
        _make_runtime_fixture(runtime, source_helper)
        source_entry = runtime / "Tool/skill/softseep/scripts/intent-coverage.py"
        installed_entry = agent / "skills/softseep/scripts/intent-coverage.py"
        _write(source_entry, "# fixture\n")
        _write(installed_entry, "# fixture\n")

        helper = _load_helper(runtime / "Tool/scripts/lib/runtime_root.py")
        origin = helper.make_registration(runtime, agent)
        origin_path = agent / "seep-runtime.json"
        _write(origin_path, json.dumps(origin, ensure_ascii=False, indent=2) + "\n")
        agent_env = {"PI_CODING_AGENT_DIR": str(agent)}

        check("source checkout resolves from repository markers",
              Path(repo_root(source_entry, env=agent_env)).resolve() == runtime.resolve())

        env_root = dict(agent_env)
        env_root["SEEP_RUNTIME_ROOT"] = str(runtime)
        check("installed copy honors the explicit runtime environment",
              Path(repo_root(installed_entry, env=env_root)).resolve() == runtime.resolve())

        check("installed copy validates the runtime-origin registration",
              Path(repo_root(installed_entry, env=agent_env)).resolve() == runtime.resolve())

        tampered = json.loads(json.dumps(origin))
        first_key = sorted(tampered["entry_sha256"])[0]
        tampered["entry_sha256"][first_key] = "0" * 64
        _write(origin_path, json.dumps(tampered, ensure_ascii=False, indent=2) + "\n")
        output = io.StringIO()
        caught = False
        try:
            with redirect_stdout(output):
                repo_root(installed_entry, env=agent_env)
        except SystemExit as exc:
            caught = exc.code == 2
        check("registration hash drift is rejected", caught
              and '"blocked_at": "runtime_mismatch"' in output.getvalue())

    return {
        "ok": not failures,
        "tool": "seep_runtime.py",
        "checks": checks,
        "failures": failures,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Locate and verify the Seep runtime root; also provides a self-test.")
    parser.add_argument("--root", nargs="?", default="",
                        help="entry script path to inspect (default: this file)")
    parser.add_argument("--self-test", action="store_true",
                        help="run isolated source/env/registration/tamper tests")
    args = parser.parse_args(argv)
    if args.self_test:
        result = self_test()
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["ok"] else 2
    if args.root:
        print(json.dumps({"ok": True, "runtime_root": repo_root(args.root)},
                         ensure_ascii=False))
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
