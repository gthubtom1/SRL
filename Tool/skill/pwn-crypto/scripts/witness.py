#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pwn-crypto witness: analyse a published PE and assert protection/route fields.

Used by Tool/skill/pwn-crypto/pack.json `witness_tool`. Exit 0 only when
pwn-check.py exits 0 AND the JSON proves binary parsing plus exploit-surface
analysis: kind == PE, a populated `protections` map (NX/PIE/Canary), non-empty
sections, dangerous imports and a suggested route. An empty file exits 2.

Default target is the published artifact of `Tool/cases/pwn-crypto07`
(justinsteven/dostackbufferoverflowgood.exe, Apache-2.0, released by its author).
The witness does not just name that file: it also requires the sha256 that
pwn-check reports to equal the sha256 registered in the case's own
`case.json` `target_files[]` entry for exactly that target path. Renaming a
different binary into `target/` therefore cannot pass, and the emitted
`artifact_kind` is read from `case.json` (`public`/`real`/...) instead of being
hardcoded to "real-target" for whatever file happened to be analysed.

The target is only ever read as bytes: it is never started, loaded, debugged or
executed as a process.

Negative-test knobs (they only change *which input* is analysed, never the
assertions or their thresholds):
    --target PATH       analyse another file (its sha256 will not match the
                        registered manifest hash, so this is the "swapped
                        target" negative case; artifact_kind is reported as
                        "overridden", never as public/real)
    --case-dir DIR      take the manifest hash from another case.json (used to
                        prove that a tampered manifest is rejected)
    --check-tool PATH   run another copy of pwn-check.py (used so the staged
                        copy of this script can be exercised against the
                        byte-identical fixture before merge)
"""
from __future__ import annotations

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
from seep_runtime import repo_root as _seep_repo_root


import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = _seep_repo_root(__file__)
CASE_DIR = "Tool/cases/pwn-crypto07"
TARGET_REL = "target/dostackbufferoverflowgood.exe"
TOOL = os.path.join(HERE, "pwn-check.py")


def fail(msg):
    print("[witness] pwn-crypto FAIL: " + msg)
    return 1


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_expectation(case_dir, target_rel):
    """(expected_sha256, evidence_kind) from the case's own case.json.

    Returns (None, kind) when the manifest does not register that target, so the
    caller can refuse instead of silently falling back to "any PE will do".
    """
    cj = os.path.join(case_dir, "case.json")
    try:
        with open(cj, encoding="utf-8") as fh:
            meta = json.load(fh)
    except Exception:
        return None, "unknown"
    kind = str((meta or {}).get("evidence_kind") or "unknown").strip().lower()
    entries = meta.get("target_files") or []
    if isinstance(entries, dict):
        entries = [entries]
    want_rel = target_rel.replace("\\", "/").lstrip("./")
    for item in entries:
        if not isinstance(item, dict):
            continue
        rel = str(item.get("path") or "").replace("\\", "/").lstrip("./")
        sha = str(item.get("sha256") or "").strip().lower()
        if rel == want_rel and re.fullmatch(r"[0-9a-f]{64}", sha):
            return sha, kind
    return None, kind


def main(argv=None):
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--target", default="")
    ap.add_argument("--case-dir", default="")
    ap.add_argument("--check-tool", default="")
    ap.add_argument("--self-test", action="store_true")
    known, _unknown = ap.parse_known_args(argv or sys.argv[1:])

    case_dir = os.path.join(ROOT, known.case_dir) if known.case_dir else os.path.join(ROOT, CASE_DIR)
    target = os.path.abspath(known.target) if known.target else os.path.join(case_dir, TARGET_REL)
    tool = os.path.abspath(known.check_tool) if known.check_tool else TOOL
    overridden = bool(known.target)

    expect_sha, evidence_kind = manifest_expectation(case_dir, TARGET_REL)
    if expect_sha is None:
        return fail("case.json 没有登记 %s 的 sha256（%s）：没有可比对的指纹就不算见证"
                    % (TARGET_REL, os.path.join(case_dir, "case.json")))
    if not os.path.isfile(target):
        return fail("目标不存在：%s" % target)

    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run(
        [sys.executable, tool, "--file", target, "--json"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=110, env=env,
    )
    if r.returncode != 0:
        return fail("pwn-check rc=%d: %s" % (r.returncode, (r.stdout + r.stderr)[-400:]))
    try:
        data = json.loads(r.stdout)
    except Exception as exc:  # noqa: BLE001
        return fail("stdout is not JSON: %s; %s" % (exc, (r.stdout + r.stderr)[-300:]))

    problems = []
    prot = data.get("protections") or {}
    if data.get("kind") != "PE":
        problems.append("kind != PE（得到 %r）" % data.get("kind"))
    if not re.fullmatch(r"[0-9a-f]{64}", str(data.get("sha256") or "")):
        problems.append("sha256 不是 64 位 hex")
    for key in ("NX", "PIE", "Canary", "RELRO"):
        if not str(prot.get(key) or "").strip():
            problems.append("protections.%s 缺失" % key)
    if not (data.get("sections") or []):
        problems.append("sections 为空")
    if not (data.get("dangerous_imports") or []):
        problems.append("dangerous_imports 为空")
    if not (data.get("next_routes") or []):
        problems.append("next_routes 为空")
    # ★ 目标绑定：报告里的 sha256 必须等于本案 manifest 登记的 sha256。
    #   旧的判据只查“是不是 PE 且有保护位”，任何 PE 都能冒充见证；这里把
    #   “分析的是不是那个已发布制品”变成机检条件（阈值未放宽，只加不减）。
    if str(data.get("sha256") or "").strip().lower() != expect_sha:
        problems.append("sha256 与 case.json 登记的制品不一致：期望 %s，实得 %s"
                        % (expect_sha, str(data.get("sha256") or "")[:64]))
    if problems:
        return fail("; ".join(problems))

    artifact_kind = "overridden" if overridden else (evidence_kind or "unknown")
    print("[witness] pwn-crypto ok: kind=%s arch=%s NX=%s PIE=%s Canary=%s sections=%d dangerous=%d routes=%d artifact_kind=%s sha256=%s"
          % (data.get("kind"), data.get("arch"), prot.get("NX"), prot.get("PIE"),
             prot.get("Canary"), len(data.get("sections") or []),
             len(data.get("dangerous_imports") or []), len(data.get("next_routes") or []),
             artifact_kind, data.get("sha256")))
    if known.self_test:
        print(json.dumps({"ok": True, "domain": "pwn-crypto", "witness": artifact_kind,
                          "artifact_kind": artifact_kind, "sha256": data.get("sha256"),
                          "manifest_sha256": expect_sha}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    if "--help" in sys.argv[1:] or "-h" in sys.argv[1:]:
        print(__doc__)
        raise SystemExit(0)
    _selftest = "--self-test" in sys.argv[1:]
    _rc = main()
    if _selftest:
        if _rc != 0:
            print(json.dumps({"ok": False, "domain": "pwn-crypto", "witness": "failed"},
                             ensure_ascii=False))
        _rc = 0 if _rc == 0 else 2
    raise SystemExit(_rc)
