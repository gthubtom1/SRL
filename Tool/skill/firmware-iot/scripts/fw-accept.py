#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fw-accept.py -- recompute the firmware-iot case acceptance checks.

For every Tool/cases/firmware-iot*/case.json it verifies:

  * required fields and evidence_kind (fixture | real, at least one real);
  * target_type consistency (fixture words only on fixtures);
  * artifact existence and sha256 recomputation on disk;
  * JSON artifacts are structured (ok:true or an explicit blocked_at);
  * refs point at real files and lessons[0] records the command + rc.

No network, no sample execution. Failures are reported per case, never as a
traceback.

Usage:
  python fw-accept.py
  python fw-accept.py --root . --json
  python fw-accept.py --self-test

Exit codes:
  0  every case passes
  1  at least one case fails a check
  2  blocked (bad root / unreadable case directory)
"""

from __future__ import annotations

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
try:
    from seep_runtime import repo_root as _seep_repo_root
except Exception as _runtime_error:  # noqa: BLE001 - convert missing runtime to JSON
    _seep_repo_root = None
    _RUNTIME_IMPORT_ERROR = type(_runtime_error).__name__
else:
    _RUNTIME_IMPORT_ERROR = ""


import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

VERSION = "1.0.0"
FIELDS = ("id", "domain", "target_type", "evidence_kind", "protection",
          "authority", "goal_level", "outcome", "artifacts", "lessons",
          "refs", "updated")
FIXTURE_WORDS = ("夹具", "教学", "fixture", "示例")
# public = 公开可分发的真实产物（教学靶场 / CTF / 公开 crackme / MIT 示例）：
# 它的 target_type **本来就该**写「公开教学靶场 XXX」。判夹具字样前先剥掉公开来源词，
# 否则真实公开样本会被逼回 fixture（另一个方向的假话）。语义见 domain_spec.EVIDENCE_KINDS。
PUBLIC_MARKERS = ("公开教学靶场", "公开", "靶场", "CTF", "crackme", "MIT", "github", "public")


def _within(base, target):
    try:
        base_real = os.path.realpath(os.path.abspath(base))
        target_real = os.path.realpath(os.path.abspath(target))
        return os.path.commonpath((base_real, target_real)) == base_real
    except (OSError, TypeError, ValueError):
        return False


def _confined_path(base, value):
    if not isinstance(value, str) or not value.strip() or os.path.isabs(value):
        return None
    candidate = os.path.abspath(os.path.join(os.path.abspath(base), value))
    return candidate if _within(base, candidate) else None


def _fixture_words(target_type, kind=""):
    t = str(target_type or "")
    if str(kind or "").strip().lower() == "public":
        for w in PUBLIC_MARKERS:
            t = t.replace(w, "")
    return [w for w in FIXTURE_WORDS if w in t]


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path, root):
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return path


def validate_case(case_dir, root):
    case_dir = os.path.abspath(case_dir)
    errors = []
    warnings = []
    cases_root = os.path.join(os.path.abspath(root), "Tool", "cases")
    if not _within(cases_root, case_dir):
        return {"case": rel(case_dir, root), "id": None, "ok": False,
                "errors": ["case directory escapes root Tool/cases"], "warnings": []}
    case_file = os.path.join(case_dir, "case.json")
    if not _within(case_dir, case_file):
        return {"case": rel(case_dir, root), "id": None, "ok": False,
                "errors": ["case.json escapes its case directory"], "warnings": []}
    if not os.path.isfile(case_file):
        return {"case": rel(case_dir, root), "id": None, "ok": False,
                "errors": ["missing case.json"], "warnings": []}
    try:
        with open(case_file, encoding="utf-8-sig") as fh:
            case = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        return {"case": rel(case_dir, root), "id": None, "ok": False,
                "errors": ["bad case.json: %s" % str(exc)[:120]], "warnings": []}
    if not isinstance(case, dict):
        return {"case": rel(case_dir, root), "id": None, "ok": False,
                "errors": ["case.json root must be a JSON object"], "warnings": []}

    cid = case.get("id")
    for key in FIELDS:
        if key not in case:
            errors.append("missing field: %s" % key)
    if case.get("domain") != "firmware-iot":
        errors.append("domain is %r, expected firmware-iot" % case.get("domain"))
    if cid and os.path.basename(case_dir) != cid:
        warnings.append("directory %s != id %s" % (os.path.basename(case_dir), cid))

    kind = case.get("evidence_kind")
    target = str(case.get("target_type") or "")
    fixture_words = _fixture_words(target, kind)
    if kind not in ("fixture", "real", "public", "self-built", "historical"):
        errors.append("evidence_kind=%r" % kind)
    elif kind == "fixture" and not fixture_words:
        errors.append("fixture case target_type lacks a fixture marker")
    elif kind in ("real", "public", "self-built") and fixture_words:
        errors.append("real case target_type contains fixture word(s): %s" % ",".join(fixture_words))

    if case.get("outcome") == "planned":
        errors.append("outcome=planned is not allowed in cases/ (move it to ROADMAP)")
    lessons = case.get("lessons") or []
    if not lessons:
        errors.append("lessons is empty")
    elif "rc=" not in str(lessons[0]):
        errors.append("lessons[0] does not record the command rc=")

    artifacts = case.get("artifacts") or []
    if not artifacts:
        errors.append("no artifacts")
    for art in artifacts:
        if not isinstance(art, dict):
            errors.append("artifact entry is not an object")
            continue
        apath = art.get("path")
        want = str(art.get("sha256") or "").lower()
        full = _confined_path(case_dir, apath)
        if full is None:
            errors.append("artifact path escapes case directory: %s" % (apath or "<empty>"))
            continue
        if not os.path.isfile(full):
            errors.append("missing artifact: %s" % (apath or "<empty>"))
            continue
        if re.fullmatch(r"[0-9a-f]{64}", want) is None:
            errors.append("artifact %s has no 64-hex sha256" % apath)
        else:
            try:
                got = sha256_file(full)
            except OSError as exc:
                errors.append("artifact %s is unreadable: %s" % (apath, type(exc).__name__))
            else:
                if got != want:
                    errors.append("artifact %s sha256 mismatch (recomputed %s)" % (apath, got[:12]))
        if apath.lower().endswith(".json"):
            try:
                with open(full, encoding="utf-8-sig") as fh:
                    payload = json.load(fh)
            except Exception as exc:  # noqa: BLE001
                errors.append("artifact %s is not valid JSON: %s" % (apath, str(exc)[:80]))
                continue
            if not isinstance(payload, dict):
                errors.append("artifact %s is not a JSON object" % apath)
            elif payload.get("ok") is not True and not payload.get("blocked_at"):
                errors.append("artifact %s has neither ok:true nor blocked_at" % apath)

    for ref in case.get("refs") or []:
        if not isinstance(ref, str):
            errors.append("ref entry is not a string")
            continue
        if "://" in ref:
            continue
        full_ref = _confined_path(root, ref)
        if full_ref is None:
            errors.append("ref escapes repository root: %s" % ref)
        elif not os.path.isfile(full_ref):
            errors.append("phantom ref: %s" % ref)

    return {"case": rel(case_dir, root), "id": cid, "evidence_kind": kind,
            "ok": not errors, "errors": errors, "warnings": warnings}


def accept(root, only=None):
    pattern = os.path.join(root, "Tool", "cases", "firmware-iot*")
    dirs = sorted(x for x in glob.glob(pattern) if os.path.isdir(x))
    if only:
        dirs = [d for d in dirs if os.path.basename(d) == only]
    results = [validate_case(d, root) for d in dirs]
    real = sum(1 for r in results if r.get("evidence_kind") in ("real", "self-built"))
    errors = []
    if len(results) < 3:
        errors.append("only %d cases (need 3-7，S5 真实目标会新增案例)" % len(results))
    if len(results) > 7:   # 与 domain_spec.LIMITS["cases_max"] 同步（S5 会为真实目标新增案例）
        errors.append("%d cases (need 3-7)" % len(results))
    if real < 1:
        errors.append("no evidence_kind=real case")
    failed = [r for r in results if not r["ok"]]
    checks = len(results) * 8
    ok = not errors and not failed
    summary = {
        "tool": "fw-accept", "version": VERSION, "ok": ok,
        "root": root, "cases": len(results), "real": real, "checks": checks,
        "summary_errors": errors, "results": results,
    }
    if not ok:
        summary["blocked_at"] = "case-validation"
        summary["reason"] = "one or more cases failed field/hash/ref/lesson checks"
    return summary


def self_test():
    checks = 0
    tmp = tempfile.mkdtemp(prefix="fw-accept-selftest-")
    try:
        case_dir = os.path.join(tmp, "Tool", "cases", "firmware-iot99")
        art_dir = os.path.join(case_dir, "artifacts")
        os.makedirs(art_dir)
        ref_dir = os.path.join(tmp, "Tool", "skill", "firmware-iot", "references")
        os.makedirs(ref_dir)
        with open(os.path.join(ref_dir, "01-criteria.md"), "w", encoding="utf-8") as fh:
            fh.write("# criteria\n")
        artifact = os.path.join(art_dir, "run.json")
        with open(artifact, "w", encoding="utf-8") as fh:
            json.dump({"ok": True, "tool": "fw-triage", "sha256": "0" * 64}, fh)
        digest = sha256_file(artifact)
        case = {
            "id": "firmware-iot99", "domain": "firmware-iot",
            "target_type": "离线夹具：合成 OTA 包", "evidence_kind": "fixture",
            "protection": [], "authority": "local", "goal_level": "J2",
            "outcome": "confirmed",
            "artifacts": [{"path": "artifacts/run.json", "sha256": digest}],
            "lessons": ["ran python fw-triage.py --file x, rc=0"],
            "refs": ["Tool/skill/firmware-iot/references/01-criteria.md"],
            "updated": "2026-10-21",
        }
        with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(case, fh, ensure_ascii=False)
        # 1) a valid fixture case passes
        root = os.path.join(tmp, "Tool", "..")
        good = validate_case(case_dir, tmp)
        assert good["ok"] is True, good["errors"]
        checks += 1
        # 2) tampering with the artifact is detected
        with open(artifact, "ab") as fh:
            fh.write(b" ")
        bad = validate_case(case_dir, tmp)
        assert bad["ok"] is False and any("sha256 mismatch" in e for e in bad["errors"])
        checks += 1
        # 3) fixture target_type must carry a fixture marker
        case["target_type"] = "real router firmware"
        case["evidence_kind"] = "fixture"
        with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(case, fh, ensure_ascii=False)
        mismatch = validate_case(case_dir, tmp)
        assert any("fixture marker" in e for e in mismatch["errors"])
        checks += 1
        # 4) phantom refs are detected
        case["target_type"] = "离线夹具：合成 OTA 包"
        case["refs"] = ["Tool/skill/firmware-iot/references/nope.md"]
        with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(case, fh, ensure_ascii=False)
        phantom = validate_case(case_dir, tmp)
        assert any("phantom ref" in e for e in phantom["errors"])
        checks += 1
        # 5) missing rc in lessons[0] is detected
        case["refs"] = []
        case["lessons"] = ["looked at it"]
        with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(case, fh, ensure_ascii=False)
        norc = validate_case(case_dir, tmp)
        assert any("rc=" in e for e in norc["errors"])
        checks += 1
        # 6) accept() enforces the at-least-one-real rule on the synthetic root
        summary = accept(tmp)
        assert summary["ok"] is False and summary["real"] == 0
        checks += 1
        # 7) malformed roots fail closed instead of raising AttributeError
        malformed_dir = os.path.join(tmp, "Tool", "cases", "firmware-iot98")
        os.makedirs(malformed_dir, exist_ok=True)
        with open(os.path.join(malformed_dir, "case.json"), "w", encoding="utf-8") as fh:
            fh.write("[]")
        malformed = validate_case(malformed_dir, tmp)
        assert malformed["ok"] is False and "JSON object" in malformed["errors"][0]
        checks += 1
        # 8) artifact/ref paths cannot escape their trusted roots
        outside = os.path.join(tmp, "outside.json")
        with open(outside, "w", encoding="utf-8") as fh:
            fh.write('{"ok": true}')
        escaped = dict(case)
        escaped["lessons"] = ["ran tool, rc=0"]
        escaped["refs"] = ["../../outside.json"]
        escaped["artifacts"] = [{"path": "../../../outside.json", "sha256": sha256_file(outside)}]
        with open(os.path.join(case_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(escaped, fh, ensure_ascii=False)
        confinement = validate_case(case_dir, tmp)
        assert any("artifact path escapes" in e for e in confinement["errors"])
        assert any("ref escapes" in e for e in confinement["errors"])
        checks += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(json.dumps({"ok": True, "tool": "fw-accept", "version": VERSION,
                      "checks": checks}, ensure_ascii=False))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Recompute firmware-iot case acceptance (fields, hashes, refs, lessons).")
    parser.add_argument("--root", default=None,
                        help="repository root (default: derived from this file)")
    parser.add_argument("--case", default=None,
                        help="only validate Tool/cases/<case> (directory name)")
    parser.add_argument("--json", action="store_true", help="emit one JSON object")
    parser.add_argument("--self-test", action="store_true",
                        help="run built-in offline checks and exit")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.root:
        root = os.path.abspath(args.root)
    elif _seep_repo_root is not None:
        root = _seep_repo_root(__file__)
    else:
        root = ""
        for parent in Path(__file__).resolve().parents:
            if (parent / "Tool" / "cases").is_dir():
                root = str(parent)
                break
        if not root:
            print(json.dumps({"ok": False, "blocked_at": "runtime_missing",
                              "reason": "softseep runtime is not importable (%s); "
                                        "use --root or reinstall it" % _RUNTIME_IMPORT_ERROR},
                             ensure_ascii=False))
            return 2
    if not os.path.isdir(os.path.join(root, "Tool", "cases")):
        print(json.dumps({"ok": False, "blocked_at": "input",
                          "reason": "no Tool/cases under root: %s" % root},
                         ensure_ascii=False))
        return 2

    summary = accept(root, args.case)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("fw-accept %s  %s" % (VERSION, summary["root"]))
        for item in summary["results"]:
            print("[%s] %-22s %s" % ("PASS" if item["ok"] else "FAIL",
                                     item["id"] or item["case"],
                                     item.get("evidence_kind") or "-"))
            for err in item["errors"]:
                print("       - " + err)
            for warn in item["warnings"]:
                print("       ~ " + warn)
        for err in summary["summary_errors"]:
            print("[FAIL] " + err)
        print("cases=%d real=%d ok=%s" % (summary["cases"], summary["real"], summary["ok"]))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
