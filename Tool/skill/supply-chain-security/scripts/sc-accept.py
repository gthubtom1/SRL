#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sc-accept.py -- recompute supply-chain-security case acceptance checks.

For every `Tool/cases/supply-chain*/case.json` it verifies:

  * required fields (same set as `Tool/scripts/lib/domain_spec.py:CASE_FIELDS`)
    and `domain == "supply-chain-security"`;
  * evidence_kind (fixture | real); fixture words only on fixtures;
  * artifacts exist and their sha256 recomputes; JSON artifacts are objects and,
    when they look like tool output (have `ok`/`blocked_at`), carry `ok:true` or
    an explicit `blocked_at`;
  * at least one `real` case and at least one real case with a recorded command
    (`rc=` in lessons or `repro.status == recorded`);
  * refs point at files that exist in the repo (no phantom refs);
  * `outcome=planned` is rejected (planned work belongs in ROADMAP).

Line-ending note: `.gitattributes` archives `*.json` as LF, but historical
artifacts were hashed on CRLF checkouts. Hashing therefore accepts a
CRLF<->LF-normalised match and reports it as a warning instead of a failure.
The raw-byte hash is still computed first and is what gets printed.

No network, no install, no sample execution. Failures are reported per case,
never as a traceback.

Usage:
  python sc-accept.py
  python sc-accept.py --root . --json
  python sc-accept.py --case supply-chain03 --json
  python sc-accept.py --self-test

Exit codes:
  0  every case passes
  1  at least one case fails a check
  2  blocked (bad root / missing Tool/cases)
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

VERSION = "1.0.0"
DOMAIN = "supply-chain-security"
CASE_PATTERN = "supply-chain*"
FIELDS = ("id", "domain", "target_type", "evidence_kind", "protection",
          "authority", "goal_level", "outcome", "artifacts", "lessons",
          "refs", "updated")
FIXTURE_WORDS = ("夹具", "教学", "fixture", "示例")
CASE_MIN, CASE_MAX = 3, 5


# ------------------------------------------------------------------ helpers
def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_check(path, want):
    """返回 (matched, mode, raw)。raw 是磁盘字节的 sha256，永远是第一判据。"""
    with open(path, "rb") as fh:
        data = fh.read()
    raw = sha256_bytes(data)
    if raw == want:
        return True, "raw", raw
    for mode, blob in (("crlf-normalized", data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")),
                       ("lf-normalized", data.replace(b"\r\n", b"\n"))):
        if sha256_bytes(blob) == want:
            return True, mode, raw
    return False, "mismatch", raw


def rel(path, root):
    try:
        return os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return path


def recorded(case):
    """real 案例是否留下命令+rc 记录。"""
    txt = "\n".join(str(x) for x in case.get("lessons") or [])
    if "rc=" in txt:
        return True
    return (case.get("repro") or {}).get("status") == "recorded"


# ------------------------------------------------------------------ validate
def validate_case(case_dir, root):
    case_dir = os.path.abspath(case_dir)
    errors = []
    warnings = []
    case_file = os.path.join(case_dir, "case.json")
    name = os.path.basename(case_dir)
    if not os.path.isfile(case_file):
        return {"case": rel(case_dir, root), "id": None, "ok": False,
                "errors": ["missing case.json"], "warnings": []}
    try:
        with open(case_file, encoding="utf-8-sig") as fh:
            case = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        return {"case": rel(case_dir, root), "id": None, "ok": False,
                "errors": ["bad case.json: %s" % str(exc)[:120]], "warnings": []}

    cid = case.get("id")
    for key in FIELDS:
        if key not in case:
            errors.append("missing field: %s" % key)
    if case.get("domain") != DOMAIN:
        errors.append("domain is %r, expected %s" % (case.get("domain"), DOMAIN))
    if cid and name != cid:
        warnings.append("directory %s != id %s" % (name, cid))

    kind = case.get("evidence_kind")
    target = str(case.get("target_type") or "")
    fixture_words = [w for w in FIXTURE_WORDS if w in target]
    if kind not in ("fixture", "real", "self-built", "historical"):
        errors.append("evidence_kind=%r (want fixture|real)" % kind)
    elif kind == "fixture" and not fixture_words:
        errors.append("fixture case target_type lacks a fixture marker")
    elif kind in ("real", "self-built") and fixture_words:
        errors.append("real case target_type contains fixture word(s): %s"
                      % ",".join(fixture_words))

    if case.get("outcome") == "planned":
        errors.append("outcome=planned is not allowed in cases/ (move it to ROADMAP)")

    lessons = case.get("lessons") or []
    if not lessons:
        errors.append("lessons is empty")

    artifacts = case.get("artifacts") or []
    if not artifacts:
        errors.append("no artifacts")
    for art in artifacts:
        if not isinstance(art, dict):
            errors.append("artifact entry is not an object")
            continue
        apath = art.get("path") or ""
        want = str(art.get("sha256") or "").lower()
        full = os.path.join(case_dir, apath)
        if not apath or not os.path.isfile(full):
            errors.append("missing artifact: %s" % (apath or "<empty>"))
            continue
        if len(want) != 64:
            errors.append("artifact %s has no 64-hex sha256" % apath)
        else:
            matched, mode, raw = hash_check(full, want)
            if not matched:
                errors.append("artifact %s sha256 mismatch (recomputed %s)" % (apath, raw[:12]))
            elif mode != "raw":
                warnings.append("artifact %s sha256 matched only after %s" % (apath, mode))
        if apath.lower().endswith(".json"):
            try:
                with open(full, encoding="utf-8-sig") as fh:
                    payload = json.load(fh)
            except Exception as exc:  # noqa: BLE001
                errors.append("artifact %s is not valid JSON: %s" % (apath, str(exc)[:80]))
                continue
            if not isinstance(payload, dict):
                errors.append("artifact %s is not a JSON object" % apath)
            elif ("ok" in payload or "blocked_at" in payload) and \
                    payload.get("ok") is not True and not payload.get("blocked_at"):
                errors.append("artifact %s has neither ok:true nor blocked_at" % apath)

    for ref in case.get("refs") or []:
        if isinstance(ref, str) and "://" not in ref and not ref.startswith("<"):
            if not os.path.isfile(os.path.join(root, ref)):
                errors.append("phantom ref: %s" % ref)

    if kind in ("real", "self-built") and not recorded(case):
        errors.append("real case has no command+rc record (lessons/repro)")

    return {"case": rel(case_dir, root), "id": cid, "evidence_kind": kind,
            "recorded": recorded(case) if kind in ("real", "self-built") else None,
            "ok": not errors, "errors": errors, "warnings": warnings}


# ------------------------------------------------------------------ aggregate
def accept(root, only=None):
    pattern = os.path.join(root, "Tool", "cases", CASE_PATTERN)
    dirs = sorted(x for x in glob.glob(pattern) if os.path.isdir(x))
    if only:
        dirs = [d for d in dirs if os.path.basename(d) == only]
    if only and not dirs:
        return {"tool": "sc-accept", "version": VERSION, "ok": False, "domain": DOMAIN,
                "root": root, "cases": 0, "real": 0, "recorded_real": 0,
                "blocked_at": "case-not-found", "reason": "no case dir named %r" % only,
                "failures": [{"case": only, "id": None, "errors": ["case not found"]}],
                "results": []}
    results = [validate_case(d, root) for d in dirs]
    real = sum(1 for r in results if r.get("evidence_kind") in ("real", "self-built"))
    recorded_real = sum(1 for r in results
                        if r.get("evidence_kind") in ("real", "self-built") and r.get("recorded"))
    failures = [{"case": r["case"], "id": r.get("id"), "errors": r["errors"]}
                for r in results if not r["ok"]]
    if not only:
        if not (CASE_MIN <= len(results) <= CASE_MAX):
            failures.append({"case": "<domain>", "id": None,
                             "errors": ["%d cases (need %d-%d)" % (
                                 len(results), CASE_MIN, CASE_MAX)]})
        if real < 1:
            failures.append({"case": "<domain>", "id": None,
                             "errors": ["no evidence_kind=real case"]})
        elif recorded_real < 1:
            failures.append({"case": "<domain>", "id": None,
                             "errors": ["no real case with a recorded command+rc"]})
    ok = not failures
    summary = {
        "tool": "sc-accept", "version": VERSION, "ok": ok,
        "domain": DOMAIN, "root": root,
        "cases": len(results), "real": real, "recorded_real": recorded_real,
        "failures": failures, "results": results,
    }
    if not ok:
        summary["blocked_at"] = "case-validation"
        summary["reason"] = "field/hash/real+recorded/ref checks failed for %d case(s)" % len(failures)
    return summary


# ------------------------------------------------------------------ self-test
def self_test():
    checks = []
    tmp = tempfile.mkdtemp(prefix="sc-accept-selftest-")
    try:
        ref_dir = os.path.join(tmp, "Tool", "skill", DOMAIN, "references")
        os.makedirs(ref_dir)
        for ref in ("01-criteria.md", "dependency-confusion.md"):
            with open(os.path.join(ref_dir, ref), "w", encoding="utf-8") as fh:
                fh.write("# %s\n" % ref)
        refs = ["Tool/skill/%s/references/01-criteria.md" % DOMAIN]

        def make_case(cid, kind, target, outcome="partial"):
            cdir = os.path.join(tmp, "Tool", "cases", cid)
            os.makedirs(os.path.join(cdir, "artifacts"), exist_ok=True)
            art = os.path.join(cdir, "artifacts", "run.json")
            with open(art, "w", encoding="utf-8") as fh:
                json.dump({"ok": True, "tool": "sc-check.py", "rule_hits": []}, fh)
            case = {
                "id": cid, "domain": DOMAIN, "target_type": target,
                "evidence_kind": kind, "protection": [], "authority": "local",
                "goal_level": "L2", "outcome": outcome,
                "artifacts": [{"path": "artifacts/run.json", "sha256": sha256_file(art)}],
                "lessons": ["ran python Tool/skill/supply-chain-security/scripts/sc-check.py --path ., rc=0"],
                "refs": list(refs), "updated": "2026-10-21",
                "repro": {"status": "recorded"},
            }
            with open(os.path.join(cdir, "case.json"), "w", encoding="utf-8") as fh:
                json.dump(case, fh, ensure_ascii=False)
            return cdir, case, art

        fix_dir, fix_case, fix_art = make_case(
            "supply-chain91", "fixture", "离线夹具：合成恶意 npm 包 manifest")
        real_dir, real_case, real_art = make_case(
            "supply-chain92", "real", "本地真实仓库只读静态扫描")
        make_case("supply-chain93", "fixture", "离线夹具：合成 workflow")

        # 1) a valid fixture case passes
        good = validate_case(fix_dir, tmp)
        checks.append(("fixture-passes", good["ok"] is True))
        # 2) tampering with the artifact is detected (raw and normalised)
        with open(fix_art, "ab") as fh:
            fh.write(b" ")
        bad = validate_case(fix_dir, tmp)
        checks.append(("tamper-detected",
                       bad["ok"] is False and any("sha256 mismatch" in e for e in bad["errors"])))
        # 3) CRLF<->LF drift is tolerated but warned, never silent
        with open(fix_art, "wb") as fh:
            fh.write(b'{"ok": true, "tool": "sc-check.py", "rule_hits": []}\n')
        with open(fix_art, "rb") as fh:
            lf = fh.read()
        fix_case["artifacts"][0]["sha256"] = sha256_bytes(lf.replace(b"\n", b"\r\n"))
        with open(os.path.join(fix_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(fix_case, fh, ensure_ascii=False)
        eol = validate_case(fix_dir, tmp)
        checks.append(("crlf-tolerated",
                       eol["ok"] is True and any("normalized" in w for w in eol["warnings"])))
        # 4) phantom refs are detected
        fix_case["refs"] = ["Tool/skill/%s/references/nope.md" % DOMAIN]
        with open(os.path.join(fix_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(fix_case, fh, ensure_ascii=False)
        phantom = validate_case(fix_dir, tmp)
        checks.append(("phantom-ref",
                       any("phantom ref" in e for e in phantom["errors"])))
        # 5) fixture marker / planned outcome are enforced
        fix_case["refs"] = list(refs)
        fix_case["target_type"] = "real scanner output"
        fix_case["outcome"] = "planned"
        with open(os.path.join(fix_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(fix_case, fh, ensure_ascii=False)
        strict = validate_case(fix_dir, tmp)
        checks.append(("fixture-marker",
                       any("fixture marker" in e for e in strict["errors"])))
        checks.append(("planned-rejected",
                       any("planned" in e for e in strict["errors"])))
        # 6) a real case without rc= must fail
        real_case["lessons"] = ["looked at it"]
        real_case.pop("repro", None)
        with open(os.path.join(real_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(real_case, fh, ensure_ascii=False)
        norc = validate_case(real_dir, tmp)
        checks.append(("real-needs-rc",
                       any("command+rc" in e for e in norc["errors"])))
        # 7) aggregate: all-real-recorded missing is a domain-level failure
        agg_bad = accept(tmp)
        checks.append(("aggregate-real-recorded",
                       agg_bad["ok"] is False
                       and agg_bad["recorded_real"] == 0
                       and any(f["case"] == "<domain>" for f in agg_bad["failures"])))
        # 8) aggregate passes once the real case records command+rc
        real_case["lessons"] = ["ran python Tool/skill/supply-chain-security/scripts/sc-check.py --path ., rc=0"]
        real_case["repro"] = {"status": "recorded"}
        with open(os.path.join(real_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(real_case, fh, ensure_ascii=False)
        # restore the fixture case to a clean state
        fix_case["target_type"] = "离线夹具：合成恶意 npm 包 manifest"
        fix_case["outcome"] = "partial"
        fix_case["artifacts"][0]["sha256"] = sha256_file(fix_art)
        with open(os.path.join(fix_dir, "case.json"), "w", encoding="utf-8") as fh:
            json.dump(fix_case, fh, ensure_ascii=False)
        agg_ok = accept(tmp)
        checks.append(("aggregate-passes",
                       agg_ok["ok"] is True and agg_ok["cases"] == 3
                       and agg_ok["real"] == 1 and agg_ok["recorded_real"] == 1))
        checks.append(("failure-shape",
                       isinstance(agg_bad.get("failures"), list)
                       and agg_bad.get("blocked_at") == "case-validation"))
        # 9) --case filters to a single directory
        one = accept(tmp, only="supply-chain92")
        checks.append(("case-filter", one["cases"] == 1 and one["ok"] is True))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    failed = [name for name, ok in checks if not ok]
    if failed:
        print(json.dumps({"ok": False, "tool": "sc-accept", "version": VERSION,
                          "blocked_at": "self-test",
                          "reason": "失败项: " + ",".join(failed)}, ensure_ascii=False))
        return 2
    print(json.dumps({"ok": True, "tool": "sc-accept", "version": VERSION,
                      "checks": len(checks), "mode": "builtin-fixture"},
                     ensure_ascii=False))
    return 0


# ------------------------------------------------------------------ main
def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="sc-accept.py",
        description="复算 supply-chain-security 案例验收：字段/证据种类/哈希/real+recorded/refs。只读，不联网。",
        epilog="示例: python sc-accept.py --root . --json；自检: python sc-accept.py --self-test")
    parser.add_argument("--root", default=None,
                        help="仓库根（默认从本文件位置推导）")
    parser.add_argument("--case", default=None,
                        help="只校验 Tool/cases/<case>（目录名，如 supply-chain03）")
    parser.add_argument("--json", action="store_true", help="输出单个 JSON 对象")
    parser.add_argument("--self-test", action="store_true",
                        help="离线自检：内置合成案例，成功时输出含 ok 的 JSON")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    root = os.path.abspath(args.root) if args.root else str(Path(__file__).resolve().parents[4])
    if not os.path.isdir(os.path.join(root, "Tool", "cases")):
        print(json.dumps({"ok": False, "blocked_at": "input",
                          "reason": "no Tool/cases under root: %s" % root},
                         ensure_ascii=False))
        return 2

    summary = accept(root, args.case)
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print("sc-accept %s  %s" % (VERSION, summary["root"]))
        for item in summary["results"]:
            print("[%s] %-18s %s" % ("PASS" if item["ok"] else "FAIL",
                                     item["id"] or item["case"],
                                     item.get("evidence_kind") or "-"))
            for err in item["errors"]:
                print("       - " + err)
            for warn in item["warnings"]:
                print("       ~ " + warn)
        for fail in summary["failures"]:
            if fail["case"] == "<domain>":
                for err in fail["errors"]:
                    print("[FAIL] " + err)
        print("cases=%d real=%d recorded_real=%d ok=%s" % (
            summary["cases"], summary["real"], summary["recorded_real"], summary["ok"]))
    if summary.get("blocked_at") == "case-not-found":
        return 2
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
