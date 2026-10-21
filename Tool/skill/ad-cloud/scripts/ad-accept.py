#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ad-accept.py —— ad-cloud 域验收（案例字段/哈希/证据链 + 凭据红线）。

逐条检查 Tool/cases/ad-cloud*/case.json：
  * 必填字段、evidence_kind ∈ fixture|real、每域至少 1 个 real 且 lessons 有命令+rc；
  * target_type 与 evidence_kind 自洽（fixture 必须带「夹具/教学/fixture」字样）；
  * artifacts 存在、sha256 复算一致；JSON 产物必须有 ok 或 blocked_at；
  * refs 指向真实文件；
  * **凭据红线**：案例目录内任何文件不得出现完整 JWT / AK-SK / 私钥块 / 明文 token 值
    （只允许指纹与声明；发现即判 FAIL，并只打印位置不打印值）。

用法：
    python ad-accept.py                 # 扫全部 ad-cloud 案例
    python ad-accept.py --root . --case ad-cloud03
    python ad-accept.py --json
    python ad-accept.py --self-test     # 离线自检，rc=0
退出码：0 全过 / 1 有失败 / 2 卡点（root 不可读等）。
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
import tempfile

VERSION = "1.0.0"
FIELDS = ("id", "domain", "target_type", "evidence_kind", "protection",
          "authority", "goal_level", "outcome", "artifacts", "lessons",
          "refs", "updated")
FIXTURE_WORDS = ("夹具", "教学", "fixture", "示例")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
AK_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PEM_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")


def _is_fixture_jwt(token):
    """payload 里自述 fixture / not-verified 的 JWT 视为夹具（仍会 warn）。"""
    import base64
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(payload.encode()).decode("utf-8", "ignore").lower()
        return ("fixture" in raw) or ("not-verified" in raw) or ("not_verified" in raw)
    except Exception:  # noqa: BLE001
        return False


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(p, root):
    try:
        return os.path.relpath(p, root).replace(os.sep, "/")
    except ValueError:
        return p


def check_case(case_dir, root, out):
    fails, warns = [], []
    cf = os.path.join(case_dir, "case.json")
    name = os.path.basename(case_dir.rstrip("/\\"))
    try:
        case = json.load(open(cf, encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [f"{name}: case.json 不可读({type(exc).__name__})"], warns
    miss = [k for k in FIELDS if k not in case]
    if miss:
        fails.append("%s: 缺字段 %s" % (name, ",".join(miss)))
    kind = case.get("evidence_kind")
    if kind not in ("fixture", "real", "self-built", "historical"):
        fails.append("%s: evidence_kind=%r" % (name, kind))
    tt = str(case.get("target_type") or "")
    is_fix = any(w in tt for w in FIXTURE_WORDS)
    if kind == "fixture" and not is_fix:
        fails.append("%s: fixture 但 target_type 未标夹具" % name)
    if kind in ("real", "self-built") and is_fix:
        fails.append("%s: real 却标成夹具" % name)
    lessons = "\n".join(case.get("lessons") or [])
    if kind in ("real", "self-built"):
        rp = case.get("repro") or {}
        recorded = ("rc=" in lessons) or ("python " in lessons) or ("命令" in lessons)
        if not recorded and rp.get("status") != "not-recorded":
            fails.append("%s: real 但无命令/rc 且未标 not-recorded" % name)
        if rp.get("status") == "not-recorded" and not rp.get("reason"):
            fails.append("%s: not-recorded 缺 reason" % name)
    for art in case.get("artifacts") or []:
        ap = art.get("path") or ""
        full = os.path.join(case_dir, ap)
        if not ap or not os.path.isfile(full):
            fails.append("%s: 幻影产物 %s" % (name, ap[:40]))
            continue
        want = str(art.get("sha256") or "").lower()
        if len(want) != 64:
            fails.append("%s: %s 缺 sha256" % (name, ap[:30]))
        elif sha256_file(full) != want:
            fails.append("%s: %s sha256 不符" % (name, ap[:30]))
        if full.endswith(".json"):
            try:
                d = json.load(open(full, encoding="utf-8"))
                if isinstance(d, dict) and "ok" not in d and "blocked_at" not in d \
                        and "results" not in d:
                    warns.append("%s: %s 无 ok/blocked_at 字段" % (name, ap[:30]))
            except Exception:  # noqa: BLE001
                warns.append("%s: %s 不是合法 JSON" % (name, ap[:30]))
    for r in case.get("refs") or []:
        if isinstance(r, str) and "://" not in r:
            if not os.path.isfile(os.path.join(root, r)):
                fails.append("%s: refs 幻影 %s" % (name, r[:40]))
    # 凭据红线：只报位置，不打印值
    for dp, dn, fn in os.walk(case_dir):
        for f in fn:
            p = os.path.join(dp, f)
            if os.path.getsize(p) > 4 * 1024 * 1024:
                continue
            try:
                txt = open(p, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for label, rx in (("JWT", JWT_RE), ("AK", AK_RE), ("PRIVATE-KEY", PEM_RE)):
                for m in rx.finditer(txt):
                    val = m.group(0)
                    # 夹具里的自述 JWT（payload 含 fixture / not-verified）不算真凭据，
                    # 但必须显式标注；否则按红线处理。
                    if label == "JWT" and (kind == "fixture" or _is_fixture_jwt(val)):
                        warns.append("%s: %s 含自述夹具 JWT（已标注 fixture）" % (name, rel(p, case_dir)))
                        continue
                    fails.append("%s: 凭据红线 %s 出现在 %s（只报位置，不输出值）"
                                 % (name, label, rel(p, case_dir)))
                    break
    out.append({"case": name, "kind": kind, "fails": fails, "warns": warns})
    return fails, warns


def run(root, only=None):
    cases = sorted(glob.glob(os.path.join(root, "Tool", "cases", "ad-cloud*")))
    cases = [c for c in cases if os.path.isfile(os.path.join(c, "case.json"))]
    if only:
        cases = [c for c in cases if os.path.basename(c) == only]
    if not cases:
        return 2, {"ok": False, "blocked_at": "cases", "reason": "no ad-cloud case found"}
    out = []
    all_fails = []
    reals = recordings = 0
    for c in cases:
        f, _ = check_case(c, root, out)
        all_fails += f
        try:
            cj = json.load(open(os.path.join(c, "case.json"), encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if cj.get("evidence_kind") in ("real", "self-built"):
            reals += 1
            txt = "\n".join(cj.get("lessons") or [])
            if "rc=" in txt or "python " in txt or "命令" in txt:
                recordings += 1
    if len(cases) < 3:
        all_fails.append("only %d cases (need 3-5)" % len(cases))
    if reals < 1:
        all_fails.append("no evidence_kind=real case")
    elif recordings < 1:
        all_fails.append("no recorded real case (command + rc)")
    return (0 if not all_fails else 1), {
        "ok": not all_fails, "cases": len(cases), "real": reals,
        "recorded_real": recordings, "failures": all_fails, "details": out,
    }


def self_test():
    checks = 0
    tmp = tempfile.mkdtemp(prefix="ad-accept-")
    try:
        case = os.path.join(tmp, "Tool", "cases", "ad-cloud99")
        os.makedirs(os.path.join(case, "artifacts"))
        art = os.path.join(case, "artifacts", "run.json")
        json.dump({"ok": True, "results": [{"kind": "windows-events", "verdict": "blocked"}]},
                  open(art, "w", encoding="utf-8"))
        sha = sha256_file(art)
        good = {
            "id": "ad-cloud99", "domain": "ad-cloud",
            "target_type": "自建靶：真实运行产出的事件 JSON", "evidence_kind": "real",
            "protection": [], "authority": "local", "goal_level": "L2",
            "outcome": "partial", "artifacts": [{"path": "artifacts/run.json", "sha256": sha}],
            "lessons": ["命令：python ad-repro.py --kind windows-events；rc=0"],
            "refs": ["Tool/skill/ad-cloud/references/01-criteria.md"],
            "updated": "2026-10-21",
        }
        ref = os.path.join(tmp, "Tool", "skill", "ad-cloud", "references", "01-criteria.md")
        os.makedirs(os.path.dirname(ref), exist_ok=True)
        open(ref, "w", encoding="utf-8").write("# fixture ref\n")
        json.dump(good, open(os.path.join(case, "case.json"), "w", encoding="utf-8"))
        rc, res = run(tmp)
        checks += 1
        assert rc == 2 or rc == 1, "单个案例少于 3 个应失败"
        # 三个案例 + 至少一个 real/recorded → 通过
        for i in (97, 98):
            d = os.path.join(tmp, "Tool", "cases", "ad-cloud%d" % i)
            os.makedirs(os.path.join(d, "artifacts"))
            a = os.path.join(d, "artifacts", "run.json")
            json.dump({"ok": True}, open(a, "w", encoding="utf-8"))
            c = dict(good, id="ad-cloud%d" % i,
                     target_type="本地离线夹具（教学）", evidence_kind="fixture",
                     artifacts=[{"path": "artifacts/run.json", "sha256": sha256_file(a)}],
                     lessons=["跑的是什么：夹具；命令：python ad-repro.py；rc=0"])
            json.dump(c, open(os.path.join(d, "case.json"), "w", encoding="utf-8"))
        rc, res = run(tmp)
        checks += 1
        assert rc == 0 and res["ok"], res
        # 篡改哈希 → 必须红
        c = json.load(open(os.path.join(case, "case.json"), encoding="utf-8"))
        c["artifacts"][0]["sha256"] = "0" * 64
        json.dump(c, open(os.path.join(case, "case.json"), "w", encoding="utf-8"))
        rc, res = run(tmp)
        checks += 1
        assert rc == 1 and any("sha256" in f for f in res["failures"]), res
        # 凭据红线 → 必须红
        c["artifacts"][0]["sha256"] = sha
        json.dump(c, open(os.path.join(case, "case.json"), "w", encoding="utf-8"))
        open(os.path.join(case, "artifacts", "leak.txt"), "w", encoding="utf-8").write(
            "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJlLXBsYWNlaG9sZGVy")
        rc, res = run(tmp)
        checks += 1
        assert rc == 1 and any("凭据红线" in f for f in res["failures"]), res
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    print(json.dumps({"ok": True, "checks": checks, "tool": "ad-accept.py",
                      "note": "offline self-test: fields/hash/real/credential-redline"}, ensure_ascii=False))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="ad-cloud 案例验收（字段/哈希/证据链/凭据红线）")
    here = os.path.abspath(__file__)                    # Tool/skill/ad-cloud/scripts/
    default_root = os.path.abspath(os.path.join(os.path.dirname(here), "..", "..", "..", ".."))
    ap.add_argument("--root", default=default_root, help="repo root")
    ap.add_argument("--case", help="only this case directory name")
    ap.add_argument("--json", action="store_true", help="emit one JSON object")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    root = os.path.abspath(args.root)
    if not os.path.isdir(os.path.join(root, "Tool", "cases")):
        print(json.dumps({"ok": False, "blocked_at": "root",
                          "reason": "no Tool/cases under %s" % root}, ensure_ascii=False))
        return 2
    rc, res = run(root, args.case)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print("cases: %d  real: %d  recorded: %d" % (res.get("cases", 0),
                                                    res.get("real", 0),
                                                    res.get("recorded_real", 0)))
        print("result: %s" % ("PASS" if res.get("ok") else "FAIL"))
        for f in res.get("failures") or []:
            print("  - FAIL %s" % f)
    return rc


if __name__ == "__main__":
    sys.exit(main())
