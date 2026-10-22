#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""skill-route-probe.py -- 技能路由探针（master-route.ps1 视角）。

回答一个问题：**用户按大白话说话时，`master-route.ps1` 会不会把它指到对的技能？**

为什么需要（2026-10-22 审计 P0）：
    .NET 正则的 \\b 把 CJK 也当 word 字符，于是「APK去广告」里的 \\bapk\\b、
    「Unity IL2CPP透视」里的 il2cpp\\b 全部匹配不上，直接掉进兜底 R0。
    当时只有「配方路由」有探针（intent-probes.json，Python 匹配），
    「技能路由」（PowerShell 匹配）一条断言都没有 —— 所以这个 bug 活了很久。

本脚本做的事：
    1. 读 Tool/config/skill-route-probes.json（每条：口吻 + 期望技能 + 期望路由 id）；
    2. 逐条调 `master-route.ps1 -Hint <口吻> -OutDir <临时目录>`；
    3. 解析它写出的 route-scope.md（避开控制台编码，直接读文件）；
    4. 断言 primary_skill / primary / primary_label 三项。

用法:
    python Tool/scripts/skill-route-probe.py
    python Tool/scripts/skill-route-probe.py --json
    python Tool/scripts/skill-route-probe.py --only web-js apk game
    python Tool/scripts/skill-route-probe.py --self-test
退出码：0 全绿（或本机无 PowerShell 时显式 skipped）/ 1 有探针失败 / 2 输入缺失。
"""

from __future__ import annotations

import argparse
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
PROBES = os.path.join(ROOT, "Tool", "config", "skill-route-probes.json")
ROUTER = os.path.join(ROOT, "Tool", "scripts", "master-route.ps1")
TIMEOUT = 60


def find_ps() -> str | None:
    """Windows 用 powershell（5.1 也要能跑），其它平台找 pwsh。"""
    for name in (("powershell", "pwsh") if os.name == "nt" else ("pwsh",)):
        p = shutil.which(name)
        if p:
            return p
    return None


def run_router(ps: str, hint: str) -> dict:
    """跑一条探针，从 route-scope.md 取事实（不解析控制台输出，避开编码问题）。"""
    out_dir = tempfile.mkdtemp(prefix="route-probe-")
    cmd = [ps, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ROUTER,
           "-Hint", hint, "-OutDir", out_dir]
    proc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=TIMEOUT)
    md = os.path.join(out_dir, "route-scope.md")
    facts: dict[str, str] = {}
    if os.path.isfile(md):
        with io.open(md, encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                if line.startswith("- ") and ": " in line:
                    k, v = line[2:].split(": ", 1)
                    facts[k.strip()] = v.strip()
    return {"rc": proc.returncode, "facts": facts, "out_dir": out_dir}


def _norm_skill(s: str) -> str:
    s = (s or "").strip().replace("\\", "/")
    for pre in ("skills/", "Tool/skill/", "./"):
        if s.startswith(pre):
            s = s[len(pre):]
    return s


def judge(probe: dict, facts: dict) -> list[str]:
    """返回失败原因列表（空 = 通过）。"""
    bad = []
    skill = _norm_skill(facts.get("primary_skill", ""))
    want = _norm_skill(probe.get("expect_skill", ""))
    if want and skill != want:
        bad.append("技能 %s ≠ 期望 %s" % (skill or "(空)", want))
    want_route = probe.get("expect_route")
    if want_route and facts.get("primary") != want_route:
        bad.append("路由 %s ≠ 期望 %s" % (facts.get("primary", "(空)"), want_route))
    want_label = probe.get("expect_label")
    if want_label and want_label not in (facts.get("primary_label") or ""):
        bad.append("label %r 不含 %r" % (facts.get("primary_label", ""), want_label))
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description="技能路由探针（master-route.ps1）")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--only", nargs="*", default=[], help="只跑 id 前缀匹配的探针")
    ap.add_argument("--probes", default=PROBES)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        ok1 = judge({"expect_skill": "apkseep/SKILL.md"}, {"primary_skill": "skills/apkseep/SKILL.md"}) == []
        ok2 = judge({"expect_skill": "apkseep/SKILL.md"}, {"primary_skill": "skills/softseep/SKILL.md"}) != []
        ok3 = judge({"expect_route": "R34"}, {"primary": "R0"}) != []
        ok4 = judge({"expect_label": "OSINT"}, {"primary_label": "OSINT / 资产测绘"}) == []
        failed = [n for n, ok in (("norm-skill", ok1), ("mismatch", ok2),
                                  ("route", ok3), ("label", ok4)) if not ok]
        print(json.dumps({"ok": not failed, "checks": 4, "failed": failed,
                          "tool": "skill-route-probe.py"}, ensure_ascii=False))
        return 0 if not failed else 1

    if not os.path.isfile(args.probes):
        print(json.dumps({"ok": False, "error": "探针文件不存在: %s" % args.probes,
                          "blocked_at": "probes-missing"}, ensure_ascii=False))
        return 2
    data = json.load(io.open(args.probes, encoding="utf-8-sig"))
    probes = data.get("probes") or []
    if args.only:
        probes = [p for p in probes if any(p["id"].startswith(x) for x in args.only)]

    ps = find_ps()
    if not ps:
        result = {"ok": True, "skipped": True,
                  "reason": "本机没有 powershell/pwsh，技能路由探针跳过（不算失败）",
                  "probes": len(probes)}
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else result["reason"])
        return 0

    results, fails = [], []
    for p in probes:
        r = run_router(ps, p["text"])
        bad = judge(p, r["facts"])
        if r["rc"] != 0:
            bad.append("master-route rc=%d" % r["rc"])
        results.append({"id": p["id"], "text": p["text"],
                        "primary": r["facts"].get("primary", ""),
                        "skill": _norm_skill(r["facts"].get("primary_skill", "")),
                        "label": r["facts"].get("primary_label", ""),
                        "bad": bad})
        if bad:
            fails.append(results[-1])
        shutil.rmtree(r["out_dir"], ignore_errors=True)

    out = {"ok": not fails, "probes": len(results), "failed": len(fails),
           "results": results, "fails": fails}
    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print("技能路由探针：%d 条，失败 %d 条" % (len(results), len(fails)))
        for f in fails:
            print("  [FAIL] %-14s %s → %s | %s | %s"
                  % (f["id"], f["text"][:22], f["primary"], f["skill"], "；".join(f["bad"])))
    return 0 if not fails else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
