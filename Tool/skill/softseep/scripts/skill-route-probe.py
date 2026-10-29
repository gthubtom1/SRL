#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""skill-route-probe.py -- 对真实 Python 路由器运行自然语言回归探针。

读取 Tool/config/skill-route-probes.json，逐条执行 route.py --resolve --json，
检查主技能、辅助技能、歧义、禁止域与主标签。无领域命中是合法结果；启动失败、
超时或坏响应均不能算通过。
只需当前 Python，不依赖 PowerShell，也不生成临时路由文件。

用法:
    python Tool/skill/softseep/scripts/skill-route-probe.py
    python Tool/skill/softseep/scripts/skill-route-probe.py --json
    python Tool/skill/softseep/scripts/skill-route-probe.py --only web-js apk game
    python Tool/skill/softseep/scripts/skill-route-probe.py --self-test
退出码：0 全绿 / 1 有探针失败 / 2 输入缺失、无效或筛选后没有探针。
"""

from __future__ import annotations

# Shared locator for both source skills and installed copies.
from pathlib import Path as _RuntimePath
import sys as _runtime_sys
_runtime_sys.path.insert(0, str(_RuntimePath(__file__).resolve().parents[2] / 'softseep' / 'scripts'))
from seep_runtime import repo_root as _seep_repo_root


import argparse
import io
import json
import os
import subprocess
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
def _repo_root(start):
    return _seep_repo_root(__file__)


ROOT = _repo_root(HERE)
PROBES = os.path.join(ROOT, "Tool", "config", "skill-route-probes.json")
ROUTER = os.path.join(ROOT, "Tool", "scripts", "route.py")
TIMEOUT = 60


def run_router(hint: str) -> dict:
    """执行唯一的路由入口，保留失败原因供探针报告。"""
    cmd = [sys.executable, ROUTER, "--resolve", hint, "--json"]
    facts: dict[str, object] = {
        "primary_skill": "", "primary_label": "", "primary": "",
        "domains": [], "labels": {},
    }
    try:
        proc = subprocess.run(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"rc": 1, "facts": facts, "error": "route.py 超时（%d 秒）" % TIMEOUT}
    except OSError as exc:
        return {"rc": 1, "facts": facts, "error": "route.py 启动失败: %s" % exc}
    try:
        data = json.loads(proc.stdout.decode("utf-8-sig"))
        if not isinstance(data, dict) or not isinstance(data.get("hits"), list):
            raise ValueError("缺 hits 数组")
        if proc.returncode in (0, 2) and not isinstance(data.get("unclassified"), bool):
            raise ValueError("缺 unclassified 布尔值")
        domains, labels = [], {}
        for hit in data["hits"]:
            if not isinstance(hit, dict) or not isinstance(hit.get("pack"), str) or not hit["pack"]:
                raise ValueError("命中项缺 pack 字符串")
            if hit.get("fallback") or hit["pack"] == "seep-router":
                continue
            pack = hit["pack"]
            if pack not in domains:
                domains.append(pack)
                labels[pack] = str(hit.get("label") or "")
        facts["domains"] = domains
        facts["labels"] = labels
        if domains:
            first = domains[0]
            first_hit = next(hit for hit in data["hits"] if hit.get("pack") == first)
            facts["primary_skill"] = "%s/SKILL.md" % first
            facts["primary_label"] = labels[first]
            facts["primary"] = "P%04d" % int(first_hit.get("priority") or 0)
    except (ValueError, TypeError, UnicodeError) as exc:
        return {"rc": 1, "facts": facts, "error": "route.py 响应无效: %s" % exc}
    return {"rc": proc.returncode, "facts": facts,
            "error": "; ".join(str(p) for p in data.get("problems", []))}


def _norm_skill(s: str) -> str:
    s = (s or "").strip().replace("\\", "/")
    for pre in ("skills/", "Tool/skill/", "./", "_pending/safe-skills/", "_pending/"):
        if s.startswith(pre):
            s = s[len(pre):]
    return s


def _norm_domain(s: str) -> str:
    value = _norm_skill(s)
    if value.endswith("/SKILL.md"):
        value = value[:-len("/SKILL.md")]
    return value


def judge(probe: dict, facts: dict) -> list[str]:
    """返回失败原因列表（空 = 通过）。"""
    bad = []
    skill = _norm_skill(facts.get("primary_skill", ""))
    domains = list(facts.get("domains") or [])
    want = _norm_skill(probe.get("expect_skill", ""))
    if not want:
        # 空期望 = 这条说法本身不该路由到任何域（例如内网/提权/非技术文本）。
        # 以前靠"什么都落到 softseep"才绿，那是假绿；现在要求真的判不出来。
        if skill or domains:
            bad.append("技能 %s（期望：判不出领域）" % ("/".join(domains) or skill))
    elif skill != want:
        bad.append("技能 %s ≠ 期望 %s" % (skill or "(空)", want))

    if "expect_aux" in probe:
        want_aux = [_norm_domain(item) for item in (probe.get("expect_aux") or [])]
        got_aux = [_norm_domain(item) for item in domains[1:]]
        if got_aux != want_aux:
            bad.append("辅助技能 %s ≠ 期望 %s"
                       % ("/".join(got_aux) or "(空)", "/".join(want_aux) or "(空)"))
    elif len(domains) > 1:
        bad.append("命中多个领域但探针未登记 expect_aux：%s" % "/".join(domains))

    if "expect_ambiguity" in probe:
        got_ambiguity = len(domains) > 1
        if got_ambiguity != bool(probe.get("expect_ambiguity")):
            bad.append("歧义=%s ≠ 期望 %s"
                       % (got_ambiguity, bool(probe.get("expect_ambiguity"))))

    forbidden = set(_norm_domain(item) for item in (probe.get("forbid") or []))
    hit_forbidden = [domain for domain in domains if _norm_domain(domain) in forbidden]
    if hit_forbidden:
        bad.append("误命中禁止域 %s（完整命中 %s）"
                   % ("/".join(hit_forbidden), "/".join(domains)))

    # S3：R 编号已随 routing.json 消失，只断言「落到哪个包」（expect_skill）与 label
    want_label = probe.get("expect_label")
    if want_label and want_label not in (facts.get("primary_label") or ""):
        bad.append("label %r 不含 %r" % (facts.get("primary_label", ""), want_label))
    return bad


def main() -> int:
    ap = argparse.ArgumentParser(description="技能路由探针（route.py）")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--only", nargs="*", default=[], help="只跑 id 前缀匹配的探针")
    ap.add_argument("--probes", default=PROBES)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        ok1 = judge({"expect_skill": "apkseep/SKILL.md"}, {"primary_skill": "skills/apkseep/SKILL.md"}) == []
        ok2 = judge({"expect_skill": "apkseep/SKILL.md"}, {"primary_skill": "skills/softseep/SKILL.md"}) != []
        ok3 = judge({"expect_skill": "softseep/SKILL.md"}, {"primary_skill": ""}) != []
        ok4 = judge({"expect_label": "OSINT"}, {"primary_label": "OSINT / 资产测绘"}) == []
        ok5 = judge(
            {"expect_skill": "apkseep/SKILL.md", "expect_aux": ["softseep"],
             "expect_ambiguity": True},
            {"primary_skill": "apkseep/SKILL.md", "domains": ["apkseep", "softseep"]},
        ) == []
        ok6 = judge(
            {"expect_skill": "apkseep/SKILL.md", "expect_aux": ["softseep"],
             "expect_ambiguity": True},
            {"primary_skill": "apkseep/SKILL.md", "domains": ["apkseep"]},
        ) != []
        ok7 = judge(
            {"expect_skill": "firmware-iot/SKILL.md", "forbid": ["web-pentest"]},
            {"primary_skill": "firmware-iot/SKILL.md",
             "domains": ["firmware-iot", "web-pentest"]},
        ) != []
        failed = [n for n, ok in (("norm-skill", ok1), ("mismatch", ok2),
                                  ("missing-skill", ok3), ("label", ok4),
                                  ("aux-positive", ok5), ("aux-missing", ok6),
                                  ("forbidden-aux", ok7)) if not ok]
        print(json.dumps({"ok": not failed, "checks": 7, "failed": failed,
                          "tool": "skill-route-probe.py"}, ensure_ascii=False))
        return 0 if not failed else 1

    if not os.path.isfile(args.probes):
        print(json.dumps({"ok": False, "error": "探针文件不存在: %s" % args.probes,
                          "blocked_at": "probes-missing"}, ensure_ascii=False))
        return 2
    try:
        with io.open(args.probes, encoding="utf-8-sig") as handle:
            data = json.load(handle)
        probes = data.get("probes") if isinstance(data, dict) else None
        if not isinstance(probes, list) or any(
                not isinstance(p, dict) or any(not isinstance(p.get(k), str)
                                               for k in ("id", "text", "expect_skill"))
                or not p["id"].strip() or not p["text"].strip()
                or ("expect_label" in p and not isinstance(p["expect_label"], str))
                or ("expect_aux" in p and (
                    not isinstance(p["expect_aux"], list)
                    or any(not isinstance(x, str) or not x.strip() for x in p["expect_aux"])))
                or ("forbid" in p and (
                    not isinstance(p["forbid"], list)
                    or any(not isinstance(x, str) or not x.strip() for x in p["forbid"])))
                or ("expect_ambiguity" in p and not isinstance(p["expect_ambiguity"], bool))
                for p in probes):
            raise ValueError("probes 必须是带 id/text/expect_skill 字符串的数组")
    except (OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc), "blocked_at": "probes-invalid"}, ensure_ascii=False))
        return 2
    if args.only:
        probes = [p for p in probes if any(p["id"].startswith(x) for x in args.only)]

    if not probes:
        print(json.dumps({"ok": False, "error": "没有选中任何探针", "blocked_at": "probes-empty"}, ensure_ascii=False))
        return 2

    results, fails = [], []
    for p in probes:
        r = run_router(p["text"])
        bad = judge(p, r["facts"])
        if r.get("error"):
            bad.append(r["error"])
        # rc=2 = 路由器判"未识别"（UNCLASSIFIED）。这是**合法结果**：
        # 仅当这条探针本来就期望有域（expect_skill 非空）时才算失败。
        # 以前这里无条件把非 0 记成失败，导致"提权/内网"这类域外说法无法表达。
        if r["rc"] not in (0, 2):
            bad.append("route.py rc=%d" % r["rc"])
        elif r["rc"] == 2 and (p.get("expect_skill") or "").strip():
            bad.append("route.py 判为未识别（期望 %s）" % p["expect_skill"])
        results.append({"id": p["id"], "text": p["text"],
                        "primary": r["facts"].get("primary", ""),
                        "skill": _norm_skill(r["facts"].get("primary_skill", "")),
                        "label": r["facts"].get("primary_label", ""),
                        "domains": r["facts"].get("domains", []),
                        "bad": bad})
        if bad:
            fails.append(results[-1])

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
