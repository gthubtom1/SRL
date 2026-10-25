#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""route.py —— 路由唯一入口（S3）：从 `Tool/skill/*/pack.json` 现算，不再有 routing.json 副本。

为什么重写：旧 `routing.json` 是可以和实现漂移的第二份表（上游 45 条路由目标全不存在就是
这个形态）。现在路由声明在包里，`route.py --check` 保证**0 条死路由**。

用法：
    python Tool/scripts/route.py --index            # 每行一条路由：priority<TAB>pack<TAB>label
    python Tool/scripts/route.py --index --json     # 机器可读
    python Tool/scripts/route.py --resolve "安卓 APK 去广告"
    python Tool/scripts/route.py --resolve "区块链智能合约有没有漏洞" --strict   # 判不出 → rc=2
    python Tool/scripts/route.py --check            # 死路由/坏正则/坏优先级 → rc=1

兜底路由（`"fallback": true`）仍然存在（保住 softseep 的兜底条目），但**不再静默**：
`--resolve` 命中它会打 `[FALLBACK]` 标记；`--strict` 下若**唯一命中是兜底**，
输出 `[UNCLASSIFIED]` 且 rc=2 —— “我判不出来”是合法且可观测的出口（PLAN-OPTIMIZATION W5）。

退出码：0 通过 / 1 有死路由或坏声明 / 2 参数错误或 --strict 判型未定（UNCLASSIFIED）
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))          # 仓库根
SKILL_DIR = os.path.join(ROOT, "Tool", "skill")

PACK_KEYS = {"schema", "id", "l1", "routes", "stages", "tools", "cases", "witness",
             "witness_tool",   # 真跑该域自己的脚本（外部评审 C1：witness 只查账本 = 假绿）
             "evidence_contract", "limitations", "invalidation"}
ROUTE_KEYS = {"label", "must", "priority",
              "fallback"}       # 兜底路由显式标记（W5）：命中它≠判型成功
ROUTE_REQUIRED = {"label", "must", "priority"}   # fallback 可选：只有兜底那条要写

UNCLASSIFIED = "[UNCLASSIFIED] 判不出领域，请先问用户一句话"


def pack_files(skill_dir=None):
    d = skill_dir or SKILL_DIR
    if not os.path.isdir(d):
        return []
    out = []
    for name in sorted(os.listdir(d)):
        p = os.path.join(d, name, "pack.json")
        if os.path.isfile(p):
            out.append((name, p))
    return out


def load_packs(skill_dir=None):
    """返回 (packs, problems)。packs 里每项带 dir/id/l1/routes，problems 非空即不可信。"""
    packs, problems = [], []
    seen = {}
    for dirname, path in pack_files(skill_dir):
        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as e:
            problems.append("%s/pack.json 解析失败：%s" % (dirname, str(e)[:60]))
            continue
        if not isinstance(raw, dict):
            problems.append("%s/pack.json 顶层不是对象" % dirname)
            continue
        pid = str(raw.get("id") or "")
        if pid != dirname:
            problems.append("%s：id=%r 与目录名不一致" % (dirname, pid))
        if pid in seen:
            problems.append("pack id 重复：%s（%s 与 %s）" % (pid, seen[pid], dirname))
        seen[pid] = dirname
        routes = raw.get("routes")
        if not isinstance(routes, list) or not routes:
            problems.append("%s：routes 为空或非数组" % dirname)
            routes = []
        for i, r in enumerate(routes):
            if not isinstance(r, dict):
                problems.append("%s routes[%d]：不是对象" % (dirname, i))
                continue
            extra = set(r) - ROUTE_KEYS
            miss = ROUTE_REQUIRED - set(r)
            if extra:
                problems.append("%s routes[%d]：多出未声明字段 %s（.strict 语义）"
                                % (dirname, i, ",".join(sorted(extra))))
            if miss:
                problems.append("%s routes[%d]：缺字段 %s" % (dirname, i, ",".join(sorted(miss))))
            must = r.get("must")
            if not isinstance(must, list) or not must:
                problems.append("%s routes[%d]：must 必须是非空数组" % (dirname, i))
            else:
                for j, pat in enumerate(must):
                    try:
                        re.compile(str(pat))
                    except re.error as e:
                        problems.append("%s routes[%d].must[%d] 正则非法：%s"
                                        % (dirname, i, j, str(e)[:40]))
            if not isinstance(r.get("priority"), int):
                problems.append("%s routes[%d]：priority 必须是整数" % (dirname, i))
            if "fallback" in r and not isinstance(r.get("fallback"), bool):
                problems.append("%s routes[%d]：fallback 必须是 true/false" % (dirname, i))
            if not str(r.get("label") or "").strip():
                problems.append("%s routes[%d]：label 不能为空" % (dirname, i))
        packs.append({"dir": dirname, "path": path, "id": pid or dirname,
                      "l1": str(raw.get("l1") or ""), "routes": routes, "raw": raw})
    return packs, problems


def flat_routes(packs):
    """扁平化：[(priority, pack_id, label, [must...])]，按优先级从高到低。"""
    out = []
    for p in packs:
        for r in p["routes"]:
            if isinstance(r, dict):
                out.append((int(r.get("priority") or 0), p["id"],
                            str(r.get("label") or ""), list(r.get("must") or [])))
    out.sort(key=lambda x: (-x[0], x[1], x[2]))
    return out


def check(skill_dir=None):
    packs, problems = load_packs(skill_dir)
    rows = flat_routes(packs)
    # 死路由判据：包目录必须存在、必须有 SKILL.md、每条路由必须能解析到 pack id
    ids = {p["id"] for p in packs}
    for p in packs:
        if not os.path.isfile(os.path.join(os.path.dirname(p["path"]), "SKILL.md")):
            problems.append("%s：缺 SKILL.md（路由指向一个不存在的能力）" % p["id"])
    dead = [r for r in rows if r[1] not in ids]
    if dead:
        problems.append("死路由 %d 条：%s" % (len(dead), "、".join("%s/%s" % (d[1], d[2]) for d in dead)))
    prios = [r[0] for r in rows]
    dup = {x for x in prios if prios.count(x) > 1}
    if dup:
        problems.append("priority 重复 %d 个：%s（路由顺序不确定）"
                        % (len(dup), "、".join(str(x) for x in sorted(dup)[:8])))
    return {"packs": len(packs), "routes": len(rows), "dead": len(dead),
            "problems": problems, "rows": rows}


def fallback_keys(packs):
    """{(pack_id, label)}：被显式标记为兜底的路由（`"fallback": true`）。"""
    out = set()
    for p in packs:
        for r in p["routes"]:
            if isinstance(r, dict) and r.get("fallback") is True:
                out.add((p["id"], str(r.get("label") or "")))
    return out


def resolve(text, skill_dir=None, limit=5):
    packs = load_packs(skill_dir)[0]
    fb = fallback_keys(packs)
    text = str(text or "")
    hits = []
    for prio, pid, label, must in flat_routes(packs):
        for pat in must:
            try:
                if re.search(pat, text):
                    hits.append({"pack": pid, "label": label, "priority": prio,
                                 "must": pat, "fallback": (pid, label) in fb})
                    break
            except re.error:
                continue
    hits.sort(key=lambda x: -x["priority"])
    return hits[:limit]


def main():
    ap = argparse.ArgumentParser(description="路由唯一入口：从 pack.json 现算（无 routing.json 副本）")
    ap.add_argument("--index", action="store_true", help="列出全部路由（priority<TAB>pack<TAB>label）")
    ap.add_argument("--check", action="store_true", help="死路由 / 坏正则 / 坏优先级 → rc=1")
    ap.add_argument("--resolve", default="", help="按一段自然语言匹配路由")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="唯一命中是兜底路由时输出 [UNCLASSIFIED] 并以 rc=2 退出")
    ap.add_argument("--skill-dir", default="", help="覆盖 Tool/skill 根（测试用）")
    a = ap.parse_args()
    sd = a.skill_dir or None

    if a.resolve:
        hits = resolve(a.resolve, sd)
        concrete = [h for h in hits if not h.get("fallback")]
        fell_back = bool(hits) and not concrete      # 命中全是兜底（或无命中）
        unclassified = a.strict and fell_back
        if a.json:
            print(json.dumps({"query": a.resolve, "hits": hits,
                              "fallback": fell_back, "unclassified": unclassified,
                              "message": UNCLASSIFIED if unclassified else ""},
                             ensure_ascii=False, indent=2))
        elif not hits:
            print(UNCLASSIFIED if a.strict
                  else "[NONE] 无路由命中（兜底路由缺失？）：%s" % a.resolve)
        else:
            for h in hits:
                print("%-24s p=%-4d %s%s" % (h["pack"], h["priority"], h["label"],
                                             "  [FALLBACK]" if h.get("fallback") else ""))
            if unclassified:
                print(UNCLASSIFIED)
        return 2 if unclassified else 0

    if a.check:
        res = check(sd)
        if a.json:
            out = {k: v for k, v in res.items() if k != "rows"}
            out["fallbacks"] = len(fallback_keys(load_packs(sd)[0]))
            print(json.dumps(out, ensure_ascii=False, indent=2))
        else:
            print("[ROUTE] %d 个 pack / %d 条路由 / 死路由 %d" % (res["packs"], res["routes"], res["dead"]))
            for p in res["problems"]:
                print("  [FAIL] " + p)
            if not res["problems"]:
                print("[PASS] 路由自洽：0 条死路由")
        return 1 if res["problems"] else 0

    if a.index:
        rows = flat_routes(load_packs(sd)[0])
        if a.json:
            fb = fallback_keys(load_packs(sd)[0])
            print(json.dumps([{"priority": p, "pack": pid, "label": lb, "must": m,
                               "fallback": (pid, lb) in fb}
                              for p, pid, lb, m in rows], ensure_ascii=False, indent=2))
        else:
            for p, pid, lb, _m in rows:
                print("%d\t%s\t%s" % (p, pid, lb))
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
