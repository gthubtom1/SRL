#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""merge-routing-fragment.py —— 把 `Tool/config/routing-fragments/*.json` 合入 SSOT。

为什么需要（血案）：
    v1.21 起每个域都有 routing-fragment，但**没有合入脚本**，于是片段与
    `Tool/scripts/routing.json` 各说一套：片段改了词边界，SSOT 还是旧的宽松词，
    实际路由（master-route.ps1 / case-init.ps1 只读 SSOT）完全没生效。

合并策略（只做三件事，绝不整表覆盖）：
    1. 片段里的 rid 必须已存在于 SSOT（不新增路由，避免 priority 缺项）；
    2. 用片段的 `keywords` 替换 SSOT 同 rid 的 `keywords`（词边界以片段为准）；
    3. `label`/`skill` 默认沿用 SSOT，片段显式提供且不同则报冲突、不覆盖。

用法：
    python Tool/scripts/merge-routing-fragment.py --check     # 只校验（rc=1 表示未合入）
    python Tool/scripts/merge-routing-fragment.py --write     # 合入并回写 SSOT
    python Tool/scripts/merge-routing-fragment.py --write --only web-pentest pwn-crypto
"""
from __future__ import annotations

import argparse
import glob
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SSOT = os.path.join(ROOT, "Tool", "scripts", "routing.json")
FRAG = os.path.join(ROOT, "Tool", "config", "routing-fragments")


def rj(p):
    with io.open(p, encoding="utf-8-sig") as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description="片段 → SSOT 合并器")
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--only", nargs="*", default=[])
    a = ap.parse_args()
    if not (a.write or a.check):
        a.check = True
    ssot = rj(SSOT)
    routes = ssot.get("routes") or {}
    prio = ssot.get("priority") or []
    problems, applied = [], []
    for f in sorted(glob.glob(os.path.join(FRAG, "*.json"))):
        dom = os.path.splitext(os.path.basename(f))[0]
        if a.only and dom not in a.only:
            continue
        frag = rj(f)
        for rid, fr in (frag.get("routes") or {}).items():
            if rid not in routes:
                problems.append("%s: %s 不在 SSOT（不新增路由）" % (dom, rid))
                continue
            sr = routes[rid]
            if (fr.get("skill") or "") and fr["skill"].replace("\\", "/") not in (sr.get("skill") or ""):
                problems.append("%s: %s skill 冲突 %s≠%s" % (dom, rid, fr.get("skill"), sr.get("skill")))
                continue
            fk = fr.get("keywords") or []
            if not fk:
                problems.append("%s: %s 无 keywords" % (dom, rid))
                continue
            if json.dumps(fk, ensure_ascii=False, sort_keys=True) == json.dumps(
                    sr.get("keywords") or [], ensure_ascii=False, sort_keys=True):
                applied.append("%s: %s 已一致" % (dom, rid))
                continue
            if a.write:
                sr["keywords"] = fk
                if fr.get("label") and not sr.get("label"):
                    sr["label"] = fr["label"]
                applied.append("%s: %s 已合入（%d 条关键词）" % (dom, rid, len(fk)))
            else:
                problems.append("%s: %s 未合入（片段与 SSOT 不一致）" % (dom, rid))
    if a.write and not problems:
        io.open(SSOT, "w", encoding="utf-8", newline="\n").write(
            json.dumps(ssot, ensure_ascii=False, indent=2) + "\n")
    for x in applied:
        print("[OK] " + x)
    for x in problems:
        print("[FAIL] " + x)
    print("结论: " + ("可合并/已合并" if not problems else "%d 处冲突或未合入" % len(problems)))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
