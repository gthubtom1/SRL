#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify-routing-coherence.py —— 路由表自洽性校验（routing.json ↔ 技能落位）

背景
----
`Tool/scripts/routing.json` 是任务路由的「单一事实源 (SSOT)」，master-route.ps1 /
case-init.ps1 都从它读规则。它一旦与真实技能目录脱节（改目录没改路由、加路由没加
priority），路由会静默失效或指向不存在的 SKILL.md —— 这类错误在运行期很难发现。

本脚本把「自洽性」变成可执行断言，退出码 0 = 自洽，1 = 不自洽。

校验项
------
  1. routing.json 可解析，且含 routes / priority / meta.fallbackId
  2. 每个 route 必有 label + skill，且 keywords 至少有一条 must 或 mustAll
  3. priority 与 routes 一一对应（无缺、无多余、无重复）
  4. fallbackId 必须在 routes 中
  5. 每个 route.skill 必须能在三种落位之一找到真实文件：
       <root>/<skill>
       <root>/skill/<skill>
       <root>/skill/safe-skills/<skill>

用法
----
    python Tool/scripts/verify-routing-coherence.py
    python Tool/scripts/verify-routing-coherence.py --json
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))  # 仓库根（Tool/scripts -> Tool -> .）
SKILLS_ROOT = os.path.join(ROOT, "Tool")       # 本包的技能根（Tool/skill/...）


def load_json(path):
    with io.open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def resolve_skill(root, skill_rel):
    rel = skill_rel.replace("\\", "/")
    for base in (root, os.path.join(root, "skill"), os.path.join(root, "skill", "safe-skills")):
        cand = os.path.join(base, rel.replace("/", os.sep))
        if os.path.isfile(cand):
            return cand
    return ""


def check(config_path):
    problems = []
    if not os.path.isfile(config_path):
        return [f"routing.json 不存在: {config_path}"], {}

    try:
        cfg = load_json(config_path)
    except Exception as exc:  # noqa: BLE001
        return [f"routing.json 不是合法 JSON: {exc}"], {}

    routes = cfg.get("routes")
    priority = cfg.get("priority")
    fallback = (cfg.get("meta") or {}).get("fallbackId")

    if not isinstance(routes, dict) or not routes:
        problems.append("routes 缺失或为空")
        return problems, {}
    if not isinstance(priority, list) or not priority:
        problems.append("priority 缺失或为空")

    for rid, route in routes.items():
        if not isinstance(route, dict):
            problems.append(f"[{rid}] route 不是对象")
            continue
        if not route.get("label"):
            problems.append(f"[{rid}] 缺少 label")
        skill = route.get("skill")
        if not skill:
            problems.append(f"[{rid}] 缺少 skill")
        else:
            resolved = resolve_skill(SKILLS_ROOT, skill)
            if not resolved:
                problems.append(f"[{rid}] skill 落位不存在: {skill}")
        kws = route.get("keywords") or []
        if not kws:
            problems.append(f"[{rid}] keywords 为空")
        for i, kw in enumerate(kws):
            if not isinstance(kw, dict) or not (kw.get("must") or kw.get("mustAll")):
                problems.append(f"[{rid}] keywords[{i}] 既无 must 也无 mustAll")

    if isinstance(priority, list):
        missing = [r for r in routes if r not in priority]
        extra = [p for p in priority if p not in routes]
        dup = sorted({p for p in priority if priority.count(p) > 1})
        if missing:
            problems.append("routes 未出现在 priority: " + ", ".join(missing))
        if extra:
            problems.append("priority 含 routes 之外的幽灵 id: " + ", ".join(extra))
        if dup:
            problems.append("priority 存在重复项: " + ", ".join(dup))

    if fallback and fallback not in routes:
        problems.append(f"meta.fallbackId 不在 routes 中: {fallback}")

    summary = {
        "config": config_path,
        "routes": sorted(routes.keys()),
        "priority": priority,
        "fallback": fallback,
        "problems": problems,
    }
    return problems, summary


def main(argv):
    ap = argparse.ArgumentParser(description="routing.json 自洽性校验")
    ap.add_argument("--config", default="", help="routing.json 路径（默认自动探测）")
    ap.add_argument("--json", action="store_true", help="以 JSON 输出结果")
    args = ap.parse_args(argv)

    candidates = [
        args.config,
        os.path.join(HERE, "routing.json"),
        os.path.join(ROOT, "Tool", "config", "routing.json"),
    ]
    config_path = ""
    for c in candidates:
        if c and os.path.isfile(c):
            config_path = c
            break
    if not config_path:
        config_path = os.path.join(HERE, "routing.json")

    problems, summary = check(config_path)

    if args.json:
        print(json.dumps({"ok": not problems, **summary}, indent=2, ensure_ascii=False))
    else:
        print("[routing-coherence] 配置: %s" % config_path)
        if summary:
            print("  路由数: %d (%s)" % (len(summary["routes"]), ", ".join(summary["routes"])))
        if problems:
            print("  [FAIL] 发现 %d 个不自洽项:" % len(problems))
            for p in problems:
                print("    - %s" % p)
        else:
            print("  [OK] 路由表自洽（routes / priority / fallback / 技能落位 全部一致）")

    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
