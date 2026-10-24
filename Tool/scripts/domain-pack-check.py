#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""domain-pack-check.py -- 「加域/加技能/加工具」的准入闸（防常驻层再胖）。

为什么需要它（2026-10-23 复盘）：
  我们靠"写规则"扩能力，结果 79 条强制语句、29,415 token 固定前缀，
  模型遵循率崩到实测区间以下（外部实验：20 条同时生效 → 最好的模型 60%）。
  根因不是某条规则写得不好，而是**没有任何东西拦着"再加一点"**。

  这个脚本就是那道闸。它只认三件事：
    1. 每个域（domain）必须有一张声明卡，字段齐、层级清（L1 描述 / L2 技能 / L3 参考）；
    2. 常驻层（技能索引）有硬预算，超了就失败 —— 想加一个新技能，就得先删掉一个；
    3. 文档里引用的脚本/技能/案例必须真实存在（防"写完就算落地"）。

用法:
    python Tool/scripts/domain-pack-check.py
    python Tool/scripts/domain-pack-check.py --json
    python Tool/scripts/domain-pack-check.py --index-chars 12000   # 覆盖常驻索引预算

退出码：0 全绿 / 1 有违规 / 2 输入缺失
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
REPO = os.path.dirname(TOOL)
AGENT_DIR = os.environ.get("PI_CODING_AGENT_DIR") or os.path.join(os.path.expanduser("~"), ".pi", "agent")

# ── 预算（依据见 docs/RESEARCH-BASELINE.md）──
INDEX_CHARS_BUDGET = 12000     # 技能索引常驻预算 ≈ 3,000 token
DESC_CHARS_HARD = 180          # 单个技能描述硬上限
DESC_CHARS_WARN = 140          # 超过就提醒（常驻层里每 40 字 ≈ 10 token/轮）
ROUTE_MIN_KEYWORD = 1          # 每条路由至少 1 条关键词

# 域任务卡六段（缺一段就算卡不完整）
CARD_SECTIONS = ("触发词", "前置", "步骤", "判据", "失败判据", "reference")


def read(p: str) -> str:
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def skill_roots() -> list[str]:
    roots = []
    for r in (os.path.join(AGENT_DIR, "skills"), os.path.join(TOOL, "skill")):
        if os.path.isdir(r):
            roots.append(r)
    return roots


def skill_desc(skill_rel: str) -> str:
    """skill_rel 形如 'apkseep/SKILL.md' → 读 frontmatter 的 description。"""
    for root in skill_roots():
        for cand in (os.path.join(root, skill_rel.replace("/", os.sep)),
                     os.path.join(root, skill_rel.split("/")[0], "SKILL.md")):
            if os.path.isfile(cand):
                t = read(cand)
                m = re.search(r"^description:\s*(.+)$", t, re.M)
                if m:
                    return m.group(1).strip().strip('"').strip("'")
    return ""


def load_baseline() -> int:
    """读历史债基线。只准降不准升（见 Tool/config/packs.baseline.json 的 _note）。"""
    p = os.path.join(TOOL, "config", "packs.baseline.json")
    try:
        return int((json.load(open(p, encoding="utf-8")).get("domain_pack") or {})
                   .get("max_errors", 0))
    except Exception:
        return 0


def res_packs(res):
    """route.check() 结果里出现过的包 id（去重、有序）。"""
    return sorted({row[1] for row in (res.get('rows') or [])})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--index-chars", type=int, default=INDEX_CHARS_BUDGET)
    ap.add_argument("--max-errors", type=int, default=None,
                    help="基线：允许的违规条数。不传就读 Tool/config/packs.baseline.json（保证单独跑与 preflight 内跑结论一致）")
    a = ap.parse_args()
    if a.max_errors is None:
        a.max_errors = load_baseline()

    errs: list[str] = []
    warns: list[str] = []
    info: dict = {}

    # ── 1. 路由自洽（pack.json 唯一事实源）+ 索引预算 ──
    import route as route_mod
    res = route_mod.check()
    info["routes"] = res["routes"]
    for p in res["problems"]:
        errs.append(p)
    skills_seen: dict[str, str] = {}
    for pid in sorted(res_packs(res)):
        sk = os.path.join(TOOL, "skill", pid, "SKILL.md")
        desc = skill_desc(pid) or ""
        if not os.path.isfile(sk):
            errs.append(f"包 {pid} 缺 SKILL.md")
            continue
        skills_seen[pid] = desc

    # ── 2. 常驻索引预算（技能描述总长）──
    total_chars = sum(len(d) for d in skills_seen.values())
    info["index_skills"] = len(skills_seen)
    info["index_chars"] = total_chars
    info["index_budget"] = a.index_chars
    over = total_chars - a.index_chars
    if over > 0:
        errs.append(f"常驻技能索引超预算：{total_chars} 字 > {a.index_chars}（超 {over}）。"
                    f"加新技能前必须先删/合并一个，或把描述压到 {DESC_CHARS_WARN} 字内。")
    for sk, d in sorted(skills_seen.items(), key=lambda kv: -len(kv[1])):
        if len(d) > DESC_CHARS_HARD:
            errs.append(f"技能描述超硬上限 {DESC_CHARS_HARD} 字：{sk}（{len(d)} 字）")
        elif len(d) > DESC_CHARS_WARN:
            warns.append(f"技能描述偏长（{len(d)} 字，建议 ≤{DESC_CHARS_WARN}）：{sk}")

    # ── 3. 域任务卡完整性 + 引用脚本存在 ──
    packs = sorted(glob.glob(os.path.join(TOOL, "prompts", "domains", "*.md")))
    info["domain_packs"] = len(packs)
    card_total = 0
    for p in packs:
        t = read(p)
        name = os.path.basename(p)
        cards = re.findall(r"^### .+$", t, re.M)
        card_total += len(cards)
        if not cards:
            errs.append(f"{name}：没有任何 `### ` 任务卡")
            continue
        # 抽查每张卡是否六段齐（按卡切块）
        blocks = re.split(r"^### ", t, flags=re.M)[1:]
        for b in blocks:
            title = b.splitlines()[0][:40] if b.splitlines() else "?"
            missing = [s for s in CARD_SECTIONS if f"{s}" not in b]
            if missing:
                warns.append(f"{name} · {title} 缺段：{'/'.join(missing)}")
        # 引用脚本必须存在
        for m in re.finditer(r"python\s+(Tool/[A-Za-z0-9_\-./]+\.py)", t):
            rel = m.group(1)
            if not os.path.isfile(os.path.join(REPO, rel.replace("/", os.sep))):
                errs.append(f"{name}：引用了不存在的脚本 {rel}")
    info["task_cards"] = card_total

    # ── 4. 技能索引 vs 磁盘技能（有没有"装了但没路由"的孤儿）──
    disk_skills = set()
    for root in skill_roots():
        for f in glob.glob(os.path.join(root, "*", "SKILL.md")):
            disk_skills.add(os.path.basename(os.path.dirname(f)))
    routed_dirs = {s.split("/")[0].replace(".md", "") for s in skills_seen}
    orphan = sorted(disk_skills - routed_dirs)
    info["skills_on_disk"] = len(disk_skills)
    info["skills_orphan"] = len(orphan)
    if orphan:
        warns.append(f"{len(orphan)} 个技能在磁盘上但没有路由（占索引但不被选中）：{', '.join(orphan[:8])}")

    # ── 输出 ──
    if a.json:
        print(json.dumps({"ok": len(errs) <= a.max_errors, "errors": errs, "warnings": warns,
                          "info": info, "max_errors": a.max_errors}, ensure_ascii=False, indent=1))
    else:
        print("域包 / 路由 / 索引 准入检查\n")
        print(f"  路由 {info['routes']} 条 / 索引技能 {info['index_skills']} 个 / "
              f"索引 {info['index_chars']} 字（预算 {info['index_budget']}）/ "
              f"域包 {info['domain_packs']} 个 / 任务卡 {info['task_cards']} 张 / "
              f"磁盘技能 {info['skills_on_disk']} 个（孤儿 {info['skills_orphan']}）")
        print()
        for e in errs:
            print(f"  [FAIL] {e}")
        for w in warns[:12]:
            print(f"  [warn] {w}")
        if len(warns) > 12:
            print(f"  [warn] …… 另有 {len(warns) - 12} 条")
        print()
        concl = ("全绿 —— 可以加新域" if not errs
                 else f"{len(errs)} 项违规（基线 {a.max_errors}）"
                 + (" → 已超基线，先修再扩域" if len(errs) > a.max_errors else " → 在基线内（历史债，只降不升）"))
        print("  结论：" + concl)

    return 0 if len(errs) <= a.max_errors else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
