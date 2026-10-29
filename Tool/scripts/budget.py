#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""budget.py —— 仓库文件与常驻提示词预算自检。

一条命令回答："这个项目有没有在变臃肿？"
退出码：0 = 全部在预算内；1 = 有超限项。

用法：
    python Tool/scripts/budget.py
    python Tool/scripts/budget.py --json
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # Tool/scripts -> Tool
if HERE not in sys.path:
    sys.path.insert(0, HERE)   # 让 `from lib.source_inventory import …` 与本文件同目录运行一致


def _server_source():
    with io.open(os.path.join(ROOT, "mcp", "seep_mcp_server.py"), encoding="utf-8") as source:
        return source.read()


def count_tools():
    src = _server_source()
    return len(re.findall(r"^@server\.tool\(\)", src, re.M))


def count_skills():
    base = os.path.join(ROOT, "skill")
    names = set()
    for d in os.listdir(base):
        p = os.path.join(base, d)
        if not os.path.isdir(p):
            continue
        if d.startswith(("_", ".")):   # S3：`_pending/` 是归档区，不索引
            continue
        if d == "safe-skills":
            for sub in os.listdir(p):
                if os.path.isdir(os.path.join(p, sub)):
                    names.add(sub)
        else:
            names.add(d)
    return len(names)


def first_party_inventory():
    """引擎文件清单（**唯一真相源**：`Tool/scripts/lib/source_inventory.py`）。

    历史（别再走回头路）：
      · 2026-10-22 前用 os.walk，把 `.pytest_cache/`/`.pi/`/`evidence/` 算进去 → 实测漂移 820↔834；
      · 之后改成「git ls-files + 12 条**子串** skip」，942 能对上账，但 #43 审计实测 13 条
        真实源被误排（`.github/workflows/*.yml` 撞 `/work`、`docs/audits/*` 撞 `/audit`、
        `setup/upstream-rules.json` 撞 `/upstream`、`Tool/skill/*/evidence/*` 撞 `/evidence/`）；
      · 回退分支还把**绝对路径**丢进同一子串判定 —— 仓库装在含 work/cases/audit/evidence
        的路径下会把 `Tool/` 整个剪掉，退化成 ~40 条静默绿。
    ⇒ 计数、排除原因、gitless 校验全部收敛到 source_inventory，本函数只做转接。

    返回 (count|None, inv)。None = 口径未验证（不准当数字用，也不准当绿）。
    """
    try:
        from lib.source_inventory import inventory  # Tool/scripts/lib
    except Exception:  # noqa: BLE001 —— 被当模块 copy 到别处时的兜底
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "seep_source_inventory", os.path.join(HERE, "lib", "source_inventory.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        inventory = mod.inventory
    try:
        inv = inventory(os.path.dirname(ROOT))
    except Exception as exc:  # noqa: BLE001 —— 清单不可用 ≠ 计数为 0
        return None, {"mode": "unverified", "mode_reason": "清单不可用：%s" % str(exc)[:160],
                      "counts": {}, "errors": [str(exc)[:200]], "source_complete": False}
    if inv.get("mode") == "unverified":
        return None, inv
    if not inv.get("source_complete", True):
        # F1/F2：数字可以给（让人看到 raw），但**不得拿去判绿** —— 消费方拿到 None → UNKN/rc2。
        return None, inv
    return inv["counts"]["first_party"], inv


def case_files():
    """案例库文件数：证据/样本/产物，单独预算（不算引擎膨胀）。"""
    d = os.path.join(ROOT, "cases")
    n = 0
    for dirpath, dirs, files in os.walk(d):
        if "__pycache__" in dirpath:
            dirs[:] = []
            continue
        n += len(files)
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(description="反臃肿预算自检")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    repo = os.path.dirname(ROOT)
    _pf_count, _pf_inv = first_party_inventory()
    budget = [
        ("MCP 工具", count_tools(), 45),
        ("技能", count_skills(), None),   # 用户决定：技能数量不设上限
        ("setup 脚本", len([f for f in os.listdir(os.path.join(repo, "setup"))
                        if f.endswith((".ps1", ".sh", ".py"))]), 22),
        ("MANUAL 手册", len([f for f in os.listdir(os.path.join(repo, "MANUAL"))
                         if f.endswith(".md")]), 16),
        ("MCP 主服务行数", len(_server_source().splitlines()), 3200),
        # 上限从 900 → 930（2026-10-25）：A+ 深度工作按"每域 ≥2000 行/篇均 ≥250"补内容，
        # 每轮会新增 2–4 篇 reference。深度是产品本身，不是膨胀；上限仍设死值，防止无节制加文件。
        ("first-party 引擎文件", _pf_count, 950),   # 950 是判据，本批不动；口径见 lib/source_inventory.py
        ("案例库文件", case_files(), 1700),   # 证据库：66 个案例的真实输入/产物
    ]

    rows = []
    over = []
    unknown = []
    for name, value, limit in budget:
        if limit is None:
            rows.append({"item": name, "value": value, "limit": None, "ok": True})
            continue
        if value is None:      # 口径未验证：既不算过，也不算超 —— 单独一档，不许静默变绿
            rows.append({"item": name, "value": None, "limit": limit, "ok": False,
                         "unverified": True})
            unknown.append(name)
            continue
        ok = value <= limit
        rows.append({"item": name, "value": value, "limit": limit, "ok": ok})
        if not ok:
            over.append(name)

    inv = {"policy": _pf_inv.get("policy"), "mode": _pf_inv.get("mode"),
           "stable": _pf_inv.get("stable"), "counts": _pf_inv.get("counts") or {},
           "mode_reason": _pf_inv.get("mode_reason") or "",
           "source_complete": _pf_inv.get("source_complete"),
           "manifest_source": _pf_inv.get("manifest_source") or "",
           "missing_tracked": [e.get("path") for e in (_pf_inv.get("missing_tracked") or [])],
           "deleted_staged": [e.get("path") for e in (_pf_inv.get("deleted_staged") or [])],
           "unsupported": [e.get("path") for e in (_pf_inv.get("unsupported") or [])]}
    _raw = (_pf_inv.get("counts") or {}).get("included")   # 实际存在数（可能与计入值不同）

    if args.json:
        print(json.dumps({"ok": not over and not unknown, "budget": rows,
                          "source_inventory": inv}, indent=2, ensure_ascii=False))
    else:
        print("[budget] 反臃肿预算自检")
        for r in rows:
            if r.get("unverified"):
                print("  %-4s %-16s %5s / %d" % ("UNKN", r["item"], "?", r["limit"]))
                continue
            mark = "OK  " if r["ok"] else "OVER"
            if r["limit"] is None:
                print("  %-4s %-16s %5d / 无上限" % (mark, r["item"], r["value"]))
            else:
                print("  %-4s %-16s %5d / %d" % (mark, r["item"], r["value"], r["limit"]))
        c = inv["counts"]
        print("  口径: %s mode=%s stable=%s tracked=%s untracked=%s 排除=%s"
              % (inv["policy"], inv["mode"], inv["stable"], c.get("tracked"),
                 c.get("untracked"), c.get("excluded")))
        if inv["missing_tracked"] or inv["unsupported"] or inv["source_complete"] is False:
            # F1/F2：**必须点名**。否则删掉工作树里的 tracked 文件就能把 OVER 洗成 OK 而无人知晓。
            print("  完整性: INCOMPLETE —— 实际存在=%s，不得当成完整清单" % (_raw,))
            if inv["missing_tracked"]:
                print("    missingTracked=%d: %s"
                      % (len(inv["missing_tracked"]),
                         ", ".join(inv["missing_tracked"][:5])))
            if inv["unsupported"]:
                print("    unsupported=%d (gitlink/嵌套 repo 未物化): %s"
                      % (len(inv["unsupported"]), ", ".join(inv["unsupported"][:5])))
        if inv["deleted_staged"]:
            print("    stagedDeleted=%d（已从索引移除，不计为缺失）: %s"
                  % (len(inv["deleted_staged"]),
                     ", ".join(inv["deleted_staged"][:5])))
        if unknown:
            print("  未验证（%s）：%s —— 不计为通过"
                  % (", ".join(unknown), inv["mode_reason"] or "无详情"))
        print("  结论:", "全部在预算内" if not over and not unknown
              else (("超限: " + ", ".join(over)) if over else "无法判定: " + ", ".join(unknown)))
    # An unknown measurement makes the whole result undecidable.  It must
    # retain rc=2 even when another independent row is already over limit;
    # otherwise callers cannot distinguish "known over" from "incomplete".
    if unknown:
        return 2
    return 1 if over else 0


# ═══════════════════════════════════════════════════════════════════════════
# 常驻层预算（原 prompt-budget.py，S4 并入：全局预算只留一个入口 budget.py）
#   python Tool/scripts/budget.py             # 仓库反膨胀预算（默认）
#   python Tool/scripts/budget.py --prompt    # 常驻可控制层 token 预算
# ═══════════════════════════════════════════════════════════════════════════

# -*- coding: utf-8 -*-
"""budget.py --prompt -- 系统提示词预算账本（谁在吃上下文）。

为什么需要它：
  一个常驻提示词层每多 1 万 token，就意味着每次调用少 1 万 token 的"工作记忆"，
  而且它不会自己消失 —— 换会话、换模型、压缩上下文之后它还在。
  2026-10-23 实测：某个逆向会话第一次调用就已经吃掉输入 **29,415 token**，
  全程 167 次调用 → 光前缀就 490 万 token，中途被迫 13 次裁剪上下文。

  规则（写进提示词的"不许/必须"）是**建议**；脚本判据是**机制**。
  能落成脚本的规则不该占提示词 —— 这个脚本存在的意义就是让"该占多少"可测量。

用法:
    python Tool/scripts/budget.py --prompt                 # 当前装配的账本
    python Tool/scripts/budget.py --prompt --json
    python Tool/scripts/budget.py --prompt --ceiling 8000   # 超了就非 0 退出（给 preflight 用）
    python Tool/scripts/budget.py --prompt --diff <file>    # 与另一次账本对比，看增肥/瘦身

退出码：0 在预算内 / 1 超预算 / 2 输入错误
"""


import argparse
import glob
import json
import os
import re
import sys

from lib.runtime_root import resolve_agent_root

AGENT_DIR = str(resolve_agent_root())
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 预算线（token）。不是硬科学，是"别把工作记忆挤没"的经验上限。
# 实测锚点：2026-10-23 会话 01a1685a 第一次调用 input+cacheRead = 29,415 token。
# 宿主自带部分（默认系统提示词 + 工具声明 + project_context 包装）用「锚点 − 其他层」反推，
# 保证账本总数与真实观测对得上，不低估。
# ★ 预算模型（2026-10-23 修正）：之前把「总上限 8,000」和「每层上限之和 10,400」写在一起，
#   自相矛盾；而且更致命的是 —— 宿主自带部分（默认提示词 + 工具声明 + 包装）实测就 10,122 token，
#   「总计 ≤8,000」在物理上不可能。
#   所以改成两个独立口径：
#     · 可控层（人设 + 纪律 + 索引 + 边界）→ 硬上限 3,500 token（这才是我们要瘦的）
#     · 总量 = 可控层 + 宿主基座（不可控，只报告不判）
#   依据：REQUIREMENTS.md 的预算/可维护性要求与本脚本的实测锚点
MEASURED_ANCHOR = 29415
CEILING_TOTAL = 13000            # 含宿主基座（只报告）
CEILING_CONTROLLABLE = 3500      # 可控制层硬上限

# ★ 指令堆叠崩塌的临界点。
# 外部证据（arXiv 2608.02639，24 条 verifier-checked 指令，stack 1→20，temp=0）：
#   1 条时遵循率 ~0.96；20 条同时生效时 —— Claude Sonnet 4.6 = 0.604，
#   Gemini 2.5 Flash = 0.433，GPT-5-mini = 0.201。
# 另一篇（arXiv 2502.12197）：护栏越多，近期模型表现「一致地趋向于零」。
# → 超过 20 条强制语句，遵循率就已经不值得依赖了；再多写只是自我安慰。
RULE_CLIFF = 20
IMPERATIVE = (r"必须|不许|禁止|一律|不得|绝不能|不要|务必|宁可|只能|才算|严禁"
              r"|(?i:\bmust\b|\bnever\b|\balways\b|\bdo not\b|\bdon't\b|\bcannot\b|\brequired\b|\bshall\b)")
CEILING_BY_KIND = {
    "persona": 1200,       # 纯风格层
    "rules": 1200,         # AGENTS.md + SEEP.md 合计
    "skills_index": 800,   # 6–8 个
    "boundary": 300,
}
# 四类之和 == CEILING_CONTROLLABLE，否则账本自己又矛盾了（已踩过一次）。
assert sum(CEILING_BY_KIND.values()) == CEILING_CONTROLLABLE, "预算表自相矛盾"
UNCONTROLLABLE_KINDS = ("base",)


def est_tokens(text: str) -> int:
    """粗估 token：CJK 约 1 字 1 token；ASCII 约 4 字符 1 token。

    实测锚点：2026-10-23 会话第一次调用 input+cacheRead = 29,415 token，
    本脚本对同一装配的估算误差在 ±15% 内（够用来做"谁在吃预算"的判断）。
    """
    cjk = 0
    other = 0
    for ch in text:
        o = ord(ch)
        if 0x2E80 <= o <= 0x9FFF or 0xF900 <= o <= 0xFAFF or 0xFF00 <= o <= 0xFF60:
            cjk += 1
        else:
            other += 1
    return int(round(cjk * 1.0 + other / 4.0))


def read(p: str) -> str:
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def layer(name: str, kind: str, path: str, text: str, note: str = "") -> dict:
    return {
        "layer": name,
        "kind": kind,
        "path": path,
        "bytes": len(text.encode("utf-8")) if text else 0,
        "chars": len(text),
        "tokens": est_tokens(text) if text else 0,
        "note": note,
    }


def skills_index() -> tuple[str, list]:
    """复刻宿主注入的技能索引：每个技能只给 name + description。"""
    roots = [os.path.join(AGENT_DIR, "skills")]
    items, blobs = [], []
    for root in roots:
        for f in sorted(glob.glob(os.path.join(root, "*", "SKILL.md"))):
            t = read(f)
            m = re.search(r"^name:\s*(.+)$", t, re.M)
            d = re.search(r"^description:\s*(.+)$", t, re.M)
            name = (m.group(1).strip() if m else os.path.basename(os.path.dirname(f)))
            desc = (d.group(1).strip().strip('"') if d else "")
            items.append({"name": name, "desc_chars": len(desc), "tokens": est_tokens(name + desc)})
            blobs.append(name + desc)
    return "\n".join(blobs), items


def persona_text() -> tuple[str, str]:
    pj = os.path.join(AGENT_DIR, "personas.json")
    try:
        d = json.load(open(pj, encoding="utf-8"))
        pid = d.get("defaultPersonaId")
    except Exception:
        pid = None
    if pid:
        p = os.path.join(AGENT_DIR, "personas", pid + ".md")
        if os.path.isfile(p):
            return read(p), p
    files = sorted(glob.glob(os.path.join(AGENT_DIR, "personas", "*.md")))
    if files:
        return read(files[0]), files[0]
    return "", "(none)"


def boundary_text() -> tuple[str, str]:
    """seep-boundary 由扩展注入；从扩展源码里取那段常量文本。"""
    for p in (os.path.join(AGENT_DIR, "extensions", "load-system-prompt.ts"),
              os.path.join(REPO, "Tool", "prompts", "extensions", "load-system-prompt.ts")):
        t = read(p)
        if not t:
            continue
        m = re.search(r"BOUNDARY_ANCHOR\s*=\s*`([\s\S]*?)`", t)
        if m and len(m.group(1)) > 100:
            return m.group(1), p
    # 兜底：用 SEEP.md 里的边界锚副本当近似
    t = read(os.path.join(AGENT_DIR, "SEEP.md"))
    m = re.search(r"<seep-boundary>[\s\S]*?</seep-boundary>", t)
    return (m.group(0) if m else ""), "(approx from SEEP.md)"


def base_prompt_estimate(others: int, anchor: int) -> int:
    """宿主自带部分（默认提示词 + 工具声明 + 包装）。

    不猜 —— 用「实测锚点 − 其他层」反推，保证账本总数与真实观测一致。
    """
    return max(1500, anchor - others)


def count_imperatives(text: str) -> int:
    """数一数这段提示词里有多少条「强制语句」（必须/不许/禁止/…）。

    为什么数它：指令遵循率不是线性的 —— 超过 ~20 条就进入崩塌区（见 RULE_CLIFF 注释）。
    规则写到 36 条并不能“更保险”，只能把整体遵循率拉低。
    """
    pat = re.compile(r"[^\n。；]*?(?:" + IMPERATIVE + r")[^\n。；]*")
    hits = [m.group(0).strip() for m in pat.finditer(text)]
    return len([h for h in hits if len(h) > 8])


def build(ceiling: int = CEILING_CONTROLLABLE, anchor: int = MEASURED_ANCHOR) -> dict:
    rows = []
    pt, pp = persona_text()
    rows.append(layer("破甲人设卡（L3 风格层）", "persona", pp, pt,
                      "纯风格：语气/称谓/范围声明；不解决任何工程问题，却每一轮都占预算"))

    ag = read(os.path.join(AGENT_DIR, "AGENTS.md"))
    rows.append(layer("AGENTS.md（L0 宿主纪律）", "rules", os.path.join(AGENT_DIR, "AGENTS.md"), ag,
                      "全部是「不许/必须」类规则；没有一条带运行期执行体"))

    sp = read(os.path.join(AGENT_DIR, "SEEP.md"))
    rows.append(layer("SEEP.md（层间裁决）", "rules", "SEEP.md", sp, "四层裁决 + 指针，体量合理"))

    bt, bp = boundary_text()
    rows.append(layer("seep-boundary（边界锚）", "boundary", bp, bt, "凭据红线/授权门/沙箱契约；小且不可省"))

    si, items = skills_index()
    rows.append(layer(f"技能索引（{len(items)} 个技能，只有 name+description）", "skills_index",
                      os.path.join(AGENT_DIR, "skills"), si,
                      "按需加载是对的；但「全量 32 个」对单个项目是噪声"))

    rows.append(layer("pi 默认提示词 + 工具声明 + 包装", "base", "(宿主反推)", "",
                      "用锚点−其他层反推；宿主自带，基本动不了"))

    others = sum(r["tokens"] for r in rows)
    rows[-1]["tokens"] = base_prompt_estimate(others, anchor)
    rows[-1]["chars"] = rows[-1]["tokens"] * 4
    rows[-1]["bytes"] = rows[-1]["tokens"] * 4

    total = sum(r["tokens"] for r in rows)
    controllable = sum(r["tokens"] for r in rows if r["kind"] not in UNCONTROLLABLE_KINDS)
    rule_stats = {
        "cliff": RULE_CLIFF,
        "AGENTS.md": count_imperatives(ag),
        "人设卡": count_imperatives(pt),
        "SEEP.md": count_imperatives(sp),
    }
    rule_stats["合计（会同时生效的）"] = rule_stats["AGENTS.md"] + rule_stats["人设卡"] + rule_stats["SEEP.md"]
    return {
        "total_tokens": total,
        "controllable_tokens": controllable,
        "controllable_ceiling": ceiling,
        "ceiling": ceiling,
        "over_by": max(0, controllable - ceiling),
        "layers": rows,
        "skills": items,
        "rule_stats": rule_stats,
    }


def render(d: dict) -> None:
    print("系统提示词预算账本（估算 token；锚点：实测首次调用 29,415）\n")
    kinds = {}
    for r in d["layers"]:
        kinds.setdefault(r["kind"], 0)
        kinds[r["kind"]] += r["tokens"]

    print(f"{'层':40s} {'类':14s} {'tokens':>8s} {'占比':>7s}")
    print("-" * 76)
    for r in sorted(d["layers"], key=lambda x: -x["tokens"]):
        pct = 100.0 * r["tokens"] / d["total_tokens"] if d["total_tokens"] else 0
        print(f"{r['layer'][:40]:40s} {r['kind']:14s} {r['tokens']:8d} {pct:6.1f}%")
    print("-" * 76)
    ctl = d.get("controllable_tokens", 0)
    ccap = d.get("controllable_ceiling", CEILING_CONTROLLABLE)
    print(f"{'可控制小计（人设+纪律+索引+边界）':40s} {'':14s} {ctl:8d}           "
          f"预算 {ccap}  {'OK' if ctl <= ccap else '超 %d' % (ctl - ccap)}")
    print(f"{'总计（含宿主基座，只报告不判）':40s} {'':14s} {d['total_tokens']:8d}           -")
    print()
    print("按类对账（同类合并计）：")
    for k, cap in CEILING_BY_KIND.items():
        v = kinds.get(k, 0)
        print(f"  {k:14s} {v:6d} / {cap:<6d} {'OK' if v <= cap else '超 %d' % (v - cap)}")
    for k in UNCONTROLLABLE_KINDS:
        if k in kinds:
            print(f"  {k:14s} {kinds[k]:6d} / {'不可控，不计入判定'}")
    print()
    rs = d.get("rule_stats")
    if rs:
        n = rs["合计（会同时生效的）"]
        vs = ("✓ 在临界点以内" if n <= rs["cliff"] else f"✗ 超过临界点 {n - rs['cliff']} 条 —— 遵循率已进入崩塌区")
        print(f"强制语句密度（遵循率崩塌临界点 = {rs['cliff']} 条）")
        print(f"  AGENTS.md {rs['AGENTS.md']} 条 / 人设卡 {rs['人设卡']} 条 / SEEP.md {rs['SEEP.md']} 条")
        print(f"  合计同时生效 ≈ {n} 条   {vs}")
        print("  依据：arXiv 2608.02639（20 条同时生效 → Claude 60% / Gemini 43% / GPT-5-mini 20% 遵循率）；")
        print("        arXiv 2502.12197（护栏越多，表现一致趋向零）。再多写不叫保险，叫稀释。")
    print()
    print("读法：")
    print("  · 只有「可控制小计」是我们的责任；宿主基座（默认提示词 + 工具声明）改不动，只报告。")
    print("  · 真正干活的技能（00-analysis 等）是按需加载的，不进这张表 —— 它们的问题是不被加载，不是太大。")
    print("  · 唯一口径见 REQUIREMENTS.md 的预算/可维护性要求与本脚本常量；别处出现的数字一律以这里为准。")


def prompt_main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ceiling", type=int, default=CEILING_CONTROLLABLE,
                    help="可控制层 token 上限（默认 3500；宿主基座只报告）")
    ap.add_argument("--anchor", type=int, default=MEASURED_ANCHOR,
                    help="实测首次调用的 input+cacheRead（用于反推宿主自带部分）")
    ap.add_argument("--diff", default=None, help="与另一次 --json 输出比较")
    a = ap.parse_args()
    if a.ceiling <= 0:
        ap.error("--ceiling must be positive")

    d = build(a.ceiling, a.anchor)

    if a.diff:
        try:
            old = json.load(open(a.diff, encoding="utf-8"))
        except Exception as e:
            print(f"[ERROR] 读不了 {a.diff}: {e}", file=sys.stderr)
            return 2
        oldm = {r["layer"]: r["tokens"] for r in old.get("layers", [])}
        print(f"对比：{a.diff}\n")
        print(f"{'层':44s} {'before':>8s} {'after':>8s} {'delta':>8s}")
        print("-" * 74)
        for r in sorted(d["layers"], key=lambda x: -x["tokens"]):
            b = oldm.get(r["layer"], 0)
            dl = r["tokens"] - b
            print(f"{r['layer'][:44]:44s} {b:8d} {r['tokens']:8d} {dl:+8d}")
        print("-" * 74)
        print(f"{'合计':44s} {old.get('total_tokens', 0):8d} {d['total_tokens']:8d} "
              f"{d['total_tokens'] - old.get('total_tokens', 0):+8d}")
        return 0

    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=1))
    else:
        render(d)
    return 0 if d.get("controllable_tokens", 0) <= d.get("controllable_ceiling", CEILING_CONTROLLABLE) else 1


def _dispatch():
    # 管道/GBK 控制台下中文与 ✓✗ 会 UnicodeEncodeError → 统一 UTF-8（脚本级，别指望调用方）
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if "--prompt" in sys.argv[1:]:
        sys.argv = [sys.argv[0]] + [a for a in sys.argv[1:] if a != "--prompt"]
        return prompt_main()
    return main(sys.argv[1:]) or 0


if __name__ == "__main__":
    sys.exit(_dispatch())
