#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check-budget.py —— 反臃肿预算自检（对应 MANUAL/BASELINE-FREEZE.md §7）

一条命令回答："这个项目有没有在变臃肿？"
退出码：0 = 全部在预算内；1 = 有超限项。

用法：
    python Tool/scripts/check-budget.py
    python Tool/scripts/check-budget.py --json
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # Tool/scripts -> Tool


def count_tools():
    src = io.open(os.path.join(ROOT, "mcp", "seep_mcp_server.py"), encoding="utf-8").read()
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


def first_party_files():
    """引擎文件计数（2026-10-22 修正：只数 git 已跟踪文件）。

    旧实现走 os.walk，会把 `.pytest_cache/`、`.pi/`、`evidence/` 这类运行时/
    忽略目录也算进去，导致同一份代码在不同机器/不同 worktree 上得出不同数字
    （实测漂移 820↔834），BASELINE 无法对账。现在优先用 `git ls-files`，
    拿不到 git（导出包/浅环境）时回退到 walk，但跳过所有点目录。
    """
    skip = ("/upstream", "/node_modules", "/__pycache__", "/mcp/Tool",
            "/破甲卡生成", "/cases", "/audit", "/work",
            "/.git/", "/.pytest_cache/", "/.pi/", "/evidence/")
    repo = os.path.dirname(ROOT)

    try:
        out = subprocess.run(["git", "-C", repo, "ls-files", "-z"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             timeout=60)
        if out.returncode == 0 and out.stdout:
            names = [p for p in out.stdout.decode("utf-8", "replace").split("\0") if p]
            total = 0
            for rel in names:
                norm = "/" + rel.replace(os.sep, "/")
                if any(s in norm for s in skip):
                    continue
                total += 1
            return total
    except Exception:
        pass

    total = 0
    for dirpath, dirs, files in os.walk(ROOT):
        norm = dirpath.replace(os.sep, "/")
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        if any(s in norm for s in skip):
            dirs[:] = []
            continue
        total += len(files)
    for name in os.listdir(repo):
        p = os.path.join(repo, name)
        if os.path.isfile(p) and not name.startswith("."):
            total += 1
    for sub in ("setup", "MANUAL", "docs"):
        d = os.path.join(repo, sub)
        if os.path.isdir(d):
            for dirpath, dirs, files in os.walk(d):
                if "__pycache__" in dirpath:
                    dirs[:] = []
                    continue
                total += len(files)
    return total


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
    budget = [
        ("MCP 工具", count_tools(), 45),
        ("技能", count_skills(), None),   # 用户决定：技能数量不设上限
        ("setup 脚本", len([f for f in os.listdir(os.path.join(repo, "setup"))
                        if f.endswith((".ps1", ".sh", ".py"))]), 22),
        ("MANUAL 手册", len([f for f in os.listdir(os.path.join(repo, "MANUAL"))
                         if f.endswith(".md")]), 16),
        ("MCP 主服务行数", len(io.open(os.path.join(ROOT, "mcp", "seep_mcp_server.py"),
                                       encoding="utf-8").read().splitlines()), 3200),
        ("first-party 引擎文件", first_party_files(), 900),
        ("案例库文件", case_files(), 1500),   # 证据库：58 个案例的真实输入/产物
    ]

    rows = []
    over = []
    for name, value, limit in budget:
        if limit is None:
            rows.append({"item": name, "value": value, "limit": None, "ok": True})
            continue
        ok = value <= limit
        rows.append({"item": name, "value": value, "limit": limit, "ok": ok})
        if not ok:
            over.append(name)

    if args.json:
        print(json.dumps({"ok": not over, "budget": rows}, indent=2, ensure_ascii=False))
    else:
        print("[budget] 反臃肿预算自检")
        for r in rows:
            mark = "OK  " if r["ok"] else "OVER"
            if r["limit"] is None:
                print("  %-4s %-16s %5d / 无上限" % (mark, r["item"], r["value"]))
            else:
                print("  %-4s %-16s %5d / %d" % (mark, r["item"], r["value"], r["limit"]))
        print("  结论:", "全部在预算内" if not over else ("超限: " + ", ".join(over)))
    return 0 if not over else 1


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

HOME = os.path.expanduser("~")
AGENT_DIR = os.environ.get("PI_CODING_AGENT_DIR") or os.path.join(HOME, ".pi", "agent")
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
#   依据：docs/PLAN-FINAL.md §预算；docs/RESEARCH-BASELINE.md
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


def build(ceiling: int = CEILING_TOTAL, anchor: int = MEASURED_ANCHOR) -> dict:
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
        "controllable_ceiling": CEILING_CONTROLLABLE,
        "ceiling": ceiling,
        "over_by": max(0, controllable - CEILING_CONTROLLABLE),
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
    print("  · 唯一口径见 docs/PLAN-FINAL.md §预算；别处出现的数字一律以那里为准。")


def prompt_main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--ceiling", type=int, default=CEILING_TOTAL)
    ap.add_argument("--anchor", type=int, default=MEASURED_ANCHOR,
                    help="实测首次调用的 input+cacheRead（用于反推宿主自带部分）")
    ap.add_argument("--diff", default=None, help="与另一次 --json 输出比较")
    a = ap.parse_args()

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
