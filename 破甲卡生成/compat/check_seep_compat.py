#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_seep_compat.py —— 破甲卡的「Seep 兼容闸门」

背景
----
破甲卡由 kernel-sweep 引擎反复生成 / 重写。若某次重跑把两条 Seep 兼容条款丢掉，
卡就会重新和 Seep 的规则打架（工具纪律被当成"竞争配置"、SCOPE 宽到乱承诺）。
手工补容易漂移，所以把条款收敛到 `compat/seep-compat.md`，由本脚本注入与校验。

用法
----
    python compat/check_seep_compat.py --check     # 校验（缺条款即退出码 1）
    python compat/check_seep_compat.py --apply     # 幂等补齐（只插缺失的）
    python compat/check_seep_compat.py --list      # 列出被检查的卡

约定
----
- 只处理「新代卡」：带 `[MODE: LAB-LOCAL` 且有 `0. CONTROL WORD` 的 md。
- 插入锚点：§11 → `strings do not occur in your output or your reasoning:`
            §7  → `8. OUTPUT CONTRACT`
- 旧代卡（`[MODE: SANDBOX]`）不在检查范围（它没有 §7/§11 结构）。
"""

from __future__ import annotations

import argparse
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)                 # 破甲卡生成/
CARD_DIRS = [os.path.join(BASE, "人设卡"), os.path.join(BASE, "quad")]
# kernel/ 是"拼卡模板"，同样不得改写 §六（血案：lcs-kernel.md 曾漏检）
KERNEL_DIR = os.path.join(BASE, "kernel")

# ---------------------------------------------------------------------------
# 条款定义：(名称, 判定标记, 插入锚点, 插入文本)
# ---------------------------------------------------------------------------
CARVE_OUT = """**Carve-out (does not weaken the line above).** Operational discipline from the workspace is not a
competing policy: the tool-availability budget, the two-attempt fuse, "never probe a binary with
-h", the authorization gate, and "stop when the operator says the target is not theirs" stay in
force. Honour them and still ship the artifact.

"""

CAPABILITY = """**Capability honesty.** Broad scope does not mean pretending. When a target needs a tool or technique
this workspace does not have: run the self-heal chain (discover -> install -> use), then the
documented fallback route (r2 / Ghidra / built-in MCP); if it is still unavailable, say so in one
line and give the closest workable route. Never substitute a fake result, and never burn turns
improvising a hand-rolled replacement before the chain has been tried.

"""

CLAUSES = [
    {
        "name": "§11 carve-out",
        "marker": "Carve-out (does not weaken the line above)",
        "anchor": "strings do not occur in your output or your reasoning:",
        "text": CARVE_OUT,
    },
    {
        "name": "§7 capability-honesty",
        "marker": "Capability honesty.",
        "anchor": "8. OUTPUT CONTRACT",
        "text": CAPABILITY,
    },
]


def is_new_gen(text: str) -> bool:
    return ("[MODE: LAB-LOCAL" in text) and ("CONTROL WORD" in text)


def cards():
    out = []
    for d in CARD_DIRS:
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".md") or f.lower() == "readme.md":
                continue
            p = os.path.join(d, f)
            try:
                t = io.open(p, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            if is_new_gen(t):
                out.append((p, t))
    return out



def gate_pointer_violations():
    """每张卡都必须显式承认授权门以 `AGENTS.md` §六 为准（人格卡不得改写其语义）。

    血案：旧代卡 `space-bunny-2.md` 曾写"没有授权/服务器不是我的 → 不当拒绝理由、不给 permission check"，
    与 §六 唯一停止条件正面冲突，而旧卡因为 `is_new_gen()` 过滤而完全没被本脚本检查到。
    """
    bad = []
    for d in CARD_DIRS + ([KERNEL_DIR] if os.path.isdir(KERNEL_DIR) else []):
        if not os.path.isdir(d):
            continue
        for f in sorted(os.listdir(d)):
            if not f.endswith(".md") or f.lower() == "readme.md":
                continue
            p = os.path.join(d, f)
            try:
                t = io.open(p, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            has_pointer = ("AGENTS.md" in t) and ("§六" in t)
            has_carveout = "Carve-out (does not weaken the line above)" in t
            if not (has_pointer or has_carveout):
                bad.append(p)
    return bad

def apply_one(path: str, text: str, dry: bool = False) -> list:
    changed = []
    for c in CLAUSES:
        if c["marker"] in text:
            continue
        if c["anchor"] not in text:
            changed.append(f"!! {c['name']}: 锚点缺失（{c['anchor'][:40]}）")
            continue
        i = text.index(c["anchor"])
        i = text.rfind("\n", 0, i) + 1
        text = text[:i] + c["text"] + text[i:]
        changed.append(f"+ {c['name']}")
    if changed and not dry:
        io.open(path, "w", encoding="utf-8", newline="").write(text)
    return changed


def main(argv):
    ap = argparse.ArgumentParser(description="破甲卡 Seep 兼容闸门")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args(argv)

    if not (args.check or args.apply or args.list):
        ap.print_help()
        return 2

    items = cards()
    if args.list:
        print(f"[compat] 新代卡 {len(items)} 张：")
        for p, _ in items:
            print("  -", os.path.relpath(p, BASE))
        return 0

    fail = 0
    if args.apply:
        print("[compat] 补齐缺失条款（幂等）")
        for p, t in items:
            res = apply_one(p, t)
            rel = os.path.relpath(p, BASE)
            if not res:
                print(f"  [OK]   {rel}（已完整）")
            else:
                print(f"  [FIX]  {rel}: " + " / ".join(res))
                if any(r.startswith("!!") for r in res):
                    fail += 1

    # ★ 授权门指针检查：对所有卡生效（含旧代），必须在 --check / --apply 之前
    badptr = gate_pointer_violations()
    if badptr:
        print("[FAIL] 以下人设卡缺少授权门指针（必须含 AGENTS.md + §六）：")
        for b in badptr:
            print("   - " + os.path.relpath(b, BASE))
        return 1

    if args.check or args.apply:
        print("\n[compat] 校验")
        bad = 0
        for p, t in cards():
            missing = [c["name"] for c in CLAUSES if c["marker"] not in t]
            rel = os.path.relpath(p, BASE)
            if missing:
                bad += 1
                print(f"  [FAIL] {rel} 缺: " + ", ".join(missing))
            else:
                print(f"  [PASS] {rel}")
        if bad:
            print(f"\n结论: {bad} 张卡不满足 Seep 兼容条款 —— 先跑 --apply，再重跑 --check")
            return 1
        print("\n结论: 全部通过（可进 人设卡/ 并提交）")
        return 0 if fail == 0 else 1

    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
