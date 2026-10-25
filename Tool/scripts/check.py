#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一条命令跑完全部检查（程序员视角：这就是 `make test`）。

为什么要有这个文件（2026-10-24）：之前在 AGENTS / README / 对话里出现 6 条命令、163 项"门禁"，
使用者根本不知道"合格"指什么。真正的程序员做法是：**一个入口，退出码，失败指到文件**。

用法：
    python Tool/scripts/check.py            # 全量（约 3-4 分钟）
    python Tool/scripts/check.py --fast     # 只跑快的（约 1 分钟；提交前用）
    python Tool/scripts/check.py --list     # 列出会跑哪些套件

退出码：0 = 全过；1 = 有失败。任何失败都会打印套件名 + 首行原因。
"""
import argparse
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY = sys.executable

# 中文 Windows 控制台默认 cp936/GBK：本脚本自己会打中文与 ✓/✗，子脚本还会打 emoji，
# 不重建 stdout/stderr 就会自崩（F1）。errors="replace" 保证只影响显示、不影响判定。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 —— 流被替换/已被关闭时忽略
        pass

# 所有子进程统一走这个 env：一次修好全部子脚本，而不是逐个改。
# 没有它：任何子脚本 print 一个非 GBK 字符（✓/✗/emoji/中文标点）就会 UnicodeEncodeError，
# 而套件失败原因只会显示“Traceback …”，误号得像真问题。
CHILD_ENV = dict(os.environ, PYTHONIOENCODING="utf-8")

# (名字, 命令参数, 是否属于 fast, 失败时给人看的一句话)
SUITES = [
    ("lint",        ["Tool/scripts/preflight.py", "--fast"], True,
     "结构/契约/入口/部署的一致性检查"),
    ("skill-tests", ["Tool/skill/softseep/scripts/intent-coverage.py", "--json"], True,
     "意图探针：用户说法能否命中对应技能"),
    ("route-tests", ["Tool/skill/softseep/scripts/skill-route-probe.py", "--json"], True,
     "路由探针：技能路由在中文边界上的行为"),
    ("invariants",  ["Tool/scripts/invariants.py", "--check"], True,
     "架构不变量：11 域 × 9 条（入口唯一/能力可达/交接闭包/证据同构/等级唯一/失败可表达/见证可跑/部署等价/能力有路线）"),
    ("unit",        ["Tool/scripts/gate.py", "--all"], True,
     "按域判定：9 个能力包各自的门槛与证据强度"),
    ("e2e",         ["Tool/scripts/domain-gate.py", "--all"], False,
     "端到端：域契约、证据链、清理、部署哈希"),
    ("kb-tests",    ["Tool/scripts/kb_acceptance.py"], False,
     "知识库检索验收语料"),
    ("mutation",    ["Tool/scripts/mutation.py"], False,
     "植入失败：故意弄坏 6 处，证明判据真的会红（约 3 分钟）"),
]


def run_one(name, argv, timeout=600):
    t0 = time.time()
    try:
        p = subprocess.run([PY] + argv, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout,
                           env=CHILD_ENV)
        out = (p.stdout or "") + (p.stderr or "")
        rc = p.returncode
    except subprocess.TimeoutExpired:
        return name, False, "超时（>%ds）" % timeout, time.time() - t0
    if "--json" in argv and "{" in out:
        import json as _j
        try:
            d = _j.loads(out[out.index("{"):])
            if isinstance(d, dict) and "ok" in d:
                return name, rc == 0 and d.get("ok") is True, "ok=%r" % d.get("ok"), time.time() - t0
        except Exception:
            pass
    # 取最后一行有信息量的输出（各脚本末行通常是「结果: x/y」或 [GATE] …）
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    tail = ""
    for l in reversed(lines):
        if ("结果:" in l) or ("[GATE]" in l) or ("[VERIFY]" in l) or ("ok" in l.lower()):
            tail = l
            break
    if not tail:
        # JSON 型套件（intent-coverage / skill-route-probe）末尾不是人话，改成读 ok 字段
        import json as _j
        if "{" in out:
            try:
                d = _j.loads(out[out.index("{"):])
                tail = "ok=%r" % d.get("ok") if isinstance(d, dict) else ""
            except Exception:
                tail = ""
    tail = tail or (lines[-1] if lines else "")
    return name, rc == 0, tail, time.time() - t0


def main():
    ap = argparse.ArgumentParser(description="跑全部检查（相当于 make test）")
    ap.add_argument("--fast", action="store_true", help="只跑快的子集（提交前用）")
    ap.add_argument("--list", action="store_true", help="列出套件后退出")
    ap.add_argument("--env", action="store_true", help="只做环境体检（这台机器装没装好）")
    ap.add_argument("--fix", dest="full_prep", action="store_true",
                    help="【会改仓库】检查前重生成 HANDOFF 状态块 + 对齐 BASELINE-FREEZE（提交前用）")
    ap.add_argument("--prep", dest="full_prep", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--fix-handoff", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()

    if a.full_prep:
        print("[注意] --fix 会改写 docs/HANDOFF.md 与 MANUAL/BASELINE-FREEZE.md；"
              "单纯检查请不带参数。")
        # 提交/检查前先把 HANDOFF 状态块重生成（否则「落后 ≤1 提交」必然红）
        try:
            out = subprocess.run([PY, os.path.join(ROOT, "Tool", "scripts", "case_state.py"),
                                  "handoff", "--repo"], cwd=ROOT, capture_output=True,
                                 text=True, encoding="utf-8", errors="replace", timeout=120,
                                 env=CHILD_ENV).stdout
            hp = os.path.join(ROOT, "docs", "HANDOFF.md")
            if os.path.isfile(hp) and out.strip():
                src = open(hp, encoding="utf-8").read()
                head = src[:src.index("## §1 状态块（生成，勿手改）")]
                NL = chr(10)
                body = "## §1 状态块（生成，勿手改）" + NL + NL + out.strip() + NL
                open(hp, "w", encoding="utf-8", newline=NL).write(head + body)
                print("已重生成 HANDOFF 状态块")
        except Exception as e:  # noqa: BLE001
            print("HANDOFF 重生成失败：%s" % e)

    if a.full_prep:
        # 自动对齐 BASELINE-FREEZE 的 first-party 数（否则每加一个文件都要手改，反复红）
        try:
            import re as _re
            p = subprocess.run([PY, os.path.join(ROOT, "Tool", "scripts", "preflight.py"), "--fast"],
                               cwd=ROOT, capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=300,
                               env=CHILD_ENV).stdout
            m = _re.search(r"实测 (\d+)", p or "")
            if m:
                actual = int(m.group(1))
                bp = os.path.join(ROOT, "MANUAL", "BASELINE-FREEZE.md")
                src = open(bp, encoding="utf-8").read()
                out = _re.sub(r"\| \d{3,4} \| \*\*900\*\* \|", "| %d | **900** |" % actual, src, count=1)
                if out != src:
                    open(bp, "w", encoding="utf-8", newline=chr(10)).write(out)
                    print("已对齐 BASELINE-FREEZE：first-party = %d" % actual)
        except Exception as e:  # noqa: BLE001
            print("对齐基线失败：%s" % e)

    if a.env:
        # 环境体检 = env-check.py（装没装好）；与项目测试分开，但走同一个入口
        rc = subprocess.run([PY, os.path.join(ROOT, "Tool", "scripts", "env-check.py"), "--text"],
                            cwd=ROOT, env=CHILD_ENV).returncode
        print("环境体检：%s" % ("通过" if rc == 0 else "有问题（见上）"))
        return rc

    suites = [s for s in SUITES if (not a.fast) or s[2]]
    if a.list:
        for n, cmd, fast, why in suites:
            print("%-12s %-6s %s" % (n, "fast" if fast else "full", why))
        return 0

    skipped = [n for n, _c, fast, _w in SUITES if fast is False] if a.fast else []
    print("检查中（%s，%d 个套件）…" % ("fast" if a.fast else "full", len(suites)))
    if a.fast and skipped:
        print("[注意] --fast 跳过：%s —— 通过 ≠ 全部通过，交付判定请跑全量 check.py" % "、".join(skipped))
    print()
    failed = []
    for name, argv, _fast, why in suites:
        n, ok, tail, secs = run_one(name, argv)
        print("%s %-12s %5.1fs  %s" % ("PASS" if ok else "FAIL", name, secs, tail[:110]))
        if not ok:
            failed.append((name, why, tail))

    print("-" * 72)
    if not failed:
        print("全部通过（%d 个套件）" % len(suites))
        return 0
    print("失败 %d 个套件：" % len(failed))
    for name, why, tail in failed:
        print("  · %s —— %s" % (name, why))
        print("    %s" % tail[:160])
    print("\n单独复跑：python Tool/scripts/check.py --list 看各套件命令；或用上面套件名对应的脚本直接跑")
    return 1


if __name__ == "__main__":
    # stdout/stderr 已在模块顶部重建为 UTF-8（此处保留原防御式重建，便于被 -c/-m 方式拉起时也无差）
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    sys.exit(main())
