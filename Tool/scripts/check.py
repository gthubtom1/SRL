#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一条命令跑完全部检查（程序员视角：这就是 `make test`）。

为什么要有这个文件（2026-10-24）：之前在 AGENTS / README / 对话里出现 6 条命令、163 项"门禁"，
使用者根本不知道"合格"指什么。真正的程序员做法是：**一个入口，退出码，失败指到文件**。

用法：
    python Tool/scripts/check.py            # 全量（约 3-4 分钟）
    python Tool/scripts/check.py --fast     # 只跑快的（约 1 分钟；提交前用）
    python Tool/scripts/check.py --list     # 列出会跑哪些套件
    python Tool/scripts/check.py --fix      # 只重生成**生成物**（docs/HANDOFF.md 状态块）；不改期望值

`--fix` / `--prep` 的边界（第 4 轮评审 P1-1；PM-SPEC §8）：
    **只许重生成生成物，不许把期望值改成当前实测。**
    - 会改：docs/HANDOFF.md 的 §1 状态块（它就是 `case_state.py handoff --repo` 的输出，
      标着「生成，勿手改」；不改它就必然红「落后 ≤1 提交」）。
    - 不会改：MANUAL/BASELINE-FREEZE.md 里的 first-party 文件数等**期望值**。
      检测到漂移时只打印漂移 + 修法，让人自己决定改数字还是改代码。
      理由：期望值一旦被脚本跟着实测跑，「基数在涨」就永远绿 —— 判据变成自证。

退出码：0 = 无失败（可能仍有 WARN/跳过）；1 = 有失败。任何失败都会打印套件名 + 首行原因。
--fast 跳过 e2e/kb-tests/mutation 时，结尾不会写“全部通过”，而是“全部套件完成：PASS a / WARN b”。
unit（gate.py --all）接受 rc ∈ {0,3}；rc=3 表示结构通过但可用性未证明，记为 WARN。
"""
import argparse
import os
import re
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
    ("kb-colloquial", ["Tool/scripts/test_kb_colloquial.py"], True,
     "口语检索：12 条大白话能否落到真实文章（别名表 + CJK 2-gram，门槛 >=10/12）"),
    ("route-tests", ["Tool/skill/softseep/scripts/skill-route-probe.py", "--json"], True,
     "路由探针：技能路由在中文边界上的行为"),
    ("rewrite-parity", ["Tool/scripts/rewrite-route-parity.py", "--json"], True,
     "改写同域：客户原话被安全词表改写后仍落原域（词表从 .ts 现读，不做 Python 抄本）"),
    ("tool-autonomy", ["Tool/scripts/test_tool_autonomy.py"], True,
     "工具自治锁：用工具静默（MCP/工具链/技能脚本）、只有跑本案目标才要回执"),
    ("read-guard",  ["Tool/scripts/test_read_guard.py"], True,
     "读守卫：个人隐私区路径拦、正常目标/案件路径放行"),
    ("pre-upload",  ["Tool/scripts/pre-upload-check.py"], True,
     "上传前体检：会进 git 的敏感文件 / 本机不该外带的目录 / 内容级凭据命中（只报文件:行+类型）"),
    ("tool-readiness", ["Tool/scripts/tool-readiness.py"], True,
     "六工具就绪表：探测/安装计划/自检机制可用（不要求本机 6 个都 READY）"),
    ("invariants",  ["Tool/scripts/invariants.py", "--check"], True,
     "架构不变量：11 域 × 9 条（入口唯一/能力可达/交接闭包/证据同构/等级唯一/失败可表达/见证可跑/部署等价/能力有路线）"),
    ("gate-tests",  ["Tool/scripts/test_gates.py"], True,
     "闸的行为测试：首答闸 9 + 运行回执闸 6 + 写守卫 4 + cmd-guard 8 + 熔断合法出口 2（node 真跑 TS 纯函数；缺 node 直接 FAIL）"),
    ("unit",        ["Tool/scripts/gate.py", "--all"], True,
     "按域判定：9 个能力包各自的门槛与证据强度"),
    ("e2e",         ["Tool/scripts/domain-gate.py", "--all"], False,
     "端到端：域契约、证据链、清理、部署哈希"),
    ("kb-tests",    ["Tool/scripts/kb_acceptance.py"], False,
     "知识库检索验收语料"),
    ("mutation",    ["Tool/scripts/mutation.py"], False,
     "植入失败：故意弄坏 6 处，证明判据真的会红（约 3 分钟）"),
]


def report_baseline_drift():
    """检测 BASELINE-FREEZE 的期望值与实测是否漂移 —— 只报修法，绝不写文件。"""
    import re as _re
    bp = os.path.join(ROOT, "MANUAL", "BASELINE-FREEZE.md")
    try:
        p = subprocess.run([PY, os.path.join(ROOT, "Tool", "scripts", "preflight.py"), "--fast"],
                           cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=300,
                           env=CHILD_ENV).stdout
    except Exception as e:  # noqa: BLE001
        print("[BASELINE] 漂移检测未完成（%s）：未写入任何文件" % str(e)[:60])
        return
    drift = [l.strip() for l in (p or "").splitlines() if "BASELINE-FREEZE:" in l]
    if not drift:
        print("[BASELINE] 无漂移（期望值与实测一致，或本轮没跑到该项）")
        return
    print("[BASELINE] 检测到漂移（只报，不改）：")
    for d in drift:
        print("  - " + d)
    m = _re.search(r"first-party\s*写\s*(\d+)[^0-9]*(\d+)", " ".join(drift))
    expect, actual = (m.group(1), m.group(2)) if m else ("<写死值>", "<实测值>")
    line_no = "?"
    try:
        # 取**度量行**（形如 `| first-party 文件（口径…） | 940 | **950** |`）：
        # 只写“first-party 文件数”的叙述行不能当成那个格子。
        for i, ln in enumerate(open(bp, encoding="utf-8", errors="replace").read().splitlines(), 1):
            if "first-party" in ln and _re.search(r"\|\s*\d{1,5}\s*\|", ln):
                line_no = str(i)
                break
    except Exception:  # noqa: BLE001
        pass
    print("[BASELINE] 拒绝改期望：期望值 %s / 实测 %s —— 脚本不替人改基线（PM-SPEC §8）"
          % (expect, actual))
    print("[BASELINE] 修法（二选一，都由人决定并留下理由）：")
    print("  1) 这次增长/收缩是**有意**的 → 手工改 %s:%s 把 %s 改成 %s，"
          "并在 docs/CHANGELOG.md 记一条为什么放宽/收紧；"
          % (os.path.join("MANUAL", "BASELINE-FREEZE.md"), line_no, expect, actual))
    print("  2) 是**意外**新增文件 → 不要动基线：把多出来的文件删掉或加进 .gitignore，"
          "让实测回到 %s；" % expect)
    print("  复核：python Tool/scripts/preflight.py --fast 2>&1 | grep BASELINE")
    print("[BASELINE] 未写入任何文件（--fix 只重生成生成物，不改期望）")


def run_one(name, argv, timeout=600, allow_rc=(0,)):
    t0 = time.time()
    try:
        p = subprocess.run([PY] + argv, cwd=ROOT, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout,
                           env=CHILD_ENV)
        out = (p.stdout or "") + (p.stderr or "")
        rc = p.returncode
    except subprocess.TimeoutExpired:
        return name, False, "超时（>%ds）" % timeout, time.time() - t0, -1, ""
    if "--json" in argv and "{" in out:
        import json as _j
        try:
            d = _j.loads(out[out.index("{"):])
            if isinstance(d, dict) and "ok" in d:
                return name, rc in allow_rc and d.get("ok") is True, "ok=%r" % d.get("ok"), time.time() - t0, rc, out
        except Exception:
            pass
    # 取最后一行有信息量的输出（各脚本末行通常是「结果: x/y」或 [GATE] …）
    # gate.py 现在会在 pass/fail 之后追加「见证证据 real/public/self-built/fixture」几行；
    # 摘要必须仍取带 pass/fail 的判定行，不能取到分档清单（否则 check.py 的 tail 会说假话）。
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    tail = ""
    for l in reversed(lines):
        if ("结果:" in l) or ("[GATE]" in l and "pass" in l and "fail" in l) \
                or ("[VERIFY]" in l) or ("ok" in l.lower()):
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
    return name, rc in allow_rc, tail, time.time() - t0, rc, out


def main():
    ap = argparse.ArgumentParser(
        description="跑全部检查（相当于 make test）",
        epilog="--fix / --prep 的边界：只重生成生成物（docs/HANDOFF.md 状态块）；"
               "**不会**把 MANUAL/BASELINE-FREEZE.md 等期望值改成当前实测（PM-SPEC §8）。"
               "检测到漂移时只打印漂移与修法，由人决定改数字还是改代码。")
    ap.add_argument("--fast", action="store_true", help="只跑快的子集（提交前用）")
    ap.add_argument("--list", action="store_true", help="列出套件后退出")
    ap.add_argument("--env", action="store_true", help="只做环境体检（这台机器装没装好）")
    ap.add_argument("--fix", dest="full_prep", action="store_true",
                    help="【只改生成物】检查前重生成 docs/HANDOFF.md 状态块；"
                         "**不改** MANUAL/BASELINE-FREEZE.md 的期望值（漂移只报修法，见 --help 顶部）")
    ap.add_argument("--prep", dest="full_prep", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--fix-handoff", action="store_true", help=argparse.SUPPRESS)
    a = ap.parse_args()

    if a.full_prep:
        print("[注意] --fix 只重生成**生成物**（docs/HANDOFF.md 状态块）；"
              "MANUAL/BASELINE-FREEZE.md 的期望值不会被改写。单纯检查请不带参数。")
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
        # ★ P1-1（第 4 轮评审）：这里原来会把 MANUAL/BASELINE-FREEZE.md 的 first-party 数
        #   改写成 preflight 的实测值 —— 那正是 PM-SPEC §8 禁止的「把期望改成当前实际」
        #   （文件每加一个就涨，判据永远绿 = 判据自证）。现在只**检测漂移并打印修法**，
        #   一个字节都不写：改期望是人的决定，不是脚本的副作用。
        report_baseline_drift()

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
    failed, warned = [], []
    for name, argv, _fast, why in suites:
        # unit（gate.py --all）：rc=3 = 结构通过、可用性未证明。不是失败，但必须打成 WARN。
        allow = (0, 3) if name == "unit" else (0,)
        n, ok, tail, secs, rc, out = run_one(name, argv, allow_rc=allow)
        mark = "PASS" if ok else "FAIL"
        if ok and rc == 3:
            nw = zr = "?"
            for ln in out.splitlines():
                # 四档摘要：real / public / self-built / fixture。没见证的包 = self-built+fixture。
                m = re.search(r"见证证据：real \d+ / public \d+ / self-built (\d+) / fixture (\d+)", ln)
                if m:
                    nw = str(int(m.group(1)) + int(m.group(2)))
                m = re.search(r"交付承诺 vs 账本：(\d+) 个案例", ln)
                if m:
                    zr = m.group(1)
                if "交付承诺 vs 账本：一致" in ln:
                    zr = "0"
            mark = "WARN"
            tail = "结构通过、可用性未证明（无真实产物见证 %s 域 / 零重放 %s）" % (nw, zr)
            warned.append((name, tail))
        print("%s %-14s %5.1fs  %s" % (mark, name, secs, tail[:110]))
        if not ok:
            failed.append((name, why, tail))

    print("-" * 72)
    for name, tail in warned:
        print("WARN %s —— %s" % (name, tail))
    if not failed and not warned and not skipped:
        print("全部通过（%d 个套件）" % len(suites))
        return 0
    if not failed:
        print("全部套件完成：PASS %d / WARN %d（跳过 %d 个：%s）"
              % (len(suites) - len(warned), len(warned), len(skipped),
                 ",".join(skipped) if skipped else "无"))
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
