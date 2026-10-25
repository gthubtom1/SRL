#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""变异测试（植入失败）：故意弄坏 6 处，验证「检查项真的会红」。

为什么需要（2026-10-25，用户的核心质疑）：
    "你每次说没问题，我随便一指又有问题" —— 因为之前的检查只证明"好代码是绿的"，
    从没系统证明"坏代码会变红"。空判据、skip 记 pass、只查存在不查内容，都会让绿是假的。
    REA 的做法：植入 3 个**必须失败**的变体，任一通过 = oracle 坏了，之前所有绿灯作废。

做法：在**仓库内就地**注入 → 跑指定检查 → 断言它变红 → `git checkout` 还原（try/finally 保证）。
不拷贝整个仓库（250MB 太慢）。结束时校验工作区干净。

用法：
    python Tool/scripts/mutation.py            # 跑全部 6 个植入
    python Tool/scripts/mutation.py --fast     # 只跑 3 个快的
退出码：0 = 全部被抓；1 = 有漏网（说明对应判据是装饰品）
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY = sys.executable
ENV = dict(os.environ, PYTHONIOENCODING="utf-8")


def run(args, timeout=900):
    p = subprocess.run([PY] + args, cwd=ROOT, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", env=ENV, timeout=timeout)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def sh(cmd):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=ENV, shell=True)


def clean_git(extra_paths=()):
    sh("git checkout -- .")
    for p in extra_paths:
        if os.path.exists(p):
            os.remove(p)


IMPLANTS = []


def implant(name, checker, expect, fast=True):
    """expect = 必须命中的判据关键字（防止"别的判据红了"被误当作抓住）。"""
    def deco(fn):
        IMPLANTS.append((name, checker, expect, fast, fn))
        return fn
    return deco


# ── 1. 改一条案例 MANIFEST 哈希 → gate 必须红 ─────────────────────
@implant("篡改案例 MANIFEST 哈希", ["Tool/scripts/gate.py", "--all"], "softseep")
def m1():
    p = "Tool/cases/golden-crackme/artifacts/MANIFEST.sha256"
    lines = open(p, encoding="utf-8").read().splitlines()
    for i, l in enumerate(lines):
        if l.strip() and not l.startswith("#"):
            h, rest = l.split(None, 1)
            lines[i] = ("0" * 64 if h[0] != "0" else "1" * 64) + " " + rest
            break
    open(p, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")


# ── 2. 让一条技能描述丢掉触发词 → 触发面探针必须红 ────────────────
@implant("删掉技能描述里的触发词", ["Tool/scripts/preflight.py", "--fast"], "触发面")
def m2():
    p = "Tool/skill/softseep/SKILL.md"
    s = open(p, encoding="utf-8").read()
    s = s.replace("初步分析这个软件", "分析一下", 1)
    open(p, "w", encoding="utf-8", newline="\n").write(s)


# ── 3. 给非总控技能加"总控"字样 → 总控唯一判据必须红 ──────────────
@implant("给普通域技能加自称总控", ["Tool/scripts/preflight.py", "--fast"], "总控唯一")
def m3():
    p = "Tool/skill/apkseep/SKILL.md"
    s = open(p, encoding="utf-8").read()
    open(p, "w", encoding="utf-8", newline="\n").write("<!-- 本文件是总控 Orchestrator -->\n" + s)


# ── 4. 在部署目录放假提示词 → 提示词残留必须红 ────────────────────
@implant("往部署目录放假提示词", ["Tool/scripts/preflight.py", "--fast"], "提示词残留")
def m4():
    d = os.path.expanduser("~/.pi/agent/prompts")
    os.makedirs(d, exist_ok=True)
    open(os.path.join(d, "zz-mutation.md"), "w", encoding="utf-8").write("---\ndescription: x\n---\n")
    return [os.path.join(d, "zz-mutation.md")]


# ── 5. 给 pack.json 加未知字段 → gate G2 必须红 ──────────────────
@implant("给 pack.json 加未知字段", ["Tool/scripts/gate.py", "--all"], "pwn-crypto")
def m5():
    p = "Tool/skill/pwn-crypto/pack.json"
    d = json.load(open(p, encoding="utf-8"))
    d["zz_unknown_field"] = True
    open(p, "w", encoding="utf-8", newline="\n").write(json.dumps(d, ensure_ascii=False, indent=2) + "\n")


# ── 6. 把事实漂移判据的依据改错（描述里写个假数字）→ 事实漂移必须红 ──
@implant("在活跃文档写错工具数", ["Tool/scripts/preflight.py", "--fast"], "事实漂移")
def m6():
    p = "README.md"
    s = open(p, encoding="utf-8").read()
    s = s.replace("20 个工具", "99 个工具", 1)
    open(p, "w", encoding="utf-8", newline="\n").write(s)


def main():
    ap = argparse.ArgumentParser(description="变异测试：植入失败，验证门禁真的会红")
    ap.add_argument("--fast", action="store_true", help="只跑快的子集")
    a = ap.parse_args()

    if sh("git status --porcelain").stdout.strip():
        print("[拒] 工作区不干净（有未提交改动）。先 commit/stash 再跑，避免误还原。")
        return 2

    picked = [x for x in IMPLANTS if (not a.fast) or x[2]]
    print("变异测试：%d 个植入（就地注入 → 跑检查 → git checkout 还原）\n" % len(picked))
    rows = []
    try:
        for name, checker, expect, _fast, fn in picked:
            clean_git()
            extra = fn() or []
            rc, out = run(checker)
            # 关键：必须由**期望的判据**抓到，其它判据红不算数（防"串谋掩盖"）
            hit_line = ""
            for line in (out or "").splitlines():
                if "[FAIL]" in line and expect in line:
                    hit_line = line.strip()
                    break
            caught = bool(hit_line)
            if not caught:
                other = ""
                for line in (out or "").splitlines():
                    if "[FAIL]" in line:
                        other = line.strip()
                        break
                hit_line = "未命中「%s」%s" % (expect, ("；其它红：" + other[:60]) if other else "")
            rows.append((name, caught, hit_line[:110]))
            clean_git(extra)
    finally:
        clean_git()

    print("%-30s %-6s %s" % ("植入", "被抓", "命中的检查"))
    print("-" * 96)
    for name, caught, hit in rows:
        print("%-30s %-6s %s" % (name, "是" if caught else "**否**", hit))
    print("-" * 96)
    ok = sum(1 for _, c, _ in rows if c)
    print("结果: %d/%d 变异被抓%s" % (ok, len(rows), "" if ok == len(rows) else "  ← 有漏网：该判据是装饰品"))
    dirty = sh("git status --porcelain").stdout.strip()
    if dirty:
        print("[!!] 还原后工作区仍不干净，请手动检查：\n" + dirty[:400])
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
