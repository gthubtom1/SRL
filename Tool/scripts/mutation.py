#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""变异测试（植入失败）：故意弄坏 6 处，验证「检查项真的会红」。

为什么需要（2026-10-25 用户的核心质疑）：
    "你每次说没问题，我随便一指又有问题" —— 因为检查只证明"好代码是绿的"，
    从没系统证明"坏代码会变红"。空判据、skip 记 pass、只查存在不查内容、被别的红掩盖，
    都会让绿是假的。REA 的做法：植入 3 个必须失败的变体，任一通过 = oracle 坏了。

做法：**只备份/还原本套件动过的那几个文件**（不依赖 git、不拷贝 250MB 仓库），
逐个植入 → 跑检查 → 断言**指定判据**变红（其它判据红不算）→ 还原。

用法：python Tool/scripts/mutation.py [--fast]
退出码：0 = 全部被抓；1 = 有漏网（该判据是装饰品）
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


class Snap:
    """只记录被改动文件的原始字节；还原时写回，其余文件一概不碰。"""

    def __init__(self):
        self.items = {}
        self.created = []

    def take(self, rel):
        p = os.path.join(ROOT, rel)
        if os.path.isfile(p):
            self.items[p] = open(p, "rb").read()
        return p

    def track_created(self, p):
        self.created.append(p)

    def restore(self):
        for p, blob in self.items.items():
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "wb").write(blob)
        for p in self.created:
            try:
                if os.path.isfile(p):
                    os.remove(p)
            except Exception:
                pass
        self.items.clear()
        self.created.clear()


IMPLANTS = []


def implant(name, checker, expect, fast=True):
    def deco(fn):
        IMPLANTS.append((name, checker, expect, fast, fn))
        return fn
    return deco


# ── 1. 改一条案例 MANIFEST 哈希 → gate 必须红 ─────────────────────
@implant("篡改案例 MANIFEST 哈希", ["Tool/scripts/gate.py", "--all"], "softseep")
def m1(sn):
    rel = "Tool/cases/golden-crackme/artifacts/MANIFEST.sha256"
    p = sn.take(rel)
    lines = open(p, encoding="utf-8").read().splitlines()
    for i, l in enumerate(lines):
        if l.strip() and not l.startswith("#"):
            h, rest = l.split(None, 1)
            lines[i] = ("0" * 64 if h[0] != "0" else "1" * 64) + " " + rest
            break
    open(p, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")


# ── 2. 把一条技能描述换成中性描述 → 触发面探针必须红 ──────────────
@implant("删掉技能描述里的触发词", ["Tool/scripts/preflight.py", "--fast"], "触发面")
def m2(sn):
    import re as _re
    p = sn.take("Tool/skill/softseep/SKILL.md")
    src = open(p, encoding="utf-8").read()
    out = _re.sub(r"^description:.*$", 'description: "通用二进制分析工具"', src, count=1, flags=_re.M)
    open(p, "w", encoding="utf-8", newline="\n").write(out)


# ── 3. 给普通域技能加"总控"字样 → 总控唯一判据必须红 ──────────────
@implant("给普通域技能加自称总控", ["Tool/scripts/preflight.py", "--fast"], "总控唯一")
def m3(sn):
    p = sn.take("Tool/skill/apkseep/SKILL.md")
    s = open(p, encoding="utf-8").read()
    open(p, "w", encoding="utf-8", newline="\n").write("<!-- 本文件是总控 Orchestrator -->\n" + s)


# ── 4. 在部署目录放假提示词 → 提示词残留必须红 ────────────────────
@implant("往部署目录放假提示词", ["Tool/scripts/preflight.py", "--fast"], "提示词残留")
def m4(sn):
    d = os.path.expanduser("~/.pi/agent/prompts")
    os.makedirs(d, exist_ok=True)
    fp = os.path.join(d, "zz-mutation.md")
    open(fp, "w", encoding="utf-8").write("---\ndescription: x\n---\n")
    sn.track_created(fp)


# ── 5. 给 pack.json 加未知字段 → gate G2 必须红 ──────────────────
@implant("给 pack.json 加未知字段", ["Tool/scripts/gate.py", "--all"], "pwn-crypto")
def m5(sn):
    p = sn.take("Tool/skill/pwn-crypto/pack.json")
    d = json.load(open(p, encoding="utf-8"))
    d["zz_unknown_field"] = True
    open(p, "w", encoding="utf-8", newline="\n").write(json.dumps(d, ensure_ascii=False, indent=2) + "\n")


# ── 6. 在活跃文档写错工具数 → 事实漂移必须红 ─────────────────────
@implant("在活跃文档写错工具数", ["Tool/scripts/preflight.py", "--fast"], "事实漂移")
def m6(sn):
    p = sn.take("README.md")
    s = open(p, encoding="utf-8").read()
    open(p, "w", encoding="utf-8", newline="\n").write(s.replace("20 个工具", "99 个工具", 1))


def main():
    ap = argparse.ArgumentParser(description="变异测试：植入失败，验证门禁真的会红")
    ap.add_argument("--fast", action="store_true", help="只跑快的子集")
    a = ap.parse_args()
    picked = [x for x in IMPLANTS if (not a.fast) or x[3]]
    print("变异测试：%d 个植入（只备份/还原本套件动过的文件）\n" % len(picked))
    rows = []
    for name, checker, expect, _fast, fn in picked:
        sn = Snap()
        try:
            fn(sn)
            rc, out = run(checker)
            hit = ""
            for line in (out or "").splitlines():
                if "[FAIL]" in line and expect in line:
                    hit = line.strip()
                    break
            if not hit:
                other = ""
                for line in (out or "").splitlines():
                    if "[FAIL]" in line:
                        other = line.strip()
                        break
                hit = "未命中「%s」%s" % (expect, ("；其它红：" + other[:60]) if other else "（全绿）")
            rows.append((name, bool(hit) and "[FAIL]" in hit, hit[:110]))
        finally:
            sn.restore()

    print("%-30s %-6s %s" % ("植入", "被抓", "命中的检查"))
    print("-" * 100)
    for name, caught, hit in rows:
        print("%-30s %-6s %s" % (name, "是" if caught else "**否**", hit))
    print("-" * 100)
    ok = sum(1 for _, c, _ in rows if c)
    print("结果: %d/%d 变异被抓%s" % (ok, len(rows),
                                 "" if ok == len(rows) else "  ← 有漏网：该判据是装饰品"))
    return 0 if ok == len(rows) else 1


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
