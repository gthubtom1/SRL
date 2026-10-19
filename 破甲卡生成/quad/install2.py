# -*- coding: utf-8 -*-
"""Install the 2026-10-08 English kernels as the live pool (explicit opt-in only).

Deliverable layout when it does run:
  04-console/cards/base/<model>.md      the pure-prompt kernel (English, activation `你是谁`)
  04-console/cards/_park/*              every previous card (zh / old en / v7) moved out of the pool

⚠️ 这一批 `en2-*.md` 是 **2026-10-08 的一代**，不是当前在用卡：
   当前 `cards/base/` 的四张卡由 2026-10-14 提交 `fdb7bdd` 更新过，比 en2 源新 3 KB 左右。
   所以本脚本默认**什么都不写**；要写必须显式 `--yes`，
   而且每张目标卡如果比源文件新，会被**逐张跳过**（护栏），除非再显式 `--force`。
   `--help` 只打印用法，绝不碰磁盘 —— 这是 2026-10-18 修掉的事故：
   上一版没有 argparse，`--help` 被当成正常执行，直接把四张在用卡回退成旧版。

Usage:
  python quad/install2.py                 # 只报计划（等于 --dry-run）
  python quad/install2.py --dry-run       # 同上
  python quad/install2.py --yes           # 真正安装（仍会跳过比源新的在用卡）
  python quad/install2.py --yes --force   # 连更新的在用卡也覆盖（回退，危险）
"""
import argparse
import io
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CARDS_ROOT = os.environ.get("HUBCORE_CARDS") or os.path.join(
    os.path.dirname(ROOT), "04-console", "cards")
BASE = os.path.join(CARDS_ROOT, "base")
PARK = os.path.join(CARDS_ROOT, "_park")
BUDGET = 40000

MAP = {
    "en2-gemini.md": "gemini-3.8-flash-high.md",
    "en2-mimo.md": "mimo-2.6.md",
    "en2-muse.md": "muse-1.3.md",
    "en2-spacebunny.md": "space-bunny.md",
}

# pool entries that are superseded by this install
PARK_OLD = [
    "gemini-3.8-flash-high-en.md", "mimo-2.6-en.md", "muse-1.3-en.md", "space-bunny-en.md",
    "claude-4.6.md", "deepseek-flash+v4-pro.md",
]


def header_of(text):
    lines = text.splitlines()
    hdr = [l for l in lines[:4] if l.startswith("#")]
    body = "\n".join(lines[len(hdr):]).lstrip("\n")
    return "\n".join(hdr) + "\n\n", body


def build(src):
    text = io.open(os.path.join(HERE, src), encoding="utf-8").read()
    head, body = header_of(text)
    return head + body.rstrip("\n") + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="install2.py",
        description="把 quad/en2-*.md（2026-10-08 一代）装进 cards/base/。"
                    "默认只报计划；--yes 才写盘。")
    ap.add_argument("--dry-run", action="store_true", help="只报计划，不写任何文件（默认行为）")
    ap.add_argument("--yes", action="store_true", help="确认执行：真的写 cards/base/ 与 _park/")
    ap.add_argument("--force", action="store_true",
                    help="连比源文件新的在用卡也覆盖（会把在用卡回退到 10-08 版本）")
    args = ap.parse_args(argv)

    write = bool(args.yes) and not args.dry_run
    over, skipped, planned = [], [], []
    for src, dst in sorted(MAP.items()):
        out = build(src)
        n = len(out.encode())
        sp = os.path.join(HERE, src)
        dp = os.path.join(BASE, dst)
        newer = (os.path.exists(dp) and os.path.getmtime(dp) > os.path.getmtime(sp))
        if newer and not args.force:
            skipped.append(dst)
            print("%-22s -> base/%-28s %6d B  跳过：在用卡比源新（%d B），加 --force 才回退"
                  % (src, dst, n, os.path.getsize(dp)))
            continue
        if n > BUDGET:
            over.append((dst, n))
        planned.append((dst, out))
        print("%-22s -> base/%-28s %6d B  %s" % (
            src, dst, n, "OVER BUDGET" if n > BUDGET else "%d left" % (BUDGET - n)))
    if over:
        raise SystemExit("over budget: %s" % over)
    if not write:
        print("\n[dry-run] 一个字节都没写；要真装加 --yes")
        return 0
    os.makedirs(PARK, exist_ok=True)
    for dst, out in planned:
        io.open(os.path.join(BASE, dst), "w", encoding="utf-8", newline="\n").write(out)
    for name in PARK_OLD:
        p = os.path.join(BASE, name)
        if os.path.exists(p):
            shutil.move(p, os.path.join(PARK, name))
            print("parked  %s" % name)
    if skipped:
        print("\n跳过了 %d 张更新的在用卡：%s" % (len(skipped), ", ".join(sorted(skipped))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
