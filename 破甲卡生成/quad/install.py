# -*- coding: utf-8 -*-
"""Install the per-model kernels into the console card pool (explicit opt-in only).

Layout produced when it does run:
  04-console/cards/base/<model>.md        <- zh kernel   (the pool slot the console reads)
  04-console/cards/base/<model>-en.md     <- en kernel   (same slot pool, English sessions)

Originals are copied to 07-kernel-sweep/_backup-cards/ on first run.
Card budget is 40000 B per file (the console refuses bigger tiles).

⚠️ 默认**不写盘**。上一版没有 argparse，任何未知参数（包括 `--help`）都被当成「执行」，
   跑一次就把 04-console/cards/base/ 的四张在用卡覆盖掉。现在：
     python quad/install.py                 # 只报计划（等于 --dry-run）
     python quad/install.py --yes           # 真装（仍跳过比源新的在用卡）
     python quad/install.py --yes --force   # 连更新的在用卡也覆盖（回退，危险）
"""
import argparse
import io
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                      # 07-kernel-sweep
CARDS = os.environ.get("HUBCORE_CARDS") or os.path.join(
    os.path.dirname(ROOT), "04-console", "cards", "base")
BACKUP = os.path.join(ROOT, "_backup-cards")
BUDGET = 40000

# quad file -> card file in the pool
MAP = {
    "zh-gemini.md": "gemini-3.8-flash-high.md",
    "zh-mimo.md": "mimo-2.6.md",
    "zh-muse.md": "muse-1.3.md",
    "zh-spacebunny.md": "space-bunny.md",
    "en-gemini.md": "gemini-3.8-flash-high-en.md",
    "en-mimo.md": "mimo-2.6-en.md",
    "en-muse.md": "muse-1.3-en.md",
    "en-spacebunny.md": "space-bunny-en.md",
}


def header_of(text):
    lines = text.splitlines()
    hdr = [l for l in lines[:4] if l.startswith("#")]
    body = "\n".join(lines[len(hdr):]).lstrip("\n")
    return "\n".join(hdr) + "\n\n", body


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="install.py",
        description="把 quad/zh-*.md 与 quad/en-*.md 装进 04-console/cards/base/。"
                    "默认只报计划；--yes 才写盘。")
    ap.add_argument("--dry-run", action="store_true", help="只报计划，不写任何文件（默认行为）")
    ap.add_argument("--yes", action="store_true", help="确认执行：真的写卡池并备份原卡")
    ap.add_argument("--force", action="store_true",
                    help="连比源文件新的在用卡也覆盖（会把在用卡回退到 quad 源那一代）")
    args = ap.parse_args(argv)

    write = bool(args.yes) and not args.dry_run
    over, skipped, planned = [], [], []
    for src, dst in sorted(MAP.items()):
        sp = os.path.join(HERE, src)
        text = io.open(sp, encoding="utf-8").read()
        head, body = header_of(text)
        out = head + body.rstrip("\n") + "\n"
        dp = os.path.join(CARDS, dst)
        n = len(out.encode())
        old = os.path.getsize(dp) if os.path.exists(dp) else 0
        newer = os.path.exists(dp) and os.path.getmtime(dp) > os.path.getmtime(sp)
        if newer and not args.force:
            skipped.append(dst)
            print("%-30s -> %-30s %6d -> %6d B  跳过：在用卡比源新，加 --force 才回退"
                  % (src, dst, old, n))
            continue
        if n > BUDGET:
            over.append((dst, n))
        planned.append((dst, out))
        print("%-30s -> %-30s %6d -> %6d B  %s" % (
            src, dst, old, n, "OVER BUDGET" if n > BUDGET else "%d left" % (BUDGET - n)))
    if over:
        raise SystemExit("over budget: %s" % over)
    if not write:
        print("\n[dry-run] 一个字节都没写；要真装加 --yes")
        return 0
    os.makedirs(BACKUP, exist_ok=True)
    for dst, out in planned:
        dp = os.path.join(CARDS, dst)
        b = os.path.join(BACKUP, dst)
        if os.path.exists(dp) and not os.path.exists(b):
            shutil.copy2(dp, b)
        io.open(dp, "w", encoding="utf-8", newline="\n").write(out)
    if skipped:
        print("\n跳过了 %d 张更新的在用卡：%s" % (len(skipped), ", ".join(sorted(skipped))))
    return 0


if __name__ == "__main__":
    sys.exit(main())
