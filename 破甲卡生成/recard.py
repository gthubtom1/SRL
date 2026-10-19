# -*- coding: utf-8 -*-
"""Splice the LCS-shaped kernel body into every base card, keeping each card's family patch.

Layout of a base card:
    # base: <name>            <- header block (kept, and only this block)
    # kind: base
    # hosts: ...
    <kernel body>             <- replaced wholesale from kernel/<file>
    ## MODEL PATCH ...        <- per-family measurement + rules (kept verbatim)

Usage:
  python recard.py --kernel kernel/lcs-kernel.md [--family none|keep] [--dry-run]
Originals are copied to _backup-kernel/<card>.md before the first write.
"""
import argparse, io, os, re, shutil, sys

HERE = os.path.dirname(os.path.abspath(__file__))
CARDS = os.environ.get("HUBCORE_CARDS") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "04-console", "cards", "base")

TAIL_RE = re.compile(r"^(<!-- fragment:|## MODEL PATCH)", re.M)

def split_card(text):
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines) and lines[i].startswith("#"):
        i += 1
    header = "".join(lines[:i])
    body = "".join(lines[i:])
    m = TAIL_RE.search(body)
    if m:
        return header, body[:m.start()].rstrip("\n") + "\n", body[m.start():]
    return header, body.rstrip("\n") + "\n", ""

def main():
    ap = argparse.ArgumentParser(
        description="把共享内核正文重新拼进所有 base 卡，保留各自的家族补丁。")
    ap.add_argument("--kernel", required=True, help="内核正文，如 kernel/lcs-kernel.md（相对本目录）")
    ap.add_argument("--dry-run", action="store_true", help="只报体积变化，不写盘")
    ap.add_argument("--only", default=None, help="只处理这几张卡（逗号分隔的文件名）")
    ap.add_argument("--family", default=None, choices=["none", "keep"],
                    help="家族补丁处理方式（当前实现总是保留，参数留着兼容旧命令）")
    a = ap.parse_args()
    kernel_path = a.kernel
    dry = a.dry_run
    kernel = io.open(os.path.join(HERE, kernel_path), encoding="utf-8").read().strip("\n") + "\n"
    backup = os.path.join(HERE, "_backup-kernel")
    os.makedirs(backup, exist_ok=True)
    only = set(a.only.split(",")) if a.only else None
    for name in sorted(os.listdir(CARDS)):
        if not name.endswith(".md"):
            continue
        if only and name not in only:
            continue
        p = os.path.join(CARDS, name)
        src = io.open(p, encoding="utf-8").read()
        header, _, tail = split_card(src)
        out = header + "\n" + kernel
        if tail.strip():
            out += "\n" + tail.strip("\n") + "\n"
        n0, n1 = len(src.encode()), len(out.encode())
        flag = "OVER BUDGET" if n1 > 40000 else "%d left" % (40000 - n1)
        print("%-34s %6d -> %6d  %s%s" % (name, n0, n1, flag, "  (dry)" if dry else ""))
        if dry or out == src:
            continue
        b = os.path.join(backup, name)
        if not os.path.exists(b):
            shutil.copy2(p, b)
        io.open(p, "w", encoding="utf-8", newline="\n").write(out)

if __name__ == "__main__":
    main()
