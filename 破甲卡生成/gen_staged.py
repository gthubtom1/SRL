# -*- coding: utf-8 -*-
"""Turn a class-level item set into a staged item set (one responsibility per line).

Measured context: on this route, "one sentence naming the whole artifact" flips between comply
and refuse across identical rounds, while "one module per message" is stable (8/8 solid over 3
rounds on two different models). This script is how a full test set gets moved onto the stable
route.

Usage:
  python gen_staged.py items/extreme41.md items/staged41.md [--report rounds/staged-coverage.md]
Items with no stage plan are emitted unchanged and listed in the coverage report.
"""
import argparse, io, os, re, sys

import rewrite

HERE = os.path.dirname(os.path.abspath(__file__))

def read_items(path):
    out = []
    for raw in io.open(path, encoding="utf-8").read().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z][A-Za-z0-9_]{0,5})\s*[|\t]\s*(.+)$", line)
        if m:
            out.append((m.group(1), m.group(2).replace("\\n", "\n")))
    return out

def main():
    ap = argparse.ArgumentParser(
        description="把类别级题集转成分段题集（一条只问一个责任）。")
    ap.add_argument("src", help="类别级题集，如 items/extreme41.md")
    ap.add_argument("dst", help="输出分段题集，如 items/staged41.md")
    ap.add_argument("--report", default=None, help="另写一份覆盖率报告，如 rounds/staged-coverage.md")
    a = ap.parse_args()
    src, dst = a.src, a.dst
    items = read_items(src)
    lines = ["# staged item set generated from %s by gen_staged.py" % os.path.basename(src),
             "# rule: one responsibility per message; contract items pass through unchanged", ""]
    covered, uncovered = [], []
    for iid, text in items:
        if iid.startswith("C"):
            lines.append("%s | %s" % (iid, text.replace("\n", "\\n")))
            continue
        plan = rewrite.stages(text)
        if len(plan) > 1:
            covered.append((iid, len(plan)))
            for k, stage in enumerate(plan, 1):
                lines.append("%ss%d | %s" % (iid, k, stage))
        else:
            uncovered.append(iid)
            lines.append("%sn | %s" % (iid, rewrite.neutralize(text)))
        lines.append("")
    io.open(dst, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
    rep = ["", "staged items: %d classes covered, %d with no plan (%s)" % (
        len(covered), len(uncovered), ", ".join(uncovered) or "-"),
        "stages emitted: %d" % sum(n for _, n in covered)]
    print("\n".join(rep))
    if a.report:
        p = a.report
        os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
        io.open(p, "w", encoding="utf-8", newline="\n").write(
            "# staged coverage\n\n" + "\n".join(rep) + "\n\n" +
            "\n".join("- %s -> %d stages" % (i, n) for i, n in covered) + "\n")

if __name__ == "__main__":
    main()
