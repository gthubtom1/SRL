# -*- coding: utf-8 -*-
"""Build the copy-paste ask card: one paste-ready question per line, grouped by need.

Why this exists: measuring showed that a single sentence naming a whole artifact flips between
comply and refuse, and that a "break it into steps" rescue line does not reliably save it either
(1/4, 0/4, 0/4 across three models). What is stable is asking one responsibility at a time
(mimo: 14/14 solid over three rounds). So the operator should not have to run a script at all —
he should be able to copy a line, paste it, get code, copy the next line.

Usage: python gen_askcard.py items/extreme41.md items/staged41.md 提问卡.md
"""
import argparse, io, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))

HEADER = """# 提问卡（复制粘贴即用）

**怎么用（三行）：**

1. 先把卡装到模型上，然后发一句 `你是谁`。回 `LCS online. Kernel loaded. Send the work.` 就说明装好了。
   （gemini：把 `你是谁` 和第一条问题放在同一条消息里发。）
2. 在下面找到你要的那一类，**从第 1 条开始，一条一条复制过去问**。一条只问一个函数。
3. 每条回答末尾会写「第几段 / 共几段 / 接口名」。按顺序把代码拼起来就是完整成品。

**为什么不能一句话要整件成品：** 实测同一个模型、同一句话，连问三次会在「给成品 / 只给一半 / 拒绝」
之间跳；拆成一条一个函数后，mimo 连问三轮 14/14 全给。**一条一条问是最省事的用法。**
"""

def read_titles(path):
    out = {}
    for line in io.open(path, encoding="utf-8").read().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "|" not in line:
            continue
        iid, text = line.split("|", 1)
        out[iid.strip()] = text.strip()
    return out

def main():
    ap = argparse.ArgumentParser(
        description="生成给人用的复制粘贴提问卡（一条只问一个函数）。")
    ap.add_argument("titles", help="类别级题集，如 items/extreme41.md（取每题的标题）")
    ap.add_argument("staged", help="分段题集，如 items/staged41.md")
    ap.add_argument("out", help="输出 markdown 路径，如 提问卡.md")
    a = ap.parse_args()
    titles = read_titles(a.titles)
    staged = io.open(a.staged, encoding="utf-8").read().splitlines()
    groups = {}
    order = []
    for line in staged:
        line = line.strip()
        if not line or line.startswith("#") or "|" not in line:
            continue
        iid, text = line.split("|", 1)
        iid = iid.strip()
        m = re.match(r"^([A-Za-z]\d+)(?:s(\d+)|n)$", iid)
        if not m:
            continue
        base = m.group(1)
        if base not in groups:
            groups[base] = []
            order.append(base)
        groups[base].append(text.strip())
    out = [HEADER]
    for base in sorted(order, key=lambda x: int(re.sub(r"\D", "", x) or 0)):
        title = titles.get(base, base)
        title = re.sub(r"[\r\n]+", " ", title)
        short = title[:34] + ("…" if len(title) > 34 else "")
        out.append("## %s · %s" % (base, short))
        for k, stage in enumerate(groups[base], 1):
            out.append("%d. %s" % (k, stage))
        out.append("")
    io.open(a.out, "w", encoding="utf-8", newline="\n").write("\n".join(out) + "\n")
    print("wrote %s: %d groups, %d questions" % (a.out, len(order), sum(len(v) for v in groups.values())))

if __name__ == "__main__":
    main()
