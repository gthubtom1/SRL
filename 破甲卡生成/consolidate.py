# -*- coding: utf-8 -*-
"""Fragment consolidation for the console-side base cards.

The patch applicator appends one `<!-- fragment:rN -->` block per round, because a BAD
sample is never deleted while the round is still being measured. That accumulates. This
tool merges a card's fragments into a single per-family section, or drops a superseded
fragment tag while the fragment file stays archived in patches/.

Usage:
  python consolidate.py merge                 # r1..rN -> one 'MODEL PATCH (consolidated)' block
  python consolidate.py drop <tag> [<tag>...] # remove fragments by tag
  python consolidate.py budget                # report card size vs BASE_BUDGET (40000)
"""
import io, os, re, sys, glob

HERE = os.path.dirname(os.path.abspath(__file__))
CARDS = os.environ.get("HUBCORE_CARDS") or os.path.join(
    os.path.dirname(HERE), "04-console", "cards", "base")
BASE_BUDGET = 40000
FRAG = re.compile(r"<!-- fragment:([a-z0-9]+) -->\n(.*?)(?=\n<!-- fragment:|\Z)", re.S)


def load(p):
    return io.open(p, encoding="utf-8").read()


def save(p, s):
    io.open(p, "w", encoding="utf-8", newline="\n").write(s)


def budget():
    rows = []
    for p in sorted(glob.glob(os.path.join(CARDS, "*.md"))):
        n = len(load(p).encode())
        rows.append((os.path.basename(p), n, n - BASE_BUDGET))
    for name, n, over in rows:
        print("%-40s %6d  %s" % (name, n, ("OVER by %d" % -over) if over > 0 else ("%d left" % -over)))
    return rows


def drop(tags):
    for p in sorted(glob.glob(os.path.join(CARDS, "*.md"))):
        s = load(p)
        n0 = len(s.encode())
        def rep(m):
            return "" if m.group(1) in tags else m.group(0)
        s2 = FRAG.sub(rep, s)
        s2 = re.sub(r"\n{3,}", "\n\n", s2).rstrip("\n") + "\n"
        if s2 != s:
            save(p, s2)
        print("%-40s %6d -> %6d" % (os.path.basename(p), n0, len(s2.encode())))


def strip_round_headers(text, tag):
    """Drop the 'MODEL PATCH R<N>' header line and the 'round N' parenthetical, keeping body."""
    text = re.sub(r"^## MODEL PATCH R\d+ — (.*?):.*?$\n", r"### \1\n", text, flags=re.M)
    text = re.sub(r"^## MODEL PATCH R\d+ — (.*?)$\n", r"### \1\n", text, flags=re.M)
    text = re.sub(r"\(measured, round \d+\)", "(measured)", text)
    return text.strip("\n")


def merge():
    for p in sorted(glob.glob(os.path.join(CARDS, "*.md"))):
        s = load(p)
        frags = FRAG.findall(s)
        if not frags:
            continue
        if "MODEL PATCH (consolidated" in s:
            print("%-40s already consolidated" % os.path.basename(p))
            continue
        body = FRAG.sub("", s).rstrip("\n")
        parts = []
        for tag, text in frags:
            parts.append(strip_round_headers(text, tag))
        joined = "\n\n".join(x for x in parts if x.strip())
        n0 = len(s.encode())
        out = body + "\n\n## MODEL PATCH (consolidated — rounds 1-5)\n\n" + joined.strip() + "\n"
        # keep each round's fragment file on disk as the archive
        save(p, out)
        print("%-40s %6d -> %6d" % (os.path.basename(p), n0, len(out.encode())))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "budget"
    if cmd == "budget":
        budget()
    elif cmd == "drop":
        drop(set(sys.argv[2:]))
    elif cmd == "merge":
        merge()
