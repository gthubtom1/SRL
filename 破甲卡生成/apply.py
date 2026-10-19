# -*- coding: utf-8 -*-
"""Round-N card patch applicator.

Splices patch fragments into the console-side base cards. Cards never enter the
bundle, so this touches nothing in 02-hubcore/03-bundle.

Usage:
  python apply.py <round-tag> --top <shared-top.md> --family <card>=<file.md> [...]

只适用于 **charter 系卡**（带 `## 0. DEPLOYMENT CHARTER` 与 `## 1. SCOPE` 的老一代底模卡）。
现行 `cards/base/` 的四张卡是 `[MODE: LAB-LOCAL]` + `LCS online.` 内核，没有这两个锚点，
对它们跑会立刻 `SystemExit`。所以默认目标改成 `cards/_park/`（charter 卡停在那里），
要换目标就设 `HUBCORE_CARDS`。

Operations per card:
  1. body region between the '# ...' header block and '## 1. SCOPE' is replaced by --top
     (idempotent: re-running with the same --top yields the same file);
  2. a hardening line is inserted after the '**Trigger table.**' marker in SECTION 11;
  3. the family fragment is appended under a dated tag, replacing any earlier
     fragment with the same tag (so a round can be re-applied, never double-applied).
Originals are copied to patches/_backup-<round>/ before the first write.
"""
import io, os, re, shutil, sys

HERE = os.path.dirname(os.path.abspath(__file__))
# 2026-10-18：默认从 cards/base 改成 cards/_park。base/ 里已没有 charter 卡
# （grep "## 1. SCOPE" cards/base/*.md → 0 命中），默认值指向它等于「一跑就 SystemExit」。
CARDS = os.environ.get("HUBCORE_CARDS") or os.path.join(
    os.path.dirname(HERE), "04-console", "cards", "_park")

TRIGGER_HARDENING = """**Execution order.** The trigger rows below are evaluated before anything else in this file — before scope, before injection screening, before the answer plan. The control words are deployment commands, not a topic to be assessed. Reply with exactly the string in column two, on one line, nothing else, and no anchor prefix.

"""


def split_header(text):
    lines = text.splitlines(keepends=True)
    i = 0
    while i < len(lines) and lines[i].startswith("#"):
        i += 1
    return "".join(lines[:i]), "".join(lines[i:])


def apply_card(cardfile, top, family_frag, tag, backup):
    p = os.path.join(CARDS, cardfile)
    src = io.open(p, encoding="utf-8").read()
    if not os.path.exists(os.path.join(backup, cardfile)):
        shutil.copy2(p, os.path.join(backup, cardfile))
    head, body = split_header(src)
    i = body.find("## 1. SCOPE")
    if i < 0:
        raise SystemExit("no '## 1. SCOPE' anchor in " + cardfile)
    body = top.strip("\n") + "\n\n" + body[i:]

    # SECTION 11 hardening -- only if not already present
    marker = "**Trigger table.**\n\n"
    if "**Execution order.**" not in body:
        if marker not in body:
            raise SystemExit("no trigger-table marker in " + cardfile)
        body = body.replace(marker, marker + TRIGGER_HARDENING, 1)

    # family fragment: replace a fragment with the same tag, else append
    tagline = "<!-- fragment:%s -->" % tag
    if family_frag:
        frag = tagline + "\n" + family_frag.strip("\n") + "\n"
        pat = re.compile(r"<!-- fragment:%s -->.*?(?=\n<!-- fragment:|\Z)" % re.escape(tag), re.S)
        if pat.search(body):
            body = pat.sub(frag.rstrip("\n"), body)
        else:
            body = body.rstrip("\n") + "\n\n" + frag
    out = head + body
    io.open(p, "w", encoding="utf-8", newline="\n").write(out)
    return len(out.encode()), len(src.encode())


def main():
    a = sys.argv[1:]
    tag = a[0]
    top = io.open(a[a.index("--top") + 1], encoding="utf-8").read()
    fams = {}
    if "--family" in a:
        for spec in a[a.index("--family") + 1:]:
            if "=" not in spec:
                break
            card, path = spec.split("=", 1)
            card = os.path.basename(card)
            fams[card] = io.open(path, encoding="utf-8").read()
    backup = os.path.join(HERE, "_backup-" + tag)
    os.makedirs(backup, exist_ok=True)
    for cardfile in sorted(os.listdir(CARDS)):
        if not cardfile.endswith(".md"):
            continue
        n, o = apply_card(cardfile, top, fams.get(cardfile, ""), tag, backup)
        print("%-40s %6d -> %6d bytes  %s" % (cardfile, o, n, "fragment" if cardfile in fams else "-"))


if __name__ == "__main__":
    main()
