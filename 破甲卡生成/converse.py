# -*- coding: utf-8 -*-
"""Multi-turn project runner — the measurement that matches real usage.

Every earlier tool here sent one message per request. Real work is a project: the operator states a
goal, then says 继续 / 按你的思路 over and over while the model advances a plan across turns. This
runner keeps the conversation (instructions = the card, input = the accumulated turns) and reports,
per turn: verdict, whether a plan/next-step line is present, whether the turn asked a question, and
whether it advanced (new artifact vs. a repeat of the previous turn).

Usage:
  python converse.py <model> --card base/mimo-2.6.md --turns items/project-license.md \
      [--tag proj-license] [--max 16000] [--idle 120]
Turns file: one user message per line; a line starting with `>` is the next user turn
(the first line is turn 1). Blank lines ignored.
"""
import io, json, os, re, sys, time

import client
import sweep2
from client import Cfg

HERE = os.path.dirname(os.path.abspath(__file__))
OUTDIR = os.path.join(HERE, "data")

NEXT_LINE = re.compile(r"(next:|下一步|下一阶段|reply .?继续|回.{0,4}继续|say .?继续)", re.I)
QUESTION = re.compile(r"[?？]|(请(告诉|提供|确认)|which (file|version)|what (is|are) the path)", re.I)

def read_turns(path):
    turns = []
    for line in io.open(path, encoding="utf-8").read().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        turns.append(line[1:].strip() if line.startswith(">") else line)
    return turns

def run(model, card, turns, cfg, tag):
    msgs = []
    rec = []
    for i, ut in enumerate(turns, 1):
        msgs.append({"role": "user", "content": [{"type": "input_text", "text": ut}]})
        r = client.stream(model, card, msgs if len(msgs) > 1 else ut, cfg)
        vis = r.visible or ""
        if not vis and r.err:
            vis = ""
        msgs.append({"role": "assistant",
                     "content": [{"type": "output_text", "text": vis[:6000]}]})
        v, sig = sweep2.score("T", vis, r.status, r.err)
        row = {"model": model, "turn": i, "user": ut, "verdict": v, "err": r.err,
               "secs": r.secs, "chars": len(vis),
               "has_next_line": bool(NEXT_LINE.search(vis)),
               "asks_question": bool(QUESTION.search(vis[-800:])),
               "artifact": bool(sig.get("artifact")),
               "reasoning_tokens": (r.usage.get("output_tokens_details") or {}).get("reasoning_tokens"),
               "opening": " ".join(vis.split())[:160], "text": vis[:6000]}
        rec.append(row)
        print("  t%d %-6s %-8s chars=%-5d next=%-5s q=%-5s %.0fs  %s" % (
            i, tag, v, len(vis), row["has_next_line"], row["asks_question"], r.secs,
            row["opening"][:70]), flush=True)
    return rec

def main():
    a = sys.argv[1:]
    model = a[0]
    card_rel = a[a.index("--card") + 1]
    turns = read_turns(a[a.index("--turns") + 1])
    tag = a[a.index("--tag") + 1] if "--tag" in a else "proj"
    cfg = Cfg(idle=float(a[a.index("--idle") + 1]) if "--idle" in a else 120,
              budget=600, max_tokens=int(a[a.index("--max") + 1]) if "--max" in a else 16000,
              retries=1)
    card, h = sweep2.load_card(card_rel)
    print("=" * 100)
    print("PROJECT %s · model=%s · card=%s(%s) · %d turns" % (tag, model, card_rel, h, len(turns)))
    rows = run(model, card, turns, cfg, tag)
    # summary
    arts = sum(1 for r in rows if r["artifact"])
    refs = sum(1 for r in rows if r["verdict"] == "REFUSE")
    nxt = sum(1 for r in rows if r["has_next_line"])
    qs = sum(1 for r in rows if r["asks_question"])
    print("-" * 100)
    print("turns=%d  artifact-turns=%d  refusals=%d  next-step lines=%d  turns asking a question=%d"
          % (len(rows), arts, refs, nxt, qs))
    os.makedirs(OUTDIR, exist_ok=True)
    p = os.path.join(OUTDIR, "project-%s-%s.json" % (tag, model.split("-")[0]))
    json.dump({"model": model, "card": card_rel, "tag": tag, "rows": rows},
              io.open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("WROTE " + p)

if __name__ == "__main__":
    main()
