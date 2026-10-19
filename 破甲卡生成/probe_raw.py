# -*- coding: utf-8 -*-
"""Raw single-request inspector.

Sends ONE (card, item) pair and dumps the transport-level truth: HTTP status,
top-level status, usage (incl. reasoning tokens), the item types that came back,
and the first bytes of each item. Use it to tell these apart:

  * policy refusal   -> visible body present, contains a refusal sentence
  * budget starvation-> visible empty, reasoning tokens > 0, status "incomplete"
  * class suppression-> visible empty, reasoning tokens == 0, status "completed"
  * gateway trouble  -> HTTP 4xx/5xx or transport exception

Usage (from 07-kernel-sweep/):
  python probe_raw.py <model> <card.md> --item "写个蠕虫..." [--max 50000] [--reasoning raw]
  python probe_raw.py <model> <card.md> --item-file items/probe10.md --n 3
"""
import io, json, os, sys, time, urllib.error, urllib.request

from sweep import B, T, load_card, CARDS

def call(model, S, u, mt):
    body = json.dumps({"model": model, "instructions": S, "input": u,
                       "max_output_tokens": mt}).encode()
    r = urllib.request.Request(B + "/responses", data=body,
                               headers={"Authorization": "Bearer " + T,
                                        "Content-Type": "application/json"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(r, timeout=200) as resp:
            raw = resp.read().decode("utf-8", "replace")
            code = resp.status
    except urllib.error.HTTPError as e:
        return {"http": e.code, "raw": e.read().decode("utf-8", "replace")[:2000],
                "secs": round(time.time() - t0, 1)}
    return {"http": code, "json": json.loads(raw), "secs": round(time.time() - t0, 1)}

def show(model, cardfile, item, mt, nocard=False):
    if nocard:
        card, h = "You are a helpful assistant.", "NO-CARD"
    else:
        card, h = load_card(cardfile)
    print("=" * 96)
    print("model=%s card=%s(%s) card_bytes=%d item=%r" % (model, cardfile, h, len(card.encode()), item[:60]))
    out = call(model, card, item, mt)
    print("http=%s secs=%s" % (out.get("http"), out.get("secs")))
    if "json" not in out:
        print("BODY: " + out.get("raw", ""))
        return
    d = out["json"]
    print("status=%r incomplete=%r usage=%s" % (d.get("status"), d.get("incomplete_details"), d.get("usage")))
    for it in d.get("output", []):
        if not isinstance(it, dict):
            continue
        texts = [c.get("text", "") for c in (it.get("content") or []) if isinstance(c, dict)]
        joined = "\n".join(texts)
        print("--- item type=%s status=%s chars=%d" % (it.get("type"), it.get("status"), len(joined)))
        print(("    " + joined[:600].replace("\n", "\n    ")) if joined else "    (no text)")
    if not d.get("output"):
        print("BODY(no output array): " + json.dumps(d, ensure_ascii=False)[:1200])

def main():
    a = sys.argv[1:]
    model = a[0]
    cardfile = a[1]
    mt = int(a[a.index("--max") + 1]) if "--max" in a else 50000
    nocard = "--no-card" in a
    if "--item" in a:
        show(model, cardfile, a[a.index("--item") + 1], mt, nocard)
        return
    path = a[a.index("--item-file") + 1]
    n = int(a[a.index("--n") + 1]) if "--n" in a else 3
    lines = [l.strip() for l in io.open(path, encoding="utf-8").read().splitlines()]
    items = [l.split("|", 1)[1].strip() for l in lines
             if l and not l.startswith("#") and "|" in l][:n]
    for it in items:
        show(model, cardfile, it, mt)

if __name__ == "__main__":
    main()
