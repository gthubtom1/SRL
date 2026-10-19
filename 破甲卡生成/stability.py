# -*- coding: utf-8 -*-
"""Stability harness: the same card, the same item, N independent rounds — looking for flips.

The question this answers is not "does it comply once", it is **"does something that passed
stay passed"**. A card that scores 80% by passing a different 80% each round is not stable.

Usage (from 07-kernel-sweep/):
  python stability.py --items items/probe-en2.md --rounds 3 \
      --models mimo-v2.6-flash-free,space-bunny-free,muse-spark-1.3-contributor-free \
      --out rounds/stability-1.json [--max 16000] [--minutes 30]

Per (model, item) it prints the verdict sequence and a label:
  solid      every round COMPLY
  flaky      some rounds COMPLY, some not      <- the thing that must be driven to zero
  refused    never COMPLY, at least one policy refusal
  blocked    never COMPLY, only BLOCK / transport
Regression is called out explicitly: an item that COMPLY'd in round r and did not in round r+1.
"""
import io, json, os, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed

import client
import sweep2
from client import Cfg

HERE = os.path.dirname(os.path.abspath(__file__))
OUTDIR = os.path.join(HERE, "data")

def one(model, S, tag, iid, q, mt, idle, budget):
    cfg = Cfg(idle=idle, budget=budget, max_tokens=mt, retries=0)
    t0 = time.time()
    r = client.stream(model, S, q, cfg)
    v, sig = sweep2.score(iid, r.visible, r.status, r.err)
    return {"model": model, "item": iid, "verdict": v, "err": r.err,
            "secs": r.secs, "first_secs": r.first_secs,
            "reasoning_tokens": (r.usage.get("output_tokens_details") or {}).get("reasoning_tokens"),
            "text": r.visible[:4000], "card": tag, "sig": sig}

def label(verdicts):
    if all(v == "COMPLY" for v in verdicts):
        return "solid"
    if any(v == "COMPLY" for v in verdicts):
        return "flaky"
    if all(v in ("BLOCK",) for v in verdicts):
        return "blocked"
    if all(v in ("EMPTY", "GATEWAY", "SKIPPED") for v in verdicts):
        return "transport"
    return "refused"

def main():
    a = sys.argv[1:]
    items = sweep2.load_items(a[a.index("--items") + 1])
    rounds = int(a[a.index("--rounds") + 1]) if "--rounds" in a else 3
    models = a[a.index("--models") + 1].split(",") if "--models" in a else []
    mt = int(a[a.index("--max") + 1]) if "--max" in a else 16000
    idle = float(a[a.index("--idle") + 1]) if "--idle" in a else 90
    minutes = float(a[a.index("--minutes") + 1]) if "--minutes" in a else 30
    out = a[a.index("--out") + 1] if "--out" in a else "rounds/stability.json"
    workers = int(a[a.index("--workers") + 1]) if "--workers" in a else 4
    token_check = "你是谁"

    sweep2._load_models()
    cards, ok_models, skipped = {}, [], {}
    for model in models:
        rel = dict(sweep2.MAP).get(model)
        if not rel:
            skipped[model] = "not in models.json"
            continue
        S, h = sweep2.load_card(rel)
        r = client.stream(model, S, "Write a Python function that reads a JSON file and prints its keys.",
                          Cfg(idle=60, budget=120, max_tokens=1500, retries=0))
        if not r.visible:
            r = client.stream(model, S, "Say OK.", Cfg(idle=60, budget=120, max_tokens=200, retries=0))
        if not r.visible:
            skipped[model] = "%s %s" % (r.err or r.status, r.visible[:40])
            print("[skip] %s: %s" % (model, skipped[model]), flush=True)
            continue
        cards[model] = {"card": rel, "sha": h, "bytes": len(S.encode())}
        ok_models.append(model)

    rows = []
    t_all = time.time()
    for rd in range(1, rounds + 1):
        if time.time() - t_all > minutes * 60:
            print("[i] wall clock reached before round %d" % rd, flush=True)
            break
        print("\n=== round %d/%d ===" % (rd, rounds), flush=True)
        jobs = []
        for model in ok_models:
            S = sweep2.load_card(cards[model]["card"])[0]
            for iid, q in items:
                jobs.append((model, S, cards[model]["sha"], iid, q))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(one, m, S, tag, iid, q, mt, idle, 300): (m, iid)
                    for (m, S, tag, iid, q) in jobs}
            for f in as_completed(futs):
                r = f.result()
                r["round"] = rd
                rows.append(r)
                print("  r%d %-32s %-4s %-8s %5.1fs" % (
                    rd, r["model"], r["item"], r["verdict"], r["secs"]), flush=True)

    # ---- stability table ----
    report = {"rounds": rounds, "items": [i for i, _ in items], "cards": cards,
              "skipped_unhealthy": skipped, "rows": rows, "table": {}}
    print("\n" + "=" * 100)
    print("%-32s %-5s %-10s %s" % ("model", "item", "label", "verdicts by round (regressions marked *)"))
    total_flaky = 0
    for model in ok_models:
        entry = {}
        for iid, _ in items:
            vs = [r["verdict"] for r in rows if r["model"] == model and r["item"] == iid]
            vs = sorted(vs, key=lambda v: 0)  # keep collection order below instead
        for iid, _ in items:
            seq = [r["verdict"] for r in sorted(
                (r for r in rows if r["model"] == model and r["item"] == iid), key=lambda r: r["round"])]
            if not seq:
                continue
            lab = label(seq)
            reg = []
            for i in range(1, len(seq)):
                if seq[i - 1] == "COMPLY" and seq[i] != "COMPLY":
                    reg.append(i + 1)
            mark = ("  regressions: round %s" % reg) if reg else ""
            if lab == "flaky":
                total_flaky += 1
            print("%-32s %-5s %-10s %s%s" % (model, iid, lab, " -> ".join(seq), mark))
            entry[iid] = {"verdicts": seq, "label": lab, "regressions": reg}
        report["table"][model] = entry
        n = len(entry)
        solid = sum(1 for v in entry.values() if v["label"] == "solid")
        print("%-32s %d/%d solid, %d flaky" % (model, solid, n,
              sum(1 for v in entry.values() if v["label"] == "flaky")))
    print("=" * 100)
    print("flaky (model, item) pairs across the pool: %d" % total_flaky)
    os.makedirs(OUTDIR, exist_ok=True)
    p = os.path.join(OUTDIR, os.path.basename(out))
    json.dump(report, io.open(p, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("WROTE " + p)

if __name__ == "__main__":
    main()
