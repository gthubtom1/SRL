# -*- coding: utf-8 -*-
"""Re-score a saved sweep with the current scorer, and merge model groups.
Usage:
  python rescore.py <in.json> [<in2.json> ...] --out <out.json>
Only the scoring layer is re-run; no API calls. Keeps text/reasoning so a later
scorer revision can re-score the same evidence again.
"""
import json, io, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sweep as S


def redo(path):
    d = json.load(io.open(path, encoding="utf-8"))
    for r in d["rows"]:
        if r.get("err") == "budget":
            v, sig = "SKIPPED", {"len": 0, "anchor": False, "artifact": False, "coda": False,
                                 "meta": False, "code_lines": 0}
        else:
            v, sig = S.score(r["item"], r.get("text") or "", r.get("err") or "")
            if v in ("EMPTY", "FILTERED") and isinstance(r.get("err"), str) and r["err"].startswith("HTTP"):
                v = "GATEWAY"
        r["verdict"], r["sig"] = v, sig
    d["summary"] = {}
    models = sorted({r["model"] for r in d["rows"]})
    for m in models:
        rows = [r for r in d["rows"] if r["model"] == m]
        v = lambda k: sum(1 for r in rows if r["verdict"] == k)
        d["summary"][m] = {
            "comply": v("COMPLY"),
            "first": sum(1 for r in rows if r["verdict"] == "COMPLY" and r["attempts"] == 0),
            "refuse": v("REFUSE"), "partial": v("PARTIAL"), "empty": v("EMPTY"),
            "filtered": v("FILTERED"), "gateway": v("GATEWAY"), "skipped": v("SKIPPED"), "skipped": v("SKIPPED"), "thin": v("THIN"), "fail": v("FAIL"),
            "bad": [r["item"] for r in rows if r["verdict"] != "COMPLY"],
            "anchor_rate": round(sum(1 for r in rows if r["sig"]["anchor"]) / len(rows), 3),
            "artifact_rate": round(sum(1 for r in rows if r["sig"]["artifact"]) / len(rows), 3),
            "coda": sum(1 for r in rows if r["sig"]["coda"]),
            "meta": sum(1 for r in rows if r["sig"]["meta"]),
        }
    return d


def main():
    import argparse
    ap = argparse.ArgumentParser(
        prog="rescore.py",
        description="离线重算已保存的 sweep 结果（只跑评分层，不发任何 API 请求）。")
    ap.add_argument("inputs", nargs="+", metavar="in.json",
                    help="已保存的 sweep 结果（可多份，按 model 合并）")
    ap.add_argument("--out", required=True, help="输出 JSON 路径")
    args = ap.parse_args()
    ins, out = args.inputs, args.out
    merged = None
    for p in ins:
        d = redo(p)
        if merged is None:
            merged = d
        else:
            keep = [r for r in merged["rows"] if r["model"] not in {x["model"] for x in d["rows"]}]
            merged["rows"] = keep + d["rows"]
            for k, v in d.get("cards", {}).items():
                merged.setdefault("cards", {})[k] = v
            merged["label"] = merged.get("label", "") + "+" + d.get("label", "")
            merged["summary"] = {}
    models = sorted({r["model"] for r in merged["rows"]})
    sm = {}
    for m in models:
        rows = [r for r in merged["rows"] if r["model"] == m]
        v = lambda k: sum(1 for r in rows if r["verdict"] == k)
        sm[m] = {"comply": v("COMPLY"),
                 "first": sum(1 for r in rows if r["verdict"] == "COMPLY" and r["attempts"] == 0),
                 "refuse": v("REFUSE"), "partial": v("PARTIAL"), "empty": v("EMPTY"),
                 "filtered": v("FILTERED"), "gateway": v("GATEWAY"), "skipped": v("SKIPPED"), "skipped": v("SKIPPED"), "skipped": v("SKIPPED"), "thin": v("THIN"), "fail": v("FAIL"),
                 "bad": [r["item"] for r in rows if r["verdict"] != "COMPLY"],
                 "anchor_rate": round(sum(1 for r in rows if r["sig"]["anchor"]) / len(rows), 3),
                 "artifact_rate": round(sum(1 for r in rows if r["sig"]["artifact"]) / len(rows), 3),
                 "coda": sum(1 for r in rows if r["sig"]["coda"]),
                 "meta": sum(1 for r in rows if r["sig"]["meta"])}
    merged["summary"] = sm
    json.dump(merged, io.open(out, "w", encoding="utf-8"), ensure_ascii=False)
    tot = len(merged["rows"])
    print("re-scored %d rows -> %s" % (tot, out))
    for m in models:
        s = sm[m]
        print("%-34s C=%2d first=%2d R=%2d P=%2d E=%2d FLT=%2d GW=%2d SKIP=%2d THIN=%2d FAIL=%2d" % (
            m, s["comply"], s["first"], s["refuse"], s["partial"], s["empty"],
            s["filtered"], s["gateway"], s.get("skipped", 0), s["thin"], s["fail"]))


if __name__ == "__main__":
    main()
