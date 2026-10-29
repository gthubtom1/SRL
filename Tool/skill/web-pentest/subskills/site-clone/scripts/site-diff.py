#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""site-diff.py -- three-way comparison of a crawl vs its offline rebuild.

Criteria (all machine-checkable):
  route coverage | pixel diff | DOM structure/text | resource set | interactions | data boundary

Usage:
  python Tool/skill/_pending/site-clone/scripts/site-diff.py --crawl work/crawl --rebuild work/rebuild --out work/diff.json
  python Tool/skill/_pending/site-clone/scripts/site-diff.py --self-test
  python Tool/skill/_pending/site-clone/scripts/site-diff.py --help

Exit codes: 0 = diff computed (JSON says pass/fail); 2 = blocked (structured JSON).
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys
import tempfile
from html.parser import HTMLParser

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

SCHEMA = "seep.site-diff/1"
BOUNDARY = ("recorded-snapshot", "local-mock", "backend-required")


def emit(obj, code=0):
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    return code


def blocked(at, reason):
    return emit({"ok": False, "blocked_at": at, "reason": str(reason)[:500]}, 2)


def read_json(p):
    with open(p, encoding="utf-8-sig") as f:
        return json.load(f)


def read_text(p):
    return open(p, encoding="utf-8", errors="replace").read()


def slug(route):
    s = re.sub(r"[^A-Za-z0-9]+", "_", route).strip("_")
    return s or "root"


def norm_space(s):
    return re.sub(r"\s+", " ", s or "").strip()


class Dom(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.text = [], []
        self.nodes = 0
        self.depth = 0
        self._stack = 0
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "template"):
            self._skip += 1
            return
        self.nodes += 1
        self.tags.append(tag)
        self._stack += 1
        self.depth = max(self.depth, self._stack)

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "template"):
            self._skip = max(0, self._skip - 1)
            return
        self._stack = max(0, self._stack - 1)

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.text.append(data.strip())


def dom_of(html_text):
    d = Dom()
    try:
        d.feed(html_text)
    except Exception:  # noqa: BLE001
        pass
    text = norm_space(" ".join(d.text))
    return {"nodes": d.nodes, "depth": d.depth, "tags": d.tags, "text": text}


def pixel_stats(a_path, b_path, masks=None):
    from PIL import Image
    import numpy as np
    try:
        a = Image.open(a_path).convert("RGB")
        b = Image.open(b_path).convert("RGB")
    except Exception as e:  # noqa: BLE001
        return {"available": False, "error": str(e)[:160], "ratio": 1.0, "mean": 255.0}
    if a.size != b.size:
        try:
            b = b.resize(a.size, Image.Resampling.LANCZOS)
        except Exception:  # noqa: BLE001
            return {"available": False, "error": "size-mismatch", "ratio": 1.0, "mean": 255.0,
                    "size_a": a.size, "size_b": b.size}
    aa, bb = np.asarray(a, dtype=np.int16), np.asarray(b, dtype=np.int16)
    d = np.abs(aa - bb).max(axis=2)
    raw = float((d > 8).mean())
    masked_px = 0
    for (x, y, w, h) in masks or []:
        x0, y0 = max(0, int(x)), max(0, int(y))
        x1, y1 = min(d.shape[1], int(x + w)), min(d.shape[0], int(y + h))
        if x1 > x0 and y1 > y0:
            masked_px += int((x1 - x0) * (y1 - y0))
            d[y0:y1, x0:x1] = 0
    return {"available": True, "ratio": round(float((d > 8).mean()), 6),
            "raw_ratio": round(raw, 6), "masked_ratio": round(masked_px / max(d.size, 1), 6),
            "masked_boxes": len(masks or []),
            "mean": round(float(np.abs(aa - bb).mean()), 4),
            "size": list(a.size), "pixels": int(d.size)}


def ratio(a, b):
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    return min(a, b) / max(a, b)


def text_similarity(a, b):
    a, b = norm_space(a), norm_space(b)
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    return round(difflib.SequenceMatcher(None, a[:30000], b[:30000]).ratio(), 6)


def tag_similarity(a, b):
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    return round(difflib.SequenceMatcher(None, a, b).ratio(), 6)


def interaction_pass(kind, exp, act):
    if not isinstance(exp, dict):
        return False
    if kind in ("title", "heading_text"):
        e, a = norm_space(str(exp.get("expected") if kind != "title" else exp.get("expected"))), norm_space(str(act.get("expected")))
        return e == a or text_similarity(e, a) >= 0.98
    if kind == "body_text_head":
        e = norm_space(str(exp.get("expected")))[:80]
        a = norm_space(str(act.get("expected")))
        return bool(e) and (a.startswith(e) or text_similarity(e, a[:len(e) + 80]) >= 0.98)
    if kind == "stylesheet_count":
        return int(act.get("expected") or 0) >= int(exp.get("expected") or 0)
    if kind == "dom_nodes":
        return ratio(int(exp.get("expected") or 0), int(act.get("expected") or 0)) >= 0.95
    if kind in ("link_count", "paragraph_count", "image_count", "document_lang"):
        return str(act.get("expected")) == str(exp.get("expected"))
    if kind == "language_menu":
        e = exp.get("expected") or {}
        a = act.get("expected") or {}
        return bool(e.get("opened")) == bool(a.get("opened")) and int(a.get("options") or 0) >= 0
    if kind == "text_input":
        e = exp.get("expected") or {}
        a = act.get("expected") or {}
        return bool(a.get("filled")) and a.get("value") == e.get("value")
    return False


def compute(crawl_dir, rebuild_dir, pixel_threshold=None):
    graph = read_json(os.path.join(crawl_dir, "site-graph.json"))
    rb = read_json(os.path.join(rebuild_dir, "rebuild.json"))
    origin = graph.get("origin", "")
    routes = graph.get("routes") or []
    seed_html = ""
    for r in routes:
        p = os.path.join(crawl_dir, r.get("html") or "")
        if os.path.isfile(p):
            seed_html += read_text(p)[:5000]
    spa = ("__NEXT_DATA__" in seed_html or "/_next/" in seed_html
           or len(routes) > 1 and "spa" in str(graph.get("engine", "")).lower())
    threshold = float(pixel_threshold if pixel_threshold is not None else (0.03 if spa else 0.01))

    # 1) route coverage
    cov = graph.get("coverage") or {}
    missing_rate = float(cov.get("missing_rate", 0.0))
    route = {"pass": missing_rate <= 0.02, "missing_rate": missing_rate,
             "expected": cov.get("expected"), "crawled": cov.get("crawled"),
             "missing_routes": graph.get("missing_routes") or []}

    # 2) pixel + 3) DOM
    pixels, doms = [], []
    local_by_route = {p.get("route"): p for p in rb.get("local_pages") or []}
    site_root = os.path.join(rebuild_dir, rb.get("site_root") or "site")
    anim_cache = {}

    def animated_boxes(route):
        boxes = []
        for im in route.get("images") or []:
            src = im.get("src") or ""
            if src.startswith("data:"):
                continue
            path = src.split("?")[0]
            if "://" in path:
                rest = path.split("://", 1)[1]
                path = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
            fp = os.path.join(site_root, path.lstrip("/"))
            if fp not in anim_cache:
                n = 1
                try:
                    from PIL import Image
                    n = getattr(Image.open(fp), "n_frames", 1)
                except Exception:  # noqa: BLE001
                    n = 1
                anim_cache[fp] = n > 1
            if anim_cache[fp]:
                boxes.append((im.get("x", 0), im.get("y", 0), im.get("w", 0), im.get("h", 0)))
        return boxes

    for r in routes:
        rt = r["route"]
        orig_shot = os.path.join(crawl_dir, r.get("screenshot") or "")
        loc = local_by_route.get(rt) or {}
        loc_shot = os.path.join(rebuild_dir, loc.get("screenshot") or "")
        ps = pixel_stats(orig_shot, loc_shot, animated_boxes(r)) \
            if os.path.isfile(orig_shot) and os.path.isfile(loc_shot) \
            else {"available": False, "error": "missing-screenshot", "ratio": 1.0, "mean": 255.0}
        ps["route"] = rt
        pixels.append(ps)
        orig_html = os.path.join(crawl_dir, r.get("html") or "")
        loc_html = os.path.join(rebuild_dir, loc.get("html") or "")
        if not os.path.isfile(loc_html):
            loc_html = os.path.join(rebuild_dir, rb.get("site_root") or "site",
                                    (rt.strip("/") + "/index.html") if rt != "/" else "index.html")
        if os.path.isfile(orig_html) and os.path.isfile(loc_html):
            a, b = dom_of(read_text(orig_html)), dom_of(read_text(loc_html))
            nr = ratio(a["nodes"], b["nodes"])
            dr = ratio(a["depth"], b["depth"])
            ts = text_similarity(a["text"], b["text"])
            tg = tag_similarity(a["tags"], b["tags"])
            doms.append({"route": rt, "pass": min(nr, dr, ts, tg) >= 0.98,
                         "node_ratio": round(nr, 6), "depth_ratio": round(dr, 6),
                         "text_similarity": ts, "tag_similarity": tg,
                         "nodes": [a["nodes"], b["nodes"]], "depth": [a["depth"], b["depth"]]})
        else:
            doms.append({"route": rt, "pass": False, "error": "missing-html"})
    avail = [p for p in pixels if p.get("available")]
    max_ratio = max([p["ratio"] for p in avail] or [1.0])
    mean_ratio = round(sum(p["ratio"] for p in avail) / len(avail), 6) if avail else 1.0
    pixel = {"pass": bool(avail) and max_ratio <= threshold, "threshold": threshold,
             "mode": "spa" if spa else "static", "max_ratio": max_ratio,
             "mean_ratio": mean_ratio, "pages": pixels}
    dom_sim = min([min(d.get("node_ratio", 0), d.get("depth_ratio", 0),
                       d.get("text_similarity", 0), d.get("tag_similarity", 0))
                   for d in doms] or [0.0])
    dom = {"pass": bool(doms) and all(d.get("pass") for d in doms),
           "min_similarity": round(dom_sim, 6), "threshold": 0.98, "pages": doms}

    # 4) resources
    res = rb.get("resources") or {}
    http404 = int(res.get("http_404") or 0)
    external = int(res.get("external_links") or 0)
    assets_failed = len(rb.get("assets_failed") or [])
    resources = {"pass": http404 == 0 and external == 0,
                 "http_404": http404, "external_links": external,
                 "assets_failed": assets_failed,
                 "requests": int(res.get("requests") or 0),
                 "samples_404": [r for r in (rb.get("local_requests") or [])
                                 if r.get("status") == 404][:10],
                 "external_samples": (res.get("external_samples") or [])[:10]}

    # 5) interactions
    exp = {i.get("kind"): i for i in (graph.get("interactions") or [])
           if i.get("applicable", True)}
    act = {i.get("kind"): i for i in (rb.get("interactions") or [])
           if i.get("applicable", True)}
    rows = []
    for kind, e in exp.items():
        a = act.get(kind)
        ok = bool(a) and interaction_pass(kind, e, a)
        rows.append({"kind": kind, "pass": ok, "expected": e.get("expected"),
                     "actual": a.get("expected") if a else None})
    passed = sum(1 for r in rows if r["pass"])
    interactions = {"pass": passed >= 5, "passed": passed, "total": len(rows),
                    "threshold": 5, "rows": rows}

    # 6) data boundary
    boundary = rb.get("data_boundary") or graph.get("data_boundary") or {}
    unlabeled = [r["route"] for r in routes if boundary.get(r["route"]) not in BOUNDARY]
    data = {"pass": not unlabeled, "pages": boundary, "unlabeled": unlabeled,
            "backend_required": rb.get("backend_required") or graph.get("backend_required") or []}
    criteria = {"route_coverage": route, "pixel": pixel, "dom": dom, "resources": resources,
                "interactions": interactions, "data_boundary": data}
    npass = sum(1 for v in criteria.values() if v.get("pass"))
    return {"schema": SCHEMA, "ok": True, "target": graph.get("target"),
            "origin": origin, "mode": "spa" if spa else "static",
            "criteria": criteria,
            "summary": {"passed": npass, "total": len(criteria),
                        "status": "PASS" if npass == len(criteria) else "PARTIAL",
                        "backend_required": data["backend_required"]}}


def self_test():
    tmp = tempfile.mkdtemp(prefix="site-diff-")
    try:
        from PIL import Image, ImageDraw
        crawl, rb = os.path.join(tmp, "crawl"), os.path.join(tmp, "rebuild")
        for d in (os.path.join(crawl, "pages"), os.path.join(crawl, "screenshots"),
                  os.path.join(rb, "local"), os.path.join(rb, "screenshots")):
            os.makedirs(d, exist_ok=True)
        html_a = "<html><body><h1>Hello</h1><p>same text</p><a href='/x'>x</a></body></html>"
        html_b = html_a
        open(os.path.join(crawl, "pages", "root.html"), "w", encoding="utf-8").write(html_a)
        open(os.path.join(rb, "local", "root.html"), "w", encoding="utf-8").write(html_b)
        img = Image.new("RGB", (120, 80), "white")
        dr = ImageDraw.Draw(img)
        dr.rectangle([10, 10, 60, 40], fill="black")
        img.save(os.path.join(crawl, "screenshots", "root.png"))
        img.save(os.path.join(rb, "screenshots", "root.png"))
        bad = Image.new("RGB", (120, 80), "white")
        ImageDraw.Draw(bad).rectangle([60, 40, 110, 70], fill="red")
        bad.save(os.path.join(rb, "screenshots", "bad.png"))
        graph = {"schema": "seep.site-crawl/1", "ok": True, "target": "fixture",
                 "origin": "http://fixture.invalid", "routes": [
                     {"route": "/", "html": "pages/root.html", "screenshot": "screenshots/root.png"}],
                 "coverage": {"expected": 1, "crawled": 1, "missing": 0, "missing_rate": 0.0},
                 "interactions": [{"kind": "title", "applicable": True, "expected": "T"},
                                  {"kind": "stylesheet_count", "applicable": True, "expected": 1},
                                  {"kind": "dom_nodes", "applicable": True, "expected": 6},
                                  {"kind": "link_count", "applicable": True, "expected": 1},
                                  {"kind": "heading_text", "applicable": True, "expected": "Hello"}],
                 "data_boundary": {"/": "recorded-snapshot"}, "backend_required": []}
        open(os.path.join(crawl, "site-graph.json"), "w", encoding="utf-8").write(
            json.dumps(graph, ensure_ascii=False))
        base_rb = {"schema": "seep.site-rebuild/1", "ok": True, "site_root": "site",
                   "local_pages": [{"route": "/", "html": "local/root.html",
                                    "screenshot": "screenshots/root.png"}],
                   "resources": {"http_404": 0, "external_links": 0, "requests": 3},
                   "assets_failed": [],
                   "interactions": [{"kind": "title", "applicable": True, "expected": "T"},
                                    {"kind": "stylesheet_count", "applicable": True, "expected": 1},
                                    {"kind": "dom_nodes", "applicable": True, "expected": 6},
                                    {"kind": "link_count", "applicable": True, "expected": 1},
                                    {"kind": "heading_text", "applicable": True, "expected": "Hello"}],
                   "data_boundary": {"/": "recorded-snapshot"}, "backend_required": []}
        open(os.path.join(rb, "rebuild.json"), "w", encoding="utf-8").write(
            json.dumps(base_rb, ensure_ascii=False))
        ok = compute(crawl, rb)
        assert ok["summary"]["status"] == "PASS", ok["summary"]
        base_rb["local_pages"][0]["screenshot"] = "screenshots/bad.png"
        open(os.path.join(rb, "rebuild.json"), "w", encoding="utf-8").write(
            json.dumps(base_rb, ensure_ascii=False))
        badres = compute(crawl, rb)
        assert badres["criteria"]["pixel"]["pass"] is False, badres["criteria"]["pixel"]
        return emit({"ok": True, "self_test": "site-diff", "pass_detected": True,
                     "pixel_fail_detected": True,
                     "pixel_ratio_fail": badres["criteria"]["pixel"]["max_ratio"]})
    except Exception as e:  # noqa: BLE001
        return blocked("self-test", "%s: %s" % (type(e).__name__, e))
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(
        description="Three-way site diff: pixel (Pillow/numpy), DOM structure/text, request set")
    ap.add_argument("--crawl", help="crawl output directory")
    ap.add_argument("--rebuild", help="rebuild output directory")
    ap.add_argument("--out", help="diff.json path (default <rebuild>/diff.json)")
    ap.add_argument("--pixel-threshold", type=float,
                    help="override threshold; default 0.01 static / 0.03 SPA")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.crawl or not a.rebuild:
        return blocked("args", "--crawl and --rebuild are required (or use --self-test)")
    try:
        res = compute(a.crawl, a.rebuild, a.pixel_threshold)
        out = a.out or os.path.join(a.rebuild, "diff.json")
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            json.dump(res, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")
        return emit({"ok": True, "schema": SCHEMA, "out": out,
                     "status": res["summary"]["status"],
                     "passed": res["summary"]["passed"], "total": res["summary"]["total"],
                     "pixel_max_ratio": res["criteria"]["pixel"]["max_ratio"],
                     "dom_min_similarity": res["criteria"]["dom"]["min_similarity"],
                     "missing_rate": res["criteria"]["route_coverage"]["missing_rate"],
                     "http_404": res["criteria"]["resources"]["http_404"],
                     "external_links": res["criteria"]["resources"]["external_links"],
                     "interactions_passed": res["criteria"]["interactions"]["passed"],
                     "backend_required": len(res["criteria"]["data_boundary"]["backend_required"])})
    except Exception as e:  # noqa: BLE001
        return blocked("diff", "%s: %s" % (type(e).__name__, e))


if __name__ == "__main__":
    sys.exit(main())
