#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""replay_diff.py — 离线副本三方对比：像素 / DOM / 网络。

流程：
  1. `python -m http.server` 等价的内置 ThreadingHTTPServer 服务 artifacts/site/；
  2. Playwright 打开每个 route，用 page.route 把同源 XHR/fetch 按
     artifacts/site/_replay/mocks.json（录制响应）回放；外联一律 abort 并记录；
  3. 1280x800 DPR=1 截图（与抓取同样禁动画 + 固定 Math.random 种子）；
  4. Pillow/numpy 算差异像素占比；DOM 用节点数/文本 3-gram Dice/标签序列相似度；
  5. 输出 artifacts/diff.json + artifacts/offline/{shots,dom,network.json}。

像素判据：任一 RGB 通道差 > 12/255 记为一个差异像素；另报平均绝对差。
DOM 判据：nodes=1-|a-b|/max；text=字符 3-gram Dice；struct=标签序列
          difflib.SequenceMatcher.ratio；总分 0.30*nodes+0.35*text+0.35*struct。
"""
from __future__ import annotations

import argparse
import difflib
import functools
import http.server
import json
import os
import socket
import socketserver
import sys
import threading
import time
import urllib.parse

import numpy as np
from PIL import Image
from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
CASE = os.path.dirname(HERE)
CRAWL = os.path.join(CASE, "artifacts", "crawl")
SITE = os.path.join(CASE, "artifacts", "site")
OFF = os.path.join(CASE, "artifacts", "offline")
DIFF = os.path.join(CASE, "artifacts", "diff.json")
CHROME = os.environ.get(
    "SEEP_CHROME",
    os.path.expanduser("~/AppData/Local/ms-playwright/chromium-1243/chrome-win64/chrome.exe"),
)

FREEZE_CSS = (
    "*,*::before,*::after{animation:none!important;animation-delay:0s!important;"
    "transition:none!important;caret-color:transparent!important}"
    "html{scroll-behavior:auto!important}"
)
SEED_JS = """
(() => { let s = 42 >>> 0;
  Math.random = function () { s = (s * 1664525 + 1013904223) >>> 0; return s / 4294967296; };
  const raf = window.requestAnimationFrame.bind(window);
  window.requestAnimationFrame = function (cb) {
    return raf(function () { cb(1200); });
  };
})();
"""
# 第三方（广告/追踪）与跨域数据 API 的分类白名单
THIRD_PARTY_SUFFIX = (
    "googlesyndication.com", "doubleclick.net", "adtrafficquality.google",
    "fundingchoicesmessages.google.com", "cloudflareinsights.com",
    "google-analytics.com", "googletagmanager.com", "gstatic.com", "google.com",
)


def slug(route: str) -> str:
    if route in ("/", ""):
        return "index"
    return route.strip("/").replace("/", "_").replace("?", "_")


def start_server(root: str):
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *a):  # noqa: D401
            pass

    class TS(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    srv = TS(("127.0.0.1", 0), functools.partial(Quiet, directory=root))
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{port}", port


def wait_loading_gone(page, timeout_ms=20000):
    try:
        page.wait_for_function(
            "() => !document.querySelector('[class*=\"LoadingScreen\"]')",
            timeout=timeout_ms)
        return True
    except Exception:
        return False


def wait_stable(page, quiet_ms=1200, timeout_ms=15000):
    prev, stable_since, t0 = None, None, time.time()
    while (time.time() - t0) * 1000 < timeout_ms:
        cur = page.evaluate(
            """() => [document.querySelectorAll('*').length,
                      (document.body ? document.body.innerText : '').length,
                      location.pathname + location.search,
                      document.querySelectorAll('canvas').length]""")
        if cur == prev:
            if stable_since and (time.time() - stable_since) * 1000 >= quiet_ms:
                return True
        else:
            prev, stable_since = cur, time.time()
        page.wait_for_timeout(150)
    return False


def dom_stats(page):
    return page.evaluate(
        """() => {
            const els = Array.from(document.querySelectorAll('*'));
            return {nodes: els.length,
                    tags: els.slice(0, 6000).map(e => e.tagName.toLowerCase()),
                    text: (document.body ? document.body.innerText : '').replace(/\\s+/g, ' ').trim(),
                    title: document.title, url: location.href,
                    html_len: document.documentElement.outerHTML.length};
        }"""
    )


def text_dice(a: str, b: str) -> float:
    def grams(s):
        s = s.lower()
        return {s[i:i + 3] for i in range(max(0, len(s) - 2))}
    ga, gb = grams(a), grams(b)
    if not ga and not gb:
        return 1.0
    return 2.0 * len(ga & gb) / (len(ga) + len(gb))


def dom_similarity(a, b) -> dict:
    node_sim = 1.0 - abs(a["nodes"] - b["nodes"]) / max(a["nodes"], b["nodes"], 1)
    text_sim = text_dice(a["text"], b["text"])
    struct_sim = difflib.SequenceMatcher(
        None, a["tags"][:6000], b["tags"][:6000], autojunk=False).ratio()
    score = 0.30 * node_sim + 0.35 * text_sim + 0.35 * struct_sim
    return {"node_sim": round(node_sim, 4), "text_sim": round(text_sim, 4),
            "struct_sim": round(struct_sim, 4), "score": round(score, 4),
            "nodes_recorded": a["nodes"], "nodes_offline": b["nodes"],
            "text_len_recorded": len(a["text"]), "text_len_offline": len(b["text"])}


def animated_asset_paths() -> set:
    """扫描抓取到的 WebP，找出带 ANIM 块的动图（逐帧不可比，需按区域遮罩）。"""
    out = set()
    root = os.path.join(CRAWL, "assets")
    for dp, _dn, fn in os.walk(root):
        for f in fn:
            p = os.path.join(dp, f)
            try:
                head = open(p, "rb").read(64)
            except Exception:
                continue
            if head[:4] == b"RIFF" and head[8:12] == b"WEBP" and b"ANIM" in head:
                out.add(os.path.relpath(p, root).replace(os.sep, "/"))
    return out


def _rect_mask(imgs, anim_paths, w, h):
    mask = np.zeros((h, w), dtype=bool)
    for o in imgs or []:
        path = urllib.parse.urlsplit(o.get("src", "")).path.lstrip("/")
        if path in anim_paths:
            x0 = max(0, int(o["x"]) - 1)
            y0 = max(0, int(o["y"]) - 1)
            x1 = min(w, int(o["x"] + o["w"]) + 1)
            y1 = min(h, int(o["y"] + o["h"]) + 1)
            if x1 > x0 and y1 > y0:
                mask[y0:y1, x0:x1] = True
    return mask


def pixel_diff(orig_path: str, off_path: str, orig_imgs, off_imgs,
               anim_paths, threshold: int = 12) -> dict:
    a = np.asarray(Image.open(orig_path).convert("RGB"), dtype=np.int16)
    b = np.asarray(Image.open(off_path).convert("RGB"), dtype=np.int16)
    if a.shape != b.shape:
        return {"diff_ratio": None, "mean_abs": None,
                "size_mismatch": [list(a.shape), list(b.shape)]}
    h, w = a.shape[:2]
    d = np.abs(a - b)
    changed = d.max(axis=2) > threshold
    total = h * w
    mask = _rect_mask(orig_imgs, anim_paths, w, h) | _rect_mask(off_imgs, anim_paths, w, h)
    valid = int((~mask).sum())
    static_px = int((changed & ~mask).sum())
    masked_px = int((changed & mask).sum())
    return {"diff_ratio": round(int(changed.sum()) / total, 6),
            "diff_ratio_static": round(static_px / valid, 6) if valid else None,
            "diff_pixels": int(changed.sum()),
            "diff_pixels_static": static_px,
            "diff_pixels_in_animated": masked_px,
            "animated_mask_ratio": round(float(mask.sum()) / total, 6),
            "animated_imgs": sorted({urllib.parse.urlsplit(o["src"]).path
                                     for o in (orig_imgs or []) 
                                     if urllib.parse.urlsplit(o["src"]).path.lstrip("/") in anim_paths}),
            "mean_abs": round(float(d.mean()), 4), "threshold": threshold}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=int, default=12)
    args = ap.parse_args()

    for d in ("shots", "dom"):
        os.makedirs(os.path.join(OFF, d), exist_ok=True)

    net = json.load(open(os.path.join(CRAWL, "network.json"), encoding="utf-8"))
    routes_doc = json.load(open(os.path.join(CRAWL, "routes.json"), encoding="utf-8"))
    crawled = [p for p in routes_doc["crawled"] if p.get("ok")]
    mocks = json.load(open(os.path.join(SITE, "_replay", "mocks.json"),
                           encoding="utf-8"))["mocks"]
    anim_paths = animated_asset_paths()

    srv, local_base, port = start_server(SITE)
    print(f"[serve] {SITE} -> {local_base}")

    ext_attempts = []
    replay_log = []
    dom_pairs = []
    pixel_pairs = []

    def handler(route):
        req = route.request
        url = req.url
        sp = urllib.parse.urlsplit(url)
        if url.startswith(local_base):
            key_full = sp.path + ("?" + sp.query if sp.query else "")
            entry = mocks.get(key_full) or mocks.get(sp.path)
            is_data = req.resource_type in ("xhr", "fetch") or sp.path.startswith("/_next/data/")
            if entry and is_data:
                body_path = os.path.join(SITE, entry["body"])
                body = open(body_path, "rb").read()
                route.fulfill(status=int(entry["status"]),
                              headers={"content-type": entry["content_type"]},
                              body=body)
                replay_log.append({"url": url, "mock": entry["body"],
                                   "recorded_url": entry["recorded_url"],
                                   "page": req.frame.url if req.frame else ""})
                return
            route.continue_()
            return
        ext_attempts.append({"url": url, "host": sp.netloc, "method": req.method,
                             "resource_type": req.resource_type,
                             "page": req.frame.url if req.frame else ""})
        route.abort()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path=CHROME)
        ctx = browser.new_context(viewport={"width": 1280, "height": 800},
                                  device_scale_factor=1, locale="en-US")
        ctx.add_init_script(SEED_JS)
        page = ctx.new_page()
        page.route("**/*", handler)

        for rec in crawled:
            route = rec["route"]
            url = local_base + route
            item = {"route": route, "url": url}
            try:
                resp = page.goto(url, wait_until="load", timeout=60000)
                item["status"] = resp.status if resp else None
                try:
                    page.wait_for_load_state("networkidle", timeout=20000)
                except Exception:
                    item["networkidle"] = "timeout"
                page.wait_for_timeout(800)
                item["loading_gone"] = wait_loading_gone(page)
                item["dom_stable"] = wait_stable(page, quiet_ms=2000)
                page.evaluate("document.fonts && document.fonts.ready")
                page.add_style_tag(content=FREEZE_CSS)
                page.evaluate("window.scrollTo(0,0)")
                page.wait_for_timeout(400)
                item["final_url"] = page.url
                st = dom_stats(page)
                st["route"] = route
                st["final_url"] = page.url
                with open(os.path.join(OFF, "dom", slug(route) + ".json"), "w",
                          encoding="utf-8", newline="\n") as f:
                    json.dump(st, f, ensure_ascii=False, indent=1)
                shot = os.path.join(OFF, "shots", slug(route) + ".png")
                page.screenshot(path=shot, full_page=False)
                orig_shot = os.path.join(CRAWL, "shots", slug(route) + ".png")
                orig_dom = json.load(open(os.path.join(CRAWL, "dom", slug(route) + ".json"),
                                          encoding="utf-8"))
                px = pixel_diff(orig_shot, shot, orig_dom.get("images"),
                                st.get("images"), anim_paths, args.threshold)
                px["route"] = route
                pixel_pairs.append(px)
                ds = dom_similarity(orig_dom, st)
                ds["route"] = route
                dom_pairs.append(ds)
                item["pixel_diff_ratio"] = px.get("diff_ratio")
                item["dom_score"] = ds["score"]
                item["ok"] = True
            except Exception as e:  # noqa: BLE001
                item["error"] = f"{type(e).__name__}: {str(e)[:200]}"
                print(f"[offline] {route} ERROR {item['error']}", flush=True)
            print(f"[offline] {route} status={item.get('status')} "
                  f"diff={item.get('pixel_diff_ratio')} dom={item.get('dom_score')}",
                  flush=True)

        browser.close()
    srv.shutdown()

    # ---- 网络残留分类
    by_host = {}
    for a in ext_attempts:
        by_host.setdefault(a["host"], {"host": a["host"], "count": 0,
                                       "resource_types": {}, "sample": a["url"]})
        by_host[a["host"]]["count"] += 1
        rt = a["resource_type"]
        by_host[a["host"]]["resource_types"][rt] = \
            by_host[a["host"]]["resource_types"].get(rt, 0) + 1
    whitelist, unexpected = [], []
    for h, info in sorted(by_host.items()):
        if h == "youtest.me":
            info["classification"] = "policy-excluded-cross-origin-brand-asset"
            info["reason"] = ("母品牌域 promo 图片；违反同源约束，未抓取，离线显示占位"
                              "（非核心 UI）")
        elif h == "api.youtest.me":
            info["classification"] = "backend-required-api"
            info["reason"] = "跨域数据接口 GET /info/country；同源克隆范围外，抓取阶段即拦截"
        elif any(h.endswith(s) for s in THIRD_PARTY_SUFFIX):
            info["classification"] = "policy-excluded-third-party"
            info["reason"] = "广告/追踪；抓取阶段一律 abort，不属于同源副本"
        else:
            info["classification"] = "unexpected"
        if info["classification"] == "unexpected":
            unexpected.append(info)
        else:
            whitelist.append(info)

    # ---- 数据边界（逐页）
    boundaries = []
    for rec in crawled:
        route = rec["route"]
        final = rec.get("final_url", "")
        err = urllib.parse.parse_qs(urllib.parse.urlsplit(final).query).get("error", [""])[0]
        redirected = urllib.parse.urlsplit(final).path != route
        if redirected:
            boundary = "backend-required"
            reason = ("路由守卫在缺少 user/player 会话时重定向到 "
                      + urllib.parse.urlsplit(final).path
                      + (f"（error={err}）" if err else ""))
        else:
            boundary = "recorded-snapshot"
            reason = "静态导出页面；数据来自录制 HTML/__NEXT_DATA__（及回放的 _next/data）"
        boundaries.append({"route": route, "boundary": boundary, "reason": reason,
                           "final_url": final})

    overall_px = (sum(x["diff_ratio"] for x in pixel_pairs if x["diff_ratio"] is not None)
                  / max(1, len([x for x in pixel_pairs if x["diff_ratio"] is not None])))
    static = [x["diff_ratio_static"] for x in pixel_pairs if x.get("diff_ratio_static") is not None]
    overall_static = sum(static) / max(1, len(static))
    overall_dom = sum(x["score"] for x in dom_pairs) / max(1, len(dom_pairs))

    out = {
        "target": "https://block.youtest.me",
        "method": {
            "viewport": "1280x800",
            "dpr": 1,
            "freeze_animations": True,
            "seeded_math_random": True,
            "pixel": "任一 RGB 通道 |Δ|>%d 记为差异像素；diff_ratio 含全部像素；"
                     "diff_ratio_static 排除动画 WebP（ANIM 块）包围盒后计算，逐帧动图不可比；"
                     "mean_abs 为全通道平均绝对差" % args.threshold,
            "dom": "nodes=1-|a-b|/max；text=字符 3-gram Dice；struct=标签前序序列 "
                   "difflib.SequenceMatcher.ratio；score=0.30/0.35/0.35",
        },
        "crawl": {"build_id": net.get("build_id"), "pages": len(crawled),
                  "routes_from_build_manifest": len(routes_doc["from_build_manifest"]),
                  "assets_same_origin": len(net["same_origin_assets"]),
                  "xhr_fetch": len(net["xhr_fetch"]),
                  "data_interfaces": sum(1 for r in net["xhr_fetch"] if r.get("is_data_interface")),
                  "blocked_by_policy": len(net["blocked_by_policy"]),
                  "blocked_hosts": net.get("blocked_hosts")},
        "pixel": {"overall_diff_ratio": round(overall_px, 6),
                  "overall_diff_ratio_static": round(overall_static, 6),
                  "threshold": args.threshold, "pages": pixel_pairs},
        "dom": {"overall_score": round(overall_dom, 4), "pages": dom_pairs},
        "network": {
            "local_base": local_base,
            "replayed_mocks": len(replay_log),
            "replayed": replay_log,
            "external_attempts_total": len(ext_attempts),
            "external_hosts": whitelist,
            "unexpected": unexpected,
            "verdict": ("clean" if not ext_attempts
                        else ("whitelist-only" if not unexpected else "unexpected-traffic")),
        },
        "data_boundary": boundaries,
        "backend_required_features": [
            "创建测验并写入后端（/user/creating -> POST api.youtest.me，未提交）",
            "玩家加入/答题（/find、/player/* 需要 quiz/user 会话数据）",
            "成绩榜与逐题答案（/user/scoreboard*、/user/share 需要后端记录）",
            "分享链接落地页（/user/share 依赖后端 user 数据）",
            "跨域国家/地区查询 api.youtest.me/info/country（同源范围外，未复制）",
        ],
        "local_mock_pages": [b["route"] for b in boundaries if b["boundary"] == "local-mock"],
    }
    # diff.json 用 ASCII 转义落盘：保证 Windows 默认 GBK 下 `json.load(open(...))`
    # 也能直接读取（验收脚本就是裸 open）。
    with open(DIFF, "w", encoding="utf-8", newline="\n") as f:
        json.dump(out, f, ensure_ascii=True, indent=1)
    with open(os.path.join(OFF, "network.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump({"external_attempts": ext_attempts, "replayed": replay_log,
                   "whitelist": whitelist, "unexpected": unexpected}, f,
                  ensure_ascii=False, indent=1)
    print(json.dumps({"pixel_overall": out["pixel"]["overall_diff_ratio"],
                      "pixel_overall_static": out["pixel"]["overall_diff_ratio_static"],
                      "dom_overall": out["dom"]["overall_score"],
                      "external": out["network"]["external_attempts_total"],
                      "verdict": out["network"]["verdict"],
                      "mocks": len(replay_log)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
