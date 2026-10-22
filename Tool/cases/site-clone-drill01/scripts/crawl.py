#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""crawl.py — block.youtest.me 只读抓取（GET/HEAD、同源、<=2 rps、<=150 页）。

产出（默认落 Tool/cases/site-clone-drill01/artifacts/crawl/）：
  html/<slug>.html        服务端原始 HTML（未改写，绝对 URL 原样保留）
  shots/<slug>.png        1280x800 DPR=1 视口截图（禁用动画后）
  dom/<slug>.json         节点数 / 文本 / 标签序列（供离线副本做 DOM 相似度）
  assets/<path>           同源静态资源（_next/static、static/assets、字体、图片…）
  data/<path>             _next/data/*.json 与同源 fetch/xhr 响应体（回放用）
  network.json            逐页请求、XHR/fetch 清单、被策略拦截的外联
  routes.json             buildManifest 推断路由 + 页面实际链接 + 抓取结果
  har.json                最小 HAR（url/method/status/headers/content-type/body 路径）

策略：
  * 只放行 https://block.youtest.me 的 GET；跨域/非 GET 一律 abort 并记录（不改目标状态）。
  * 全局令牌桶严格 0.5s/请求（<=2 rps）。
  * 注入固定种子 Math.random + 禁动画 CSS，保证原站/离线截图可比较。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import sys
import threading
import time
import urllib.parse

from playwright.sync_api import sync_playwright

BASE = "https://block.youtest.me"
BUILD_ID_FALLBACK = ""
HERE = os.path.dirname(os.path.abspath(__file__))
CASE = os.path.dirname(HERE)
OUT = os.path.join(CASE, "artifacts", "crawl")
CHROME = os.environ.get(
    "SEEP_CHROME",
    "C:/Users/toti/AppData/Local/ms-playwright/chromium-1243/chrome-win64/chrome.exe",
)

FREEZE_CSS = (
    "*,*::before,*::after{animation:none!important;animation-delay:0s!important;"
    "transition:none!important;caret-color:transparent!important}"
    "html{scroll-behavior:auto!important}"
)
SEED_JS = """
(() => {
  let s = 42 >>> 0;
  Math.random = function () {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 4294967296;
  };
  // 冻结 rAF 时间戳：Lottie/JS 动画停在同一相位，原站与离线才可比
  const raf = window.requestAnimationFrame.bind(window);
  window.requestAnimationFrame = function (cb) {
    return raf(function () { cb(1200); });
  };
})();
"""


class Bucket:
    """全局最小间隔令牌桶：所有出站请求共用。"""

    def __init__(self, rps: float):
        self.interval = 1.0 / float(rps)
        self.next_at = 0.0
        self.lock = threading.Lock()
        self.count = 0

    def wait(self):
        with self.lock:
            now = time.time()
            if now < self.next_at:
                time.sleep(self.next_at - now)
            self.next_at = max(now, self.next_at) + self.interval
            self.count += 1


def wait_loading_gone(page, timeout_ms=20000):
    """等应用自己的 LoadingScreen 消失（客户端重定向/水合完成）。"""
    try:
        page.wait_for_function(
            "() => !document.querySelector('[class*=\"LoadingScreen\"]')",
            timeout=timeout_ms)
        return True
    except Exception:
        return False


def wait_stable(page, quiet_ms=1200, timeout_ms=15000):
    """等 DOM 节点数/文本长度/路由连续 quiet_ms 不变（含客户端重定向）。"""
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


def slug(route: str) -> str:
    if route in ("/", ""):
        return "index"
    return route.strip("/").replace("/", "_").replace("?", "_")


def save(path: str, data: bytes) -> str:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path


def asset_rel(url: str) -> str:
    """把同源 URL 映射成 assets/ 下的相对路径（丢弃 query）。"""
    u = urllib.parse.urlsplit(url)
    p = urllib.parse.unquote(u.path).lstrip("/")
    if not p:
        p = "index.html"
    if p.endswith("/"):
        p += "index.html"
    return p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rps", type=float, default=2.0)
    ap.add_argument("--max-pages", type=int, default=150)
    ap.add_argument("--width", type=int, default=1280)
    ap.add_argument("--height", type=int, default=800)
    ap.add_argument("--quiet-settle", type=float, default=2500)
    args = ap.parse_args()

    for d in ("html", "shots", "dom", "assets", "data"):
        os.makedirs(os.path.join(OUT, d), exist_ok=True)

    bucket = Bucket(args.rps)
    pages_meta = []
    all_requests = []            # 所有观测到的请求（含被拦截）
    asset_index = {}             # url -> {"path": rel, "sha256": ..., "content_type": ...}
    har_entries = []
    doc_html = {}                # route -> raw HTML（供 rebuild）
    seen_bodies = set()

    def on_response(resp):
        req = resp.request
        try:
            headers = resp.headers
        except Exception:
            headers = {}
        ct = (headers.get("content-type") or "").split(";")[0].strip().lower()
        rec = {
            "url": resp.url,
            "method": req.method,
            "resource_type": req.resource_type,
            "status": resp.status,
            "content_type": ct,
            "same_origin": resp.url.startswith(BASE),
            "page": req.frame.url if req.frame else "",
        }
        all_requests.append(rec)
        if not rec["same_origin"] or req.method not in ("GET", "HEAD"):
            return
        if resp.url in seen_bodies:
            return
        try:
            body = resp.body()
        except Exception as e:  # noqa: BLE001
            rec["body_error"] = str(e)[:80]
            return
        seen_bodies.add(resp.url)
        rec["size"] = len(body)
        rec["sha256"] = hashlib.sha256(body).hexdigest()
        if req.resource_type == "document" or ct == "text/html":
            rel = "html/" + slug(urllib.parse.urlsplit(resp.url).path) + ".html"
            save(os.path.join(OUT, rel), body)
            rec["saved"] = rel
            doc_html[urllib.parse.urlsplit(resp.url).path] = body
        else:
            rel = asset_rel(resp.url)
            target = os.path.join(OUT, "data" if (req.resource_type in ("xhr", "fetch")
                                                 or "/_next/data/" in resp.url) else "assets", rel)
            save(target, body)
            rec["saved"] = os.path.relpath(target, OUT).replace(os.sep, "/")
            asset_index[resp.url] = {"path": rec["saved"], "sha256": rec["sha256"],
                                     "content_type": ct, "status": resp.status}
        har_entries.append({
            "request": {"method": req.method, "url": resp.url},
            "response": {"status": resp.status,
                         "content": {"mimeType": ct, "size": len(body),
                                     "text_path": rec["saved"]}},
        })

    def make_handler(page_label):
        def handler(route):
            req = route.request
            url = req.url
            allowed = url.startswith(BASE) and req.method in ("GET", "HEAD")
            if not allowed:
                all_requests.append({
                    "url": url, "method": req.method,
                    "resource_type": req.resource_type, "status": 0,
                    "content_type": "", "same_origin": url.startswith(BASE),
                    "page": page_label, "blocked": True,
                })
                route.abort()
                return
            bucket.wait()
            try:
                route.continue_()
            except Exception:
                pass
        return handler

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, executable_path=CHROME)
        ctx = browser.new_context(
            viewport={"width": args.width, "height": args.height},
            device_scale_factor=1,
            locale="en-US",
        )
        ctx.add_init_script(SEED_JS)
        ctx.on("response", on_response)
        page = ctx.new_page()
        page.route("**/*", make_handler("bootstrap"))

        # 1) buildManifest 推断路由（同源 GET，计入限速）
        bm_url = None
        bucket.wait()
        r = ctx.request.get(BASE + "/")
        home_html = r.body().decode("utf-8", "replace")
        m = re.search(r'"buildId":"([^"]+)"', home_html)
        build_id = m.group(1) if m else BUILD_ID_FALLBACK
        bm_url = f"{BASE}/_next/static/{build_id}/_buildManifest.js"
        bucket.wait()
        bm_txt = ctx.request.get(bm_url).text()
        routes = [x for x in re.findall(r'"/([A-Za-z0-9_\-/]*)"\s*:\s*\[', bm_txt)]
        routes = ["/" + x for x in routes]
        routes = [x for x in routes if x not in ("/_app", "/_error")]
        routes = sorted(set(routes), key=lambda x: (x.count("/"), x))
        if "/" not in routes:
            routes.insert(0, "/")

        # 1b) 补齐 buildManifest 里的路由 chunk 与 _next/data JSON（同源 GET）
        route_chunks = {}
        for m in re.finditer(r'"(/[^"]+)"\s*:\s*\[([^\]]*)\]', bm_txt):
            rt, payload = m.group(1), m.group(2)
            if rt in ("/_app", "/_error"):
                continue
            route_chunks[rt] = re.findall(r'"([^"]+)"', payload)
        prefetch = []
        for rt, chunks in route_chunks.items():
            for c in chunks:
                prefetch.append(BASE + "/_next/" + c.lstrip("/"))
        for rt in routes:
            data_path = "index.json" if rt == "/" else rt.strip("/") + ".json"
            prefetch.append(f"{BASE}/_next/data/{build_id}/{data_path}")
        for url in dict.fromkeys(prefetch):
            if url in asset_index:
                continue
            bucket.wait()
            try:
                rr = ctx.request.get(url, timeout=30000)
                if rr.status != 200:
                    continue
                body = rr.body()
                ct = (rr.headers.get("content-type") or "").split(";")[0].strip().lower()
                is_data = "/_next/data/" in url
                rel = asset_rel(url)
                target = os.path.join(OUT, "data" if is_data else "assets", rel)
                save(target, body)
                asset_index[url] = {
                    "path": os.path.relpath(target, OUT).replace(os.sep, "/"),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "content_type": ct, "status": 200,
                }
            except Exception:
                continue

        # 2) 逐页抓取
        links = {}
        for route in routes[: args.max_pages]:
            page.unroute_all(behavior="ignoreErrors")
            page.route("**/*", make_handler(route))
            url = BASE + route
            rec = {"route": route, "url": url, "ok": False}
            try:
                resp = page.goto(url, wait_until="load", timeout=90000)
                rec["status"] = resp.status if resp else None
                try:
                    page.wait_for_load_state("networkidle", timeout=30000)
                except Exception:
                    rec["networkidle"] = "timeout"
                page.wait_for_timeout(800)
                rec["loading_gone"] = wait_loading_gone(page)
                rec["dom_stable"] = wait_stable(page, quiet_ms=2000)
                page.evaluate("document.fonts && document.fonts.ready")
                page.add_style_tag(content=FREEZE_CSS)
                page.evaluate("window.scrollTo(0,0)")
                page.wait_for_timeout(400)
                rec["final_url"] = page.url
                rec["title"] = page.title()
                stats = page.evaluate(
                    """() => {
                        const els = Array.from(document.querySelectorAll('*'));
                        const tags = els.slice(0, 6000).map(e => e.tagName.toLowerCase());
                        const txt = (document.body ? document.body.innerText : '')
                            .replace(/\\s+/g, ' ').trim();
                        const imgs = Array.from(document.images).map(im => {
                            const r = im.getBoundingClientRect();
                            return {src: im.currentSrc || im.src,
                                    x: r.x, y: r.y, w: r.width, h: r.height};
                        }).filter(o => o.w > 0 && o.h > 0 &&
                                   o.y < innerHeight && o.y + o.h > 0);
                        return {nodes: els.length, tags: tags, text: txt,
                                images: imgs,
                                html_len: document.documentElement.outerHTML.length};
                    }"""
                )
                stats.update({"route": route, "url": url, "final_url": rec["final_url"],
                              "title": rec["title"], "status": rec.get("status")})
                save(os.path.join(OUT, "dom", slug(route) + ".json"),
                     json.dumps(stats, ensure_ascii=False, indent=1).encode("utf-8"))
                rec.update({"nodes": stats["nodes"], "text_len": len(stats["text"]),
                            "body": stats["text"][:300]})
                page.screenshot(path=os.path.join(OUT, "shots", slug(route) + ".png"),
                                full_page=False)
                # 页面内链接（同源、无 hash）
                anchors = page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)")
                links[route] = sorted({a for a in anchors if a.startswith(BASE)})
                rec["ok"] = True
            except Exception as e:  # noqa: BLE001
                rec["error"] = f"{type(e).__name__}: {str(e)[:200]}"
            pages_meta.append(rec)
            print(f"[page] {route} -> {rec.get('status')} nodes={rec.get('nodes')} "
                  f"final={rec.get('final_url')} {rec.get('error', '')}", flush=True)

        # 3) 资产推断：从已抓 HTML/CSS/JS 里找 /_next/static、/static 引用
        candidates = set()
        pat_abs = re.compile(r"https?://block\.youtest\.me(/[^\"'\\\s)>]+)")
        pat_rel = re.compile(r"[\"'(](/(?:_next/static|static/assets)/[^\"'\\\s)>]+)")
        pat_cssurl = re.compile(r"url\((['\"]?)(/[^)'\"\\]+)\1\)")
        for dp, _dn, fn in os.walk(OUT):
            for f in fn:
                if not f.lower().endswith((".html", ".css", ".js", ".json", ".webmanifest")):
                    continue
                fp = os.path.join(dp, f)
                try:
                    text = open(fp, encoding="utf-8", errors="replace").read()
                except Exception:
                    continue
                for pat in (pat_abs, pat_rel, pat_cssurl):
                    for mm in pat.finditer(text):
                        path = mm.group(1)
                        if path.startswith("/_next/static") or path.startswith("/static/assets"):
                            candidates.add(path)
        # 常见站点级文件
        for extra in ("/favicon.ico", "/favicon.svg", "/favicon-96x96.png",
                      "/apple-touch-icon.png", "/site.webmanifest",
                      "/web-app-manifest-192x192.png", "/web-app-manifest-512x512.png"):
            candidates.add(extra)

        fetched = 0
        for path in sorted(candidates):
            url = BASE + path
            if url in asset_index:
                continue
            if fetched >= 600:
                break
            bucket.wait()
            try:
                rr = ctx.request.get(url, timeout=30000)
                if rr.status != 200:
                    continue
                body = rr.body()
                ct = (rr.headers.get("content-type") or "").split(";")[0].strip().lower()
                rel = asset_rel(url)
                target = os.path.join(OUT, "assets", rel)
                save(target, body)
                asset_index[url] = {
                    "path": os.path.relpath(target, OUT).replace(os.sep, "/"),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "content_type": ct, "status": 200,
                }
                fetched += 1
            except Exception:
                continue

        browser.close()

    # 4) 汇总
    xhr = [r for r in all_requests
           if r["resource_type"] in ("xhr", "fetch") or "/_next/data/" in r["url"]]
    for r in xhr:
        r["is_data_interface"] = bool(
            (r.get("content_type") or "").startswith("application/json")
            or "/_next/data/" in r["url"] or "/api/" in r["url"])
    blocked = [r for r in all_requests if r.get("blocked")]
    net = {
        "target": BASE,
        "build_id": build_id if "build_id" in dir() else "",
        "rps": args.rps,
        "pages": pages_meta,
        "requests_total": len(all_requests),
        "same_origin_assets": asset_index,
        "xhr_fetch": xhr,
        "blocked_by_policy": blocked,
        "blocked_hosts": sorted({urllib.parse.urlsplit(r["url"]).netloc for r in blocked}),
    }
    save(os.path.join(OUT, "network.json"),
         json.dumps(net, ensure_ascii=False, indent=1).encode("utf-8"))
    save(os.path.join(OUT, "har.json"),
         json.dumps({"log": {"entries": har_entries}}, ensure_ascii=False,
                    indent=1).encode("utf-8"))
    save(os.path.join(OUT, "routes.json"),
         json.dumps({"from_build_manifest": routes, "page_links": links,
                     "crawled": pages_meta}, ensure_ascii=False,
                    indent=1).encode("utf-8"))

    ok = [x for x in pages_meta if x.get("ok")]
    print(f"[done] pages ok={len(ok)}/{len(pages_meta)} assets={len(asset_index)} "
          f"xhr={len(xhr)} blocked={len(blocked)} requests={len(all_requests)}", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
