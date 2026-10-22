#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""site-rebuild.py -- materialise a crawled site offline: local assets, rewritten
links, HAR mock for Playwright page.route, and an http.server preview.

Input : a directory produced by site-crawl.py (site-graph.json + pages/ + screenshots/)
Output: <out>/site/ (static preview root), <out>/har.json, <out>/mock/playwright-route.js,
        <out>/rebuild.json, <out>/local/ (DOM after local load), <out>/screenshots/ (rebuilt).

Usage:
  python Tool/skill/site-clone/scripts/site-rebuild.py --crawl work/crawl --out work/rebuild
  python Tool/skill/site-clone/scripts/site-rebuild.py --crawl work/crawl --out work/rebuild --serve --port 8787
  python Tool/skill/site-clone/scripts/site-rebuild.py --self-test
  python Tool/skill/site-clone/scripts/site-rebuild.py --help

Exit codes: 0 = ok; 2 = blocked (structured JSON on stdout).
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import glob
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import traceback
import time
import urllib.parse
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

SCHEMA = "seep.site-rebuild/1"
UA = "seep-site-clone/1.0 (+authorized 1:1 clone; GET only)"
PNG_1PX = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
ASSET_EXT = (".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
             ".ico", ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".webm", ".avif")


def emit(obj, code=0):
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    return code


def blocked(at, reason):
    return emit({"ok": False, "blocked_at": at, "reason": str(reason)[:500]}, 2)


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def read_json(p):
    with open(p, encoding="utf-8-sig") as f:
        return json.load(f)


def norm_url(u, base=None):
    u = urllib.parse.urljoin(base, u) if base else u
    p = urllib.parse.urlsplit(u)
    return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", p.query, ""))


def same_origin(u, origin):
    p, o = urllib.parse.urlsplit(u), urllib.parse.urlsplit(origin)
    return (p.scheme, p.netloc.lower()) == (o.scheme, o.netloc.lower())


def slug(route):
    s = re.sub(r"[^A-Za-z0-9]+", "_", route).strip("_")
    return s or "root"


def route_file(route):
    if route in ("", "/"):
        return "index.html"
    clean = route.strip("/")
    if "." in clean.rsplit("/", 1)[-1]:
        return clean
    return clean + "/index.html"


def local_url_path(url):
    p = urllib.parse.urlsplit(url)
    path = urllib.parse.unquote(p.path or "/")
    if path.endswith("/"):
        path += "index.html"
    return path


def find_chromium():
    env = os.environ.get("SITE_CLONE_CHROMIUM") or os.environ.get("CHROMIUM_PATH")
    if env and os.path.isfile(env):
        return env
    roots = []
    for k in ("LOCALAPPDATA", "APPDATA"):
        if os.environ.get(k):
            roots.append(os.path.join(os.environ[k], "ms-playwright"))
    if os.environ.get("HOME"):
        roots += [os.path.join(os.environ["HOME"], ".cache", "ms-playwright"),
                  os.path.join(os.environ["HOME"], "AppData", "Local", "ms-playwright")]
    pats = []
    for r in roots:
        pats += [os.path.join(r, "chromium-*", "chrome-*", "chrome.exe"),
                 os.path.join(r, "chromium-*", "chrome-*", "chrome")]
    for p in pats:
        hits = sorted(glob.glob(p))
        if hits:
            return hits[-1]
    return None


class Rate:
    def __init__(self, rps):
        self.delay = 1.0 / max(float(rps), 0.1)
        self.last = 0.0

    def wait(self):
        s = self.delay - (time.time() - self.last)
        if s > 0:
            time.sleep(s)
        self.last = time.time()


class Quiet(SimpleHTTPRequestHandler):
    def log_message(self, *a, **k):
        pass


def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.geturl(), dict(r.headers), r.read()


def write_file(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
    kw = {} if mode == "wb" else {"encoding": "utf-8", "newline": "\n"}
    with open(path, mode, **kw) as f:
        f.write(data)


def download_assets(graph, site, rps, timeout):
    origin = graph["origin"]
    rate = Rate(rps)
    saved, failed = [], []
    seen = set()
    for a in graph.get("assets") or []:
        u = a.get("url") or ""
        if not u or u in seen:
            continue
        seen.add(u)
        if not same_origin(u, origin):
            continue
        rp = urllib.parse.urlsplit(u).path
        if rp.startswith("/_next/data/") or rp.startswith("/api/"):
            continue
        rel = local_url_path(u).lstrip("/")
        dest = os.path.join(site, rel)
        if os.path.isfile(dest):
            continue
        rate.wait()
        try:
            status, final, hdr, body = fetch(u, timeout=timeout)
            if status != 200:
                failed.append({"url": u, "status": status})
                continue
            write_file(dest, body)
            saved.append({"url": u, "file": "site/" + rel, "status": status,
                          "content_type": hdr.get("Content-Type", ""),
                          "sha256": sha256_bytes(body), "bytes": len(body)})
        except Exception as e:  # noqa: BLE001
            failed.append({"url": u, "error": str(e)[:160]})
    return saved, failed


def copy_api(graph, crawl, site, out):
    entries, har_entries = [], []
    for i, ent in enumerate(graph.get("api") or []):
        bf = ent.get("body_file")
        if not bf:
            continue
        src = os.path.join(crawl, bf)
        if not os.path.isfile(src):
            continue
        body = open(src, "rb").read()
        u = ent["url"]
        if same_origin(u, graph["origin"]):
            rel = local_url_path(u).lstrip("/")
            write_file(os.path.join(site, rel), body)
            target = "site/" + rel
        else:
            host = urllib.parse.urlsplit(u).hostname or "external"
            rel = "mock/api/%s/%s" % (host, local_url_path(u).lstrip("/"))
            write_file(os.path.join(out, rel), body)
            target = rel
        entries.append({"url": u, "file": target, "status": ent.get("status") or 200,
                        "content_type": ent.get("content_type") or "application/json",
                        "sha256": sha256_bytes(body), "bytes": len(body)})
        ct = ent.get("content_type") or "application/json"
        text = None
        enc = None
        if any(x in ct.lower() for x in ("json", "text", "javascript", "xml")):
            text = body.decode("utf-8", "replace")
        else:
            enc = "base64"
            text = base64.b64encode(body).decode("ascii")
        har_entries.append({
            "startedDateTime": "1970-01-01T00:00:00.000Z", "time": 0,
            "request": {"method": "GET", "url": u, "httpVersion": "HTTP/1.1",
                        "headers": [], "queryString": [], "cookies": [],
                        "headersSize": -1, "bodySize": 0},
            "response": {"status": ent.get("status") or 200, "statusText": "OK",
                         "httpVersion": "HTTP/1.1",
                         "headers": [{"name": "content-type", "value": ct}],
                         "cookies": [], "content": {"size": len(body), "mimeType": ct,
                                                    "text": text, **({"encoding": enc} if enc else {})},
                         "redirectURL": "", "headersSize": -1, "bodySize": len(body)},
            "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
        })
    har = {"log": {"version": "1.2",
                   "creator": {"name": "site-rebuild.py", "version": "1.0"},
                   "entries": har_entries}}
    write_file(os.path.join(out, "har.json"),
               json.dumps(har, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    route_js = """// Generated by site-rebuild.py -- Playwright page.route HAR replay.
// Usage: const mock = require('./mock/playwright-route.js');
//        await mock(page);  // before page.goto()
const HAR = require('../har.json');
module.exports = async function mock(page) {
  const entries = HAR.log.entries;
  await page.route('**/*', async (route) => {
    const url = route.request().url();
    const hit = entries.find(e => e.request.url === url) ||
                entries.find(e => e.request.url.split('?')[0] === url.split('?')[0]);
    if (!hit) {
      const u = new URL(url);
      if (u.hostname === '127.0.0.1' || u.hostname === 'localhost') return route.continue();
      return route.abort();
    }
    const c = hit.response.content;
    const body = c.encoding === 'base64'
      ? Buffer.from(c.text, 'base64') : Buffer.from(c.text || '', 'utf8');
    const headers = {};
    for (const h of hit.response.headers) headers[h.name] = h.value;
    return route.fulfill({status: hit.response.status, headers, body});
  });
};
"""
    write_file(os.path.join(out, "mock", "playwright-route.js"), route_js)
    return entries, har_entries


def rewrite_css_simple(css, origin):
    def repl(m):
        q, u = m.group(1), m.group(2).strip()
        if u.startswith("data:"):
            return m.group(0)
        if u.startswith("//"):
            u = "https:" + u
        if u.startswith(("http://", "https://")):
            if not same_origin(u, origin):
                return "url(%s/__external__/blocked.png%s)" % (q, q)
            u = urllib.parse.urlsplit(u).path
        if u.startswith("/"):
            return "url(%s%s%s)" % (q, u, q)
        return m.group(0)
    return re.sub(r"url\(\s*(['\"]?)(.*?)\1\s*\)", repl, css, flags=re.I | re.S)


def local_route(path):
    if path in ("", "/"):
        return "/"
    p = path.strip("/")
    if "." in p.rsplit("/", 1)[-1]:
        return "/" + p
    return "/" + p + "/"


def rewrite_html(text, origin, base, site):
    """Rewrite absolute/relative URLs to local paths; neutralise off-origin resources."""
    ext = {"url": None}

    def map_url(u, tag, attr):
        if not u or u.startswith(("data:", "javascript:", "mailto:", "tel:", "#", "blob:")):
            return u
        nu = norm_url(u, base)
        if same_origin(nu, origin):
            path = urllib.parse.urlsplit(nu).path
            if tag == "a" and not path.endswith(ASSET_EXT):
                q = urllib.parse.urlsplit(nu).query
                return local_route(path) + (("?" + q) if q else "")
            return path or "/"
        ext["url"] = nu
        if tag == "a":
            return "#"
        if tag in ("img", "source", "video", "audio", "track"):
            return "data:image/gif;base64," + base64.b64encode(PNG_1PX).decode("ascii")
        if tag in ("script",):
            return "/__external__/blocked.js"
        if tag == "link":
            return "/__external__/blocked.css"
        suffix = os.path.splitext(urllib.parse.urlsplit(nu).path)[1].lower()
        return "/__external__/blocked" + (suffix if suffix in (".js", ".css", ".png", ".svg", ".woff2") else "")

    def repl_tag(m):
        tag = m.group(1).lower()
        raw = m.group(0)
        # drop preconnect/dns-prefetch and off-origin stylesheet/script entirely
        if tag == "link":
            rel = (re.search(r'rel\s*=\s*["\']([^"\']+)', raw, re.I) or [None, ""])[1].lower()
            href = (re.search(r'href\s*=\s*["\']([^"\']+)', raw, re.I) or [None, ""])[1]
            if href and not href.startswith(("data:", "#")) and not same_origin(norm_url(href, base), origin):
                if "stylesheet" in rel or "preload" in rel or "preconnect" in rel or "dns-prefetch" in rel:
                    return ""
        def attr_sub(am):
            name = am.group(1)
            q = am.group(2) or ""
            u = am.group(3) if am.group(2) else (am.group(4) or "")
            if name.lower() == "srcset":
                parts = []
                for part in u.split(","):
                    bits = part.strip().split()
                    if not bits:
                        continue
                    bits[0] = map_url(bits[0], tag, name)
                    parts.append(" ".join(bits))
                val = ", ".join(parts)
            else:
                val = map_url(u, tag, name)
            if q:
                return "%s=%s%s%s" % (name, q, val, q)
            return "%s=%s" % (name, val)
        raw = re.sub(r'\b(href|src|action|poster|data-src|srcset)\s*=\s*(?:(["\'])(.*?)\2|([^\s>]+))',
                     attr_sub, raw, flags=re.I | re.S)
        if tag == "a" and ext["url"]:
            raw = raw[:-1] + ' data-original-href="%s">' % ext["url"].replace('"', "&quot;")
            ext["url"] = None
        return raw

    text = re.sub(r"<(a|link|script|img|source|form|iframe|video|audio|track|use|image)\b[^>]*>",
                  repl_tag, text, flags=re.I | re.S)
    # inline <style> blocks and style="" attributes
    text = re.sub(r"(<style[^>]*>)(.*?)(</style>)",
                  lambda m: m.group(1) + rewrite_css_simple(m.group(2), origin) + m.group(3),
                  text, flags=re.I | re.S)
    text = re.sub(r'(style\s*=\s*["\'])(.*?)(["\'])',
                  lambda m: m.group(1) + rewrite_css_simple(m.group(2), origin) + m.group(3),
                  text, flags=re.I | re.S)
    return text


def make_stubs(site):
    d = os.path.join(site, "__external__")
    write_file(os.path.join(d, "blocked.js"), "/* external resource blocked by site-clone */\n")
    write_file(os.path.join(d, "blocked.css"), "/* external resource blocked by site-clone */\n")
    write_file(os.path.join(d, "blocked.png"), PNG_1PX)
    write_file(os.path.join(d, "blocked.svg"),
               '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>\n')
    write_file(os.path.join(d, "blocked.woff2"), b"")
    write_file(os.path.join(d, "blocked"), "external resource blocked\n")
    write_file(os.path.join(d, "blocked.json"), "{}\n")


def freeze_dom(text):
    """Remove app scripts while keeping the already-rendered DOM/CSS snapshot.

    This is the deterministic 1:1 mode: the crawler saved the post-JS DOM, so
    dropping scripts prevents a second hydration pass from re-rendering pages
    differently (especially routes that need backend state).
    """
    text = re.sub(r"<script\b[^>]*>.*?</script>", "", text, flags=re.I | re.S)
    text = re.sub(r"<script\b[^>]*/?>", "", text, flags=re.I | re.S)
    # JS-driven entrance animations leave inline opacity:0/scale(.9) in the snapshot;
    # without JS they would stay hidden.  Restore the final visible state for images.
    def unhide_img(m):
        tag = m.group(0)
        if re.search(r"opacity:\s*0(?:\.0+)?", tag, re.I):
            tag = re.sub(r"opacity:\s*0(?:\.0+)?", "opacity:1", tag, flags=re.I)
            tag = re.sub(r"translate3d\([^)]*\)", "translate3d(0,0,0)", tag, flags=re.I)
            tag = re.sub(r"scale\([^)]*\)", "scale(1)", tag, flags=re.I)
        return tag
    text = re.sub(r"<img\b[^>]*>", unhide_img, text, flags=re.I)
    marker = '<!-- site-clone-mode:frozen-dom -->'
    if "</head>" in text and marker not in text:
        text = text.replace("</head>", marker + "</head>", 1)
    return text


def rebuild_static(crawl, out, rps, timeout, freeze=True):
    graph = read_json(os.path.join(crawl, "site-graph.json"))
    origin = graph["origin"]
    site = os.path.join(out, "site")
    for d in ("site", "local", "screenshots", "mock"):
        os.makedirs(os.path.join(out, d), exist_ok=True)
    make_stubs(site)
    saved_assets, failed_assets = download_assets(graph, site, rps, timeout)
    api_entries, har_entries = copy_api(graph, crawl, site, out)

    pages = []
    for r in graph.get("routes") or []:
        src = os.path.join(crawl, r.get("html") or "")
        if not r.get("html") or not os.path.isfile(src):
            pages.append({"route": r["route"], "file": None, "status": r.get("status"),
                          "error": "missing html snapshot"})
            continue
        text = open(src, encoding="utf-8", errors="replace").read()
        if freeze:
            text = freeze_dom(text)
        rewritten = rewrite_html(text, origin, r.get("final_url") or r.get("url"), site)
        rel = route_file(r["route"])
        dest = os.path.join(site, rel)
        write_file(dest, rewritten)
        pages.append({"route": r["route"], "file": "site/" + rel, "status": r.get("status"),
                      "bytes": len(rewritten.encode("utf-8")),
                      "url": r.get("url"), "final_url": r.get("final_url")})

    # rewrite downloaded CSS url(...) references
    for dp, dn, fn in os.walk(site):
        for f in fn:
            if f.endswith(".css"):
                p = os.path.join(dp, f)
                txt = open(p, encoding="utf-8", errors="replace").read()
                write_file(p, rewrite_css_simple(txt, origin))
    return graph, site, pages, saved_assets, failed_assets, api_entries, har_entries


async def replay_local(out, site, graph, pages, timeout):
    """Load the rebuilt site with Playwright, screenshot it, replay interactions."""
    from playwright.async_api import async_playwright  # local import
    handler = lambda *a, **k: Quiet(*a, directory=site, **k)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    base = "http://127.0.0.1:%d" % port
    har = read_json(os.path.join(out, "har.json"))
    local_pages, requests = [], []
    interactions = []
    try:
        async with async_playwright() as p:
            exe = find_chromium()
            browser = await p.chromium.launch(headless=True, executable_path=exe) if exe \
                else await p.chromium.launch(headless=True)
            vp = graph.get("viewport") or {"width": 1280, "height": 720, "dpr": 1}
            ctx = await browser.new_context(viewport={"width": vp.get("width", 1280),
                                                       "height": vp.get("height", 720)},
                                            device_scale_factor=vp.get("dpr", 1))
            page = await ctx.new_page()
            seen_req = {}
            page.on("request", lambda r: seen_req.__setitem__(r.url, {
                "url": r.url, "method": r.method, "resource_type": r.resource_type,
                "status": None}))
            resp_map = {}
            page.on("response", lambda r: resp_map.__setitem__(r.url, r))

            async def route_handler(route):
                u = route.request.url
                if u.startswith(base):
                    return await route.continue_()
                hit = next((e for e in har["log"]["entries"] if e["request"]["url"] == u), None)
                if hit is None:
                    hit = next((e for e in har["log"]["entries"]
                                if e["request"]["url"].split("?")[0] == u.split("?")[0]), None)
                if hit is None:
                    return await route.abort()
                c = hit["response"]["content"]
                body = base64.b64decode(c["text"]) if c.get("encoding") == "base64" \
                    else (c.get("text") or "").encode("utf-8")
                headers = {h["name"]: h["value"] for h in hit["response"]["headers"]}
                return await route.fulfill(status=hit["response"]["status"], headers=headers,
                                           body=body)

            await ctx.route("**/*", route_handler)
            for pg in pages:
                if not pg.get("file"):
                    continue
                url = base + local_route(pg["route"])
                try:
                    resp = await page.goto(url, wait_until="load", timeout=timeout * 1000)
                    await page.wait_for_timeout(3500)
                    html_text = await page.content()
                    sl = slug(pg["route"])
                    write_file(os.path.join(out, "local", sl + ".html"), html_text)
                    await page.screenshot(path=os.path.join(out, "screenshots", sl + ".png"),
                                          full_page=False, animations="disabled")
                    for u, r in list(resp_map.items()):
                        if u in seen_req:
                            seen_req[u]["status"] = r.status
                    local_pages.append({"route": pg["route"], "status": resp.status if resp else 0,
                                        "final_url": page.url, "html": "local/%s.html" % sl,
                                        "screenshot": "screenshots/%s.png" % sl})
                except Exception as e:  # noqa: BLE001
                    local_pages.append({"route": pg["route"], "status": 0,
                                        "error": str(e)[:200]})
                finally:
                    resp_map.clear()
            # interactions are replayed on the seed page only (same script as crawl)
            seed = (graph.get("routes") or [{}])[0].get("route", "/")
            try:
                await page.goto(base + local_route(seed), wait_until="load", timeout=timeout * 1000)
                await page.wait_for_timeout(2500)
                interactions = await run_interactions(page)
            except Exception as e:  # noqa: BLE001
                interactions = [{"kind": "replay", "applicable": False, "error": str(e)[:200]}]
            requests = sorted(seen_req.values(), key=lambda x: x["url"])
            await browser.close()
    finally:
        srv.shutdown()
    return local_pages, requests, interactions, port


async def run_interactions(page):
    out = []
    async def add(kind, expected, **extra):
        out.append(dict({"kind": kind, "expected": expected, "applicable": True}, **extra))
    try:
        await add("title", await page.title())
    except Exception:  # noqa: BLE001
        pass
    try:
        body = re.sub(r"\s+", " ", await page.inner_text("body")).strip()
        await add("body_text_head", body[:160])
    except Exception:  # noqa: BLE001
        pass
    try:
        await add("stylesheet_count", await page.eval_on_selector_all("link[rel=stylesheet]", "els=>els.length"))
    except Exception:  # noqa: BLE001
        pass
    try:
        await add("dom_nodes", await page.eval_on_selector_all("*", "els=>els.length"))
    except Exception:  # noqa: BLE001
        pass
    try:
        h = await page.eval_on_selector_all("h1,h2", "els=>els[0]?els[0].innerText:''")
        h = re.sub(r"\s+", " ", h or "").strip()
        if h:
            await add("heading_text", h[:120])
    except Exception:  # noqa: BLE001
        pass
    try:
        await add("link_count", await page.eval_on_selector_all("a[href]", "els=>els.length"))
    except Exception:  # noqa: BLE001
        pass
    try:
        await add("paragraph_count", await page.eval_on_selector_all("p", "els=>els.length"))
    except Exception:  # noqa: BLE001
        pass
    try:
        await add("image_count", await page.eval_on_selector_all("img", "els=>els.length"))
    except Exception:  # noqa: BLE001
        pass
    try:
        lang = await page.eval_on_selector_all("html", "els=>els[0]?els[0].lang:''")
        if lang:
            await add("document_lang", lang)
    except Exception:  # noqa: BLE001
        pass
    try:
        btn = page.locator('button[aria-label*="Language"], button[aria-label*="语言"]').first
        if await btn.count():
            await btn.click(timeout=3000)
            await page.wait_for_timeout(600)
            n = await page.eval_on_selector_all(
                '[role=option], [role=menuitem], [role=listbox] li',
                "els=>els.filter(e=>{const r=e.getBoundingClientRect();return r.width>0&&r.height>0}).length")
            await add("language_menu", {"opened": n > 0, "options": n})
    except Exception as e:  # noqa: BLE001
        out.append({"kind": "language_menu", "applicable": False, "expected": None,
                    "error": str(e)[:120]})
    try:
        inp = page.locator("input[type=text]:visible, input:not([type]):visible").first
        if await inp.count():
            await inp.fill("site-clone", timeout=3000)
            v = await inp.input_value()
            await add("text_input", {"value": v, "filled": bool(v)})
    except Exception as e:  # noqa: BLE001
        out.append({"kind": "text_input", "applicable": False, "expected": None,
                    "error": str(e)[:120]})
    return out


def check_external_links(site):
    bad = []
    for dp, dn, fn in os.walk(site):
        for f in fn:
            if not f.endswith((".html", ".css")):
                continue
            p = os.path.join(dp, f)
            txt = open(p, encoding="utf-8", errors="replace").read()
            for m in re.finditer(r'(?<![-\w])(?:href|src|action)\s*=\s*["\'](https?://[^"\']+)', txt, re.I):
                bad.append({"file": os.path.relpath(p, site).replace(os.sep, "/"),
                            "url": m.group(1)})
    return bad


def serve(site, port, seconds):
    handler = lambda *a, **k: Quiet(*a, directory=site, **k)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(json.dumps({"preview": "http://127.0.0.1:%d/" % httpd.server_address[1],
                      "root": site}, ensure_ascii=False), flush=True)
    if seconds > 0:
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        time.sleep(seconds)
        httpd.shutdown()
    else:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


def self_test():
    tmp = tempfile.mkdtemp(prefix="site-rebuild-")
    try:
        crawl = os.path.join(tmp, "crawl")
        out = os.path.join(tmp, "rebuild")
        os.makedirs(os.path.join(crawl, "pages"))
        os.makedirs(os.path.join(crawl, "api"))
        html_text = ("<!doctype html><html><head><title>Fx</title>"
                     "<link rel=stylesheet href=/a.css></head><body><h1>Fx</h1>"
                     "<a href=/about>About</a><a href=https://ext.example/x>Ext</a>"
                     "<img src=/i.png></body></html>\n")
        write_file(os.path.join(crawl, "pages", "root.html"), html_text)
        write_file(os.path.join(crawl, "pages", "about.html"),
                   "<!doctype html><html><head><title>About</title></head><body><h1>About</h1></body></html>\n")
        write_file(os.path.join(crawl, "api", "001-root.json"), '{"ok":true}\n')
        graph = {"schema": "seep.site-crawl/1", "ok": True, "engine": "fixture",
                 "target": "http://fixture.invalid/", "origin": "http://fixture.invalid",
                 "viewport": {"width": 800, "height": 600, "dpr": 1},
                 "limits": {"max_pages": 2, "max_depth": 1, "rps": 20},
                 "routes": [{"route": "/", "url": "http://fixture.invalid/",
                             "final_url": "http://fixture.invalid/", "status": 200,
                             "html": "pages/root.html", "screenshot": None},
                            {"route": "/about", "url": "http://fixture.invalid/about",
                             "final_url": "http://fixture.invalid/about", "status": 200,
                             "html": "pages/about.html", "screenshot": None}],
                 "assets": [], "api": [{"url": "http://fixture.invalid/api/x", "status": 200,
                                        "content_type": "application/json",
                                        "body_file": "api/001-root.json", "sha256": None}],
                 "external": [], "interactions": [], "data_boundary": {"/": "recorded-snapshot"},
                 "backend_required": []}
        write_file(os.path.join(crawl, "site-graph.json"),
                   json.dumps(graph, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        g, site, pages, assets, failed, api_entries, har = rebuild_static(crawl, out, 20, 10)
        assert len(pages) == 2 and all(p["file"] for p in pages), pages
        assert os.path.isfile(os.path.join(site, "index.html"))
        assert os.path.isfile(os.path.join(site, "about", "index.html"))
        root = open(os.path.join(site, "index.html"), encoding="utf-8").read()
        assert "/about/" in root and "data-original-href=" in root
        assert har and os.path.isfile(os.path.join(out, "har.json"))
        assert os.path.isfile(os.path.join(out, "mock", "playwright-route.js"))
        assert check_external_links(site) == [], check_external_links(site)
        return emit({"ok": True, "self_test": "site-rebuild", "pages": len(pages),
                     "har_entries": len(har), "external_links": 0})
    except Exception as e:  # noqa: BLE001
        return blocked("self-test", "%s: %s | %s" % (type(e).__name__, e, traceback.format_exc().splitlines()[-2]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(
        description="Materialise a crawl offline: local assets, rewritten links, HAR mock, preview server")
    ap.add_argument("--crawl", help="crawl output directory (site-graph.json)")
    ap.add_argument("--out", help="rebuild output directory")
    ap.add_argument("--rps", type=float, default=2.0)
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--serve", action="store_true", help="serve the rebuilt site with http.server")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--serve-seconds", type=float, default=0)
    ap.add_argument("--no-replay", action="store_true", help="skip Playwright local replay/screenshots")
    ap.add_argument("--keep-js", action="store_true",
                    help="keep app scripts (SPA/HAR mode); default freezes the captured DOM")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.crawl or not a.out:
        return blocked("args", "--crawl and --out are required (or use --self-test)")
    try:
        t0 = time.time()
        os.makedirs(a.out, exist_ok=True)
        graph, site, pages, assets, failed, api_entries, har = rebuild_static(
            a.crawl, a.out, a.rps, a.timeout, freeze=not a.keep_js)
        local_pages, requests, interactions, port = [], [], [], None
        if not a.no_replay:
            local_pages, requests, interactions, port = asyncio.run(
                replay_local(a.out, site, graph, pages, a.timeout))
        ext = check_external_links(site)
        status404 = [r for r in requests if r.get("status") == 404]
        rebuild = {
            "schema": SCHEMA, "ok": True, "crawl": a.crawl, "site_root": "site",
            "origin": graph["origin"], "target": graph.get("target"),
            "viewport": graph.get("viewport"),
            "pages": pages, "assets": assets, "assets_failed": failed,
            "api": api_entries,
            "mock": {"har": "har.json", "route": "mock/playwright-route.js",
                     "entries": len(har)},
            "resources": {"external_links": len(ext), "external_samples": ext[:20],
                          "http_404": len(status404), "requests": len(requests)},
            "local_requests": requests, "local_pages": local_pages,
            "interactions": interactions,
            "data_boundary": graph.get("data_boundary") or {},
            "backend_required": graph.get("backend_required") or [],
            "preview": {"root": site, "port": port},
            "elapsed_s": round(time.time() - t0, 2),
        }
        write_file(os.path.join(a.out, "rebuild.json"),
                   json.dumps(rebuild, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
        if a.serve:
            serve(site, a.port, a.serve_seconds)
        return emit({"ok": True, "schema": SCHEMA, "out": a.out, "pages": len(pages),
                     "assets": len(assets), "assets_failed": len(failed),
                     "har_entries": len(har), "local_requests": len(requests),
                     "http_404": len(status404), "external_links": len(ext),
                     "interactions": len(interactions), "preview_port": port})
    except Exception as e:  # noqa: BLE001
        return blocked("rebuild", e)


if __name__ == "__main__":
    sys.exit(main())
