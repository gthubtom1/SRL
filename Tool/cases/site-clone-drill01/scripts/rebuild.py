#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rebuild.py — 把 crawl/ 的原始抓取重建成可离线服务的静态副本。

产物：
  artifacts/site/                     http.server 根目录（route -> <route>/index.html）
  artifacts/site/_replay/mocks.json   XHR/fetch 回放表（路径 -> 录制响应体）
  artifacts/site/_replay/bodies/      回放响应体副本
  artifacts/rebuild-report.json       改写统计、缺失引用、第三方剔除清单

改写规则（只动 block.youtest.me 自身）：
  * `https://block.youtest.me/xxx` -> `/xxx`（保留 query）
  * `http(s)://block.youtest.me`     -> ``（裸域名）
  * 第三方脚本标签（Cloudflare beacon / AdSense / funding-choices）剔除：
    它们是跨域追踪/广告，不属于同源克隆范围，抓取阶段已被策略拦截。
  * `https://api.youtest.me/...` 原样保留 -> 离线时暴露为 backend-required。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
CASE = os.path.dirname(HERE)
CRAWL = os.path.join(CASE, "artifacts", "crawl")
SITE = os.path.join(CASE, "artifacts", "site")
REPORT = os.path.join(CASE, "artifacts", "rebuild-report.json")
BASE = "https://block.youtest.me"

THIRD_PARTY = ("static.cloudflareinsights.com", "pagead2.googlesyndication.com",
               "fundingchoicesmessages.google.com", "googleads.g.doubleclick.net",
               "ep1.adtrafficquality.google", "ep2.adtrafficquality.google")


def slug(route: str) -> str:
    if route in ("/", ""):
        return "index"
    return route.strip("/").replace("/", "_").replace("?", "_")


def rewrite(text: str) -> str:
    text = text.replace("https://block.youtest.me/", "/")
    text = text.replace("http://block.youtest.me/", "/")
    text = text.replace("https://block.youtest.me", "")
    text = text.replace("http://block.youtest.me", "")
    return text


def strip_third_party(html: str) -> tuple[str, list[str]]:
    removed = []

    def repl(m):
        tag = m.group(0)
        for host in THIRD_PARTY:
            if host in tag:
                removed.append(tag[:160])
                return ""
        return tag

    html = re.sub(r"<script[^>]*>[\s\S]*?</script>", repl, html)
    html = re.sub(r"<script[^>]*/>", repl, html)
    return html, removed


def main() -> int:
    if os.path.isdir(SITE):
        shutil.rmtree(SITE)
    os.makedirs(os.path.join(SITE, "_replay", "bodies"), exist_ok=True)

    net = json.load(open(os.path.join(CRAWL, "network.json"), encoding="utf-8"))
    routes = json.load(open(os.path.join(CRAWL, "routes.json"), encoding="utf-8"))
    crawled = [p for p in routes["crawled"] if p.get("ok")]

    copied_assets = 0
    missing_assets = []
    rewritten_pages = []
    third_party_removed = []

    # 1) 页面
    for p in crawled:
        route = p["route"]
        src = os.path.join(CRAWL, "html", slug(route) + ".html")
        if not os.path.isfile(src):
            missing_assets.append(f"html:{route}")
            continue
        html = open(src, encoding="utf-8", errors="replace").read()
        absolute = len(re.findall(r"https?://block\.youtest\.me", html))
        html2, removed = strip_third_party(html)
        html2 = rewrite(html2)
        third_party_removed += removed
        rel = route.strip("/")
        out = os.path.join(SITE, rel, "index.html") if rel else os.path.join(SITE, "index.html")
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write(html2)
        rewritten_pages.append({"route": route, "file": os.path.relpath(out, SITE),
                                "absolute_urls_rewritten": absolute,
                                "third_party_tags_removed": len(removed)})

    # 2) 资源（网络抓到的 + 推断补抓的）
    for url, meta in net["same_origin_assets"].items():
        src = os.path.join(CRAWL, meta["path"])
        if not os.path.isfile(src):
            missing_assets.append(url)
            continue
        path = urllib.parse.unquote(urllib.parse.urlsplit(url).path).lstrip("/")
        if not path or path.endswith("/"):
            path += "index.html"
        dst = os.path.join(SITE, path)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        data = open(src, "rb").read()
        if path.endswith((".css", ".js", ".json", ".webmanifest", ".svg")):
            try:
                txt = data.decode("utf-8")
            except UnicodeDecodeError:
                pass
            else:
                txt = rewrite(txt)
                data = txt.encode("utf-8")
        with open(dst, "wb") as f:
            f.write(data)
        copied_assets += 1

    # 3) XHR/fetch 回放表（按 path 与 path?query 双键）
    mocks = {}
    bodies = 0
    for r in net["xhr_fetch"]:
        if not r.get("saved") or not r["url"].startswith(BASE):
            continue
        src = os.path.join(CRAWL, r["saved"])
        if not os.path.isfile(src):
            continue
        sp = urllib.parse.urlsplit(r["url"])
        key_path = sp.path
        key_full = sp.path + ("?" + sp.query if sp.query else "")
        name = (hashlib.sha256(key_full.encode()).hexdigest()[:8] + "-"
                + (re.sub(r"[^A-Za-z0-9_.-]+", "_", key_full.strip("/"))[-100:] or "root"))
        if not name.endswith(".json"):
            name += ".json"
        dst_rel = os.path.join("_replay", "bodies", name)
        dst = os.path.join(SITE, dst_rel)
        data = open(src, "rb").read()
        with open(dst, "wb") as f:
            f.write(data)
        entry = {"status": r.get("status", 200),
                 "content_type": r.get("content_type") or "application/json",
                 "body": dst_rel.replace(os.sep, "/"),
                 "recorded_url": r["url"]}
        if sp.query:
            mocks[key_full] = entry
        else:
            mocks[key_path] = entry
        bodies += 1

    with open(os.path.join(SITE, "_replay", "mocks.json"), "w", encoding="utf-8",
              newline="\n") as f:
        json.dump({"base": BASE, "mocks": mocks}, f, ensure_ascii=False, indent=1)

    # 4) 报告：离线副本里仍然指向未落盘路径的引用
    referenced = set()
    for dp, _dn, fn in os.walk(SITE):
        for f in fn:
            if not f.lower().endswith((".html", ".css", ".js")):
                continue
            txt = open(os.path.join(dp, f), encoding="utf-8", errors="replace").read()
            for m in re.finditer(r"[\"'(](/(?:_next|static|favicon|apple|site\.webmanifest|web-app)[^\"'\\\s)>]*)", txt):
                referenced.add(urllib.parse.urlsplit(m.group(1)).path)
    on_disk = set()
    for dp, _dn, fn in os.walk(SITE):
        for f in fn:
            on_disk.add("/" + os.path.relpath(os.path.join(dp, f), SITE).replace(os.sep, "/"))
    def looks_like_file(p: str) -> bool:
        last = p.rstrip("/").rsplit("/", 1)[-1]
        return "." in last and not last.endswith(".") and last not in (".", "..")

    dangling = sorted(p for p in referenced if p not in on_disk
                      and looks_like_file(p)
                      and not any(p == d.rstrip("/") + "/index.html" for d in on_disk))

    report = {
        "target": BASE,
        "site_dir": "artifacts/site",
        "pages": rewritten_pages,
        "assets_copied": copied_assets,
        "replay_mocks": bodies,
        "third_party_tags_removed": third_party_removed,
        "dangling_local_refs": dangling[:80],
        "dangling_local_refs_count": len(dangling),
        "missing_assets": missing_assets,
        "server_hint": "cd artifacts/site && python -m http.server 8765",
    }
    with open(REPORT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
    print(f"[rebuild] pages={len(rewritten_pages)} assets={copied_assets} "
          f"mocks={bodies} dangling={len(dangling)} third_party_removed={len(third_party_removed)}")
    if dangling:
        print("[rebuild] dangling sample:", dangling[:8])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
