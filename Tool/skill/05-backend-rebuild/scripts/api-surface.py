#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""api-surface.py -- 把抓包/静态证据压成一张可实施的 API 面（api-surface.json）。

输入（至少一种，可叠加）：
  --har    HAR 1.2（浏览器 DevTools / Playwright / mitmproxy 导出）
  --pcap   pcap 的 JSON 流表（{flows:[...]} / {requests:[...]} / 裸列表）；
           二进制 pcap 不能解析（纯标准库），会返回 blocked_at=pcap-binary，
           请先转成 JSON 流表或在抓包机上导出 HAR。
  --js     JS 文本或目录：抽 URL / fetch 字面量 / 路由常量 / 主机常量，
           并登记"定长截断"别名（/v1/chat/c 是 /v1/chat/completions 的前缀）。

输出：
  <out>                  api-surface.json（端点为唯一真源，按 host+path+method 排序）
  <samples-dir>          每个观测响应的 JSON 样本（默认 <out 目录>/samples/）

判据（脚本自己检查）：
  1. 每个端点至少一条证据（har/pcap/js），否则进 `orphans`；
  2. 截断/别名单独成条，不并进规范路径；
  3. 每个端点有 role（login/list/submit/heartbeat），供 switch-verify 分类。

用法：
  python Tool/skill/05-backend-rebuild/scripts/api-surface.py \
      --har work/capture/har.json --js work/site/assets --out work/api/api-surface.json
  python Tool/skill/05-backend-rebuild/scripts/api-surface.py --self-test
  python Tool/skill/05-backend-rebuild/scripts/api-surface.py --help

退出码：0 = ok；2 = blocked（stdout 打 {ok:false,blocked_at,reason}）。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import tempfile
from urllib.parse import parse_qsl, urlsplit

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

SCHEMA = "seep.api-surface/1"
MAX_BYTES_DEFAULT = 65536
API_PATH_HINTS = (
    "/api", "/v1", "/v2", "/v3", "/info", "/auth", "/login", "/token", "/session",
    "/user", "/player", "/find", "/dl", "/script", "/heartbeat", "/ping", "/poll",
    "/version", "/upload", "/admin", "/quiz", "/scoreboard", "/share", "/data",
)
ROLE_RULES = (
    ("login", re.compile(r"(?i)(login|signin|sign-in|auth|token|session|join|/player$|/user$|/users?/login)")),
    ("heartbeat", re.compile(r"(?i)(heartbeat|keepalive|keep-alive|/ping|/poll|/version|/alive|/uptime|/info/)")),
)
METHOD_WORDS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")


def emit(obj, code=0):
    print(json.dumps(obj, ensure_ascii=False, indent=2))
    return code


def blocked(at, reason):
    return emit({"ok": False, "blocked_at": at, "reason": str(reason)[:600]}, 2)

class JsonArgParser(argparse.ArgumentParser):
    """参数错误也走统一失败形状：{ok:false,blocked_at,reason} + rc=2。"""

    def error(self, message):
        blocked("args", message)
        raise SystemExit(2)



def read_text(path, limit=None):
    with open(path, "rb") as f:
        raw = f.read(limit) if limit else f.read()
    return raw.decode("utf-8", "replace"), raw


def sha8(b):
    return hashlib.sha256(b).hexdigest()[:12]


def norm_path(p):
    p = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+", "", p or "")
    p = p.split("#", 1)[0]
    p = re.sub(r"/{2,}", "/", p)
    if len(p) > 1:
        p = p.rstrip("/")
    return p or "/"


def slug(s, n=60):
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")
    return (s or "x")[:n]


def query_map(qs):
    out = {}
    for k, v in parse_qsl(qs or "", keep_blank_values=True):
        out.setdefault(k, []).append(v)
    return out


def value_type(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "integer"
    if isinstance(v, float):
        return "real"
    if isinstance(v, str):
        return "text"
    if isinstance(v, list):
        return "array"
    return "object"


def body_fields(body):
    """只取顶层字段；嵌套对象按 `a.b` 展开一层，用来登记参数名。"""
    out = {}
    if isinstance(body, dict):
        for k, v in body.items():
            out[k] = value_type(v)
            if isinstance(v, dict):
                for k2, v2 in v.items():
                    out[f"{k}.{k2}"] = value_type(v2)
    elif isinstance(body, list) and body and isinstance(body[0], dict):
        for k, v in body[0].items():
            out[k] = value_type(v)
    return out


def infer_role(method, path, has_query):
    for role, rx in ROLE_RULES:
        if rx.search(path):
            return role
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        return "submit"
    if method == "GET":
        return "list"
    return "other"


def make_endpoint(method, host, path, scheme=""):
    method = (method or "GET").upper()
    prefix = f"{scheme}://" if scheme else ""
    return {
        "id": f"{method} {prefix}{host}{path}",
        "method": method,
        "scheme": scheme,
        "host": host,
        "path": path,
        "role": infer_role(method, path, False),
        "truncated": False,
        "aliases": [],
        "query": {},
        "body_fields": {},
        "samples": [],
        "evidence": [],
        "notes": [],
    }


def add_evidence(ep, kind, ref, extra=None):
    for e in ep["evidence"]:
        if e["kind"] == kind and e["ref"] == ref:
            return
    item = {"kind": kind, "ref": ref}
    if extra:
        item.update(extra)
    ep["evidence"].append(item)


def add_query(ep, qmap, source):
    for k, vals in qmap.items():
        slot = ep["query"].setdefault(k, {"observed": [], "required": False, "source": []})
        for v in vals:
            if v not in slot["observed"]:
                slot["observed"].append(v)
        if source not in slot["source"]:
            slot["source"].append(source)


def add_body_fields(ep, fields, source):
    for k, t in fields.items():
        slot = ep["body_fields"].setdefault(k, {"types": [], "source": []})
        if t not in slot["types"]:
            slot["types"].append(t)
        if source not in slot["source"]:
            slot["source"].append(source)


def store_sample(ep, raw_body, status, mime, origin, samples_dir, max_bytes, note=None):
    if raw_body is None:
        return
    if isinstance(raw_body, str) and not raw_body.strip():
        return
    if isinstance(raw_body, (dict, list)):
        raw = json.dumps(raw_body, ensure_ascii=False, sort_keys=True).encode("utf-8")
        parsed = raw_body
    else:
        raw = raw_body.encode("utf-8", "replace")
        try:
            parsed = json.loads(raw_body)
        except Exception:  # noqa: BLE001
            parsed = None
    if len(raw) > max_bytes:
        raw = raw[:max_bytes]
    digest = hashlib.sha256(raw).hexdigest()
    body_file = None
    if samples_dir:
        os.makedirs(samples_dir, exist_ok=True)
        body_file = os.path.join(samples_dir, f"{slug(ep['id'],40)}-{digest[:10]}.json")
        with open(body_file, "wb") as f:
            f.write(raw)
    sample = {
        "status": int(status) if status is not None else None,
        "mime": mime or "",
        "origin": origin,
        "sha256": digest,
        "bytes": len(raw),
        "body_file": os.path.basename(body_file) if body_file else None,
        "json": parsed is not None,
        "excerpt": (raw[:400].decode("utf-8", "replace") if not isinstance(raw_body, (dict, list))
                    else json.dumps(raw_body, ensure_ascii=False)[:400]),
    }
    if note:
        sample["note"] = note
    for s in ep["samples"]:
        if s["sha256"] == digest:
            return
    ep["samples"].append(sample)


# ------------------------------------------------------------------ HAR
def from_har(path, samples_dir, max_bytes, host_filter):
    text, _ = read_text(path)
    try:
        doc = json.loads(text)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"HAR 不是合法 JSON：{e}")
    log = doc.get("log") if isinstance(doc, dict) else None
    entries = (log or {}).get("entries") if isinstance(log, dict) else None
    if entries is None and isinstance(doc, list):
        entries = doc
    if not isinstance(entries, list):
        raise ValueError("HAR 缺少 log.entries")
    out = []
    for i, e in enumerate(entries):
        req = e.get("request") or {}
        url = req.get("url") or ""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not host or (host_filter and host not in host_filter):
            continue
        path = norm_path(parts.path)
        method = (req.get("method") or "GET").upper()
        qmap = query_map(parts.query)
        for q in req.get("queryString") or []:
            qmap.setdefault(q.get("name", ""), []).append(q.get("value", ""))
        post = req.get("postData") or {}
        body_text = post.get("text")
        fields = {}
        if body_text:
            try:
                fields = body_fields(json.loads(body_text))
            except Exception:  # noqa: BLE001
                fields = {"_raw": "text"}
        resp = e.get("response") or {}
        content = resp.get("content") or {}
        body = content.get("text")
        if isinstance(body, str) and not body.strip():
            body = None                      # 空 body 不是样本
        if body and content.get("encoding") == "base64":
            try:
                body = base64.b64decode(body).decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                body = None
        out.append({
            "method": method, "host": host, "scheme": (parts.scheme or "").lower(),
            "path": path, "query": qmap,
            "body_fields": fields, "status": resp.get("status"),
            "mime": content.get("mimeType") or (resp.get("headers") or {}),
            "response_body": body, "ref": f"har#entries[{i}]",
            "origin": "recorded",
        })
    return out


# ------------------------------------------------------------------ pcap(json)
PCAP_MAGIC = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")


def from_pcap(path, samples_dir, max_bytes, host_filter):
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic in PCAP_MAGIC or magic[:2] == b"\x0a\x0d":
        raise Blocked("pcap-binary",
                      "二进制 pcap 需先转 JSON 流表（{flows:[{method,url,response:{status,body}}]}）或导出 HAR")
    text, _ = read_text(path)
    try:
        doc = json.loads(text)
    except Exception as e:  # noqa: BLE001
        raise ValueError(f"pcap(json) 不是合法 JSON：{e}")
    if isinstance(doc, dict):
        rows = doc.get("flows") or doc.get("requests") or doc.get("entries") or []
    elif isinstance(doc, list):
        rows = doc
    else:
        rows = []
    out = []
    for i, r in enumerate(rows):
        url = r.get("url") or ""
        host = (r.get("host") or urlsplit(url).hostname or "").lower()
        if not host or (host_filter and host not in host_filter):
            continue
        path = norm_path(r.get("path") or urlsplit(url).path)
        method = (r.get("method") or "GET").upper()
        qmap = query_map(urlsplit(url).query)
        qmap.update({k: v if isinstance(v, list) else [str(v)] for k, v in (r.get("query") or {}).items()})
        body = r.get("body")
        fields = body_fields(body) if isinstance(body, (dict, list)) else {}
        resp = r.get("response") or {}
        out.append({
            "method": method, "host": host, "scheme": (urlsplit(url).scheme or "").lower(),
            "path": path, "query": qmap,
            "body_fields": fields, "status": resp.get("status"),
            "mime": resp.get("content_type") or "",
            "response_body": resp.get("body") if isinstance(resp.get("body"), (dict, list))
            else resp.get("body"), "ref": f"pcap#flow[{i}]", "origin": "recorded",
        })
    return out


class Blocked(Exception):
    def __init__(self, at, reason):
        super().__init__(reason)
        self.at = at
        self.reason = reason


# ------------------------------------------------------------------ JS
URL_RX = re.compile(r"https?://[A-Za-z0-9._~:/?#@!$&'()*+,;=%\[\]-]{4,300}")
PATH_RX = re.compile(r"""["'`](/(?:[A-Za-z0-9_\-{}\[\]$.:]|/){1,120})["'`]""")
HOST_RX = re.compile(r"""(?:host|baseUrl|BASE_URL|apiHost|API_HOST|origin)\s*[:=]\s*["']([^"']{3,120})["']""")
FETCH_RX = re.compile(r"(?:fetch|axios|\.ajax|request|got|http\.(?:get|post)|method)\s*[.(]?\s*([A-Za-z]{3,6})\b")
METHOD_LITERAL_RX = re.compile(r"""["'](GET|POST|PUT|PATCH|DELETE)["']""")


def js_files(root):
    if os.path.isfile(root):
        return [root]
    out = []
    for dp, dn, fn in os.walk(root):
        for f in fn:
            if f.lower().endswith((".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".map")):
                out.append(os.path.join(dp, f))
    return sorted(out)


def from_js(root, prefixes, host_filter):
    files = js_files(root)
    if not files:
        raise ValueError(f"JS 路径下没有可读的 .js/.mjs 文件：{root}")
    refs = []
    for fp in files:
        text, _ = read_text(fp, limit=8 * 1024 * 1024)
        rel = os.path.basename(fp)
        hosts = [h for h in HOST_RX.findall(text)]
        for u in URL_RX.findall(text):
            p = urlsplit(u)
            host = (p.hostname or "").lower()
            if host_filter and host not in host_filter:
                continue
            if not p.path or p.path == "/":
                continue                      # 纯主机常量不是端点
            refs.append({"raw": u, "host": host, "scheme": (p.scheme or "").lower(),
                         "path": norm_path(p.path),
                         "query": query_map(p.query), "method": None,
                         "ref": f"js:{rel}", "kind": "url"})
        for m in PATH_RX.finditer(text):
            raw = m.group(1)
            if not any(raw.startswith(x) for x in prefixes):
                continue
            ctx = text[max(0, m.start() - 90):m.start()]
            method = None
            lm = METHOD_LITERAL_RX.findall(ctx)
            if lm:
                method = lm[-1].upper()
            else:
                fm = re.search(r"(?:axios|fetch|got|request)\s*\.?\s*(get|post|put|patch|delete)\b", ctx, re.I)
                if fm:
                    method = fm.group(1).upper()
            host = hosts[0] if hosts else ""
            scheme = ""
            if host.startswith("http"):
                scheme = (urlsplit(host).scheme or "").lower()
                host = (urlsplit(host).hostname or "").lower()
            refs.append({"raw": raw, "host": (host or "").lower(), "scheme": scheme,
                         "path": norm_path(raw),
                         "query": {}, "method": method, "ref": f"js:{rel}@{m.start()}", "kind": "path"})
    return refs


def mark_truncated(refs):
    """前缀截断：同一 host 下，A 是 B 的严格前缀且不以 / 结尾 → A 记为 B 的截断别名。"""
    paths = sorted({(r["host"], r["path"]) for r in refs if r.get("path")})
    aliases = {}
    for host, p in paths:
        if p.endswith("/") or p == "/":
            continue
        for host2, q in paths:
            if host2 != host or q == p:
                continue
            if q.startswith(p + "/") or (q.startswith(p) and len(q) > len(p) and q[len(p)] not in "/"):
                aliases.setdefault((host, p), []).append(q)
                break
    return aliases


def analyze(har=None, pcap=None, js=None, samples_dir=None, max_bytes=MAX_BYTES_DEFAULT,
            prefixes=API_PATH_HINTS, hosts=None):
    host_filter = {h.lower() for h in hosts} if hosts else None
    if samples_dir:
        os.makedirs(samples_dir, exist_ok=True)
    eps = {}
    orphans = []
    stats = {"har": 0, "pcap": 0, "js": 0}

    def get_ep(method, host, path, scheme=""):
        key = (method, host, path)
        if key not in eps:
            eps[key] = make_endpoint(method, host, path, scheme)
        elif scheme and not eps[key]["scheme"]:
            eps[key]["scheme"] = scheme
            eps[key]["id"] = f"{method} {scheme}://{host}{path}"
        return eps[key]

    if har:
        rows = from_har(har, samples_dir, max_bytes, host_filter)
        stats["har"] = len(rows)
        for r in rows:
            ep = get_ep(r["method"], r["host"], r["path"], r.get("scheme", ""))
            add_evidence(ep, "har", r["ref"])
            add_query(ep, r["query"], "har")
            add_body_fields(ep, r["body_fields"], "har")
            store_sample(ep, r["response_body"], r["status"], r["mime"], "recorded",
                         samples_dir, max_bytes)
        if not rows:
            orphans.append({"kind": "har", "ref": har, "reason": "无同源/白名单内条目"})

    if pcap:
        rows = from_pcap(pcap, samples_dir, max_bytes, host_filter)
        stats["pcap"] = len(rows)
        for r in rows:
            ep = get_ep(r["method"], r["host"], r["path"], r.get("scheme", ""))
            add_evidence(ep, "pcap", r["ref"])
            add_query(ep, r["query"], "pcap")
            add_body_fields(ep, r["body_fields"], "pcap")
            store_sample(ep, r["response_body"], r["status"], r["mime"], "recorded",
                         samples_dir, max_bytes)
        if not rows:
            orphans.append({"kind": "pcap", "ref": pcap, "reason": "流表为空"})

    if js:
        refs = from_js(js, prefixes, host_filter)
        stats["js"] = len(refs)
        alias_map = mark_truncated(refs)
        for r in refs:
            method = r["method"] or "GET"
            host = r["host"] or ""
            path = r["path"]
            ep = get_ep(method, host, path, r.get("scheme", ""))
            add_evidence(ep, "js", r["ref"], {"raw": r["raw"][:300]})
            add_query(ep, r["query"], "js")
            if (host, path) in alias_map:
                ep["truncated"] = True
                ep["aliases"] = sorted(set(ep["aliases"]) | set(alias_map[(host, path)]))
                ep["notes"].append("客户端发出的路径是定长截断形态；必须按此形态注册，不能只实现规范路径")
        if not refs:
            orphans.append({"kind": "js", "ref": js, "reason": "未命中 URL/路由字面量"})

    endpoints = []
    for key in sorted(eps):
        ep = eps[key]
        if not ep["host"]:
            ep["notes"].append("仅静态证据：host 未确定（需抓包或 host 常量确认）")
        # 只读 GET 没有 body 字段时，把 query 当参数面
        if ep["method"] == "GET" and not ep["query"] and ep["body_fields"]:
            ep["notes"].append("GET 带 body：记录原始形态，服务端按实际实现")
        ep["query"] = {k: {"observed": sorted(set(v["observed"])), "required": v["required"],
                          "source": sorted(v["source"])} for k, v in sorted(ep["query"].items())}
        ep["body_fields"] = {k: {"types": sorted(set(v["types"])), "source": sorted(v["source"])}
                             for k, v in sorted(ep["body_fields"].items())}
        ep["samples"].sort(key=lambda s: (s["sha256"], str(s["status"])))
        ep["evidence"].sort(key=lambda e: (e["kind"], e["ref"]))
        ep["aliases"] = sorted(set(ep["aliases"]))
        ep["role"] = infer_role(ep["method"], ep["path"], bool(ep["query"]))
        endpoints.append(ep)

    by_role = {}
    for ep in endpoints:
        by_role.setdefault(ep["role"], []).append(ep["id"])
    no_sample = [ep["id"] for ep in endpoints if not ep["samples"] and ep["evidence"]
                 and any(e["kind"] in ("har", "pcap") for e in ep["evidence"])]
    return {
        "schema": SCHEMA,
        "sources": {"har": har, "pcap": pcap, "js": js, "samples_dir": samples_dir},
        "stats": {
            "endpoints": len(endpoints),
            "by_method": {m: sum(1 for e in endpoints if e["method"] == m)
                          for m in sorted({e["method"] for e in endpoints})},
            "by_role": {k: len(v) for k, v in sorted(by_role.items())},
            "truncated": sum(1 for e in endpoints if e["truncated"]),
            "with_samples": sum(1 for e in endpoints if e["samples"]),
            "har_entries": stats["har"], "pcap_flows": stats["pcap"], "js_refs": stats["js"],
        },
        "endpoints": endpoints,
        "roles": {k: v for k, v in sorted(by_role.items())},
        "orphans": orphans,
        "rules": [
            "一 shape 一端点：method+host+path 三元组唯一，query 只做参数面。",
            "截断/别名单独成条（truncated=true），禁止只按规范路径实现。",
            "每个端点必须有证据（har/pcap/js）或显式标为静态推断（无 host）。",
            "没有响应样本的端点，mock 只能返回派生骨架，不能假装是录制。",
        ],
    }


# ------------------------------------------------------------------ self-test
SELFTEST_HAR = {
    "log": {"version": "1.2", "entries": [
        {"request": {"method": "POST",
                     "url": "https://api.example.test/v1/chat/completions?trace=1",
                     "queryString": [{"name": "trace", "value": "1"}],
                     "postData": {"text": json.dumps({"messages": [{"role": "user"}], "model": "m1"})}},
         "response": {"status": 401,
                      "content": {"mimeType": "application/json",
                                  "text": json.dumps({"error": "session_expired", "code": 401})}}},
        {"request": {"method": "GET",
                     "url": "https://api.example.test/info/country?ip=1.2.3.4"},
         "response": {"status": 200,
                      "content": {"mimeType": "application/json",
                                  "text": json.dumps({"country": "US", "flag": "us.svg"})}}},
    ]}
}
SELFTEST_JS = """
const BASE_URL = "https://api.example.test";
async function ask(){ return fetch(BASE, {method:"POST"}).then(r=>r.json()); }
const a = "/v1/chat/c";
const b = "/v1/chat/completions";
const country = "/info/country";
const hb = "/api/heartbeat";
"""


def self_test():
    with tempfile.TemporaryDirectory() as td:
        har = os.path.join(td, "har.json")
        with open(har, "w", encoding="utf-8") as f:
            json.dump(SELFTEST_HAR, f)
        pcap = os.path.join(td, "pcap.json")
        with open(pcap, "w", encoding="utf-8") as f:
            json.dump({"flows": [{"method": "POST", "url": "https://api.example.test/api/player",
                                  "body": {"name": "p", "code": "abc"},
                                  "response": {"status": 200, "body": {"player_id": "p1", "created_at": "2026-01-02T03:04:05Z"}}}]}, f)
        js = os.path.join(td, "app.js")
        with open(js, "w", encoding="utf-8") as f:
            f.write(SELFTEST_JS)
        out = os.path.join(td, "api-surface.json")
        samples = os.path.join(td, "samples")
        doc = analyze(har=har, pcap=pcap, js=js, samples_dir=samples)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)

        ids = {e["id"] for e in doc["endpoints"]}
        assert doc["schema"] == SCHEMA
        assert len(doc["endpoints"]) >= 5, ids
        assert "GET https://api.example.test/info/country" in ids, ids
        assert "POST https://api.example.test/api/player" in ids, ids
        assert "POST https://api.example.test/v1/chat/completions" in ids, ids
        assert doc["stats"]["truncated"] >= 1, "截断路径未登记"
        trunc = [e for e in doc["endpoints"] if e["truncated"]]
        assert any(a.endswith("/v1/chat/completions") for e in trunc for a in e["aliases"]), trunc
        assert any(e["path"] == "/v1/chat/c" for e in trunc), trunc
        country = [e for e in doc["endpoints"] if e["path"] == "/info/country"][0]
        assert country["role"] == "heartbeat", country["role"]
        assert "ip" in country["query"], country["query"]
        assert country["samples"] and country["samples"][0]["json"], country["samples"]
        assert os.listdir(samples), "样本未落盘"
        login = [e for e in doc["endpoints"] if e["path"] == "/api/player"][0]
        assert login["role"] == "login", login["role"]
        assert "name" in login["body_fields"] and "code" in login["body_fields"], login["body_fields"]
        # 失败路径：不存在的输入必须 rc=2 形状
        try:
            analyze(har=os.path.join(td, "missing.json"))
        except Exception:  # noqa: BLE001
            pass
        else:
            raise AssertionError("缺文件应抛错")
        return emit({"ok": True, "self_test": True, "endpoints": len(doc["endpoints"]),
                     "truncated": doc["stats"]["truncated"], "roles": doc["roles"]}, 0)


def main(argv=None):
    ap = JsonArgParser(
        description="HAR/pcap(json)/JS → api-surface.json（端点+方法+参数+样本+角色）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="退出码：0 ok / 2 blocked")
    ap.add_argument("--har")
    ap.add_argument("--pcap")
    ap.add_argument("--js")
    ap.add_argument("--out", default="api-surface.json")
    ap.add_argument("--samples-dir", default=None,
                    help="样本落盘目录，默认 <out 目录>/samples")
    ap.add_argument("--max-sample-bytes", type=int, default=MAX_BYTES_DEFAULT)
    ap.add_argument("--hosts", default="", help="逗号分隔的主机白名单（默认全部）")
    ap.add_argument("--js-path-prefixes", default="", help="逗号分隔，覆盖默认路由前缀表")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            return self_test()
        except Exception as e:  # noqa: BLE001
            return blocked("self-test", e)
    if not (args.har or args.pcap or args.js):
        return blocked("input", "至少给 --har / --pcap / --js 之一")

    samples_dir = args.samples_dir or os.path.join(
        os.path.dirname(os.path.abspath(args.out)) or ".", "samples")
    prefixes = tuple(x.strip() for x in args.js_path_prefixes.split(",") if x.strip()) or API_PATH_HINTS
    hosts = [x.strip() for x in args.hosts.split(",") if x.strip()]
    try:
        doc = analyze(har=args.har, pcap=args.pcap, js=args.js, samples_dir=samples_dir,
                      max_bytes=args.max_sample_bytes, prefixes=prefixes, hosts=hosts)
    except Blocked as b:
        return blocked(b.at, b.reason)
    except Exception as e:  # noqa: BLE001
        return blocked("analyze", e)

    if not doc["endpoints"]:
        return blocked("extract", "未抽到任何端点：检查 HAR 是否脱敏成空、JS 前缀过滤是否过严")
    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return emit({"ok": True, "out": args.out, "stats": doc["stats"],
                 "roles": doc["roles"], "orphans": len(doc["orphans"])}, 0)


if __name__ == "__main__":
    sys.exit(main())
