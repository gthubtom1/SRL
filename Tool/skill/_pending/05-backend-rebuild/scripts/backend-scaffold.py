#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""backend-scaffold.py -- 按 api-surface + schema 生成可跑的本地 mock 服务（零依赖）。

生成物（全部落在 --out 目录，可直接 scp 到干净机器）：
  server.py            http.server 单文件服务；录制的响应逐字节回放
  routes.json          路由表（含截断/别名、role、快照来源）
  snapshots/*.json     录制快照（来自 api-surface 的样本）
  schema.json          schema-infer 的产物副本（表/主键/枚举/时间）
  hosts.fragment       <host> → 127.0.0.1 的 hosts 片段（不自动写系统 hosts）
  proxy.pac            最小 PAC：仅这些 host 走本地代理
  README.md            部署与切换说明

服务语义：
  * 命中端点且**有录制快照** → 按录制状态码 + 原样 body 返回（source=recorded）；
  * 命中端点但**无快照** → 200 + 派生骨架（source=scaffold-stub，绝不假装是录制）；
  * 路径在表里但方法不对 → 405 method_not_allowed（附 allowed）；
  * 完全未注册 → 404 not_implemented（与鉴权失败区分开）；
  * --strict：缺必需 query/body 字段 → 400 validation_failed；
  * 测试钩子（默认开，--no-test-hooks 关）：`__delay=<秒>`、`__status=<码>`、`__error=<code>`。

用法：
  python Tool/skill/_pending/05-backend-rebuild/scripts/backend-scaffold.py \
      --api work/api/api-surface.json --schema work/api/schema.json --out work/backend
  python Tool/skill/_pending/05-backend-rebuild/scripts/backend-scaffold.py --api ... --schema ... --out ... --serve --port 8787
  python Tool/skill/_pending/05-backend-rebuild/scripts/backend-scaffold.py --self-test

退出码：0 = ok；2 = blocked（{ok:false,blocked_at,reason}）。
"""
from __future__ import annotations

import argparse
import json
import os
import pprint
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

SCHEMA = "seep.backend-scaffold/1"


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



def slug(s, n=60):
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", str(s or "")).strip("_")
    return (s or "x")[:n]


def load_json(p):
    with open(p, encoding="utf-8-sig") as f:
        return json.load(f)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def path_pattern(path):
    """把 /a/{id} /a/:id /a/<id> 转成正则；其余字符转义。"""
    parts = []
    for seg in path.split("/"):
        if re.fullmatch(r"\{[^/{}]+\}|:[A-Za-z_][\w]*|<[^/<>]+>", seg):
            parts.append(r"[^/]+")
        else:
            parts.append(re.escape(seg))
    return "^" + "/".join(parts) + "/?$"


def find_schema_table(schema_doc, names):
    tables = {t.get("name"): t for t in (schema_doc or {}).get("tables", [])}
    for n in names:
        if n in tables:
            return tables[n]
    for n in names:
        for k, t in tables.items():
            if n and (n in k or k in n):
                return t
    return None


def build_stub(ep, schema_doc):
    """派生骨架：只给形状（空列表/空字段名），不放任何伪造业务值。"""
    segs = [s for s in ep["path"].split("/") if s and not s.startswith(("{", ":", "<"))]
    table = find_schema_table(schema_doc, segs[::-1])
    body = {
        "ok": True,
        "source": "scaffold-stub",
        "snapshot": "missing",
        "endpoint": ep["id"],
        "reason": "无录制快照：形状按 api-surface/schema 推断，不是业务数据",
    }
    if table:
        body["table"] = table.get("name")
        body["fields"] = [f["name"] for f in table.get("fields", [])]
    if ep["role"] == "list":
        body["items"] = []
        body["total"] = 0
    elif ep["role"] in ("login", "submit"):
        body["result"] = None
    return body


def resolve_sample(api_doc, sample):
    base = (api_doc.get("sources") or {}).get("samples_dir") or ""
    fn = sample.get("body_file")
    if not fn:
        return None
    for cand in (os.path.join(base, fn), fn):
        if os.path.isfile(cand):
            return cand
    return None


def build(api_path, schema_path, out_dir):
    api = load_json(api_path)
    schema = load_json(schema_path) if schema_path and os.path.isfile(schema_path) else {"tables": []}
    endpoints = api.get("endpoints") or []
    if not endpoints:
        raise ValueError("api-surface.json 里没有 endpoints")

    snap_dir = os.path.join(out_dir, "snapshots")
    os.makedirs(snap_dir, exist_ok=True)
    routes, used, missing = [], 0, 0
    for ep in endpoints:
        paths = [ep["path"]] + [a for a in ep.get("aliases") or []]
        snap_file = None
        if ep.get("samples"):
            src = resolve_sample(api, ep["samples"][0])
            if src:
                snap_file = f"snapshots/{slug(ep['id'], 50)}.json"
                shutil.copyfile(src, os.path.join(out_dir, snap_file))
                used += 1
        if snap_file:
            stub = None
            status = ep["samples"][0].get("status") or 200
            origin = "recorded"
        else:
            stub = build_stub(ep, schema)
            status = 200
            origin = "scaffold-stub"
            missing += 1
        for p in sorted(set(paths)):
            routes.append({
                "method": ep["method"],
                "path": p,
                "pattern": path_pattern(p),
                "endpoint": ep["id"],
                "role": ep.get("role") or "other",
                "status": int(status),
                "snapshot": snap_file,
                "origin": origin,
                "truncated": p != ep["path"],
                "query": sorted((ep.get("query") or {}).keys()),
                "body_fields": sorted((ep.get("body_fields") or {}).keys()),
                "required_query": sorted(k for k, v in (ep.get("query") or {}).items() if v.get("required")),
            })
    routes.sort(key=lambda r: (r["path"], r["method"], r["endpoint"]))
    hosts = sorted({ep["host"] for ep in endpoints if ep.get("host")})

    stub_map = {r["endpoint"]: build_stub(ep, schema) for r in routes for ep in endpoints
                if ep["id"] == r["endpoint"] and r["origin"] == "scaffold-stub"}
    ctx = {
        "routes": routes,
        "hosts": hosts,
        "stubs": stub_map,
        "tables": [{"name": t.get("name"), "primary_key": t.get("primary_key")}
                   for t in schema.get("tables", [])],
        "schema_doc": schema,
    }
    with open(os.path.join(out_dir, "server.py"), "w", encoding="utf-8") as f:
        f.write(SERVER_TEMPLATE.replace("__CTX__", pprint.pformat(ctx, width=110, sort_dicts=False)))
    with open(os.path.join(out_dir, "routes.json"), "w", encoding="utf-8") as f:
        json.dump({"schema": SCHEMA, "routes": routes, "hosts": hosts,
                   "stats": {"routes": len(routes), "recorded": used, "stub": missing}},
                  f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "schema.json"), "w", encoding="utf-8") as f:
        json.dump(schema, f, ensure_ascii=False, indent=2)
    with open(os.path.join(out_dir, "hosts.fragment"), "w", encoding="utf-8") as f:
        f.write("# 本地后端切换片段（不自动写入系统 hosts；容器/CI 用 --add-host 或挂载）\n")
        for h in hosts:
            f.write(f"127.0.0.1 {h}\n")
    with open(os.path.join(out_dir, "proxy.pac"), "w", encoding="utf-8") as f:
        f.write("function FindProxyForURL(url, host) {\n  var local = %s;\n"
                "  for (var i = 0; i < local.length; i++) { if (host === local[i]) "
                "return \"PROXY 127.0.0.1:8787; DIRECT\"; }\n  return \"DIRECT\";\n}\n"
                % json.dumps(hosts, ensure_ascii=False))
    with open(os.path.join(out_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(README_TEMPLATE.format(
            routes=len(routes), recorded=used, stub=missing,
            hosts=", ".join(f"`{h}`" for h in hosts) or "（无 host）",
            tables=", ".join(f"`{t['name']}`" for t in ctx["tables"]) or "（无表）"))
    return {"routes": len(routes), "recorded": used, "stub": missing, "hosts": hosts,
            "out": out_dir, "tables": [t["name"] for t in ctx["tables"]]}


README_TEMPLATE = """# 本地 mock 后端（backend-scaffold.py 生成）

- 路由 {routes} 条；录制快照回放 {recorded} 条；无快照派生骨架 {stub} 条。
- 目标 host：{hosts}
- 表：{tables}

## 起服务（零依赖，Python ≥ 3.8）

```bash
python server.py --host 127.0.0.1 --port 8787
curl -s http://127.0.0.1:8787/__health
curl -s http://127.0.0.1:8787/__routes
```

## 三路语义（验收必须都跑）

| 路径 | 请求 | 期望 |
|---|---|---|
| 正常 | 原样请求（query/body 同抓包） | 2xx + `source=recorded`（无快照则 `scaffold-stub`） |
| 超时 | `?__delay=3` + 客户端 1s 超时 | 客户端超时；服务端不崩 |
| 错误码 | `?__status=401&__error=session_expired` | 4xx + `{{"error": ...}}`，不是 404 |

`__delay/__status/__error` 是本地测试钩子，生产部署请加 `--no-test-hooks`。

## 切换

- hosts：`cat hosts.fragment >> /etc/hosts`（Windows：`C:\\Windows\\System32\\drivers\\etc\\hosts`）
- 代理：浏览器/客户端 PAC 指向 `proxy.pac`
- 客户端内 patch：只改 host 常量，不改协议与签名

## 未实现接口

返回 `404 {{"error":"not_implemented","path":...,"snapshot":"missing"}}`，
与鉴权失败（401）严格区分；不要用 401 掩盖缺路由。
"""

SERVER_TEMPLATE = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地 mock 后端（backend-scaffold.py 生成；只依赖标准库）。

启动：python server.py --host 127.0.0.1 --port 8787
钩子：__delay=<秒> / __status=<码> / __error=<code>（--no-test-hooks 关闭）
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CTX = __CTX__
ROUTES = [(re.compile(r["pattern"]), r) for r in CTX["routes"]]
STUBS = CTX["stubs"]
HERE = os.path.dirname(os.path.abspath(__file__))


def load_snapshot(rel):
    if not rel:
        return None
    p = os.path.join(HERE, rel)
    try:
        with open(p, "rb") as f:
            return f.read()
    except Exception:
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "seep-mock/1.0"
    strict = False
    hooks = True

    def log_message(self, fmt, *args):
        if not getattr(self.server, "quiet", False):
            sys.stderr.write("%s - %s\\n" % (self.address_string(), fmt % args))

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Seep-Mock", "1")
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def _match(self, method, path):
        hits, allowed = [], set()
        for rx, r in ROUTES:
            if not rx.match(path):
                continue
            if r["method"] == method:
                hits.append(r)
            else:
                allowed.add(r["method"])
        return hits, sorted(allowed)

    def _handle(self, method):
        u = urllib.parse.urlsplit(self.path)
        path = u.path or "/"
        q = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        if path == "/__health":
            rec = sum(1 for r in CTX["routes"] if r["origin"] == "recorded")
            return self._send(200, {"ok": True, "routes": len(CTX["routes"]),
                                    "recorded": rec, "stub": len(CTX["routes"]) - rec,
                                    "hosts": CTX["hosts"], "tables": CTX["tables"],
                                    "strict": self.strict, "hooks": self.hooks})
        if path == "/__routes":
            return self._send(200, CTX["routes"])
        if self.hooks and "__delay" in q:
            try:
                time.sleep(max(0.0, min(10.0, float(q["__delay"]))))
            except Exception:
                pass
        if self.hooks and "__status" in q:
            try:
                code = int(q["__status"])
            except Exception:
                code = 500
            return self._send(code, {"ok": False, "error": q.get("__error") or "forced_error",
                                     "forced": True})
        hits, allowed = self._match(method, path)
        if not hits:
            if allowed:
                return self._send(405, {"ok": False, "error": "method_not_allowed",
                                        "path": path, "method": method, "allowed": allowed})
            return self._send(404, {"ok": False, "error": "not_implemented", "path": path,
                                    "method": method, "snapshot": "missing",
                                    "hint": "该路径未注册；不要用 401 掩盖缺路由"})
        r = hits[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        payload = None
        if raw:
            try:
                payload = json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                payload = None
        if self.strict:
            missing = [k for k in r.get("required_query") or [] if k not in q]
            need = [k for k in r.get("body_fields") or [] if not isinstance(payload, dict) or k not in payload]
            if raw and need and not missing:
                missing = need[:3]
            if missing:
                return self._send(400, {"ok": False, "error": "validation_failed",
                                        "missing": missing, "endpoint": r["endpoint"]})
        snap = load_snapshot(r.get("snapshot"))
        if snap is not None:
            return self._send(r.get("status") or 200, snap)
        body = STUBS.get(r["endpoint"]) or {"ok": False, "error": "stub_missing",
                                            "endpoint": r["endpoint"]}
        return self._send(r.get("status") or 200, body)

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_PUT(self):
        self._handle("PUT")

    def do_PATCH(self):
        self._handle("PATCH")

    def do_DELETE(self):
        self._handle("DELETE")

    def do_HEAD(self):
        self._handle("HEAD")


def main(argv=None):
    ap = argparse.ArgumentParser(description="seep 本地 mock 后端")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--no-test-hooks", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    Handler.strict = a.strict
    Handler.hooks = not a.no_test_hooks
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    srv.quiet = a.quiet
    base = "http://%s:%d" % (a.host, srv.server_address[1])
    print(json.dumps({"ok": True, "base": base, "routes": len(CTX["routes"])}, ensure_ascii=False), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def wait_health(base, tries=60, timeout=0.5):
    last = None
    for _ in range(tries):
        try:
            with urllib.request.urlopen(base + "/__health", timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(0.1)
    raise TimeoutError(f"本地服务未就绪：{last}")


def serve_forever(out_dir, host, port, strict, hooks, quiet):
    server = os.path.join(out_dir, "server.py")
    cmd = [sys.executable, server, "--host", host, "--port", str(port)]
    if strict:
        cmd.append("--strict")
    if not hooks:
        cmd.append("--no-test-hooks")
    if quiet:
        cmd.append("--quiet")
    return subprocess.call(cmd)


# ------------------------------------------------------------------ self-test
def self_test():
    api = {
        "schema": "seep.api-surface/1",
        "sources": {"samples_dir": None},
        "endpoints": [
            {"id": "POST https://api.example.test/api/login", "method": "POST",
             "scheme": "https", "host": "api.example.test", "path": "/api/login",
             "role": "login", "truncated": False, "aliases": [],
             "query": {}, "body_fields": {"name": {"types": ["text"], "source": ["har"]},
                                          "code": {"types": ["text"], "source": ["har"]}},
             "samples": [{"status": 200, "mime": "application/json", "origin": "recorded",
                          "sha256": "x", "bytes": 20, "body_file": None, "json": True,
                          "excerpt": "{}"}], "evidence": [], "notes": []},
            {"id": "GET https://api.example.test/api/list", "method": "GET",
             "scheme": "https", "host": "api.example.test", "path": "/api/list",
             "role": "list", "truncated": False, "aliases": ["/api/l"],
             "query": {"page": {"observed": ["1"], "required": False, "source": ["har"]}},
             "body_fields": {}, "samples": [], "evidence": [], "notes": []},
        ],
    }
    schema = {"schema": "seep.schema-infer/1", "tables": [
        {"name": "players", "rows": 2, "primary_key": ["id"],
         "fields": [{"name": "id", "sql_type": "TEXT"}, {"name": "name", "sql_type": "TEXT"}]}],
        "ddl": 'CREATE TABLE IF NOT EXISTS "players" ("id" TEXT PRIMARY KEY);'}
    with tempfile.TemporaryDirectory() as td:
        out = os.path.join(td, "backend")
        os.makedirs(out)
        # 先落一条真实快照文件，验证 recorded 逐字节回放
        snap_dir = os.path.join(td, "samples")
        os.makedirs(snap_dir)
        body = json.dumps({"token": "t-1", "player_id": "p1"}, ensure_ascii=False)
        with open(os.path.join(snap_dir, "login.json"), "w", encoding="utf-8") as f:
            f.write(body)
        api["sources"]["samples_dir"] = snap_dir
        api["endpoints"][0]["samples"][0]["body_file"] = "login.json"
        apip = os.path.join(td, "api-surface.json")
        schp = os.path.join(td, "schema.json")
        json.dump(api, open(apip, "w", encoding="utf-8"))
        json.dump(schema, open(schp, "w", encoding="utf-8"))
        info = build(apip, schp, out)
        for f in ("server.py", "routes.json", "snapshots", "hosts.fragment",
                  "proxy.pac", "README.md", "schema.json"):
            assert os.path.exists(os.path.join(out, f)), f
        assert info["recorded"] == 1 and info["stub"] >= 1, info

        port = free_port()
        proc = subprocess.Popen([sys.executable, os.path.join(out, "server.py"),
                                 "--port", str(port), "--quiet"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            base = f"http://127.0.0.1:{port}"
            health = wait_health(base)
            assert health["ok"] and health["routes"] >= 3, health

            def call(method, path, data=None):
                req = urllib.request.Request(base + path, method=method,
                                             data=json.dumps(data).encode() if data else None,
                                             headers={"Content-Type": "application/json"})
                try:
                    with urllib.request.urlopen(req, timeout=3) as r:
                        return r.status, r.read().decode("utf-8")
                except urllib.error.HTTPError as e:
                    return e.code, e.read().decode("utf-8")

            code, text = call("POST", "/api/login", {"name": "p", "code": "c"})
            assert code == 200 and json.loads(text)["token"] == "t-1", (code, text)
            code, text = call("GET", "/api/list")
            assert code == 200 and json.loads(text)["source"] == "scaffold-stub", (code, text)
            code, text = call("GET", "/api/l")          # 截断别名
            assert code == 200, (code, text)
            code, text = call("GET", "/api/nope")
            assert code == 404 and json.loads(text)["error"] == "not_implemented", (code, text)
            code, text = call("GET", "/api/login")
            assert code == 405 and json.loads(text)["error"] == "method_not_allowed", (code, text)
            code, text = call("GET", "/api/list?__status=401&__error=session_expired")
            assert code == 401 and json.loads(text)["error"] == "session_expired", (code, text)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                proc.kill()
        return emit({"ok": True, "self_test": True, "routes": info["routes"],
                     "recorded": info["recorded"], "stub": info["stub"]}, 0)


def main(argv=None):
    ap = JsonArgParser(
        description="api-surface + schema → 可跑本地 mock（http.server，零依赖）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="退出码：0 ok / 2 blocked")
    ap.add_argument("--api", required=False, help="api-surface.json")
    ap.add_argument("--schema", default=None, help="schema.json（可缺：缺则只回放录制）")
    ap.add_argument("--out", default="backend")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--serve", action="store_true", help="生成后直接前台起服务")
    ap.add_argument("--strict", action="store_true", help="缺必需参数回 400")
    ap.add_argument("--no-test-hooks", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            return self_test()
        except Exception as e:  # noqa: BLE001
            return blocked("self-test", e)
    if not args.api:
        return blocked("input", "缺少 --api api-surface.json")
    try:
        os.makedirs(args.out, exist_ok=True)
        info = build(args.api, args.schema, args.out)
    except FileNotFoundError as e:
        return blocked("input", e)
    except Exception as e:  # noqa: BLE001
        return blocked("scaffold", e)
    emit({"ok": True, "out": args.out, "stats": info, "serve": bool(args.serve)}, 0)
    if args.serve:
        return serve_forever(args.out, args.host, args.port, args.strict,
                             not args.no_test_hooks, args.quiet)
    return 0


if __name__ == "__main__":
    sys.exit(main())
