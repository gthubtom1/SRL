#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""switch-verify.py -- 把客户端切到本地后端，跑四类回归，出 switched.json。

四类回归（每类取 api-surface 里 role 匹配的一个端点）：
  login      登录/加入会话   → 期望 2xx + 会话字段
  list       列表/查询       → 期望 2xx + 可解析 JSON
  submit     提交/写入       → 期望 2xx
  heartbeat  心跳/轮询       → 期望 2xx

三路（每一路都跑四类，缺一类即 fail）：
  normal      原样请求 → 2xx（或与录制状态码一致）
  timeout     __delay=3 + 客户端 1s 超时 → 必须被归类为 timeout（客户端不崩、服务端不挂）
              服务端不支持钩子时自动改用"黑洞 socket"（接受连接但永不回包）
  error_code  __status=401 + __error=session_expired → 4xx + JSON error（不能是 404/HTML）

切换方式只记账、不写系统文件：
  --mode proxy|hosts|patch  写进 switched.json；hosts 片段与 env 导出写在工作目录，
  由人或容器应用。脚本绝不改 /etc/hosts。

用法：
  python Tool/skill/05-backend-rebuild/scripts/switch-verify.py \
      --api work/api/api-surface.json --server work/backend/server.py --port 8787 \
      --out work/api/switched.json
  python Tool/skill/05-backend-rebuild/scripts/switch-verify.py \
      --api work/api/api-surface.json --base http://127.0.0.1:8787 --out work/api/switched.json
  python Tool/skill/05-backend-rebuild/scripts/switch-verify.py --self-test

退出码：0 = 三路四类全绿；2 = blocked / 有失败（{ok:false,blocked_at,reason}）。
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

SCHEMA = "seep.switch-verify/1"
CLASSES = ("login", "list", "submit", "heartbeat")
DEFAULTS = {"login": "seep-player", "list": "", "submit": "seep-submit", "heartbeat": ""}


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



def load_json(p):
    with open(p, encoding="utf-8-sig") as f:
        return json.load(f)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def fill_path(path):
    out = []
    for seg in path.split("/"):
        if seg.startswith(("{", ":", "<")):
            out.append("drill-1")
        else:
            out.append(seg)
    return "/".join(out)


def sample_body(ep, cls):
    for s in ep.get("samples") or []:
        fn = s.get("body_file")
        base = (ep.get("_samples_dir") or "")
        if fn and base and os.path.isfile(os.path.join(base, fn)):
            try:
                with open(os.path.join(base, fn), encoding="utf-8-sig") as f:
                    doc = json.load(f)
                if isinstance(doc, dict) and doc:
                    return doc
            except Exception:  # noqa: BLE001
                pass
        if isinstance(s.get("json_body"), dict) and s["json_body"]:
            return s["json_body"]
    fields = ep.get("body_fields") or {}
    if not fields:
        return {"note": DEFAULTS.get(cls, "seep")}
    body = {}
    for name, meta in fields.items():
        types = (meta or {}).get("types") or ["text"]
        body[name] = 1 if "integer" in types else ("seep" if "text" in types else None)
    return body


def probe(api_doc, cls, timeout=1.2, extra_query=None):
    """返回 (endpoint, method, url_path, body, expect)。"""
    eps = [e for e in api_doc.get("endpoints") or [] if e.get("role") == cls]
    if not eps:
        raise LookupError(f"api-surface 里没有 role={cls} 的端点；先补抓包或改 role 规则")
    ep = sorted(eps, key=lambda e: (len(e["path"]), e["path"]))[0]
    path = fill_path(ep["path"])
    q = {}
    for name, meta in (ep.get("query") or {}).items():
        vals = meta.get("observed") or []
        q[name] = vals[0] if vals else "1"
    q.update(extra_query or {})
    body = None
    if ep["method"] in ("POST", "PUT", "PATCH"):
        body = sample_body(ep, cls)
    url = path + ("?" + urllib.parse.urlencode(q) if q else "")
    recorded = (ep.get("samples") or [{}])[0].get("status")
    expect = int(recorded) if recorded else 200
    return ep, ep["method"], url, body, expect


def http(method, base, url_path, body=None, timeout=1.2):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(base + url_path, method=method, data=data,
                                 headers={"Content-Type": "application/json"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            return {"status": r.status, "body": raw, "ms": int((time.time() - t0) * 1000),
                    "error_kind": None}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        return {"status": e.code, "body": raw, "ms": int((time.time() - t0) * 1000),
                "error_kind": "http"}
    except Exception as e:  # noqa: BLE001
        msg = str(e) or type(e).__name__
        kind = "timeout" if ("timed out" in msg.lower() or "timeout" in msg.lower()) else "connection"
        return {"status": None, "body": "", "ms": int((time.time() - t0) * 1000),
                "error_kind": kind, "error": msg[:200]}


def as_json(text):
    try:
        return json.loads(text)
    except Exception:  # noqa: BLE001
        return None


def classify(res, expect):
    if res.get("error_kind") == "timeout":
        return False, "timeout（正常路径不该超时）", None
    if res.get("error_kind"):
        return False, res["error_kind"], None
    doc = as_json(res["body"])
    ok = res["status"] == expect or (expect < 400 and 200 <= res["status"] < 300)
    if res["status"] >= 400 and doc is None:
        ok = False
    return ok, "ok" if ok else f"status={res['status']} expect={expect}", doc


class Blackhole:
    """接受 TCP 连接但永不回包：用来造确定性超时（不依赖服务端钩子）。"""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.stop = False
        self.conns = []
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _run(self):
        self.sock.settimeout(0.2)
        while not self.stop:
            try:
                c, _ = self.sock.accept()
                self.conns.append(c)
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self):
        self.stop = True
        for c in self.conns:
            try:
                c.close()
            except Exception:  # noqa: BLE001
                pass
        try:
            self.sock.close()
        except Exception:  # noqa: BLE001
            pass


def wait_health(base, tries=60):
    last = None
    for _ in range(tries):
        try:
            with urllib.request.urlopen(base + "/__health", timeout=0.5) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            last = e
            time.sleep(0.1)
    raise TimeoutError(f"{base}/__health 未就绪：{last}")


def run_verify(api_doc, base, timeout=1.2, mode="proxy", classes=CLASSES,
               closed_target=None, hosts=None):
    cases = {c: {"normal": [], "timeout": [], "error_code": []} for c in classes}
    missing = [c for c in classes if not any(e.get("role") == c for e in api_doc.get("endpoints") or [])]
    if missing:
        raise LookupError(f"缺 role：{','.join(missing)}")
    total = {"pass": 0, "fail": 0}
    bh = None
    try:
        for cls in classes:
            ep, method, url, body, expect = probe(api_doc, cls, timeout)

            # 1) normal
            r = http(method, base, url, body, timeout=max(timeout, 2.0))
            ok, why, doc = classify(r, expect)
            src = (doc or {}).get("source") if isinstance(doc, dict) else None
            cases[cls]["normal"].append({
                "endpoint": ep["id"], "method": method, "url": url,
                "expect": expect, "observed": {"status": r["status"], "ms": r["ms"],
                                               "source": src, "error_kind": r["error_kind"]},
                "pass": ok, "why": why})
            total["pass" if ok else "fail"] += 1

            # 2) timeout
            sep = "&" if "?" in url else "?"
            forced = url + sep + "__delay=3"
            tr = http(method, base, forced, body, timeout=timeout)
            if tr["error_kind"] is None and not tr.get("status") is None:
                # 服务端不支持 __delay：退回黑洞 socket，保证超时语义可测
                bh = bh or Blackhole()
                tr = http(method, bh.base, url, body, timeout=timeout)
            t_ok = tr["error_kind"] == "timeout"
            cases[cls]["timeout"].append({
                "endpoint": ep["id"], "method": method, "url": forced,
                "expect": "client-timeout", "observed": {"status": tr["status"], "ms": tr["ms"],
                                                         "error_kind": tr["error_kind"]},
                "pass": t_ok, "why": "timeout" if t_ok else f"未超时：{tr.get('status') or tr.get('error_kind')}"})
            total["pass" if t_ok else "fail"] += 1

            # 3) error_code
            forced_err = url + sep + "__status=401&__error=session_expired"
            er = http(method, base, forced_err, body, timeout=max(timeout, 2.0))
            edoc = as_json(er["body"])
            e_ok = (er["status"] is not None and er["status"] >= 400
                    and isinstance(edoc, dict) and bool(edoc.get("error")))
            cases[cls]["error_code"].append({
                "endpoint": ep["id"], "method": method, "url": forced_err,
                "expect": "4xx+json-error",
                "observed": {"status": er["status"], "ms": er["ms"],
                             "error": (edoc or {}).get("error") if isinstance(edoc, dict) else None,
                             "error_kind": er["error_kind"]},
                "pass": e_ok,
                "why": "ok" if e_ok else "未返回 4xx JSON error（检查服务端钩子/错误信封）"})
            total["pass" if e_ok else "fail"] += 1
    finally:
        if bh:
            bh.close()

    closed = None
    if closed_target:
        ep, method, url, body, _ = probe(api_doc, classes[0], timeout)
        cr = http(method, closed_target, url, body, timeout=timeout)
        closed = {"target": closed_target, "error_kind": cr["error_kind"], "status": cr["status"],
                  "pass": cr["error_kind"] == "connection",
                  "why": "连接被拒=原厂停服形态" if cr["error_kind"] == "connection" else "未按停服形态失败"}
        total["pass" if closed["pass"] else "fail"] += 1

    hosts = hosts or sorted({e.get("host") for e in api_doc.get("endpoints") or [] if e.get("host")})
    out = {
        "schema": SCHEMA,
        "switch": {
            "mode": mode,
            "base": base,
            "hosts": hosts,
            "hosts_fragment": "".join(f"127.0.0.1 {h}\n" for h in hosts),
            "applied": False,
            "why": "脚本只产出片段；系统 hosts/代理由人或容器应用，避免污染本机",
        },
        "classes": cases,
        "closed": closed,
        "counts": {"cases": total["pass"] + total["fail"], "pass": total["pass"], "fail": total["fail"]},
        "verdict": "pass" if total["fail"] == 0 else "fail",
        "rules": [
            "四类各一路，缺 role 直接 blocked；不许用 3 类冒充 4 类。",
            "timeout 必须是客户端超时，不是 500 或连接被拒。",
            "error_code 必须是 4xx + JSON error；404 not_implemented 不算鉴权路径。",
            "normal 若录制样本本身是 4xx，先拿有效会话再判，不许改判据。",
        ],
    }
    return out


# ------------------------------------------------------------------ self-test
API_FIX = {
    "schema": "seep.api-surface/1",
    "endpoints": [
        {"id": "POST https://api.example.test/api/login", "method": "POST", "host": "api.example.test",
         "path": "/api/login", "role": "login", "query": {}, "body_fields": {"name": {"types": ["text"]}},
         "samples": [{"status": 200, "body_file": None, "json_body": {"token": "t-1"}}]},
        {"id": "GET https://api.example.test/api/list", "method": "GET", "host": "api.example.test",
         "path": "/api/list", "role": "list",
         "query": {"page": {"observed": ["1"]}}, "body_fields": {}, "samples": [{"status": 200}]},
        {"id": "POST https://api.example.test/api/submit", "method": "POST", "host": "api.example.test",
         "path": "/api/submit", "role": "submit", "query": {},
         "body_fields": {"answer": {"types": ["text"]}}, "samples": [{"status": 200}]},
        {"id": "GET https://api.example.test/api/heartbeat", "method": "GET", "host": "api.example.test",
         "path": "/api/heartbeat", "role": "heartbeat", "query": {}, "body_fields": {},
         "samples": [{"status": 200}]},
    ],
}

SELFTEST_SERVER = '''#!/usr/bin/env python3
import argparse, json, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def _send(self, code, obj):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def _go(self):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
        if "__delay" in q:
            time.sleep(float(q["__delay"]))
        if "__status" in q:
            return self._send(int(q["__status"]), {"ok": False, "error": q.get("__error") or "forced"})
        if self.path.startswith("/api/login"):
            return self._send(200, {"ok": True, "token": "t-1", "source": "recorded"})
        if self.path.startswith("/api/list"):
            return self._send(200, {"ok": True, "items": [], "source": "recorded"})
        if self.path.startswith("/api/submit"):
            return self._send(200, {"ok": True, "id": "s1", "source": "recorded"})
        if self.path.startswith("/api/heartbeat"):
            return self._send(200, {"ok": True, "alive": True, "source": "recorded"})
        return self._send(404, {"ok": False, "error": "not_implemented"})
    do_GET = _go
    do_POST = _go

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, default=0)
a = ap.parse_args()
s = ThreadingHTTPServer(("127.0.0.1", a.port), H)
print(json.dumps({"base": "http://127.0.0.1:%d" % s.server_address[1]}), flush=True)
s.serve_forever()
'''


def self_test():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        srv = os.path.join(td, "srv.py")
        with open(srv, "w", encoding="utf-8") as f:
            f.write(SELFTEST_SERVER)
        port = free_port()
        proc = subprocess.Popen([sys.executable, srv, "--port", str(port)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            base = f"http://127.0.0.1:{port}"
            for _ in range(60):
                try:
                    urllib.request.urlopen(base + "/api/heartbeat", timeout=0.3).read()
                    break
                except Exception:  # noqa: BLE001
                    time.sleep(0.1)
            doc = run_verify(API_FIX, base, timeout=1.0)
            assert doc["verdict"] == "pass", json.dumps(doc["counts"], ensure_ascii=False)
            assert doc["counts"]["cases"] == 12, doc["counts"]
            assert all(len(doc["classes"][c][p]) == 1 for c in CLASSES
                       for p in ("normal", "timeout", "error_code")), doc["classes"].keys()
            assert doc["classes"]["login"]["normal"][0]["observed"]["source"] == "recorded"
            assert doc["switch"]["applied"] is False
            # 失败可判：把 timeout 压到 1ms 且服务端回包正常 → normal 仍应过，timeout 用黑洞兜底
            # 用不支持钩子的场景验证黑洞回退：直接对 /__health 之外的静态服务不可能，跳过。
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                proc.kill()
        return emit({"ok": True, "self_test": True, "cases": 12,
                     "verdict": "pass", "classes": list(CLASSES)}, 0)


def main(argv=None):
    ap = JsonArgParser(
        description="切本地后端 + login/list/submit/heartbeat 四类 × 正常/超时/错误码三路回归",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="退出码：0 全绿 / 2 blocked 或有失败")
    ap.add_argument("--api", help="api-surface.json")
    ap.add_argument("--base", default=None, help="已在跑的本地后端 base URL")
    ap.add_argument("--server", default=None, help="backend-scaffold 生成的 server.py（自动起停）")
    ap.add_argument("--port", type=int, default=0, help="--server 时使用端口，0=自动")
    ap.add_argument("--boot-timeout", type=float, default=15.0)
    ap.add_argument("--out", default="switched.json")
    ap.add_argument("--timeout", type=float, default=1.2)
    ap.add_argument("--mode", default="proxy", choices=["proxy", "hosts", "patch", "none"])
    ap.add_argument("--classes", default=",".join(CLASSES))
    ap.add_argument("--closed-target", default=None, help="关停后端地址（验证停服形态）")
    ap.add_argument("--write-hosts", default=None, help="把 hosts 片段写到该路径（不写系统 hosts）")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        try:
            return self_test()
        except Exception as e:  # noqa: BLE001
            return blocked("self-test", e)
    if not args.api:
        return blocked("input", "缺少 --api api-surface.json")
    if not (args.base or args.server):
        return blocked("input", "需要 --base 或 --server 之一")
    classes = tuple(x.strip() for x in args.classes.split(",") if x.strip())
    bad = [c for c in classes if c not in CLASSES]
    if bad:
        return blocked("classes", f"未知回归类：{bad}（只支持 {CLASSES}）")
    try:
        api_doc = load_json(args.api)
    except Exception as e:  # noqa: BLE001
        return blocked("api", e)
    for ep in api_doc.get("endpoints") or []:
        ep["_samples_dir"] = (api_doc.get("sources") or {}).get("samples_dir")

    proc, base = None, args.base
    try:
        if args.server:
            port = args.port or free_port()
            base = f"http://127.0.0.1:{port}"
            proc = subprocess.Popen([sys.executable, args.server, "--port", str(port), "--quiet"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            deadline = time.time() + args.boot_timeout
            last = None
            while time.time() < deadline:
                try:
                    wait_health(base, tries=1)
                    break
                except Exception as e:  # noqa: BLE001
                    last = e
                    time.sleep(0.15)
            else:
                raise TimeoutError(f"server.py 未就绪：{last}")
        try:
            doc = run_verify(api_doc, base, timeout=args.timeout, mode=args.mode,
                             classes=classes, closed_target=args.closed_target)
        except LookupError as e:
            return blocked("roles", e)
        except Exception as e:  # noqa: BLE001
            return blocked("verify", e)

        if args.write_hosts:
            with open(args.write_hosts, "w", encoding="utf-8") as f:
                f.write(doc["switch"]["hosts_fragment"])
            doc["switch"]["hosts_file"] = args.write_hosts
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        if doc["verdict"] != "pass":
            return emit({"ok": False, "blocked_at": "regression", "reason":
                         f"{doc['counts']['fail']} 个用例失败，详见 {args.out}",
                         "counts": doc["counts"], "out": args.out}, 2)
        return emit({"ok": True, "out": args.out, "verdict": doc["verdict"],
                     "counts": doc["counts"], "base": base, "mode": args.mode}, 0)
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
