#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""回环回显服务：只监听 127.0.0.1:18321，用于现场抓一条真实 HTTP 会话。

返回体是固定 JSON（无敏感数据），响应里带 Set-Cookie 与 X-Session-Id，
方便后续用 pcap-summary.py / tshark 观察 header 与业务字段。
用法：python input/echo_server.py [port]
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18321
STATE = {"n": 0}


class Handler(BaseHTTPRequestHandler):
    server_version = "ProtoLab/1.0"

    def _respond(self, code, obj, extra=None):
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "sid=lab-%04d; Path=/" % STATE["n"])
        self.send_header("X-Session-Id", "lab-%04d" % STATE["n"])
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
        sys.stdout.write("%s %s -> %d (%s)\n" % (
            self.command, self.path, code, "lab-%04d" % STATE["n"]))
        sys.stdout.flush()

    def do_GET(self):
        STATE["n"] += 1
        if self.path.startswith("/v1/telemetry"):
            self._respond(200, {"ok": True, "kind": "telemetry", "seq": STATE["n"]})
        else:
            self._respond(200, {"ok": True, "kind": "ping", "seq": STATE["n"]})

    def do_POST(self):
        STATE["n"] += 1
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        self._respond(200, {"ok": True, "kind": "echo", "bytes": len(raw), "seq": STATE["n"]})

    def log_message(self, fmt, *args):  # 关掉默认 stderr 噪声，改由 do_* 输出
        return


if __name__ == "__main__":
    sys.stdout.write("listening on 127.0.0.1:%d\n" % PORT)
    sys.stdout.flush()
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
