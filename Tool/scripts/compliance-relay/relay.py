#!/usr/bin/env python3
"""Local HTTP relay. Request/response bodies retain their original bytes.

Lab/force flags are status preferences only. They cannot enable text rewriting,
provider safety overrides or refusal retries. Existing protocol names remain
available to diagnostics and regression tests; they do not authorize mutation.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(HERE, "relay-config.json")
DEFAULT_PORT = 17890
AGENT_DIR = os.environ.get("PI_CODING_AGENT_DIR") or os.path.join(os.path.expanduser("~"), ".pi", "agent")
DEFAULT_LAB_FLAG = os.path.join(AGENT_DIR, "lab-mode.flag")
DEFAULT_PI_MODELS = os.path.join(AGENT_DIR, "models.json")
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailer", "trailers", "transfer-encoding", "upgrade"}
REQUEST_HEADER_DROP = {"host", "content-length"}
CHUNK_SIZE = 8192


def detect_protocol(path: str) -> str | None:
    lowered = path.lower().split("?", 1)[0]
    for suffix, protocol in (("/messages", "anthropic-messages"),
                             ("/chat/completions", "openai-completions"),
                             ("/responses", "openai-responses")):
        if lowered.endswith(suffix):
            return protocol
    return None


class LabModeGate:
    """Live status only; a regular flag file enables the work preference."""
    def __init__(self, flag_path: str, force: bool | None = None):
        self.flag_path, self.force = flag_path, force

    def is_active(self) -> bool:
        if self.force is not None:
            return self.force
        try:
            import stat
            return stat.S_ISREG(os.lstat(self.flag_path).st_mode)
        except OSError:
            return False


def _load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_or_init_config(port: int | None) -> dict:
    cfg = _load_json(CONFIG_FILE) if os.path.isfile(CONFIG_FILE) else {
        "schema": 1, "port": DEFAULT_PORT, "token": "", "upstreams": {}}
    if not cfg.get("token"):
        cfg["token"] = secrets.token_urlsafe(24)
    if port is not None:
        cfg["port"] = port
    cfg.setdefault("schema", 1)
    cfg.setdefault("port", DEFAULT_PORT)
    cfg.setdefault("upstreams", {})
    # Retire even previously enabled configurations. No retry code consumes them.
    cfg.pop("refusalRetry", None)
    cfg.pop("refusalRetryAttempts", None)
    with open(CONFIG_FILE, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(cfg, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return cfg


def scan_pi_providers(pi_models_path: str) -> dict[str, str]:
    """Explicit CLI helper. Reads provider endpoints, never emits auth values."""
    if not os.path.isfile(pi_models_path):
        return {}
    providers = _load_json(pi_models_path).get("providers")
    if not isinstance(providers, dict):
        return {}
    return {f"pi-{name}": cfg["baseUrl"].rstrip("/")
            for name, cfg in providers.items()
            if isinstance(cfg, dict) and isinstance(cfg.get("baseUrl"), str)
            and cfg["baseUrl"].startswith(("http://", "https://"))}


class RelayState:
    def __init__(self, config: dict, gate: LabModeGate):
        self.config, self.gate = config, gate
        self.token = config["token"]
        self.upstreams = config.get("upstreams", {})
        self.verbose = False


def _parse_route(raw_path: str) -> tuple[str, str, str] | None:
    path = raw_path.split("?", 1)[0]
    query = raw_path[len(path):]
    parts = path.split("/")
    if len(parts) < 4 or parts[1] != "r":
        return None
    rest = "/" + "/".join(parts[4:]) if len(parts) > 4 else "/"
    return parts[2], parts[3], rest + query


def _split_upstream(base_url: str) -> tuple[str, str, int | None, str]:
    parts = urlsplit(base_url)
    return parts.scheme or "https", parts.hostname or "", parts.port, parts.path.rstrip("/")


def _read_request_body(handler: BaseHTTPRequestHandler) -> bytes | None:
    te = (handler.headers.get("Transfer-Encoding") or "").lower()
    if "chunked" in te:
        chunks: list[bytes] = []
        while True:
            line = handler.rfile.readline(65536).strip()
            try:
                size = int(line.split(b";", 1)[0], 16)
            except ValueError:
                return None
            if size < 0:
                return None
            if size == 0:
                # Consume optional trailer headers through the terminating CRLF.
                while True:
                    trailer = handler.rfile.readline(65536)
                    if trailer in (b"\r\n", b"\n", b""):
                        break
                break
            chunk = handler.rfile.read(size)
            if len(chunk) != size or handler.rfile.read(2) != b"\r\n":
                return None
            chunks.append(chunk)
        return b"".join(chunks)
    try:
        length = int(handler.headers.get("Content-Length") or "0")
    except ValueError:
        return None
    if length < 0:
        return None
    data = handler.rfile.read(length)
    return data if len(data) == length else None


def _apply_rewrite(state: RelayState, protocol: str | None, raw_body: bytes) -> tuple[bytes, int]:
    """Compatibility boundary: no parsing/reserialization, in every mode."""
    return raw_body, 0


class RelayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SeepComplianceRelay/2.0"
    state: RelayState = None  # type: ignore[assignment]

    def log_message(self, fmt: str, *args) -> None:
        return

    def _send_plain(self, code: int, message: str) -> None:
        payload = message.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _resolve(self) -> tuple[str, str, str] | None:
        route = _parse_route(self.path)
        if route is None:
            self._send_plain(404, "not found")
            return None
        token, key, rest = route
        if not secrets.compare_digest(token, self.state.token):
            self._send_plain(403, "forbidden")
            return None
        upstream = self.state.upstreams.get(key)
        if not upstream:
            self._send_plain(502, "unknown upstream key")
            return None
        return key, upstream, rest

    def _forward(self, method: str) -> None:
        # Consume the framed body even on rejected routes. Closing a Windows
        # socket with unread bytes can reset it before the 403/404 reaches peers.
        raw_body = _read_request_body(self)
        if raw_body is None:
            self.close_connection = True
            self._send_plain(400, "bad request body")
            return
        resolved = self._resolve()
        if resolved is None:
            return
        _, upstream, rest = resolved
        body, _ = _apply_rewrite(self.state, detect_protocol(rest), raw_body)
        try:
            scheme, host, port, base_path = _split_upstream(upstream)
            if scheme not in ("http", "https") or not host:
                raise ValueError()
        except ValueError:
            self._send_plain(502, "invalid upstream")
            return
        target = f"{base_path}{rest}" if base_path else rest
        if not target.startswith("/"):
            target = "/" + target
        connection_headers = {v.strip().lower() for v in self.headers.get("Connection", "").split(",")}
        headers = {name: value for name, value in self.headers.items()
                   if name.lower() not in HOP_BY_HOP | REQUEST_HEADER_DROP | connection_headers}
        headers["Content-Length"] = str(len(body))
        conn = (HTTPSConnection if scheme == "https" else HTTPConnection)(host, port, timeout=600)
        resp = None
        started = False
        try:
            # Exactly one request. Errors, empty results and refusals go back as received.
            conn.request(method, target, body=body, headers=headers)
            resp = conn.getresponse()
            self.send_response(resp.status)
            resp_connection = {v.strip().lower() for v in (resp.getheader("Connection") or "").split(",")}
            for name, value in resp.getheaders():
                if name.lower() not in HOP_BY_HOP | {"content-length"} | resp_connection:
                    self.send_header(name, value)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            started = True
            while True:
                chunk = resp.read1(CHUNK_SIZE)
                if not chunk:
                    break
                self.wfile.write(f"{len(chunk):X}\r\n".encode("ascii") + chunk + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
            if self.state.verbose:
                # No URL/query, token, request, response or auth header in logs.
                print(f"[PASS] status={resp.status} lab={self.state.gate.is_active()} rewrite=false retry=false", flush=True)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True
        except Exception:
            if started:
                self.close_connection = True
            else:
                self._send_plain(502, "upstream error")
        finally:
            if resp is not None:
                resp.close()
            conn.close()

    def do_POST(self) -> None:
        self._forward("POST")

    def do_GET(self) -> None:
        self._forward("GET")

    def do_PUT(self) -> None:
        self._forward("PUT")

    def do_DELETE(self) -> None:
        self._forward("DELETE")

    def do_PATCH(self) -> None:
        self._forward("PATCH")


class RelayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address) -> None:
        # Do not include exception text: it can contain a URL or payload fragment.
        print("[ERROR] relay handler failure", file=sys.stderr, flush=True)


def create_server(state: RelayState, host: str, port: int) -> RelayHTTPServer:
    handler_cls = type("BoundRelayHandler", (RelayHandler,), {"state": state})
    return RelayHTTPServer((host, port), handler_cls)


def main() -> int:
    parser = argparse.ArgumentParser(description="Seep 原文透传中继；不改写任务，不重试拒答")
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--force-on", action="store_true", help="兼容工作状态开关；不启用改写")
    parser.add_argument("--force-off", action="store_true", help="兼容工作状态开关；请求始终透传")
    parser.add_argument("--scan-pi", action="store_true", help="显式读取 provider endpoint 生成映射")
    parser.add_argument("--lab-flag", default=DEFAULT_LAB_FLAG)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if args.force_on and args.force_off:
        parser.error("--force-on 与 --force-off 不能同时使用")
    config = load_or_init_config(args.port)
    if args.scan_pi:
        config["upstreams"].update(scan_pi_providers(DEFAULT_PI_MODELS))
        with open(CONFIG_FILE, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(config, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        print("[OK] upstream 映射已写入配置；访问令牌仅保存在本机配置中")
        return 0
    force = True if args.force_on else False if args.force_off else None
    state = RelayState(config, LabModeGate(args.lab_flag, force))
    state.verbose = args.verbose
    server = create_server(state, args.host, config["port"])
    print(f"Seep Relay listening on {args.host}:{server.server_port}; rewrite=false retry=false", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
