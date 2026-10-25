#!/usr/bin/env python3
"""Probe the MT Manager built-in APK MCP server (Streamable HTTP).

MT Manager (bin.mt.plus) ships an "APK MCP" service that exposes its APK
analysis/edit/repack/sign capabilities to MCP clients over Streamable HTTP,
by default on device port 8787 (reachable from the PC via
``adb forward tcp:8787 tcp:8787``).

This script does the MCP handshake by hand (JSON-RPC 2.0 over plain HTTP
POSTs, no mcp SDK dependency):

  1. ``initialize``        -> serverInfo + capabilities
  2. ``notifications/initialized``
  3. ``tools/list``        -> tool inventory

Output is a human-readable capability report grouping the ``mt_apk_*`` tools
by category. When the server is not up yet (it must be started by hand in
the MT UI; adb cannot start it), the script prints waiting instructions and
exits 2, so it can also be used as a "is it up yet" check in a loop.

Verification status of the protocol shape: measured against the MT 2.26.9
implementation on 2026-09 (see docs/tool-verification/EXTENSION-kernel-ondevice.md).
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8787/mcp"

# Tool categories for the report, keyed by name prefix within mt_apk_*.
CATEGORIES = [
    ("open", "APK open/selection"),
    ("list", "Entry listing"),
    ("search", "Text/string search"),
    ("read", "Content read"),
    ("dex", "Dex analysis"),
    ("resource", "Resources"),
    ("native", "Native (.so) static analysis"),
    ("edit", "Edit sessions"),
    ("patch", "Byte/instruction patching"),
    ("build", "Repack + sign"),
    ("close", "Cleanup"),
]


def http_post(url, payload, session_id=None, timeout=10.0):
    """POST one JSON-RPC message; return (status, headers, parsed-body-or-None).

    Handles both plain application/json responses and text/event-stream
    (SSE-framed) responses, which Streamable HTTP servers may use for
    request bodies. Returns the first JSON object found in either shape.
    """
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            sid = resp.headers.get("Mcp-Session-Id")
            return resp.status, sid, parse_body(raw, resp.headers.get("Content-Type", ""))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        return e.code, None, parse_body(raw, e.headers.get("Content-Type", ""))


def parse_body(raw, ctype):
    """Extract the first JSON message from a JSON or SSE-framed body."""
    raw = raw.strip()
    if not raw:
        return None
    if "text/event-stream" in (ctype or ""):
        for line in raw.splitlines():
            if line.startswith("data:"):
                chunk = line[len("data:"):].strip()
                try:
                    return json.loads(chunk)
                except ValueError:
                    continue
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def print_waiting_help(url):
    host = "127.0.0.1"
    print("[waiting] MCP server is not answering at %s" % url)
    print()
    print("The MT APK MCP must be started by hand in the MT UI (adb cannot start it):")
    print("  1. On the phone: MT Manager -> side drawer -> Tools -> APK MCP -> Start")
    print("  2. Note the address shown on that page (host:port, default 8787)")
    print("  3. On the PC, make the port reachable over USB:")
    print("       adb forward tcp:8787 tcp:8787")
    print("  4. Re-run this probe:  python mt_mcp_probe.py")
    print()
    print("(LAN alternative: connect the PC and phone to the same network and pass")
    print(" --url http://<phone-ip>:8787/mcp)")


def self_test():
    """Offline self-test: a loopback stub MCP server, no device, no internet.

    Exercises the parts that decide the verdict: JSON/SSE body framing, the
    Mcp-Session-Id round trip, and the full initialize -> tools/list -> grouping
    path against a server that speaks the same wire format.
    """
    import contextlib
    import io
    import os
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    checks = 0
    seen = []
    tools = [
        {'name': 'mt_apk_open', 'description': 'Open an APK\nsecond line ignored'},
        {'name': 'mt_apk_build_sign', 'description': 'Repack and sign'},
        {'name': 'mt_apk_misc_thing', 'description': 'unclassified helper'},
        {'name': 'not_mt', 'description': 'foreign tool'},
    ]

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _reply(self, code, body, ctype='application/json', sid=None):
            raw = body.encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(raw)))
            if sid:
                self.send_header('Mcp-Session-Id', sid)
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            # Drain the body BEFORE answering an error: a reply that leaves unread
            # request bytes makes Windows abort the connection (WinError 10053)
            # instead of delivering the 404 to the client.
            n = int(self.headers.get('Content-Length') or 0)
            raw = self.rfile.read(n)
            if self.path not in ('/mcp', '/sse'):
                self.send_error(404)
                return
            req = json.loads(raw.decode('utf-8'))
            seen.append((req.get('method'), self.headers.get('Mcp-Session-Id')))
            if self.path == '/sse':
                self._reply(200, 'event: message\ndata: %s\n\n'
                            % json.dumps({'jsonrpc': '2.0', 'id': req.get('id'),
                                          'result': {'protocolVersion': '2024-11-05',
                                                     'serverInfo': {'name': 'mt',
                                                                    'version': '2.26.9'}}}),
                            ctype='text/event-stream', sid='sid-sse')
                return
            if req.get('method') == 'initialize':
                self._reply(200, json.dumps({
                    'jsonrpc': '2.0', 'id': req.get('id'),
                    'result': {'protocolVersion': '2024-11-05',
                               'serverInfo': {'name': 'mt', 'version': '2.26.9'},
                               'capabilities': {}}}), sid='sid-1')
                return
            if req.get('method') == 'tools/list':
                self._reply(200, json.dumps({'jsonrpc': '2.0', 'id': req.get('id'),
                                             'result': {'tools': tools}}))
                return
            self._reply(202, '')

    server = HTTPServer(('127.0.0.1', 0), Handler)
    url = 'http://127.0.0.1:%d/mcp' % server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    old_no_proxy = os.environ.get('no_proxy')
    os.environ['no_proxy'] = '127.0.0.1'
    try:
        # 1) body framing: plain JSON, SSE-framed JSON, junk
        assert parse_body('{"a": 1}', 'application/json') == {'a': 1}
        assert parse_body('event: message\ndata: {"b": 2}\n', 'text/event-stream') == {'b': 2}
        assert parse_body('   ', 'application/json') is None
        assert parse_body('{not json', 'application/json') is None
        assert parse_body('data: nope\n', 'text/event-stream') is None
        checks += 1

        # 2) one JSON-RPC POST: status, session id, and the parsed result
        status, sid, body = http_post(url, {'jsonrpc': '2.0', 'id': 1,
                                            'method': 'initialize'}, timeout=5.0)
        assert status == 200, status
        assert sid == 'sid-1', sid
        assert body['result']['serverInfo'] == {'name': 'mt', 'version': '2.26.9'}, body
        checks += 1

        # 3) SSE responses and the outgoing session header
        status, sid, body = http_post('http://127.0.0.1:%d/sse' % server.server_address[1],
                                      {'jsonrpc': '2.0', 'id': 2,
                                       'method': 'initialize'}, timeout=5.0)
        assert (status, sid) == (200, 'sid-sse'), (status, sid)
        assert body['result']['protocolVersion'] == '2024-11-05', body
        status, _sid, body = http_post(url, {'jsonrpc': '2.0', 'id': 3,
                                             'method': 'tools/list'},
                                       session_id='sid-1', timeout=5.0)
        assert status == 200 and body['result']['tools'] == tools
        assert seen[-1] == ('tools/list', 'sid-1'), seen[-1]
        checks += 1

        # 4) an HTTP error is returned as a status, not raised as a traceback
        status, sid, body = http_post('http://127.0.0.1:%d/nope' % server.server_address[1],
                                      {'jsonrpc': '2.0', 'id': 4, 'method': 'x'},
                                      timeout=5.0)
        assert status == 404 and sid is None and body is None, (status, sid, body)
        checks += 1

        # 5) the full CLI handshake and the capability grouping it prints
        out = io.StringIO()
        old_argv = sys.argv
        sys.argv = ['mt_mcp_probe.py', '--url', url]
        try:
            with contextlib.redirect_stdout(out):
                rc = main()
        finally:
            sys.argv = old_argv
        text = out.getvalue()
        assert rc == 0, rc
        assert '== MCP tool inventory: 4 tool(s) ==' in text, text[:400]
        assert '[APK open/selection] 1' in text, text
        assert '[Repack + sign] 1' in text, text
        assert '[non-mt_apk tools] 1' in text, text
        assert 'second line ignored' not in text, 'the description was not cut to line 1'
        assert seen[-2][0] == 'notifications/initialized', seen[-2:]
        assert seen[-1] == ('tools/list', 'sid-1'), seen[-1]
        checks += 1

        # 6) defaults the documented workflow depends on
        assert DEFAULT_URL == 'http://127.0.0.1:8787/mcp', DEFAULT_URL
        help_out = io.StringIO()
        with contextlib.redirect_stdout(help_out):
            print_waiting_help(DEFAULT_URL)
        assert 'adb forward tcp:8787 tcp:8787' in help_out.getvalue()
        checks += 1

        print(json.dumps({'ok': True, 'checks': checks, 'tool': 'mt_mcp_probe.py'}))
        return 0
    except Exception as exc:
        print(json.dumps({'ok': False, 'checks': checks, 'tool': 'mt_mcp_probe.py',
                          'reason': '%s: %s' % (type(exc).__name__, exc)}))
        return 1
    finally:
        server.shutdown()
        server.server_close()
        if old_no_proxy is None:
            os.environ.pop('no_proxy', None)
        else:
            os.environ['no_proxy'] = old_no_proxy


def main():
    ap = argparse.ArgumentParser(
        description="Probe the MT Manager APK MCP (Streamable HTTP) and list its tools.")
    ap.add_argument("--url", default=DEFAULT_URL,
                    help="MCP endpoint (default: %(default)s)")
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="per-request timeout in seconds (default: %(default)s)")
    ap.add_argument("--json", action="store_true",
                    help="print raw JSON-RPC responses instead of the report")
    ap.add_argument("--self-test", action="store_true",
                    help="run the offline built-in checks and exit (loopback stub server)")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    # 1) initialize
    init = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mt-mcp-probe", "version": "0.1"},
        },
    }
    try:
        status, session_id, body = http_post(args.url, init, timeout=args.timeout)
    except (urllib.error.URLError, OSError) as e:
        print_waiting_help(args.url)
        if args.json:
            print("[error] %s" % e)
        return 2

    if body is None or "result" not in (body or {}):
        print("[unexpected] HTTP %d, no MCP initialize result in response" % status)
        if args.json:
            print(json.dumps(body, indent=2) if body is not None else "(empty body)")
        return 1

    result = body["result"]
    server = result.get("serverInfo", {})
    proto = result.get("protocolVersion", "?")
    print("[online] %s | server %s %s | protocol %s | HTTP %d%s" % (
        args.url, server.get("name", "?"), server.get("version", "?"),
        proto, status, " | session %s" % session_id if session_id else ""))
    if args.json:
        print(json.dumps(result, indent=2))

    # 2) initialized notification (no id -> notification; 202 expected, body ignored)
    note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    try:
        http_post(args.url, note, session_id=session_id, timeout=args.timeout)
    except (urllib.error.URLError, OSError):
        pass  # some servers accept it silently; tools/list will tell us

    # 3) tools/list
    listing = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    try:
        status, _, body = http_post(args.url, listing, session_id=session_id,
                                    timeout=args.timeout)
    except (urllib.error.URLError, OSError) as e:
        print("[error] tools/list failed after successful initialize: %s" % e)
        return 1

    if body is None or "result" not in (body or {}):
        print("[unexpected] HTTP %d, no tools/list result" % status)
        if args.json:
            print(json.dumps(body, indent=2) if body is not None else "(empty body)")
        return 1

    tools = body["result"].get("tools", [])
    if args.json:
        print(json.dumps(body, indent=2))

    # 4) capability report
    print()
    print("== MCP tool inventory: %d tool(s) ==" % len(tools))
    mt_tools = [t for t in tools if t.get("name", "").startswith("mt_apk_")]
    other = [t for t in tools if not t.get("name", "").startswith("mt_apk_")]

    grouped = {prefix: [] for prefix, _ in CATEGORIES}
    for t in sorted(mt_tools, key=lambda x: x.get("name", "")):
        name = t.get("name", "")
        suffix = name[len("mt_apk_"):]
        placed = False
        for prefix, label in CATEGORIES:
            if suffix == prefix or suffix.startswith(prefix + "_"):
                grouped[prefix].append(t)
                placed = True
                break
        if not placed:
            grouped.setdefault("misc", []).append(t)

    for prefix, label in CATEGORIES:
        items = grouped.get(prefix, [])
        if not items:
            continue
        print("\n[%s] %s" % (label, len(items)))
        for t in items:
            desc = (t.get("description") or "").strip().splitlines()
            first = desc[0].strip() if desc else ""
            print("  %-42s %s" % (t.get("name"), first[:90]))
    if grouped.get("misc"):
        print("\n[other mt_apk_*] %d" % len(grouped["misc"]))
        for t in grouped["misc"]:
            print("  %s" % t.get("name"))

    if other:
        print("\n[non-mt_apk tools] %d" % len(other))
        for t in other:
            print("  %s" % t.get("name"))

    print()
    print("Constraints (from the official MT MCP docs, see on-device-tooling.md):")
    print("  - no Java decompilation; read smali directly instead")
    print("  - .so support is static analysis only (no dynamic run, no pseudo-C)")
    print("  - resources.arsc: existing entries editable, no new locales/entries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
