#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Probe an app's HTTP API the way the app does.

Purpose-built for the common frustration: your request gets 403 while the app
works fine. Almost always the app sends a header you are not sending (frequently
one custom header), or your egress IP differs from the device's.

Usage
-----
  python probe_api.py --base https://api.example.com --path /health
  python probe_api.py --base https://api.example.com --path /adverts \
      --param position=banner --header 'X-App-Name: myapp'
  python probe_api.py --base https://api.example.com \
      --path "/items?page=1" --raw

Options
-------
  --base        Base URL (required)
  --path        Path, may already contain a query string (required)
  --method      GET / POST / PUT (default: GET；GET 行为与旧版完全一致)
  --data        Request body for POST/PUT. `@file` reads the body from a file.
                Default Content-Type: application/json for `{`/`[` bodies,
                otherwise application/x-www-form-urlencoded (override with --header).
  --param k=v   Repeatable; appended as query parameters
  --header k=v  Repeatable; sent as-is. Always send the app's real headers.
  --token T     Convenience: adds 'Authorization: Bearer T'
  --ua UA       User-Agent (default: okhttp/4.12.0)
  --no-proxy    Ignore environment proxy settings (recommended)
  --show        Print the first N bytes of the body (default 800)

Exit codes
----------
  0  HTTP < 400
  1  transport error (DNS/TLS/timeout, no HTTP response)
  2  bad arguments
  3  HTTP >= 400 (4xx/5xx). The summary JSON still has ok:true but
     http_status >= 400 — a 404 is not a success, do not replay it as one.

A one-line JSON summary is always printed as the last stdout line:
  {"ok": true, "method": "GET", "url": "...", "http_status": 200, "body_bytes": 123}

Interpreting results
--------------------
  200 + data        -> alive; read the envelope shape
  200 + empty list  -> valid input, nothing to return. Do NOT assume "ad removed":
                       it may simply be that no item is configured.
  400 + message     -> input is validated; the message often lists valid values
  401/403, no creds -> auth-gated (server-side ownership)
  401/403, forged   -> token is verified server-side; client patching cannot mint one
  403 + HTML body    -> a WAF/CDN refused your *request shape* or egress, not the endpoint
  404               -> exact path mismatch
"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

METHODS = ("GET", "POST", "PUT")


def build_opener(no_proxy):
    if no_proxy:
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener()


def _summary(ok, method, url, status, nbytes):
    return {"ok": ok, "method": method, "url": url,
            "http_status": status, "body_bytes": nbytes}


def _emit(summary):
    """结构化摘要（最后一行 JSON），供配方/判据机检。"""
    print(json.dumps(summary, ensure_ascii=False))


def _build_url(a):
    url = a.base.rstrip('/') + a.path
    if a.param:
        params = []
        for p in a.param:
            if '=' not in p:
                raise ValueError('--param expects k=v, got %r' % p)
            k, v = p.split('=', 1)
            params.append((k, v))
        sep = '&' if '?' in url else '?'
        url += sep + urllib.parse.urlencode(params)
    return url


def _build_headers(a, body):
    headers = {
        'User-Agent': a.ua,
        'Accept': 'application/json',
    }
    for h in a.header:
        if ':' not in h:
            raise ValueError('--header expects "Name: value", got %r' % h)
        k, v = h.split(':', 1)
        headers[k.strip()] = v.strip()
    if a.token:
        headers['Authorization'] = 'Bearer %s' % a.token
    if body is not None and not any(k.lower() == 'content-type' for k in headers):
        head = body.lstrip()[:1]
        headers['Content-Type'] = ('application/json' if head in ('{', '[')
                                   else 'application/x-www-form-urlencoded')
    return headers


def probe(base, path, method="GET", param=None, header=None, token=None,
          ua='okhttp/4.12.0', no_proxy=False, show=800, data=None):
    """发一次请求并打印结果；返回 (rc, summary)。rc: 0/<400, 1 传输错, 2 参数, 3 >=400。"""
    class _A:
        pass
    a = _A()
    a.base, a.path, a.method, a.param, a.header = base, path, method.upper(), param or [], header or []
    a.token, a.ua, a.no_proxy, a.show, a.data = token, ua, no_proxy, show, data
    if a.method not in METHODS:
        print('[FAIL] --method must be one of %s, got %r' % ('/'.join(METHODS), method))
        _emit(_summary(False, str(method), base, None, 0))
        return 2, _summary(False, str(method), base, None, 0)
    try:
        url = _build_url(a)
    except ValueError as exc:
        print('[FAIL] %s' % exc)
        return 2, _summary(False, a.method, base, None, 0)

    body = None
    if a.data is not None:
        if a.data.startswith('@'):
            try:
                with open(a.data[1:], 'r', encoding='utf-8', errors='replace') as fh:
                    body = fh.read()
            except OSError as exc:
                print('[FAIL] cannot read --data file: %s' % exc)
                return 2, _summary(False, a.method, url, None, 0)
        else:
            body = a.data
    if body is not None and a.method == 'GET':
        print('[FAIL] --data needs --method POST/PUT')
        return 2, _summary(False, a.method, url, None, 0)

    try:
        headers = _build_headers(a, body)
    except ValueError as exc:
        print('[FAIL] %s' % exc)
        return 2, _summary(False, a.method, url, None, 0)

    print('[req] %s %s' % (a.method, url))
    for k, v in headers.items():
        shown = v if k.lower() != 'authorization' else v[:24] + '...'
        print('      %s: %s' % (k, shown))
    payload = body.encode('utf-8') if isinstance(body, str) else None
    if payload is not None:
        print('      [body] %d bytes' % len(payload))

    req = urllib.request.Request(url, data=payload, headers=headers, method=a.method)
    op = build_opener(a.no_proxy)
    status = None
    nbytes = 0
    try:
        with op.open(req, timeout=30) as r:
            raw = r.read()
            nbytes = len(raw)
            body_text = raw.decode('utf-8', 'replace')
            status = int(r.status)
            print('[res] %s  %s' % (status, r.headers.get('Content-Type', '')))
            print(body_text[:a.show])
            if body_text.strip().startswith(('{', '[')):
                try:
                    parsed = json.loads(body_text)
                    if isinstance(parsed, dict) and 'data' in parsed:
                        d = parsed['data']
                        if isinstance(d, dict) and 'list' in d:
                            print('[shape] data.list length=%s' % len(d['list'] or []))
                except Exception:
                    pass
    except urllib.error.HTTPError as e:
        raw = e.read()
        nbytes = len(raw)
        status = int(e.code)
        print('[res] HTTP %s' % status)
        print(raw.decode('utf-8', 'replace')[:a.show])
    except Exception as e:
        print('[ERR] %s' % e)
        summary = _summary(False, a.method, url, None, 0)
        _emit(summary)
        return 1, summary

    rc = 0 if status is not None and status < 400 else 3
    summary = _summary(True, a.method, url, status, nbytes)
    _emit(summary)
    return rc, summary


def self_test():
    """离线自测：本机 127.0.0.1 临时 HTTP 服务（不联网），验证 200/404/POST。"""
    import contextlib
    import io
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    seen = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _reply(self, code, body):
            data = body.encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            seen['GET'] = self.path
            if self.path.startswith('/missing'):
                self._reply(404, '{"error":"not found"}')
            else:
                self._reply(200, '{"ok":true,"data":{"list":[1,2]}}')

        def do_POST(self):
            n = int(self.headers.get('Content-Length') or 0)
            seen['POST'] = self.rfile.read(n).decode('utf-8', 'replace')
            seen['CT'] = self.headers.get('Content-Type')
            self._reply(200, '{"ok":true,"echo":%s}' % json.dumps(seen['POST']))

    srv = HTTPServer(('127.0.0.1', 0), H)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    base = 'http://127.0.0.1:%d' % port
    checks, fails = [], []

    def run(argv):
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                rc = main(argv)
        except SystemExit as exc:            # argparse 失败（无效 --method 等）→ rc=2
            rc = exc.code if isinstance(exc.code, int) else 2
        lines = [ln for ln in buf.getvalue().strip().splitlines() if ln.strip()]
        summary = None
        try:
            summary = json.loads(lines[-1]) if lines else None
        except ValueError:
            summary = None
        return rc, summary, buf.getvalue()

    try:
        rc, sm, _ = run(['--base', base, '--path', '/health', '--no-proxy'])
        checks.append(('get-200-rc0', rc == 0))
        checks.append(('get-200-status', sm and sm.get('http_status') == 200))
        checks.append(('get-200-ok', sm and sm.get('ok') is True))

        rc, sm, _ = run(['--base', base, '--path', '/missing', '--no-proxy'])
        checks.append(('404-rc3', rc == 3))
        checks.append(('404-status-in-json', sm and sm.get('http_status') == 404))
        checks.append(('404-ok-true', sm and sm.get('ok') is True))

        rc, sm, out = run(['--base', base, '--path', '/echo', '--method', 'POST',
                           '--data', '{"a":1}', '--no-proxy'])
        checks.append(('post-rc0', rc == 0))
        checks.append(('post-body-echoed', seen.get('POST') == '{"a":1}'))
        checks.append(('post-method-in-json', sm and sm.get('method') == 'POST'))
        checks.append(('post-json-content-type', seen.get('CT') == 'application/json'))

        rc, _, _ = run(['--base', base, '--path', '/health', '--method', 'PATCH'])
        checks.append(('bad-method-rc2', rc == 2))
        rc, _, _ = run(['--base', base, '--path', '/health', '--param', 'bad'])
        checks.append(('bad-param-rc2', rc == 2))
    finally:
        srv.shutdown()
        srv.server_close()

    fails = [name for name, ok in checks if not ok]
    print(json.dumps({'ok': not fails, 'tool': 'probe_api.py',
                      'checks': len(checks), 'failures': fails}, ensure_ascii=False))
    return 0 if not fails else 1


def main(argv=None):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument('--base')
    ap.add_argument('--path')
    ap.add_argument('--method', default='GET', choices=list(METHODS))
    ap.add_argument('--data', default=None, help='POST/PUT body, @file reads a file')
    ap.add_argument('--param', action='append', default=[])
    ap.add_argument('--header', action='append', default=[])
    ap.add_argument('--token')
    ap.add_argument('--ua', default='okhttp/4.12.0')
    ap.add_argument('--no-proxy', action='store_true')
    ap.add_argument('--show', type=int, default=800)
    ap.add_argument('--self-test', action='store_true', help='离线自测（本机临时 HTTP 服务）')
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.base or not a.path:
        ap.error('--base and --path are required (or use --self-test)')

    rc, _ = probe(a.base, a.path, method=a.method, param=a.param, header=a.header,
                  token=a.token, ua=a.ua, no_proxy=a.no_proxy, show=a.show, data=a.data)
    return rc


if __name__ == '__main__':
    raise SystemExit(main())
