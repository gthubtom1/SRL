#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal HTTP/HTTPS forward proxy for giving an offline Android device network access.

Situation: the device has no working network interface (DHCP failure, no default route), so
every request the app makes fails.

Why this works: it does not need a network interface on the device at all. `adb reverse`
opens a listener on the **device's own loopback**, which exists regardless:

    1) run this proxy on the host        (0.0.0.0:8080)
    2) adb -s <serial> reverse tcp:8080 tcp:8080
    3) on the device: settings put global http_proxy 127.0.0.1:8080
    4) the app's HTTP/HTTPS traffic travels over USB and is sent by the host

Supports:
  - CONNECT tunnelling (what HTTPS uses)
  - absolute-URI plain HTTP forwarding

Forwards only: it does not MITM, does not decrypt TLS and does not modify traffic, so
certificate validation is unaffected. See references/environment.md.

Usage: python usb_net_proxy.py [listen_port] [logfile]
       python usb_net_proxy.py --self-test        # offline contract self-test
"""
import socket
import sys
import threading
import time

SELF_TEST = '--self-test' in sys.argv[1:]
if SELF_TEST:
    # The self-test never opens a listening socket or a log file; PORT/LOGF only
    # have to exist because they are module-level names main() uses.
    PORT, LOGF = 8080, None
else:
    if len(sys.argv) > 1 and sys.argv[1] in ('-h', '--help'):
        print(__doc__)
        sys.exit(0)

    try:
        PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    except ValueError:
        print('error: listen_port must be a number, got %r\n' % sys.argv[1])
        print(__doc__)
        sys.exit(2)
    LOGF = sys.argv[2] if len(sys.argv) > 2 else None
_lock = threading.Lock()
_logf = open(LOGF, 'a', encoding='utf-8') if LOGF else None


def log(msg):
    line = '[%s] %s' % (time.strftime('%H:%M:%S'), msg)
    print(line, flush=True)
    if _logf:
        with _lock:
            _logf.write(line + '\n')
            _logf.flush()


def pump(a, b):
    """Copy a -> b in one direction until either end closes."""
    try:
        while True:
            r, _, _ = select_select([a], [], [], 30)
            if not r:
                break
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except Exception:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass


def select_select(rlist, wlist, xlist, timeout):
    import select
    return select.select(rlist, wlist, xlist, timeout)


def read_head(sock, limit=65536):
    data = b''
    while b'\r\n\r\n' not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk
    return data


def handle(client, addr):
    client.settimeout(30)
    try:
        head = read_head(client)
        if not head:
            client.close()
            return
        first = head.split(b'\r\n', 1)[0].decode('latin-1')
        parts = first.split(' ')
        if len(parts) < 3:
            client.close()
            return
        method, target = parts[0].upper(), parts[1]
        rest = head.split(b'\r\n\r\n', 1)[1] if b'\r\n\r\n' in head else b''

        if method == 'CONNECT':
            host, _, port = target.rpartition(':')
            port = int(port or 443)
            log('CONNECT %s:%d' % (host, port))
            remote = socket.create_connection((host, port), timeout=20)
            client.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            client.settimeout(None)
            remote.settimeout(None)
            t = threading.Thread(target=pump, args=(client, remote), daemon=True)
            t.start()
            pump(remote, client)
        else:
            # Plain HTTP: target is normally an absolute URI
            if target.startswith('http://'):
                without = target[len('http://'):]
                hostport = without.split('/', 1)[0]
                path = '/' + without.split('/', 1)[1] if '/' in without else '/'
            else:
                hostport = None
                for ln in head.split(b'\r\n'):
                    if ln.lower().startswith(b'host:'):
                        hostport = ln.split(b':', 1)[1].strip().decode()
                path = target
            if not hostport:
                client.close()
                return
            host, _, port = hostport.rpartition(':')
            port = int(port or 80)
            log('HTTP %s%s' % (hostport, path))
            remote = socket.create_connection((host, port), timeout=20)
            req = ('%s %s HTTP/1.1\r\n' % (method, path)).encode()
            hdrs = head.split(b'\r\n')[1:]
            for h in hdrs:
                if h.lower().startswith(b'proxy-connection'):
                    continue
                req += h + b'\r\n'
            req += b'\r\n' + rest
            remote.sendall(req)
            client.settimeout(None)
            remote.settimeout(None)
            t = threading.Thread(target=pump, args=(client, remote), daemon=True)
            t.start()
            pump(remote, client)
    except Exception as e:
        log('ERR %s %s' % (addr, e))
        try:
            client.close()
        except Exception:
            pass


def self_test():
    """Offline self-test: hand-built request bytes, no listening socket, no network.

    handle() is the whole proxy decision, so it is driven here with a stub client
    and a stub remote: CONNECT must answer 200 before pumping, and a plain HTTP
    request must be rewritten to origin-form with Proxy-Connection removed.
    """
    import contextlib
    import io
    import json
    import os

    checks = []

    def chk(name, cond, detail=''):
        checks.append((name, bool(cond), detail))

    class FakeSock(object):
        def __init__(self, chunks=(), name='sock'):
            self.chunks = list(chunks)
            self.sent = b''
            self.closed = False
            self.timeouts = []
            self.name = name

        def recv(self, n):
            return self.chunks.pop(0) if self.chunks else b''

        def sendall(self, data):
            self.sent += data

        def settimeout(self, value):
            self.timeouts.append(value)

        def shutdown(self, how):
            pass

        def close(self):
            self.closed = True

    # 1) read_head: terminator detection, limit, and a closed peer
    got = read_head(FakeSock([b'GET / HTTP/1.1\r\nHost: x\r\n\r\nBODY']))
    chk('read-head-keeps-terminator', got.startswith(b'GET / HTTP/1.1') and
        b'\r\n\r\n' in got, got)
    chk('read-head-keeps-body', got.endswith(b'BODY'), got)
    limited = read_head(FakeSock([b'A' * 20]), limit=10)
    chk('read-head-limit', len(limited) == 20, len(limited))
    chk('read-head-empty', read_head(FakeSock([])) == b'')

    # 2) handle(): CONNECT tunnel
    global pump
    real_create = socket.create_connection
    real_pump = pump
    remotes = []

    class FakeRemote(FakeSock):
        pass

    def fake_create(address, timeout=None):
        r = FakeRemote(name='remote')
        r.address = address
        r.timeout_arg = timeout
        remotes.append(r)
        return r

    pumped = []
    quiet = io.StringIO()
    real_stdout = sys.stdout
    sys.stdout = quiet
    try:
        socket.create_connection = fake_create
        pump = lambda a, b: pumped.append((a.name, b.name))

        client = FakeSock([b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n'],
                          name='client')
        handle(client, ('127.0.0.1', 5000))
        chk('connect-one-remote', len(remotes) == 1, len(remotes))
        chk('connect-target', remotes and remotes[0].address == ('example.com', 443),
            remotes and remotes[0].address)
        chk('connect-timeout-20', remotes and remotes[0].timeout_arg == 20,
            remotes and remotes[0].timeout_arg)
        chk('connect-200-first', client.sent.startswith(
            b'HTTP/1.1 200 Connection Established\r\n\r\n'), client.sent[:60])
        chk('connect-pumped-both-ways', len(pumped) == 2, pumped)

        # 3) handle(): plain HTTP absolute URI -> origin form, Proxy-Connection removed
        remotes.clear()
        pumped.clear()
        body = (b'GET http://example.org:8080/path?q=1 HTTP/1.1\r\n'
                b'Host: example.org\r\n'
                b'Proxy-Connection: keep-alive\r\n'
                b'\r\n'
                b'hello')
        client = FakeSock([body], name='client')
        handle(client, ('127.0.0.1', 5001))
        req = remotes[0].sent
        chk('http-target', remotes[0].address == ('example.org', 8080), remotes[0].address)
        chk('http-origin-form', req.startswith(b'GET /path?q=1 HTTP/1.1\r\n'), req[:60])
        chk('http-keeps-host-header', b'Host: example.org\r\n' in req, req[:120])
        chk('http-drops-proxy-connection', b'Proxy-Connection' not in req, req[:160])
        chk('http-keeps-body', req.endswith(b'hello'), req[-20:])
        chk('http-pumped', len(pumped) == 2, pumped)

        # 4) malformed / hostless requests close the client instead of dialling out
        remotes.clear()
        bad = FakeSock([b'GET\r\n\r\n'], name='bad')
        handle(bad, ('127.0.0.1', 5002))
        chk('malformed-closes-client', bad.closed is True and remotes == [],
            (bad.closed, len(remotes)))
        hostless = FakeSock([b'GET /relative HTTP/1.1\r\n\r\n'], name='hostless')
        handle(hostless, ('127.0.0.1', 5003))
        chk('hostless-closes-client', hostless.closed is True and remotes == [],
            (hostless.closed, len(remotes)))
    finally:
        sys.stdout = real_stdout
        socket.create_connection = real_create
        pump = real_pump

    # 5) CLI contract: the port is validated before anything is bound; -h documents
    #    the adb reverse recipe.
    import subprocess
    me = os.path.abspath(__file__)
    bad_port = subprocess.run([sys.executable, me, 'not-a-port'], capture_output=True,
                              text=True, errors='replace')
    chk('bad-port-exits-2', bad_port.returncode == 2, bad_port.returncode)
    chk('bad-port-message', 'listen_port must be a number' in bad_port.stdout,
        (bad_port.stdout or '')[:80])
    helped = subprocess.run([sys.executable, me, '--help'], capture_output=True,
                            text=True, errors='replace')
    chk('help-exits-0', helped.returncode == 0, helped.returncode)
    for needle in ('CONNECT tunnelling', 'adb reverse', '--self-test'):
        chk('help-mentions-%s' % needle.replace(' ', '-'), needle in helped.stdout)

    fails = [(n, d) for n, ok, d in checks if not ok]
    print(json.dumps({'ok': not fails, 'checks': len(checks), 'tool': 'usb_net_proxy.py',
                      'failures': [n for n, _ in fails]}, ensure_ascii=False))
    for n, d in fails:
        print('FAIL %s: %s' % (n, d), file=sys.stderr)
    return 0 if not fails else 1


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', PORT))
    srv.listen(128)
    log('proxy listening on 0.0.0.0:%d' % PORT)
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()


if __name__ == '__main__':
    if SELF_TEST:
        sys.exit(self_test())
    main()
