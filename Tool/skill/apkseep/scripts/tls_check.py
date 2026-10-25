#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TLS certificate health check for one or more hosts.

WHY THIS EXISTS
---------------
When a repacked app's login/registration fails with
`Chain validation failed` / `SSLHandshakeException`, the cause is often the
*server* certificate, not your patch. This script answers that question
independently of the app, so you can rule the server side in or out **before**
touching the APK. It is step 2 of the three-step TLS triage:
  1. take the real request URL / host out of the runtime probe (see frida_probe.js)
  2. verify that host's certificate out-of-band  <-- this script
  3. compare with another host of the same app (usually one of them is fine),
     which proves the failure is host-specific and not your clock/network

WHY IT STILL PRINTS THE CERTIFICATE WHEN VERIFICATION FAILS
-----------------------------------------------------------
`ssl.SSLSocket.getpeercert()` returns an empty dict whenever the handshake was
not validated, and `verification_mode=CERT_NONE` never validates. So on failure
we re-read the peer certificate in DER form and decode it locally. That is what
turns "it failed" into "it failed because notAfter is 39 days in the past".

WHAT IT REPORTS
---------------
Per host: strict verification result, protocol/cipher, subject, issuer,
notBefore, notAfter, days remaining, and a classification of the failure:
  EXPIRED            certificate has expired
  NOT-YET-VALID      certificate is not valid yet
  HOSTNAME-MISMATCH  chain is fine, the name does not match
  UNTRUSTED-CA       self-signed, or issuer not in the trust store
  CHAIN-BROKEN       bad signature / invalid CA / incomplete chain
  REVOKED            revoked by the issuer
  OTHER              anything else, with the raw OpenSSL message

Exit code: 0 if every host verified strictly, 2 if any host failed.
Pure standard library, Python 3.9+.

USAGE
-----
  python tls_check.py api.example.com
  python tls_check.py api.example.com cdn.example.com
  python tls_check.py api.example.com --port 8443
  python tls_check.py 203.0.113.10 --sni api.example.com   # IP + real SNI name
  python tls_check.py api.example.com --json                # machine-readable
"""
import argparse
import hashlib
import json
import os
import socket
import ssl
import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
import tempfile
from datetime import datetime, timezone

DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10

# OpenSSL X509_V_ERR_* -> (classification, human readable)
VERIFY_CODE_CLASS = {
    7: ('CHAIN-BROKEN', 'certificate signature failure'),
    9: ('NOT-YET-VALID', 'certificate is not yet valid'),
    10: ('EXPIRED', 'certificate has expired'),
    18: ('UNTRUSTED-CA', 'self-signed certificate'),
    19: ('UNTRUSTED-CA', 'self-signed certificate in certificate chain'),
    20: ('UNTRUSTED-CA', 'unable to get local issuer certificate'),
    21: ('UNTRUSTED-CA', 'unable to verify the first certificate'),
    24: ('CHAIN-BROKEN', 'invalid CA certificate'),
    27: ('REVOKED', 'certificate revoked'),
    62: ('HOSTNAME-MISMATCH', 'hostname mismatch'),
}

# What a failure means for the reverse-engineering workflow.
CLASS_ACTION = {
    'EXPIRED': 'server-side problem: the certificate chain is not trustworthy '
               'any more. Re-signing the APK cannot fix this, and a client patch '
               'is the only way to keep the app usable.',
    'NOT-YET-VALID': 'either the server is misconfigured or the device clock is '
                     'wrong. Check the device date before blaming the app.',
    'HOSTNAME-MISMATCH': 'the chain is valid but the connection is using the '
                         'wrong name. Check for a proxy, a hosts entry, or a '
                         'hardcoded IP + wrong SNI.',
    'UNTRUSTED-CA': 'the presented chain is not rooted in the system trust store. '
                    'Expected for a MITM/proxy setup; suspicious for a public API.',
    'CHAIN-BROKEN': 'the server sent an incomplete or internally inconsistent '
                    'chain. Often a missing intermediate certificate.',
    'REVOKED': 'the certificate was revoked by its issuer.',
    'OTHER': 'read the raw OpenSSL message below; this is not one of the '
             'well-known failure classes.',
}


def fmt_name(parts):
    """Flatten ((('commonName','x'),),) into 'commonName=x'."""
    if not parts:
        return None
    flat = []
    for rdn in parts:
        for key, val in rdn:
            flat.append('%s=%s' % (key, val))
    return ', '.join(flat)


def parse_asn1_time(text):
    """'Nov 29 23:59:59 2026 GMT' -> aware UTC datetime (or None)."""
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.endswith(' GMT') or cleaned.endswith(' UTC'):
        cleaned = cleaned[:-4].rstrip()
    try:
        return datetime.strptime(cleaned, '%b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def decode_der(der):
    """Decode a DER certificate without ever verifying it.

    Uses the CPython private helper that backs `getpeercert()`; if it is not
    available we still return what we can (length + fingerprint), because a
    partially decoded certificate beats no certificate at all.
    """
    info = {'der_bytes': len(der),
            'sha256': hashlib.sha256(der).hexdigest(),
            'sha1': hashlib.sha1(der).hexdigest()}
    helper = getattr(getattr(ssl, '_ssl', None), '_test_decode_cert', None)
    if helper is None:
        return info
    path = None
    try:
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as fh:
            path = fh.name
            fh.write(pem)
        info.update(helper(path))
    except Exception:
        pass
    finally:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass
    return info


def fetch_peer_cert(host, port, sni, timeout):
    """Read the peer certificate even when the chain cannot be validated."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
    return decode_der(der) if der else {}


def strict_connect(host, port, sni, timeout):
    """Full strict verification: system trust store + hostname match."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=sni) as tls:
            return {
                'cert': tls.getpeercert() or {},
                'protocol': tls.version(),
                'cipher': (tls.cipher() or ('', '', ''))[0],
            }


def check_host(host, port, sni, timeout):
    """Return one result dict; never raises for network/TLS problems."""
    res = {
        'host': host,
        'port': port,
        'sni': sni,
        'ok': False,
        'classification': None,
        'reason': None,
        'verify_code': None,
        'protocol': None,
        'cipher': None,
        'subject': None,
        'issuer': None,
        'not_before': None,
        'not_after': None,
        'days_remaining': None,
        'fingerprint_sha256': None,
        'action': None,
        'error': None,
    }

    try:
        hit = strict_connect(host, port, sni, timeout)
    except ssl.SSLCertVerificationError as exc:
        code = getattr(exc, 'verify_code', None)
        cls, human = VERIFY_CODE_CLASS.get(code, ('OTHER', getattr(exc, 'verify_message', str(exc))))
        res['classification'] = cls
        res['reason'] = human
        res['verify_code'] = code
        res['action'] = CLASS_ACTION.get(cls)
        res['error'] = '%s: %s' % (type(exc).__name__, exc)
    except (ssl.SSLError, socket.error, OSError) as exc:
        res['classification'] = 'OTHER'
        res['reason'] = 'connection or handshake failed before certificate validation'
        res['action'] = CLASS_ACTION['OTHER']
        res['error'] = '%s: %s' % (type(exc).__name__, exc)
        return res
    else:
        cert = hit['cert']
        res.update({'ok': True, 'protocol': hit['protocol'], 'cipher': hit['cipher'],
                    'subject': fmt_name(cert.get('subject')),
                    'issuer': fmt_name(cert.get('issuer')),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter')})
        res['days_remaining'] = days_left(res['not_after'])
        return res

    # Verification failed: still try to show the real certificate.
    try:
        cert = fetch_peer_cert(host, port, sni, timeout)
    except Exception as exc:
        res['error'] = (res['error'] or '') + ' | peek failed: %s' % exc
        return res

    res.update({'subject': fmt_name(cert.get('subject')),
                'issuer': fmt_name(cert.get('issuer')),
                'not_before': cert.get('notBefore'),
                'not_after': cert.get('notAfter'),
                'fingerprint_sha256': cert.get('sha256')})
    res['days_remaining'] = days_left(res['not_after'])
    return res


def days_left(not_after):
    dt = parse_asn1_time(not_after)
    if dt is None:
        return None
    return (dt - datetime.now(timezone.utc)).days


def report(res, out=sys.stdout):
    w = out.write
    w('== %s:%d%s\n' % (res['host'], res['port'],
                        '' if res['sni'] == res['host'] else '  (SNI: %s)' % res['sni']))
    if res['ok']:
        w('   status         : OK (strict verification passed)\n')
    else:
        w('   status         : FAIL - %s\n' % res['classification'])
        w('   reason         : %s\n' % res['reason'])
        if res['verify_code'] is not None:
            w('   verify_code    : %d\n' % res['verify_code'])
    if res['protocol']:
        w('   protocol       : %s  cipher: %s\n' % (res['protocol'], res['cipher']))
    w('   subject        : %s\n' % (res['subject'] or '<undecoded>'))
    w('   issuer         : %s\n' % (res['issuer'] or '<undecoded>'))
    w('   notBefore      : %s\n' % (res['not_before'] or '<unknown>'))
    w('   notAfter       : %s\n' % (res['not_after'] or '<unknown>'))
    days = res['days_remaining']
    if days is not None:
        if days < 0:
            w('   validity       : EXPIRED %d days ago\n' % (-days))
        else:
            w('   days remaining : %d\n' % days)
    if res['fingerprint_sha256']:
        w('   sha256         : %s\n' % res['fingerprint_sha256'])
    if res['action'] and not res['ok']:
        w('   action         : %s\n' % res['action'])
    if res['error']:
        w('   raw error      : %s\n' % res['error'])
    w('\n')


def self_test():
    """Offline self-test: hand-written dates/report rows, no socket is opened.

    check_host is exercised with strict_connect/fetch_peer_cert stubbed, which is
    exactly the boundary that turns an OpenSSL verify_code into a classification.
    """
    import contextlib
    import io
    import json

    checks = []

    def chk(name, cond, detail=''):
        checks.append((name, bool(cond), detail))

    # 1) ASN.1 time parsing and the days-remaining arithmetic
    dt = parse_asn1_time('Nov 29 23:59:59 2026 GMT')
    chk('asn1-gmt', dt == datetime(2026, 11, 29, 23, 59, 59, tzinfo=timezone.utc), dt)
    chk('asn1-utc', parse_asn1_time('Jan  1 00:00:00 2030 UTC') ==
        datetime(2030, 1, 1, tzinfo=timezone.utc))
    chk('asn1-garbage-none', parse_asn1_time('not a date') is None)
    chk('asn1-empty-none', parse_asn1_time(None) is None and parse_asn1_time('') is None)
    chk('days-left-future-positive', (days_left('Nov 29 23:59:59 2999 GMT') or 0) > 300000,
        days_left('Nov 29 23:59:59 2999 GMT'))
    chk('days-left-expired-negative', (days_left('Jan  1 00:00:00 2020 GMT') or 0) < 0,
        days_left('Jan  1 00:00:00 2020 GMT'))
    chk('days-left-unknown-none', days_left(None) is None and days_left('x') is None)

    # 2) distinguished names are flattened, not printed as tuples
    chk('fmt-name-flat', fmt_name(((('commonName', 'api.example.com'),),
                                   (('organizationName', 'Example'),))) ==
        'commonName=api.example.com, organizationName=Example', fmt_name(
            ((('commonName', 'api.example.com'),), (('organizationName', 'Example'),))))
    chk('fmt-name-empty', fmt_name(None) is None and fmt_name(()) is None)

    # 3) the OpenSSL code -> classification table, and that every class says what to do
    chk('verify-code-expired', VERIFY_CODE_CLASS[10][0] == 'EXPIRED', VERIFY_CODE_CLASS[10])
    chk('verify-code-hostname', VERIFY_CODE_CLASS[62][0] == 'HOSTNAME-MISMATCH')
    chk('verify-code-self-signed-is-untrusted', VERIFY_CODE_CLASS[18][0] == 'UNTRUSTED-CA')
    classes = {cls for cls, _msg in VERIFY_CODE_CLASS.values()}
    chk('action-for-every-class', classes <= set(CLASS_ACTION), sorted(classes))
    chk('action-expired-mentions-server', 'server-side' in CLASS_ACTION['EXPIRED'],
        CLASS_ACTION['EXPIRED'])

    # 4) check_host over a stubbed handshake: expired, verified, and unreachable
    global strict_connect, fetch_peer_cert
    real_strict, real_peer = strict_connect, fetch_peer_cert
    try:
        class FakeVerify(ssl.SSLCertVerificationError):
            pass

        def make_verify_error(code):
            exc = FakeVerify('certificate verify failed')
            exc.verify_code = code
            exc.verify_message = 'expired certificate'
            return exc

        def raise_strict(code):
            def _f(host, port, sni, timeout):
                raise make_verify_error(code)
            return _f

        strict_connect = raise_strict(10)
        fetch_peer_cert = lambda host, port, sni, timeout: {
            'subject': ((('commonName', 'api.example.com'),),),
            'issuer': ((('commonName', 'Example CA'),),),
            'notBefore': 'Jan  1 00:00:00 2020 GMT',
            'notAfter': 'Jan  1 00:00:00 2021 GMT',
            'sha256': 'deadbeef' * 8,
            'der_bytes': 10,
        }
        res = check_host('api.example.com', 443, 'api.example.com', 1)
        chk('expired-classification', res['classification'] == 'EXPIRED',
            res['classification'])
        chk('expired-not-ok', res['ok'] is False)
        chk('expired-verify-code', res['verify_code'] == 10, res['verify_code'])
        chk('expired-action-set', bool(res['action']) and
            res['action'] == CLASS_ACTION['EXPIRED'])
        chk('expired-still-shows-cert', res['subject'] == 'commonName=api.example.com',
            res['subject'])
        chk('expired-days-negative', (res['days_remaining'] or 0) < 0, res['days_remaining'])
        chk('expired-fingerprint', res['fingerprint_sha256'] == 'deadbeef' * 8)

        strict_connect = lambda host, port, sni, timeout: {
            'cert': {'subject': ((('commonName', 'api.example.com'),),),
                     'issuer': ((('commonName', 'Example CA'),),),
                     'notBefore': 'Jan  1 00:00:00 2020 GMT',
                     'notAfter': 'Jan  1 00:00:00 2999 GMT'},
            'protocol': 'TLSv1.3',
            'cipher': 'TLS_AES_128_GCM_SHA256',
        }
        ok_res = check_host('api.example.com', 8443, 'api.example.com', 1)
        chk('verified-ok', ok_res['ok'] is True and ok_res['classification'] is None,
            ok_res['classification'])
        chk('verified-protocol', ok_res['protocol'] == 'TLSv1.3', ok_res['protocol'])
        chk('verified-cipher', ok_res['cipher'] == 'TLS_AES_128_GCM_SHA256')
        chk('verified-days-positive', (ok_res['days_remaining'] or 0) > 0)

        def raise_oserror(host, port, sni, timeout):
            raise OSError('connection refused')
        strict_connect = raise_oserror
        err_res = check_host('127.0.0.1', 1, '127.0.0.1', 1)
        chk('unreachable-is-other', err_res['classification'] == 'OTHER' and
            err_res['ok'] is False, err_res['classification'])
        chk('unreachable-keeps-error', 'OSError' in (err_res['error'] or ''),
            err_res['error'])

        # 5) report(): the human row must state the verdict, not only the raw error
        buf = io.StringIO()
        report(res, out=buf)
        text = buf.getvalue()
        chk('report-fail-header', 'status         : FAIL - EXPIRED' in text, text[:120])
        chk('report-shows-notafter', 'notAfter' in text and
            'Jan  1 00:00:00 2021 GMT' in text, text[:200])
        chk('report-shows-fingerprint', 'sha256         : ' + 'deadbeef' * 8 in text)
        chk('report-shows-action', 'action         : ' in text)
        buf = io.StringIO()
        report(ok_res, out=buf)
        chk('report-ok-header', 'status         : OK (strict verification passed)' in
            buf.getvalue(), buf.getvalue()[:80])
    finally:
        strict_connect, fetch_peer_cert = real_strict, real_peer

    # 6) argparse contract: at least one HOST is required, --port/--sni exist
    import subprocess
    me = os.path.abspath(__file__)
    helped = subprocess.run([sys.executable, me, '--help'], capture_output=True,
                            text=True, errors='replace')
    chk('help-rc0', helped.returncode == 0, helped.returncode)
    for flag in ('--port', '--sni', '--timeout', '--json', '--self-test'):
        chk('help-mentions-%s' % flag, flag in helped.stdout)
    no_host = subprocess.run([sys.executable, me], capture_output=True, text=True,
                             errors='replace')
    chk('no-host-exits-2', no_host.returncode == 2, no_host.returncode)
    chk('default-port', DEFAULT_PORT == 443, DEFAULT_PORT)
    chk('default-timeout', DEFAULT_TIMEOUT == 10, DEFAULT_TIMEOUT)

    fails = [(n, d) for n, ok, d in checks if not ok]
    print(json.dumps({'ok': not fails, 'checks': len(checks), 'tool': 'tls_check.py',
                      'failures': [n for n, _ in fails]}, ensure_ascii=False))
    for n, d in fails:
        print('FAIL %s: %s' % (n, d), file=sys.stderr)
    return 0 if not fails else 1


def main():
    ap = argparse.ArgumentParser(
        description='Verify TLS certificates for one or more hosts, strictly, '
                    'and classify any failure (expired / hostname mismatch / untrusted CA).')
    ap.add_argument('hosts', nargs='+', metavar='HOST',
                    help='hostname or IP to check, e.g. api.example.com')
    ap.add_argument('--port', type=int, default=DEFAULT_PORT,
                    help='TCP port (default %d)' % DEFAULT_PORT)
    ap.add_argument('--sni', default=None,
                    help='override the SNI/hostname to validate against; useful when '
                         'HOST is a bare IP, e.g. --sni api.example.com')
    ap.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT,
                    help='connect timeout in seconds (default %d)' % DEFAULT_TIMEOUT)
    ap.add_argument('--json', action='store_true', help='emit JSON instead of a report')
    ap.add_argument('--self-test', action='store_true', dest='self_test',
                    help='run the offline self-test (stubbed handshake, no network)')
    if '--self-test' in sys.argv[1:]:
        return self_test()
    args = ap.parse_args()

    results = []
    for host in args.hosts:
        sni = args.sni or host
        results.append(check_host(host, args.port, sni, args.timeout))

    if args.json:
        json.dump(results, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write('\n')
    else:
        for res in results:
            report(res)

        bad = [r for r in results if not r['ok']]
        good = [r for r in results if r['ok']]
        if len(results) > 1:
            if bad and good:
                print('SUMMARY: %d/%d hosts failed. At least one host on this app '
                      'verifies fine, so the failure is host-specific (server side), '
                      'not a clock/network problem on your side.'
                      % (len(bad), len(results)))
            elif bad:
                print('SUMMARY: every host failed. Suspect the network path, a proxy, '
                      'or the device/host clock before blaming the app.')
            else:
                print('SUMMARY: all %d hosts verified strictly.' % len(results))
        for r in bad:
            print('FAIL %s -> %s' % (r['host'], r['classification']))

    return 0 if all(r['ok'] for r in results) else 2


if __name__ == '__main__':
    sys.exit(main())
