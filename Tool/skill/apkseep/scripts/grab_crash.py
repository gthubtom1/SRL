#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Capture a crash stack when the app's crash-reporter SDK is hiding it.

Problem this solves
-------------------
Many apps install a global uncaught-exception handler (友盟/UCrash, Bugly, Firebase
Crashlytics in some configs). The Java stack then never reaches `logcat` -- you only
see something like:

    W/UCrash.Java: uncaughtException time: <ts>

...and the process dies. Without a stack you are guessing.

Three ways to get it, in order of reliability:
  1. Frida: hook Thread.setDefaultUncaughtExceptionHandler (use references/dynamic-frida.md)
  2. Race the reporter's own log file (this script): it writes a file under the app's
     data dir, then zips, uploads, and deletes it. Poll fast and copy on sight.
  3. Use a build with the reporter disabled.

Usage
-----
  python grab_crash.py --pkg com.example.app --activity .MainActivity
  python grab_crash.py --pkg com.example.app --activity .MainActivity \
      --scan-dir /data/data/com.example.app --wait 25

Notes
-----
* `--scan-dir` defaults to /data/data/<pkg>; the script searches a few levels deep for
  newly appeared *.log / *.txt / *.stacktrace files, so you do not have to know which
  SDK is installed.
* The watcher loop self-terminates after ~80 s, so nothing is left running on device.
* Requires root (the app's data dir is private).
"""
import argparse
import json
import subprocess
import sys
import time

CAPTURE = '/data/local/tmp/_skill_crash_capture.log'


def adb(args, serial=None, timeout=180):
    cmd = ['adb']
    if serial:
        cmd += ['-s', serial]
    cmd += args
    r = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=timeout)
    return (r.stdout or '') + (('\n[stderr]\n' + r.stderr) if (r.stderr or '').strip() else '')


def su(cmd, serial=None):
    return adb(['shell', 'su -c "%s"' % cmd.replace('"', '\\"')], serial)


def self_test():
    """Offline self-test: adb is replaced by a stub, so no device and no root.

    What is asserted is the thing that breaks silently on a real device: the exact
    command lines (serial, force-stop, the on-device watcher's scan dir) and the
    distinction between "captured a file" and "captured nothing".
    """
    import contextlib
    import io
    import types

    checks = 0
    try:
        def run_with_stub(argv, captured='java.lang.RuntimeException: boom\n'):
            calls, popens = [], []
            real = (subprocess.run, subprocess.Popen, time.sleep)

            def fake_run(cmd, **kw):
                calls.append(list(cmd))
                joined = ' '.join(cmd)
                if 'pidof' in joined:
                    return types.SimpleNamespace(stdout='4242\n', stderr='')
                if 'head -c' in joined:
                    return types.SimpleNamespace(stdout=captured, stderr='')
                return types.SimpleNamespace(stdout='', stderr='')

            class FakePopen:
                def __init__(self, cmd, **kw):
                    popens.append(list(cmd))

            old_argv = sys.argv
            sys.argv = argv
            out = io.StringIO()
            try:
                subprocess.run, subprocess.Popen = fake_run, FakePopen
                time.sleep = lambda _s: None
                with contextlib.redirect_stdout(out):
                    rc = main()
            finally:
                subprocess.run, subprocess.Popen, time.sleep = real
                sys.argv = old_argv
            return rc, out.getvalue(), calls, popens

        rc, text, calls, popens = run_with_stub(
            ['grab_crash.py', '--pkg', 'com.example.app', '--activity', '.Main',
             '--serial', 'SER1', '--wait', '1'])
        assert rc == 0, rc
        checks += 1

        # 1) the serial is carried into every adb call, and the app is force-stopped first
        assert calls[0] == ['adb', '-s', 'SER1', 'shell',
                            'su -c "am force-stop com.example.app"'], calls[0]
        assert all(c[0] == 'adb' and c[1:3] == ['-s', 'SER1'] for c in calls), calls
        assert any('rm -f /data/local/tmp/_skill_crash_capture.log' in c[-1] for c in calls)
        assert any('am start -n com.example.app/.Main' in c[-1] for c in calls), calls
        checks += 1

        # 2) the on-device watcher covers the default scan dir and the capture path
        assert len(popens) == 1, popens
        watch = ' '.join(popens[0])
        assert '/data/data/com.example.app' in watch, watch
        assert 'find' in watch and 'cp -f' in watch and '-newermt' in watch, watch
        assert '/data/local/tmp/_skill_crash_capture.log' in watch, watch
        checks += 1

        # 3) the report carries the pid and the captured text
        assert '[grab] pid: 4242' in text, text
        assert 'java.lang.RuntimeException: boom' in text, text
        checks += 1

        # 4) --scan-dir overrides the default, and an empty capture says so
        rc, text, calls, popens = run_with_stub(
            ['grab_crash.py', '--pkg', 'com.example.app', '--activity', '.Main',
             '--serial', 'SER2', '--scan-dir', '/sdcard/logs', '--wait', '1'],
            captured='')
        assert rc == 0, rc
        watch = ' '.join(popens[0])
        assert '/sdcard/logs' in watch and '/data/data/com.example.app' not in watch, watch
        assert '(nothing captured)' in text, text
        assert 'Frida approach' in text, text
        checks += 1

        print(json.dumps({'ok': True, 'checks': checks, 'tool': 'grab_crash.py'}))
        return 0
    except Exception as exc:
        print(json.dumps({'ok': False, 'checks': checks, 'tool': 'grab_crash.py',
                          'reason': '%s: %s' % (type(exc).__name__, exc)}))
        return 1


def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument('--pkg', required=True)
    ap.add_argument('--activity', required=True)
    ap.add_argument('--serial')
    ap.add_argument('--scan-dir')
    ap.add_argument('--wait', type=int, default=25)
    a = ap.parse_args()

    scan = a.scan_dir or ('/data/data/%s' % a.pkg)
    s = a.serial

    # On-device watcher: copy any *.log/*.txt that appears under the app dir.
    watch = (
        "i=0; while [ $i -lt 400 ]; do "
        "  find {d} -maxdepth 5 -type f \\( -name '*.log' -o -name '*.txt' -o -name '*.stacktrace' "
        "     -o -name '*.crash' \\) -newermt '-3 minutes' -exec cp -f {{}} {c} \\; 2>/dev/null; "
        "  i=$((i+1)); sleep 0.2; "
        "done"
    ).format(d=scan, c=CAPTURE)

    su('am force-stop %s' % a.pkg, s)
    su('rm -f %s' % CAPTURE, s)
    print('[grab] arming on-device watcher over %s' % scan)
    subprocess.Popen(['adb'] + (['-s', s] if s else []) +
                     ['shell', "su -c '%s'" % watch],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)

    print('[grab] starting app')
    print(adb(['shell', 'am start -n %s/%s' % (a.pkg, a.activity)], s))
    time.sleep(a.wait)

    pid = adb(['shell', 'pidof %s' % a.pkg], s).strip()
    print('[grab] pid: %s' % (pid or '(dead -> likely crashed)'))

    print('[grab] ==== captured file ====')
    out = su('head -c 6000 %s' % CAPTURE, s)
    if 'No such file' in out or not out.strip():
        print('(nothing captured)')
        print('[hint] the reporter may have deleted it faster than 0.2 s, or it writes '
              'outside --scan-dir. Use the Frida approach instead.')
    else:
        print(out)
    return 0


if __name__ == '__main__':
    sys.exit(main())
