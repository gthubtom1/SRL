#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Quoting-safe ADB helper.

Why this exists: if you build device commands inside a host shell, the host expands
`$`, `|`, `>`, and quotes *before* adb sees them. Symptoms are host-side errors that
look like device failures -- "Could not find a part of the path", "no closing quote",
"Missing type name after '['", unexpanded variables. Windows PowerShell is the worst
offender (it also eats `$var:`, `[^"...`, `$(...)`).

Calling adb from Python with an argument list avoids all of it.

Configuration (first match wins):
  1. CLI flags: --serial / --adb
  2. env: ADB_SERIAL / ADB_PATH
  3. defaults below

Usage
-----
  python devsh.py sh  "pm list packages | grep myapp"      # as the shell user
  python devsh.py su  "pm grant <pkg> android.permission.X"
  python devsh.py sh  "dumpsys window | grep mCurrentFocus"
  python devsh.py pull /data/local/tmp/x.apk ./x.apk
  python devsh.py push ./x.apk /data/local/tmp/x.apk
  python devsh.py dev                                       # list devices
  python devsh.py --self-test                               # offline self-check (JSON, rc 0/1)

`su` wraps the command in `su -c "..."`; internal double quotes are escaped.
"""
import argparse
import io
import json
import os
import subprocess
import sys
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    import device_shell as _shell          # same directory as this script
except ImportError:                        # run from the repository root instead
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import device_shell as _shell

DEFAULT_ADB = 'adb'
DEFAULT_SERIAL = None


def resolve():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument('--adb')
    ap.add_argument('--serial')
    known, _ = ap.parse_known_args()
    adb = known.adb or os.environ.get('ADB_PATH') or DEFAULT_ADB
    serial = known.serial or os.environ.get('ADB_SERIAL') or DEFAULT_SERIAL
    return adb, serial


def run(adb, serial, args, timeout=300):
    cmd = [adb]
    if serial:
        cmd += ['-s', serial]
    cmd += args
    r = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=timeout)
    out = r.stdout or ''
    if (r.stderr or '').strip():
        out += '\n[stderr]\n' + r.stderr
    return r.returncode, out


def strip_adb_flags(argv):
    """Drop `--adb[=X]` / `--serial[=X]` from the mode argv, keeping everything else."""
    cleaned = []
    skip = False
    for a in argv:
        if skip:
            skip = False
            continue
        if a in ('--adb', '--serial'):
            skip = True
            continue
        if a.startswith('--adb=') or a.startswith('--serial='):
            continue
        cleaned.append(a)
    return cleaned


def self_test():
    """Offline self-test: no adb is executed and no device is needed.

    devsh exists because a value that reaches the DEVICE SHELL unquoted is a bug, so the
    assertions are on the exact strings the device would receive (`su -c '<cmd>'`), on
    the argv cleaning that decides what is a mode and what is a flag, and on the CLI's
    exit codes (2 = usage, never a traceback and never a silent adb call).
    """
    import contextlib

    def run_main(*argv):
        buf = io.StringIO()
        saved = sys.argv
        sys.argv = ['devsh.py'] + list(argv)
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                return main(), buf.getvalue()
        finally:
            sys.argv = saved

    checks = 0
    try:
        assert _shell.su_wrap(['id']) == "su -c 'id'", _shell.su_wrap(['id'])
        assert _shell.su_wrap(['head', '-c', '6000', '/data/local/tmp/x']) == \
            "su -c 'head -c 6000 /data/local/tmp/x'", \
            _shell.su_wrap(['head', '-c', '6000', '/data/local/tmp/x'])
        assert _shell.validate_device_path('/data/local/tmp/x') == '/data/local/tmp/x'
        try:
            _shell.validate_device_path('/sdcard/a b')
        except _shell.Refused:
            pass
        else:
            raise AssertionError('a path with a space was accepted for the device shell')
        checks += 1

        assert strip_adb_flags(['--adb', '/opt/adb', '--serial', 'SER', 'sh', 'id']) == \
            ['sh', 'id'], strip_adb_flags(['--adb', '/opt/adb', '--serial', 'SER',
                                           'sh', 'id'])
        assert strip_adb_flags(['--adb=/x/adb', 'sh', 'id']) == ['sh', 'id']
        assert strip_adb_flags(['sh', 'id', '--serial=SER']) == ['sh', 'id']
        assert strip_adb_flags(['suf', '/data/x', '7000']) == ['suf', '/data/x', '7000']
        checks += 1

        saved_argv, saved_env = sys.argv, dict(os.environ)
        try:
            sys.argv = ['devsh.py', '--adb', '/opt/adb', '--serial', 'SER', 'sh', 'id']
            os.environ.pop('ADB_PATH', None)
            os.environ.pop('ADB_SERIAL', None)
            assert resolve() == ('/opt/adb', 'SER'), resolve()

            sys.argv = ['devsh.py', 'sh', 'id']
            os.environ['ADB_PATH'] = '/env/adb'
            os.environ['ADB_SERIAL'] = 'ENVSER'
            assert resolve() == ('/env/adb', 'ENVSER'), resolve()

            # flags beat the environment
            sys.argv = ['devsh.py', '--adb', '/cli/adb', 'sh', 'id']
            assert resolve() == ('/cli/adb', 'ENVSER'), resolve()

            sys.argv = ['devsh.py', '--adb=/cli/adb', '--serial=CLISER', 'sh', 'id']
            assert resolve() == ('/cli/adb', 'CLISER'), resolve()
        finally:
            sys.argv = saved_argv
            os.environ.clear()
            os.environ.update(saved_env)
        checks += 1

        rc, text = run_main()
        assert rc == 2, 'no mode must be a usage error (2), got %r' % (rc,)
        assert 'python devsh.py' in text, text
        rc, _t = run_main('--help')
        assert rc == 0, rc
        rc, _t = run_main('sh')          # fewer than two arguments: usage
        assert rc == 2, rc
        rc, _t = run_main('bogus-mode', 'x')
        assert rc == 2, rc
        checks += 1
    except Exception as exc:          # a failed assertion IS the signal: report, rc=1
        print(json.dumps({"ok": False, "checks": checks, "tool": "devsh.py",
                          "reason": "%s: %s" % (type(exc).__name__, exc)},
                         ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, "checks": checks, "tool": "devsh.py"},
                     ensure_ascii=False))
    return 0


def main():
    if any(a == '--self-test' for a in sys.argv[1:]):
        return self_test()

    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print((__doc__ or "").strip() or "usage: devsh.py ...")
        return 0
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    adb, serial = resolve()
    argv = strip_adb_flags(sys.argv[1:])
    if len(argv) < 2 and argv and argv[0] not in ('dev',):
        print(__doc__)
        return 2

    mode = argv[0]

    try:
        if mode == 'dev':
            rc, out = run(adb, None, ['devices', '-l'])
        elif mode in ('sh', 'shell'):
            rc, out = run(adb, serial, ['shell', argv[1]])
        elif mode == 'su':
            # POSIX single-quote quoting, via the shared module. The previous form escaped only double
            # quotes, so `;`, `$( )` and backticks still reached the device shell as syntax -- and this
            # helper sits directly under an agent's hands. See scripts/device_shell.py.
            rc, out = run(adb, serial, ['shell', _shell.su_wrap([argv[1]])])
        elif mode == 'suf':  # read a device text file
            # `suf` interpolates a path and a byte count into a device command, so both are validated:
            # a path with a space or a metacharacter is refused here rather than mangled on the device.
            path = _shell.validate_device_path(argv[1])
            size = argv[2] if len(argv) > 2 else '6000'
            if not size.isdigit():
                print('suf: size must be a decimal byte count, got %r' % size, file=sys.stderr)
                return 2
            rc, out = run(adb, serial, ['shell', _shell.su_wrap(['head', '-c', size, path])])
        elif mode == 'pull':
            rc, out = run(adb, serial, ['pull', argv[1], argv[2]])
        elif mode == 'push':
            rc, out = run(adb, serial, ['push', argv[1], argv[2]])
        else:
            print(__doc__)
            return 2
    except _shell.Refused as exc:
        # A malformed device value is a usage error (2): distinguishable by a caller from "the device
        # said no" (1) and from a defect in this tool (4). Never a traceback.
        print('refused: %s' % exc, file=sys.stderr)
        print('RESULT=refused')
        return 2

    sys.stdout.write(out)
    return 0 if rc == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
