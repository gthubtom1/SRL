#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Install an APK and run a launch health check, extracting the signals that matter.

Automates the verification loop from references/verification.md:
  install -> clear logcat -> launch -> sample pid twice -> scan for fatal signatures
  -> capture a screenshot.

Why the pid is sampled TWICE: a crash loop shows a live pid at any single instant.
The second sample catches it.

Usage
-----
  python install_test.py --apk out/app.apk --pkg com.example.app --activity .MainActivity
  python install_test.py --apk out/app.apk --pkg com.example.app --activity .MainActivity \
      --shots out/shot.png --uninstall-first --grant READ_PHONE_STATE --grant ACCESS_FINE_LOCATION

Useful flags
------------
  --uninstall-first   wipe app data (needed when the signing key changed, and the only
                      way to test "does this survive a fresh install")
  --keep-data         reinstall over the existing app (requires the same signing key;
                      preserves login state -- valuable when the feature under test
                      needs auth)
  --grant NAME        runtime permission to grant (repeatable). Must be granted as
                      root: the shell user gets SecurityException.
  --wait N            seconds between the two pid samples (default 18)

Exit code is 0 only when the app launched AND both pid samples agree.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

FATAL = re.compile(
    r'FATAL EXCEPTION|VerifyError|IncompatibleClassChangeError|'
    r'ClassNotFoundException|NoClassDefFoundError|LinkageError|'
    r'Failure starting process|uncaughtException',
    re.I)


def adb(args, serial=None, timeout=600):
    cmd = ['adb']
    if serial:
        cmd += ['-s', serial]
    cmd += args
    r = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=timeout)
    return (r.stdout or '') + (('\n[stderr]\n' + r.stderr) if (r.stderr or '').strip() else '')


def sh(cmd, serial=None):
    return adb(['shell', cmd], serial)


def su(cmd, serial=None):
    return adb(['shell', 'su -c "%s"' % cmd.replace('"', '\\"')], serial)


def self_test():
    """Offline self-test: adb is replaced by a stub, so no device and no APK.

    The pass/fail rule is the point of this script, so it is asserted in both
    directions: stable pid + clean logcat -> 0, a dead or crash-looping app -> 1.
    """
    import contextlib
    import io
    import types

    checks = 0
    try:
        def run_with_stub(argv, pids=('4242', '4242'), logcat=''):
            calls = []
            seq = list(pids)
            real = (subprocess.run, time.sleep)

            def fake_run(cmd, **kw):
                calls.append(list(cmd))
                joined = ' '.join(cmd)
                if 'pidof' in joined:
                    return types.SimpleNamespace(
                        stdout=(seq.pop(0) if seq else '') + '\n', stderr='')
                if 'logcat' in cmd and '-d' in cmd:
                    return types.SimpleNamespace(stdout=logcat, stderr='')
                return types.SimpleNamespace(stdout='', stderr='')

            old_argv = sys.argv
            sys.argv = argv
            out = io.StringIO()
            try:
                subprocess.run = fake_run
                time.sleep = lambda _s: None
                with contextlib.redirect_stdout(out):
                    rc = main()
            finally:
                subprocess.run, time.sleep = real
                sys.argv = old_argv
            return rc, out.getvalue(), calls

        base = ['install_test.py', '--apk', 'out/app.apk', '--pkg', 'com.example.app',
                '--activity', '.MainActivity', '--wait', '1']

        rc, text, calls = run_with_stub(base)
        assert rc == 0, rc
        assert '[result] OK' in text, text
        assert '[6] pid @+6s : 4242' in text and '[7] pid @+7s : 4242' in text, text
        checks += 1

        # the install path is asserted exactly: wrong flags here break --keep-data
        assert ['adb', 'push', 'out/app.apk', '/data/local/tmp/_skill_stage.apk'] in calls, calls
        assert ['adb', 'shell', 'su -c "pm install -r -t -d /data/local/tmp/_skill_stage.apk"'] \
            in calls, calls
        assert ['adb', 'shell', 'am start -n com.example.app/.MainActivity'] in calls, calls
        checks += 1

        # --grant normalises a bare permission name and grants it as root
        rc, _text, calls = run_with_stub(base + ['--grant', 'READ_PHONE_STATE'])
        assert rc == 0, rc
        assert ['adb', 'shell',
                'su -c "pm grant com.example.app android.permission.READ_PHONE_STATE"'] \
            in calls, calls
        checks += 1

        # a crash loop shows a live pid once: the second sample must catch it
        rc, text, _calls = run_with_stub(base, pids=('4242', ''))
        assert rc == 1, rc
        assert '[result] CHECK' in text, text
        checks += 1

        # fatal signatures are matched, and reported
        fatal = '01-01 00:00:00.000 E/AndroidRuntime: FATAL EXCEPTION: main'
        assert FATAL.search(fatal) is not None
        assert FATAL.search('I/ActivityManager: Start proc com.example.app') is None
        rc, text, _calls = run_with_stub(base, logcat=fatal + '\n')
        assert rc == 1, rc
        assert 'FATAL EXCEPTION: main' in text, text
        checks += 1

        print(json.dumps({'ok': True, 'checks': checks, 'tool': 'install_test.py'}))
        return 0
    except Exception as exc:
        print(json.dumps({'ok': False, 'checks': checks, 'tool': 'install_test.py',
                          'reason': '%s: %s' % (type(exc).__name__, exc)}))
        return 1


def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument('--apk', required=True)
    ap.add_argument('--pkg', required=True)
    ap.add_argument('--activity', required=True, help='e.g. .MainActivity or fully qualified')
    ap.add_argument('--serial')
    ap.add_argument('--uninstall-first', action='store_true')
    ap.add_argument('--keep-data', action='store_true')
    ap.add_argument('--grant', action='append', default=[])
    ap.add_argument('--wait', type=int, default=18)
    ap.add_argument('--shots')
    a = ap.parse_args()

    s = a.serial
    print('[0] devices:'); print(adb(['devices', '-l']))

    if a.uninstall_first:
        print('[1] uninstall'); print(su('am force-stop %s; pm uninstall %s' % (a.pkg, a.pkg), s))
    stage = '/data/local/tmp/_skill_stage.apk'
    print('[2] push'); print(adb(['push', a.apk, stage], s))
    print('[3] install'); print(su('pm install -r -t -d %s' % stage, s))

    for perm in a.grant:
        p = perm if perm.startswith('android.permission.') else 'android.permission.' + perm
        su('pm grant %s %s' % (a.pkg, p), s)

    print('[4] clear logcat'); adb(['logcat', '-c'], s)
    comp = '%s/%s' % (a.pkg, a.activity if a.activity.startswith('.') or '.' in a.activity
                      else a.activity)
    print('[5] launch'); print(sh('am start -n %s' % comp, s))

    time.sleep(6)
    p1 = sh('pidof %s' % a.pkg, s).strip()
    print('[6] pid @+6s : %s' % (p1 or '(dead)'))
    time.sleep(a.wait)
    p2 = sh('pidof %s' % a.pkg, s).strip()
    print('[7] pid @+%ds : %s' % (6 + a.wait, p2 or '(dead)'))

    print('[8] focus  : %s' % sh('dumpsys window | grep mCurrentFocus', s).strip())

    if a.shots:
        su('screencap -p /sdcard/_skill_shot.png', s)
        print(adb(['pull', '/sdcard/_skill_shot.png', a.shots], s))

    print('[9] fatal signatures:')
    log = adb(['logcat', '-d', '-v', 'brief'], s)
    hits = [ln for ln in log.splitlines() if FATAL.search(ln)]
    if hits:
        for ln in hits[-25:]:
            print('   ', ln)
    else:
        print('    none')

    ok = bool(p1) and p1 == p2 and not hits
    print()
    print('[result] %s' % ('OK  (launched, stable, no fatal signatures)'
                           if ok else 'CHECK (see above)'))
    print('[note] stability is NOT proof the patch worked. Exercise the changed '
          'feature and its neighbours -- see references/verification.md.')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
