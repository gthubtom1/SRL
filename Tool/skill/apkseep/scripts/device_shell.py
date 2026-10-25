#!/usr/bin/env python3
"""Device-side command construction: quoting, argv, and identifier validation.

Why this module exists: `adb shell` hands your string to a **device shell** (toybox `sh`), and two of
this kit's scripts had different, partially-wrong ideas about that. One escaped only double quotes, so
a `;`, a `$(...)` or a backtick in a value still reached the shell as syntax; the other quoted
correctly but let a malformed value go through to fail later, far from the caller, as a confusing
`grep: no such file` or an empty result. Both are the same defect seen from two sides: **a value that
becomes shell syntax**.

None of this is exotic. The values are package names, component names, paths and sizes that the user
typed or that came out of a manifest, and the failure mode when one is malformed is a wasted round,
not an exploit. The rules are still worth enforcing in one place:

  * **Validate what has a known shape.** An Android package name has a defined grammar; a value that
    does not match it will never select a package, so rejecting it here is strictly better than
    passing it to the device and reading an empty result as "not installed".
  * **Quote what does not.** Paths and free-form text are escaped with POSIX single quotes -- the
    only form that makes `$`, backticks, `;`, `|` and newlines literal to `sh`.
  * **Prefer an argv array over a string** whenever the command is not being run through `su -c`.
    `['adb', 'shell', 'cmd', arg]` sends `arg` as a separate argument; adb quotes it for the device
    shell, and there is no string to get the quoting wrong in.

Usage as a module:

    from device_shell import validate_package, validate_component, sh_quote, su_wrap, adb_shell

    adb_shell(serial, ['dumpsys', 'package', validate_package(pkg)])     # argv, no string
    su_wrap(['cat', validate_device_path(path)])                          # -> one quoted string

Usage as a tool:

    python device_shell.py --check com.example.app
    python device_shell.py --quote "a b;c"
    python device_shell.py --selftest

Exit codes: 0 success / 1 the value was refused / 2 usage error / 4 internal error.
"""
from __future__ import annotations

import argparse
import io
import json
import re
import sys

# Android's own grammar: one or more Java-package segments, each starting with a letter.
PACKAGE_RE = re.compile(r'^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$')
# A component is `pkg/Class`, `pkg/.Class` or `pkg/full.Class.Path`.
COMPONENT_RE = re.compile(
    r'^(?P<pkg>[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+)'
    r'/(?P<cls>\.?[A-Za-z][A-Za-z0-9_.$]*)$')
# Device paths we are willing to interpolate: absolute, no control characters, no shell metachars.
PATH_SAFE_RE = re.compile(r'^/[A-Za-z0-9_./@+:=~-]*$')
# A user id as `pm`/`dumpsys` reports it, or a process id.
PID_RE = re.compile(r'^[1-9][0-9]{0,6}$')


class Refused(ValueError):
    """A value failed validation. Callers translate this into exit code 1, never a traceback."""


def _reject(kind, value, why):
    raise Refused('%s is not valid: %r -- %s' % (kind, value, why))


def validate_package(value):
    """A package name, or refuse. Raises `Refused`."""
    if not isinstance(value, str) or not value:
        _reject('package name', value, 'empty')
    if len(value) > 255:
        _reject('package name', value, 'longer than the platform maximum')
    if not PACKAGE_RE.match(value):
        _reject('package name', value,
                'must be dot-separated segments each starting with a letter (Android grammar)')
    return value


def validate_component(value, default_package=None):
    """`pkg/Class`, `pkg/.Class` or a bare `.Class` when `default_package` is given."""
    if not isinstance(value, str) or not value:
        _reject('component', value, 'empty')
    if '/' not in value and default_package:
        value = '%s/%s' % (validate_package(default_package), value)
    m = COMPONENT_RE.match(value)
    if not m:
        _reject('component', value, 'expected package/Class with a valid package part')
    validate_package(m.group('pkg'))
    if m.group('cls').endswith('.'):
        _reject('component', value, 'class part ends with a dot')
    return value


def validate_device_path(value):
    """An absolute device path with no character that could be shell syntax."""
    if not isinstance(value, str) or not value:
        _reject('device path', value, 'empty')
    if len(value) > 4096:
        _reject('device path', value, 'unreasonably long')
    if not PATH_SAFE_RE.match(value):
        _reject('device path', value,
                'must be absolute and free of whitespace, quotes and shell metacharacters')
    if '..' in value.split('/'):
        _reject('device path', value, 'contains a parent-directory segment')
    return value


def validate_pid(value):
    if isinstance(value, int):
        value = str(value)
    if not isinstance(value, str) or not PID_RE.match(value):
        _reject('pid', value, 'expected a positive decimal pid')
    return value


def sh_quote(value):
    """POSIX single-quote quoting: the one form that makes every metacharacter literal."""
    if not isinstance(value, str):
        value = str(value)
    return "'" + value.replace("'", "'\\''") + "'"


def su_wrap(argv):
    """Wrap already-validated argv into a single `su -c '<cmd>'` string for the device shell."""
    if isinstance(argv, str):
        argv = [argv]
    return 'su -c %s' % sh_quote(' '.join(argv))


def adb_shell(serial=None, argv=(), root=False, quote=True):
    """Build an adb argv list. `root=True` routes through `su -c`; `quote=False` sends argv directly."""
    if isinstance(argv, str):
        argv = [argv]
    base = ['adb'] + (['-s', serial] if serial else []) + ['shell']
    if root:
        return base + [su_wrap(argv)]
    if not quote:
        return base + list(argv)
    return base + [' '.join(sh_quote(a) for a in argv)]


def selftest():
    """Assert the properties this module claims. Returns a list of (name, ok, detail)."""
    cases = []
    payloads = ['a; rm -rf /sdcard/x', 'a$(id)b', 'a`id`b', 'a b', 'a\nb', 'a|b', "a'b"]

    for p in payloads:
        quoted = sh_quote(p)
        # A single-quoted POSIX string must contain no unescaped quote and must round-trip.
        ok = quoted.startswith("'") and quoted.endswith("'")
        inner = quoted[1:-1]
        ok = ok and re.fullmatch(r"[^']*('\\''[^']*)*", inner) is not None
        cases.append(('sh_quote makes %r inert' % p, ok, quoted))

    for good in ('com.example.app', 'a.b.c_d.e1'):
        try:
            validate_package(good)
            cases.append(('accepts valid package %r' % good, True, ''))
        except Refused as exc:
            cases.append(('accepts valid package %r' % good, False, str(exc)))

    for bad in ('', 'nodots', 'com..app', '1com.example', 'com.example.app;rm -rf /',
                'com.example.app$(id)', 'com.example.app`id`'):
        try:
            validate_package(bad)
            cases.append(('refuses invalid package %r' % bad, False, 'it was accepted'))
        except Refused as exc:
            cases.append(('refuses invalid package %r' % bad, True, str(exc)))

    for good in ('/data/local/tmp/x', '/sdcard/Android/data/com.example.app/files'):
        try:
            validate_device_path(good)
            cases.append(('accepts valid path %r' % good, True, ''))
        except Refused as exc:
            cases.append(('accepts valid path %r' % good, False, str(exc)))

    for bad in ('relative/path', '/data/../etc/passwd', '/sdcard/x;id', '/sdcard/x$(id)',
                '/sdcard/a b'):
        try:
            validate_device_path(bad)
            cases.append(('refuses unsafe path %r' % bad, False, 'it was accepted'))
        except Refused as exc:
            cases.append(('refuses unsafe path %r' % bad, True, str(exc)))

    try:
        validate_component('com.example.app/.MainActivity')
        validate_component('.MainActivity', default_package='com.example.app')
        cases.append(('accepts component forms', True, ''))
    except Refused as exc:
        cases.append(('accepts component forms', False, str(exc)))
    for bad in ('com.example.app', 'com.example.app/', 'nodots/Main'):
        try:
            validate_component(bad)
            cases.append(('refuses bad component %r' % bad, False, 'it was accepted'))
        except Refused as exc:
            cases.append(('refuses bad component %r' % bad, True, str(exc)))

    argv = adb_shell('SERIAL', ['dumpsys', 'package', validate_package('com.example.app')])
    # With quote=True the adb argv is `adb -s SERIAL shell "<one string for the device shell>"`, so
    # the package must appear as a *quoted* token inside that string; with quote=False it must be its
    # own argv element. Both forms are asserted -- an assertion that accepts only one of them is how
    # this selftest first failed, by hard-coding a length instead of checking the property.
    quoted_form = argv[-1] if argv[-2] == 'shell' else ''
    direct = adb_shell('SERIAL', ['dumpsys', 'package', 'com.example.app'], quote=False)
    cases.append(('quoted form carries the package as one quoted token',
                  "'com.example.app'" in quoted_form, quoted_form))
    cases.append(('direct form carries the package as one argv element',
                  direct[-1] == 'com.example.app' and direct[-2] == 'package', ' '.join(direct)))
    cases.append(('root form routes through su -c as a single string',
                  adb_shell('SERIAL', ['id'], root=True)[-1].startswith('su -c '),
                  adb_shell('SERIAL', ['id'], root=True)[-1]))
    wrapped = su_wrap(['cat', '/data/local/tmp/x'])
    cases.append(('su wrapper is a single quoted string',
                  wrapped.startswith('su -c \'') and wrapped.endswith('\''), wrapped))
    return cases


def self_test():
    """Offline self-test: the module's own selftest() cases, plus exact-value assertions.

    `selftest()` states the properties ("quoting is inert", "garbage is refused"); this
    wrapper fails if ANY of them regresses and adds the three exact strings other scripts
    depend on -- `sh_quote`'s output, `su_wrap`'s output, and the argv form -- because
    those are a contract, not a preference. No device, no adb, no subprocess.
    """
    import contextlib

    def quiet(*argv):
        """Run the CLI with its stdout/stderr captured; nothing but the JSON may print."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            return main(list(argv))

    checks = 0
    try:
        cases = selftest()
        assert cases, 'selftest() returned no cases'
        failed = [(name, detail) for name, ok, detail in cases if not ok]
        assert not failed, 'the module\'s own selftest cases failed: %s' % (failed,)
        checks += 1

        assert sh_quote("a b;c") == "'a b;c'", sh_quote("a b;c")
        assert sh_quote("a'b") == "'a'\\''b'", sh_quote("a'b")
        assert sh_quote('') == "''", sh_quote('')
        assert sh_quote('a$(id)b') == "'a$(id)b'", sh_quote('a$(id)b')
        checks += 1

        assert su_wrap(['cat', '/data/local/tmp/x']) == \
            "su -c 'cat /data/local/tmp/x'", su_wrap(['cat', '/data/local/tmp/x'])
        assert su_wrap(["sh", "-c", "echo 'x'"]) == "su -c 'sh -c echo '\\''x'\\'''", \
            su_wrap(["sh", "-c", "echo 'x'"])
        assert adb_shell('SER', ['id'], root=True)[-1].startswith('su -c ')
        assert adb_shell('SER', ['id'], quote=False) == ['adb', '-s', 'SER', 'shell', 'id']
        assert adb_shell(None, ['id'], quote=False) == ['adb', 'shell', 'id']
        checks += 1

        assert validate_package('com.example.app') == 'com.example.app'
        assert validate_pid(4242) == '4242' and validate_pid('1') == '1'
        assert validate_component('.M', default_package='com.example.app') == \
            'com.example.app/.M', validate_component('.M', default_package='com.example.app')
        for bad_call in (lambda: validate_package('com..app'),
                         lambda: validate_package('1com.example'),
                         lambda: validate_package('com.example.app;id'),
                         lambda: validate_device_path('/sdcard/a b'),
                         lambda: validate_device_path('/data/../etc/passwd'),
                         lambda: validate_device_path('relative'),
                         lambda: validate_component('com.example.app'),
                         lambda: validate_pid('0'),
                         lambda: validate_pid('12a')):
            try:
                bad_call()
            except Refused:
                continue
            raise AssertionError('a malformed value was accepted: %r' % (bad_call,))
        checks += 1

        # The CLI contract: --check accepts, and a refusal is exit 1 (not a traceback).
        assert quiet('--check', 'com.example.app') == 0
        assert quiet('--check', 'com..app') == 1
        assert quiet('--check-path', '/sdcard/a b') == 1
        assert quiet('--quote', 'a b;c') == 0
        assert quiet() == 2
        checks += 1
    except Exception as exc:          # a failed assertion IS the signal: report, rc=1
        print(json.dumps({"ok": False, "checks": checks, "tool": "device_shell.py",
                          "reason": "%s: %s" % (type(exc).__name__, exc)},
                         ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, "checks": checks, "tool": "device_shell.py"},
                     ensure_ascii=False))
    return 0


def exit_code_for(main_fn):
    """Run a script's `main()` and turn a refusal into exit 2 with one line, never a traceback.

    Kept here so every script that validates device values reports the same way: a malformed
    identifier is a *usage* error (2), distinguishable from "the device said no" (1) and from a
    defect in the tool (4).
    """
    try:
        return main_fn()
    except Refused as exc:
        print('refused: %s' % exc, file=sys.stderr)
        print('RESULT=refused')
        return 2


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog='device_shell.py',
        description='Validate Android identifiers and quote values for the device shell. '
                    'Importable as a module; the CLI is for checking a value by hand.',
        epilog='examples:\n'
               '  device_shell.py --check com.example.app\n'
               '  device_shell.py --check com.example.app/.MainActivity\n'
               '  device_shell.py --quote "a b;c"\n'
               '  device_shell.py --selftest\n')
    ap.add_argument('--check', metavar='VALUE',
                    help='validate as a package name')
    ap.add_argument('--check-component', metavar='VALUE',
                    help='validate as package/Class, or as .Class together with --package')
    ap.add_argument('--package', metavar='PKG', help='default package for --check-component')
    ap.add_argument('--check-path', metavar='PATH', help='validate a device path')
    ap.add_argument('--quote', metavar='VALUE', help='print the POSIX-quoted form')
    ap.add_argument('--su', metavar='ARGV', help='print a su -c wrapper for a space-separated argv')
    ap.add_argument('--selftest', action='store_true', help='assert this module\'s own claims')
    ap.add_argument('--self-test', action='store_true', dest='self_test',
                    help='run the offline self-test and exit (JSON, rc 0/1)')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()

    if args.selftest:
        cases = selftest()
        bad = [c for c in cases if not c[1]]
        for name, ok, detail in cases:
            print('  %-52s %s' % (name, 'ok' if ok else 'FAIL'))
        print()
        print('RESULT=%s' % ('selftest_ok' if not bad else 'selftest_failed'))
        return 0 if not bad else 4

    try:
        if args.check:
            print('accepted: %s' % validate_package(args.check))
            print('RESULT=accepted')
            return 0
        if args.check_component:
            print('accepted: %s' % validate_component(args.check_component, args.package))
            print('RESULT=accepted')
            return 0
        if args.check_path:
            print('accepted: %s' % validate_device_path(args.check_path))
            print('RESULT=accepted')
            return 0
        if args.quote:
            if args.su:
                print(su_wrap([args.quote]))
            else:
                print(sh_quote(args.quote))
            print('RESULT=quoted')
            return 0
        if args.su:
            print(su_wrap(args.su.split()))
            print('RESULT=quoted')
            return 0
    except Refused as exc:
        print('refused: %s' % exc, file=sys.stderr)
        print('RESULT=refused')
        return 1

    ap.print_help()
    print('RESULT=usage_error')
    return 2


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except (ValueError, OSError):
            pass
    sys.exit(main())
