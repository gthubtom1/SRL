#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""baksmali / smali wrapper.

Assembling and disassembling dex requires smali + baksmali + several runtime jars on
the classpath. Getting the set wrong produces a bare `ClassNotFoundException` that
looks like a broken tool rather than a missing jar, so this wrapper centralizes it.

Two ways to configure the classpath, in priority order:
  1. --cp "jar1;jar2"          (explicit, per invocation)
  2. APK_REVERSE_SMALI_CP env var
  3. a `smali_cp.txt` next to this script (one jar path per line, '#' comments ok)

Required jars: smali, baksmali, dexlib2, util, antlr-runtime, stringtemplate,
jcommander, guava.

Usage
-----
  python smtool.py d <in.dex> <out_dir>      # disassemble to a smali tree
  python smtool.py a <in_tree> <out.dex>     # assemble a smali tree back to dex
  python smtool.py check                     # print the resolved classpath and exit

Notes
-----
* Always pass the tree directory as its own argument; do not rely on the shell.
* Call java from Python rather than from a shell: PowerShell in particular mangles
  arguments containing ';' or '$', which silently drops jars from the classpath.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CP_FILE = os.path.join(HERE, 'smali_cp.txt')

JAR_NAMES = [
    'smali-2.5.2.jar',
    'antlr-runtime-3.5.2.jar',
    'stringtemplate-3.2.1.jar',
    'baksmali-2.5.2.jar',
    'util-2.5.2.jar',
    'jcommander-1.64.jar',
    'guava-27.1-android.jar',
    'dexlib2-2.5.2.jar',
]


def resolve_cp(explicit=None):
    if explicit:
        return explicit
    env = os.environ.get('APK_REVERSE_SMALI_CP')
    if env:
        return env
    if os.path.isfile(CP_FILE):
        parts = []
        for line in open(CP_FILE, encoding='utf-8'):
            line = line.strip()
            if line and not line.startswith('#'):
                parts.append(line)
        if parts:
            return os.pathsep.join(parts)
    # last resort: look for the jars in a 'tools' dir next to this script
    cand = [os.path.join(HERE, 'tools', n) for n in JAR_NAMES]
    if all(os.path.isfile(c) for c in cand):
        return os.pathsep.join(cand)
    return None


def run(cp, main_class, args):
    cmd = ['java', '-cp', cp, main_class] + args
    r = subprocess.run(cmd, capture_output=True, text=True, errors='replace')
    out = (r.stdout or '') + (('\n[stderr]\n' + r.stderr) if (r.stderr or '').strip() else '')
    return r.returncode, out


def self_test():
    """Offline self-test: classpath precedence + CLI contract, no java invoked."""
    import contextlib
    import io
    import json
    import shutil
    import tempfile

    checks = []

    def chk(name, cond, detail=""):
        checks.append((name, bool(cond), detail))

    global CP_FILE, HERE
    real_cp_file, real_here = CP_FILE, HERE
    env_key = 'APK_REVERSE_SMALI_CP'
    saved_env = os.environ.pop(env_key, None)
    tmp = tempfile.mkdtemp(prefix='smtool-selftest-')
    try:
        # 1) precedence: explicit --cp beats the env var beats smali_cp.txt
        chk('explicit-cp-wins', resolve_cp('a.jar;b.jar') == 'a.jar;b.jar',
            resolve_cp('a.jar;b.jar'))
        os.environ[env_key] = 'env1.jar;env2.jar'
        chk('env-cp-used', resolve_cp(None) == 'env1.jar;env2.jar', resolve_cp(None))
        chk('env-loses-to-explicit', resolve_cp('x.jar') == 'x.jar')
        del os.environ[env_key]

        # 2) smali_cp.txt: '#' comments and blank lines are skipped, entries joined
        here = os.path.join(tmp, 'scripts')
        os.makedirs(here)
        CP_FILE = os.path.join(here, 'smali_cp.txt')
        HERE = here
        with open(CP_FILE, 'w', encoding='utf-8') as fh:
            fh.write('# comment line\n\n/opt/smali.jar\n/opt/baksmali.jar\n')
        want = os.pathsep.join(['/opt/smali.jar', '/opt/baksmali.jar'])
        chk('cp-file-parsed', resolve_cp(None) == want, resolve_cp(None))

        # 3) nothing configured -> None, and main() says so instead of calling java
        CP_FILE = os.path.join(here, 'no-such-cp.txt')
        chk('no-cp-is-none', resolve_cp(None) is None, resolve_cp(None))
        real_argv = sys.argv
        try:
            sys.argv = ['smtool.py', 'check']
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_no_cp = main()
            chk('no-cp-rc1', rc_no_cp == 1, rc_no_cp)
            chk('no-cp-message', 'no classpath' in buf.getvalue(), buf.getvalue())

            # 4) `check` reports each jar as OK/MISSING, and the file list is not guessed
            present = os.path.join(tmp, 'present.jar')
            open(present, 'wb').close()
            missing = os.path.join(tmp, 'missing.jar')
            cp = os.pathsep.join([present, missing])
            sys.argv = ['smtool.py', 'check', '--cp', cp]
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_check = main()
            out = buf.getvalue()
            chk('check-rc0', rc_check == 0, rc_check)
            chk('check-marks-present', ('OK ' in out and present in out), out)
            chk('check-marks-missing', ('MISSING' in out and missing in out), out)
            chk('check-echoes-classpath', ('classpath: %s' % cp) in out, out)

            # 5) usage errors, so a typo does not become a java invocation
            sys.argv = ['smtool.py']
            with contextlib.redirect_stdout(io.StringIO()):
                rc_empty = main()
            chk('no-args-rc2', rc_empty == 2, rc_empty)
            sys.argv = ['smtool.py', 'd', '--cp', cp]
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_short_d = main()
            chk('disassemble-needs-two-paths-rc2', rc_short_d == 2, rc_short_d)
            chk('disassemble-usage-printed', 'smtool.py d' in buf.getvalue(), buf.getvalue())
            sys.argv = ['smtool.py', 'a', 'tree', '--cp', cp]
            with contextlib.redirect_stdout(io.StringIO()):
                rc_short_a = main()
            chk('assemble-needs-two-paths-rc2', rc_short_a == 2, rc_short_a)
            sys.argv = ['smtool.py', 'nonsense', '--cp', cp]
            with contextlib.redirect_stdout(io.StringIO()):
                rc_bad = main()
            chk('unknown-command-rc2', rc_bad == 2, rc_bad)
            sys.argv = ['smtool.py', '--help']
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_help = main()
            chk('help-rc0', rc_help == 0, rc_help)
            chk('help-mentions-classpath', 'classpath' in buf.getvalue(), buf.getvalue()[:80])
        finally:
            sys.argv = real_argv
    finally:
        CP_FILE, HERE = real_cp_file, real_here
        if saved_env is not None:
            os.environ[env_key] = saved_env
        else:
            os.environ.pop(env_key, None)
        shutil.rmtree(tmp, ignore_errors=True)

    fails = [(n, d) for n, ok, d in checks if not ok]
    print(json.dumps({'ok': not fails, 'checks': len(checks), 'tool': 'smtool.py',
                      'failures': [n for n, _ in fails]}, ensure_ascii=False))
    for n, d in fails:
        print('FAIL %s: %s' % (n, d), file=sys.stderr)
    return 0 if not fails else 1


def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print((__doc__ or "").strip() or "usage: smtool.py ...")
        return 0
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    explicit = None
    argv = sys.argv[1:]
    if '--cp' in argv:
        i = argv.index('--cp')
        explicit = argv[i + 1]
        del argv[i:i + 2]

    cp = resolve_cp(explicit)
    if not cp:
        print('[FAIL] no classpath. Provide --cp, set APK_REVERSE_SMALI_CP, '
              'or create smali_cp.txt next to this script.')
        return 1

    cmd = argv[0]
    if cmd == 'check':
        print('classpath: %s' % cp)
        for j in cp.split(os.pathsep):
            print('  %s  %s' % ('OK ' if os.path.isfile(j) else 'MISSING', j))
        return 0

    if cmd in ('d', 'dis', 'disassemble'):
        if len(argv) < 3:
            print('usage: smtool.py d <in.dex> <out_dir>')
            return 2
        rc, out = run(cp, 'org.jf.baksmali.Main', ['d', argv[1], '-o', argv[2]])
    elif cmd in ('a', 'asm', 'assemble'):
        if len(argv) < 3:
            print('usage: smtool.py a <in_tree> <out.dex>')
            return 2
        rc, out = run(cp, 'org.jf.smali.Main', ['a', argv[1], '-o', argv[2]])
    else:
        print(__doc__)
        return 2

    print(out.strip()[-4000:])
    print('rc=%d' % rc)
    return 0 if rc == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
