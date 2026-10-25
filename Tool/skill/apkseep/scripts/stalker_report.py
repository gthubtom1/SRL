#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Summarize a stalker_trace.js log: block histogram, skeleton, call edges.

WHY THIS EXISTS
---------------
scripts/stalker_trace.js records, for one target module, the basic blocks a
thread really executed. Raw, that log answers nothing -- the value comes from
three reductions, and each maps to a deobfuscation decision:

  * execution histogram (BLK lines) -- in a control-flow-flattened function
    the dispatcher block runs orders of magnitude more often than any real
    block; the top of this histogram IS the dispatcher;
  * first-visit order (BB lines) -- the deduplicated block set in first-visit
    order approximates the real CFG skeleton with the flattening state machine
    stripped out;
  * call edges (CALL lines) -- which functions inside the module talk to each
    other, independent of symbol names.

This tool is deliberately stdlib-only and parses text, so it works on logs
written by run_probe.py (each event line embedded in a `[host ts] [dev ts]
TRACE ...` wrapper) and on raw one-event-per-line logs alike.

Usage
-----
  python stalker_report.py trace.log
  python stalker_report.py trace.log --top 30 --skeleton 80
  python stalker_report.py trace.log --json report.json
  python stalker_report.py trace.log --quiet          # summary only

Reading the output
------------------
  * DONE ... truncated=1  -- the trace hit maxBlocks; ratios are still useful,
    absolute counts are not.
  * zero BLK but nonzero BB -- the thread stopped between translation and
    execution (short follow, or the trigger returned immediately).
  * zero BB and zero BLK with DONE present -- module never ran on the followed
    thread; pick a real trigger instead of `main`.
  * everything zero, no DONE -- the trace never started: check READY/TRIG-FAIL
    lines in the log first.
"""

import argparse
import json
import re
import sys
from collections import Counter, OrderedDict

MOD_RE = re.compile(r'\bMOD (\S+) base=(0x[0-9a-fA-F]+) size=(\d+)(?:\s+path=(\S+))?')
BB_RE = re.compile(r'\bBB (\d+) (\S+)\+0x([0-9a-fA-F]+)')
BLK_RE = re.compile(r'\bBLK (\d+) (\S+)\+0x([0-9a-fA-F]+)(?:\s+size=(\d+))?')
CALL_RE = re.compile(r'\bCALL (\S+) (\S+) -> (\S+)')
DONE_RE = re.compile(r'\bDONE reason=(\S+) blocks=(\d+) blk=(\d+) calls=(\d+) truncated=(\d)')
FATAL_RE = re.compile(r'\b(FATAL|TRIG-FAIL) (.*)')


def parse_log(path):
    stats = {
        'mods': OrderedDict(),        # name -> {base, size, path}
        'bb': [],                     # (seq, mod, offset) first-visit order
        'blk': [],                    # (seq, mod, offset, size|None) executions
        'calls': [],                  # (depth, from, to)
        'done': None,
        'fatals': [],
    }
    with open(path, encoding='utf-8', errors='replace') as fh:
        for raw in fh:
            m = MOD_RE.search(raw)
            if m:
                name, base, size, path = m.groups()
                if name not in stats['mods']:
                    stats['mods'][name] = {
                        'base': base, 'size': int(size), 'path': path or ''}
                continue
            m = BLK_RE.search(raw)
            if m:
                seq, mod, off, size = m.groups()
                stats['blk'].append((int(seq), mod, int(off, 16),
                                     int(size) if size else None))
                continue
            m = BB_RE.search(raw)
            if m:
                seq, mod, off = m.groups()
                stats['bb'].append((int(seq), mod, int(off, 16)))
                continue
            m = CALL_RE.search(raw)
            if m:
                stats['calls'].append(m.groups())
                continue
            m = DONE_RE.search(raw)
            if m and stats['done'] is None:
                stats['done'] = m.groups()
                continue
            m = FATAL_RE.search(raw)
            if m:
                stats['fatals'].append(m.group(0).strip())
    return stats


def blockkey(mod, off):
    return '%s+0x%x' % (mod, off)


def collapse_consecutive(items):
    """[(mod, off), ...] -> [(key, repeats), ...] with runs collapsed."""
    out = []
    for mod, off in items:
        key = blockkey(mod, off)
        if out and out[-1][0] == key:
            out[-1] = (key, out[-1][1] + 1)
        else:
            out.append((key, 1))
    return out


def self_test():
    """Offline self-test: a hand-written trace log in a temp dir, no device."""
    import contextlib
    import io
    import json
    import os
    import shutil
    import subprocess
    import tempfile

    checks = []

    def chk(name, cond, detail=''):
        checks.append((name, bool(cond), detail))

    log_text = (
        '[host 2024-01-01 00:00:00.000] [dev 1.50] MOD libfoo.so base=0x764c0aa000 '
        'size=40960 path=/data/local/tmp/libfoo.so\n'
        '[host] [dev] BB 1 libfoo.so+0x1000\n'
        'BB 2 libfoo.so+0x1004\n'
        'BLK 3 libfoo.so+0x1000 size=16\n'
        'BLK 4 libfoo.so+0x1000 size=16\n'
        'BLK 5 libfoo.so+0x1004\n'
        'CALL 0 libfoo.so+0x1000 -> libfoo.so+0x1004\n'
        'CALL 1 libfoo.so+0x1000 -> libfoo.so+0x1004\n'
        'DONE reason=maxblocks blocks=5 blk=9 calls=2 truncated=1\n'
        'FATAL follow window closed\n')

    tmp = tempfile.mkdtemp(prefix='stalker-report-selftest-')
    try:
        log = os.path.join(tmp, 'trace.log')
        with open(log, 'w', encoding='utf-8') as fh:
            fh.write(log_text)

        # 1) the parser: wrapper prefixes are transparent, sizes are optional
        st = parse_log(log)
        chk('parse-module-name', list(st['mods']) == ['libfoo.so'], list(st['mods']))
        chk('parse-module-base', st['mods']['libfoo.so']['base'] == '0x764c0aa000',
            st['mods']['libfoo.so'])
        chk('parse-module-size', st['mods']['libfoo.so']['size'] == 40960)
        chk('parse-module-path', st['mods']['libfoo.so']['path'] == '/data/local/tmp/libfoo.so')
        chk('parse-bb-order', [b[2] for b in st['bb']] == [0x1000, 0x1004], st['bb'])
        chk('parse-blk-count', len(st['blk']) == 3, len(st['blk']))
        chk('parse-blk-size', st['blk'][0][3] == 16 and st['blk'][2][3] is None, st['blk'])
        chk('parse-calls', len(st['calls']) == 2 and
            st['calls'][0] == ('0', 'libfoo.so+0x1000', 'libfoo.so+0x1004'), st['calls'])
        chk('parse-done', st['done'] == ('maxblocks', '5', '9', '2', '1'), st['done'])
        chk('parse-fatals', len(st['fatals']) == 1 and 'follow window' in st['fatals'][0],
            st['fatals'])

        # 2) the reductions: block keys and consecutive-run collapsing
        chk('blockkey', blockkey('libfoo.so', 0x1000) == 'libfoo.so+0x1000',
            blockkey('libfoo.so', 0x1000))
        runs = collapse_consecutive([('m', 1), ('m', 1), ('m', 2), ('m', 1)])
        chk('collapse-consecutive', runs == [('m+0x1', 2), ('m+0x2', 1), ('m+0x1', 1)], runs)

        # 3) main(): summary + histogram + json payload, driven through sys.argv
        real_argv = sys.argv
        try:
            sys.argv = ['stalker_report.py', log]
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = main()
            out = buf.getvalue()
            chk('main-rc0', rc == 0, rc)
            chk('main-counts-unique', 'unique blocks first-seen (BB) : 2' in out, out[:200])
            chk('main-counts-exec', 'block executions (BLK)        : 3' in out)
            chk('main-counts-calls', 'call edges (CALL)             : 2' in out)
            chk('main-done-line', 'DONE reason=maxblocks truncated=1' in out, out[:200])
            chk('main-histogram-top', 'libfoo.so+0x1000' in out)

            json_path = os.path.join(tmp, 'report.json')
            sys.argv = ['stalker_report.py', log, '--json', json_path, '--top', '1']
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_q = main()
            chk('main-json-rc0', rc_q == 0, rc_q)
            sys.argv = ['stalker_report.py', log, '--quiet']
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc_quiet = main()
            chk('main-quiet-rc0', rc_quiet == 0, rc_quiet)
            chk('main-quiet-hides-histogram', '== execution histogram' not in buf.getvalue(),
                buf.getvalue()[:120])
            with open(json_path, encoding='utf-8') as fh:
                payload = json.load(fh)
            chk('json-summary', payload['summary']['bb'] == 2 and
                payload['summary']['blk'] == 3, payload['summary'])
            chk('json-histogram', payload['histogram'].get('libfoo.so+0x1000') == 2,
                payload['histogram'])
            chk('json-call-edges', payload['call_edges'].get(
                'libfoo.so+0x1000 -> libfoo.so+0x1004') == 2, payload['call_edges'])
            chk('json-collapsed', payload['collapsed'][0] == ['libfoo.so+0x1000', 2],
                payload['collapsed'])

            # 4) a trace that never ran is a negative result (rc 1 without DONE)
            empty_log = os.path.join(tmp, 'empty.log')
            with open(empty_log, 'w', encoding='utf-8') as fh:
                fh.write('MOD libfoo.so base=0x1000 size=4096\n')
            sys.argv = ['stalker_report.py', empty_log, '--quiet']
            with contextlib.redirect_stdout(io.StringIO()):
                rc_empty = main()
            chk('no-blocks-no-done-rc1', rc_empty == 1, rc_empty)
            with open(empty_log, 'a', encoding='utf-8') as fh:
                fh.write('DONE reason=detach blocks=0 blk=0 calls=0 truncated=0\n')
            sys.argv = ['stalker_report.py', empty_log, '--quiet']
            with contextlib.redirect_stdout(io.StringIO()):
                rc_empty_done = main()
            chk('no-blocks-with-done-rc0', rc_empty_done == 0, rc_empty_done)
        finally:
            sys.argv = real_argv

        # 5) CLI contract
        me = os.path.abspath(__file__)
        helped = subprocess.run([sys.executable, me, '--help'], capture_output=True,
                                text=True, errors='replace')
        chk('help-rc0', helped.returncode == 0, helped.returncode)
        for flag in ('--top', '--skeleton', '--edges', '--seq', '--json', '--quiet',
                     '--self-test'):
            chk('help-mentions-%s' % flag, flag in helped.stdout)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    fails = [(n, d) for n, ok, d in checks if not ok]
    print(json.dumps({'ok': not fails, 'checks': len(checks),
                      'tool': 'stalker_report.py',
                      'failures': [n for n, _ in fails]}, ensure_ascii=False))
    for n, d in fails:
        print('FAIL %s: %s' % (n, d), file=sys.stderr)
    return 0 if not fails else 1


def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()
    ap = argparse.ArgumentParser(
        description='Summarize a stalker_trace.js log into a block histogram, '
                    'a first-visit CFG skeleton, and call-edge tables.')
    ap.add_argument('log', help='trace log written by run_probe.py (wrapped '
                                'lines are fine) or a raw event-per-line log')
    ap.add_argument('--top', type=int, default=20,
                    help='rows in the execution histogram (default 20)')
    ap.add_argument('--skeleton', type=int, default=40,
                    help='rows of the first-visit order to print (default 40)')
    ap.add_argument('--edges', type=int, default=15,
                    help='rows in the call-edge table (default 15)')
    ap.add_argument('--seq', type=int, default=60,
                    help='entries of the collapsed execution sequence to print '
                         '(default 60)')
    ap.add_argument('--json', metavar='PATH', default=None,
                    help='also write the full reduced data as JSON')
    ap.add_argument('--quiet', action='store_true',
                    help='print the summary block only')
    ap.add_argument('--self-test', action='store_true', dest='self_test',
                    help='run the offline self-test (hand-written log, no device)')
    args = ap.parse_args()

    st = parse_log(args.log)

    print('== summary ==')
    for name, info in st['mods'].items():
        print('  module %-24s base=%s size=%d %s'
              % (name, info['base'], info['size'],
                 ('(target)' if st['bb'] and st['bb'][0][1] == name else '')))
    print('  unique blocks first-seen (BB) : %d' % len(st['bb']))
    print('  block executions (BLK)        : %d' % len(st['blk']))
    print('  call edges (CALL)             : %d' % len(st['calls']))
    if st['done']:
        reason, nb, nk, nc, trunc = st['done']
        print('  DONE reason=%s truncated=%s (device-side counts: bb=%s blk=%s call=%s)'
              % (reason, trunc, nb, nk, nc))
    else:
        print('  DONE line missing -- trace ended without a clean stop '
              '(detach or crash?)')
    for f in st['fatals'][:5]:
        print('  NOTE %s' % f)

    if not st['bb'] and not st['blk']:
        print('\n  no target-module blocks at all. In order of likelihood:\n'
              '    1. the module was never loaded on the followed thread '
              '(check the MOD lines);\n'
              '    2. the trigger never fired (TRIG-FAIL above, or the app '
              'never called it);\n'
              '    3. the follow window closed before any code ran '
              '(raise followMs, or use a call trigger instead of main).')
        return 0 if st['done'] else 1

    first_seen = {}
    for seq, mod, off in st['bb']:
        first_seen.setdefault(blockkey(mod, off), seq)

    if not args.quiet:
        hist = Counter(blockkey(mod, off) for _, mod, off, _ in st['blk'])
        total = sum(hist.values())
        if hist:
            print('\n== execution histogram: top %d (dispatcher candidates) ==' % args.top)
            print('  %-6s %-8s %-7s %-28s %s'
                  % ('rank', 'count', 'pct', 'block', 'firstSeen'))
            for rank, (key, cnt) in enumerate(hist.most_common(args.top), 1):
                pct = 100.0 * cnt / total if total else 0.0
                print('  %-6d %-8d %5.1f%%  %-28s #%s'
                      % (rank, cnt, pct, key, first_seen.get(key, '-')))
            print('  (a block at the top by a wide margin, with many distinct '
                  'successors below,\n   is the classic control-flow-'
                  'flattening dispatcher; see\n   references/'
                  'native-dbi-and-deobfuscation.md)')

        if st['bb']:
            print('\n== first-visit order (CFG skeleton, first %d of %d) =='
                  % (min(args.skeleton, len(st['bb'])), len(st['bb'])))
            for seq, mod, off in st['bb'][:args.skeleton]:
                print('  #%d %s' % (seq, blockkey(mod, off)))

        if st['calls']:
            edges = Counter('%s -> %s' % (frm, to) for _, frm, to in st['calls'])
            print('\n== call edges (top %d of %d) ==' % (args.edges, len(edges)))
            for edge, cnt in edges.most_common(args.edges):
                print('  %-8d %s' % (cnt, edge))

        collapsed = collapse_consecutive([(mod, off) for _, mod, off, _ in st['blk']])
        if collapsed:
            print('\n== collapsed execution sequence (first %d runs of %d) =='
                  % (min(args.seq, len(collapsed)), len(collapsed)))
            line = '  '
            for key, reps in collapsed[:args.seq]:
                piece = key + ('*%d' % reps if reps > 1 else '')
                if len(line) + len(piece) > 100:
                    print(line)
                    line = '  '
                line += piece + ' -> '
            if line.strip():
                print(line[:-4])

    if args.json:
        payload = {
            'modules': st['mods'],
            'summary': {
                'bb': len(st['bb']), 'blk': len(st['blk']),
                'calls': len(st['calls']), 'done': st['done'],
            },
            'first_seen': first_seen,
            'histogram': dict(Counter(
                blockkey(mod, off) for _, mod, off, _ in st['blk'])),
            'bb_sequence': [blockkey(mod, off) for _, mod, off in st['bb']],
            'collapsed': collapsed if st['blk'] else [],
            'call_edges': dict(Counter('%s -> %s' % (f, t)
                                       for _, f, t in st['calls'])),
        }
        with open(args.json, 'w', encoding='utf-8') as fh:
            json.dump(payload, fh, indent=1)
        print('\njson written to %s' % args.json)

    return 0


if __name__ == '__main__':
    sys.exit(main())
