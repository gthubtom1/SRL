#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Diff two dex files at the class_defs level: class names + access_flags.
The interesting flag is ACC_INTERFACE (0x200).

Use it to prove that a disassemble -> reassemble round-trip did not damage the dex's
interface/class relationships. The classic symptom of that damage is
IncompatibleClassChangeError ("Found interface X, but class was expected") at runtime.

Important limitation: this check compares tables only. It cannot see code-item damage —
see references/patch-audit.md for the checks that can.
"""
import argparse
import io
import json
import os
import shutil
import struct
import sys
import tempfile

ACC_INTERFACE = 0x200


def uleb128(data, off):
    result = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, off


def read_strings(data):
    strings_size = struct.unpack('<I', data[0x38:0x3C])[0]
    strings_off = struct.unpack('<I', data[0x3C:0x40])[0]
    out = []
    for i in range(strings_size):
        sdata_off = struct.unpack('<I', data[strings_off + i * 4: strings_off + i * 4 + 4])[0]
        n, p = uleb128(data, sdata_off)
        raw = data[p:p + n]
        out.append(raw.decode('utf-8', 'replace'))
    return out


def class_map(path):
    data = open(path, 'rb').read()
    strings = read_strings(data)
    n_types = struct.unpack('<I', data[0x40:0x44])[0]
    type_ids_off = struct.unpack('<I', data[0x44:0x48])[0]
    types = []
    for i in range(n_types):
        idx = struct.unpack('<I', data[type_ids_off + i * 4: type_ids_off + i * 4 + 4])[0]
        types.append(strings[idx] if idx < len(strings) else '')
    class_defs_size = struct.unpack('<I', data[0x60:0x64])[0]
    class_defs_off = struct.unpack('<I', data[0x64:0x68])[0]
    out = {}
    for i in range(class_defs_size):
        base = class_defs_off + i * 32
        class_idx, access_flags = struct.unpack('<II', data[base:base + 8])
        name = types[class_idx] if class_idx < len(types) else '?'
        out[name] = access_flags
    return out


def self_test():
    """Offline self-test: generated dex tables, no sample builds.

    `class_map()` reads only the string/type/class_def tables, so the fixture is built
    from exactly those tables and the assertions are on the parsed VALUES and FLAGS.
    The interesting case is a class that loses ACC_INTERFACE: that is the
    IncompatibleClassChangeError this tool exists to catch, and it must show up as an
    ACC_INTERFACE mismatch and a non-zero exit.
    """
    import contextlib

    def table_dex(classes):
        """A dex carrying just string_ids / type_ids / class_defs for `classes`."""
        def uleb(value):
            out = bytearray()
            while True:
                b = value & 0x7F
                value >>= 7
                if value:
                    out.append(b | 0x80)
                else:
                    out.append(b)
                    return bytes(out)

        str_ids_off = 112
        type_ids_off = str_ids_off + 4 * len(classes)
        class_defs_off = type_ids_off + 4 * len(classes)
        data_off = class_defs_off + 32 * len(classes)
        data = bytearray()
        str_offs = []
        for name, _flags in classes:
            raw = name.encode('utf-8')
            str_offs.append(data_off + len(data))
            data += uleb(len(raw)) + raw + b'\x00'
        total = data_off + len(data)
        head = bytearray(112)
        head[0:8] = b'dex\n035\x00'
        struct.pack_into('<I', head, 0x20, total)
        struct.pack_into('<I', head, 0x24, 112)
        struct.pack_into('<II', head, 0x38, len(classes), str_ids_off)
        struct.pack_into('<II', head, 0x40, len(classes), type_ids_off)
        struct.pack_into('<II', head, 0x60, len(classes), class_defs_off)
        body = bytearray()
        for off in str_offs:
            body += struct.pack('<I', off)
        for i in range(len(classes)):
            body += struct.pack('<I', i)                      # type -> string idx
        for i, (_name, flags) in enumerate(classes):
            body += struct.pack('<IIII', i, flags, 0xFFFFFFFF, 0)      # class_idx .. interfaces
            body += struct.pack('<IIII', 0xFFFFFFFF, 0, 0, 0)          # source .. static_values
        body += data
        return bytes(head) + bytes(body)

    checks = 0
    tmpdir = tempfile.mkdtemp(prefix='dex-classdiff-selftest-')
    try:
        assert uleb128(b'\xe5\x8e\x26', 0) == (624485, 3), uleb128(b'\xe5\x8e\x26', 0)
        assert uleb128(b'\x7f', 0) == (127, 1)
        assert uleb128(b'\x80\x01', 0) == (128, 2)
        checks += 1

        a_path = os.path.join(tmpdir, 'a.dex')
        b_path = os.path.join(tmpdir, 'b.dex')
        with open(a_path, 'wb') as fh:
            fh.write(table_dex([('Lcom/ex/A;', 0x1), ('Lcom/ex/B;', 0x601)]))
        with open(b_path, 'wb') as fh:
            fh.write(table_dex([('Lcom/ex/A;', 0x1), ('Lcom/ex/B;', 0x1),
                                ('Lcom/ex/C;', 0x1)]))

        A = class_map(a_path)
        B = class_map(b_path)
        assert A == {'Lcom/ex/A;': 0x1, 'Lcom/ex/B;': 0x601}, A
        assert set(B) == {'Lcom/ex/A;', 'Lcom/ex/B;', 'Lcom/ex/C;'}, B
        assert A['Lcom/ex/B;'] & ACC_INTERFACE == ACC_INTERFACE, A
        assert B['Lcom/ex/B;'] & ACC_INTERFACE == 0, B
        checks += 1

        out = io.StringIO()
        saved = sys.argv
        try:
            sys.argv = ['dex_classdiff.py', a_path, b_path, '--quiet']
            with contextlib.redirect_stdout(out):
                rc = main()
        finally:
            sys.argv = saved
        text = out.getvalue()
        assert rc == 1, 'a structural difference must exit non-zero, got %r' % (rc,)
        assert 'A classes=2  B classes=3' in text, text
        assert 'only_in_A=0  only_in_B=1' in text, text
        assert '*** ACC_INTERFACE mismatch: 1 ***' in text, text
        assert 'STRUCTURAL DIFFERENCE' in text, text
        checks += 1

        out = io.StringIO()
        try:
            sys.argv = ['dex_classdiff.py', a_path, a_path, '--quiet']
            with contextlib.redirect_stdout(out):
                rc = main()
        finally:
            sys.argv = saved
        assert rc == 0, rc
        assert 'verdict: class tables identical' in out.getvalue(), out.getvalue()
        checks += 1
    except Exception as exc:          # a failed assertion IS the signal: report, rc=1
        print(json.dumps({"ok": False, "checks": checks, "tool": "dex_classdiff.py",
                          "reason": "%s: %s" % (type(exc).__name__, exc)},
                         ensure_ascii=False))
        return 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    print(json.dumps({"ok": True, "checks": checks, "tool": "dex_classdiff.py"},
                     ensure_ascii=False))
    return 0


def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()

    ap = argparse.ArgumentParser(
        description='Compare two dex files at class_defs level (names + access_flags). '
                    'Proves a reassembly did not damage interface/class relationships.')
    ap.add_argument('a', help='first dex (e.g. the original)')
    ap.add_argument('b', help='second dex (e.g. the rebuilt one)')
    ap.add_argument('filter', nargs='?', default=None,
                    help='only report names containing this substring')
    ap.add_argument('--max-list', type=int, default=10,
                    help='how many A-only / B-only names to print (default 10)')
    ap.add_argument('--max-flags', type=int, default=25,
                    help='how many access_flags differences to print (default 25)')
    ap.add_argument('--quiet', action='store_true',
                    help='print only the summary counts')
    ap.add_argument('--self-test', action='store_true', dest='self_test',
                    help='run offline self-test and exit (no sample builds needed)')
    args = ap.parse_args()

    A = class_map(args.a)
    B = class_map(args.b)
    only_a = sorted(set(A) - set(B))
    only_b = sorted(set(B) - set(A))

    diff_iface = []
    diff_flags = []
    for name in sorted(set(A) & set(B)):
        fa, fb = A[name], B[name]
        if bool(fa & ACC_INTERFACE) != bool(fb & ACC_INTERFACE):
            diff_iface.append((name, fa, fb))
        elif fa != fb:
            diff_flags.append((name, fa, fb))

    print('A classes=%d  B classes=%d' % (len(A), len(B)))
    print('only_in_A=%d  only_in_B=%d' % (len(only_a), len(only_b)))
    if not args.quiet:
        for n in only_a[:args.max_list]:
            print('  A-only:', n)
        for n in only_b[:args.max_list]:
            print('  B-only:', n)

    print('\n*** ACC_INTERFACE mismatch: %d ***' % len(diff_iface))
    if not args.quiet:
        for name, fa, fb in diff_iface:
            if args.filter and args.filter not in name:
                continue
            print('  %-70s A=%s B=%s' % (name, hex(fa), hex(fb)))

    print('\naccess_flags diff (same interface-ness): %d' % len(diff_flags))
    if not args.quiet:
        shown = 0
        for name, fa, fb in diff_flags:
            if args.filter and args.filter not in name:
                continue
            if shown >= args.max_flags:
                print('  ... (%d more suppressed)' % (len(diff_flags) - shown))
                break
            print('  %-70s A=%s B=%s' % (name, hex(fa), hex(fb)))
            shown += 1

    # Exit non-zero when a structural difference exists, so a caller can gate on it.
    verdict = (len(only_a) == 0 and len(only_b) == 0 and len(diff_iface) == 0)
    print('\nverdict: %s' % ('class tables identical'
                             if verdict else 'STRUCTURAL DIFFERENCE — inspect above'))
    return 0 if verdict else 1


if __name__ == '__main__':
    sys.exit(main())
