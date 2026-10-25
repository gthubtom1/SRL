#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Find every reference to a method/field/class, so you can judge blast radius
BEFORE patching it.

This is the check that prevents the classic mistake: patching something that looked
ad-specific but is actually a general utility with dozens of callers.

Usage
-----
  # a smali tree, a single .dex, a directory holding either, or an .apk
  python find_refs.py <smali_tree|dex|dir|apk> 'Lcom/pkg/Helper;->showAd(Landroid/app/Activity;)V'

  # a whole class (all of its members)
  python find_refs.py <smali_tree|dex|dir|apk> 'Lcom/pkg/Helper;'

  # a field
  python find_refs.py <smali_tree|dex|dir|apk> 'Lcom/pkg/Helper;->count:I'

  # just the counts, no listing
  python find_refs.py <smali_tree|dex|dir|apk> 'Lcom/pkg/Helper;->showAd' --count-only

Reading the result
------------------
  few callers, all inside one feature area   -> safe to patch
  many callers, or callers in unrelated pkgs -> general utility. DO NOT patch it.
                                                Go one level up and patch the
                                                specific caller instead.

The first line is part of the answer, not decoration. `[scanned] 0 file(s)` means
the input was never read -- an unsupported path, a typo, a directory with nothing
this script can open -- and it is a different result from "read N files and found
nothing". The two used to print identically, which put a false zero on exactly the
decision this script exists to protect. Input that cannot be read now exits 2 and
says why.

Input forms, precisely:
  .smali file     text scan (no decoder needed)
  .dex file       decoded with dexutil (no baksmali/jadx required)
  directory       every .smali and .dex found under it, recursively
  .apk/.zip/...   every classes*.dex inside the archive
  anything else   refused with an error, rather than reported as "no references"

Also inspect the signature. If it mentions Modifier / ContentScale / Shape / View /
ColorScheme or a content-generic model type, it is shared UI, not your target.
"""
import argparse
import json
import os
import re
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dexutil import (  # noqa: E402
    IFIELD_OPS, INVOKE_OPS, PFIELD_OPS, SFIELD_OPS, insn_units, load_dex, u16,
)

TEXT_EXT = ('.smali',)
DEX_EXT = ('.dex',)
ARCHIVE_EXT = ('.apk', '.zip', '.jar', '.xapk', '.apks', '.apkm')
REF_RE_TMPL = r'invoke[^\n]*%s|sget[^\n]*%s|sput[^\n]*%s|new-instance[^\n]*%s|check-cast[^\n]*%s'

FIELD_OPS = tuple(IFIELD_OPS) + tuple(PFIELD_OPS) + tuple(SFIELD_OPS)
# new-instance (0x22) and check-cast (0x1F) both carry a type index at byte 2,
# which is where the 21c format puts it.
TYPE_OPS = (0x1F, 0x22)
# classes.dex, classes2.dex, ... in an archive.
ARCHIVE_DEX_RE = re.compile(r'(?:^|/)classes\d*\.dex$')

EXIT_FOUND = 0
EXIT_NO_MATCH = 1
EXIT_BAD_INPUT = 2


def gather(root):
    """Return (smali_paths, dex_paths, archive_paths).

    Raises ValueError for input this script cannot read, so that "nothing was
    scanned" can never be mistaken for "nothing references it".
    """
    if os.path.isdir(root):
        smali, dexs = [], []
        for dp, _dirs, files in os.walk(root):
            for fn in sorted(files):
                path = os.path.join(dp, fn)
                if fn.endswith(TEXT_EXT):
                    smali.append(path)
                elif fn.endswith(DEX_EXT):
                    dexs.append(path)
        if not smali and not dexs:
            raise ValueError(
                'no .smali and no .dex files under %s.\n'
                '        A directory of .apk archives is not scanned; pass the '
                '.apk itself, or disassemble first (%s).'
                % (root, 'smtool.py'))
        return smali, dexs, []

    if not os.path.exists(root):
        raise ValueError('no such file or directory: %s' % root)

    low = root.lower()
    if low.endswith(TEXT_EXT):
        return [root], [], []
    if low.endswith(DEX_EXT):
        return [], [root], []
    if low.endswith(ARCHIVE_EXT):
        return [], [], [root]
    raise ValueError(
        '%s is not a .smali file, a .dex, a directory, or an archive.\n'
        '        Accepted: .smali, .dex, a directory holding either, '
        '%s' % (root, '/'.join(ARCHIVE_EXT)))


def method_owner(text, idx):
    """Map a character offset to the enclosing .method declaration."""
    head = text.rfind('.method ', 0, idx)
    if head < 0:
        return '?'
    end = text.find('\n', head)
    return text[head:end].strip()


def scan_smali(path, pat):
    """Return [(offset, owner, matched_text)] for one smali file."""
    try:
        with open(path, encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError:
        return []
    return [(m.start(), method_owner(text, m.start()), m.group(0).strip())
            for m in pat.finditer(text)]


def walk_insns(dex, code_off):
    """Yield (offset, opcode) for one method body.

    Deliberately not dex.decode(): this walks every instruction of every method
    in the dex, and the per-instruction dict decode() builds is not needed to
    read an operand index out of the raw bytes.
    """
    info = dex.code_info(code_off)
    pos = info['insns_off']
    end = pos + info['insns_size'] * 2
    while pos < end:
        op = dex.d[pos]
        units = insn_units(op, dex.d, pos, end)
        if units < 1 or pos + units * 2 > end:
            return
        yield pos, op
        pos += units * 2


def scan_dex(dex, needle):
    """Return [(insn_off, owner, rendered)] for references inside one dex.

    The rendered form is the same string the smali side matches textually
    (`Lcom/pkg/Helper;->showAd(Landroid/app/Activity;)V`), so both input forms
    answer the same question the same way.
    """
    out = []
    for i in range(dex.header['class_defs_size']):
        cd_off = dex.header['class_defs_off'] + i * 32
        for _section, _midx, cls, name, desc, code_off in dex.methods_at(cd_off):
            if not code_off:
                continue
            owner = '%s->%s%s' % (cls, name, desc)
            for pos, op in walk_insns(dex, code_off):
                if op in INVOKE_OPS:
                    cls2, nm, ds = dex.method(u16(dex.d, pos + 2))
                    rendered = '%s->%s%s' % (cls2, nm, ds)
                elif op in FIELD_OPS:
                    cls2, nm, ty = dex.field(u16(dex.d, pos + 2))
                    rendered = '%s->%s:%s' % (cls2, nm, ty)
                elif op in TYPE_OPS:
                    rendered = dex.type_(u16(dex.d, pos + 2))
                else:
                    continue
                if needle in rendered:
                    out.append((pos, owner, rendered))
    return out


def dex_sources(path):
    """Return [(label, Dex)] for a .dex file or every classes*.dex in an archive."""
    if path.lower().endswith(DEX_EXT):
        dex, _entry = load_dex(path)
        return [(path, dex)]
    with zipfile.ZipFile(path) as z:
        names = sorted(n for n in z.namelist() if ARCHIVE_DEX_RE.search(n))
    if not names:
        raise ValueError('no classes*.dex inside %s' % path)
    out = []
    for name in names:
        dex, _entry = load_dex(path, entry=name)
        out.append(('%s!%s' % (path, name), dex))
    return out


def _fixture_dex():
    """A structurally valid dex whose reference counts are known in advance.

        Lcom/example/Caller;->go()V    invoke-static  Lcom/example/Target;->run()V   x2
        Lcom/example/Target;->run()V   invoke-virtual Ljava/lang/String;->length()I  x3

    so the correct answers are 3, 2 and 2. Built here rather than shipped as a
    sample so the self-test has no dependency on -- and no resemblance to --
    target data.
    """
    CALLER, TARGET = 'Lcom/example/Caller;', 'Lcom/example/Target;'
    OBJECT, STRING = 'Ljava/lang/Object;', 'Ljava/lang/String;'

    def uleb(n):
        out = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            out.append(b | (0x80 if n else 0))
            if not n:
                return bytes(out)

    def p16(v):
        return struct.pack('<H', v)

    def p32(v):
        return struct.pack('<I', v)

    def string_data(s):
        raw = s.encode('utf-8')
        return uleb(len(raw)) + raw + b'\x00'

    def code_item(registers, outs, insns):
        body = b''.join(p16(u) for u in insns)
        return (p16(registers) + p16(0) + p16(outs) + p16(0)
                + p32(0) + p32(len(insns)) + body)

    def class_data(entries):
        out = uleb(0) + uleb(0) + uleb(len(entries)) + uleb(0)
        prev = 0
        for mi, acc, co in entries:
            out += uleb(mi - prev) + uleb(acc) + uleb(co)
            prev = mi
        return out

    strings = sorted({CALLER, TARGET, OBJECT, STRING, 'I', 'V',
                      'go', 'run', 'length'})
    sidx = {s: i for i, s in enumerate(strings)}
    types = sorted({CALLER, TARGET, OBJECT, STRING, 'I', 'V'}, key=lambda t: sidx[t])
    tidx = {t: i for i, t in enumerate(types)}
    protos = [('I', 'I'), ('V', 'V')]
    protos.sort(key=lambda p: tidx[p[1]])
    pidx = {s: i for i, (s, _r) in enumerate(protos)}
    methods = [(CALLER, 'go', 'V'), (TARGET, 'run', 'V'), (STRING, 'length', 'I')]
    methods.sort(key=lambda m: (tidx[m[0]], sidx[m[1]], pidx[m[2]]))
    midx = {(c, n): i for i, (c, n, _r) in enumerate(methods)}

    insns_go = [0x71, midx[(TARGET, 'run')], 0] * 2 + [0x000E]
    insns_run = [0x106E, midx[(STRING, 'length')], 0] * 3 + [0x000E]

    off = 0x70
    string_ids_off = off
    off += 4 * len(strings)
    type_ids_off = off
    off += 4 * len(types)
    proto_ids_off = off
    off += 12 * len(protos)
    method_ids_off = off
    off += 8 * len(methods)
    class_defs_off = off
    off += 32 * 2
    data_off = off

    data = bytearray()

    def align(n):
        while len(data) % n:
            data.append(0)

    str_offs = []
    for s in strings:
        str_offs.append(data_off + len(data))
        data += string_data(s)

    align(4)
    code_go_off = data_off + len(data)
    data += code_item(0, 0, insns_go)
    align(4)
    code_run_off = data_off + len(data)
    data += code_item(1, 1, insns_run)
    align(4)

    cd_go_off = data_off + len(data)
    data += class_data([(midx[(CALLER, 'go')], 0x0009, code_go_off)])
    cd_run_off = data_off + len(data)
    data += class_data([(midx[(TARGET, 'run')], 0x0009, code_run_off)])

    string_ids = b''.join(p32(str_offs[i]) for i in range(len(strings)))
    type_ids = b''.join(p32(sidx[t]) for t in types)
    proto_ids = b''.join(p32(sidx[sh]) + p32(tidx[ret]) + p32(0)
                         for sh, ret in protos)
    method_ids = b''.join(p16(tidx[c]) + p16(pidx[r]) + p32(sidx[n])
                          for c, n, r in methods)

    def class_def(class_idx, super_idx, cd_off):
        return (p32(class_idx) + p32(0x0001) + p32(super_idx) + p32(0)
                + p32(0xFFFFFFFF) + p32(0) + p32(cd_off) + p32(0))

    classes = sorted([(CALLER, cd_go_off), (TARGET, cd_run_off)],
                     key=lambda c: tidx[c[0]])
    class_defs = b''.join(class_def(tidx[c], tidx[OBJECT], cdo) for c, cdo in classes)

    h = bytearray(0x70)
    h[0:8] = b'dex\n035\x00'
    h[32:36] = p32(data_off + len(data))
    h[36:40] = p32(0x70)
    h[40:44] = p32(0x12345678)
    h[56:60] = p32(len(strings))
    h[60:64] = p32(string_ids_off)
    h[64:68] = p32(len(types))
    h[68:72] = p32(type_ids_off)
    h[72:76] = p32(len(protos))
    h[76:80] = p32(proto_ids_off)
    h[80:84] = p32(0)
    h[84:88] = p32(method_ids_off)
    h[88:92] = p32(len(methods))
    h[92:96] = p32(method_ids_off)
    h[96:100] = p32(2)
    h[100:104] = p32(class_defs_off)
    h[104:108] = p32(len(data))
    h[108:112] = p32(data_off)
    return bytes(h) + string_ids + type_ids + proto_ids + method_ids \
        + class_defs + bytes(data)


SELF_TEST_SMALI = """.class public Lcom/example/Target;
.super Ljava/lang/Object;

.method public static run()V
    .registers 1
    invoke-virtual {v0}, Ljava/lang/String;->length()I
    invoke-virtual {v0}, Ljava/lang/String;->length()I
    invoke-static {}, Lcom/example/Target;->run()V
    return-void
.end method
"""


def self_test():
    """Offline self-test: a built-in fixture dex plus a built-in smali file."""
    import contextlib
    import io
    import shutil
    import tempfile

    checks = 0
    tmp = tempfile.mkdtemp(prefix='find_refs-selftest-')

    def run(argv):
        old = sys.argv
        sys.argv = argv
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = main()
        finally:
            sys.argv = old
        return rc, out.getvalue()

    def pat(needle):
        esc = re.escape(needle)
        return re.compile(REF_RE_TMPL % (esc, esc, esc, esc, esc))

    try:
        dex_path = os.path.join(tmp, 'fixture.dex')
        with open(dex_path, 'wb') as fh:
            fh.write(_fixture_dex())
        smali_path = os.path.join(tmp, 'Target.smali')
        with open(smali_path, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(SELF_TEST_SMALI)

        # 1) the fixture really is a structurally valid dex
        dex, _entry = load_dex(dex_path)
        assert dex.check() == [], dex.check()
        assert list(dex.class_names()) == ['Lcom/example/Caller;',
                                           'Lcom/example/Target;'], list(dex.class_names())
        checks += 1

        # 2) dex-side counts: the answers written down in the fixture, not "some hits"
        hits = scan_dex(dex, 'Ljava/lang/String;->length')
        assert len(hits) == 3, len(hits)
        assert all(rendered == 'Ljava/lang/String;->length()I' for _o, _w, rendered in hits)
        assert all(owner == 'Lcom/example/Target;->run()V' for _o, owner, _r in hits)
        assert len(scan_dex(dex, 'Lcom/example/Target;->run')) == 2
        assert len(scan_dex(dex, 'Lcom/example/Target;')) == 2
        checks += 1

        # 3) smali-side counts answer the same question identically
        smali_hits = scan_smali(smali_path, pat('Ljava/lang/String;->length'))
        assert len(smali_hits) == 2, len(smali_hits)
        assert smali_hits[0][1] == '.method public static run()V', smali_hits[0][1]
        assert len(scan_smali(smali_path, pat('Lcom/example/Target;->run'))) == 1
        checks += 1

        # 4) unreadable input is refused instead of reported as zero references
        empty = os.path.join(tmp, 'empty')
        os.makedirs(empty)
        with open(os.path.join(empty, 'notes.txt'), 'w') as fh:
            fh.write('nothing here\n')
        try:
            gather(empty)
            raise AssertionError('gather() accepted a directory with nothing to scan')
        except ValueError:
            pass
        try:
            gather(os.path.join(tmp, 'nope.bin'))
            raise AssertionError('gather() accepted an unsupported extension')
        except ValueError:
            pass
        assert gather(smali_path) == ([smali_path], [], [])
        checks += 1

        # 5) CLI: found -> 0 with the right total, not-found -> 1
        rc, text = run(['find_refs.py', dex_path, 'Lcom/example/Target;->run'])
        assert rc == EXIT_FOUND, rc
        assert '[total refs] 2 across 1 files' in text, text
        rc, text = run(['find_refs.py', dex_path, 'Lcom/example/Nothing;->here'])
        assert rc == EXIT_NO_MATCH, rc
        assert 'found no reference' in text, text
        checks += 1

        print(json.dumps({'ok': True, 'checks': checks, 'tool': 'find_refs.py'}))
        return 0
    except Exception as exc:
        print(json.dumps({'ok': False, 'checks': checks, 'tool': 'find_refs.py',
                          'reason': '%s: %s' % (type(exc).__name__, exc)}))
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()
    ap = argparse.ArgumentParser(
        description='Count and list references to a method/field/class, in a smali '
                    'tree, a .dex, a directory of either, or an .apk.')
    ap.add_argument('root', help='.smali file, .dex file, directory, or archive')
    ap.add_argument('needle', help='e.g. Lcom/pkg/Helper;->showAd(...)V, '
                                   'Lcom/pkg/Helper;, or Lcom/pkg/Helper;->count:I')
    ap.add_argument('--count-only', action='store_true')
    ap.add_argument('--max-print', type=int, default=60)
    a = ap.parse_args()

    esc = re.escape(a.needle)
    # match the needle plus one more char so we do not match a longer prefix
    pat = re.compile(REF_RE_TMPL % (esc, esc, esc, esc, esc))

    try:
        smali_paths, dex_paths, archives = gather(a.root)
    except ValueError as exc:
        print('[error] %s' % exc)
        return EXIT_BAD_INPUT

    per_file = []          # (count, label, hits)
    scanned = 0
    unreadable = []

    for path in smali_paths:
        hits = scan_smali(path, pat)
        scanned += 1
        if hits:
            per_file.append((len(hits), path, hits))

    for path in dex_paths + archives:
        try:
            sources = dex_sources(path)
        except (ValueError, OSError, zipfile.BadZipFile) as exc:
            unreadable.append('%s (%s)' % (path, exc))
            continue
        for label, dex in sources:
            problems = dex.check()
            if problems:
                unreadable.append('%s (%s)' % (label, problems[0]))
                continue
            hits = scan_dex(dex, a.needle)
            scanned += 1
            if hits:
                per_file.append((len(hits), label, hits))

    if scanned == 0:
        print('[error] nothing readable was scanned under %s' % a.root)
        for u in unreadable:
            print('  unreadable: %s' % u)
        print('        Input was refused rather than reported as zero references, '
              'because the two are not the same answer.')
        return EXIT_BAD_INPUT

    total = sum(c for c, _l, _h in per_file)
    per_file.sort(key=lambda row: row[0], reverse=True)
    print('[scanned] %d file(s) (%d smali, %d dex)'
          % (scanned, len(smali_paths), scanned - len(smali_paths)))
    print('[total refs] %d across %d files' % (total, len(per_file)))
    for u in unreadable:
        print('[unreadable] %s' % u)
    print()

    printed = 0
    for cnt, label, hits in per_file:
        print('%-70s %d' % (label, cnt))
        if a.count_only:
            continue
        for off, owner, rendered in hits:
            if printed >= a.max_print:
                print('  ... (truncated)')
                return EXIT_FOUND
            print('    in %s' % owner)
            print('      %s' % rendered)
            printed += 1

    if total == 0:
        print('[note] scanned %d file(s) and found no reference to %r. Check the '
              'descriptor prefix "L...;", the exact obfuscated name, and whether the '
              'behaviour lives in another dex or in native code.'
              % (scanned, a.needle))
        return EXIT_NO_MATCH
    return EXIT_FOUND


if __name__ == '__main__':
    sys.exit(main())
