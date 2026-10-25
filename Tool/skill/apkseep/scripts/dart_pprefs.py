#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dart AOT object-pool reference index: pool offset -> the instructions that load it.

WHY THIS EXISTS
---------------
blutter's `pp.txt` tells you what is *in* the object pool (strings, types, closures,
field metadata) but not which code reads it. "Who uses this string" is the most frequent
question in Dart AOT work, and it needs an index you build once and query constantly.

Building that index with a general-purpose disassembler is the trap here: decoding every
instruction of a multi-MB `.text` with detail enabled and asking for per-instruction
register writes costs minutes of CPU and 1-2 GB of peak memory, and on a 16 GB host it is
indistinguishable from a hang -- no output, no progress, nothing to interrupt. Only three
encodings can reach the pool, so this decodes them from the raw 32-bit words instead:
seconds, and a flat memory profile.

Recognised forms (AArch64, little endian), with x27 = pool base:

    add  xD, x27, #imm12, lsl #12   ->   xD = x27 + (imm12 << 12)
    ldr  XD, [xN, #imm12 * size]    ->   GP register file, size from bits 31-30
    ldr  DD, [xN, #imm12 * size]    ->   SIMD&FP register file (bit 26 set)
    ldur XD/DD, [xN, #simm9]        ->   unscaled variant, both files

Both register files must be covered. Restricting the LDR form to the GP words
(0xF94/0xB94) silently drops `ldr dN, [x27, #imm]` (0xFD400000), which is how every
*double* constant in the pool is read -- an entire class of references disappears from
the index. On a real Dart 3.6.0 libapp.so that was 302 pool offsets and 1,802 sites lost
(measured, see the verification record); one of them had 150 reference sites that would
all have been reported as zero.

A reference is either a direct load whose base is x27, or a load consuming the register an
ADD just derived from x27. The compiler emits that pair back to back, so a small window
keeps it exact without full liveness analysis.

USAGE
-----
    python dart_pprefs.py libapp.so pp_refs.json              # build the index
    python dart_pprefs.py --lookup pp_refs.json 0x1d1a8 0xc9d0
    python dart_pprefs.py libapp.so out.json --window 5       # widen the ADD->LDR window

NOTES
-----
* Offsets are **pool** offsets -- the `pp+0x...` space used by pp.txt -- not file offsets.
  Keep the two spaces apart in your notes; conflating them costs hours.
* One offset commonly has many reference sites. Count them before editing the entry:
  a shared constant will change behaviour everywhere at once (see references/dart-aot.md).
"""
import argparse
import json
import os
import struct
import sys

POOL_REG = 27          # x27: object-pool base in Dart AOT on arm64
DEFAULT_WINDOW = 3     # instructions an ADD-derived address may survive


def text_section(path):
    """Return (vaddr, bytes) of .text, parsing ELF64 section headers directly."""
    blob = open(path, 'rb').read()
    if blob[:4] != b'\x7fELF':
        raise SystemExit('not an ELF file: %s' % path)
    if blob[4] != 2:
        raise SystemExit('not ELF64: %s' % path)
    e_shoff = struct.unpack_from('<Q', blob, 0x28)[0]
    e_shentsize = struct.unpack_from('<H', blob, 0x3A)[0]
    e_shnum = struct.unpack_from('<H', blob, 0x3C)[0]
    e_shstrndx = struct.unpack_from('<H', blob, 0x3E)[0]

    def sh(i):
        return struct.unpack_from('<IIQQQQ', blob, e_shoff + i * e_shentsize)

    _, _, _, _, shstr_off, shstr_size = sh(e_shstrndx)
    strs = blob[shstr_off:shstr_off + shstr_size]
    for i in range(e_shnum):
        name, _typ, _flags, addr, off, size = sh(i)
        end = strs.find(b'\x00', name)
        if strs[name:end].decode('ascii', 'replace') == '.text':
            return addr, blob[off:off + size]
    raise SystemExit('.text not found; pass --text with its virtual address')


def sx(value, bits):
    m = 1 << (bits - 1)
    return (value ^ m) - m


def scan(text_addr, blob, window):
    refs = {}
    pending = {}
    words = struct.unpack_from('<%dI' % (len(blob) // 4), blob, 0)

    for i, w in enumerate(words):
        addr = text_addr + i * 4

        # add xD, x27, #hi, lsl #12
        if w & 0xFFC00000 == 0x91400000 and (w >> 5) & 0x1F == POOL_REG:
            # Keep the shift out of the mask expression: `a & m << n` binds as
            # `a & (m << n)` in Python, which silently produces a wrong base.
            imm = (w >> 10) & 0xFFF
            pending[w & 0x1F] = [imm << 12, i]
            continue

        # LDR (immediate) / LDUR across BOTH register files. Bits 31-30 give the access
        # size and therefore the immediate scale; bit 26 selects the SIMD&FP file.
        # Matching only the GP words (0xF94/0xB94) drops `ldr dN, [x27, #imm]`
        # (0xFD400000) and with it every double constant read from the pool.
        ldr_scale = {0xF9400000: 3, 0xB9400000: 2, 0x79400000: 1, 0x39400000: 0,
                     0xFD400000: 3, 0xBD400000: 2, 0x7D400000: 1, 0x3DC00000: 4,
                     }.get(w & 0xFFC00000)
        ldur = (w & 0xFFE00C00) in (0xF8400000, 0xB8400000, 0x78400000, 0x38400000,
                                    0xFC400000, 0xBC400000, 0x7C400000, 0x3C400000)

        if ldr_scale is not None or ldur:
            rn = (w >> 5) & 0x1F
            rd = w & 0x1F
            if ldr_scale is not None:
                disp = ((w >> 10) & 0xFFF) << ldr_scale
            else:
                disp = sx((w >> 12) & 0x1FF, 9)
            if rn == POOL_REG:
                refs.setdefault(disp, []).append(addr)
            elif rn in pending:
                base, seq = pending.pop(rn)
                if i - seq <= window:
                    refs.setdefault(base + disp, []).append(addr)
            pending.pop(rd, None)   # this load overwrote rd
            continue

        if w & 0xFFC00000 in (0x91000000, 0x91400000):
            pending.pop(w & 0x1F, None)
        for r in [r for r, (_o, s) in pending.items() if i - s > window]:
            del pending[r]

    return refs


def build(so, out, window):
    text_addr, blob = text_section(so)
    refs = scan(text_addr, blob, window)
    with open(out, 'w', encoding='utf-8') as fh:
        json.dump({hex(k): v for k, v in refs.items()}, fh)
    total = sum(len(v) for v in refs.values())
    print('.text vaddr=0x%x  bytes=%d' % (text_addr, len(blob)))
    print('distinct pool offsets : %d' % len(refs))
    print('reference sites       : %d' % total)
    for off in sorted(refs, key=lambda k: -len(refs[k]))[:8]:
        print('   pp+0x%-8x %4d sites' % (off, len(refs[off])))
    print('written %s' % out)


def lookup(path, offsets):
    refs = {int(k, 16): v for k, v in json.load(open(path, encoding='utf-8')).items()}
    for spec in offsets:
        off = int(spec, 16)
        sites = sorted(refs.get(off, []))
        print('pp+0x%x: %d ref site(s)' % (off, len(sites)))
        for s in sites:
            print('   0x%x' % s)


def self_test():
    """Offline self-test: a generated ELF64 image and hand-encoded AArch64 words.

    The claims worth asserting are the ones that were silently wrong once: the ADD->LDR
    pair resolves to the pool offset, BOTH register files are covered (the SIMD&FP `ldr
    dN, [x27, #imm]` form is why double constants used to vanish from the index), and the
    ADD->LDR window is bounded. Each is asserted on `scan()`'s returned offsets.
    """
    import contextlib
    import io
    import json as _json
    import tempfile

    def mini_elf64(text, addr=0x1000):
        shstr = b"\x00.text\x00.shstrtab\x00"
        text_off = 64
        shstr_off = text_off + len(text)
        shstr_off += (-shstr_off) % 8
        e_shoff = shstr_off + len(shstr)
        e_shoff += (-e_shoff) % 8
        head = bytearray(64)
        head[0:4] = b"\x7fELF"
        head[4] = 2          # ELFCLASS64
        head[5] = 1          # ELFDATA2LSB
        head[6] = 1
        struct.pack_into('<H', head, 0x10, 2)          # e_type = ET_EXEC
        struct.pack_into('<H', head, 0x12, 183)       # e_machine = AArch64
        struct.pack_into('<Q', head, 0x28, e_shoff)
        struct.pack_into('<H', head, 0x34, 64)
        struct.pack_into('<H', head, 0x3A, 64)
        struct.pack_into('<H', head, 0x3C, 3)
        struct.pack_into('<H', head, 0x3E, 2)
        blob = head + text
        blob += b"\x00" * (shstr_off - len(blob))
        blob += shstr
        blob += b"\x00" * (e_shoff - len(blob))
        blob += b"\x00" * 64
        blob += struct.pack('<IIQQQQ', 1, 1, 6, addr, text_off, len(text))
        blob += b"\x00" * 24
        blob += struct.pack('<IIQQQQ', 7, 3, 0, 0, shstr_off, len(shstr))
        blob += b"\x00" * 24
        return bytes(blob)

    def add_xd_x27(rd, imm12, shift12=True):
        return 0x91000000 | (0x400000 if shift12 else 0) | (imm12 << 10) | (POOL_REG << 5) | rd

    def ldr_gp(rt, rn, disp):
        return 0xF9400000 | ((disp >> 3) << 10) | (rn << 5) | rt

    def ldr_fp(rt, rn, disp):
        return 0xFD400000 | ((disp >> 3) << 10) | (rn << 5) | rt

    checks = 0
    tmpdir = tempfile.mkdtemp(prefix='dart-pprefs-selftest-')
    try:
        assert POOL_REG == 27 and DEFAULT_WINDOW == 3
        checks += 1

        assert sx(0x1FF, 9) == -1, sx(0x1FF, 9)
        assert sx(0x1F, 5) == -1, sx(0x1F, 5)
        assert sx(0x10, 9) == 16, sx(0x10, 9)
        checks += 1

        addr_base = 0x1000
        words = [
            add_xd_x27(1, 0x9D),                  # add x1, x27, #0x9d, lsl #12
            ldr_gp(2, 1, 0x10),                   # ldr x2, [x1, #0x10] -> 0x9d010
            ldr_gp(3, POOL_REG, 0x20),            # ldr x3, [x27, #0x20] -> 0x20
            ldr_fp(5, POOL_REG, 0x30),            # ldr d5, [x27, #0x30] -> 0x30
            # ADD-derived base that a LDR only picks up inside the window
            add_xd_x27(4, 0x1),                   # add x4, x27, #0x1, lsl #12
            0xD503201F, 0xD503201F, 0xD503201F, 0xD503201F,   # 4 nops: distance 5
            ldr_gp(6, 4, 0x8),                    # ldr x6, [x4, #0x8]
        ]
        blob = b''.join(struct.pack('<I', w) for w in words)

        refs = scan(addr_base, blob, 3)
        assert set(refs) == {0x9D010, 0x20, 0x30}, sorted(hex(k) for k in refs)
        assert refs[0x9D010] == [addr_base + 4], refs[0x9D010]
        assert refs[0x20] == [addr_base + 8], refs[0x20]
        assert refs[0x30] == [addr_base + 12], refs[0x30]
        checks += 1

        # The GP-only mask (0xF94/0xB94) is exactly the defect the module documents: it
        # drops `ldr dN, [x27, #imm]`, so the SIMD&FP hit above must not be optional.
        assert 0x30 in refs, 'the SIMD&FP register file was not scanned'
        assert scan(addr_base, blob, 5).get(0x1008), \
            'a window of 5 must reach the ADD-derived load'
        assert 0x1008 not in scan(addr_base, blob, 3), \
            'the ADD->LDR window is not bounded'
        checks += 1

        ldur = 0xF8400000 | (27 << 5) | 7        # ldur x7, [x27, #0]  (unscaled form)
        assert 0 in scan(addr_base, struct.pack('<I', ldur), 3), \
            'the LDUR form is not recognised'
        checks += 1

        so = os.path.join(tmpdir, 'libapp.so')
        with open(so, 'wb') as fh:
            fh.write(mini_elf64(blob))
        text_addr, text_blob = text_section(so)
        assert (text_addr, text_blob) == (addr_base, blob), (hex(text_addr), len(text_blob))
        checks += 1

        out_json = os.path.join(tmpdir, 'pp_refs.json')
        with contextlib.redirect_stdout(io.StringIO()):
            build(so, out_json, DEFAULT_WINDOW)
        written = _json.load(open(out_json, encoding='utf-8'))
        assert written.get(hex(0x9D010)) == [addr_base + 4], written
        assert written.get(hex(0x30)) == [addr_base + 12], written
        checks += 1

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lookup(out_json, ['0x9d010', '0xdead'])
        lines = [ln for ln in out.getvalue().splitlines() if ln.strip()]
        assert lines[0] == 'pp+0x9d010: 1 ref site(s)', lines
        assert lines[1] == '   0x1004', lines
        assert lines[2] == 'pp+0xdead: 0 ref site(s)', lines
        checks += 1

        with open(os.path.join(tmpdir, 'bad.bin'), 'wb') as fh:
            fh.write(b'\x7fELX' + b'\x00' * 64)
        try:
            text_section(os.path.join(tmpdir, 'bad.bin'))
        except SystemExit as exc:
            assert 'not an ELF file' in str(exc), exc
        else:
            raise AssertionError('a non-ELF input was accepted')
        checks += 1
    except Exception as exc:          # a failed assertion IS the signal: report, rc=1
        print(json.dumps({"ok": False, "checks": checks, "tool": "dart_pprefs.py",
                          "reason": "%s: %s" % (type(exc).__name__, exc)},
                         ensure_ascii=False))
        return 1
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    print(json.dumps({"ok": True, "checks": checks, "tool": "dart_pprefs.py"},
                     ensure_ascii=False))
    return 0


def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()

    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('sample', nargs='?', help='libapp.so (build mode)')
    ap.add_argument('out', nargs='?', help='output json (build mode)')
    ap.add_argument('--lookup', metavar='REFS_JSON', help='query an existing index')
    ap.add_argument('--window', type=int, default=DEFAULT_WINDOW,
                    help='instructions an ADD-derived address may survive (default %d)'
                         % DEFAULT_WINDOW)
    ap.add_argument('--self-test', action='store_true', dest='self_test',
                    help='run offline self-test and exit (no sample needed)')
    a = ap.parse_args()

    if a.lookup:
        rest = sys.argv[sys.argv.index('--lookup') + 2:]
        if not rest:
            raise SystemExit('give at least one hex pool offset')
        lookup(a.lookup, rest)
        return 0
    if not (a.sample and a.out):
        raise SystemExit('usage: dart_pprefs.py <libapp.so> <out.json>')
    build(a.sample, a.out, a.window)
    return 0


if __name__ == '__main__':
    sys.exit(main())
