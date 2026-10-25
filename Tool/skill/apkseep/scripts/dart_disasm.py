#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Annotated, windowed disassembly of a Dart AOT snapshot, plus a caller index.

WHY THIS EXISTS
---------------
Two things make Dart AOT code readable at all:

  1. **Pool annotations.** A raw `ldr x2, [x27, #0x9d0]` is meaningless; annotated with the
     pool entry it becomes `"vipflag"` and the surrounding code explains itself. This tool
     resolves those loads and prints what they point at, including how many other sites
     reference the same entry.
  2. **Windowed disassembly.** Decoding an entire multi-MB `.text` in one pass is how a host
     gets pinned at 1-2 GB and the run looks like a hang. Disassemble only the ranges you
     care about -- that is what this tool does, and it is not a limitation but the method.

Booleans are annotated too: Dart materialises `true`/`false` as small offsets from the null
register, so `add x0, x22, #0x20` is marked TRUE and `#0x30` is marked FALSE. Those are the
cheapest patch sites in the whole snapshot.

The caller index answers the other half of every question -- "what calls this function".
It is built from B/BL target arithmetic on the raw words, so it needs no disassembler at all
and finishes in seconds.

USAGE
-----
    # a window around one address (default: 0x180 before, 0x220 after)
    python dart_disasm.py libapp.so --pp pp.txt --refs pp_refs.json 0x26e390

    # an explicit range
    python dart_disasm.py libapp.so --pp pp.txt --refs pp_refs.json --range 0x64f310 0x64f3e0

    # widen / narrow the window
    python dart_disasm.py libapp.so --refs pp_refs.json 0x64f1bc --before 0x80 --after 0x40

    # caller index
    python dart_disasm.py libapp.so --build-index callers.json
    python dart_disasm.py libapp.so --index callers.json 0x26e230 0x64f0f0

INPUTS
------
  * `--pp` is the decompiler's pool listing (blutter `pp.txt`): lines shaped
    `[pp+0x9d0] String: "vipflag"`. Without it, loads are annotated with the raw offset only.
  * `--refs` is the pool-offset -> code-site index built by `dart_pprefs.py`.

Requires `capstone` for disassembly; the caller index works without it.
"""
import argparse
import json
import os
import re
import struct
import sys

POOL_REG = 27
BOOL_TRUE, BOOL_FALSE = 0x20, 0x30
PP_LINE = re.compile(r'^\[(pp\+0x[0-9a-f]+)\](.*)$')


def text_section(path):
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
        name, _t, _f, addr, off, size = sh(i)
        end = strs.find(b'\x00', name)
        if strs[name:end].decode('ascii', 'replace') == '.text':
            return addr, blob[off:off + size]
    raise SystemExit('.text not found')


def load_pp(path):
    pool = {}
    if not path or not os.path.exists(path):
        return pool
    for line in open(path, encoding='utf-8', errors='replace'):
        m = PP_LINE.match(line.rstrip('\n'))
        if m:
            pool[int(m.group(1)[5:], 16)] = m.group(2).strip()[:120]
    return pool


def load_refs(path):
    if not path or not os.path.exists(path):
        return {}
    return {int(k, 16): v for k, v in json.load(open(path, encoding='utf-8')).items()}


def disasm_window(sample, addr, before, after, pp, refs):
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        print(json.dumps({"ok": False, "blocked_at": "tool-missing",
                          "reason": "capstone is required for disassembly: "
                                    "python -m pip install capstone"},
                         ensure_ascii=False))
        raise SystemExit(2)

    text_addr, blob = text_section(sample)
    end_of_text = text_addr + len(blob)
    start = max(text_addr, addr - before)
    stop = min(end_of_text, addr + after)

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True      # without this, one undecodable byte silently ends the range
    md.detail = True        # without this, operands are unavailable

    print('range 0x%x..0x%x   focus=0x%x' % (start, stop, addr))
    pending = {}
    for ins in md.disasm(blob[start - text_addr:stop - text_addr], start):
        if ins.id == 0:                      # SKIPDATA pseudo-instruction: no operands
            print('%x: %s' % (ins.address, ins.mnemonic))
            continue
        note = ''
        ops = ins.operands
        rn = ins.reg_name
        if (ins.mnemonic == 'add' and len(ops) == 3 and ops[1].type == 1
                and rn(ops[1].reg) == 'x27' and ops[2].type == 2
                and ops[2].shift.value == 12):
            pending[rn(ops[0].reg)] = ops[2].imm << 12
        elif (ins.mnemonic == 'add' and len(ops) == 3 and ops[1].type == 1
                and rn(ops[1].reg) == 'x22' and ops[2].type == 2):
            note = {BOOL_TRUE: '   ; TRUE', BOOL_FALSE: '   ; FALSE'}.get(ops[2].imm, '')
        elif ins.mnemonic in ('ldr', 'ldur') and len(ops) == 2 and ops[1].type == 3:
            base = rn(ops[1].mem.base) if ops[1].mem.base else ''
            off = None
            if base == 'x27':
                off = ops[1].mem.disp
            elif base in pending:
                off = pending.pop(base) + ops[1].mem.disp
            if off is not None:
                text = pp.get(off, '')
                sites = refs.get(off, [])
                note = '   ; pp+0x%x %s  [%d refs]' % (off, text, len(sites))
        mark = '   <<<' if abs(ins.address - addr) < 4 else ''
        print('%x: %-8s %s%s%s' % (ins.address, ins.mnemonic, ins.op_str, note, mark))


def build_index(sample, out):
    """B/BL target -> call sites, decoded arithmetically (no disassembler needed)."""
    text_addr, blob = text_section(sample)
    index = {}
    words = struct.unpack_from('<%dI' % (len(blob) // 4), blob, 0)
    for i, w in enumerate(words):
        if w & 0xFC000000 in (0x14000000, 0x94000000):
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            site = text_addr + i * 4
            index.setdefault(site + (imm << 2), []).append(site)
    with open(out, 'w', encoding='utf-8') as fh:
        json.dump({hex(k): v for k, v in index.items()}, fh)
    print('distinct targets : %d' % len(index))
    print('call sites       : %d' % sum(len(v) for v in index.values()))
    print('written %s' % out)


def lookup_index(sample, path, addrs):
    index = {int(k, 16): v for k, v in json.load(open(path, encoding='utf-8')).items()}
    for spec in addrs:
        target = int(spec, 16)
        sites = sorted(index.get(target, []))
        print('0x%x: %d caller(s)' % (target, len(sites)))
        for s in sites[:80]:
            print('   0x%x' % s)
        if len(sites) > 80:
            print('   ... %d more' % (len(sites) - 80))


def self_test():
    """Offline self-test: a generated ELF64 image, no sample and no capstone.

    `disasm_window` needs capstone, which an offline host may not have -- so the
    self-test covers the parts that must work everywhere: the ELF section walk, the
    `pp.txt` / `--refs` parsers, and the B/BL caller index, whose target arithmetic is
    decoded from raw words rather than by a disassembler. A BL at 0x1000 that targets
    0x1040 must appear in the index as exactly that, keyed by target.
    """
    import contextlib
    import io
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
        struct.pack_into('<H', head, 0x34, 64)        # e_ehsize
        struct.pack_into('<H', head, 0x3A, 64)        # e_shentsize
        struct.pack_into('<H', head, 0x3C, 3)         # e_shnum
        struct.pack_into('<H', head, 0x3E, 2)         # e_shstrndx
        blob = head + text
        blob += b"\x00" * (shstr_off - len(blob))
        blob += shstr
        blob += b"\x00" * (e_shoff - len(blob))
        blob += b"\x00" * 64                                             # SHT_NULL
        blob += struct.pack('<IIQQQQ', 1, 1, 6, addr, text_off, len(text))
        blob += b"\x00" * 24                                            # .text rest
        blob += struct.pack('<IIQQQQ', 7, 3, 0, 0, shstr_off, len(shstr))
        blob += b"\x00" * 24                                            # .shstrtab rest
        return bytes(blob)

    checks = 0
    tmpdir = tempfile.mkdtemp(prefix='dart-disasm-selftest-')
    try:
        words = [0xD503201F] * 20
        words[0] = 0x94000000 | 0x10        # bl 0x1040, from 0x1000
        words[16] = 0x14000000 | 0x10       # b 0x1080, from 0x1040
        text = b''.join(struct.pack('<I', w) for w in words)
        so = os.path.join(tmpdir, 'libapp.so')
        with open(so, 'wb') as fh:
            fh.write(mini_elf64(text))

        addr, blob = text_section(so)
        assert addr == 0x1000, hex(addr)
        assert blob == text, (len(blob), len(text))
        checks += 1

        index_path = os.path.join(tmpdir, 'callers.json')
        with contextlib.redirect_stdout(io.StringIO()):
            build_index(so, index_path)
        index = json.load(open(index_path, encoding='utf-8'))
        assert index == {hex(0x1040): [0x1000], hex(0x1080): [0x1040]}, index
        checks += 1

        pp_path = os.path.join(tmpdir, 'pp.txt')
        with io.open(pp_path, 'w', encoding='utf-8') as fh:
            fh.write('[pp+0x9d0] String: "vipflag"\n'
                     'not a pool line\n'
                     '[pp+0x1a] Object: Foo\n')
        pool = load_pp(pp_path)
        assert pool == {0x9D0: 'String: "vipflag"', 0x1A: 'Object: Foo'}, pool
        assert load_pp(None) == {} and load_pp(os.path.join(tmpdir, 'nope.txt')) == {}
        checks += 1

        refs_path = os.path.join(tmpdir, 'pp_refs.json')
        json.dump({'9d0': [4194304, 4194308]}, open(refs_path, 'w', encoding='utf-8'))
        refs = load_refs(refs_path)
        assert refs == {0x9D0: [4194304, 4194308]}, refs
        assert load_refs(None) == {} and load_refs(os.path.join(tmpdir, 'n.json')) == {}
        checks += 1

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            lookup_index(so, index_path, ['0x1040', '0x1044'])
        lines = [ln for ln in out.getvalue().splitlines() if ln.strip()]
        assert lines[0] == '0x1040: 1 caller(s)', lines
        assert lines[1] == '   0x1000', lines   # 3-space indent from lookup_index
        assert lines[2] == '0x1044: 0 caller(s)', lines
        checks += 1

        assert (POOL_REG, BOOL_TRUE, BOOL_FALSE) == (27, 0x20, 0x30)
        assert PP_LINE.match('[pp+0x9d0] String: x').group(1) == 'pp+0x9d0'
        assert PP_LINE.match(' [pp+0x9d0]') is None, 'the regex is anchored'
        checks += 1

        with open(os.path.join(tmpdir, 'not-elf.bin'), 'wb') as fh:
            fh.write(b'MZ\x90\x00 not an elf at all')
        try:
            text_section(os.path.join(tmpdir, 'not-elf.bin'))
        except SystemExit as exc:
            assert 'not an ELF file' in str(exc), exc
        else:
            raise AssertionError('a non-ELF input was accepted')
        checks += 1
    except Exception as exc:          # a failed assertion IS the signal: report, rc=1
        print(json.dumps({"ok": False, "checks": checks, "tool": "dart_disasm.py",
                          "reason": "%s: %s" % (type(exc).__name__, exc)},
                         ensure_ascii=False))
        return 1
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    print(json.dumps({"ok": True, "checks": checks, "tool": "dart_disasm.py"},
                     ensure_ascii=False))
    return 0


def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()

    ap = argparse.ArgumentParser(
        description=__doc__.split('\n')[0],
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument('sample', help='libapp.so')
    ap.add_argument('addr', nargs='*', help='hex address(es) to disassemble around')
    ap.add_argument('--pp', metavar='PP_TXT', help="decompiler pool listing (blutter pp.txt)")
    ap.add_argument('--self-test', action='store_true', dest='self_test',
                    help='run offline self-test and exit (no sample, no capstone)')
    ap.add_argument('--refs', metavar='REFS_JSON', help='index from dart_pprefs.py')
    ap.add_argument('--range', nargs=2, metavar=('START', 'END'))
    ap.add_argument('--before', default='0x180')
    ap.add_argument('--after', default='0x220')
    ap.add_argument('--build-index', metavar='OUT_JSON')
    ap.add_argument('--index', metavar='CALLERS_JSON')
    a = ap.parse_args()

    if a.build_index:
        return build_index(a.sample, a.build_index)
    if a.index:
        if not a.addr:
            raise SystemExit('give at least one hex address to look up')
        return lookup_index(a.sample, a.index, a.addr)

    pp = load_pp(a.pp)
    refs = load_refs(a.refs)
    if a.range:
        start, stop = int(a.range[0], 16), int(a.range[1], 16)
        disasm_window(a.sample, start, 0, stop - start, pp, refs)
        return 0
    if not a.addr:
        raise SystemExit('give an address, --range, --build-index, or --index')
    for spec in a.addr:
        disasm_window(a.sample, int(spec, 16),
                      int(a.before, 0), int(a.after, 0), pp, refs)
    return 0


if __name__ == '__main__':
    sys.exit(main())
