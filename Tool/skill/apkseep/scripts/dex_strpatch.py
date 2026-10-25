#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Byte-level, in-place patch of a string constant inside a dex — no smali round-trip.

Why not a smali round-trip: a disassemble -> reassemble of a whole tree can damage
R8-optimized output in ways the class table does not show. Observed symptom: a synthetic
access bridge lost its interface/class relationship, producing
IncompatibleClassChangeError ("Found interface X, but class was expected") at runtime even
though class_defs and access_flags looked untouched. See references/pitfalls.md P3.

What this script does instead (zero structural change to the dex):
  1. Replaces the target string with another of **exactly equal byte length**. Equal length
     keeps the string_data_item uleb128 length prefix unchanged, so offsets, indices and
     every table stay exactly where they were.
  2. Recomputes the dex header signature (SHA-1, from offset 32) and checksum (adler32,
     from offset 12).

Use only when the replacement can be equal-length. Otherwise use a method-level dex API
rewrite (references/dex-patching.md, technique 1).

Usage: python dex_strpatch.py <in.dex> <out.dex> <old_str> <new_str>
Requires len(new) == len(old) in UTF-8 bytes, and exactly one occurrence of old in the dex.
"""
import hashlib
import json
import os
import shutil
import struct
import sys
import tempfile
import zlib


def _uleb128(data, off):
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


def _read_strings(data):
    off = struct.unpack('<I', data[0x3C:0x40])[0]
    size = struct.unpack('<I', data[0x38:0x3C])[0]
    out = []
    for i in range(size):
        sdata_off = struct.unpack('<I', data[off + i * 4: off + i * 4 + 4])[0]
        n, p = _uleb128(data, sdata_off)
        out.append((sdata_off, bytes(data[p:p + n])))
    return out


def _order_ok(data, off, ob, nb):
    """Check whether replacing `ob` with `nb` still satisfies the string_ids ordering rule.

    Note: string_ids stores the offset of each string_data_item — i.e. the position of the
    **length prefix** (a few bytes ahead of the UTF-8 payload), not of the text itself — so
    matching by string-data offset directly is not possible; this matches the entry by
    content instead.
    """
    entries = _read_strings(data)
    idx = None
    for i, (_sdata_off, raw) in enumerate(entries):
        if raw == ob:
            idx = i
            break
    if idx is None:
        print('[order] target string not found in string_ids, skip check')
        return True
    prev = entries[idx - 1][1] if idx > 0 else None
    nxt = entries[idx + 1][1] if idx + 1 < len(entries) else None
    if prev is not None and nb <= prev:
        print('[order] FAIL: new %r <= prev %r' % (nb, prev))
        return False
    if nxt is not None and nb >= nxt:
        print('[order] FAIL: new %r >= next %r' % (nb, nxt))
        return False
    print('[order] OK: %r < %r < %r' % (prev, nb, nxt))
    return True


def _mini_dex(strings):
    """dex-shaped bytes with a real, correctly ordered string_ids table.

    Only the tables this tool reads are populated (magic, 0x38/0x3C, string_ids,
    string_data_items) -- exactly what the in-place patcher touches -- so the
    fixture pins the contract without shipping a sample dex.
    """
    ids_off = 0x70
    data_off = ids_off + 4 * len(strings)
    ids = []
    blob = b''
    for s in strings:
        raw = s.encode('utf-8')
        n = len(raw)
        prefix = bytearray()
        while True:
            b = n & 0x7F
            n >>= 7
            prefix.append(b | (0x80 if n else 0))
            if not n:
                break
        ids.append(data_off + len(blob))
        blob += bytes(prefix) + raw + b'\x00'
    hdr = bytearray(ids_off)
    hdr[0:8] = b'dex\n035\x00'
    hdr[0x38:0x3C] = struct.pack('<I', len(strings))
    hdr[0x3C:0x40] = struct.pack('<I', ids_off)
    body = bytes(hdr) + b''.join(struct.pack('<I', o) for o in ids) + blob
    # file_size, so the fixture is a self-consistent dex image
    return body[:0x20] + struct.pack('<I', len(body)) + body[0x24:]


def self_test():
    """Offline self-test: built-in bytes only, no network, no external tools."""
    checks = 0
    tmp = tempfile.mkdtemp(prefix='dex_strpatch-selftest-')

    def run(argv):
        """Call main() with a patched argv; the tool's own prints are captured, not shown."""
        import contextlib
        import io
        old = sys.argv
        sys.argv = argv
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                return main()
        finally:
            sys.argv = old

    try:
        src = os.path.join(tmp, 'in.dex')
        with open(src, 'wb') as fh:
            fh.write(_mini_dex(['aaa', 'com.old.host', 'zzz']))

        # 1) ULEB128 length prefix: the 2-byte form must decode to 128
        assert _uleb128(b'\x80\x01', 0) == (128, 2), _uleb128(b'\x80\x01', 0)
        checks += 1

        # 2) string_ids read back in table order, with their data offsets
        entries = _read_strings(bytearray(open(src, 'rb').read()))
        assert [raw for _off, raw in entries] == [b'aaa', b'com.old.host', b'zzz'], entries
        checks += 1

        # 3) an equal-length patch lands on the exact byte offset and re-signs
        dst = os.path.join(tmp, 'out.dex')
        before = open(src, 'rb').read()
        off = before.find(b'com.old.host')
        rc = run(['dex_strpatch.py', src, dst, 'com.old.host', 'com.new.host'])
        assert rc == 0, rc
        after = open(dst, 'rb').read()
        assert len(after) == len(before), (len(before), len(after))
        assert after[off:off + 12] == b'com.new.host', after[off:off + 12]
        # nothing but the string, the signature and the checksum moved
        assert after[:8] == before[:8], 'magic/checksum area rewritten unexpectedly'
        assert after[32:off] == before[32:off] and after[off + 12:] == before[off + 12:]
        assert hashlib.sha1(after[32:]).digest() == after[12:32], 'signature not refreshed'
        assert zlib.adler32(after[12:]) & 0xFFFFFFFF == struct.unpack('<I', after[8:12])[0], \
            'checksum not refreshed'
        checks += 1

        # 4) a length change is refused (it would move every offset)
        bad = os.path.join(tmp, 'bad.dex')
        rc = run(['dex_strpatch.py', src, bad, 'com.old.host', 'com.new'])
        assert rc == 1, rc
        assert not os.path.exists(bad), 'a refused patch still wrote an output file'
        checks += 1

        # 5) a non-unique target is refused rather than patched twice
        dup = os.path.join(tmp, 'dup.dex')
        with open(dup, 'wb') as fh:
            fh.write(_mini_dex(['aaa', 'dup', 'dup', 'zzz']))
        rc = run(['dex_strpatch.py', dup, os.path.join(tmp, 'dup_out.dex'), 'dup', 'day'])
        assert rc == 1, rc
        checks += 1

        # 6) a replacement that would break string_ids ordering is refused
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            ordered = _order_ok(bytearray(_mini_dex(['aaa', 'mmm', 'zzz'])), 0,
                                b'mmm', b'zzz1')
        assert ordered is False, 'an out-of-order replacement was accepted'
        checks += 1

        print(json.dumps({'ok': True, 'checks': checks, 'tool': 'dex_strpatch.py'}))
        return 0
    except Exception as exc:
        print(json.dumps({'ok': False, 'checks': checks, 'tool': 'dex_strpatch.py',
                          'reason': '%s: %s' % (type(exc).__name__, exc)}))
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()
    if len(sys.argv) > 1 and sys.argv[1] in ('-h', '--help'):
        print(__doc__)
        return 0
    if len(sys.argv) < 5:
        print('error: needs 4 arguments, got %d\n' % (len(sys.argv) - 1))
        print(__doc__)
        return 2
    src, dst, old, new = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    ob, nb = old.encode('utf-8'), new.encode('utf-8')
    if len(ob) != len(nb):
        print('[FAIL] length mismatch: %d vs %d (must be equal)' % (len(ob), len(nb)))
        return 1
    data = bytearray(open(src, 'rb').read())
    if data[:8] != b'dex\n035\x00' and data[:4] != b'dex\n':
        print('[warn] unexpected magic: %r' % bytes(data[:8]))
    n = data.count(ob)
    print('[info] occurrences of %r = %d' % (old, n))
    if n != 1:
        print('[FAIL] expected exactly 1 occurrence')
        return 1
    off = data.find(ob)

    # The dex spec requires string_ids to be ordered by string content. An equal-length
    # replacement moves no offset, but it does change where this entry sits in that ordering
    # — and once it lands out of order the whole dex is rejected by the ClassLoader
    # (symptom: ClassNotFoundException naming the Application class). So validate the
    # interval before writing.
    if not _order_ok(data, off, ob, nb):
        print('[FAIL] replacement would break string_ids ordering. '
              'Pick a string that stays between its two neighbours.')
        return 1

    data[off:off + len(ob)] = nb
    print('[ok] patched at offset 0x%x: %r -> %r' % (off, old, new))

    # signature = SHA-1 over data[32:], stored at 12..32
    sig = hashlib.sha1(bytes(data[32:])).digest()
    data[12:32] = sig
    # checksum = adler32 over data[12:], stored at 8..12 (little endian)
    chk = zlib.adler32(bytes(data[12:])) & 0xFFFFFFFF
    data[8:12] = struct.pack('<I', chk)
    print('[ok] signature=%s checksum=0x%08x' % (sig.hex(), chk))

    open(dst, 'wb').write(bytes(data))
    print('[ok] wrote %s (%d bytes)' % (dst, len(data)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
