#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Encode or inject AndroidX DataStore (Preferences) protobuf entries.

WHY THIS EXISTS
---------------
Some feature gates are not decided in code but in a preferences file that the app
reads at runtime, e.g. a "free until <timestamp>" value. Changing the code alone can
then be pointless, while writing the state directly proves the hypothesis in one
shot: if the behavior changes, the key really is the gate; if it does not, the gate
is elsewhere (usually server-side).

WHAT THE FILE IS
----------------
DataStore/Preferences serializes to a protobuf on disk. On a device it lives under
the app's private directory, typically:
    <app_files_dir>/datastore/<name>.preferences_pb
and the container is:
    message PreferenceMap { map<string, Value> preferences = 1; }
    message Value { oneof { bool boolean = 1; float float = 2; int32 integer = 3;
                            int64 long = 4; string string = 5; double double = 6;
                            bytes bytes = 8; } }

The map field is the part people get wrong: every entry needs BOTH the outer
0x0A <len> (the map field itself) AND the inner 0x0A <len key> <key> +
0x12 <len value> <value>. Writing only the inner form produces a file that
deserializes into nothing, and some apps then die on the next read with an
exception that is swallowed by their crash reporter -- no stack, no clue.

Bytes writes here are the exact encoding, so this script doubles as a reference.

USAGE
-----
  # write a fresh file with one big "never expires" timestamp
  python datastore_inject.py --file example.preferences_pb \
      --key example_expiry_epoch_ms --type long --value 4102444800000

  # keep every other key from an existing file and replace/add just this one
  python datastore_inject.py --in pulled.preferences_pb --file patched.preferences_pb \
      --key example_expiry_epoch_ms --type long --value 4102444800000

  # add more than one entry
  python datastore_inject.py --file out.pb --key example_flag --type bool --value true \
      --extra example_name=hello:string

  # inspect a pulled file (what keys exist, and what they decode to)
  python datastore_inject.py --in pulled.preferences_pb --list

Deploying the result: the app must not be running while you overwrite the file
(it will rewrite the file on exit), so push, fix ownership/selinux context if
needed, then start the app. Verify by reading the key back with --list.

Pure standard library, Python 3.9+.
"""
import argparse
import io
import json
import os
import shutil
import struct
import sys
import tempfile

DEFAULT_FILE = 'example.preferences_pb'
DEFAULT_KEY = 'example_expiry_epoch_ms'
DEFAULT_VALUE = '4102444800000'   # ~2100-01-01 in ms: "far future" in either unit
TYPES = ('long', 'int', 'bool', 'float', 'double', 'string', 'bytes')

# tag = (field_number << 3) | wire_type, per the Value oneof above.
VALUE_TAG = {
    'bool': (1, 0),
    'float': (2, 5),
    'integer': (3, 0),
    'long': (4, 0),
    'string': (5, 2),
    'double': (6, 1),
    'bytes': (8, 2),
}


def varint(n):
    """Unsigned LEB128. Negative int32/int64 are encoded as 64-bit twos complement."""
    if n < 0:
        n += 1 << 64
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError('truncated varint at offset %d' % pos)
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 70:
            raise ValueError('varint too long at offset %d' % pos)


def tag_bytes(field, wire):
    return varint((field << 3) | wire)


def encode_value(kind, raw):
    """Encode the Value payload (the bytes after the inner 0x12 <len>)."""
    if kind == 'bool':
        field, wire = VALUE_TAG['bool']
        truthy = str(raw).strip().lower() in ('1', 'true', 'yes', 'on')
        return tag_bytes(field, wire) + varint(1 if truthy else 0)
    if kind in ('long', 'int'):
        field, wire = VALUE_TAG['long' if kind == 'long' else 'integer']
        return tag_bytes(field, wire) + varint(int(str(raw), 0))
    if kind == 'float':
        field, wire = VALUE_TAG['float']
        return tag_bytes(field, wire) + struct.pack('<f', float(raw))
    if kind == 'double':
        field, wire = VALUE_TAG['double']
        return tag_bytes(field, wire) + struct.pack('<d', float(raw))
    if kind == 'string':
        field, wire = VALUE_TAG['string']
        data = str(raw).encode('utf-8')
        return tag_bytes(field, wire) + varint(len(data)) + data
    if kind == 'bytes':
        field, wire = VALUE_TAG['bytes']
        data = bytes.fromhex(str(raw))
        return tag_bytes(field, wire) + varint(len(data)) + data
    raise ValueError('unknown type: %s' % kind)


def encode_entry(key, value_payload):
    """Encode one PreferenceMap entry.

    Two levels of 0x0A on purpose:
        outer: 0x0A <len(inner)>                       <- the map field (field 1)
        inner: 0x0A <len(key)> <key> 0x12 <len(value)> <value>
    Dropping the outer tag+length is the classic mistake: DataStore then
    deserializes an empty map, and the failure surfaces far away from here.
    """
    kb = key.encode('utf-8')
    inner = (tag_bytes(1, 2) + varint(len(kb)) + kb
             + tag_bytes(2, 2) + varint(len(value_payload)) + value_payload)
    return tag_bytes(1, 2) + varint(len(inner)) + inner


def split_entries(data):
    """Split a PreferenceMap into raw top-level field slices."""
    pos = 0
    entries = []
    while pos < len(data):
        start = pos
        tag, pos = read_varint(data, pos)
        wire = tag & 0x07
        if wire == 2:
            length, pos = read_varint(data, pos)
            pos += length
        elif wire == 0:
            _, pos = read_varint(data, pos)
        elif wire == 5:
            pos += 4
        elif wire == 1:
            pos += 8
        else:
            raise ValueError('unsupported wire type %d at offset %d' % (wire, start))
        if pos > len(data):
            raise ValueError('truncated field at offset %d' % start)
        entries.append((tag, data[start:pos]))
    return entries


def decode_entry(raw):
    """Return (key, value_payload) of one entry, or (None, None) if malformed."""
    try:
        pos = 0
        tag, pos = read_varint(raw, pos)
        if (tag >> 3) != 1 or (tag & 7) != 2:
            return None, None
        length, pos = read_varint(raw, pos)
        inner = raw[pos:pos + length]

        p = 0
        t1, p = read_varint(inner, p)
        if (t1 >> 3) != 1:
            return None, None
        klen, p = read_varint(inner, p)
        key = inner[p:p + klen].decode('utf-8', 'replace')
        p += klen

        t2, p = read_varint(inner, p)
        if (t2 >> 3) != 2:
            return None, None
        vlen, p = read_varint(inner, p)
        return key, inner[p:p + vlen]
    except Exception:
        return None, None


def describe_value(payload):
    """Best-effort decode of a Value payload for the --list output."""
    try:
        pos = 0
        tag, pos = read_varint(payload, pos)
        field, wire = tag >> 3, tag & 7
        if field == 1 and wire == 0:
            val, _ = read_varint(payload, pos)
            return 'bool=%s' % bool(val)
        if field == 3 and wire == 0:
            val, _ = read_varint(payload, pos)
            return 'integer=%d' % val
        if field == 4 and wire == 0:
            val, _ = read_varint(payload, pos)
            return 'long=%d' % val
        if field == 2 and wire == 5:
            return 'float=%r' % struct.unpack('<f', payload[pos:pos + 4])[0]
        if field == 6 and wire == 1:
            return 'double=%r' % struct.unpack('<d', payload[pos:pos + 8])[0]
        if field == 5 and wire == 2:
            length, pos = read_varint(payload, pos)
            return 'string=%r' % payload[pos:pos + length].decode('utf-8', 'replace')
        if field == 8 and wire == 2:
            length, pos = read_varint(payload, pos)
            return 'bytes=%s' % payload[pos:pos + length].hex()
    except Exception:
        pass
    return 'raw=%s' % payload.hex()


def parse_extra(items):
    """--extra key=value[:type] -> [(key, type, value)]"""
    out = []
    for item in items:
        if '=' not in item:
            raise SystemExit('--extra expects key=value[:type], got %r' % item)
        key, rest = item.split('=', 1)
        kind = 'string'
        if ':' in rest:
            rest, kind = rest.rsplit(':', 1)
        if kind not in TYPES:
            raise SystemExit('--extra %s: unknown type %r (choose from %s)'
                             % (key, kind, ', '.join(TYPES)))
        out.append((key, kind, rest))
    return out


def self_test():
    """Offline self-test: hand-checked varints and a known-good encoded entry.

    The byte encoding is this script's whole value, so the assertions are on BYTES and on
    the round-trip: `encode_entry` must produce the two-level 0x0A map form (the classic
    mistake is writing only the inner one, which deserializes into an empty map), every
    value type must decode back to its own text, and the CLI's own re-parse check must
    accept what it wrote.
    """
    import contextlib

    contextlib_redirect = contextlib.redirect_stdout
    checks = 0
    tmpdir = tempfile.mkdtemp(prefix='datastore-inject-selftest-')
    try:
        assert varint(0) == b'\x00'
        assert varint(127) == b'\x7f'
        assert varint(128) == b'\x80\x01'
        assert varint(300) == b'\xac\x02'
        assert varint(-1) == b'\xff' * 9 + b'\x01', 'negatives are 64-bit two\'s complement'
        checks += 1

        for value in (0, 1, 300, 4102444800000):
            raw = varint(value)
            assert read_varint(raw, 0) == (value, len(raw)), (value, raw)
        assert read_varint(b'\xac\x02tail', 0) == (300, 2), 'must stop at the end marker'
        try:
            read_varint(b'\x80', 0)
        except ValueError as exc:
            assert 'truncated varint' in str(exc), str(exc)
        else:
            raise AssertionError('a truncated varint was accepted')
        checks += 1

        # The exact two-level map encoding, byte for byte:
        #   outer 0x0A <len> | inner (0x0A <len> key | 0x12 <len> value)
        #   long value payload: 0x20 (= field 4, varint) then the value
        entry = encode_entry('k', encode_value('long', '5'))
        assert entry.hex() == '0a070a016b12022005', entry.hex()
        assert entry[0] == 0x0A and entry[2] == 0x0A and entry[4] == ord('k'), entry.hex()
        assert entry[5] == 0x12, entry.hex()
        key, payload = decode_entry(entry)
        assert (key, payload) == ('k', b'\x20\x05'), (key, payload)
        checks += 1

        cases = [('bool', 'true', 'bool=True'),
                 ('bool', '0', 'bool=False'),
                 ('int', '7', 'integer=7'),
                 ('long', '4102444800000', 'long=4102444800000'),
                 ('float', '1.5', 'float=1.5'),
                 ('double', '2.25', 'double=2.25'),
                 ('string', 'hello', "string='hello'"),
                 ('bytes', '00ff10', 'bytes=00ff10')]
        for kind, raw, expect in cases:
            built = encode_entry('key_' + kind, encode_value(kind, raw))
            k, p = decode_entry(built)
            assert k == 'key_' + kind, (kind, k)
            assert describe_value(p) == expect, (kind, describe_value(p), expect)
        checks += 1

        two = encode_entry('a', encode_value('bool', 'true')) + \
            encode_entry('b', encode_value('string', 'x'))
        slices = split_entries(two)
        assert len(slices) == 2, slices
        assert slices[0][1] == encode_entry('a', encode_value('bool', 'true')), slices[0]
        assert [decode_entry(raw)[0] for _tag, raw in slices] == ['a', 'b']
        assert split_entries(b'') == [], 'an empty map has no entries'
        checks += 1

        assert parse_extra(['k=v:bool']) == [('k', 'bool', 'v')]
        assert parse_extra(['k=plain']) == [('k', 'string', 'plain')]
        assert parse_extra(['k=a:b:bool']) == [('k', 'bool', 'a:b')], parse_extra(['k=a:b:bool'])
        for bad in (['no-equals'], ['k=v:nosuchtype']):
            try:
                parse_extra(bad)
            except SystemExit:
                pass
            else:
                raise AssertionError('parse_extra accepted %r' % (bad,))
        checks += 1

        # The CLI re-parses what it built before writing; assert it stays honest --
        # a dry run must not create the file, and --list must read the same values back.
        target = os.path.join(tmpdir, 'example.preferences_pb')
        out = io.StringIO()
        saved = sys.argv
        try:
            sys.argv = ['datastore_inject.py', '--file', target, '--key', 'flag',
                        '--type', 'bool', '--value', 'true',
                        '--extra', 'name=hello:string', '--dry-run']
            with contextlib_redirect(out):
                rc = main()
        finally:
            sys.argv = saved
        assert rc == 0, rc
        assert not os.path.exists(target), '--dry-run wrote the file'
        assert '[check] re-parsed 2 entry(ies); flag = bool=True' in out.getvalue(), \
            out.getvalue()
        checks += 1

        try:
            sys.argv = ['datastore_inject.py', '--file', target, '--key', 'flag',
                        '--type', 'bool', '--value', 'true',
                        '--extra', 'name=hello:string']
            with contextlib_redirect(io.StringIO()):
                assert main() == 0
        finally:
            sys.argv = saved
        assert os.path.exists(target), 'the real run wrote nothing'
        data = open(target, 'rb').read()
        assert len(split_entries(data)) == 2, split_entries(data)
        checks += 1

        out = io.StringIO()
        try:
            sys.argv = ['datastore_inject.py', '--in', target, '--list']
            with contextlib_redirect(out):
                rc = main()
        finally:
            sys.argv = saved
        text = out.getvalue()
        assert rc == 0, rc
        assert 'flag' in text and 'bool=True' in text, text
        assert "name" in text and "string='hello'" in text, text
        assert '[ok] 2 entry(ies)' in text, text
        checks += 1
    except Exception as exc:          # a failed assertion IS the signal: report, rc=1
        print(json.dumps({"ok": False, "checks": checks, "tool": "datastore_inject.py",
                          "reason": "%s: %s" % (type(exc).__name__, exc)},
                         ensure_ascii=False))
        return 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    print(json.dumps({"ok": True, "checks": checks, "tool": "datastore_inject.py"},
                     ensure_ascii=False))
    return 0


def main():
    if '--self-test' in sys.argv[1:]:
        return self_test()

    ap = argparse.ArgumentParser(
        description='Encode or inject AndroidX DataStore (Preferences) protobuf '
                    'entries, with the correct two-level map encoding.')
    ap.add_argument('--file', default=DEFAULT_FILE,
                    help='output .pb path (default: %s)' % DEFAULT_FILE)
    ap.add_argument('--key', default=DEFAULT_KEY,
                    help='preference key to write (default: %s)' % DEFAULT_KEY)
    ap.add_argument('--value', default=DEFAULT_VALUE,
                    help='value for --key (default: %s)' % DEFAULT_VALUE)
    ap.add_argument('--type', choices=TYPES, default='long',
                    help='value type (default: long)')
    ap.add_argument('--in', dest='existing', default=None,
                    help='existing .pb to read: preserves all other keys')
    ap.add_argument('--extra', action='append', default=[],
                    help='key=value[:type], repeatable, added alongside --key')
    ap.add_argument('--list', action='store_true',
                    help='list the entries of --in and exit (no writing)')
    ap.add_argument('--dry-run', action='store_true',
                    help='print what would be written, write nothing')
    ap.add_argument('--self-test', action='store_true', dest='self_test',
                    help='run offline self-test and exit (writes only to a temp dir)')
    args = ap.parse_args()

    if args.list:
        if not args.existing:
            raise SystemExit('--list needs --in <file.preferences_pb>')
        with open(args.existing, 'rb') as fh:
            data = fh.read()
        print('[in] %s (%d bytes)' % (args.existing, len(data)))
        shown = 0
        for tag, raw in split_entries(data):
            key, payload = decode_entry(raw)
            if key is None:
                print('   <unparsed field tag=0x%02x, %d bytes>' % (tag, len(raw)))
                continue
            print('   %-32s %s   (value=%d bytes)' % (key, describe_value(payload), len(payload)))
            shown += 1
        print('[ok] %d entry(ies)' % shown)
        return 0

    # Build the entry list: preserved entries first, then the injected ones.
    chunks = []
    if args.existing:
        with open(args.existing, 'rb') as fh:
            original = fh.read()
        replaced = {args.key}
        replaced.update(k for k, _, _ in parse_extra(args.extra))
        kept = 0
        for _tag, raw in split_entries(original):
            key, _payload = decode_entry(raw)
            if key is None:
                chunks.append(raw)          # unknown field: keep it verbatim
                continue
            if key in replaced:
                print('[keep-skip] %s is being replaced' % key)
                continue
            chunks.append(raw)
            kept += 1
        print('[in] preserved %d existing entry(ies) from %s' % (kept, args.existing))

    target = encode_entry(args.key, encode_value(args.type, args.value))
    chunks.append(target)
    print('[inject] %s (%s) = %s -> %d bytes' % (args.key, args.type, args.value, len(target)))

    for key, kind, value in parse_extra(args.extra):
        entry = encode_entry(key, encode_value(kind, value))
        chunks.append(entry)
        print('[inject] %s (%s) = %s -> %d bytes' % (key, kind, value, len(entry)))

    data = b''.join(chunks)

    # Self-check: re-parse what we just built. A file that does not parse back is
    # exactly the failure mode that kills the app with no usable stack.
    found = {}
    for _tag, raw in split_entries(data):
        key, payload = decode_entry(raw)
        if key is not None:
            found[key] = describe_value(payload)
    for key in [args.key] + [k for k, _t, _v in parse_extra(args.extra)]:
        if key not in found:
            raise SystemExit('internal error: %r does not parse back; refusing to write' % key)
    print('[check] re-parsed %d entry(ies); %s = %s' % (len(found), args.key, found[args.key]))
    print('[hex] %s' % data.hex(' '))

    if args.dry_run:
        print('[dry-run] nothing written')
        return 0

    with open(args.file, 'wb') as fh:
        fh.write(data)
    print('[ok] wrote %s (%d bytes)' % (args.file, len(data)))
    print('[note] push it to <app_files_dir>/datastore/<name>.preferences_pb while the app '
          'is NOT running, then start the app and read the key back with --list')
    return 0


if __name__ == '__main__':
    sys.exit(main())
