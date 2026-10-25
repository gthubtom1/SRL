#!/usr/bin/env python3
"""Scan memory captures for embedded dex images and optionally extract them.

A packer can keep a decrypted dex in a buffer that never appears in
`/proc/<pid>/maps` under a dex-looking name -- it sits inside an anonymous rw-p
mapping. Neither `maps` analysis nor a per-mapping dump finds that on its own;
searching the bytes for the dex magic does. This script does the search and, with
`--dump`, writes each hit out at the size its own header declares.

Typical use, after taking raw regions from a live process (root required):

    adb shell 'su -c "cat /proc/<pid>/mem"' ...        # or per-region dd exports
    python skills/apkseep/scripts/dex_mem_scan.py region_dir/ --dump out/

Feeding the extracted images to `dex_dump_validate.py` is the next step: this
script only *finds* and *cuts*; that one judges whether what came out is a real
body or an extraction-shell skeleton.

**Measured hit rate on the reference device: zero for anonymous regions.** The
root-dump pass recorded in `docs/tool-verification/EXTENSION-rootdump.md` scanned
142 anonymous mappings and returned **no hits**, while the *named* ART dex mappings
in the same process yielded 17 dex images without any search at all. A negative
result from this script is therefore weak evidence: it is compatible with "the
payload is not resident", "the payload is resident but not as a contiguous
dex-magic image", and "the payload was paged out between capture and scan". Treat a
zero-hit scan as a reason to check the named mappings first
(`[anon:dalvik-classes*.dex extracted in memory from <src>]`), not as a conclusion
about the packer. A positive hit inside a genuinely unnamed mapping has not been
observed here yet.

Scope note: the header's `file_size` field decides the cut. When the declared size
does not fit inside the capture, the hit is reported and skipped rather than
guessed at -- a dex whose tail is missing is not recoverable by truncating the
wrong end. Page-aligned captures from a VMA routinely overrun the image they hold,
so a run against raw VMA exports usually needs `--keep-partial` or a trim step
before `dex_dump_validate.py` will accept the output.
"""
import argparse
import hashlib
import io
import json
import os
import shutil
import struct
import sys
import tempfile

MAGIC = b"dex\n0"
HEADER_SIZE = 112
OVERLAP = 0x80  # enough to complete a header straddling two chunks


def valid_version(four_bytes):
    """`dex\\n0XY` -> 'XY' when both digits are decimal, else None."""
    ver = four_bytes[4:7]
    if len(ver) != 3 or not (ver[0:1].isdigit() and ver[1:2].isdigit()
                             and ver[2:3].isdigit()):
        return None
    return ver.decode("ascii")


def find_offsets(path, chunk_size):
    """Yield (absolute offset, buffer, index in buffer, buffer base) for each magic.

    Chunks overlap by OVERLAP bytes so a header straddling a chunk boundary is
    still seen whole; the caller dedupes repeated offsets.
    """
    size = os.path.getsize(path)
    carry = b""
    pos = 0
    with open(path, "rb") as fh:
        while pos < size:
            fh.seek(pos)
            buf = carry + fh.read(chunk_size)
            base = pos - len(carry)
            start = 0
            while True:
                i = buf.find(MAGIC, start)
                if i < 0:
                    break
                start = i + 1
                yield base + i, buf, i, base
            if len(buf) <= OVERLAP:
                break
            carry = buf[-OVERLAP:]
            pos += len(buf) - len(carry)


def read_header(fh, offset):
    """Return (file_size, class_defs_size, link_size) or None if the header is short."""
    fh.seek(offset)
    head = fh.read(HEADER_SIZE)
    if len(head) < HEADER_SIZE:
        return None
    if head[:4] != b"dex\n"[:4]:
        return None
    file_size = struct.unpack_from("<I", head, 32)[0]
    class_defs_size = struct.unpack_from("<I", head, 96)[0]
    link_size = struct.unpack_from("<I", head, 104)[0]
    return file_size, class_defs_size, link_size


def scan_file(path, chunk_size, min_size, do_dump, dump_dir, keep_partial):
    """Scan one capture; return (records, extracted_count, skipped_count)."""
    records = []
    extracted = 0
    skipped = 0
    seen = set()
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        for offset, buf, i, base in find_offsets(path, chunk_size):
            ver = valid_version(buf[i:i + 8]) if i + 8 <= len(buf) else None
            if ver is None:
                continue
            if offset in seen:
                continue
            seen.add(offset)
            head = read_header(fh, offset)
            if head is None:
                continue
            file_size, class_defs_size, link_size = head
            if file_size < 112 or file_size > (1 << 32):
                continue

            fits = file_size <= (size - offset)
            rec = {
                "capture": os.path.basename(path),
                "offset": offset,
                "version": ver,
                "file_size": file_size,
                "class_defs_size": class_defs_size,
                "link_size": link_size,
                "fits": fits,
            }
            if fits and file_size >= min_size:
                takes = file_size
            elif keep_partial and not fits:
                takes = size - offset
                rec["partial"] = takes
            else:
                rec["skipped"] = ("declared %d B, %d B available"
                                  % (file_size, size - offset))
                skipped += 1
                records.append(rec)
                continue

            fh.seek(offset)
            blob = fh.read(takes)
            rec["sha256"] = hashlib.sha256(blob).hexdigest()
            if do_dump:
                stem = os.path.splitext(os.path.basename(path))[0]
                name = "%s+0x%08x.dex" % (stem, offset)
                out = os.path.join(dump_dir, name)
                with open(out, "wb") as ofh:
                    ofh.write(blob)
                rec["written"] = out
                extracted += 1
            records.append(rec)
    return records, extracted, skipped


def collect_targets(paths):
    targets = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                full = os.path.join(p, name)
                if os.path.isfile(full) and not name.endswith((".txt", ".json", ".md")):
                    targets.append(full)
        else:
            targets.append(p)
    return targets


def self_test():
    """Offline self-test: generated capture files, no process memory needed.

    A scan tool is only as good as its OFFSETS, so every record asserted here carries the
    offset it was planted at. The chunk-boundary case is included because the overlap
    loop is the one piece that silently drops hits: a magic straddling two chunk reads
    must still be found whole, with the same absolute offset.
    """
    import contextlib

    def fake_dex(size=4096, version=b'035', class_defs=7, link=0):
        buf = bytearray(size)
        buf[0:8] = b'dex\n' + version + b'\x00'
        struct.pack_into('<I', buf, 32, size)          # file_size
        struct.pack_into('<I', buf, 96, class_defs)    # class_defs_size
        struct.pack_into('<I', buf, 104, link)         # link_size
        return bytes(buf)

    checks = 0
    tmpdir = tempfile.mkdtemp(prefix='dex-mem-scan-selftest-')
    try:
        assert valid_version(b'dex\n035\x00') == '035'
        assert valid_version(b'dex\n039\x00') == '039'
        assert valid_version(b'dex\n0x5\x00') is None, 'version digits must be decimal'
        assert valid_version(b'dex\n03') is None, 'a short version is not a version'
        assert MAGIC == b'dex\n0' and HEADER_SIZE == 112
        checks += 1

        dex = fake_dex()
        capture = b'\xaa' * 0x40 + dex
        cap_path = os.path.join(tmpdir, 'region.bin')
        with open(cap_path, 'wb') as fh:
            fh.write(capture)

        records, extracted, skipped = scan_file(cap_path, 1 << 20, 4096, False,
                                                tmpdir, False)
        assert (extracted, skipped) == (0, 0), (extracted, skipped)
        assert len(records) == 1, records
        rec = records[0]
        assert rec['offset'] == 0x40, hex(rec['offset'])
        assert rec['version'] == '035', rec['version']
        assert rec['file_size'] == 4096 and rec['fits'] is True, rec
        assert rec['class_defs_size'] == 7, rec['class_defs_size']
        assert rec['capture'] == 'region.bin', rec['capture']
        assert rec['sha256'] == hashlib.sha256(dex).hexdigest(), rec['sha256']
        assert 'skipped' not in rec and 'partial' not in rec, rec
        checks += 1

        # A magic that straddles a chunk boundary must still be found, at its real
        # offset: this is what the OVERLAP carry is for.
        straddle = b'\x00' * 195 + dex
        straddle_path = os.path.join(tmpdir, 'straddle.bin')
        with open(straddle_path, 'wb') as fh:
            fh.write(straddle)
        recs, _e, _s = scan_file(straddle_path, 200, 4096, False, tmpdir, False)
        assert [r['offset'] for r in recs] == [195], [r['offset'] for r in recs]
        checks += 1

        # Declared size that runs past the end of the capture: reported and skipped,
        # and only written when --keep-partial says the truncation is acceptable.
        clipped = b'\x00' * 0x20 + dex[:1000]
        clip_path = os.path.join(tmpdir, 'clipped.bin')
        with open(clip_path, 'wb') as fh:
            fh.write(clipped)
        recs, extracted, skipped = scan_file(clip_path, 1 << 20, 4096, False,
                                             tmpdir, False)
        assert skipped == 1 and extracted == 0, (extracted, skipped)
        assert recs[0]['fits'] is False, recs[0]
        assert recs[0]['skipped'] == 'declared 4096 B, 1000 B available', recs[0]
        recs, _e, _s = scan_file(clip_path, 1 << 20, 4096, False, tmpdir, True)
        assert recs[0]['partial'] == 1000, recs[0]
        checks += 1

        # --min-size evicts stray magics whose declared size is too small.
        recs, _e, skipped = scan_file(cap_path, 1 << 20, 1 << 20, False, tmpdir, False)
        assert skipped == 1 and recs[0]['fits'] is True, recs[0]
        checks += 1

        # --dump writes each hit at its declared size, named after the capture + offset.
        dump_dir = os.path.join(tmpdir, 'dump')
        os.makedirs(dump_dir)
        recs, extracted, _s = scan_file(cap_path, 1 << 20, 4096, True, dump_dir, False)
        assert extracted == 1, extracted
        written = recs[0]['written']
        assert os.path.basename(written) == 'region+0x00000040.dex', written
        with open(written, 'rb') as fh:
            assert fh.read() == dex, 'the dump must be exactly the declared image'
        checks += 1

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = main([cap_path, '--json'])
        assert rc == 0, rc
        payload = json.loads(out.getvalue())
        assert payload['records'][0]['offset'] == 0x40, payload['records']
        assert payload['extracted'] == 0 and payload['skipped'] == 0, payload
        checks += 1

        # No hit at all is exit 1, not a silent success: a zero-hit scan is weak
        # evidence and the exit code has to say so.
        empty_path = os.path.join(tmpdir, 'nothing.bin')
        with open(empty_path, 'wb') as fh:
            fh.write(b'\x00' * 512)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = main([empty_path])
        assert rc == 1, rc
        checks += 1

        # collect_targets skips notes in a region directory and keeps the blobs.
        targets = collect_targets([tmpdir])
        names = sorted(os.path.basename(t) for t in targets)
        assert 'region.bin' in names and 'clipped.bin' in names, names
        assert not any(n.endswith(('.txt', '.json', '.md')) for n in names), names
        checks += 1
    except Exception as exc:          # a failed assertion IS the signal: report, rc=1
        print(json.dumps({"ok": False, "checks": checks, "tool": "dex_mem_scan.py",
                          "reason": "%s: %s" % (type(exc).__name__, exc)},
                         ensure_ascii=False))
        return 1
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    print(json.dumps({"ok": True, "checks": checks, "tool": "dex_mem_scan.py"},
                     ensure_ascii=False))
    return 0


def main(argv=None):
    if '--self-test' in (sys.argv[1:] if argv is None else argv):
        return self_test()

    ap = argparse.ArgumentParser(
        description="Scan memory captures (or any blob) for embedded dex images "
                    "'dex\\n03x', report each hit, and optionally extract them at "
                    "the size their own headers declare. Pair with "
                    "dex_dump_validate.py, which judges what was extracted.")
    ap.add_argument("path", nargs="+",
                    help="a capture file, or a directory of region exports")
    ap.add_argument("--dump", metavar="DIR",
                    help="write each hit into DIR as <capture>+0x<offset>.dex")
    ap.add_argument("--json", action="store_true",
                    help="emit the record list as JSON")
    ap.add_argument("--chunk-size", type=int, default=64 << 20, metavar="N",
                    help="read the capture in N-byte chunks (default 64 MiB); use a "
                         "smaller value for very large captures")
    ap.add_argument("--min-size", type=int, default=4096, metavar="N",
                    help="ignore hits whose declared file_size is below N bytes "
                         "(default 4096) -- stray magics in unrelated data")
    ap.add_argument("--keep-partial", action="store_true",
                    help="also write hits whose declared size runs past the end of "
                         "the capture (truncated region); the result is NOT a dex")
    ap.add_argument("--self-test", action="store_true", dest="self_test",
                    help="run offline self-test and exit (no capture needed)")
    args = ap.parse_args(argv)

    targets = collect_targets(args.path)
    if not targets:
        print("no capture files found in the given path(s)", file=sys.stderr)
        return 1

    dump_dir = None
    if args.dump:
        dump_dir = os.path.abspath(args.dump)
        os.makedirs(dump_dir, exist_ok=True)

    all_records = []
    total_extracted = 0
    total_skipped = 0
    for t in targets:
        records, extracted, skipped = scan_file(
            t, args.chunk_size, args.min_size,
            dump_dir is not None, dump_dir or ".", args.keep_partial)
        all_records.extend(records)
        total_extracted += extracted
        total_skipped += skipped

    if args.json:
        print(json.dumps({"records": all_records,
                          "extracted": total_extracted,
                          "skipped": total_skipped}, indent=2))
        return 0 if all_records else 1

    print("== dex memory scan: %d capture(s), %d hit(s) =="
          % (len(targets), len(all_records)))
    fmt = "%-34s %12s  %3s  %12s  %10s  %-6s"
    print(fmt % ("capture", "offset", "ver", "file_size", "classes", "state"))
    for r in all_records:
        state = "ok" if r.get("fits") and not r.get("partial") else (
            "partial" if r.get("partial") else "skipped")
        print(fmt % (r["capture"][:34], "0x%x" % r["offset"], r["version"],
                     r["file_size"], r["class_defs_size"], state))
        if r.get("written"):
            print("%-34s   wrote %s" % ("", r["written"]))
        if r.get("skipped"):
            print("%-34s   skipped: %s" % ("", r["skipped"]))

    unique = {r["sha256"] for r in all_records if r.get("sha256")}
    print("\n%d hit(s) with a complete declared size, %d unique by sha256, "
          "%d skipped" % (total_extracted, len(unique), total_skipped))
    if total_extracted:
        print("next: python dex_dump_validate.py %s" % (dump_dir or "<dump dir>"))
    return 0 if all_records else 1


if __name__ == "__main__":
    sys.exit(main())
