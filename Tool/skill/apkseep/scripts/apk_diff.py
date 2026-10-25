#!/usr/bin/env python3
"""Entry-level APK diff: what actually changed between two builds.

Two jobs, both recurring:

  1. **Audit a build you did not produce.** Given an original and a
     "cracked"/"modded" copy, this lists every entry that differs, every entry
     the author ADDED, and every entry they REMOVED. Added entries under
     `lib/`, `assets/`, or new dex files are the interesting ones -- that is
     where injected payloads live.

  2. **Verify your own build was surgical.** After repacking, the diff against
     the original must contain exactly the entries you intended to touch and
     nothing else. A surprise entry is a bug in your pipeline, not in the app.

It compares *content*, not just sizes: two builds can have identical sizes and
different bytes, and a same-size replacement is exactly the case a careless
comparison misses.

Usage
-----
  python apk_diff.py original.apk modified.apk
  python apk_diff.py original.apk modified.apk --hide-identical
  python apk_diff.py original.apk modified.apk --only 'classes.*\\.dex|lib/.*'
  python apk_diff.py original.apk modified.apk --summary
"""

import argparse
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import zipfile

# Directories worth naming explicitly -- this is where injected code lives.
INTERESTING = ("lib/", "assets/", "META-INF/services/")


def snapshot(path):
    """{entry_name: (size, sha256, compress_type, crc)}"""
    out = {}
    with zipfile.ZipFile(path) as z:
        for it in z.infolist():
            if it.is_dir():
                continue
            data = z.read(it.filename)
            out[it.filename] = (
                len(data),
                hashlib.sha256(data).hexdigest(),
                it.compress_type,
                it.CRC,
            )
    return out


def classify(name):
    if re.match(r"^classes\d*\.dex$", name):
        return "dex"
    if name.startswith("META-INF/") and name.endswith((".RSA", ".SF", ".MF", ".DSA", ".EC")):
        return "signature"
    if name.startswith(INTERESTING):
        return "code/assets"
    return "other"


def self_test():
    """Offline self-test: built-in bytes only, no network, no sample APKs.

    Builds two small APKs (zip archives) in a temporary directory and asserts on the
    exact entries `snapshot()`/`classify()` report and on `main()`'s count lines, so a
    regression in content comparison (not just in size comparison) fails the test.
    """
    try:
        import contextlib

        checks = 0
        tmp = tempfile.mkdtemp(prefix="apk-diff-selftest-")

        def build(name, entries):
            path = os.path.join(tmp, name)
            with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
                for entry, data in entries:
                    z.writestr(entry, data)
            return path

        try:
            a = build("a.apk", [("classes.dex", b"AAAA"),
                               ("res/x.png", b"same"),
                               ("assets/old.bin", b"removed-in-B")])
            # classes.dex keeps the SAME SIZE and changes bytes: the case a size-only
            # comparison misses entirely, which is the whole point of hashing.
            b = build("b.apk", [("classes.dex", b"AAAB"),
                               ("res/x.png", b"same"),
                               ("lib/arm64-v8a/libinject.so", b"\x7fELF payload")])

            snap_a = snapshot(a)
            assert sorted(snap_a) == ["assets/old.bin", "classes.dex", "res/x.png"], \
                sorted(snap_a)
            checks += 1
            size, sha, ctype, _crc = snap_a["classes.dex"]
            assert (size, ctype) == (4, zipfile.ZIP_STORED), (size, ctype)
            assert sha == hashlib.sha256(b"AAAA").hexdigest(), sha
            checks += 1

            assert classify("classes.dex") == "dex"
            assert classify("classes3.dex") == "dex"
            assert classify("lib/x86/liby.so") == "code/assets"
            assert classify("assets/payload.json") == "code/assets"
            assert classify("META-INF/CERT.RSA") == "signature"
            assert classify("res/layout/a.xml") == "other"
            checks += 1

            snap_b = snapshot(b)
            only_a = sorted(set(snap_a) - set(snap_b))
            only_b = sorted(set(snap_b) - set(snap_a))
            changed = [n for n in sorted(set(snap_a) & set(snap_b))
                       if snap_a[n][1] != snap_b[n][1]]
            assert only_a == ["assets/old.bin"], only_a
            assert only_b == ["lib/arm64-v8a/libinject.so"], only_b
            assert changed == ["classes.dex"], changed
            assert snap_a["classes.dex"][0] == snap_b["classes.dex"][0], "sizes must match"
            checks += 1

            out = io.StringIO()
            saved = sys.argv
            sys.argv = ["apk_diff.py", a, b, "--summary"]
            try:
                with contextlib.redirect_stdout(out):
                    main()
            finally:
                sys.argv = saved
            text = out.getvalue()
            assert "only in A (removed)  : 1" in text, text
            assert "only in B (added)    : 1" in text, text
            assert "content changed      : 1" in text, text
            assert "identical            : 1" in text, text
            assert "=== ADDED" not in text, "--summary must not list entries"
            checks += 1

            out = io.StringIO()
            sys.argv = ["apk_diff.py", a, b]
            try:
                with contextlib.redirect_stdout(out):
                    main()
            finally:
                sys.argv = saved
            text = out.getvalue()
            assert "(SAME SIZE)" in text, text
            assert "+ lib/arm64-v8a/libinject.so" in text, text
            assert "[code/assets]" in text, text
            checks += 1
        finally:
            for name in os.listdir(tmp):
                os.unlink(os.path.join(tmp, name))
            os.rmdir(tmp)

    except Exception as exc:          # a failed assertion IS the signal: report, rc=1
        print(json.dumps({"ok": False, "checks": checks, "tool": "apk_diff.py",
                          "reason": "%s: %s" % (type(exc).__name__, exc)},
                         ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, "checks": checks, "tool": "apk_diff.py"},
                     ensure_ascii=False))
    return 0


def main():
    if "--self-test" in sys.argv[1:]:
        return self_test()

    ap = argparse.ArgumentParser(description="Entry-level APK diff.")
    ap.add_argument("--self-test", action="store_true", dest="self_test",
                    help="run offline self-test and exit")
    ap.add_argument("original")
    ap.add_argument("modified")
    ap.add_argument("--only", help="regex: restrict output to matching entry names")
    ap.add_argument("--hide-identical", action="store_true",
                    help="omit the identical-count line")
    ap.add_argument("--summary", action="store_true",
                    help="counts only, no per-entry listing")
    ap.add_argument("--max", type=int, default=200,
                    help="max entries listed per section (default 200)")
    args = ap.parse_args()

    try:
        a = snapshot(args.original)
        b = snapshot(args.modified)
    except Exception as e:
        sys.exit("error reading APK: %s" % e)

    only_a = sorted(set(a) - set(b))
    only_b = sorted(set(b) - set(a))
    common = sorted(set(a) & set(b))
    changed = [n for n in common if a[n][1] != b[n][1]]

    rx = re.compile(args.only) if args.only else None

    def keep(n):
        return rx.search(n) if rx else True

    def sha(path, n):
        return a[n][1][:16] if n in a else b[n][1][:16]

    print("A (original) %s  entries=%d" % (args.original, len(a)))
    print("B (modified) %s  entries=%d" % (args.modified, len(b)))
    print("")
    print("only in A (removed)  : %d" % len(only_a))
    print("only in B (added)    : %d" % len(only_b))
    print("content changed      : %d" % len(changed))
    if not args.hide_identical:
        print("identical            : %d" % (len(common) - len(changed)))
    print("")

    # Signature entries always differ; say so once instead of listing them.
    sig_only = [n for n in (only_a + only_b) if classify(n) == "signature"]
    if sig_only:
        print("(note: %d signature entries account for most of the add/remove noise)"
              % len(sig_only))

    if args.summary:
        return

    if only_b:
        print("\n=== ADDED in B  (injection candidates) ===")
        shown = 0
        for n in only_b:
            if not keep(n) or classify(n) == "signature":
                continue
            print("  + %-52s %9d B  [%s]" % (n, b[n][0], classify(n)))
            shown += 1
            if shown >= args.max:
                print("  ... (truncated)")
                break

    if only_a:
        print("\n=== REMOVED from A ===")
        shown = 0
        for n in only_a:
            if not keep(n) or classify(n) == "signature":
                continue
            print("  - %-52s %9d B  [%s]" % (n, a[n][0], classify(n)))
            shown += 1
            if shown >= args.max:
                print("  ... (truncated)")
                break

    if changed:
        print("\n=== CONTENT CHANGED ===")
        shown = 0
        for n in changed:
            if not keep(n):
                continue
            sa, sb = a[n], b[n]
            cmark = "" if sa[2] == sb[2] else "  ctype %d->%d" % (sa[2], sb[2])
            same_size = "  (SAME SIZE)" if sa[0] == sb[0] else ""
            print("  ~ %-52s A %9d %s  B %9d %s%s%s"
                  % (n, sa[0], sa[1][:16], sb[0], sb[1][:16], same_size, cmark))
            shown += 1
            if shown >= args.max:
                print("  ... (truncated)")
                break
        if any(a[n][0] == b[n][0] for n in changed if keep(n)):
            print("\n  (SAME SIZE means the change is not a length difference --")
            print("   a size-only comparison would have missed it entirely)")

    if not (only_a or only_b or changed):
        print("no differences at all")


if __name__ == "__main__":
    sys.exit(main())
