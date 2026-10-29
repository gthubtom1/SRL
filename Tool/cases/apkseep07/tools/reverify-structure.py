#!/usr/bin/env python3
"""Recompute the AP07 structure/root/secret/shell facts from the shipped APK."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
CASE = HERE.parent
DEFAULT_TARGET = CASE / "target" / "UnCrackable-Level2.apk"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    args = parser.parse_args(argv)
    target = args.target.resolve()
    if not target.is_file():
        print("status=FAIL")
        print("failure=target missing: %s" % target)
        return 2

    before = target.read_bytes()
    failures = []
    with ZipFile(target) as archive:
        names = archive.namelist()
        dex_names = sorted(name for name in names if name.endswith(".dex"))
        so_names = sorted(name for name in names if name.endswith(".so"))
        dex_sizes = {name: archive.getinfo(name).file_size for name in dex_names}
        so_sizes = {name: archive.getinfo(name).file_size for name in so_names}
        dex_bytes = b"".join(archive.read(name) for name in dex_names)
        so_bytes = b"".join(archive.read(name) for name in so_names)

    print("### target")
    print("path=%s" % target)
    print("size=%d" % len(before))
    print("sha256=%s" % sha256_bytes(before))

    print("### composition")
    print("entries=%d" % len(names))
    print("dex=%s" % ",".join("%s:%d" % (name, dex_sizes[name])
                              for name in dex_names))
    print("so=%s" % ",".join("%s:%d" % (name, so_sizes[name])
                             for name in so_names))
    if dex_names != ["classes.dex"] or len(dex_bytes) != 719560:
        failures.append("dex composition differs from one 719560-byte classes.dex")
    if len(so_names) != 4:
        failures.append("expected four native libfoo.so ABIs")

    root_dex = dex_bytes.count(b"/system/xbin")
    root_so = so_bytes.count(b"/system/xbin")
    print("### root-detection")
    print("root_marker.dex=%d" % root_dex)
    print("root_marker.so=%d" % root_so)
    print("status=%s" % ("PASS" if (root_dex, root_so) == (1, 0) else "FAIL"))
    if (root_dex, root_so) != (1, 0):
        failures.append("root marker counts differ from dex=1 so=0")

    secret = b"Thanks for all the fish"
    secret_dex = dex_bytes.count(secret)
    secret_so = so_bytes.count(secret)
    fish_dex = dex_bytes.count(b"fish")
    fish_so = so_bytes.count(b"fish")
    print("### secret")
    print("secret.dex=%d" % secret_dex)
    print("secret.so=%d" % secret_so)
    print("fish_fragment.dex=%d" % fish_dex)
    print("fish_fragment.so=%d" % fish_so)
    print("status=%s" % ("PASS" if not any(
        (secret_dex, secret_so, fish_dex, fish_so)) else "FAIL"))
    if any((secret_dex, secret_so, fish_dex, fish_so)):
        failures.append("secret or fish fragment appears in plaintext")

    features = [
        "StubApp", "libjiagu", "DexHelper", "com.qihoo", "SecShell",
        "bangcle", "secneo", "AppWrapper", "aliprotect", "libnesec",
        "libshella", "libmobisec", "jiagu", "libexec", "libshell",
    ]
    hits = {name: dex_bytes.count(name.encode("ascii")) for name in features}
    nonzero = sum(value != 0 for value in hits.values())
    total_hits = sum(hits.values())
    print("### shell-features")
    for name in features:
        print("feature.%s=%d" % (name, hits[name]))
    print("features.nonzero=%d" % nonzero)
    print("features.total_hits=%d" % total_hits)
    print("status=%s" % ("PASS" if nonzero == 0 and total_hits == 0 else "FAIL"))
    if nonzero or total_hits:
        failures.append("shell feature counts are non-zero")

    after = target.read_bytes()
    print("### target-integrity")
    print("target.sha256.before=%s" % sha256_bytes(before))
    print("target.sha256.after=%s" % sha256_bytes(after))
    print("target.unmodified=%s" % str(before == after).lower())
    if before != after:
        failures.append("target changed while it was inspected")

    print("### conclusion")
    print("checks.failures=%d" % len(failures))
    for failure in failures:
        print("failure=%s" % failure)
    print("status=%s" % ("PASS" if not failures else "FAIL"))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
