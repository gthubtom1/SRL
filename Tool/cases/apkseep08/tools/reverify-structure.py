#!/usr/bin/env python3
"""Recompute the shipped commercial-APK structure evidence with the stdlib."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from zipfile import ZipFile


HERE = Path(__file__).resolve().parent
CASE = HERE.parent
DEFAULT_TARGET = CASE / "target" / "release.apk"
EXPECTED_SHA256 = "4e74b5208a59709a74ae507163080a209c30dc6922500b9dc5eeb3c384e94b3b"
EXPECTED_SIZE = 100524601
EXPECTED_ENTRIES = 1430
EXPECTED_DEX_COUNT = 6
EXPECTED_SO_COUNT = 52
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=DEFAULT_TARGET)
    args = parser.parse_args(argv)
    target = args.target.resolve()
    if not target.is_file():
        print("status=FAIL")
        print("failure=target missing: %s" % target)
        return 2

    data = target.read_bytes()
    before = hashlib.sha256(data).hexdigest()
    with ZipFile(target) as archive:
        infos = archive.infolist()
        dex = [
            {"name": info.filename, "size": info.file_size}
            for info in infos
            if info.filename.lower().endswith(".dex")
        ]
        so_count = sum(info.filename.lower().endswith(".so") for info in infos)

    after = hashlib.sha256(target.read_bytes()).hexdigest()
    failures = []
    if before != EXPECTED_SHA256:
        failures.append("target sha256 changed")
    if len(data) != EXPECTED_SIZE:
        failures.append("target size changed")
    if len(infos) != EXPECTED_ENTRIES:
        failures.append("zip entry count changed")
    if len(dex) != EXPECTED_DEX_COUNT:
        failures.append("dex count changed")
    if so_count != EXPECTED_SO_COUNT:
        failures.append("native library count changed")
    if before != after:
        failures.append("target changed while it was inspected")

    report = {
        "target": target.relative_to(CASE).as_posix(),
        "sha256": before,
        "sha256_after": after,
        "size": len(data),
        "entries": len(infos),
        "dex": dex,
        "so_count": so_count,
        "target_unmodified": before == after,
        "failures": failures,
        "status": "PASS" if not failures else "FAIL",
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
