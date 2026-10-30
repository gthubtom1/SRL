#!/usr/bin/env python3
"""Bounded, offline, exact scalar transition search. No process access."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import sys
import tempfile

MAX_BYTES = 16 * 1024 * 1024
MAX_MANIFEST = 16384
TYPES = {"i8": "b", "u8": "B", "i16": "h", "u16": "H",
         "i32": "i", "u32": "I", "i64": "q", "u64": "Q",
         "f32": "f", "f64": "d"}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def bounded_read(path, limit):
    require(not str(path).startswith(("\\\\", "//")), "network paths are unsupported")
    require(not str(path.resolve()).startswith(("\\\\", "//")), "network paths are unsupported")
    require(path.is_file(), "input must be a regular file")
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    require(len(data) <= limit, "input exceeds byte limit")
    require(data, "empty input")
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
            "SHA256 must be 64 lowercase hex characters")
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate manifest key")
        result[key] = value
    return result


def scalar(value, kind, endian):
    require(isinstance(value, str) and len(value) <= 128, "invalid scalar text")
    try:
        if kind.startswith("f"):
            number = float(value)
            require(math.isfinite(number), "non-finite scalar")
        else:
            number = int(value, 10)
        return struct.pack(("<" if endian == "little" else ">") + TYPES[kind], number)
    except (OverflowError, struct.error) as exc:
        raise ValueError("scalar outside selected type range") from exc
    except ValueError as exc:
        raise ValueError("invalid or non-finite scalar") from exc


def compare(manifest_path, expected_build, kind, endian, before_value,
            after_value, alignment=1, max_results=256):
    require(kind in TYPES and endian in ("little", "big"), "unsupported type or endian")
    require(type(alignment) is int and 1 <= alignment <= 4096, "alignment outside 1..4096")
    require(type(max_results) is int and 1 <= max_results <= 4096, "max-results outside 1..4096")
    sha(expected_build)
    old = scalar(before_value, kind, endian)
    new = scalar(after_value, kind, endian)
    require(old != new, "values encode identically; transition is not discriminating")
    raw = bounded_read(manifest_path, MAX_MANIFEST)
    manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    require(isinstance(manifest, dict) and set(manifest) == {
        "project", "version", "run", "before", "after"}, "invalid manifest fields")
    for key in ("project", "version", "run"):
        value = manifest[key]
        require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", value),
                "project/version/run must be bounded non-secret identifiers")
    blobs = []
    identities = []
    hashes = []
    for phase in ("before", "after"):
        item = manifest[phase]
        require(isinstance(item, dict) and set(item) == {
            "path", "sha256", "build_sha256", "region_id", "region_start"},
            "invalid snapshot descriptor")
        require(sha(item["build_sha256"]) == expected_build,
                "build mismatch: re-acquire same-build snapshots; do not reuse offsets")
        require(isinstance(item["region_id"], str) and
                re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", item["region_id"]), "invalid region id")
        require(type(item["region_start"]) is int and
                0 <= item["region_start"] <= 2**64 - 1, "invalid region start")
        require(isinstance(item["path"], str) and 0 < len(item["path"]) <= 4096,
                "invalid snapshot path")
        path = Path(item["path"])
        require(not str(path).startswith(("\\\\", "//")), "network paths are unsupported")
        if not path.is_absolute():
            path = manifest_path.parent / path
        data = bounded_read(path, MAX_BYTES)
        require(digest(data) == sha(item["sha256"]), "snapshot SHA256 mismatch")
        blobs.append(data)
        hashes.append(digest(data))
        identities.append((item["region_id"], item["region_start"]))
    require(identities[0] == identities[1], "region identity/origin mismatch")
    before, after = blobs
    require(len(before) == len(after), "length changed: re-capture the same mapped region")
    require(len(before) >= len(old), "snapshot shorter than scalar")
    count = 0
    offsets = []
    cursor = 0
    while True:
        offset = before.find(old, cursor)
        if offset < 0:
            break
        cursor = offset + 1
        if offset % alignment == 0 and after.startswith(new, offset):
            count += 1
            if len(offsets) < max_results:
                offsets.append(offset)
    status = "not_found" if count == 0 else "unique_candidate" if count == 1 else "ambiguous"
    return {"ok": True, "status": status,
            **{key: manifest[key] for key in ("project", "version", "run")},
            "build_sha256": expected_build, "snapshot_sha256": hashes,
            "region_id": identities[0][0], "region_start": identities[0][1],
            "length": len(before), "type": kind, "endian": endian,
            "before_encoded_hex": old.hex(), "after_encoded_hex": new.hex(),
            "alignment": alignment, "candidate_count": count,
            "offsets": offsets, "truncated": count > len(offsets),
            "offset_basis": "zero-based snapshot-relative bytes; not VA/RVA or pointer chain",
            "scope": "exact encoded transition only; build/region provenance supplied by operator"}


def self_test(root):
    root.mkdir(parents=True, exist_ok=True)
    checks = []
    with tempfile.TemporaryDirectory(prefix="snapshot-test-", dir=root) as directory:
        folder = Path(directory)
        build = "a" * 64
        def fixture(before, after):
            manifest = {"project": "synthetic", "version": "v1", "run": "r1"}
            for phase, data in (("before", before), ("after", after)):
                (folder / (phase + ".bin")).write_bytes(data)
                manifest[phase] = {"path": phase + ".bin", "sha256": digest(data),
                                   "build_sha256": build, "region_id": "fixture", "region_start": 0}
            return manifest
        def run(manifest, **kwargs):
            path = folder / "pair.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            options = dict(kind="i32", endian="little", before_value="100", after_value="75")
            options.update(kwargs)
            return compare(path, build, **options)
        def rejected(name, manifest, **kwargs):
            try:
                run(manifest, **kwargs)
            except (ValueError, OSError):
                checks.append(name)
                return
            raise AssertionError(name + " was accepted")
        old, new = struct.pack("<i", 100), struct.pack("<i", 75)
        m = fixture(b"XYZ" + old + b"tail", b"XYZ" + new + b"tail")
        result = run(m)
        assert result["offsets"] == [3] and result["status"] == "unique_candidate"
        checks.append("unique unaligned transition at byte 3")
        assert run(m, alignment=4)["status"] == "not_found"
        checks.append("alignment excludes unaligned candidate")
        assert run(m, after_value="74")["status"] == "not_found"
        checks.append("wrong control value not found")
        m = fixture(old * 3, new * 3)
        result = run(m, max_results=1)
        assert result["status"] == "ambiguous" and result["candidate_count"] == 3 and result["truncated"]
        checks.append("multiple hits retained as ambiguity with exact count")
        m["after"]["build_sha256"] = "b" * 64
        rejected("mixed builds rejected", m)
        m["before"]["build_sha256"] = "b" * 64
        rejected("two old-build snapshots rejected against expected build", m)
        m = fixture(old, new + b"x")
        rejected("length change rejected", m)
        m = fixture(old, new)
        m["after"]["region_start"] = 4
        rejected("region origin mismatch rejected", m)
        m = fixture(old, new)
        m["after"]["sha256"] = "0" * 64
        rejected("tampered snapshot rejected", m)
        m = fixture(old, new)
        rejected("unchanged encoded values rejected", m, after_value="100")
        rejected("integer overflow rejected", m, before_value=str(2**40))
        rejected("nonfinite float rejected", m, kind="f32", before_value="nan")
        m = fixture(b"p" + struct.pack(">h", -10), b"p" + struct.pack(">h", 20))
        assert run(m, kind="i16", endian="big", before_value="-10", after_value="20")["offsets"] == [1]
        checks.append("big endian signed transition")
        m = fixture(struct.pack("<f", 1.5), struct.pack("<f", 2.5))
        assert run(m, kind="f32", before_value="1.5", after_value="2.5")["offsets"] == [0]
        checks.append("float32 encoded transition")
        path = folder / "oversize.bin"
        with path.open("wb") as handle:
            handle.truncate(MAX_BYTES + 1)
        try:
            bounded_read(path, MAX_BYTES)
            raise AssertionError("oversize accepted")
        except ValueError:
            checks.append("oversize input rejected")
    return {"ok": True, "scope": "synthetic offline tests only", "checks": checks, "count": len(checks)}


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, '{"ok":false,"reason":"invalid arguments; use --help"}\n')


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, help="JSON pair manifest; see SKILL.md")
    parser.add_argument("--build-sha256", help="expected current executable/module SHA256")
    parser.add_argument("--type", choices=TYPES)
    parser.add_argument("--endian", choices=("little", "big"))
    parser.add_argument("--before", help="known scalar before controlled action (decimal)")
    parser.add_argument("--after", help="known scalar after controlled action (decimal)")
    parser.add_argument("--alignment", type=int, default=1, help="snapshot-relative alignment, 1..4096")
    parser.add_argument("--max-results", type=int, default=256, help="report cap, 1..4096; total count remains exact")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--self-test-dir", type=Path, default=Path("tmp/capability-logs/game-runtime"))
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            result = self_test(args.self_test_dir)
        else:
            require(all(value is not None for value in (args.manifest, args.build_sha256,
                    args.type, args.endian, args.before, args.after)), "missing comparison arguments; see --help")
            result = compare(args.manifest, args.build_sha256, args.type, args.endian,
                             args.before, args.after, args.alignment, args.max_results)
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
        # Never print raw snapshot bytes, paths, or malformed input content.
        reason = str(exc) if type(exc) is ValueError else type(exc).__name__
        print(json.dumps({"ok": False, "status": "invalid_input", "reason": reason}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
