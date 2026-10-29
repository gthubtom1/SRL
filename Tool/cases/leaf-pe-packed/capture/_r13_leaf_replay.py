from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import struct
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[4]
CASE = ROOT / "Tool/cases/leaf-pe-packed"
CAPTURE = CASE / "capture"
HOME = ROOT / "tmp/r13-five/isolated/home"
TEMP = ROOT / "tmp/r13-five/isolated/temp"
AGENT = ROOT / "tmp/r13-five/isolated/agent"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def binding(path: Path) -> dict[str, str]:
    return {
        "path": path.relative_to(CASE).as_posix(),
        "sha256": sha256(path),
    }


def run(label: str, argv: list[str], *, stdin: bytes | None = None,
        watch: tuple[Path, ...] = ()) -> dict:
    stdout_path = CAPTURE / f"r13-{label}.stdout.txt"
    stderr_path = CAPTURE / f"r13-{label}.stderr.txt"
    before = {p.relative_to(ROOT).as_posix(): sha256(p) for p in watch}
    env = dict(os.environ)
    env.update({
        "HOME": str(HOME),
        "USERPROFILE": str(HOME),
        "TEMP": str(TEMP),
        "TMP": str(TEMP),
        "PI_CODING_AGENT_DIR": str(AGENT),
    })
    proc = subprocess.run(
        argv,
        cwd=ROOT,
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
        env=env,
    )
    stdout_path.write_bytes(proc.stdout)
    stderr_path.write_bytes(proc.stderr)
    after = {p.relative_to(ROOT).as_posix(): sha256(p) for p in watch}
    record = {
        "label": label,
        "argv": argv,
        "cwd": ".",
        "rc": proc.returncode,
        "stdout": binding(stdout_path),
        "stderr": binding(stderr_path),
        "watched_sha256_before": before,
        "watched_sha256_after": after,
        "watched_unmodified": before == after,
    }
    if stdin is not None:
        record["stdin"] = stdin.decode("utf-8", "replace")
    return record


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    size = len(data)
    return round(-sum((count / size) * math.log2(count / size)
                      for count in counts if count), 6)


def pe_facts(path: Path) -> dict:
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError("missing MZ header")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("missing PE signature")
    machine, count = struct.unpack_from("<HH", data, pe + 4)
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    entry_rva = struct.unpack_from("<I", data, optional + 16)[0]
    image_base = struct.unpack_from("<Q" if magic == 0x20B else "<I",
                                    data, optional + 24)[0]
    subsystem = struct.unpack_from("<H", data, optional + 68)[0]
    checksum = struct.unpack_from("<I", data, optional + 64)[0]
    table = optional + optional_size
    sections = []
    for index in range(count):
        off = table + index * 40
        raw_name = data[off:off + 8].split(b"\0", 1)[0]
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", data, off + 8
        )
        sections.append({
            "name": raw_name.decode("ascii", "replace"),
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": raw_size,
            "raw_pointer": raw_pointer,
            "entropy": entropy(data[raw_pointer:raw_pointer + raw_size]),
        })
    entry_section = next((s["name"] for s in sections
                          if s["virtual_address"] <= entry_rva <
                          s["virtual_address"] + max(s["virtual_size"], s["raw_size"])), None)
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "size": len(data),
        "sha256": sha256(path),
        "machine": hex(machine),
        "optional_magic": hex(magic),
        "image_base": hex(image_base),
        "subsystem": subsystem,
        "checksum": hex(checksum),
        "entry_rva": hex(entry_rva),
        "entry_section": entry_section,
        "sections": sections,
        "upx_magic_offsets": [hex(i) for i in range(len(data))
                              if data.startswith(b"UPX!", i)],
        "contains_PASS": data.find(b"PASS"),
        "contains_trance": data.find(b"trance"),
    }


def main() -> int:
    CAPTURE.mkdir(parents=True, exist_ok=True)
    for path in (HOME, TEMP, AGENT):
        path.mkdir(parents=True, exist_ok=True)
    python = sys.executable
    packed = CASE / "target/a_upx.exe"
    unpacked = CASE / "unpacked/a_unpacked.exe"
    patched = CASE / "artifacts/a_upx.patched.exe"
    watch = (packed, unpacked, patched)

    if "--inspect-only" in sys.argv[1:]:
        print(json.dumps({
            "ok": True,
            "packed": pe_facts(packed),
            "unpacked": pe_facts(unpacked),
            "patched": pe_facts(patched),
        }, ensure_ascii=False, indent=2))
        return 0

    static = run(
        "leaf-pe-structure",
        [python, "-B", "-X", "utf8",
         "Tool/cases/leaf-pe-packed/capture/_r13_leaf_replay.py", "--inspect-only"],
        watch=watch,
    )

    results = [static]
    for label, executable, text in (
        ("packed-trance", packed, "trance"),
        ("packed-wrong", packed, "wrong"),
        ("unpacked-wrong", unpacked, "wrong"),
        ("patched-wrong", patched, "wrong"),
    ):
        results.append(run(
            f"leaf-{label}",
            [executable.relative_to(ROOT).as_posix()],
            stdin=(text + "\n").encode("ascii"),
            watch=watch,
        ))

    payload = {
        "ok": True,
        "schema": "seep.r13-case-repro/1",
        "case": "leaf-pe-packed",
        "results": results,
        "all_rc_zero": all(item["rc"] == 0 for item in results),
        "all_watched_unmodified": all(item["watched_unmodified"] for item in results),
    }
    out = CAPTURE / "r13-repro.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "case": "leaf-pe-packed",
        "rc": [item["rc"] for item in results],
        "watched": payload["all_watched_unmodified"],
        "output": out.relative_to(ROOT).as_posix(),
    }, ensure_ascii=False))
    return 0 if payload["all_rc_zero"] and payload["all_watched_unmodified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
