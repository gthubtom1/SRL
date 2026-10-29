#!/usr/bin/env python3
"""Offline firmware triage: container magic, entropy, credential clues, next commands.

Pure Python standard library. No network, no execution of the sample.

Usage:
  python fw-triage.py --file firmware.bin
  python fw-triage.py --file firmware.bin --json
  python fw-triage.py --file firmware.bin --max-scan-mb 512

Exit codes:
  0  analysis completed (findings may still need manual verification)
  2  bad input / unreadable file
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import mmap
import os
import posixpath
import re
import shlex
import shutil
import sys
import tempfile
import time
from collections import Counter

VERSION = "1.1.0"

# (type, magic, description, search_everywhere)
SIGNATURES = [
    ("squashfs", b"hsqs", "SquashFS little-endian (hsqs)", True),
    ("squashfs", b"sqsh", "SquashFS big-endian (sqsh)", True),
    ("squashfs", b"qshs", "SquashFS variant (qshs)", True),
    ("squashfs", b"shsq", "SquashFS variant (shsq)", True),
    ("ubi", b"UBI#", "UBI erase-count header (UBI#)", True),
    ("cramfs", b"\x45\x3d\xcd\x28", "CramFS little-endian", True),
    ("cramfs", b"\x28\xcd\x3d\x45", "CramFS big-endian", True),
    ("jffs2", b"\x85\x19", "JFFS2 node magic 0x1985 (LE)", True),
    ("jffs2", b"\x19\x85", "JFFS2 node magic 0x1985 (BE)", True),
    ("tar", b"ustar", "POSIX tar (ustar at header+257)", True),
    ("gzip", b"\x1f\x8b", "gzip stream", True),
    ("zstd", b"\x28\xb5\x2f\xfd", "Zstandard frame", True),
    ("xz", b"\xfd7zXZ\x00", "XZ stream", True),
    ("bzip2", b"BZh", "bzip2 stream", True),
    ("zip", b"PK\x03\x04", "ZIP archive", True),
    ("7z", b"7z\xbc\xaf'\x1c", "7-Zip archive", True),
    ("cpio", b"070701", "cpio newc archive", True),
    ("cpio", b"070702", "cpio crc archive", True),
    ("uimage", b"\x27\x05\x19\x56", "U-Boot uImage", True),
    ("dtb", b"\xd0\x0d\xfe\xed", "Flattened device tree", True),
    ("trx", b"HDR0", "Broadcom TRX container", True),
    ("elf", b"\x7fELF", "ELF executable/object", True),
    ("pe", b"MZ", "PE/COFF (DOS MZ header)", False),
]

CRED_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", re.I)),
    ("certificate", re.compile(r"-----BEGIN CERTIFICATE-----", re.I)),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("ssh-public-key", re.compile(r"\bssh-(?:rsa|dss|ed25519)\s+AAAA[0-9A-Za-z+/=]{20,}")),
    ("shadow-entry", re.compile(r"^[A-Za-z0-9_.-]+:\$[0-9a-z]+\$[^\s:]{8,}")),
    ("passwd-entry", re.compile(r"^(?:root|admin|user|guest|support):[^:\r\n]{0,64}:\d+:\d+:")),
    ("password-assign", re.compile(r"(?i)\b(?:password|passwd|pwd|pass)\s*[=:]\s*\S{3,128}")),
    ("secret-assign", re.compile(r"(?i)\b(?:secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[=:]\s*\S{4,160}")),
    ("wifi-psk", re.compile(r"(?i)\b(?:wpa[_-]?passphrase|psk)\s*[=:]\s*\S{6,128}")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{12,}")),
]

SERVICE_HINTS = [
    ("telnet", re.compile(rb"\btelnetd\b", re.I)),
    ("ssh", re.compile(rb"\bdropbear\b|\bsshd\b", re.I)),
    ("http", re.compile(rb"\b(?:httpd|uhttpd|lighttpd|goahead|boa)\b", re.I)),
    ("nvram", re.compile(rb"\bnvram\b", re.I)),
    ("mtd", re.compile(rb"/dev/mtd|mtdparts", re.I)),
    ("init", re.compile(rb"/etc/init\.d|/etc/rc\.d|inittab", re.I)),
]

STRING_RE = re.compile(rb"[\x09\x20-\x7e]{6,512}")


def human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024.0 or unit == "TiB":
            return "%.1f %s" % (value, unit)
        value /= 1024.0
    return "%d B" % n


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = float(len(data))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def entropy_profile(mm, size: int, max_sample: int = 16 * 1024 * 1024):
    if size == 0:
        return {"overall": 0.0, "max_block": 0.0, "high_block_ratio": 0.0,
                "sampled_bytes": 0, "sample_truncated": False}
    sample = mm[:min(size, max_sample)]
    truncated = size > len(sample)
    if truncated and size > 1024 * 1024:
        sample = sample + mm[-1024 * 1024:]
    blocks = [sample[i:i + 4096] for i in range(0, len(sample), 4096)]
    block_entropies = [entropy(b) for b in blocks if len(b) >= 256]
    high = sum(1 for e in block_entropies if e >= 7.2)
    return {
        "overall": round(entropy(sample), 3),
        "max_block": round(max(block_entropies) if block_entropies else 0.0, 3),
        "high_block_ratio": round(high / len(block_entropies), 3) if block_entropies else 0.0,
        "sampled_bytes": len(sample),
        "sample_truncated": truncated,
    }


def find_containers(mm, size: int, max_hits: int = 24):
    hits = []
    seen = set()
    for kind, magic, desc, everywhere in SIGNATURES:
        if not everywhere:
            if size >= len(magic) and mm[:len(magic)] == magic:
                hits.append({"offset": 0, "type": kind, "description": desc,
                             "confidence": "high"})
            continue
        start = 0
        found = 0
        while found < 8:
            idx = mm.find(magic, start)
            if idx < 0:
                break
            start = idx + 1
            offset = idx - 257 if kind == "tar" and idx >= 257 else idx
            if offset < 0:
                continue
            if kind == "tar" and size >= offset + 262 and mm[offset + 257:offset + 262] != b"ustar":
                continue
            key = (kind, offset)
            if key in seen:
                continue
            seen.add(key)
            confidence = "high"
            if kind == "jffs2":
                confidence = "medium"  # 0x1985 occurs in random data; confirm node headers
            hits.append({"offset": offset, "type": kind, "description": desc,
                         "confidence": confidence})
            found += 1
    total = len(hits)
    hits.sort(key=lambda item: (0 if item["confidence"] == "high" else 1, item["offset"]))
    hits = hits[:max_hits]
    hits.sort(key=lambda item: (item["offset"], item["type"]))
    return hits, max(0, total - len(hits))


def redact(sample: str) -> str:
    """Keep enough context to locate the clue, never the secret itself."""
    text = " ".join(sample.split())
    low = text.lower()
    if "begin" in low and "private key" in low:
        return "-----BEGIN ... PRIVATE KEY----- <redacted>"
    if "begin" in low and "certificate" in low:
        return "-----BEGIN CERTIFICATE----- <redacted>"
    match = re.search(
        r"(?i)((?:password|passwd|pwd|pass|secret|token|api[_-]?key|access[_-]?key|"
        r"wpa[_-]?passphrase|psk)\s*[=:]\s*)(\S+)", text)
    if match:
        return match.group(1) + "<redacted>"
    match = re.search(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b", text)
    if match:
        return "<redacted aws-access-key>"
    if low.startswith("ssh-") or re.search(r"\bssh-(?:rsa|dss|ed25519)\s+", text, re.I):
        return "<redacted ssh-public-key>"
    if re.search(r"\bbearer\s+\S+", text, re.I):
        return "Bearer <redacted>"
    # passwd/shadow-shaped records are useful only as a username plus the fact
    # that the second field was present. Never echo the field itself.
    identity = re.search(r"(?:^|\s)([A-Za-z0-9_.-]+):([^:\s]+):", text)
    if identity and (identity.group(2).startswith("$") or text.count(":") >= 6):
        return identity.group(1) + ":<redacted>"
    # This function is only called after a credential regex matched. A miss in
    # the specific formatters must therefore fail closed instead of returning
    # an arbitrary 48-character prefix that can contain the secret.
    return "<redacted credential clue>"


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


def collect_clues(mm, size: int, max_scan: int, max_clues: int):
    scan = mm[:min(size, max_scan)]
    clues = []
    seen = set()
    for match in STRING_RE.finditer(scan):
        raw = match.group()
        try:
            text = raw.decode("latin-1")
        except Exception:
            continue
        for kind, pattern in CRED_PATTERNS:
            if not pattern.search(text):
                continue
            snippet = redact(text)
            key = (kind, snippet)
            if key in seen:
                continue
            seen.add(key)
            clues.append({"offset": match.start(), "type": kind, "snippet": snippet})
            if len(clues) >= max_clues:
                return clues, True
        if len(clues) >= max_clues:
            return clues, True
    return clues, False


def collect_service_hints(mm, size: int, max_scan: int):
    scan = mm[:min(size, max_scan)]
    found = {}
    for kind, pattern in SERVICE_HINTS:
        match = pattern.search(scan)
        if match:
            found[kind] = match.start()
    return found


def quote(path: str) -> str:
    return shlex.quote(path)


def carve_template(path: str, offsets, out_dir: str) -> str:
    off = offsets[0] if offsets else 0
    return (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        "src = Path(%r).read_bytes()\n"
        "off = %d\n"
        "dst = Path(%r)\n"
        "dst.parent.mkdir(parents=True, exist_ok=True)\n"
        "dst.write_bytes(src[off:])\n"
        "print('carved', len(src) - off, 'bytes ->', dst)\n"
        "PY" % (path, off, posixpath.join(out_dir, "carved-at-%d.bin" % off))
    )


def build_commands(path: str, types, containers, tools, out_dir: str):
    q = quote(path)
    cmds = [
        "file %s && sha256sum %s" % (q, q),
        "strings -a -n 6 %s | grep -Ei 'passwd|shadow|password|secret|token|BEGIN .*PRIVATE|AKIA|ssh-rsa|telnetd|dropbear|httpd|nvram' | head -80" % q,
    ]
    offsets = sorted({c["offset"] for c in containers if c["type"] in types})
    if offsets and offsets != [0]:
        cmds.append("dd if=%s of=%s bs=1 skip=%d  # carve first embedded container" %
                    (q, quote(posixpath.join(out_dir, "part.bin")), offsets[0]))
        cmds.append(carve_template(path, offsets, out_dir))

    if tools.get("binwalk"):
        cmds.append("binwalk -E %s | head -40" % q)
        cmds.append("binwalk -e --run-as=root -C %s %s" % (quote(out_dir), q))
        cmds.append("binwalk --dd='.*' -C %s %s" % (quote(posixpath.join(out_dir, "raw")), q))
    else:
        cmds.append("# binwalk not found: use 7z first, then carve by the offsets above")
        cmds.append("7z l %s" % q)
        cmds.append("7z x %s -o%s" % (q, quote(out_dir)))
        cmds.append(carve_template(path, offsets, out_dir))

    if "squashfs" in types:
        target = q if 0 in offsets else quote(posixpath.join(out_dir, "part.bin"))
        cmds.append("unsquashfs -s %s" % target)
        cmds.append("unsquashfs -d %s -f %s" % (quote(posixpath.join(out_dir, "rootfs")), target))
        cmds.append("# non-standard SquashFS: sasquatch -d %s %s" %
                    (quote(posixpath.join(out_dir, "rootfs-sasquatch")), target))
        if tools.get("7z"):
            cmds.append("7z x %s -o%s  # 7z fallback when unsquashfs is unavailable" %
                        (target, quote(posixpath.join(out_dir, "rootfs-7z"))))
    if "ubi" in types:
        target = q if 0 in offsets else quote(posixpath.join(out_dir, "part.bin"))
        cmds.append("ubireader_display_info %s | head -80" % target)
        cmds.append("ubireader_extract_images -o %s %s" % (quote(posixpath.join(out_dir, "ubi")), target))
        cmds.append("ubireader_extract_files -o %s %s/*.ubi" %
                    (quote(posixpath.join(out_dir, "ubi-root")), quote(posixpath.join(out_dir, "ubi"))))
        cmds.append("# missing ubireader: python3 -m pip install --user ubi_reader  (needs approval)")
    if "cramfs" in types:
        cmds.append("cramfsck -x %s %s" % (quote(posixpath.join(out_dir, "cramfs")), q))
        cmds.append("7z x %s -o%s  # CramFS fallback" % (q, quote(posixpath.join(out_dir, "cramfs-7z"))))
    if "jffs2" in types:
        cmds.append("jefferson -d %s %s" % (quote(posixpath.join(out_dir, "jffs2")), q))
        cmds.append("# missing jefferson: python3 -m pip install --user jefferson  (needs approval)")
    if "tar" in types:
        cmds.append("tar -xvf %s -C %s" % (q, quote(out_dir)))
    if "gzip" in types:
        cmds.append("python3 -c \"import gzip,pathlib; pathlib.Path(r'%s').write_bytes(gzip.open(r'%s','rb').read())\"" %
                    (posixpath.join(out_dir, "gzip.out"), path))
        cmds.append("gzip -dc %s > %s" % (q, quote(posixpath.join(out_dir, "gzip.out"))))
    if "zstd" in types:
        cmds.append("zstd -d %s -o %s" % (q, quote(posixpath.join(out_dir, "zstd.out"))))
        cmds.append("7z x %s -o%s  # zstd fallback" % (q, quote(posixpath.join(out_dir, "zstd-7z"))))
    if "xz" in types:
        cmds.append("xz -dc %s > %s" % (q, quote(posixpath.join(out_dir, "xz.out"))))
    if "bzip2" in types:
        cmds.append("bzip2 -dc %s > %s" % (q, quote(posixpath.join(out_dir, "bzip2.out"))))
    if "zip" in types:
        cmds.append("7z x %s -o%s" % (q, quote(posixpath.join(out_dir, "zip"))))
    if "cpio" in types:
        cmds.append("mkdir -p %s && (cd %s && cpio -idmv < %s)" %
                    (quote(posixpath.join(out_dir, "cpio")), quote(posixpath.join(out_dir, "cpio")), q))
    if types and types <= {"pe", "elf", "dtb"}:
        cmds.append("# Not a firmware container: use the binary/ELF/DTB analysis route, not binwalk recursion.")
    cmds.append("grep -RInE 'root:|admin:|password|passwd|shadow|telnetd|dropbear|httpd' %s/etc 2>/dev/null | head -60" %
                quote(posixpath.join(out_dir, "rootfs")))
    cmds.append("find %s -type f \\( -name 'id_rsa*' -o -name '*.pem' -o -name '*.key' -o -name 'authorized_keys' \\) -print" %
                quote(posixpath.join(out_dir, "rootfs")))
    return cmds


def analyse(path: str, max_scan_mb: int, max_clues: int, out_dir: str):
    out_dir = out_dir.replace("\\", "/")
    result = {
        "tool": "fw-triage",
        "version": VERSION,
        "generated_at": (os.environ.get("SEEP_TIMESTAMP") or None),
        "file": path,
        "ok": True,
    }
    try:
        size = os.path.getsize(path)
        digest = sha256_file(path)
    except OSError as exc:
        return None, {"ok": False, "blocked_at": "input",
                       "reason": "%s: %s" % (type(exc).__name__, exc),
                       "error": {"code": "FILE_UNREADABLE",
                                 "message": str(exc), "path": path}}

    tools = {name: shutil.which(name) is not None
             for name in ("binwalk", "7z", "unsquashfs", "sasquatch", "ubireader_extract_images",
                          "jefferson", "cramfsck", "zstd", "strings")}
    max_scan = max(1, max_scan_mb) * 1024 * 1024

    if size == 0:
        result.update({"size": 0, "sha256": digest, "containers": [],
                       "containers_truncated": 0,
                       "entropy": {"overall": 0.0, "max_block": 0.0,
                                   "high_block_ratio": 0.0, "sampled_bytes": 0,
                                   "sample_truncated": False},
                       "credential_clues": [], "clues_truncated": False,
                       "service_hints": {}, "tools": tools,
                       "suggested_commands": ["file %s" % quote(path)],
                       "verdict": "empty file; nothing to triage"})
        return result, None

    with open(path, "rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            containers, hidden = find_containers(mm, size)
            types = {c["type"] for c in containers}
            ent = entropy_profile(mm, size)
            clues, clipped = collect_clues(mm, size, max_scan, max_clues)
            hints = collect_service_hints(mm, size, max_scan)
        finally:
            mm.close()

    if ent["overall"] >= 7.2 and ent["high_block_ratio"] >= 0.5:
        ent["interpretation"] = "high entropy: compressed/encrypted, or a packed filesystem; verify against magic hits"
    elif ent["overall"] < 6.0:
        ent["interpretation"] = "low entropy: mostly plaintext/metadata; look for headers and scripts"
    else:
        ent["interpretation"] = "mixed entropy: container + padding/compressed regions likely"

    if containers and types <= {"pe", "elf", "dtb"}:
        verdict = ("not a firmware container (%s): this is a bare binary/DTB. Use the binary/ELF/DTB route; "
                   "do not claim a rootfs was unpacked." % ", ".join(sorted(types)))
    elif containers:
        verdict = ("container magic found (%s); extract and verify /etc, /bin/busybox and a real service response. "
                   "Credential strings are leads only until located in the extracted rootfs." %
                   ", ".join(sorted(types)))
    elif ent["overall"] >= 7.2:
        verdict = ("no known container magic and high entropy: suspect encrypted/vendor container or raw compressed image; "
                   "check vendor header, U-Boot/kernel decryptor, then UART/SPI route.")
    else:
        verdict = ("no known container magic: raw kernel/ELF/PE, truncated image, or custom format; "
                   "confirm with file/binwalk and do not claim unpack success.")

    result.update({
        "size": size,
        "size_human": human_bytes(size),
        "sha256": digest,
        "containers": containers,
        "containers_truncated": hidden,
        "entropy": ent,
        "credential_clues": clues,
        "clues_truncated": clipped,
        "service_hints": hints,
        "tools": tools,
        "suggested_commands": build_commands(path, types, containers, tools, out_dir),
        "verdict": verdict,
        "limits": [
            "Triage only: it does not unpack, emulate, or prove J1/J2/J3.",
            "Credential clues are candidates; confirm file:line in the extracted rootfs and redact values.",
            "Offsets are absolute in the supplied file; carve before running unsquashfs/ubireader on an embedded image.",
        ],
    })
    return result, None


def self_test():
    """Offline self-test: built-in bytes only, no network, no external tools."""
    checks = 0
    tmp = tempfile.mkdtemp(prefix="fw-triage-selftest-")
    try:
        sample = os.path.join(tmp, "sample.bin")
        blob = (b"\x00" * 512 + b"hsqs" + b"\x00" * 128 + b"UBI#" + b"\x00" * 128 +
                b"root::0:0:root:/root:/bin/sh\n" +
                b"-----BEGIN RSA PRIVATE KEY-----\nMIIEabcdef\n-----END RSA PRIVATE KEY-----\n")
        with open(sample, "wb") as fh:
            fh.write(blob)
        result, err = analyse(sample, 1, 10, "out")
        assert err is None and result and result.get("ok") is True
        checks += 1
        types = {c["type"] for c in result["containers"]}
        assert {"squashfs", "ubi"} <= types, types
        checks += 1
        assert result["entropy"]["overall"] > 0.0
        checks += 1
        kinds = {c["type"] for c in result["credential_clues"]}
        assert "passwd-entry" in kinds, kinds
        checks += 1
        assert all("<redacted>" in c["snippet"] for c in result["credential_clues"]
                   if c["type"] == "private-key")
        checks += 1
        bearer = redact("header bearer abcdefghijklmnopqrstuvwxyz tail")
        assert "abcdefghijklmnopqrstuvwxyz" not in bearer and "<redacted>" in bearer
        checks += 1

        empty = os.path.join(tmp, "empty.bin")
        open(empty, "wb").close()
        empty_result, empty_err = analyse(empty, 1, 10, "out")
        assert empty_err is None and empty_result["size"] == 0
        checks += 1

        absent, absent_err = analyse(os.path.join(tmp, "missing.bin"), 1, 10, "out")
        assert absent is None and absent_err and absent_err.get("blocked_at") == "input"
        checks += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(json.dumps({"ok": True, "tool": "fw-triage", "version": VERSION,
                      "checks": checks}, ensure_ascii=False))
    return 0


def print_human(result, err):
    if err:
        print("[ERROR] %s: %s" % (err["error"]["code"], err["error"]["message"]))
        print(json.dumps(err, ensure_ascii=False, indent=2))
        return
    print("=" * 78)
    print("fw-triage %s  %s (%s)" % (result["version"], result["file"], result.get("size_human", "0 B")))
    print("sha256 %s" % result["sha256"])
    print("=" * 78)
    ent = result["entropy"]
    print("[entropy] overall=%.3f max_block=%.3f high_block_ratio=%.2f sampled=%s%s" %
          (ent["overall"], ent["max_block"], ent["high_block_ratio"],
           human_bytes(ent["sampled_bytes"]), " (truncated)" if ent.get("sample_truncated") else ""))
    print("          %s" % ent.get("interpretation", ""))
    print("\n[containers]")
    if not result["containers"]:
        print("  (none recognised)")
    for c in result["containers"]:
        print("  +0x%08x  %-10s %-42s [%s]" %
              (c["offset"], c["type"], c["description"], c["confidence"]))
    if result["containers_truncated"]:
        print("  ... %d more hits omitted" % result["containers_truncated"])
    print("\n[credential clues] %d%s" % (len(result["credential_clues"]),
                                         " (truncated)" if result["clues_truncated"] else ""))
    if not result["credential_clues"]:
        print("  (none in scanned strings; absence is not proof)")
    for clue in result["credential_clues"]:
        print("  +0x%08x  %-16s %s" %
              (clue["offset"], clue["type"], clue["snippet"]))
    if result["service_hints"]:
        print("\n[service hints] " + ", ".join(
            "%s@0x%x" % (k, v) for k, v in sorted(result["service_hints"].items())))
    print("\n[tool status] " + ", ".join(
        "%s=%s" % (k, "yes" if v else "no") for k, v in result["tools"].items()))
    print("\n[suggested commands]")
    for cmd in result["suggested_commands"]:
        print("  " + cmd.replace("\n", "\n  "))
    print("\n[verdict] " + result["verdict"])
    print("\n[limits]")
    for item in result["limits"]:
        print("  - " + item)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline firmware triage: magic/container, entropy, credential strings, extraction commands.")
    parser.add_argument("--file", help="firmware image to inspect (read-only)")
    parser.add_argument("--json", action="store_true", help="emit one JSON object")
    parser.add_argument("--max-scan-mb", type=positive_int, default=256,
                        help="max MiB scanned for strings/magic (default 256)")
    parser.add_argument("--max-clues", type=positive_int, default=80,
                        help="max credential clues reported (default 80)")
    parser.add_argument("--out-dir", default="work/fw-triage",
                        help="directory used in suggested extraction commands")
    parser.add_argument("--self-test", action="store_true",
                        help="run the offline built-in checks and exit (no file needed)")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.file:
        err = {"ok": False, "blocked_at": "input",
               "reason": "--file is required unless --self-test is used",
               "error": {"code": "FILE_REQUIRED",
                         "message": "--file is required unless --self-test is used",
                         "path": ""}}
        print(json.dumps(err, ensure_ascii=False, indent=2))
        if not args.json:
            print("[ERROR] FILE_REQUIRED: use --file or --self-test", file=sys.stderr)
        return 2

    if not os.path.exists(args.file):
        err = {"ok": False, "blocked_at": "input",
               "reason": "no such file: %s" % args.file,
               "error": {"code": "FILE_NOT_FOUND",
                         "message": "no such file", "path": args.file}}
        print(json.dumps(err, ensure_ascii=False, indent=2))
        if not args.json:
            print("[ERROR] FILE_NOT_FOUND: %s" % args.file, file=sys.stderr)
        return 2
    if not os.path.isfile(args.file):
        err = {"ok": False, "blocked_at": "input",
               "reason": "path is not a regular file: %s" % args.file,
               "error": {"code": "NOT_A_REGULAR_FILE",
                         "message": "path is not a regular file", "path": args.file}}
        print(json.dumps(err, ensure_ascii=False, indent=2))
        if not args.json:
            print("[ERROR] NOT_A_REGULAR_FILE: %s" % args.file, file=sys.stderr)
        return 2

    try:
        result, err = analyse(args.file, args.max_scan_mb, args.max_clues, args.out_dir)
    except OSError as exc:
        result, err = None, {
            "ok": False, "blocked_at": "input",
            "reason": "%s: %s" % (type(exc).__name__, exc),
            "error": {"code": "FILE_UNREADABLE", "message": str(exc), "path": args.file},
        }
    except Exception as exc:  # noqa: BLE001 - CLI must never leak a traceback
        result, err = None, {
            "ok": False, "blocked_at": "internal",
            "reason": "analysis failed: %s" % type(exc).__name__,
            "error": {"code": "ANALYSIS_FAILED", "message": type(exc).__name__,
                      "path": args.file},
        }
    if err:
        print(json.dumps(err, ensure_ascii=False, indent=2))
        if not args.json:
            print_human(None, err)
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_human(result, None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
