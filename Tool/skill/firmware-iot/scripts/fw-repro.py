#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fw-repro.py -- offline carve + extract + rootfs evidence for a firmware image.

It does four things and stops there:

  1. identify the outer format (PE/ELF/Broadcom blob/SquashFS/UBI/...);
  2. carve the first filesystem/archive container to <out-dir>/carved-<off>.bin;
  3. extract it with standard-library code first, external tools second;
  4. scan the extracted tree for accounts, keys, init scripts, services and
     dangerous calls, with values redacted and file:line evidence kept.

It never boots, emulates, flashes or executes the sample. Missing external
tools are reported as {"blocked_at": "tool-missing"} instead of a traceback.

Usage:
  python fw-repro.py --file firmware.bin
  python fw-repro.py --file firmware.bin --out-dir work/fw-repro --json
  python fw-repro.py --self-test

Exit codes:
  0  analysis completed (extraction may have been skipped/not applicable)
  1  extraction of a filesystem container failed with the tools present
  2  blocked: input unreadable, or a filesystem container needs a missing tool
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import hashlib
import json
import lzma
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from collections import Counter

VERSION = "1.0.0"
MAX_READ = 64 * 1024 * 1024

FIXTURE_WORDS = ("夹具", "教学", "fixture", "示例")

KEY_NAMES = {
    "passwd": re.compile(r"(^|/)etc/passwd$"),
    "shadow": re.compile(r"(^|/)etc/shadow$"),
    "inittab": re.compile(r"(^|/)etc/inittab$"),
    "init.d": re.compile(r"(^|/)etc/(init\.d|rc\.d)/"),
    "cgi": re.compile(r"(^|/)(cgi-bin|www/cgi-bin|htdocs/cgi-bin)/"),
    "web-root": re.compile(r"(^|/)(www|htdocs|webui|lighttpd)/"),
    "private-key": re.compile(r"\.(pem|key|p12|pfx)$|(^|/)id_(rsa|ecdsa|ed25519)$"),
    "authorized-keys": re.compile(r"(^|/)authorized_keys$"),
}

TEXT_LIMIT = 256 * 1024
MAX_FINDINGS = 200

CRED_RULES = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")),
    ("certificate", re.compile(r"-----BEGIN CERTIFICATE-----")),
    ("empty-password", re.compile(r"(?m)^(?:root|admin|support):(?::|:[^:]*:0:0:)")),
    ("shadow-hash", re.compile(r"(?m)^(?:root|admin):\$[0-9a-z]+\$")),
    ("password-assign", re.compile(r"(?i)\b(?:password|passwd|pwd|pass)\s*[=:]\s*\S{3,128}")),
    ("secret-assign", re.compile(r"(?i)\b(?:secret|token|api[_-]?key|access[_-]?key)\s*[=:]\s*\S{4,160}")),
    ("ssh-public", re.compile(r"\bssh-(?:rsa|dss|ed25519)\s+AAAA[0-9A-Za-z+/=]{20,}")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{12,}")),
]

SERVICE_RULES = [
    ("telnetd", re.compile(r"\btelnetd\b")),
    ("dropbear", re.compile(r"\bdropbear\b")),
    ("httpd", re.compile(r"\b(?:uhttpd|lighttpd|goahead|boa|httpd)\b")),
    ("nvram", re.compile(r"\bnvram\b")),
    ("mtd", re.compile(r"/dev/mtd|mtdparts")),
    ("cgi-system", re.compile(r"\b(?:system|popen|execve|exec)\s*\(")),
    ("shell-meta", re.compile(r"\$\((?:[^)]*)\$|`[^`]+`|\$\{?(?:QUERY_STRING|HTTP_|REMOTE_ADDR)")),
]

PE_MACHINES = {0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM", 0x01C4: "ARMv7",
               0xAA64: "ARM64", 0x0200: "IA64", 0x5064: "RISCV64"}
UEFI_SUBSYSTEMS = {10: "EFI application", 11: "EFI boot service driver",
                   12: "EFI runtime driver", 13: "EFI ROM",
                   16: "Windows boot application (UEFI-era)"}
UEFI_CLUES = (b"EFI_BOOT_SERVICES", b"EFI_SYSTEM_TABLE", b"LoadImage",
              b"gBS->", b"SecureBoot", b"EFI_STATUS")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    total = float(len(data))
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def read_limited(path, limit=MAX_READ):
    size = os.path.getsize(path)
    with open(path, "rb") as fh:
        data = fh.read(limit)
    return data, size, size > len(data)


def u16(data, off, endian="<"):
    if off + 2 > len(data):
        return 0
    return struct.unpack_from(endian + "H", data, off)[0]


def u32(data, off, endian="<"):
    if off + 4 > len(data):
        return 0
    return struct.unpack_from(endian + "I", data, off)[0]


def parse_pe(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    lfanew = u32(data, 0x3C)
    if lfanew + 24 > len(data) or data[lfanew:lfanew + 4] != b"PE\x00\x00":
        return None
    coff = lfanew + 4
    machine = u16(data, coff)
    nsec = u16(data, coff + 2)
    opt_size = u16(data, coff + 16)
    opt = coff + 20
    magic = u16(data, opt)
    subsystem = u16(data, opt + 68)
    sec_off = opt + opt_size
    sections = []
    for i in range(min(nsec, 64)):
        off = sec_off + i * 40
        if off + 40 > len(data):
            break
        name = data[off:off + 8].rstrip(b"\x00").decode("latin-1", "replace")
        raw_size = u32(data, off + 16)
        raw_ptr = u32(data, off + 20)
        body = data[raw_ptr:raw_ptr + raw_size] if raw_size and raw_ptr < len(data) else b""
        sections.append({"name": name, "raw_offset": raw_ptr, "raw_size": raw_size,
                         "entropy": round(entropy(body[:4 * 1024 * 1024]), 3)})
    clues = [c.decode("ascii") for c in UEFI_CLUES if c in data[:8 * 1024 * 1024]]
    return {
        "kind": "pe",
        "machine": PE_MACHINES.get(machine, "0x%04x" % machine),
        "machine_id": "0x%04x" % machine,
        "subsystem": UEFI_SUBSYSTEMS.get(subsystem, "0x%04x" % subsystem),
        "subsystem_id": subsystem,
        "is_uefi": subsystem in UEFI_SUBSYSTEMS or len(clues) >= 2,
        "uefi_clues": clues,
        "sections": sections,
        "overall_entropy": round(entropy(data[:4 * 1024 * 1024]), 3),
    }


def parse_elf(data):
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        return None
    cls = {1: "ELF32", 2: "ELF64"}.get(data[4], "ELF?")
    endian = "<" if data[5] == 1 else ">"
    machine = u16(data, 18, endian)
    names = {3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}
    return {"kind": "elf", "class": cls, "endian": "little" if endian == "<" else "big",
            "machine": names.get(machine, "0x%04x" % machine), "machine_id": machine,
            "entry": u32(data, 24, endian)}


def scan_brcm(data):
    offsets = []
    start = 0
    while len(offsets) < 32:
        idx = data.find(b"BRCM", start)
        if idx < 0:
            break
        offsets.append(idx)
        start = idx + 1
    if not offsets:
        return None
    tail = data[-4096:].decode("latin-1", "replace")
    meta = {}
    for key, pattern in (("version", r"Version:\s*([0-9][0-9A-Za-z._-]{2,40})"),
                         ("fwid", r"FWID:\s*([0-9a-fA-F.-]{1,80})"),
                         ("date", r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"),
                         ("pdt", r"PDT\s+([^\r\n\x00]{1,80})")):
        match = re.search(pattern, tail)
        if match:
            meta[key] = match.group(1).strip()
    return {"kind": "brcm", "tag_offsets": offsets, "tail_meta": meta,
            "header_dwords": [u32(data, i * 4) for i in range(min(8, len(data) // 4))]}


def detect_formats(data):
    found = []

    def add(kind, offset, note):
        found.append({"type": kind, "offset": offset, "note": note})

    if parse_pe(data):
        add("pe", 0, "PE/COFF (MZ + PE signature)")
    if data[:4] == b"\x7fELF":
        add("elf", 0, "ELF header")
    for offset in (0,):
        if data[offset:offset + 4] in (b"hsqs", b"sqsh", b"qshs", b"shsq"):
            add("squashfs", offset, "SquashFS superblock")
    idx = data.find(b"UBI#")
    while idx >= 0 and len([f for f in found if f["type"] == "ubi"]) < 8:
        add("ubi", idx, "UBI erase-count header")
        idx = data.find(b"UBI#", idx + 1)
    if data[:4] in (b"\x45\x3d\xcd\x28", b"\x28\xcd\x3d\x45"):
        add("cramfs", 0, "CramFS superblock")
    for magic, note in ((b"\x85\x19", "JFFS2 node 0x1985 LE"), (b"\x19\x85", "JFFS2 node 0x1985 BE")):
        idx = data.find(magic)
        if idx >= 0:
            add("jffs2", idx, note + " (weak signature)")
            break
    for magic, kind, note in ((b"\x1f\x8b", "gzip", "gzip stream"),
                             (b"\xfd7zXZ\x00", "xz", "XZ stream"),
                             (b"BZh", "bzip2", "bzip2 stream"),
                             (b"\x28\xb5\x2f\xfd", "zstd", "Zstandard frame")):
        idx = data.find(magic)
        if idx >= 0:
            add(kind, idx, note)
    idx = data.find(b"PK\x03\x04")
    if idx >= 0:
        add("zip", idx, "ZIP local file header")
    if data[257:262] == b"ustar":
        add("tar", 0, "POSIX tar header")
    idx = data.find(b"070701")
    if idx < 0:
        idx = data.find(b"070702")
    if idx >= 0:
        add("cpio", idx, "cpio newc archive")
    if data[:4] == b"\x27\x05\x19\x56":
        add("uimage", 0, "U-Boot uImage")
    if data[:4] == b"\xd0\x0d\xfe\xed":
        add("dtb", 0, "Flattened device tree")
    if data[:4] == b"HDR0":
        add("trx", 0, "Broadcom TRX")
    if scan_brcm(data):
        first = scan_brcm(data)["tag_offsets"][0]
        add("brcm", first, "Broadcom firmware tag")
    return found


PRIMARY_ORDER = ["squashfs", "ubi", "cramfs", "zip", "tar", "cpio",
                 "uimage", "dtb", "trx", "pe", "elf", "brcm",
                 "gzip", "xz", "bzip2", "zstd", "jffs2"]
PRIMARY_GROUPS = [
    ("filesystem", ("squashfs", "ubi", "cramfs", "zip", "tar", "cpio")),
    ("boot-image", ("uimage", "dtb", "trx")),
    ("binary", ("pe", "elf", "brcm")),
    ("stream", ("gzip", "xz", "bzip2", "zstd")),
    ("weak-signature", ("jffs2",)),
]
EXTERNAL = {
    "squashfs": ["unsquashfs", "sasquatch", "7z"],
    "ubi": ["ubireader_extract_files", "7z"],
    "cramfs": ["cramfsck", "7z"],
    "jffs2": ["jefferson", "7z"],
    "cpio": ["cpio", "7z"],
    "zstd": ["zstd", "7z"],
}


def choose_primary(formats):
    """Prefer a real filesystem/archive over a bare binary, and both over a weak hit."""
    for _group, kinds in PRIMARY_GROUPS:
        for kind in kinds:
            hits = [f for f in formats if f["type"] == kind]
            if hits:
                return min(hits, key=lambda f: f["offset"])
    return None


def safe_join(dest, name):
    dest_abs = os.path.abspath(dest)
    target = os.path.abspath(os.path.join(dest_abs, name))
    if target != dest_abs and not target.startswith(dest_abs + os.sep):
        raise ValueError("unsafe archive member: %s" % name)
    rel = os.path.relpath(target, dest_abs)
    cursor = dest_abs
    for part in rel.split(os.sep):
        cursor = os.path.join(cursor, part)
        if os.path.islink(cursor):
            raise ValueError("unsafe archive member traverses symlink: %s" % name)
    return target


def extract_zip(path, dest):
    written = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            target = safe_join(dest, info.filename)
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            written.append(os.path.relpath(target, dest).replace(os.sep, "/"))
    return written


def extract_tar(path, dest):
    written = []
    with tarfile.open(path, "r:*") as tf:
        for member in tf.getmembers():
            target = safe_join(dest, member.name)
            if member.isdir():
                os.makedirs(target, exist_ok=True)
                continue
            if not member.isfile():
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            written.append(os.path.relpath(target, dest).replace(os.sep, "/"))
    return written


def extract_stream(kind, src_path, dest):
    if kind == "gzip":
        with gzip.open(src_path, "rb") as src:
            body = src.read(MAX_READ + 1)
    elif kind == "xz":
        with lzma.open(src_path, "rb") as src:
            body = src.read(MAX_READ + 1)
    elif kind == "bzip2":
        with bz2.open(src_path, "rb") as src:
            body = src.read(MAX_READ + 1)
    else:
        raise ValueError(kind)
    if len(body) > MAX_READ:
        raise ValueError("decompressed stream exceeds the %d-byte analysis limit" % MAX_READ)
    os.makedirs(dest, exist_ok=True)
    out = os.path.join(dest, kind + ".out")
    with open(out, "wb") as fh:
        fh.write(body)
    return [os.path.basename(out)], body


def run_external(kind, src_path, dest, attempts):
    for tool in EXTERNAL.get(kind, []):
        exe = shutil.which(tool)
        if not exe:
            continue
        if tool == "7z":
            cmd = [exe, "x", src_path, "-o" + dest, "-y"]
        elif tool == "cramfsck":
            cmd = [exe, "-x", dest, src_path]
        elif tool == "ubireader_extract_files":
            cmd = [exe, "-o", dest, src_path]
        elif tool == "unsquashfs":
            cmd = [exe, "-d", dest, "-f", src_path]
        elif tool == "sasquatch":
            cmd = [exe, "-d", dest, "-f", src_path]
        elif tool == "jefferson":
            cmd = [exe, "-d", dest, src_path]
        elif tool == "zstd":
            cmd = [exe, "-d", "-f", src_path, "-o", os.path.join(dest, "zstd.out")]
        elif tool == "cpio":
            os.makedirs(dest, exist_ok=True)
            with open(src_path, "rb") as fh:
                proc = subprocess.run([exe, "-idmv"], stdin=fh, cwd=dest,
                                      capture_output=True, timeout=180)
            attempts.append({"tool": tool, "rc": proc.returncode,
                             "stderr": proc.stderr.decode("utf-8", "replace")[-400:]})
            if proc.returncode == 0:
                return written_tree(dest)
            continue
        else:
            cmd = [exe, src_path]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=180)
        except Exception as exc:  # noqa: BLE001
            attempts.append({"tool": tool, "rc": None, "stderr": str(exc)[:200]})
            continue
        attempts.append({"tool": tool, "rc": proc.returncode,
                         "stderr": proc.stderr.decode("utf-8", "replace")[-400:]})
        if proc.returncode == 0:
            written = written_tree(dest)
            if written:
                return written
    return None


def written_tree(dest):
    out = []
    if not os.path.isdir(dest):
        return out
    for dp, dn, fn in os.walk(dest):
        for name in fn:
            out.append(os.path.relpath(os.path.join(dp, name), dest).replace(os.sep, "/"))
            if len(out) >= 20000:
                return out
    return out


def redact(text):
    text = text.split("\n", 1)[0]
    low = text.lower()
    if "begin" in low and "private key" in low:
        return "-----BEGIN ... PRIVATE KEY----- <redacted>"
    if "begin" in low and "certificate" in low:
        return "-----BEGIN CERTIFICATE----- <redacted>"
    match = re.search(r"(?i)((?:password|passwd|pwd|pass|secret|token|api[_-]?key)\s*[=:]\s*)(\S+)", text)
    if match:
        return match.group(1) + "<redacted>"
    if re.search(r"\bbearer\s+\S+", text, re.I):
        return "Bearer <redacted>"
    if re.search(r"\bssh-(?:rsa|dss|ed25519)\s+", text, re.I):
        return "<redacted ssh-public-key>"
    identity = re.search(r"(?:^|\s)([A-Za-z0-9_.-]+):([^:\s]+):", text)
    if identity and (identity.group(2).startswith("$") or text.count(":") >= 6):
        return identity.group(1) + ":<redacted>"
    # The caller reached this function only after a sensitive-data rule
    # matched. Fail closed rather than echoing an arbitrary prefix.
    return "<redacted credential clue>"


def scan_tree(dest):
    report = {"dirs": 0, "files": 0, "bytes": 0, "key_files": [], "findings": [],
              "top_dirs": [], "truncated": False, "skipped_symlinks": 0}
    if not os.path.isdir(dest):
        return report
    seen = set()
    for dp, dn, fn in os.walk(dest):
        report["dirs"] += 1
        for name in list(dn):
            if os.path.islink(os.path.join(dp, name)):
                report["skipped_symlinks"] += 1
                dn.remove(name)
        rel_dir = os.path.relpath(dp, dest).replace(os.sep, "/")
        if rel_dir != "." and rel_dir.count("/") == 0 and rel_dir not in report["top_dirs"]:
            report["top_dirs"].append(rel_dir)
        for name in fn:
            full = os.path.join(dp, name)
            if os.path.islink(full):
                report["skipped_symlinks"] += 1
                continue
            rel = os.path.relpath(full, dest).replace(os.sep, "/")
            report["files"] += 1
            try:
                report["bytes"] += os.path.getsize(full)
            except OSError:
                pass
            for kind, pattern in KEY_NAMES.items():
                if pattern.search(rel):
                    report["key_files"].append({"kind": kind, "path": rel})
                    break
            try:
                with open(full, "rb") as stream:
                    body = stream.read(TEXT_LIMIT)
            except OSError:
                continue
            text = body.decode("latin-1", "replace")
            for kind, pattern in CRED_RULES + SERVICE_RULES:
                for match in pattern.finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    key = (kind, rel, line)
                    if key in seen:
                        continue
                    seen.add(key)
                    snippet = redact(text[match.start():match.start() + 160].split("\n")[0])
                    report["findings"].append({"kind": kind, "path": rel,
                                               "line": line, "snippet": snippet})
                    if len(report["findings"]) >= MAX_FINDINGS:
                        report["truncated"] = True
                        break
                if report["truncated"]:
                    break
            if report["truncated"]:
                break
        if report["truncated"]:
            break
    return report


def verdict_for(result):
    if result.get("blocked_at"):
        return "blocked: %s -- %s" % (result["blocked_at"],
                                      result.get("blocked_reason", "external tool missing"))
    primary = result.get("primary")
    if primary in ("pe", "elf"):
        meta = result.get(primary) or {}
        if meta.get("is_uefi"):
            return ("UEFI boot component (%s, %s%s): firmware, not a rootfs. "
                    "Next: dump firmware volumes / Secure Boot variables; "
                    "do not claim J1/J2 from the PE alone."
                    % (meta.get("machine"), meta.get("subsystem"),
                       "; clues=" + ",".join(meta.get("uefi_clues") or [])
                       if meta.get("uefi_clues") else ""))
        return ("bare %s binary (%s, %s): use the binary-reverse route; no rootfs was unpacked."
                % (primary.upper(), meta.get("machine", "unknown"),
                   meta.get("subsystem", "unknown")))
    if primary == "brcm":
        return ("vendor firmware blob (Broadcom BRCM tags): segment/entropy analysis only; "
                "no filesystem and no service evidence, so J1/J2/J3 stay open.")
    extraction = result.get("extraction") or {}
    if extraction.get("status") == "extracted":
        findings = result.get("rootfs", {}).get("findings", [])
        if findings:
            return ("rootfs extracted and %d candidate findings located. Confirm each at file:line, "
                    "redact values, then verify login/service in an isolated environment." % len(findings))
        return "rootfs extracted; no credential/service clue matched -- inspect init scripts and web root manually."
    if extraction.get("status") == "not-applicable":
        return "no filesystem/archive container to extract; static format evidence only."
    return "extraction did not produce a tree; treat as reconnaissance, not as unpack success."


def analyse(path, out_dir):
    result = {"tool": "fw-repro", "version": VERSION,
              "generated_at": (os.environ.get("SEEP_TIMESTAMP") or None),
              "file": path, "ok": True, "out_dir": out_dir}
    try:
        size = os.path.getsize(path)
        digest = sha256_file(path)
    except OSError as exc:
        result.update({"ok": False, "blocked_at": "input",
                       "blocked_reason": str(exc)})
        return result
    result.update({"size": size, "sha256": digest})
    if size == 0:
        result.update({"formats": [], "primary": None, "extraction": {"status": "empty"},
                       "verdict": "empty file; nothing to extract"})
        return result

    data, real_size, truncated = read_limited(path)
    result["analysed_bytes"] = len(data)
    result["truncated"] = truncated
    formats = detect_formats(data)
    result["formats"] = formats
    primary = choose_primary(formats)
    result["primary"] = primary["type"] if primary else None

    pe = parse_pe(data)
    if pe:
        result["pe"] = pe
    elf = parse_elf(data)
    if elf:
        result["elf"] = elf
    brcm = scan_brcm(data)
    if brcm:
        result["brcm"] = brcm

    try:
        os.makedirs(out_dir, exist_ok=True)
    except OSError as exc:
        raise Blocked("out", "%s: %s" % (type(exc).__name__, exc))
    extraction = {"status": "not-applicable", "dest": out_dir, "attempts": [],
                  "members": 0, "blocked": []}
    if primary:
        kind = primary["type"]
        source = path
        if primary["offset"] > 0:
            carved = os.path.join(out_dir, "carved-0x%x.bin" % primary["offset"])
            with open(carved, "wb") as fh:
                with open(path, "rb") as src:
                    src.seek(primary["offset"])
                    shutil.copyfileobj(src, fh)
            source = carved
            result["carved"] = {"path": carved,
                                "sha256": sha256_file(carved),
                                "size": os.path.getsize(carved)}
        dest = os.path.join(out_dir, "extracted-" + kind)
        shutil.rmtree(dest, ignore_errors=True)
        if kind in ("zip", "tar"):
            os.makedirs(dest, exist_ok=True)
            try:
                members = extract_zip(source, dest) if kind == "zip" else extract_tar(source, dest)
                extraction.update({"status": "extracted", "members": len(members)})
            except Exception as exc:  # noqa: BLE001
                extraction.update({"status": "extract-failed", "error": str(exc)[:200]})
        elif kind in ("gzip", "xz", "bzip2"):
            try:
                members, body = extract_stream(kind, source, dest)
                extraction.update({"status": "extracted", "members": len(members),
                                   "stream_bytes": len(body)})
                inner = detect_formats(body)
                if inner:
                    result["inner_formats"] = inner
            except Exception as exc:  # noqa: BLE001
                extraction.update({"status": "extract-failed", "error": str(exc)[:200]})
        elif kind in EXTERNAL:
            available = [t for t in EXTERNAL[kind] if shutil.which(t)]
            if not available:
                extraction["status"] = "blocked"
                extraction["blocked"].append({
                    "stage": "extract", "blocked_at": "tool-missing", "type": kind,
                    "candidates": EXTERNAL[kind],
                    "reason": "no extractor for %s on this host" % kind})
                result.update({"ok": False, "blocked_at": "tool-missing",
                               "blocked_reason": "no extractor for %s (tried %s)"
                               % (kind, ",".join(EXTERNAL[kind]))})
            else:
                os.makedirs(dest, exist_ok=True)
                members = run_external(kind, source, dest, extraction["attempts"])
                if members:
                    extraction.update({"status": "extracted", "members": len(members)})
                else:
                    extraction.update({"status": "extract-failed",
                                       "available": available})
        elif kind in ("squashfs", "ubi", "cramfs", "jffs2"):
            extraction.update({"status": "unsupported"})
    result["extraction"] = extraction

    if extraction["status"] == "extracted":
        result["rootfs"] = scan_tree(os.path.join(out_dir, "extracted-" + primary["type"]))
    elif extraction["status"] == "not-applicable":
        result["rootfs"] = {"dirs": 0, "files": 0, "bytes": 0, "key_files": [],
                            "findings": [], "top_dirs": [], "truncated": False}
    result["verdict"] = verdict_for(result)
    if extraction["status"] == "extract-failed":
        result["ok"] = False
        result["blocked_at"] = "extract-failed"
        result["blocked_reason"] = ("extraction failed for %s; inspect extraction.attempts"
                                    % (primary["type"] if primary else "unknown"))
    return result


def self_test():
    checks = 0
    tmp = tempfile.mkdtemp(prefix="fw-repro-selftest-")
    try:
        # 1) synthetic OTA zip with a tiny rootfs
        ota = os.path.join(tmp, "ota.zip")
        with zipfile.ZipFile(ota, "w") as zf:
            zf.writestr("rootfs/etc/passwd", "root::0:0:root:/root:/bin/sh\n")
            zf.writestr("rootfs/etc/shadow", "root:$6$salt$HASH_SECRET_VALUE:19000:0:99999:7:::\n")
            zf.writestr("rootfs/etc/init.d/rcS", "telnetd -l /bin/sh\n")
            zf.writestr("rootfs/etc/ssl/private/server.key",
                        "-----BEGIN RSA PRIVATE KEY-----\nMIIEsecret\n")
            zf.writestr("rootfs/www/cgi-bin/upgrade",
                        "#!/bin/sh\nsystem(\"tar -xzf $QUERY_STRING\")\n")
            zf.writestr("rootfs/etc/api.conf", "Authorization: bearer BEARER_SECRET_VALUE_123\n")
        result = analyse(ota, os.path.join(tmp, "out-zip"))
        assert result["ok"] is True and result["primary"] == "zip"
        checks += 1
        assert result["extraction"]["status"] == "extracted"
        checks += 1
        kinds = {f["kind"] for f in result["rootfs"]["findings"]}
        assert {"empty-password", "shadow-hash", "private-key", "telnetd", "cgi-system",
                "bearer-token"} <= kinds, kinds
        checks += 1
        rendered = json.dumps(result["rootfs"]["findings"], ensure_ascii=False)
        assert all(value not in rendered for value in
                   ("MIIEsecret", "HASH_SECRET_VALUE", "BEARER_SECRET_VALUE_123"))
        checks += 1

        # 2) gzip payload hidden behind a vendor header: carve then extract
        gz = os.path.join(tmp, "wrapped.bin")
        with open(gz, "wb") as fh:
            fh.write(b"VENDOR-HEADER" * 8)
            fh.write(gzip.compress(b"root::0:0:root:/root:/bin/sh\n"))
        gz_result = analyse(gz, os.path.join(tmp, "out-gz"))
        assert gz_result["ok"] is True and gz_result["primary"] == "gzip"
        checks += 1
        assert gz_result["extraction"]["status"] == "extracted"
        checks += 1
        assert gz_result["carved"]["size"] > 0
        checks += 1

        # 3) minimal PE32+ (UEFI application) header
        pe_path = os.path.join(tmp, "mini.efi")
        header = bytearray(0x200)
        header[0:2] = b"MZ"
        struct.pack_into("<I", header, 0x3C, 0x80)
        header[0x80:0x84] = b"PE\x00\x00"
        struct.pack_into("<H", header, 0x84, 0x8664)   # machine
        struct.pack_into("<H", header, 0x86, 1)        # sections
        struct.pack_into("<H", header, 0x94, 0xF0)     # optional header size
        struct.pack_into("<H", header, 0x98, 0x20B)    # PE32+
        struct.pack_into("<H", header, 0x98 + 68, 10)  # EFI application
        sec = 0x98 + 0xF0
        header[sec:sec + 8] = b".text\x00\x00\x00"
        struct.pack_into("<I", header, sec + 16, 0x40)
        struct.pack_into("<I", header, sec + 20, 0x1C0)
        header[0x1C0:0x200] = b"\x90" * 64
        with open(pe_path, "wb") as fh:
            fh.write(header)
        pe = parse_pe(bytes(header))
        assert pe and pe["machine"] == "x86-64" and pe["is_uefi"]
        checks += 1
        assert pe["sections"][0]["name"] == ".text"
        checks += 1
        pe_result = analyse(pe_path, os.path.join(tmp, "out-pe"))
        assert pe_result["ok"] is True and pe_result["primary"] == "pe"
        checks += 1

        # 4) fake SquashFS still yields a structured decision, never a traceback
        sq = os.path.join(tmp, "fake.squashfs")
        with open(sq, "wb") as fh:
            fh.write(b"hsqs" + b"\x00" * 256)
        sq_result = analyse(sq, os.path.join(tmp, "out-sq"))
        assert sq_result["primary"] == "squashfs"
        checks += 1
        assert sq_result["extraction"]["status"] in ("blocked", "extract-failed", "extracted")
        checks += 1

        # 5) Broadcom tag + FWID in the tail
        brcm = os.path.join(tmp, "fw.bin")
        with open(brcm, "wb") as fh:
            fh.write(b"\x00\x00\x00\x00" + b"BRCM" + b"\x00" * 128 +
                     b"PDT Ucode Ver: 764.1115 FWID: 01-deadbeef\n")
        brcm_result = analyse(brcm, os.path.join(tmp, "out-brcm"))
        assert brcm_result["primary"] == "brcm"
        checks += 1
        assert brcm_result["brcm"]["tail_meta"].get("fwid") == "01-deadbeef"
        checks += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(json.dumps({"ok": True, "tool": "fw-repro", "version": VERSION,
                      "checks": checks}, ensure_ascii=False))
    return 0


class Blocked(Exception):
    """结构化卡点：main 捕获后输出 {ok:false, blocked_at, reason} 并 rc=2。"""

    def __init__(self, stage, reason):
        super().__init__(reason)
        self.stage = stage
        self.reason = reason


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline firmware carve/extract/rootfs-evidence tool (no boot, no network).")
    parser.add_argument("--file", help="firmware image to analyse (read-only)")
    parser.add_argument("--out-dir", default="work/fw-repro",
                        help="working directory for carved/extracted output (default: work/fw-repro)")
    parser.add_argument("--json", action="store_true", help="emit one JSON object")
    parser.add_argument("--self-test", action="store_true",
                        help="run built-in offline checks and exit")
    parser.add_argument("--version", action="version", version=VERSION)
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.file:
        print(json.dumps({"ok": False, "blocked_at": "input",
                          "reason": "--file is required unless --self-test is used"},
                         ensure_ascii=False))
        return 2
    if not os.path.exists(args.file):
        print(json.dumps({"ok": False, "blocked_at": "input",
                          "reason": "no such file: %s" % args.file}, ensure_ascii=False))
        return 2
    if not os.path.isfile(args.file):
        print(json.dumps({"ok": False, "blocked_at": "input",
                          "reason": "not a regular file: %s" % args.file}, ensure_ascii=False))
        return 2

    try:
        result = analyse(args.file, args.out_dir.replace("\\", "/"))
    except Blocked as exc:
        print(json.dumps({"ok": False, "blocked_at": exc.stage, "reason": exc.reason},
                         ensure_ascii=False))
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI must never leak a traceback
        print(json.dumps({"ok": False, "blocked_at": "internal",
                          "reason": "analysis failed: %s" % type(exc).__name__},
                         ensure_ascii=False))
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("fw-repro %s  %s (%d bytes)" % (VERSION, result["file"], result.get("size", 0)))
        print("sha256 %s" % result.get("sha256", ""))
        print("primary: %s" % result.get("primary"))
        for fmt in result.get("formats") or []:
            print("  +0x%08x %-10s %s" % (fmt["offset"], fmt["type"], fmt["note"]))
        ext = result.get("extraction") or {}
        print("extraction: %s (%d members)" % (ext.get("status"), ext.get("members", 0)))
        for item in ext.get("blocked") or []:
            print("  blocked_at=%s %s" % (item["blocked_at"], item["reason"]))
        rootfs = result.get("rootfs") or {}
        print("rootfs: %d files / %d bytes" % (rootfs.get("files", 0), rootfs.get("bytes", 0)))
        for finding in (rootfs.get("findings") or [])[:40]:
            print("  %-16s %s:%d  %s" % (finding["kind"], finding["path"],
                                         finding["line"], finding["snippet"]))
        print("verdict: %s" % result.get("verdict", ""))
    blocked = result.get("blocked_at")
    if blocked == "extract-failed":
        return 1
    if blocked:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
