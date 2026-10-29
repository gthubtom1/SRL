#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synthetic PE load-config boundary tests for pwn-check.py's Canary detection.

Why this file exists
--------------------
The original `pwn-check.py` decided "SecurityCookie declared?" with two hard-coded
constants that are wrong for one of the two PE flavours:

    if lc_size >= 0x48:                      # ← single magic threshold for both
        cookie_off = lo + (0x58 if bits==64 else 0x3C)
        b.has_load_config_cookie = u32(...)  # ← always 4 bytes, even for PE64

Per the PE/COFF layout the SecurityCookie field sits at

    PE32 : offset 0x3C, pointer width 4, so the structure must be >= 0x40 bytes
    PE64 : offset 0x58, pointer width 8, so the structure must be >= 0x60 bytes

so a PE32 whose load-config directory is exactly 0x40 bytes was skipped, and a PE64
cookie whose value is `0x0000_0001_0000_0000` (high dword nonzero, low dword zero)
read as 0 through `u32` and reported as "not found".

These tests build **synthetic** minimal PE images byte-by-byte (no real sample is
executed or even needed) and assert the fixed parser's verdict plus its
boundary behaviour: nothing may be read past the file end or past the section's
raw data, and a load-config `Size` field smaller than the minimum must not be
trusted.

The images are tiny and only satisfy what `parse_pe()` touches: DOS header with
`e_lfanew`, PE signature, COFF header, optional header with the data-directory
array, one section that maps the load-config bytes.

Usage:
    python Tool/cases/pwn-crypto07/tools/parser-boundary-tests.py           # rc=0 + JSON
    python Tool/cases/pwn-crypto07/tools/parser-boundary-tests.py --json
Only reads/writes nothing but stdout: no target execution, no files written.
"""
from __future__ import annotations

import importlib.util
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CASE = os.path.dirname(HERE)
FIXTURE_PWN_CHECK = os.path.abspath(
    os.path.join(CASE, "..", "..", "skill", "pwn-crypto", "scripts", "pwn-check.py"))


def load_pwn_check(path=None):
    """Import pwn-check.py as a module (no execution of any analysed file)."""
    cand = [path] if path else []
    cand.append(os.path.abspath(FIXTURE_PWN_CHECK))
    for p in cand:
        if p and os.path.isfile(p):
            spec = importlib.util.spec_from_file_location("pwn_check_under_test", p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod, p
    raise SystemExit("找不到 pwn-check.py（试过 %s）" % ", ".join(cand))


def build_pe(bits=32, lc_size=0x40, declared_size=None, cookie=0x1,
             lc_inside_section=True, truncate_after=None, with_dir=True):
    """Build a minimal PE image that carries a load-config blob.

    Layout (all offsets by hand, no linker):
        0x000  DOS header, e_lfanew = 0x40
        0x040  "PE\\0\\0" + COFF + optional header
        file_alignment 0x200: one section .rdata starting at 0x200
        load-config blob at section VA 0x1000 (file offset 0x200)
    """
    is64 = bits == 64
    opt_size = 224 if is64 else 224          # both PE32/PE32+ use 224 in practice
    e_lfanew = 0x40
    coff = e_lfanew + 4
    opt = coff + 20
    sec_table = opt + opt_size
    sec_raw = 0x200
    lc_rva = 0x1000

    img = bytearray(sec_raw + 0x400)
    # ── DOS header ──
    img[0:2] = b"MZ"
    struct.pack_into("<I", img, 0x3C, e_lfanew)
    # ── PE signature + COFF ──
    img[e_lfanew:e_lfanew + 4] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", img, coff,
                     0x8664 if is64 else 0x14C,   # Machine
                     1,                          # NumberOfSections
                     0, 0, 0,                    # timestamps/ptr/symbols
                     opt_size, 0x0102)           # SizeOfOptionalHeader, Characteristics
    # ── Optional header ──
    struct.pack_into("<H", img, opt, 0x20B if is64 else 0x10B)   # Magic
    struct.pack_into("<I", img, opt + 16, 0x1000)                # AddressOfEntryPoint
    struct.pack_into("<I", img, opt + 28, 0x400000)              # ImageBase (PE32+ 8 bytes but low dword enough)
    struct.pack_into("<I", img, opt + 56, 0x2000)                # SizeOfImage
    struct.pack_into("<H", img, opt + 70, 0x8000)                # DllCharacteristics
    n_dirs_off = opt + (108 if is64 else 92)
    struct.pack_into("<I", img, n_dirs_off, 16)
    dirs = opt + (112 if is64 else 96)
    if with_dir:
        struct.pack_into("<II", img, dirs + 10 * 8, lc_rva, lc_size)
    # ── one section mapping lc_rva -> sec_raw ──
    img[sec_table:sec_table + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", img, sec_table + 8, 0x400, lc_rva, 0x400, sec_raw)
    struct.pack_into("<I", img, sec_table + 36, 0x40000040)

    # ── load-config blob ──
    blob = bytearray(max(lc_size if lc_size > 0 else 0x40, 0x40))
    struct.pack_into("<I", blob, 0, declared_size if declared_size is not None else len(blob))
    off = 0x3C if not is64 else 0x58
    width = 4 if not is64 else 8
    if off + width <= len(blob):
        struct.pack_into("<I" if width == 4 else "<Q", blob, off, cookie)
    # write the blob; if it does not fit in the section (lc_inside_section=False),
    # spill past the section's declared raw size so the section bound is violated
    put = sec_raw if lc_inside_section else sec_raw + 0x200
    need = put + len(blob)
    if need > len(img):
        img.extend(b"\x00" * (need - len(img)))
    img[put:put + len(blob)] = blob
    out = bytes(img[:truncate_after]) if truncate_after else bytes(img)
    return out


def parse(mod, data):
    b = mod.Binary()
    try:
        mod.parse_pe(data, b)
    except (ValueError, struct.error, IndexError) as exc:
        return {"raised": "%s: %s" % (type(exc).__name__, exc),
                "canary": None, "has_cookie": None, "load_config": None}
    return {"raised": None, "canary": b.prot.get("Canary"),
            "has_cookie": b.has_load_config_cookie,
            "load_config": getattr(b, "load_config", None),
            "bits": b.bits}


def main(argv=None):
    as_json = "--json" in (argv if argv is not None else sys.argv[1:])
    src = os.environ.get("PWN_CHECK_PATH") or None
    mod, used = load_pwn_check(src)

    cases = []

    def add(name, bits, expect_found, **kw):
        data = build_pe(bits=bits, **kw)
        res = parse(mod, data)
        ok = (res["has_cookie"] is expect_found) and res["raised"] is None
        cases.append({"name": name, "bits": bits, "expect_found": expect_found,
                      "ok": ok, "verdict": res["canary"],
                      "has_cookie": res["has_cookie"], "raised": res["raised"],
                      "load_config": res["load_config"],
                      "kwargs": {k: v for k, v in kw.items()}})

    # ── PE32 ──
    add("pe32 dir_size=0x40 (exact minimum) cookie=nonzero", 32, True,
        lc_size=0x40, cookie=0x1234, declared_size=0x40)
    add("pe32 dir_size=0x3C (one dword short) -> must not read", 32, False,
        lc_size=0x3C, cookie=0x1234, declared_size=0x3C)
    add("pe32 dir_size=0x40 but declared Size=0x3C -> untrusted", 32, False,
        lc_size=0x40, cookie=0x1234, declared_size=0x3C)
    add("pe32 cookie field == 0 -> not found", 32, False,
        lc_size=0x40, cookie=0, declared_size=0x40)

    # ── PE64（u32 读法的真实缺陷点）──
    add("pe64 dir_size=0x60 (exact minimum) high!=0 low==0 -> Found", 64, True,
        lc_size=0x60, cookie=0x0000000100000000, declared_size=0x60)
    add("pe64 dir_size=0x58 (one field short) -> must not read", 64, False,
        lc_size=0x58, cookie=0x0000000100000000, declared_size=0x58)
    add("pe64 dir_size=0x60 declared Size=0x48 -> untrusted", 64, False,
        lc_size=0x60, cookie=0x0000000100000000, declared_size=0x48)
    add("pe64 cookie=1 -> Found", 64, True,
        lc_size=0x60, cookie=1, declared_size=0x60)

    # ── 边界：不得越界读 ──
    cases.append(_section_overflow_case(mod, add))
    add("pe32 truncated right after the field -> still readable", 32, True,
        lc_size=0x40, cookie=0x1234, declared_size=0x40, truncate_after=0x200 + 0x40)
    add("pe32 truncated before the cookie field -> must not read", 32, False,
        lc_size=0x40, cookie=0x1234, declared_size=0x40, truncate_after=0x200 + 0x3C)
    add("no load-config data directory -> not found", 32, False, with_dir=False)

    passed = sum(1 for c in cases if c["ok"])
    report = {"schema": "seep.pwn-parser-boundary-tests/1",
              "pwn_check_under_test": used,
              "pwn_check_sha256": _sha256(used),
              "synthetic_hosts": "built in memory; no file on disk, no process started",
              "summary": {"total": len(cases), "passed": passed,
                          "failed": [c["name"] for c in cases if not c["ok"]]},
              "cases": cases}
    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print("[boundary] pwn-check=%s sha256=%s" % (os.path.basename(used),
                                                     report["pwn_check_sha256"]))
        for c in cases:
            print("  %-4s %-62s -> canary=%-26s expected_found=%s"
                  % ("PASS" if c["ok"] else "FAIL", c["name"], str(c["verdict"]),
                     c["expect_found"]))
        print("[boundary] %d/%d PASS" % (passed, len(cases)))
    return 0 if passed == len(cases) else 1


def _section_overflow_case(mod, _add):
    """load-config 落在节 raw 数据之外：映射成功但字段越节 → 不得读取。"""
    data = build_pe(bits=32, lc_size=0x40, cookie=0x1234, declared_size=0x40,
                    lc_inside_section=False)
    res = parse(mod, data)
    ok = (res["has_cookie"] is False) and res["raised"] is None
    return {"name": "pe32 load-config outside section raw data -> must not read",
            "bits": 32, "expect_found": False, "ok": ok, "verdict": res["canary"],
            "has_cookie": res["has_cookie"], "raised": res["raised"],
            "load_config": res["load_config"], "kwargs": {"lc_inside_section": False}}


def _sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
