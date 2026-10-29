#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent (2nd implementation) PE header probe for pwn-crypto07.

Purpose: document *exactly* which raw facts back each protection string, and fix the
pointer-width mistake the first probe made, so the case does not inherit it.

Compared with the earlier, non-shipped probe, this implementation:
  * SecurityCookie is read with the correct width per flavour
    (PE32: offset 0x3C / 4 bytes, minimum 0x40; PE64: offset 0x58 / 8 bytes, minimum 0x60)
  * both the directory Size and the structure's own Size field are checked
  * the field must land inside the file *and* inside the section's raw data
  * the resulting RVA is sanity-checked against SizeOfImage, because a "cookie" that
    points outside the image cannot be a real /GS cookie pointer
  * DllCharacteristics bits, section flags and a name scan are re-derived by hand

Reads bytes only. Never starts, loads or debugs the target.

Usage:
    python Tool/cases/pwn-crypto07/tools/header-probe.py [--json]
Exit: 0 always (it reports observations, it does not judge the case).
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CASE = os.path.dirname(HERE)
TARGET = os.path.join(CASE, "target", "dostackbufferoverflowgood.exe")

DLLCHAR = {"HIGH_ENTROPY_VA": 0x0020, "DYNAMIC_BASE(ASLR)": 0x0040,
           "FORCE_INTEGRITY": 0x0080, "NX_COMPAT(DEP)": 0x0100,
           "NO_SEH": 0x0400, "NO_BIND": 0x0800, "APPCONTAINER": 0x1000,
           "WDM_DRIVER": 0x2000, "GUARD_CF": 0x4000, "TERMINAL_SERVER_AWARE": 0x8000}


def probe(path):
    with open(path, "rb") as fh:
        d = fh.read()
    out = {"target": os.path.relpath(path, CASE).replace("\\", "/"),
           "size": len(d), "sha256": hashlib.sha256(d).hexdigest()}

    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    out["e_lfanew"] = "0x%x" % e_lfanew
    out["pe_signature"] = d[e_lfanew:e_lfanew + 4].hex()
    coff = e_lfanew + 4
    machine, nsects = struct.unpack_from("<HH", d, coff)
    opt_size = struct.unpack_from("<H", d, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", d, opt)[0]
    is64 = magic == 0x20B
    bits = 64 if is64 else 32
    dllchars = struct.unpack_from("<H", d, opt + 70)[0]
    out.update({"machine": "0x%x" % machine, "magic": "0x%x" % magic, "bits": bits,
                "num_sections": nsects, "opt_header_size": opt_size,
                "dll_characteristics": "0x%04x" % dllchars,
                "entry_rva": "0x%x" % struct.unpack_from("<I", d, opt + 16)[0],
                "image_base": "0x%x" % struct.unpack_from(
                    "<Q" if is64 else "<I", d, opt + (24 if is64 else 28))[0],
                "size_of_image": "0x%x" % struct.unpack_from("<I", d, opt + 56)[0],
                "size_of_headers": "0x%x" % struct.unpack_from("<I", d, opt + 60)[0]})
    out["dll_characteristics_bits"] = {k: bool(dllchars & v) for k, v in DLLCHAR.items()}

    dirs = opt + (112 if is64 else 96)
    n_dirs = struct.unpack_from("<I", d, opt + (108 if is64 else 92))[0]
    out["num_data_dirs"] = n_dirs
    sec_off = opt + opt_size
    secs, bad = [], []
    for i in range(nsects):
        p = sec_off + i * 40
        if p + 40 > len(d):
            bad.append("section table truncated at index %d" % i)
            break
        name = d[p:p + 8].rstrip(b"\x00").decode("latin-1")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", d, p + 8)
        chars = struct.unpack_from("<I", d, p + 36)[0]
        secs.append({"name": name, "va": "0x%x" % va, "vsize": vsize,
                     "rawptr": rawptr, "rawsize": rawsize,
                     "chars": "0x%08x" % chars,
                     "readable": bool(chars & 0x40000000),
                     "writable": bool(chars & 0x80000000),
                     "executable": bool(chars & 0x20000000),
                     "raw_within_file": rawptr + rawsize <= len(d)})
    out["sections"] = secs
    out["sections_raw_within_file"] = all(s["raw_within_file"] for s in secs)
    out["section_table_problems"] = bad

    def map_rva(rva):
        for s in secs:
            va = int(s["va"], 16)
            if va <= rva < va + max(s["vsize"], s["rawsize"]):
                delta = rva - va
                if delta >= s["rawsize"]:
                    return None, s
                return s["rawptr"] + delta, s
        return None, None

    # ── load-config / SecurityCookie ──
    cookie_off = 0x58 if is64 else 0x3C
    cookie_width = 8 if is64 else 4
    lc_min = cookie_off + cookie_width
    lc_rva = lc_size = 0
    if n_dirs > 10 and dirs + 10 * 8 + 8 <= len(d):
        lc_rva, lc_size = struct.unpack_from("<II", d, dirs + 10 * 8)
    lo, sec = map_rva(lc_rva) if lc_rva else (None, None)
    lc = {"rva": "0x%x" % lc_rva, "dir_size": lc_size,
          "cookie_offset": "0x%x" % cookie_off, "cookie_width": cookie_width,
          "minimum_structure_size": "0x%x" % lc_min,
          "dir_size_sufficient": lc_size >= lc_min,
          "file_offset": None if lo is None else "0x%x" % lo}
    cookie = None
    if lo is not None:
        declared = struct.unpack_from("<I", d, lo)[0] if lo + 4 <= len(d) else None
        field_end = lo + cookie_off + cookie_width
        in_file = field_end <= len(d)
        in_section = sec is not None and field_end <= sec["rawptr"] + sec["rawsize"]
        lc.update({"declared_size": declared,
                   "declared_size_sufficient": declared is not None and declared >= lc_min,
                   "field_within_file": in_file, "field_within_section": in_section})
        if in_file and in_section and declared is not None and declared >= lc_min:
            cookie = struct.unpack_from("<Q" if is64 else "<I", d, lo + cookie_off)[0]
            lc["raw_cookie_value"] = "0x%x" % cookie
            # 语义合理性：SecurityCookie 字段存的是**绝对 VA**（指针值），
            # PE32/PE64 都一样——不要再加 ImageBase。越出 image 就不可能是真 cookie。
            image_base = int(out["image_base"], 16)
            size_image = int(out["size_of_image"], 16)
            lc["cookie_as_va"] = "0x%x" % cookie
            lc["cookie_within_image"] = image_base <= cookie < image_base + size_image
    out["load_config"] = lc
    out["security_cookie_declared"] = bool(cookie)
    out["security_cookie_semantically_plausible"] = bool(
        cookie and lc.get("cookie_within_image"))

    low = d.lower()
    out["name_scan"] = {t: (t.encode() in low) for t in
                        ("__security_check_cookie", "__security_init_cookie",
                         "__report_gsfailure", "__gsfailure", "@stack_chk")}
    out["notes"] = [
        "SecurityCookie 非零只说明 load config 里声明了 cookie（链接器放了 /GS 支撑结构），",
        "不等于每个函数都插了 GS prologue；本探针不做任何动态验证。",
        "DllCharacteristics 是可选头声明，运行时实际页权限由加载器/系统策略决定，未验证。",
    ]
    return out


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    if "--help" in args or "-h" in args:
        print(__doc__)
        return 0
    if not os.path.isfile(TARGET):
        print(json.dumps({"ok": False, "blocked_at": "target",
                          "reason": "目标不存在：%s" % TARGET}, ensure_ascii=False))
        return 2
    res = probe(TARGET)
    if "--json" in args:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print("[probe] %s size=%d sha256=%s" % (res["target"], res["size"],
                                                res["sha256"][:16]))
        print("[probe] bits=%s dllchars=%s sections=%d cookie_declared=%s plausible=%s"
              % (res["bits"], res["dll_characteristics"], len(res["sections"]),
                 res["security_cookie_declared"],
                 res["security_cookie_semantically_plausible"]))
        print("[probe] load_config=%s" % json.dumps(res["load_config"], ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
