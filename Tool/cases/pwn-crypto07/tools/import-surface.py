#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Import-surface census for pwn-crypto07 (why `dangerous_imports` is a lower bound).

`pwn-check.py` matches dangerous imports by **symbol name** against a fixed
whitelist. For this target that yields exactly one entry, which is easy to
misread as "the binary barely imports anything risky". This tool records the raw
census the case needs in order to state the opposite honestly:

  * per-DLL symbol counts (from the real import directory)
  * which WS2_32 entries are imported **by ordinal** (`#ord_N`) and therefore can
    never be matched to `recv`/`send`/`closesocket` by a name whitelist
  * which C-runtime names go through `api-ms-win-crt-*` API sets and
    `__stdio_common_*` instead of the classic names the whitelist expects
  * the security-relevant names that are parsed but not listed (severity "低")

Reads bytes only; no target execution, no network.

Usage:
    python Tool/cases/pwn-crypto07/tools/import-surface.py [--json]
Exit: 0 always (it reports a census; it does not judge the case).
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

# names that a human would call security-relevant but that the whitelist does not list
WATCH = ("IsDebuggerPresent", "SetUnhandledExceptionFilter", "UnhandledExceptionFilter",
         "TerminateProcess", "GetModuleHandleW", "_beginthread", "VirtualProtect",
         "LoadLibraryA", "GetProcAddress", "HeapCreate", "HeapAlloc", "HeapFree")


def parse_imports(d):
    """Return (rows, problems). rows = [{library, symbol, ordinal, by_ordinal}]."""
    if len(d) < 0x40 or d[:2] != b"MZ":
        return [], ["not a PE (no MZ)"]
    e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
    if d[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return [], ["no PE signature at e_lfanew"]
    coff = e_lfanew + 4
    nsects = struct.unpack_from("<H", d, coff + 2)[0]
    opt_size = struct.unpack_from("<H", d, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", d, opt)[0]
    is64 = magic == 0x20B
    dirs = opt + (112 if is64 else 96)
    n_dirs = struct.unpack_from("<I", d, opt + (108 if is64 else 92))[0]
    sec_off = opt + opt_size
    secs = []
    for i in range(min(nsects, 96)):
        p = sec_off + i * 40
        if p + 40 > len(d):
            break
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", d, p + 8)
        secs.append((va, vsize, rawptr, rawsize))

    def map_rva(rva):
        for va, vsize, rawptr, rawsize in secs:
            if va <= rva < va + max(vsize, rawsize):
                delta = rva - va
                return rawptr + delta if delta < rawsize else None
        return None

    rows, problems = [], []
    if n_dirs <= 1:
        return rows, ["no import directory"]
    rva, size = struct.unpack_from("<II", d, dirs + 8)
    off = map_rva(rva)
    if off is None:
        return rows, ["import directory RVA not mapable"]
    step = 8 if is64 else 4
    for idx in range(256):
        dp = off + idx * 20
        if dp + 20 > len(d):
            problems.append("import descriptor table truncated")
            break
        oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", d, dp)
        if not (oft or name_rva or ft):
            break
        noff = map_rva(name_rva)
        dll = ""
        if noff is not None:
            nul = d.find(b"\x00", noff, min(len(d), noff + 256))
            dll = d[noff:nul if nul >= 0 else noff + 256].decode("latin-1", "replace")
        toff = map_rva(oft or ft)
        if toff is None:
            problems.append("%s: thunk RVA not mapable" % dll)
            continue
        for j in range(4096):
            p = toff + j * step
            if p + step > len(d):
                problems.append("%s: thunk array truncated" % dll)
                break
            val = struct.unpack_from("<Q" if is64 else "<I", d, p)[0]
            if val == 0:
                break
            high = 1 << (63 if is64 else 31)
            if val & high:
                rows.append({"library": dll, "symbol": "#ord_%d" % (val & 0xffff),
                             "ordinal": val & 0xffff, "by_ordinal": True})
                continue
            hoff = map_rva(val & 0x7FFFFFFF)
            if hoff is None or hoff + 2 > len(d):
                problems.append("%s: hint/name RVA not mapable" % dll)
                continue
            nul = d.find(b"\x00", hoff + 2, min(len(d), hoff + 512))
            name = d[hoff + 2:nul if nul >= 0 else hoff + 512].decode("latin-1", "replace")
            rows.append({"library": dll, "symbol": name, "ordinal": None,
                         "by_ordinal": False})
    return rows, problems


def census(path):
    with open(path, "rb") as fh:
        d = fh.read()
    rows, problems = parse_imports(d)
    per_dll = {}
    for r in rows:
        per_dll.setdefault(r["library"], []).append(r)
    summary = {}
    for dll, items in per_dll.items():
        by_ord = [i["symbol"] for i in items if i["by_ordinal"]]
        summary[dll] = {"total": len(items), "by_ordinal": len(by_ord),
                        "ordinals": by_ord,
                        "named": sorted(i["symbol"] for i in items if not i["by_ordinal"])}
    watch_hits = sorted({r["symbol"] for r in rows if r["symbol"] in WATCH})
    api_set = sorted(dll for dll in per_dll if dll.lower().startswith("api-ms-win-"))
    ss_common = sorted({r["symbol"] for r in rows
                        if r["symbol"].startswith("__stdio_common_")})
    classic = sorted({r["symbol"] for r in rows
                      if r["symbol"] in ("printf", "sprintf", "malloc", "free",
                                          "memcpy", "strcpy", "gets", "scanf")})
    return {
        "target": os.path.relpath(path, CASE).replace("\\", "/"),
        "size": len(d),
        "sha256": hashlib.sha256(d).hexdigest(),
        "import_total": len(rows),
        "dll_count": len(per_dll),
        "per_dll": {k: {"total": v["total"], "by_ordinal": v["by_ordinal"],
                        "ordinals": v["ordinals"], "named": v["named"]}
                    for k, v in sorted(summary.items())},
        "ordinal_only_dlls": sorted(k for k, v in summary.items() if v["by_ordinal"]),
        "ordinal_mapped_names_possible": False,
        "ordinal_mapping_note": "按序号导入的符号在 PE 里没有名字；不查外部 .def/序号表就无法还原"
                               "成 recv/send/closesocket，因此名字白名单必然漏掉它们。",
        "api_set_dlls": api_set,
        "stdio_common_symbols": ss_common,
        "classic_whitelist_names_present": classic,
        "security_relevant_not_whitelisted": watch_hits,
        "parser_problems": problems,
        "limits": [
            "这是导入面普查，不是漏洞证据：导入了什么不等于哪条路径可达。",
            "序号导入无法还原名字（未使用外部序号表），所以 recv/send/closesocket 的存在"
            "只能按 DLL 推断，不能按名字断言。",
            "零动态验证。",
        ],
    }


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    if "--help" in args or "-h" in args:
        print(__doc__)
        return 0
    if not os.path.isfile(TARGET):
        print(json.dumps({"ok": False, "blocked_at": "target",
                          "reason": "目标不存在：%s" % TARGET}, ensure_ascii=False))
        return 2
    res = census(TARGET)
    if "--json" in args:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print("[imports] %s size=%d sha256=%s total=%d dlls=%d"
              % (res["target"], res["size"], res["sha256"][:16],
                 res["import_total"], res["dll_count"]))
        for dll, v in res["per_dll"].items():
            print("  %-38s total=%-3d ordinal=%-2d" % (dll, v["total"], v["by_ordinal"]))
        print("[imports] api-set DLLs=%d stdio_common=%d classic_names=%s"
              % (len(res["api_set_dlls"]), len(res["stdio_common_symbols"]),
                 res["classic_whitelist_names_present"] or "none"))
        print("[imports] security-relevant but not whitelisted: %s"
              % (res["security_relevant_not_whitelisted"] or "none"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
