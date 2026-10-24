#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pwn-check.py — 纯标准库 PE/ELF 保护位与利用路线预判.

用法:
    python Tool/skill/pwn-crypto/scripts/pwn-check.py --file ./chall
    python Tool/skill/pwn-crypto/scripts/pwn-check.py --file ./sample.exe --json

只读文件，不执行目标。输出 checksec 近似值、危险导入、format 串风险和
下一步优先尝试的利用路线。PE 没有 ELF RELRO 概念，RELRO 以 N/A 标注；
NX/PIE/Canary 用 DllCharacteristics、导入表与 load-config 线索近似。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import struct
import sys

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

DANGEROUS = {
    # 栈/内存拷贝
    "strcpy": ("栈溢出", "高"), "strcat": ("栈溢出", "高"),
    "sprintf": ("栈溢出/格式化", "高"), "vsprintf": ("栈溢出/格式化", "高"),
    "gets": ("栈溢出", "高"), "scanf": ("栈溢出/格式化", "中"),
    "sscanf": ("栈溢出/格式化", "中"), "memcpy": ("越界写", "中"),
    "memmove": ("越界写", "中"), "strncpy": ("边界写", "中"),
    "read": ("越界写", "中"), "recv": ("越界写", "中"),
    "recvfrom": ("越界写", "中"), "fgets": ("边界写", "低"),
    # 命令/执行
    "system": ("命令执行", "高"), "popen": ("命令执行", "高"),
    "execve": ("命令执行", "高"), "execl": ("命令执行", "高"),
    "execvp": ("命令执行", "高"), "winexec": ("命令执行", "高"),
    "shellexecutea": ("命令执行", "高"), "shellexecutew": ("命令执行", "高"),
    # 格式化/输出
    "printf": ("格式化字符串", "中"), "fprintf": ("格式化字符串", "中"),
    "vprintf": ("格式化字符串", "中"), "vfprintf": ("格式化字符串", "中"),
    "snprintf": ("格式化字符串", "低"), "syslog": ("格式化字符串", "低"),
    # 堆
    "malloc": ("堆", "中"), "calloc": ("堆", "中"),
    "realloc": ("堆", "中"), "free": ("堆", "中"),
    # 内存权限 / 注入
    "mmap": ("内存权限", "低"), "mprotect": ("内存权限", "中"),
    "virtualalloc": ("内存权限", "中"), "virtualprotect": ("内存权限", "中"),
    "writeprocessmemory": ("进程注入", "高"),
    "createremotethread": ("进程注入", "高"),
    # 反调试/沙箱
    "ptrace": ("反调试", "低"), "isdebuggerpresent": ("反调试", "低"),
    "checkremotedebuggerpresent": ("反调试", "低"),
    # 提权
    "setuid": ("提权", "低"), "setgid": ("提权", "低"),
}

FMT_TOKEN = re.compile(
    r"%(?:\d+\$)?[-+#0 ]*\d*(?:\.\d+)?(?:hh|h|ll|l|L|z|j|t)*[diouxXeEfFgGaAcspn%]"
)
FMT_FUNCS = {"printf", "fprintf", "vprintf", "vfprintf", "sprintf", "vsprintf",
             "snprintf", "syslog", "scanf", "fscanf", "sscanf"}
CRYPTO_HINTS = ("rsa", "aes", "ecb", "cbc", "prng", "lattice", "coppersmith",
                "modinv", "pow(", "n = ", "c = ", "e = 3", "mt19937")
ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def u16(data, off, endian="<"):
    return struct.unpack_from(endian + "H", data, off)[0]


def u32(data, off, endian="<"):
    return struct.unpack_from(endian + "I", data, off)[0]


def u64(data, off, endian="<"):
    return struct.unpack_from(endian + "Q", data, off)[0]


def entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = float(len(data))
    return -sum((c / n) * math.log(c / n, 2) for c in counts if c)


def strings_from(data, limit=20000):
    out, seen = [], set()
    for m in ASCII_RE.finditer(data):
        s = m.group().decode("latin-1", "replace")
        if s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= limit:
                break
    for m in UTF16_RE.finditer(data):
        s = m.group().decode("utf-16le", "replace")
        if len(s) >= 4 and s not in seen:
            seen.add(s)
            out.append(s)
            if len(out) >= limit:
                break
    return out


class Section:
    def __init__(self, name, va, vsize, rawptr, rawsize, chars=0):
        self.name, self.va, self.vsize = name, va, vsize
        self.rawptr, self.rawsize, self.chars = rawptr, rawsize, chars


class Binary:
    def __init__(self):
        self.kind = "unknown"
        self.arch = "unknown"
        self.bits = 0
        self.endian = "little"
        self.sections = []
        self.imports = []          # [(dll_or_lib, symbol)]
        self.symbols = set()
        self.prot = {}
        self.notes = []
        self.entry = 0
        self.dllchars = 0
        self.has_load_config_cookie = False
        self.fmt_funcs = set()
        self.heap_funcs = set()
        self.danger = []
        self.fmt_risks = []

    def map_rva(self, rva):
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.rawsize):
                delta = rva - s.va
                if delta < s.rawsize:
                    return s.rawptr + delta
                return None
        return rva if rva < 0x1000 else None


def parse_imports(data, rva, size, b):
    off = b.map_rva(rva)
    if off is None:
        b.notes.append("导入表 RVA 无法映射到文件偏移")
        return
    end = min(len(data), off + (size if size else 0x1000))
    idx = 0
    for _ in range(256):
        d = off + idx * 20
        if d + 20 > end:
            break
        oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", data, d)
        if not (oft or name_rva or ft):
            break
        noff = b.map_rva(name_rva)
        dll = ""
        if noff is not None and noff < len(data):
            nul = data.find(b"\x00", noff, min(len(data), noff + 256))
            dll = data[noff:nul if nul >= 0 else noff + 256].decode("latin-1", "replace")
        thunk_rva = oft or ft
        toff = b.map_rva(thunk_rva)
        if toff is None:
            idx += 1
            continue
        step = 8 if b.bits == 64 else 4
        for j in range(4096):
            p = toff + j * step
            if p + step > len(data):
                break
            val = u64(data, p) if b.bits == 64 else u32(data, p)
            if val == 0:
                break
            high = 1 << (63 if b.bits == 64 else 31)
            if val & high:
                b.imports.append((dll, "#ord_%d" % (val & 0xffff)))
                continue
            hoff = b.map_rva(val & 0x7fffffff)
            if hoff is None or hoff + 2 > len(data):
                continue
            nul = data.find(b"\x00", hoff + 2, min(len(data), hoff + 512))
            name = data[hoff + 2:nul if nul >= 0 else hoff + 512].decode("latin-1", "replace")
            if name:
                b.imports.append((dll, name))
        idx += 1


def parse_pe(data, b):
    b.kind = "PE"
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("不是 MZ/PE 文件")
    e_lfanew = u32(data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("e_lfanew 处没有 PE 签名")
    coff = e_lfanew + 4
    machine = u16(data, coff)
    nsects = u16(data, coff + 2)
    opt_size = u16(data, coff + 16)
    opt = coff + 20
    magic = u16(data, opt)
    b.bits = 64 if magic == 0x20B else 32
    b.arch = {0x14C: "x86", 0x8664: "x86_64", 0xAA64: "arm64",
              0x1C0: "arm", 0x1C4: "arm"}.get(machine, "machine_0x%x" % machine)
    b.entry = u32(data, opt + 16)
    b.dllchars = u16(data, opt + 70)
    dirs = opt + (112 if b.bits == 64 else 96)
    n_dirs = u32(data, opt + (108 if b.bits == 64 else 92))
    sec_off = opt + opt_size
    for i in range(min(nsects, 96)):
        p = sec_off + i * 40
        if p + 40 > len(data):
            break
        raw = data[p:p + 8].rstrip(b"\x00").decode("latin-1", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, p + 8)
        chars = u32(data, p + 36)
        b.sections.append(Section(raw, va, vsize, rawptr, rawsize, chars))
    # 导入目录（index 1）与 load config（index 10）
    if n_dirs > 1 and dirs + 16 <= len(data):
        rva, size = struct.unpack_from("<II", data, dirs + 8)
        if rva:
            parse_imports(data, rva, size, b)
    if n_dirs > 10 and dirs + 10 * 8 + 8 <= len(data):
        lc_rva, lc_size = struct.unpack_from("<II", data, dirs + 10 * 8)
        if lc_rva and lc_size >= 0x48:
            lo = b.map_rva(lc_rva)
            if lo is not None and lo + 0x48 <= len(data):
                cookie_off = lo + (0x58 if b.bits == 64 else 0x3C)
                if cookie_off + 4 <= len(data):
                    b.has_load_config_cookie = u32(data, cookie_off) != 0
                if b.has_load_config_cookie:
                    b.notes.append("load config 声明了 SecurityCookie")
    # 保护位：DllCharacteristics 近似
    nx = bool(b.dllchars & 0x0100)
    aslr = bool(b.dllchars & 0x0040)
    cfg = bool(b.dllchars & 0x4000)
    b.prot = {
        "NX": "Enabled" if nx else "Disabled",
        "PIE": "Enabled (DYNAMIC_BASE/ASLR)" if aslr else "Disabled",
        "Canary": "Found (SecurityCookie)" if b.has_load_config_cookie else "Not found",
        "RELRO": "N/A (PE 无 ELF RELRO)",
    }
    flags = []
    if cfg:
        flags.append("CFG")
    if b.dllchars & 0x0020:
        flags.append("HIGH_ENTROPY_VA")
    if b.dllchars & 0x0080:
        flags.append("FORCE_INTEGRITY")
    if flags:
        b.notes.append("DllCharacteristics 其它标志: " + ", ".join(flags))
    b.notes.append("PE 保护位为 DllCharacteristics 近似；IAT 可写性需看节权限与加载配置")


def elf_map_vaddr(b, vaddr):
    for s in b.sections:
        if s.va <= vaddr < s.va + max(s.vsize, 1):
            if s.rawptr and vaddr - s.va < s.rawsize:
                return s.rawptr + (vaddr - s.va)
    return None


def parse_elf(data, b):
    b.kind = "ELF"
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise ValueError("不是 ELF 文件")
    cls, enc = data[4], data[5]
    b.bits = 64 if cls == 2 else 32
    b.endian = "little" if enc == 1 else "big"
    e = "<" if b.endian == "little" else ">"
    b.arch = {0x03: "x86", 0x3E: "x86_64", 0x28: "arm", 0xB7: "aarch64",
              0x08: "mips"}.get(u16(data, 18, e), "machine_0x%x" % u16(data, 18, e))
    e_type = u16(data, 16, e)
    b.entry = u64(data, 24, e) if b.bits == 64 else u32(data, 24, e)
    if b.bits == 64:
        phoff, shoff = u64(data, 32, e), u64(data, 40, e)
        phentsize, phnum = u16(data, 54, e), u16(data, 56, e)
        shentsize, shnum, shstrndx = u16(data, 58, e), u16(data, 60, e), u16(data, 62, e)
    else:
        phoff, shoff = u32(data, 28, e), u32(data, 32, e)
        phentsize, phnum = u16(data, 42, e), u16(data, 44, e)
        shentsize, shnum, shstrndx = u16(data, 46, e), u16(data, 48, e), u16(data, 50, e)
    relro = now = False
    nx = True
    for i in range(min(phnum, 256)):
        p = phoff + i * phentsize
        if p + phentsize > len(data):
            break
        p_type = u32(data, p, e)
        flags = u64(data, p + 4, e) if b.bits == 64 else u32(data, p + 24, e)
        off = u64(data, p + 8, e) if b.bits == 64 else u32(data, p + 4, e)
        filesz = u64(data, p + 32, e) if b.bits == 64 else u32(data, p + 16, e)
        if p_type == 0x6474E551:  # PT_GNU_STACK
            nx = not (flags & 0x1)
        elif p_type == 0x6474E552:  # PT_GNU_RELRO
            relro = True
        elif p_type == 2:  # PT_DYNAMIC
            step = 16 if b.bits == 64 else 8
            for j in range(min(filesz // step, 512)):
                q = off + j * step
                if q + step > len(data):
                    break
                tag = u64(data, q, e) if b.bits == 64 else u32(data, q, e)
                val = u64(data, q + 8, e) if b.bits == 64 else u32(data, q + 4, e)
                if tag == 0:
                    break
                if tag == 24:  # DT_BIND_NOW
                    now = True
                elif tag == 30 and val & 0x8:  # DT_FLAGS DF_BIND_NOW
                    now = True
                elif tag == 0x6FFFFFFB and val & 0x1:  # DT_FLAGS_1 DF_1_NOW
                    now = True
    # 节表：符号、节名
    secs = []
    shstr = b""
    for i in range(min(shnum, 512)):
        p = shoff + i * shentsize
        if p + shentsize > len(data):
            break
        name_off, s_type = u32(data, p, e), u32(data, p + 4, e)
        s_flags = u64(data, p + 8, e) if b.bits == 64 else u32(data, p + 8, e)
        addr = u64(data, p + 16, e) if b.bits == 64 else u32(data, p + 12, e)
        off = u64(data, p + 24, e) if b.bits == 64 else u32(data, p + 16, e)
        size = u64(data, p + 32, e) if b.bits == 64 else u32(data, p + 20, e)
        link = u32(data, p + 40, e) if b.bits == 64 else u32(data, p + 24, e)
        entsize = u64(data, p + 56, e) if b.bits == 64 else u32(data, p + 36, e)
        secs.append((name_off, s_type, addr, off, size, link, entsize, s_flags))
        if i == shstrndx:
            shstr = data[off:off + size]
    sections = []
    for (name_off, s_type, addr, off, size, link, entsize, s_flags) in secs:
        name = ""
        if shstr and name_off < len(shstr):
            nul = shstr.find(b"\x00", name_off)
            name = shstr[name_off:nul if nul >= 0 else len(shstr)].decode("latin-1", "replace")
        sections.append(Section(name, addr, size, off, size, s_flags))
        if addr and size and s_type == 1:  # PROGBITS 才用于 RVA 映射
            pass
    b.sections = sections
    # 符号表
    for (name_off, s_type, addr, off, size, link, entsize, s_flags) in secs:
        if s_type not in (2, 11):  # SYMTAB / DYNSYM
            continue
        str_sec = None
        if 0 <= link < len(secs):
            str_sec = secs[link]
        if not str_sec or not str_sec[4]:
            continue
        str_off, str_size = str_sec[3], str_sec[4]
        strtab = data[str_off:str_off + str_size]
        step = entsize or (24 if b.bits == 64 else 16)
        for j in range(min(size // step, 20000)):
            q = off + j * step
            if q + step > len(data):
                break
            st_name = u32(data, q, e)
            if b.bits == 64:
                st_shndx = u16(data, q + 6, e)
            else:
                st_shndx = u16(data, q + 14, e)
            if st_name >= len(strtab):
                continue
            nul = strtab.find(b"\x00", st_name)
            nm = strtab[st_name:nul if nul >= 0 else len(strtab)].decode("latin-1", "replace")
            if not nm:
                continue
            b.symbols.add(nm)
            if st_shndx == 0 and nm not in b.imports:
                b.imports.append(("", nm))
    if shstr:
        b.notes.append("ELF 节名/符号表已解析，导入=未定义符号（非 PLT 调用明细）")
    canary = any("__stack_chk_fail" in s or "__stack_chk_guard" in s for s in b.symbols)
    b.prot = {
        "NX": "Enabled" if nx else "Disabled (GNU_STACK executable)",
        "PIE": "Enabled (ET_DYN)" if e_type == 3 else "Disabled (ET_EXEC)",
        "Canary": "Found (__stack_chk_*) " if canary else "Not found",
        "RELRO": "Full" if (relro and now) else ("Partial" if relro else "None"),
    }


def analyze_imports(b):
    for dll, sym in b.imports:
        base = sym.lower().lstrip("_")
        if base.startswith("imp_"):
            base = base[4:]
        if base in FMT_FUNCS:
            b.fmt_funcs.add(base)
        if base in ("__security_check_cookie", "__security_init_cookie",
                    "__stack_chk_fail", "__stack_chk_guard"):
            b.has_load_config_cookie = True
            if b.kind == "PE":
                b.prot["Canary"] = "Found (cookie import)"
            else:
                b.prot["Canary"] = "Found (__stack_chk_*)"
        if base in ("malloc", "free", "calloc", "realloc", "new", "delete"):
            b.heap_funcs.add(base)
        rec = DANGEROUS.get(base)
        if rec and rec[1] in ("高", "中"):
            b.danger.append({"library": dll, "symbol": sym,
                             "category": rec[0], "severity": rec[1]})


def analyze_strings(b, strings):
    fmt_funcs = b.fmt_funcs or {"printf"}
    for s in strings:
        toks = FMT_TOKEN.findall(s)
        if not toks:
            continue
        unique = list(dict.fromkeys(toks))
        if "%n" in s:
            sev, why = "high", "含 %n，可直接任意写"
        elif "%s" in s or "%p" in s:
            sev, why = "medium", "含 %s/%p，可读任意地址/栈"
        elif len(unique) >= 3:
            sev, why = "medium", "多格式符，可能被当作可控模板"
        else:
            sev, why = "low", "单个常见格式符，需确认是否用户可控"
        if fmt_funcs and sev != "low":
            why += "；目标导入了格式化函数"
        b.fmt_risks.append({"string": s[:160], "tokens": unique[:8],
                            "severity": sev, "why": why})
    b.fmt_risks.sort(key=lambda x: {"high": 0, "medium": 1, "low": 2}[x["severity"]])
    b.fmt_risks = b.fmt_risks[:25]


def decide(b, strings):
    lower = "\n".join(strings).lower()
    crypto = any(h in lower for h in CRYPTO_HINTS)
    fmt_high = any(x["severity"] in ("high", "medium") for x in b.fmt_risks)
    stack_unsafe = any(d["category"].startswith(("栈", "越界写")) for d in b.danger)
    heap_semantic = any(x in lower for x in ("tcache", "uaf", "use after free",
                                             "double free", "free_hook",
                                             "heap overflow", "heap-buffer-overflow"))
    heap = heap_semantic or (bool(b.heap_funcs) and not stack_unsafe)
    has_canary = b.prot["Canary"].startswith("Found")
    nx = b.prot["NX"].startswith("Enabled")
    pie = b.prot["PIE"].startswith("Enabled")
    routes = []
    if fmt_high and (b.fmt_funcs or b.kind == "ELF"):
        routes.append({
            "route": "格式化字符串",
            "why": "发现 %n/%s/%p 模板且存在格式化函数；先定位参数序号，再泄漏或写 GOT/返回地址",
            "first_steps": ["发送 AAAA.%p... 找偏移", "Partial RELRO/GOT 可写则优先 GOT",
                            "64 位地址含 NUL 时放末尾并用 %hhn"],
        })
    if heap:
        routes.append({
            "route": "堆 tcache/UAF",
            "why": "存在 malloc/free 或堆语义字符串；先找 UAF/重复释放/越界写",
            "first_steps": ["确认 glibc 版本与 safe-linking", "先泄漏 heap 再泄漏 libc",
                            "tcache poison 目标按 0x10 对齐并复核 key"],
        })
    if stack_unsafe:
        routes.append({
            "route": "栈溢出 + ROP" if nx else "栈溢出 + shellcode",
            "why": "导入不安全拷贝/输入函数；用 cyclic 找偏移，检查 canary 与 NX",
            "first_steps": ["cyclic 定位覆盖长度", "有 canary 先泄漏/绕开",
                            "有 PIE 先泄漏代码/libc 基址；注意 16 字节对齐"],
        })
    if b.prot["RELRO"].startswith("Full") and b.kind == "ELF":
        routes.append({
            "route": "hook/退出链或栈迁移",
            "why": "Full RELRO 使 GOT 只读；glibc>=2.34 已移除 __free_hook",
            "first_steps": ["查 _IO_list_all/exit_funcs/environ", "或改程序自身函数指针"],
        })
    if crypto and not routes:
        routes.append({
            "route": "密码学求解",
            "why": "字符串出现 RSA/AES/ECB/CBC/PRNG 等线索",
            "first_steps": ["先确认填充、是否同一消息、模数是否互质",
                            "RSA 回代 pow(m,e,n)==c；分组做块关系比对"],
        })
    if not routes:
        routes.append({
            "route": "先定位输入面与校验分支",
            "why": "未发现典型危险导入/格式串；可能为逻辑漏洞、白盒或纯密码题",
            "first_steps": ["列输入点、比较点、可控缓冲区", "查整数/off-by-one 与协议解析",
                            "必要时先用 checksec + 动态断点确认崩溃点"],
        })
    # 把保护位影响写进首条路线
    lead = routes[0]
    caveats = []
    if has_canary and lead["route"].startswith("栈"):
        caveats.append("Canary 存在：先泄漏或改走格式化/堆")
    if pie and lead["route"].startswith("栈"):
        caveats.append("PIE 开启：先泄漏代码基址，不能硬编码")
    if b.prot["NX"].startswith("Enabled"):
        caveats.append("NX 开启：不要指望栈上 shellcode，走 ROP/ORW")
    if caveats:
        lead["caveats"] = caveats
    return routes


def _repo_root(start):
    """仓库根：向上找含 Tool/cases 的目录（S4 后脚本位于 Tool/skill/<pack>/scripts/，固定层数会算错）。"""
    d = os.path.abspath(start)
    for _ in range(8):
        if os.path.isdir(os.path.join(d, "Tool", "cases")):
            return d
        nd = os.path.dirname(d)
        if nd == d:
            break
        d = nd
    return os.path.abspath(os.path.join(start, "..", "..", "..", ".."))


ROOT = _repo_root(os.path.dirname(os.path.abspath(__file__)))


def error_payload(blocked_at, reason):
    """结构化失败对象：任何入口失败都返回这个形状，调用方按 rc=2 处理。"""
    return {"ok": False, "blocked_at": blocked_at, "reason": reason}


def emit_error(args, blocked_at, reason, rc=2):
    """统一错误输出：JSON 模式输出结构化对象，文本模式输出 [ERR]。"""
    payload = error_payload(blocked_at, reason)
    if args.json:
        print(json.dumps(payload, ensure_ascii=False))
    else:
        print("[ERR] %s: %s" % (blocked_at, reason), file=sys.stderr)
        print(json.dumps(payload, ensure_ascii=False))
    return rc


def analyze_bytes(data, label, max_strings=12000):
    """解析一段 PE/ELF 字节流，返回 pwn-check 的结论 dict（不自读文件）。"""
    b = Binary()
    if data[:2] == b"MZ":
        parse_pe(data, b)
    elif data[:4] == b"\x7fELF":
        parse_elf(data, b)
    else:
        raise ValueError("既不是 PE(MZ) 也不是 ELF")
    strings = strings_from(data, max_strings)
    analyze_imports(b)
    analyze_strings(b, strings)
    routes = decide(b, strings)
    return {
        "file": label,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "kind": b.kind,
        "arch": b.arch,
        "bits": b.bits,
        "entry": "0x%x" % b.entry,
        "protections": b.prot,
        "sections": [{"name": s.name, "va": "0x%x" % s.va,
                      "vsize": s.vsize, "rawsize": s.rawsize,
                      "writable": bool(s.chars & 0x80000000) if b.kind == "PE" else bool(s.chars & 0x1),
                      "executable": bool(s.chars & 0x20000000) if b.kind == "PE" else bool(s.chars & 0x4)}
                     for s in b.sections[:32]],
        "import_count": len(b.imports),
        "dangerous_imports": b.danger[:60],
        "format_string_risks": b.fmt_risks,
        "next_routes": routes,
        "notes": b.notes,
    }


def self_test():
    """离线自检：用仓库内真实 PE 样本 + 内置字符串，覆盖解析/判据/失败形状。"""
    checks = []
    sample = os.path.join(ROOT, "Tool", "samples", "real", "crackerjack", "a.exe")
    if not os.path.isfile(sample):
        return error_payload("self-test-sample", "缺少仓库内真实样本 Tool/samples/real/crackerjack/a.exe"), 2
    with open(sample, "rb") as fh:
        data = fh.read()
    res = analyze_bytes(data, "Tool/samples/real/crackerjack/a.exe", 4000)
    checks.append(("kind==PE", res["kind"] == "PE"))
    checks.append(("sha256", len(res["sha256"]) == 64))
    checks.append(("protections", set(res["protections"]) >= {"NX", "PIE", "Canary", "RELRO"}))
    checks.append(("routes", len(res["next_routes"]) >= 1))
    b = Binary()
    analyze_strings(b, ["%n write", "plain %d", "%s.%p leak"])
    sev = {x["string"]: x["severity"] for x in b.fmt_risks}
    checks.append(("fmt-%n-high", sev.get("%n write") == "high"))
    checks.append(("fmt-leak-medium", sev.get("%s.%p leak") == "medium"))
    payload = error_payload("parse", "bad magic")
    checks.append(("error-shape", payload["ok"] is False and payload["blocked_at"] == "parse"))
    failed = [name for name, ok in checks if not ok]
    if failed:
        return error_payload("self-test", "失败项: " + ",".join(failed)), 2
    return {"ok": True, "checks": len(checks), "sample": "Tool/samples/real/crackerjack/a.exe",
            "sample_sha256": res["sha256"]}, 0


def main():
    ap = argparse.ArgumentParser(
        description="PE/ELF 保护位、危险导入、format 串风险与利用路线预判（纯标准库，只读）",
        epilog="退出码：0 成功；2 结构化失败（blocked_at/reason）。")
    ap.add_argument("--file", "-f", help="PE/ELF 文件路径")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--max-strings", type=int, default=12000, help="扫描字符串上限（默认 12000）")
    ap.add_argument("--self-test", action="store_true", help="离线自检（真实 PE 样本 + 内置格式串）")
    args = ap.parse_args()
    if args.self_test:
        payload, rc = self_test()
        print(json.dumps(payload, ensure_ascii=False))
        return rc
    if not args.file:
        return emit_error(args, "args", "缺少 --file（或改用 --self-test）", 2)
    path = os.path.abspath(args.file)
    if not os.path.isfile(path):
        return emit_error(args, "read", "文件不存在: %s" % args.file, 2)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return emit_error(args, "read", "读取失败: %s" % exc, 2)
    b = Binary()
    try:
        result = analyze_bytes(data, path, args.max_strings)
    except (ValueError, struct.error, IndexError) as exc:
        return emit_error(args, "parse", "解析失败: %s" % exc, 2)
    # 文本模式需要 Section 标志位与 notes，重解析一次供打印（JSON 已由 analyze_bytes 生成）
    try:
        if data[:2] == b"MZ":
            parse_pe(data, b)
        else:
            parse_elf(data, b)
        analyze_imports(b)
        analyze_strings(b, strings_from(data, args.max_strings))
    except (ValueError, struct.error, IndexError):
        pass
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    print("== pwn-check ==")
    print("file      : %s" % path)
    print("sha256    : %s" % result["sha256"])
    print("format    : %s %s %d-bit  entry=%s  size=%d" %
          (b.kind, b.arch, b.bits, result["entry"], len(data)))
    print("protect   : NX=%s | PIE=%s | Canary=%s | RELRO=%s" %
          (b.prot["NX"], b.prot["PIE"], b.prot["Canary"], b.prot["RELRO"]))
    for n in b.notes:
        print("note      : %s" % n)
    print("\n-- 危险/敏感导入（%d/%d）--" % (len(b.danger), len(b.imports)))
    if b.danger:
        for d in b.danger[:30]:
            print("  [%-4s] %-18s %s!%s" % (d["severity"], d["category"], d["library"], d["symbol"]))
    else:
        print("  （未命中清单；仍需看动态解析 LoadLibrary/GetProcAddress）")
    print("\n-- 字符串 format 串风险（%d）--" % len(b.fmt_risks))
    if b.fmt_risks:
        for x in b.fmt_risks[:15]:
            print("  [%-6s] %s" % (x["severity"], x["string"][:100]))
            print("           %s" % x["why"])
    else:
        print("  （未发现 %n/%s/%p 类模板）")
    print("\n-- 下一步优先路线 --")
    for i, r in enumerate(result["next_routes"], 1):
        print("%d. %s" % (i, r["route"]))
        print("   判据: %s" % r["why"])
        for s in r["first_steps"]:
            print("   - %s" % s)
        for c in r.get("caveats", []):
            print("   ! %s" % c)
    print("\n提示：本脚本只做静态预判；seccomp 白名单用 seccomp-tools dump，libc 用同版本核对。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
