#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""preflight-classify：softseep 判型前的「看目标」预判器（源自 relab2 实战，适配 Seep）。

为什么需要（relab2 盲跑 31 靶标实测）：
    只给一个裸文件路径时，纯关键词判型会把 24/31 判成「通用/低置信」，
    因为路径本身几乎不带业务关键词。先读文件头与结构，能直接得到
    平台(Windows/Android/Linux/Web) + 保护形态(壳/反调试/.NET) + 建议类型，
    再交给 softseep 判型，命中率显著提升。

本脚本只做一件事：读文件头与结构，产出**结构化分类**，交给 softseep 当提示。
它不改任何路由表、不猜业务语义、不执行目标。

用法：
    python preflight-classify.py <path>            # JSON（platform / protection / suggested_type）
    python preflight-classify.py <path> --hint     # 一行可直接喂给 softseep 判型的提示词
    python preflight-classify.py <dir>             # 批量

退出码：0 成功（无论识别到什么）；2 路径不存在。
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import os
import struct
import sys
import tempfile
import zipfile

# ---- 容器/格式魔数 ----
MAGIC = [
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"\xfe\xed\xfa\xce", "macho"), (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"), (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xca\xfe\xba\xbe", "macho-fat"),
    (b"PK\x03\x04", "zip"),
    (b"\xd0\xcf\x11\xe0", "ole"),
    (b"Rar!", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ", "xz"),
    (b"FWS", "swf"), (b"CWS", "swf-zlib"), (b"ZWS", "swf-lzma"),
    (b"\xa1\xb2\xc3\xd4", "pcap"), (b"\xd4\xc3\xb2\xa1", "pcap"),
    (b"\x0a\x0d\x0d\x0a", "pcapng"),
    (b"Cr24", "crx"),
    (b"dex\n", "dex"),
    (b"\x27\x05\x19\x56", "uimage"),
    (b"hsqs", "squashfs"), (b"sqsh", "squashfs-be"),
    (b"\x85\x19\x03\x20", "jffs2"), (b"\x1f\x8b\x08", "gzip"),
    (b"UBI#", "ubifs"), (b"hsqs", "squashfs"),
    (b"cramfs", "cramfs"),
]

# 固件里常见的文件系统/引导魔数（任意偏移）
FW_SIGS = [
    (b"hsqs", "squashfs"), (b"sqsh", "squashfs-be"),
    (b"\x85\x19\x03\x20", "jffs2"), (b"UBI#", "ubifs"),
    (b"cramfs", "cramfs"), (b"\x27\x05\x19\x56", "uimage"),
    (b"HDR0", "trx"), (b"CSYS", "cisco"),
]

# 反调试 / 保护相关的导入名（PE）
ANTIDEBUG_IMPORTS = {
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "OutputDebugStringA", "OutputDebugStringW", "GetTickCount", "QueryPerformanceCounter",
    "NtSetInformationThread", "NtQuerySystemInformation", "CreateToolhelp32Snapshot",
    "Process32First", "Process32Next", "FindWindowA", "FindWindowW",
}
ANTIVM_STRINGS = [
    b"VMware", b"VirtualBox", b"VBox", b"QEMU", b"Xen", b"Hyper-V", b"vbox",
    b"SbieDll", b"dbghelp", b"OllyDbg", b"x64dbg", b"IDA", b"Wireshark",
]

# 已知壳的节名 / 特征
PACKER_SECTIONS = {
    ".upx0", ".upx1", ".upx2", "UPX0", "UPX1", "UPX2",
    ".aspack", ".adata", "ASPack", ".nsp0", ".nsp1", ".nsp2",
    ".themida", ".winlice", ".vmp0", ".vmp1", ".vmp2", ".enigma1", ".enigma2",
    ".petite", ".pec1", ".pec2", ".mpress1", ".mpress2", ".yP", ".y0da",
    ".Gogi", ".GWan",
}
PACKER_STRINGS = [b"UPX!", b"UPX0", b"UPX1", b"ASPack", b"Themida", b"VMProtect", b".vmp"]


def entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    c = [0] * 256
    for b in buf:
        c[b] += 1
    n = len(buf)
    return -sum((v / n) * math.log2(v / n) for v in c if v)


def sniff(head: bytes) -> str:
    for sig, kind in MAGIC:
        if head.startswith(sig):
            return kind
    return "unknown"


def parse_pe(data: bytes) -> dict:
    out: dict = {"format": "pe"}
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            out["error"] = "PE signature not found"
            return out
        machine, nsec = struct.unpack_from("<HH", data, e_lfanew + 4)
        opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        opt_off = e_lfanew + 24
        magic = struct.unpack_from("<H", data, opt_off)[0]
        is64 = magic == 0x20B
        out["machine"] = {0x14C: "i386", 0x8664: "x86-64", 0xAA64: "arm64", 0x1C0: "arm"}.get(machine, hex(machine))
        out["bitness"] = 64 if is64 else 32
        out["entry_rva"] = struct.unpack_from("<I", data, opt_off + 16)[0]
        # data directories
        dd_off = opt_off + (112 if is64 else 96)
        ndd = struct.unpack_from("<I", data, opt_off + (108 if is64 else 92))[0]
        dirs = []
        for i in range(min(ndd, 16)):
            rva, size = struct.unpack_from("<II", data, dd_off + i * 8)
            dirs.append((rva, size))
        out["has_clr"] = len(dirs) > 14 and dirs[14][1] > 0
        out["has_imports"] = len(dirs) > 1 and dirs[1][1] > 0
        out["has_relocs"] = len(dirs) > 5 and dirs[5][1] > 0
        # sections
        sec_off = opt_off + opt_size
        secs = []
        for i in range(nsec):
            o = sec_off + i * 40
            name = data[o:o + 8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
            body = data[rawptr:rawptr + rawsize]
            secs.append({
                "name": name,
                "vaddr": vaddr,
                "vsize": vsize,
                "raw": rawsize,
                "entropy": round(entropy(body), 2),
            })
        out["sections"] = secs
        # packer heuristics
        names = {s["name"] for s in secs}
        hits = sorted(names & PACKER_SECTIONS)
        if hits:
            out["packer_sections"] = hits
        # EP outside sections?
        if secs:
            last_end = max((s["vaddr"] + max(s["vsize"], s["raw"]) for s in secs), default=0)
            if out["entry_rva"] > last_end:
                out["entry_outside_sections"] = True
        # high entropy
        hi = [s["name"] for s in secs if s["entropy"] > 7.0 and s["raw"] > 512]
        if hi:
            out["high_entropy_sections"] = hi
        # string-based packer hints
        ph = [p.decode() for p in PACKER_STRINGS if p in data[:4096] or p in data]
        if ph:
            out["packer_strings"] = sorted(set(ph))
    except Exception as exc:  # noqa: BLE001
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    return out


def parse_elf(data: bytes) -> dict:
    out: dict = {"format": "elf"}
    try:
        cls = data[4]
        out["bitness"] = 32 if cls == 1 else 64
        out["endian"] = "le" if data[5] == 1 else "be"
        e_type = struct.unpack_from("<H", data, 16)[0]
        out["type"] = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}.get(e_type, hex(e_type))
        out["machine"] = struct.unpack_from("<H", data, 18)[0]
        out["entry"] = struct.unpack_from("<I", data, 24)[0] if cls == 1 else struct.unpack_from("<Q", data, 24)[0]
        if cls == 1:
            phoff = struct.unpack_from("<I", data, 28)[0]
            shoff = struct.unpack_from("<I", data, 32)[0]
            phentsize, phnum = struct.unpack_from("<HH", data, 42)
            shentsize, shnum = struct.unpack_from("<HH", data, 46)
        else:
            phoff = struct.unpack_from("<Q", data, 32)[0]
            shoff = struct.unpack_from("<Q", data, 40)[0]
            phentsize, phnum = struct.unpack_from("<HH", data, 54)
            shentsize, shnum = struct.unpack_from("<HH", data, 60)
        out["phnum"] = phnum
        out["shnum"] = shnum
        out["stripped_sections"] = (shoff == 0 or shnum == 0)
        # 段
        segs = []
        for i in range(min(phnum, 32)):
            o = phoff + i * phentsize
            if cls == 1:
                p_type, p_off, p_va, _, p_fsz, p_msz, p_flags, _ = struct.unpack_from("<IIIIIIII", data, o)
            else:
                p_type, p_flags = struct.unpack_from("<II", data, o)
                p_off, p_va, _, p_fsz, p_msz = struct.unpack_from("<QQQQQ", data, o + 8)
            segs.append({"type": p_type, "off": p_off, "vaddr": p_va, "filesz": p_fsz, "memsz": p_msz})
        out["segments"] = segs
        # 入口落在映射段外？
        if segs:
            inside = any(s["vaddr"] <= out["entry"] < s["vaddr"] + max(s["filesz"], s["memsz"]) for s in segs if s["type"] == 1)
            out["entry_mapped"] = inside
        # Go / Rust
        if b"Go build ID" in data or b".gopclntab" in data:
            out["language"] = "go"
        elif b"rustc" in data or b"panicked at" in data:
            out["language"] = "rust"
        elif b"GLIBC" in data:
            out["language"] = "c/c++"
    except Exception as exc:  # noqa: BLE001
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    return out


def parse_zip(data: bytes, path: str) -> dict:
    out: dict = {"format": "zip"}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            out["entries"] = len(names)
            out["top"] = sorted({n.split("/")[0] for n in names if n})[:12]
            if "AndroidManifest.xml" in names:
                out["container"] = "apk"
            if "classes.dex" in names:
                out["dex"] = True
            if any(n.startswith("META-INF/") for n in names) and any(n.endswith(".class") for n in names):
                out["container"] = "jar"
            if any(n.startswith("chrome/") or n == "manifest.json" for n in names):
                out["container"] = out.get("container") or "extension"
            if "firmware" in " ".join(names).lower():
                out["container"] = "firmware-archive"
    except Exception as exc:  # noqa: BLE001
        out["error"] = "%s: %s" % (type(exc).__name__, exc)
    return out


def scan_firmware(data: bytes) -> list[str]:
    found = []
    for sig, name in FW_SIGS:
        idx = data.find(sig)
        if idx >= 0:
            found.append("%s@0x%x" % (name, idx))
    return found[:8]


def platform_of(info: dict) -> str:
    """映射到 softseep 的平台轴：Windows / Android / Linux / Web / Flutter。"""
    fmt = info.get("format")
    container = info.get("container")
    if container == "apk" or fmt in ("apk", "dex"):
        return "Android"
    if container == "extension" or fmt == "crx":
        return "Web"
    if fmt == "pe":
        return "Windows"
    if fmt == "elf":
        return "Linux"
    if fmt in ("macho", "macho-fat"):
        return "macOS"
    if fmt == "swf":
        return "Web"
    if fmt in ("pcap", "pcapng"):
        return "Web"
    if info.get("firmware_signatures"):
        return "Firmware"
    return "Unknown"


def suggested_type_of(info: dict) -> str:
    """映射到 softseep 的类型轴（粗判，仅作判型提示，不取代判型）。"""
    fmt = info.get("format")
    if fmt in ("pcap", "pcapng"):
        return "协议分析"
    if info.get("packer_sections") or info.get("packer_strings") or info.get("entry_outside_sections"):
        return "脱壳/解包"
    if info.get("has_clr"):
        return "授权/许可"  # .NET 客户端最常见诉求是授权/激活
    if fmt in ("apk", "dex", "jar"):
        return "授权/许可"
    if info.get("firmware_signatures"):
        return "脱壳/解包"
    # 裸可执行：默认测绘/分析（无明确动词时）
    return "测绘报告"


def protection_of(info: dict) -> list[str]:
    """保护形态标签：壳 / 高熵 / 反调试 / 反虚拟机 / .NET / 去符号。"""
    tags = []
    if info.get("packer_sections") or info.get("packer_strings") or info.get("entry_outside_sections"):
        tags.append("packed")
    if info.get("high_entropy_sections"):
        tags.append("high-entropy:" + ",".join(info["high_entropy_sections"][:3]))
    if info.get("antidebug_imports"):
        tags.append("antidebug")
    if info.get("antivm_strings"):
        tags.append("antivm")
    if info.get("has_clr"):
        tags.append(".NET/CLR")
    if info.get("stripped_sections"):
        tags.append("stripped")
    return tags


def route_for(info: dict) -> list[str]:
    """兼容旧字段：给出建议路由 id（Seep 不使用，保留以防外部脚本引用）。"""
    fmt = info.get("format")
    if info.get("container") == "apk":
        return ["R1", "R2"]
    if info.get("container") == "extension":
        return ["R30"]
    if fmt == "pe":
        if info.get("has_clr"):
            return ["R5"]
        if info.get("packer_sections") or info.get("packer_strings") or info.get("entry_outside_sections"):
            return ["R54", "R53", "R6"]
        if info.get("machine") == "x86-64":
            return ["R53", "R6"]
        return ["R6", "R7"]
    if fmt == "elf":
        if info.get("stripped_sections"):
            return ["R7", "R6"]
        if info.get("language") == "go" or info.get("language") == "rust":
            return ["R33", "R7"]
        return ["R7", "R6"]
    if fmt == "macho" or fmt == "macho-fat":
        return ["R31"]
    if fmt == "swf" or fmt == "swf-zlib" or fmt == "swf-lzma":
        return ["R0"]
    if fmt == "dex":
        return ["R1"]
    if fmt == "pcap" or fmt == "pcapng":
        return ["R21", "R25"]
    if fmt == "crx":
        return ["R30"]
    if info.get("firmware_signatures"):
        return ["R8", "R7"]
    if fmt == "zip":
        return ["R0"]
    return ["R0"]


def classify_zip_member(data: bytes, zip_name: str = "") -> dict | None:
    """从 zip 里挑最可能的**样本主体**并分类。只读，不解压到磁盘。

    ★ 不能只取最大文件：metroapp.zip 里最大的是 Dependencies/x86/VCLibs.appx（依赖包），
      真正的目标是 MetroApp_1.0.0.5_Win32.appx。按「名字像样本 + 可执行扩展名 - 依赖目录」打分。
    """
    TEXT_EXT = (".txt", ".md", ".html", ".htm", ".json", ".xml", ".csv", ".nfo", ".url", ".lnk",
                ".ps1", ".psd1", ".cer", ".p7b", ".png", ".jpg", ".ico", ".cat")
    EXEC_EXT = (".exe", ".dll", ".sys", ".so", ".elf", ".appx", ".appxbundle", ".msix",
                ".jar", ".apk", ".bin", ".efi", ".ko", ".dylib")
    stem = os.path.splitext(os.path.basename(zip_name))[0].lower()
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            cands = [i for i in z.infolist() if not i.is_dir() and i.file_size > 0]
            if not cands:
                return None

            def score(i):
                low = i.filename.lower()
                s = 0
                if low.endswith(TEXT_EXT):
                    s -= 60
                if low.endswith(EXEC_EXT):
                    s += 50
                if "dependencies/" in low or "/redist/" in low:
                    s -= 80
                if stem and stem in low:
                    s += 100
                # 轻微偏好大文件，但不足以压过上面的判据
                s += min(i.file_size, 4 << 20) / float(4 << 20) * 10
                return s

            best = max(cands, key=score)
            if best.file_size > (64 << 20):
                return {"format": "too-large", "member": best.filename, "bytes": best.file_size}
            body = z.read(best)
    except Exception:  # noqa: BLE001
        return None
    kind = sniff(body[:4096])
    out: dict = {"member": best.filename, "bytes": len(body), "format": kind}
    if kind == "pe":
        out.update(parse_pe(body))
        out["format"] = "pe"
    elif kind == "elf":
        out.update(parse_elf(body))
        out["format"] = "elf"
    elif kind in ("macho", "macho-fat"):
        out["format"] = "macho"
    elif kind.startswith("swf"):
        out["format"] = "swf"
    elif kind == "dex":
        out["format"] = "dex"
    elif kind == "zip":
        # .appx / .msix 本身就是 zip；再往里看一层拿真正的 .exe/.dll
        deep = classify_zip_member(body, best.filename)
        if deep:
            out["nested"] = deep
            out["format"] = deep.get("format", "zip")
            for k in ("machine", "bitness", "has_clr", "packer_sections", "language"):
                if deep.get(k):
                    out[k] = deep[k]
        else:
            out["format"] = "zip"
    ad = [s for s in ANTIDEBUG_IMPORTS if s.encode() in body]
    if ad:
        out["antidebug_imports"] = sorted(ad)[:8]
    return out


def classify(path: str) -> dict:
    with open(path, "rb") as f:
        data = f.read()
    head = data[:4096]
    kind = sniff(head)
    info: dict = {
        "path": path,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "magic_kind": kind,
        "format": kind,
    }
    if kind == "pe":
        info.update(parse_pe(data))
        info["format"] = "pe"
    elif kind == "elf":
        info.update(parse_elf(data))
        info["format"] = "elf"
    elif kind in ("macho", "macho-fat"):
        info["format"] = "macho"
    elif kind == "zip":
        z = parse_zip(data, path)
        info.update(z)
        if z.get("container") == "apk":
            info["format"] = "apk"
        elif z.get("container") == "jar":
            info["format"] = "jar"
        else:
            info["format"] = "zip"
            # ★ 2026-10-17 盲跑实测：Reversing.KR 等靶标大量以 .zip 分发，
            #   只看容器层会让 easy_unpack/hateintel/windowskernel 全部落到 R0。
            #   这里递归看**最大的二进制成员**，把真实类型提到顶层。
            inner = classify_zip_member(data, path)
            if inner:
                info["inner"] = inner
                info["format"] = inner.get("format", "zip")
                for k in ("machine", "bitness", "has_clr", "packer_sections",
                          "packer_strings", "entry_outside_sections",
                          "stripped_sections", "language", "antidebug_imports"):
                    if inner.get(k):
                        info[k] = inner[k]
    elif kind.startswith("swf"):
        info["format"] = "swf"
    elif kind == "unknown":
        # 可能是裸固件
        fw = scan_firmware(data)
        if fw:
            info["format"] = "firmware"
            info["firmware_signatures"] = fw
    else:
        info["format"] = kind

    # 反调试 / 反虚拟机字符串
    ad = [s for s in ANTIDEBUG_IMPORTS if s.encode() in data]
    if ad:
        info["antidebug_imports"] = sorted(ad)[:8]
    av = [s.decode() for s in ANTIVM_STRINGS if s in data]
    if av:
        info["antivm_strings"] = sorted(set(av))[:8]

    info["platform"] = platform_of(info)
    info["protection"] = protection_of(info)
    info["suggested_type"] = suggested_type_of(info)
    info["suggested_routes"] = route_for(info)  # 兼容旧字段，Seep 不依赖
    info["hint"] = to_hint(info)
    # ★ 没有专用技能时，明确说出来，而不是静默回退 R0。
    #   R0 是「通用逆向方法论」，不是「这个格式有人管」。
    gaps = {
        "swf": "SWF/Flash 无专用技能（routing.json 无对应路由）；回退 R0 通用方法论，Flash 反编译需额外工具链",
        "jar": "Java/JAR 无专用技能（routing.json 无对应路由）；回退 R0 通用方法论，Java 字节码反编译需 jadx/CFR",
    }
    if info.get("format") in gaps:
        info["gap"] = gaps[info["format"]]
    return info


def to_hint(info: dict) -> str:
    parts = ["sample", os.path.basename(info["path"]), "platform=%s" % info.get("platform")]
    if info.get("suggested_type"):
        parts.append("type=%s" % info["suggested_type"])
    parts.append("format=%s" % info.get("format"))
    for k in ("machine", "bitness", "language", "container"):
        if info.get(k):
            parts.append("%s=%s" % (k, info[k]))
    prot = info.get("protection") or []
    if prot:
        parts.append("protection=%s" % ",".join(prot))
    if info.get("firmware_signatures"):
        parts.append("firmware")
    return " ".join(parts)


HELP_TEXT = """preflight-classify.py — softseep 判型前的目标预判器

用法:
  python preflight-classify.py <path> [--hint]
  python preflight-classify.py --self-test
  python preflight-classify.py --help

输入:
  <path>   单个文件或目录（只读，不执行目标）
  --hint   每个目标打印一行可直接喂给 softseep 的提示词

输出:
  默认 JSON（platform/protection/suggested_type/sections/hint）；--hint 时一行文本

退出码:
  0 成功（无论识别到什么）
  2 路径不存在 / 参数错误 / self-test 失败

self-test:
  离线生成最小 PE，验证 magic/PE 解析/JSON 输出；不联网、不读外部样本。
"""


def self_test() -> int:
    checks = 0
    try:
        assert sniff(b"MZ\x90\x00") == "pe"; checks += 1
        assert entropy(b"\x00" * 32) == 0.0; checks += 1
        data = bytearray(0x400)
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HH", data, 0x84, 0x8664, 1)      # machine, nsec
        struct.pack_into("<H", data, 0x94, 0xF0)           # SizeOfOptionalHeader
        opt = 0x98
        struct.pack_into("<H", data, opt, 0x20B)           # PE32+
        struct.pack_into("<I", data, opt + 16, 0x1000)     # AddressOfEntryPoint
        struct.pack_into("<I", data, opt + 108, 16)        # NumberOfRvaAndSizes
        sec = opt + 0xF0
        data[sec:sec + 8] = b".text\0\0\0"
        struct.pack_into("<IIII", data, sec + 8, 0x1000, 0x1000, 0, 0)
        parsed = parse_pe(bytes(data))
        assert parsed.get("format") == "pe" and parsed.get("machine") == "x86-64"; checks += 1
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(data)
            tmp = f.name
        try:
            info = classify(tmp)
            assert info.get("format") == "pe" and info.get("platform") == "Windows"; checks += 1
            assert info.get("sections") and info["sections"][0]["name"] == ".text"; checks += 1
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        print(json.dumps({"ok": True, "checks": checks}, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "self-test",
                          "reason": "%s: %s" % (type(exc).__name__, exc)}, ensure_ascii=True))
        return 2


def main(argv: list[str]) -> int:
    if "--help" in argv or "-h" in argv:
        print(HELP_TEXT)
        return 0
    if "--self-test" in argv:
        return self_test()
    if not argv:
        print(json.dumps({"ok": False, "blocked_at": "args",
                          "reason": "缺少 <path>；用 --help 看用法"}, ensure_ascii=True))
        return 2
    target = argv[0]
    as_hint = "--hint" in argv
    if not os.path.exists(target):
        print(json.dumps({"ok": False, "blocked_at": "input",
                          "reason": "路径不存在：%s" % target}, ensure_ascii=True))
        return 2
    paths = []
    if os.path.isdir(target):
        for name in sorted(os.listdir(target)):
            p = os.path.join(target, name)
            if os.path.isfile(p):
                paths.append(p)
    else:
        paths.append(target)
    if not paths:
        print(json.dumps({"ok": False, "blocked_at": "input",
                          "reason": "目录中没有文件：%s" % target}, ensure_ascii=True))
        return 2
    results = []
    for p in paths:
        try:
            info = classify(p)
        except Exception as exc:  # noqa: BLE001
            info = {"path": p, "error": "%s: %s" % (type(exc).__name__, exc)}
        results.append(info)
        if as_hint:
            print(to_hint(info))
    if not as_hint:
        # ★ ensure_ascii=True：PowerShell 子进程默认按本地码页解码 stdout，
        #   带中文的 UTF-8 会被打乱 -> ConvertFrom-Json 抛错 -> preflight 静默失效（实测 SWF 就是这样丢的）。
        #   转义成 \uXXXX 后任何码页都能正确解析。
        print(json.dumps(results if len(results) > 1 else results[0], ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
