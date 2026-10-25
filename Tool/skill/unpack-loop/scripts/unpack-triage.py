#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""unpack-triage：脱壳前的**只读**判型（不运行、不写盘、不改字节）。

为什么需要（2026-10-25）：脱壳域此前只有方法没有工具 —— `unpack-loop` 0 个脚本，
而外部同类（yaklang / re-anti-analysis）都带可执行入口。这个脚本只回答三个问题：
  ① 这是什么载体 / 有没有壳（三证据）
  ② 属于哪一类壳（A 标准压缩 / B 整盘加密 / C 虚拟化 / D 反作弊加固 / E 自研）
  ③ 该走哪条路 + 缺什么

用法：
    python unpack-triage.py <file> [--json]
退出码：0 = 已给出判型；2 = 无法判（文件不可读等）
"""
import argparse
import collections
import hashlib
import json
import math
import os
import sys

STD_SECTIONS = {".text", ".rdata", ".data", ".pdata", "_rdata", ".code", ".bss", ".tls"}
KNOWN_PACK_SECTIONS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX", ".aspack": "ASPack", ".adata": "ASPack",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS", ".vmp0": "VMProtect", ".vmp1": "VMProtect",
    ".enigma1": "Enigma", ".enigma2": "Enigma", ".themida": "Themida", ".winlice": "Themida",
}


def entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    c = collections.Counter(blob)
    n = len(blob)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def analyze(path: str) -> dict:
    data = open(path, "rb").read()
    out = {
        "file": os.path.basename(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "is_pe": data[:2] == b"MZ",
        "sections": [],
        "evidence": [],
        "hard_blockers": [],
    }
    if not out["is_pe"]:
        out["verdict"] = {"class": "非 PE", "route": "不属于脱壳域（ELF/Mach-O/其它）→ 回 seep-router 选域"}
        return out

    try:
        import pefile  # type: ignore
    except Exception:
        out["evidence"].append("pefile 不可用：只能给文件级事实（大小/哈希/魔数）")
        out["verdict"] = {"class": "未判", "route": "装 pefile 后重跑（python -m pip install pefile）"}
        return out

    pe = pefile.PE(path, fast_load=True)
    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_sec = ""
    std_zero, exes = [], []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin1", "replace")
        raw = s.SizeOfRawData
        ent = s.get_entropy()
        out["sections"].append({"name": name, "va": hex(s.VirtualAddress), "raw": raw,
                                "vsize": s.Misc_VirtualSize, "entropy": round(ent, 2),
                                "exec": bool(s.Characteristics & 0x20000000)})
        if name.lower() in STD_SECTIONS and raw == 0:
            std_zero.append(name)
        if s.VirtualAddress <= ep_rva < s.VirtualAddress + max(s.Misc_VirtualSize, raw or 1):
            ep_sec = name
        if raw and raw / max(1, len(data)) > 0.90 and ent > 7.5:
            exes.append((name, ent, raw))

    # ── 三证据（与 references/packers-quickref.md 对齐）───────────────
    ev = out["evidence"]
    if std_zero:
        ev.append("标准节被搬空（RawSize=0）：%s" % ", ".join(std_zero[:6]))
    if exes:
        n, e, r = exes[0]
        ev.append("单节占比>90%% 且熵 %.2f：%s（%d 字节）" % (e, n, r))
    try:
        pe.parse_data_directories()
        nimp = sum(len(e.imports) for e in (getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []))
        out["import_count"] = nimp
        if nimp < 10:
            ev.append("导入很少（%d 条）：疑似壳自行解析导入" % nimp)
    except Exception:
        out["import_count"] = None
    epn = (ep_sec or "").lower()
    if epn and epn not in {".text", ".code"}:
        ev.append("入口点落在非代码节：%s（EP RVA=%s）" % (ep_sec, hex(ep_rva)))

    # ── 分类 ──────────────────────────────────────────────────
    hints = [v for k, v in KNOWN_PACK_SECTIONS.items() if any(k == s["name"].lower() for s in out["sections"])]
    hints = sorted(set(hints))
    packed = len(ev) >= 2
    if not packed:
        cls, route = "无壳/弱信号", "可直接静态分析（不需要脱壳）；若行为异常再回 unpack-loop"
    elif hints:
        cls = "A 标准压缩壳（%s）" % "/".join(hints)
        route = "先试官方解包（upx -d / 对应工具）；失败再走 OEP 法（references/oep-locate.md）"
    elif any(s["name"].startswith(".") and not s["name"].isprintable() for s in out["sections"]) or exes:
        cls = "B 整盘加密（畸形节名/整盘塞入单节）"
        route = "必须动态：判型→OEP→dump→修 IAT（references/oep-locate.md → iat-repair.md）"
    elif epn and epn not in {".text", ".code"}:
        cls = "B/C（EP 不在代码节，需动态确认是否虚拟化）"
        route = "先按 B 类走；若见到 VM 解释器循环，按 C 类（函数级）处理"
    else:
        cls = "E 自研/未识别"
        route = "按 B 类流程走，每步留证据；不要凭熵下结论"

    out["packer_hints"] = hints
    out["verdict"] = {"class": cls, "route": route}
    if out.get("import_count") == 0:
        out["hard_blockers"].append("导入表为空：常见于整盘加密，dump 后必须修 IAT")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="脱壳前只读判型（不运行目标、不写盘）")
    ap.add_argument("file")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if not os.path.isfile(a.file):
        print("[ERR] 文件不存在：%s" % a.file)
        return 2
    r = analyze(a.file)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0
    print("文件: %s  %d 字节  sha256=%s…" % (r["file"], r["size"], r["sha256"][:16]))
    print("证据（%d 条，≥2 条才算判出壳）:" % len(r["evidence"]))
    for e in r["evidence"] or ["（无）"]:
        print("  -", e)
    if r["sections"]:
        print("%-10s %10s %10s %8s %6s" % ("节", "VA", "RawSize", "Size", "熵"))
        for s in r["sections"]:
            print("%-10s %10s %10d %8d %6.2f" % (s["name"], s["va"], s["raw"], s["vsize"], s["entropy"]))
    v = r["verdict"]
    print("\n判定: %s" % v["class"])
    print("路线: %s" % v["route"])
    for b in r["hard_blockers"]:
        print("注意: %s" % b)
    return 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
