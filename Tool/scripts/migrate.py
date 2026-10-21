#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""migrate.py —— 跨版本追版引擎（第 04 阶段用）。

它解决的问题：
    01 旁路卡密 → 02 改 UI → 03 接授权，做完一整套之后，原作者发新版了。
    从零再走一遍是浪费：**位点语义没变，只是 RVA 漂了；UI 素材完全可复用；
    授权挂载点只是在新的位点上重挂一次**。追版 = 迁移三张资产清单，不是重新逆向。

工作方式（对应 SKILL 的 7 步流水线的 1/2/7 步）：
    fingerprint  版本指纹（hash/节表/熵/壳线索）—— 判断"壳换没换"
    init         建版本账（versions/<ver>/manifest.json）
    add-site     把旧版位点连同 AOB 特征码记账（支持相对操作数自动通配）
    align        在新版二进制里滑窗对齐每条 AOB，输出命中率与需人工清单
    report       生成《迁移差异报告》markdown

设计纪律：
    · 命中率不到 100% 就明说"K 处需人工"，绝不假装成功；
    · 只做"对位"，不自动改判定逻辑 —— 语义确认永远是人/agent 的判断；
    · 零第三方依赖（纯标准库），任何机器 clone 下来就能跑。

用法：
    python Tool/scripts/migrate.py fingerprint <exe>
    python Tool/scripts/migrate.py init --case <case目录> --exe <旧版exe> --version 6.8
    python Tool/scripts/migrate.py add-site --case <case目录> --version 6.8 \\
        --id gate-01 --sem "卡密判定跳转" --rva 0x4f9f4 --window 24 --wildcard-rel
    python Tool/scripts/migrate.py align --case <case目录> --old 6.8 --new <新版exe> --new-version 6.9
    python Tool/scripts/migrate.py report --case <case目录> --old 6.8 --new-version 6.9
    python Tool/scripts/migrate.py show --case <case目录>
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

SCHEMA = "seep-migration/1"


# --------------------------------------------------------------------------- PE
def pe_info(path):
    """最小 PE 解析：machine / 节表 / 入口 RVA。不做任何依赖。"""
    if not path or not os.path.isfile(path):
        raise SystemExit(f"[ERR] 文件不存在：{path or '(空)'}")
    data = open(path, "rb").read()
    out = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if len(data) < 0x40:
        raise SystemExit("[ERR] 文件太小（%d B），不是有效 PE：%s" % (len(data), path))
    if data[:2] != b"MZ":
        out["format"] = "not-pe"
        return out, data
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        out["format"] = "not-pe"
        return out, data
    coff = e_lfanew + 4
    machine, nsect, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    pe32p = magic == 0x20B
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    image_base = struct.unpack_from("<Q" if pe32p else "<I", data, opt + 24)[0]
    sect_off = opt + opt_size
    sections = []
    for i in range(nsect):
        b = sect_off + i * 40
        name = data[b:b + 8].rstrip(b"\0").decode("latin-1", "replace")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", data, b + 8)
        sections.append({"name": name, "rva": va, "vsize": vsize,
                         "raw_ptr": rawptr, "raw_size": rawsize})
    out.update({
        "format": "PE32+" if pe32p else "PE32",
        "machine": {0x8664: "x64", 0x14C: "x86", 0xAA64: "arm64"}.get(machine, hex(machine)),
        "image_base": hex(image_base), "entry_rva": hex(entry), "sections": sections,
    })
    out["packer_hint"] = _packer_hint(sections, data)
    return out, data


def _entropy(b):
    if not b:
        return 0.0
    freq = [0] * 256
    for x in b:
        freq[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def _packer_hint(sections, data):
    """熵 + 节名启发式。只做提示，不下结论（真判壳走 seep_packer_detect）。"""
    hints = []
    for s in sections:
        raw = data[s["raw_ptr"]:s["raw_ptr"] + s["raw_size"]]
        e = _entropy(raw[:2_000_000])
        s["entropy"] = round(e, 2)
        if e > 7.5 and s["raw_size"] > 4096:
            hints.append(f"{s['name']} 熵 {e:.2f}")
    odd = [s["name"] for s in sections if s["name"] in
           (".aspack", "UPX0", "UPX1", ".themida", ".vmp0", ".vmp1", ".enigma1", ".ace0")]
    if odd:
        hints.append("可疑节名 " + "/".join(odd))
    if not hints:
        return "无明显加壳特征（熵/节名正常）"
    return "；".join(hints) + " —— 先过壳再追版"


def rva2off(info, rva):
    for s in info.get("sections") or []:
        if s["rva"] <= rva < s["rva"] + max(s["vsize"], s["raw_size"]):
            return s["raw_ptr"] + (rva - s["rva"])
    return None


def off2rva(info, off):
    for s in info["sections"]:
        if s["raw_ptr"] <= off < s["raw_ptr"] + s["raw_size"]:
            return s["rva"] + (off - s["raw_ptr"])
    return None


# ------------------------------------------------------------------ AOB / 滑窗
REL_OPS = (b"\xe8", b"\xe9", b"\xeb", b"\x74", b"\x75", b"\x0f")
REL_PREFIX = (b"\x48\x8d", b"\x4c\x8d", b"\x0f\x84", b"\x0f\x85", b"\x0f\x86", b"\x0f\x87")


def mask_rel(raw):
    """把相对寻址的操作数掩成 ??（重编译必漂，掩掉才能跨版本匹配）。"""
    out = list(raw)
    i = 0
    n = len(raw)
    while i < n - 1:
        two = bytes(raw[i:i + 2])
        if two in REL_PREFIX:                       # 48 8D 0D imm32 / 0F 84 rel32 …
            for k in range(i + 2, min(i + 6, n)):
                out[k] = None
            i += 6
            continue
        if bytes([raw[i]]) in (b"\xe8", b"\xe9") and i + 5 <= n:   # call/jmp rel32
            for k in range(i + 1, i + 5):
                out[k] = None
            i += 5
            continue
        if bytes([raw[i]]) in (b"\x74", b"\x75", b"\xeb") and i + 2 <= n:  # jcc rel8
            out[i + 1] = None
            i += 2
            continue
        i += 1
    return out


def aob_to_regex(aob):
    parts = aob.split()
    pat = b""
    for p in parts:
        if p in ("??", "?", "**"):
            pat += b"."
        else:
            pat += re.escape(bytes([int(p, 16)]))
    return re.compile(pat, re.DOTALL)


def aob_str_from_raw(raw, wild):
    out = []
    for i, b in enumerate(raw):
        out.append("??" if (wild and b is None) else f"{b:02X}")
    return " ".join(out)


def find_aob(data, aob, limit=50):
    rx = aob_to_regex(aob)
    hits = []
    for m in rx.finditer(data):
        hits.append(m.start())
        if len(hits) >= limit:
            break
    return hits


# ------------------------------------------------------------------- manifest
def case_version_dir(case, ver):
    return os.path.join(case, "versions", ver)


def manifest_path(case, ver):
    return os.path.join(case_version_dir(case, ver), "manifest.json")


def load_manifest(case, ver):
    p = manifest_path(case, ver)
    if not os.path.isfile(p):
        raise SystemExit(f"[ERR] 没有版本账：{p}\n先跑：migrate.py init --case {case} --exe <{ver} 的 exe> --version {ver}")
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save_manifest(case, ver, m):
    d = case_version_dir(case, ver)
    os.makedirs(d, exist_ok=True)
    with open(manifest_path(case, ver), "w", encoding="utf-8") as f:
        json.dump(m, f, ensure_ascii=False, indent=2)


# -------------------------------------------------------------------- commands
def cmd_fingerprint(a):
    info, _ = pe_info(a.exe)
    print(json.dumps(info, ensure_ascii=False, indent=2))


def cmd_init(a):
    info, _ = pe_info(a.exe)
    if info.get("format") not in ("PE32", "PE32+"):
        raise SystemExit(f"[ERR] 不是 PE 文件：{a.exe}（版本账目前只对 PE 有意义）")
    m = {
        "schema": SCHEMA, "version": a.version,
        "source_exe": os.path.abspath(a.exe),
        "binary": {k: info.get(k) for k in
                   ("sha256", "size", "format", "machine", "entry_rva", "packer_hint")},
        "sites": [], "ui": [], "license": [], "acceptance": [],
        "notes": "01 阶段每改一处就 add-site；02 阶段把替换的素材记到 ui[]；03 阶段把挂载点记到 license[]。",
    }
    save_manifest(a.case, a.version, m)
    print(f"[OK] 版本账已建：{manifest_path(a.case, a.version)}")
    print(f"     {m['binary']['format']} / {m['binary']['machine']} / {m['binary']['size']} B / 壳：{m['binary']['packer_hint']}")


def cmd_add_site(a):
    m = load_manifest(a.case, a.version)
    exe = a.exe or m.get("source_exe", "")
    if not exe or not os.path.isfile(exe):
        raise SystemExit(f"[ERR] 该版本账的 source_exe 已失效（{exe or '空'}）；用 --exe 显式指定")
    info, data = pe_info(exe)
    if info.get("format") not in ("PE32", "PE32+"):
        raise SystemExit(f"[ERR] 不是 PE 文件：{exe}")
    raw = str(a.rva).strip()
    try:
        rva = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 0)
    except ValueError:
        raise SystemExit(f"[ERR] RVA 不合法：{raw}（用 0x4f9f4 这种十六进制或十进制）")
    off = rva2off(info, rva)
    if off is None:
        raise SystemExit(f"[ERR] RVA {hex(rva)} 不在任何节里")
    raw = list(data[off:off + a.window])
    wild = mask_rel(raw) if a.wildcard_rel else raw
    aob = aob_str_from_raw(wild, a.wildcard_rel)
    hits = find_aob(data, aob)
    site = {
        "id": a.id, "sem": a.sem, "kind": a.kind, "aob": aob,
        "rva": hex(rva), "window": a.window,
        "patch": {"orig": a.orig or "", "new": a.new or ""},
        "verified_by": a.verified_by or "",
        "self_check": {"hits_in_own_binary": len(hits),
                       "unique": len(hits) == 1},
    }
    m["sites"] = [s for s in m["sites"] if s["id"] != a.id] + [site]
    save_manifest(a.case, a.version, m)
    flag = "OK" if len(hits) == 1 else f"注意：本体内命中 {len(hits)} 次（不唯一，追版时需靠上下文消歧）"
    print(f"[OK] 位点 {a.id} 已记账（{flag}）\n     AOB: {aob}")


def cmd_align(a):
    old = load_manifest(a.case, a.old)
    if not os.path.isfile(a.new):
        raise SystemExit(f"[ERR] 新版不存在：{a.new}")
    info, data = pe_info(a.new)
    results = []
    for s in old.get("sites", []):
        hits = find_aob(data, s["aob"])
        offs = [off2rva(info, h) for h in hits]
        if len(hits) == 1:
            status, new_rva = "unique", offs[0]
        elif len(hits) > 1:
            status, new_rva = "multi", offs[0]
        else:
            status, new_rva = "miss", None
        results.append({
            "id": s["id"], "sem": s.get("sem", ""), "status": status,
            "old_rva": s.get("rva"), "new_rva": (hex(new_rva) if new_rva is not None else None),
            "candidates": len(hits), "aob": s["aob"],
        })
    total = len(results)
    hit = sum(1 for r in results if r["status"] == "unique")
    out = {
        "schema": SCHEMA, "from": a.old, "to": a.new_version or "NEW",
        "new_binary": {k: info.get(k) for k in ("sha256", "size", "format", "machine", "packer_hint")},
        "results": results, "hit": hit, "total": total,
        "need_manual": [r["id"] for r in results if r["status"] != "unique"],
    }
    d = case_version_dir(a.case, a.new_version or "NEW")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "align.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print(f"[对齐] {a.old} → {out['to']}：{hit}/{total} 唯一命中")
    for r in results:
        tag = {"unique": "OK  ", "multi": "MULTI", "miss": "MISS "}[r["status"]]
        print(f"  [{tag}] {r['id']:<12} {r['old_rva']} → {r['new_rva'] or '-'}  ({r['sem']})")
    if out["need_manual"]:
        print(f"\n[!] 需人工定位 {len(out['need_manual'])} 处：{', '.join(out['need_manual'])}")
        print("    下一步：用字符串锚 / xref / 反编译特征回溯（见 04 技能「兜底三重」），"
              "定位后 add-site 重记，再 align 一次。")
    else:
        print("\n[OK] 全部唯一命中，可进入构建与验收。")
    return 0 if not out["need_manual"] else 1


def cmd_report(a):
    old = load_manifest(a.case, a.old)
    ver = a.new_version or "NEW"
    p = os.path.join(case_version_dir(a.case, ver), "align.json")
    if not os.path.isfile(p):
        raise SystemExit(f"[ERR] 先跑 align：{p} 不存在")
    al = json.load(open(p, encoding="utf-8"))
    lines = [f"# 追版差异报告：{al['from']} → {al['to']}", "",
             f"- 新版指纹：`{al['new_binary']['sha256'][:16]}…` / {al['new_binary']['size']} B / "
             f"{al['new_binary']['format']} {al['new_binary']['machine']}",
             f"- 壳线索：{al['new_binary']['packer_hint']}",
             f"- 位点命中：**{al['hit']}/{al['total']}**", "",
             "| 位点 | 语义 | 旧 RVA | 新 RVA | 状态 |", "|---|---|---|---|---|"]
    for r in al["results"]:
        lines.append(f"| `{r['id']}` | {r['sem']} | {r['old_rva']} | {r['new_rva'] or '—'} | {r['status']} |")
    if al["need_manual"]:
        lines += ["", f"## 需人工定位（{len(al['need_manual'])} 处）", "",
                  "按「兜底三重」逐条处理：唯一字符串锚 → xref 回溯 → 反编译特征比对。",
                  "定位后 `add-site` 重记并再 `align` 一次。", ""]
    else:
        lines += ["", "全部唯一命中。", ""]
    out = os.path.join(case_version_dir(a.case, ver), "migrate-report.md")
    open(out, "w", encoding="utf-8").write("\n".join(lines))
    print(f"[OK] 报告：{out}")


def cmd_show(a):
    m = load_manifest(a.case, a.version)
    b = m["binary"]
    print(f"{a.case} / {m['version']}  {b['format']} {b['machine']} {b['size']} B")
    print(f"  sha256: {b['sha256']}")
    print(f"  壳线索: {b['packer_hint']}")
    print(f"  位点 {len(m['sites'])} / UI {len(m['ui'])} / 授权 {len(m['license'])} / 验收 {len(m['acceptance'])}")
    for s in m["sites"]:
        print(f"    - {s['id']:<12} {s['rva']:<10} {s.get('sem','')}  aob={s['aob'][:44]}…")


def main():
    ap = argparse.ArgumentParser(description="跨版本追版引擎（Seep 第 04 阶段）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("fingerprint", help="打印版本指纹")
    p.add_argument("exe")
    p.set_defaults(func=cmd_fingerprint)

    p = sub.add_parser("init", help="建版本账")
    p.add_argument("--case", required=True)
    p.add_argument("--exe", required=True)
    p.add_argument("--version", required=True)
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("add-site", help="记账一个位点（含 AOB 自动提取）")
    p.add_argument("--case", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--exe", default="", help="可选：直接指定该版本 exe（默认读 manifest 的 source_exe）")
    p.add_argument("--id", required=True)
    p.add_argument("--sem", required=True)
    p.add_argument("--rva", required=True)
    p.add_argument("--window", type=int, default=16)
    p.add_argument("--wildcard-rel", action="store_true", help="把相对操作数掩成 ??（跨版本必用）")
    p.add_argument("--kind", default="code")
    p.add_argument("--orig", default="")
    p.add_argument("--new", default="")
    p.add_argument("--verified-by", default="")
    p.set_defaults(func=cmd_add_site)

    p = sub.add_parser("align", help="在新版二进制里对齐全部位点")
    p.add_argument("--case", required=True)
    p.add_argument("--old", required=True)
    p.add_argument("--new", required=True)
    p.add_argument("--new-version", default="")
    p.set_defaults(func=cmd_align)

    p = sub.add_parser("report", help="生成差异报告")
    p.add_argument("--case", required=True)
    p.add_argument("--old", required=True)
    p.add_argument("--new-version", default="")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("show", help="看版本账")
    p.add_argument("--case", required=True)
    p.add_argument("--version", required=True)
    p.set_defaults(func=cmd_show)

    a = ap.parse_args()
    rc = a.func(a)
    sys.exit(rc or 0)


if __name__ == "__main__":
    main()
