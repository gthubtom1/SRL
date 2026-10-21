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

> 本篇：编译命令 / 免杀增强 / 验证闭环 / MCP 映射。前篇：`03-attack-chain-and-verification.md`。

## 编译命令参考

| 编译器 | 命令 |
|--------|------|
| MinGW | `x86_64-w64-mingw32-gcc -o out.exe loader.c -mwindows -Os -static -s -lrpcrt4` |
| MSVC | `cl.exe /MT /O2 /GS- /GL loader.c /link /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup rpcrt4.lib` |
| Clang | `clang -target x86_64-w64-mingw32 -o out.exe loader.c -mwindows -Os -static -s -lrpcrt4` |

关键编译选项：

| 选项 | 作用 |
|------|------|
| `-mwindows` / `/SUBSYSTEM:WINDOWS` | 无控制台窗口 |
| `-Os` / `/O2` | 优化体积/速度，破坏调试符号 |
| `-static` / `/MT` | 静态链接 CRT，避免 DLL 依赖 |
| `-s` | Strip 符号表 |
| `-fvisibility=hidden` | 隐藏 ELF 符号 (非 PE) |
| `/GS-` | 禁用安全检查 (/GS 的反向，降低特征) |

---

## 免杀效果增强

### 代码层面
- **变量名随机化**：每次生成替换所有变量名为随机字符串
- **控制流平坦化**：用 switch-case + indirect jump 替代直连逻辑流
- **字符串全加密**：`"ntdll.dll"` 等敏感字符串用 XOR 存储，运行时解密
- **API 哈希调用**：用 djb2 / crc32 哈希查找 API 地址，而非明文 `GetProcAddress`

### 二进制层面
- **资源文件**：添加合法图标/UAC manifest/版本信息，伪装正常程序
- **数字签名伪造**：从合法文件复制 Authenticode 签名区
- **节区合并**：`.text` 和 `.rdata` 合并，减少节数量

---

## 证据与验证闭环

每步完成标准：

| 步骤 | 验证方法 | 通过标准 |
|------|---------|---------|
| Patch | `strings payload_patched.bin \| grep -c <特征字符串>` | 特征字符串减少 >50% |
| Encrypt | `python -c "print(all(b != 0xfc for b in open('payload_encrypted.bin','rb').read()))"` | 无原始 msfvenom stub 特征 (0xfc 等) |
| Obfuscate | 检查生成的 `.c` 文件无可直接 grep 到的 shellcode 字节 | 杀软静态扫描不报毒 |
| 编译 | `hash_file` 每次生成 hash 不同 | 两次编译同一源码 hash 不同 |
| 免杀 | VT+本地杀软实机测试 | WD/火绒/360 不报毒, VT ≤5 检出 |
| 执行 | 沙箱中实际运行, 确认 C2 上线 | msfconsole 收到 session |

## MCP 工具映射

| 步骤 | MCP 工具 | 说明 |
|------|---------|------|
| 生成 shellcode | `run_ctf_tool "msfvenom ..."` | 或直接调 msfvenom |
| 分析原始 PE 结构 | `triage_pe` | 获取节区/导入表 |
| Patch 字节 | `patch_pe_bytes` | 修改 shellcode 中已知特征字节 |
| 静态分析 Loader | `ghidra_headless_analyze` | 验证 Loader 没有明显特征 |
| 提取 IOC | `extract_iocs_from_summary` | 提取编译后 PE 的 IOC |
| Hash 验证 | `hash_file` | 验证每次生成的 hash 不同 |
| YARA 自检 | `make_yara_stub` | 对自己生成的 PE 写 YARA 规则自检 |

## 文档元信息

- **状态**: draft
- **复审轮次**: 1
- **覆盖**: shellcode 全生命周期 (生成→处理→加载→执行)
- **落地形态**: loader / shellcode / patch / 脚本化执行链
