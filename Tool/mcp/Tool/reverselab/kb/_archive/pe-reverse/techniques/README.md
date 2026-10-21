# PE 逆向技术库 — 逐篇索引

Windows PE/原生二进制逆向技术库。共 **38 篇 technique + 2 篇 README**，按「先判型 → 再定位 → 后验证」组织。

## 使用顺序

```text
01 triage（哈希/壳/导入/字符串）
  → 02 PE 结构（头/节/TLS）
  → 03 静态（结构体/反汇编/断点/动态解析）
  → 04 动态（注入/Hook/内存/反调试/Procmon）
  → 05 脱壳（Dump/VMP）
  → 10 授权（分类/定位/算法/签名/公钥/自引用/跨版本）
  → 08 Patch / 06 IOC / 07 YARA-Sigma
  → 11 范式 / 13 报告 / 14 UI 验收 / 15 失败判据
```

## 目录

### 01-triage

- [`01-triage/01-aob-signature-scan.md`](01-triage/01-aob-signature-scan.md) — AOB 特征码扫描：模式、通配符、唯一性验证。

### 02-pe-structure

- [`02-pe-structure/01-pe-header-parsing.md`](../../../pe-reverse/techniques/02-pe-structure/01-pe-header-parsing.md) — PE 头、节表、导入/导出、数据目录解析。
- [`02-pe-structure/02-tls-callback-analysis.md`](../../../pe-reverse/techniques/02-pe-structure/02-tls-callback-analysis.md) — TLS Callback 早期执行链：定位、dump、与反调试/反 dump 的关系。

### 03-static-analysis

- [`03-static-analysis/01-struct-reconstruction.md`](../../../pe-reverse/techniques/03-static-analysis/01-struct-reconstruction.md) — 内存结构体逆向重建：偏移、字段语义、交叉验证。
- [`03-static-analysis/02-disasm-jit-asm.md`](03-static-analysis/02-disasm-jit-asm.md) — Zydis 反汇编与 Xbyak JIT 汇编。
- [`03-static-analysis/03-x64dbg-breakpoints.md`](03-static-analysis/03-x64dbg-breakpoints.md) — x64dbg 断点策略：软件/硬件/内存/条件断点。
- [`03-static-analysis/04-reclass-reconstruction.md`](03-static-analysis/04-reclass-reconstruction.md) — ReClass 结构体实时重建。
- [`03-static-analysis/05-dynamic-api-resolution.md`](03-static-analysis/05-dynamic-api-resolution.md) — 动态 API 解析链还原：`LoadLibrary/GetProcAddress`、哈希解析。

### 04-dynamic-analysis

- [`04-dynamic-analysis/01-dll-injection.md`](04-dynamic-analysis/01-dll-injection.md) — DLL 注入三模式：远程线程/APC/手动映射。
- [`04-dynamic-analysis/02-trampoline-detour.md`](04-dynamic-analysis/02-trampoline-detour.md) — Trampoline Hook：长度、重定位、栈对齐。
- [`04-dynamic-analysis/03-external-memory-rw.md`](04-dynamic-analysis/03-external-memory-rw.md) — 外部进程内存读写与 region 表。
- [`04-dynamic-analysis/04-naked-function-hook.md`](04-dynamic-analysis/04-naked-function-hook.md) — Naked 函数 Hook（内联汇编）。
- [`04-dynamic-analysis/05-anti-debug-bypass.md`](../../../pe-reverse/techniques/04-dynamic-analysis/05-anti-debug-bypass.md) — 反调试检测与绕过：PEB/DRx/时序/VEH。
- [`04-dynamic-analysis/06-manual-map-injection.md`](04-dynamic-analysis/06-manual-map-injection.md) — 手动映射 DLL 注入：重定位/导入/ TLS。
- [`04-dynamic-analysis/07-direct-syscall.md`](04-dynamic-analysis/07-direct-syscall.md) — Direct Syscall：绕过用户态 Hook。
- [`04-dynamic-analysis/08-procmon-patterns.md`](04-dynamic-analysis/08-procmon-patterns.md) — Procmon 行为监控与过滤。

### 05-crypto-unpack

- [`05-crypto-unpack/01-pe-unpack-dump.md`](../../../pe-reverse/techniques/05-crypto-unpack/01-pe-unpack-dump.md) — PE 脱壳/内存 Dump/IAT 修复 + TLS Callback 早期链。
- [`05-crypto-unpack/02-vmp-virtualization-analysis.md`](05-crypto-unpack/02-vmp-virtualization-analysis.md) — VMP 虚拟化原理与 VM Entry 定位。
- [`05-crypto-unpack/03-vmp-devirtualization-toolchain.md`](05-crypto-unpack/03-vmp-devirtualization-toolchain.md) — VMP 去虚拟化工具链。

### 06-ioc-extraction

- [`06-ioc-extraction/01-ioc-extraction.md`](06-ioc-extraction/01-ioc-extraction.md) — IOC 提取：网络/文件/注册表/互斥体。
- [`06-ioc-extraction/02-persistence-startup-chain.md`](06-ioc-extraction/02-persistence-startup-chain.md) — 持久化与启动链 IOC。

### 07-yara-sigma

- [`07-yara-sigma/01-yara-rule-writing.md`](07-yara-sigma/01-yara-rule-writing.md) — YARA 规则编写（逆向视角）。

### 08-patch

- [`08-patch/01-code-patching.md`](../../../pe-reverse/techniques/08-patch/01-code-patching.md) — 代码 Patch 与字节修改：等长/校验/回滚。

### 09-av-evasion

- [`09-av-evasion/01-ai-powered-evasion.md`](09-av-evasion/01-ai-powered-evasion.md) — Shellcode Patch/加密（静态特征破坏）。
- [`09-av-evasion/02-shellcode-obfuscation-and-loader.md`](09-av-evasion/02-shellcode-obfuscation-and-loader.md) — Shellcode 混淆 + Loader 模板。
- [`09-av-evasion/03-attack-chain-and-verification.md`](09-av-evasion/03-attack-chain-and-verification.md) — 攻击链组装与分段验证。
- [`09-av-evasion/04-compile-verify-and-mapping.md`](09-av-evasion/04-compile-verify-and-mapping.md) — 编译参数、免杀增强、验证闭环、MCP 映射。

### 10-license-keygen

- [`10-license-keygen/01-license-mechanism-classification.md`](10-license-keygen/01-license-mechanism-classification.md) — 许可证机制分类与攻击路径选择。
- [`10-license-keygen/02-validation-function-location.md`](../../../pe-reverse/techniques/10-license-keygen/02-validation-function-location.md) — 校验函数定位。
- [`10-license-keygen/03-key-algorithm-recovery.md`](10-license-keygen/03-key-algorithm-recovery.md) — 注册码算法还原与 keygen。
- [`10-license-keygen/04-signature-chain-pubkey-swap.md`](10-license-keygen/04-signature-chain-pubkey-swap.md) — 签名链校验与公钥替换。
- [`10-license-keygen/05-keygen-frida-verification-loop.md`](10-license-keygen/05-keygen-frida-verification-loop.md) — keygen 实机验证闭环。
- [`10-license-keygen/06-cloud-license-frida-hook.md`](10-license-keygen/06-cloud-license-frida-hook.md) — 云端授权识别与 Frida hook。
- [`10-license-keygen/07-self-referencing-signature-convergence.md`](10-license-keygen/07-self-referencing-signature-convergence.md) — 自引用签名与单步收敛。
- [`10-license-keygen/08-cross-version-aob-migration.md`](10-license-keygen/08-cross-version-aob-migration.md) — 跨版本 AOB 迁移与双态修补。
- [`10-license-keygen/09-runtime-callstack-locating.md`](10-license-keygen/09-runtime-callstack-locating.md) — 运行时调用栈定位。
- [`10-license-keygen/10-multiversion-signature-narrowing.md`](10-license-keygen/10-multiversion-signature-narrowing.md) — 多版本特征码收窄与数据段漂移。

### 11-project-paradigms

- [`11-project-paradigms/01-project-patterns-a-j.md`](11-project-paradigms/01-project-patterns-a-j.md) — 项目 A–J 十型：架构、脆弱性、穿透要点。
- [`11-project-paradigms/02-project-decision-and-stats.md`](11-project-paradigms/02-project-decision-and-stats.md) — 四步检测、D2.5 三问、统计表、C-1..C-9 复现路径。

### 13-report-template

- [`13-report-template/01-report-skeleton.md`](13-report-template/01-report-skeleton.md) — 12 节报告骨架、证据分级、交付前自检。

### 14-ui-verification

- [`14-ui-verification/01-ui-acceptance.md`](14-ui-verification/01-ui-acceptance.md) — 控件 dump、`EM_GETLINECOUNT` 行数判定、菜单驱动、失败判据。

### 15-decision

- `15-decision/failure-criteria.md` — 失败判据表与三条熔断。

### 攻击网

- `attack-network.md` — PE 分析全网图、关键枢纽、路径与节点执行口径。

## 文档质量基线

每篇至少含：入口信号、可复制命令、确认判据、失败判据、边界。记录证据时写哈希、文件偏移、VA/RVA、节区、API、字符串、断点命中、寄存器/栈参数、dump 路径、原始字节/新字节、行为差异。

## 标准工作流

```text
Hash/类型/保护 → 符号/函数恢复 → Ghidra/IDA 静态 → x64dbg/Frida/Procmon 动态
→ IOC/YARA/Sigma → Patch/Keygen → 行为验证 → 报告
```
