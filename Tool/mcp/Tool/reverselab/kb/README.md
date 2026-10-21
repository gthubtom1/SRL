# Knowledge Base

> 本文件是 KB 根索引：**每个文件至少被这里引用一次**（门禁 `domain-gate.py --links` 会验）。
> 分域板（board）见下表；根目录散篇按前缀分组。新增散篇必须加进这里，否则算孤儿。

| Area | Path | Content |
|---|---|---|
| Web CTF | [ctf-website](ctf-website/README.md) | Web 攻击全表面 + 云原生 + CVE |
| Web Pentest | [web-pentest](web-pentest/README.md) | 现网 Web/API 验证（六类打法 + 失败判据） |
| Pwn / Crypto | [pwn-crypto](pwn-crypto/README.md) | 保护位→打法矩阵 / 密码学攻击 |
| Firmware / IoT | [firmware-iot](firmware-iot/README.md) | 固件提取 / 仿真 / 硬件接口 |
| AD / Cloud | [ad-cloud](ad-cloud/README.md) | Kerberos / ADCS / K8s / 云凭据 |
| Protocol | [protocol](protocol/README.md) | 分帧 / 状态机 / 重放构造 |
| Plugin | [plugin](plugin/README.md) | 浏览器扩展 / asar / BepInEx / VSIX |
| Forensics | [forensics](forensics/README.md) | 内存 / 磁盘 / iOS·macOS / 游戏客户端 |
| Malware | [malware-analysis](malware-analysis/README.md) | 行为时间线 / IOC / YARA·Sigma |
| Supply Chain | [supply-chain](supply-chain/README.md) | SBOM / 依赖投毒 / CI 权限 / 签名 |
| APK Reverse | [apk-reverse](apk-reverse/README.md) | APK/DEX/SO 逆向 |
| PE Reverse | [pe-reverse](pe-reverse/README.md) | 反汇编 / 注入 / 脱壳 / 授权 / 补丁 |
| General | [general](general/README.md) | 密码学 / 协议 / 内核 / 方法论 |
| Windows | [windows](windows/README.md) | Windows 运行时与工具链 |

## 根目录：AI 复盘

- [ai-findings](ai-findings/README.md) — 可复用的发现/坑点/打法，不是命令流水账

## 根目录：现场日志（field journal）

- [field_journal_2026-05-15-cellular-pro-mumu-ksad-fragment-fix.md](field_journal_2026-05-15-cellular-pro-mumu-ksad-fragment-fix.md)
- [field_journal_2026-05-15_lumine-go-reverse.md](field_journal_2026-05-15_lumine-go-reverse.md) — lumine v0.9.1 — Go TLS 分片代理逆向
- [field_journal_2026-05-16_pentest-personalblog-fun-mass-assignment.md](field_journal_2026-05-16_pentest-personalblog-fun-mass-assignment.md) — {target_domain} 渗透测试记录
- [field_journal_2026-05-17_pentest-vue-spa-actuator-leak.md](field_journal_2026-05-17_pentest-vue-spa-actuator-leak.md) — Field Journal — Vue SPA + Spring Boot 后台站点 Web 渗透
- [field_journal_2026-05-25_pentest-cf-access-sibling-subdomain-cookie-poisoning.md](field_journal_2026-05-25_pentest-cf-access-sibling-subdomain-cookie-poisoning.md) — 2026-05-25 CF Access 兄弟子域配置错误 → 跨子域 Cookie 投毒 + Session Fixation
- [field_journal_2026-05-26_pentest-newapi-rate-limit-bypass.md](field_journal_2026-05-26_pentest-newapi-rate-limit-bypass.md) — 2026-05-26 CTF Web 网关限速绕过与信息暴露
- [field_journal_2026-06-29_burp-mcp-full-test-and-fix.md](field_journal_2026-06-29_burp-mcp-full-test-and-fix.md) — 2026-06-29 burp-mcp-full 全量测试与修复
- [field_journal_2026-07-05_dsl-vm-captcha-reverse.md](field_journal_2026-07-05_dsl-vm-captcha-reverse.md) — 验证码系统完整逆向分析
- [field_journal_2026-07-14_android-arm64-self-extract-source-recovery.md](field_journal_2026-07-14_android-arm64-self-extract-source-recovery.md) — 2026-07-14 Android ARM64 自解压程序源码恢复
- [field_journal_2026-07-18_gin-juice-client-friction.md](field_journal_2026-07-18_gin-juice-client-friction.md) — 现代 Web 靶场摩擦 → skill 加固
- [field_journal_2026-07-20_reverse-toolchain-windows-bootstrap.md](field_journal_2026-07-20_reverse-toolchain-windows-bootstrap.md) — 2026-07-20 Windows 逆向工具链完整自举
- [field_journal_2026-07-22_electron-bytenode-privileged-update-chain.md](field_journal_2026-07-22_electron-bytenode-privileged-update-chain.md) — 2026-07-22 Electron Bytenode 特权更新链分析
- [field_journal_2026-08-01_nextjs-cdk-contract-faithful-local-reconstruction.md](field_journal_2026-08-01_nextjs-cdk-contract-faithful-local-reconstruction.md) — Next.js CDK 订单中心的契约保真本地重建
- [field_journal_2026-08-01_pentest-encryption-oracle-public-template-sql-admin-takeover.md](field_journal_2026-08-01_pentest-encryption-oracle-public-template-sql-admin-takeover.md) — 2026-08-01 通用加密 oracle 与公开模板解析器组合成 SQL 管理员接管
- [field_journal_2026-08-06_cortex-m-msc-firmware-self-keyed-rotate-xor.md](field_journal_2026-08-06_cortex-m-msc-firmware-self-keyed-rotate-xor.md) — 2026-08-06 Cortex-M 虚拟磁盘升级固件的自带掩码旋转/XOR 封装
- [field_journal_2026-08-08_client-neutral-structured-routing-pr-integration.md](field_journal_2026-08-08_client-neutral-structured-routing-pr-integration.md) — 2026-08-08 平台无关结构化路由 PR 集成
- [field_journal_2026-08-08_pr-value-triage-and-safe-integration.md](field_journal_2026-08-08_pr-value-triage-and-safe-integration.md) — 2026-08-08 开放 PR 价值分级与安全集成
- [field_journal_2026-08-14_windows-powershell-native-exit-code-pr-review.md](field_journal_2026-08-14_windows-powershell-native-exit-code-pr-review.md) — 2026-08-14 Windows PowerShell 原生命令退出码 PR 审查
- [field_journal_2026-08-17_tool-index-r2-fallback-powershell-pwsh-host-fix.md](field_journal_2026-08-17_tool-index-r2-fallback-powershell-pwsh-host-fix.md) — 2026-08-17 reverse-skill
- [field_journal_2026-08-20_apk-flutter-banner-ad-removal.md](field_journal_2026-08-20_apk-flutter-banner-ad-removal.md) — 2026-08-20 Flutter APK 服务端驱动广告去除（第三方仿冒包）
- [field_journal_2026-09-03_issue-pr-security-boundary-integration.md](field_journal_2026-09-03_issue-pr-security-boundary-integration.md) — 2026-09-03 多 Issue/PR 安全边界集成
- [field_journal_CONTRIBUTE-BACK.md](field_journal_CONTRIBUTE-BACK.md) — 社区进化：向主仓库贡献经验
- [field_journal__index.md](field_journal__index.md) — 项目经验索引
- [field_journal__template.md](field_journal__template.md) — [日期] [项目简称]
- [field_journal_anonymization.md](field_journal_anonymization.md) — Field-Journal 脱敏规范
- [field_journal_precedent-auth.md](field_journal_precedent-auth.md) — 授权预声明 — 减少 disclaimer 噪音，不能代替 scope.md
- [field_journal_precedent-pentest.md](field_journal_precedent-pentest.md) — 渗透测试操作先例库
- [field_journal_precedent-reverse.md](field_journal_precedent-reverse.md) — 逆向工程操作先例库
- [field_journal_seed-001_elf-packed-loader.md](field_journal_seed-001_elf-packed-loader.md) — [种子] ELF 自解压加载器逆向
- [field_journal_seed-002_go-malware-stripped.md](field_journal_seed-002_go-malware-stripped.md) — [种子] Go 恶意软件逆向（stripped + Garble）
- [field_journal_seed-003_web-api-auth-bypass.md](field_journal_seed-003_web-api-auth-bypass.md) — [种子] Web API 未授权访问 + IDOR
- [field_journal_seed-004_js-sign-webpack.md](field_journal_seed-004_js-sign-webpack.md) — [种子] JS 签名逆向（Webpack + AES + 时间戳）
- [field_journal_seed-005_ad-certipy-esc1.md](field_journal_seed-005_ad-certipy-esc1.md) — [2026-03] AD CS ESC1 证书模板滥用 → 域管权限
- [field_journal_seed-006_ssrf-cloud-metadata.md](field_journal_seed-006_ssrf-cloud-metadata.md) — [2026-02] SSRF → 云元数据 → AK/SK → OSS 全量数据
- [field_journal_seed-007_ntlm-relay-coercer.md](field_journal_seed-007_ntlm-relay-coercer.md) — [2026-04] NTLM Relay + Coercer → 域管权限（无需密码）
- [field_journal_seed-008_apk-okhttp-ssl-pin-bypass.md](field_journal_seed-008_apk-okhttp-ssl-pin-bypass.md) — [种子] APK Frida 绕过 OkHttp SSL Pinning
- [field_journal_seed-009_ios-jailbreak-detect-bypass.md](field_journal_seed-009_ios-jailbreak-detect-bypass.md) — [种子] iOS 越狱检测绕过 + 抓包
- [field_journal_seed-010_ctf-pwn-rop-x64.md](field_journal_seed-010_ctf-pwn-rop-x64.md) — [种子] CTF Pwn — x64 栈溢出 + ROP 链调用 system
- [field_journal_seed-011_pcap-protocol-reverse.md](field_journal_seed-011_pcap-protocol-reverse.md) — [种子] PCAP 自定义二进制协议逆向
- [field_journal_seed-012_log4shell-jndi-rce.md](field_journal_seed-012_log4shell-jndi-rce.md) — [种子] Log4Shell（CVE-2021-44228）JNDI 注入打 RCE
- [field_journal_seed-013_kerberoasting-spn.md](field_journal_seed-013_kerberoasting-spn.md) — [种子] Kerberoasting → 离线破解 → DA
- [field_journal_seed-014_unity-il2cpp-reverse.md](field_journal_seed-014_unity-il2cpp-reverse.md) — [种子] Unity IL2CPP 游戏逆向 → 还原元数据 + 修改逻辑
- [field_journal_seed-015_iot-firmware-uart.md](field_journal_seed-015_iot-firmware-uart.md) — [种子] IoT 路由器固件提取 + UART 串口拿 root
- [field_journal_seed-016_k8s-container-escape.md](field_journal_seed-016_k8s-container-escape.md) — [种子] 容器逃逸 → 拿宿主机 root（cap_sys_admin / 特权容器 / docker.sock）
- [field_journal_seed-017_xxe-oob-exfil.md](field_journal_seed-017_xxe-oob-exfil.md) — [种子] XXE 盲注 OOB → 外带 /etc/passwd 与内网探测

## 根目录：逆向模式库（re_pattern）

- [re_pattern_SKILL.md](re_pattern_SKILL.md) — Reverse Engineering
- [re_pattern_anti-analysis.md](re_pattern_anti-analysis.md) — CTF Reverse - Anti-Analysis Techniques & Bypasses
- [re_pattern_awesome-re-resources.md](re_pattern_awesome-re-resources.md) — 逆向工程参考资源汇总
- [re_pattern_crypto-decode-tools.md](re_pattern_crypto-decode-tools.md) — 加解密 / 编解码工具速查
- [re_pattern_elf-analysis.md](re_pattern_elf-analysis.md) — ELF 二进制深度分析参考
- [re_pattern_field-notes.md](re_pattern_field-notes.md) — Reverse Engineering Field Notes
- [re_pattern_go-reverse.md](re_pattern_go-reverse.md) — Go 二进制逆向指南
- [re_pattern_kernel-driver-reverse.md](re_pattern_kernel-driver-reverse.md) — 内核驱动逆向参考
- [re_pattern_languages-compiled.md](re_pattern_languages-compiled.md) — CTF Reverse - Compiled Language Reversing (Go, Rust)
- [re_pattern_languages-platforms.md](re_pattern_languages-platforms.md) — CTF Reverse - Platform & Framework-Specific Techniques
- [re_pattern_languages.md](re_pattern_languages.md) — CTF Reverse - Language-Specific Techniques
- [re_pattern_patterns-ctf-2.md](re_pattern_patterns-ctf-2.md) — CTF Reverse - Competition-Specific Patterns (Part 2)
- [re_pattern_patterns-ctf-3.md](re_pattern_patterns-ctf-3.md) — CTF Reverse - Competition-Specific Patterns (Part 3)
- [re_pattern_patterns-ctf.md](re_pattern_patterns-ctf.md) — CTF Reverse - Competition-Specific Patterns (Part 1)
- [re_pattern_patterns.md](re_pattern_patterns.md) — CTF Reverse - Patterns & Techniques
- [re_pattern_platforms-hardware.md](re_pattern_platforms-hardware.md) — CTF Reverse - Hardware and Advanced Architecture Reversing
- [re_pattern_platforms.md](re_pattern_platforms.md) — CTF Reverse - Platform-Specific Reversing
- [re_pattern_tools-advanced.md](re_pattern_tools-advanced.md) — CTF Reverse - Advanced Tools & Deobfuscation
- [re_pattern_tools-dynamic.md](re_pattern_tools-dynamic.md) — CTF Reverse - Dynamic Analysis Tools
- [re_pattern_tools.md](re_pattern_tools.md) — CTF Reverse - Tools Reference

## 根目录：其它

- [AI-USAGE.md](AI-USAGE.md) — Knowledge Base AI Usage
- [edr_bypass_SKILL.md](edr_bypass_SKILL.md) — EDR 绕过：从防御方实现逆向到红队绕过
- [js_reverse_SKILL.md](js_reverse_SKILL.md) — MCP 前端 JS 逆向作业规范
- [mumu_crash_guard_and_hotpatch_spec.md](mumu_crash_guard_and_hotpatch_spec.md) — Windows 客户端复杂宿主内存热补丁与崩溃防御规范 (MuMu 实战提炼)

## 使用纪律

1. 先查本索引，再 `seep_kb_search`；两者都空才允许从零推理。
2. 结论必须落到"判据/失败判据"，不落"感觉"。
