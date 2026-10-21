# Windows 逆向技术库

Windows PE/二进制逆向技术库。

## 入口

- [完整技术索引](techniques/README.md)
- Board：`boards/windows/README.md`
- 模板：`templates/notes/windows-pe-analysis.md`

## 分析链

```text
样本哈希/类型/保护 → 静态分析 → 动态验证 → 脱壳/配置恢复 → IOC → YARA/Sigma → Patch
```

## 目录

### 本地代码执行

- [`techniques/notepadpp-config-injection.md`](techniques/notepadpp-config-injection.md) — Notepad++ config.xml 命令注入（CVE-2026-48778）

### 2026 授权 / VM / 内核

- [`techniques/2026-vmp-ultralock.md`](techniques/2026-vmp-ultralock.md) — VMP 3.9.x UltraLock：ProductCode + RSA 绑定链
- [`techniques/2026-themida-vm-bypass.md`](techniques/2026-themida-vm-bypass.md) — Themida VM 函数级绕过：dispatch hook / 原生分支
- [`techniques/2026-cet-lacuna-pdata.md`](techniques/2026-cet-lacuna-pdata.md) — CET 影子栈 + `.pdata` 空洞假栈（LACUNA Chain）
- [`techniques/2026-win11-26h2-kernel.md`](techniques/2026-win11-26h2-kernel.md) — Win11 26H2：HVCI / KCET audit / KDP Pool
