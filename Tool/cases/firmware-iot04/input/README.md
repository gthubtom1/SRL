# 输入来源（real）

- 文件：`SecConfig.efi`
- 本机来源：`C:/Windows/System32/SecConfig.efi`
- 类型：Windows UEFI 时代启动应用（PE32+ x86-64，9 sections）
- SHA256：`820a15d9746c2877484f203f1d4678001d9a60173b3bfd6bf05884d41bba623e`
- 大小：1346960 字节
- 复制命令：`cp <source> Tool/cases/firmware-iot04/input/SecConfig.efi`
- 授权：本机系统文件，只读静态分析；未读取固件卷/变量，未修改系统。

复现产物：

```bash
python Tool/scripts/fw-triage.py --file Tool/cases/firmware-iot04/input/SecConfig.efi --json > artifacts/triage.json
python Tool/skill/firmware-iot/scripts/fw-repro.py --file Tool/cases/firmware-iot04/input/SecConfig.efi --out-dir work/fw-case04 --json > artifacts/repro.json
```
