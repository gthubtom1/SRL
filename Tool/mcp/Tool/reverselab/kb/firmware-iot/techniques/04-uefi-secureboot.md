# 04 UEFI 与 Secure Boot 速查

> 目标：从单个 `.efi` 或 SPI dump 出发，判断组件身份、固件卷、Secure Boot 变量与签名链。
> 配套：`references/05-uefi-and-secure-boot.md`、`references/04-walkthrough-uefi-efi.md`。
> 只读分析；写 flash/改变量必须单独授权并先备份。

## 0. 入口信号

- 目标文件是 `.efi`/`.rom`/`.cap`，或 SPI dump 里出现 `_FVH`、`VZ`、`PE\0\0`。
- 设备/主机启用 Secure Boot，或需要判断某个 boot app 是否被 db/dbx 覆盖。
- 更新包内出现 `FV`、`DXE`、`PEI`、`Setup`、`SecureBoot` 字样。

## 1. 单个 PE/TE 组件

```bash
file SecConfig.efi
python Tool/skill/firmware-iot/scripts/fw-repro.py --file SecConfig.efi --json
objdump -h SecConfig.efi | head -30
strings -a -n 8 SecConfig.efi | grep -Ei 'EFI_|SecureBoot|dbx|LoadImage|gBS' | head -40
```

判据：machine/subsystem/节表可解析；UEFI 线索（`EFI_BOOT_SERVICES`/`LoadImage` 等）≥2 或
subsystem 10–13。TE 镜像看 `VZ` 头与节表，不要求 `MZ`。
失败判据：头损坏/加壳；`file` 不识别且无 `VZ` → 记未识别，不要猜。

## 2. 固件卷（FV）与 FFS

```bash
uefi-firmware-parser -b -o work/fv fw.bin
# 或 UEFITool 打开 fw.bin 导出 FV/FFS
grep -abo '_FVH' fw.bin
```

判据：FV 头长度自洽；FFS GUID/节可读；关键模块能定位到偏移。
失败判据：只有 `_FVH` 字符串、无有效头 → dump 截断/OOB/压缩 FV；先解压或重 dump。

## 3. Secure Boot 变量

| 变量 | 作用 | 检查点 |
|---|---|---|
| `PK` | 根信任 | 是否存在、是否可更新 KEK |
| `KEK` | 更新 db/dbx | 证书/哈希列表 |
| `db` | 允许的签名/哈希 | 目标 PE 的 SHA256/证书是否在列 |
| `dbx` | 吊销列表 | 目标 PE 哈希是否被禁 |
| `SecureBoot` | 开关 | 值 + 变量属性 |
| `SetupMode` | 是否允许改 PK | 值 |

```bash
chipsec_util uefi var-list
chipsec_util uefi var-read dbx work/vars/dbx.bin
chipsec_util spi dump work/spi.bin      # 只读；确认平台支持
```

判据：变量可解析为 `EFI_SIGNATURE_LIST`；目标 PE 的哈希/证书与 db/dbx 比对有明确结论；
event log 能重放到 PCR（TPM 场景）。
失败判据：变量读不到（权限/驱动/虚拟机）；签名链缺中间证书；只有单 PE 没有变量 → 只能 E0/E1。

## 4. 失败判据（本页）

| 现象 | 判定 | 改走哪条 |
|---|---|---|
| 只有 `.efi`，无 FV/变量 | 组件级证据 | 走 `references/04-walkthrough-uefi-efi.md` 静态路线 |
| `_FVH` 解析失败 | 截断/压缩/OOB | 重 dump、解压 FV、换解析器 |
| dbx 里没有目标哈希 | 不能证明可加载 | 继续查 db 证书与自定义策略 |
| `SecureBoot=1` | 只说明开关 | 还要看 db/dbx/KEK 与 shim/MOK |
| 需要写变量才能继续 | 超出只读范围 | 停止；申请授权并准备恢复 |

## 5. 边界

- 不提供绕过他人 Secure Boot、植入 bootkit 的步骤。
- 变量/固件卷格式随厂商/版本变化，以实际解析为准。
- 单 PE 的节熵/字符串不能证明启动链可信或不可信。
