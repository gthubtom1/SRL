# 05 UEFI / Secure Boot：从单个 `.efi` 到固件卷与变量

> 配套 `firmware-iot/SKILL.md`、`references/04-walkthrough-uefi-efi.md`、案例 `firmware-iot04`。
> **适用**：拿到 `.efi`/SPI flash dump/固件更新包，需要判断启动组件、固件卷、Secure Boot 策略。
> **不适用**：绕过他人设备的安全启动、植入 bootkit、未授权的持久化。本文只做只读解析与验证。
>
> 本域对 UEFI 的判据不是“能启动”，而是：**组件身份、固件卷结构、变量策略、签名链**四件事有证据。

## 0. 先分类：你拿到的是哪一层

| 输入 | 典型来源 | 能回答什么 | 不能回答什么 |
|---|---|---|---|
| 单个 `.efi` | `C:/Windows/System32/*.efi`、ESP、驱动包 | PE32+ 架构、subsystem、节熵、版本/导入、是否 UEFI 组件 | 固件卷布局、Secure Boot 是否信任它 |
| 厂商固件更新包 | 官网 `.exe/.cab/.bin` | 外层容器、内嵌 FV/PE、版本 | 设备实际运行的镜像 |
| SPI flash dump | `flashrom`/编程器 | 完整 FV、NVRAM 变量、ME/EC 区、签名链 | 运行时内存状态、TPM 事件 |
| UEFI 变量导出 | `chipsec`/OS API | PK/KEK/db/dbx、BootOrder、SecureBoot | 变量是否被运行时篡改 |
| TPM event log | Linux `tpm2_eventlog`、Windows | PCR 度量链、启动组件哈希 | 组件是否恶意（需与已知哈希比对） |

固定坐标：`sha256`、大小、来源、读取命令、是否含 OOB/填充。缺一项就不入结论。

## 1. PE32+ / TE 镜像的最小解析

UEFI 应用与 DXE 驱动通常是 PE32+，少数为 TE（`VZ` 头）。先看：

```bash
file SecConfig.efi
python Tool/skill/firmware-iot/scripts/fw-repro.py --file SecConfig.efi --json
objdump -h SecConfig.efi | head -30
strings -a -n 8 SecConfig.efi | grep -Ei 'EFI_|SecureBoot|dbx|PK|KEK|LoadImage|gBS' | head -40
```

`fw-repro` 的 `pe` 段给出：

```json
{"machine":"x86-64","subsystem":"Windows boot application (UEFI-era)",
 "is_uefi":true,"sections":[{"name":".text","entropy":6.491}, ...]}
```

判读要点：

- `subsystem` 10/11/12/13 是经典 EFI application/boot service/runtime/ROM；
  16 常见于 Windows boot application，仍可能是 UEFI 时代组件，需结合节名与字符串判断。
- 节名 `TRANSIT`/`PAGER32C`/`PAGE` 常见于 Windows boot 组件；`.text` 高熵不一定是壳，
  可能只是压缩/优化后的代码。
- `is_uefi` 是**线索**，不是“可信/不可信”的结论。

TE 镜像：头为 `VZ`（`0x5A56`），字段为 `Machine`/`NumberOfSections`/`Subsystem`/
`AddressOfEntryPoint`/`BaseOfCode`，后接 40 字节节表。没有 MZ/PE 签名，
不要因为 `file` 不识别就判“不是固件”。

## 2. 固件卷（FV）与 FFS

SPI dump 里通常有多个 FV，FV 头以 `_FVH` 结尾签名（offset 0x28 起），
内部是 FFS 文件（GUID + 头 + 节），节里可能是 PE32/TE、raw、UI、version。

```bash
# 只读解析，不改镜像
python -m uefi_firmware --help          # 若已安装
uefi-firmware-parser -b -o work/fv fw.bin
# 或使用 UEFITool（GUI/CLI）打开 fw.bin，导出 FV/FFS/PE
```

机检判据：

1. 至少一个 FV 头 `_FVH` 可解析，长度字段与文件边界自洽；
2. FFS 文件 GUID 可读，PE32/TE 节能被 `fw-repro`/`objdump` 识别；
3. 关键模块（SEC/PEI/DXE/BDS、Setup、SecureBoot）能定位到 FV/文件偏移；
4. 若厂商用压缩 FV，需先解压（LZMA/Tiano），解压后重复 1–3。

失败判据：只有 `_FVH` 字符串、没有可解析头/长度；或 FFS 全为 0xFF（空片）。
此时先确认 dump 是否含 OOB/是否被截断，不要反复换解析器。

## 3. Secure Boot：变量与签名链

Secure Boot 的核心变量：

| 变量 | 作用 | 只读检查 | 常见误判 |
|---|---|---|---|
| `PK` | Platform Key，根信任 | `chipsec_util uefi var-list` / `efi-reader` | 有 PK ≠ 已开启 Secure Boot |
| `KEK` | Key Exchange Key，更新 db/dbx | 读 `EFI_SIGNATURE_LIST` | KEK 为空不等于无保护 |
| `db` | 允许的签名/哈希 | 列出证书与 SHA256 | db 有厂商证书 ≠ 只允许厂商 |
| `dbx` | 吊销的签名/哈希 | 查目标 PE 的 SHA256 是否在列 | dbx 未列 ≠ 一定可加载（还有自定义策略） |
| `SecureBoot` | 运行时开关 | `chipsec_util uefi var-read SecureBoot` | 变量为 1 仍可能有 shim/自定义校验 |
| `SetupMode` | 是否允许改 PK | 读变量 | SetupMode=0 不代表 db 不可被漏洞改 |

签名链检查顺序：

1. 计算目标 PE 的 SHA256，查 `dbx` 是否有相同哈希；
2. 查 `db` 里证书的公钥是否能验证该 PE 的 Authenticode/PKCS#7 签名；
3. 查 `KEK` 是否能更新 `db`，`PK` 是否能更新 `KEK`；
4. 若使用 shim，检查 shim 的 `MokList`/`MokListX`（机器所有者密钥）与 `shim_lock` 协议；
5. 记录变量属性（`NV`/`BS`/`RT`、时间戳、认证头），不要把“读到了”当“策略正确”。

只读命令示例（需管理员/授权，先备份变量）：

```bash
chipsec_util uefi var-list
chipsec_util uefi var-read PK work/vars/PK.bin
chipsec_util uefi var-read dbx work/vars/dbx.bin
chipsec_util spi dump work/spi.bin       # 只读；确认工具版本与芯片支持
```

注意：`chipsec` 的 SPI 读写能力取决于平台与驱动；**默认只 dump，不 write**。
写变量/写 flash 只在单独授权与可恢复设备上进行。

## 4. TPM 与 measured boot

- PCR[0] 固件代码、PCR[2] 固件配置/option ROM、PCR[4] boot manager、
  PCR[7] Secure Boot 策略、PCR[11] shim/GRUB 等（具体映射随实现变化）。
- 用 `tpm2_eventlog`/`Get-WinEvent` 读 event log，核对每个 EV_EFI_BOOT_SERVICES_APPLICATION
  的哈希是否等于你分析的 PE。
- 判据：event log 的哈希链能重放到当前 PCR 值；否则“度量”不成立。
- 误报：TPM 未启用、event log 被清空、PCR 被 reset 都会导致对不上；先确认状态再下结论。

## 5. 固件更新包与回滚保护

厂商更新包常见结构：`exe` 自解压 → `cab`/`zip` → 厂商头 → FV/EC/ME 镜像。

```bash
7z l update.exe
7z x update.exe -owork/update
binwalk work/update/*.bin | head -40
```

检查点：

- 包内是否有版本号/日期/机型白名单；与设备当前版本比对；
- 是否有签名文件（`.sig`/`.p7b`/`.cat`）与校验逻辑；
- 是否允许降级（anti-rollback）：看更新器里的版本比较与 `dbx`/SVN 字段；
- 是否对 FV 做哈希/签名：只改 rootfs 不改签名通常会被拒。

失败判据：只有外层解压成功、没有内层镜像或签名；或版本比较逻辑不可见。
此时不要声称“可降级/可持久化”。

## 6. 判据表（UEFI 专用）

| 场景 | 判据（可机检） | 证据形态 | 误报风险 |
|---|---|---|---|
| 组件识别 | PE32+/TE 头可解析；machine/subsystem/节表自洽 | `fw-repro` JSON + `objdump -h` | `.efi` 扩展名不等于 UEFI；subsystem 16 需结合上下文 |
| 固件卷 | `_FVH` 头长度自洽；FFS GUID/节可解析 | 解析器输出 + 偏移 | 压缩 FV 未解压时全是乱码 |
| Secure Boot 状态 | `SecureBoot`/`SetupMode` 变量值 + 变量属性 | 变量二进制 + 属性 | 变量为 1 不等于策略严格 |
| dbx 覆盖 | 目标 PE SHA256 在 dbx 的 EFI_SIGNATURE_LIST 中 | 哈希 + 解析结果 | 不在 dbx 不等于可加载 |
| 签名验证 | db/KEK/PK 链能验证 PE 的 PKCS#7 | `openssl`/解析器输出 | 自签名/测试证书易误判 |
| 度量启动 | event log 哈希链可重放到 PCR | `tpm2_eventlog` 输出 | TPM 未启用/日志清空会假失败 |

## 7. 失败判据（转哪条）

- 只有 `.efi`、没有 FV/变量 → 只能做组件级 E0/E1，转 `04-walkthrough-uefi-efi.md` 的静态路线；
  不要写“Secure Boot 可绕过”。
- SPI dump 解析不出 FV → 先确认芯片/电压/是否含 OOB，再换 `chipsec`/`uefi-firmware-parser`/UEFITool；
  不要反复 `binwalk -e`。
- 变量读不到 → 检查权限、驱动、是否虚拟机；缺工具走 `blocked_at: "tool-missing"`。
- 签名链断在中间（缺 KEK/中间证书） → 记录缺口，不要用“自签名”补结论。
- 需要写 flash/改变量才能继续 → 停止；先备份并确认恢复路径。

## 8. 边界

- 仅对自有或明确授权的设备/镜像操作；不提供绕过他人 Secure Boot、植入 bootkit 的步骤。
- UEFI 分析默认只读：dump、解析、比对；写操作单独授权。
- 单个 PE 的节熵/字符串不能证明启动链可信或不可信；必须回到变量、签名与度量证据。
- 本文件不替代芯片厂商文档；FV/变量格式随版本变化，以实际解析结果为准。
