# 05 UEFI / Secure Boot：从单个 `.efi` 到固件卷与变量

> 配套 `firmware-iot/SKILL.md`、`references/04-walkthrough-uefi-efi.md`、案例 `firmware-iot04`。
> **范围**：拿到 `.efi`/SPI flash dump/固件更新包，需要判断启动组件、固件卷、Secure Boot 策略。
> 范围：本文只做只读解析与验证（组件身份/固件卷/变量策略/签名链）；启动链改造与持久化放进授权任务书的单独条目。
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

- 只在自有或明确授权的设备/镜像上操作；遇到 Secure Boot 校验，按 `01-criteria.md` 记录策略与签名链后收束。
- UEFI 分析默认只读：dump、解析、比对；写操作单独授权。
- 单个 PE 的节熵/字符串不能证明启动链可信或不可信；必须回到变量、签名与度量证据。
- 本文件不替代芯片厂商文档；FV/变量格式随版本变化，以实际解析结果为准。

## 9. Secure Boot 审计的 12 项勾选判据

> 用法：每项只能填 `pass/fail/na/unverified`；`fail` 必须附证据，`na` 必须写原因。

| # | 判据 | 通过 | 常见误判 |
| :-: | --- | --- | --- |
| 1 | PK 存在且非空 | 变量长度 > 0，签名列表可解析 | 有 PK ≠ Secure Boot 开启 |
| 2 | KEK 能验证 db 更新 | KEK 证书链能签 db 更新 | KEK 为空不等于无保护 |
| 3 | db 只含预期发布者 | 列出证书 subject/SHA256，逐条能解释 | 有第三方证书 = 可能允许第三方 |
| 4 | dbx 覆盖目标 PE 哈希 | 目标 SHA256 在 dbx 列表中 | 不在 dbx ≠ 可加载 |
| 5 | SecureBoot 变量 = 1 | 变量值 + 属性（NV/BS/RT） | 为 1 仍可能有 shim |
| 6 | SetupMode = 0 | 需要先确认未认证改 PK | 为 0 不代表无漏洞 |
| 7 | 目标 PE 签名链完整 | `openssl`/解析器能验到 db 根 | 自签名/测试证书易误判 |
| 8 | 无 shim 绕过 | 无 `MokList` 可疑条目，`shim_lock` 未被禁用 | 有 shim ≠ 一定可利用 |
| 9 | 变量属性合理 | 关键变量带 `NV+BS+RT` 与认证头 | 可写变量可能是设计 |
| 10 | FV 内关键模块完整 | SEC/PEI/DXE/BDS 能定位 | 只有 `_FVH` 字符串不算 |
| 11 | 更新包签名覆盖 FV | 内层镜像有 `.sig/.cat` 且验证 | 只有外层 exe 签名不算 |
| 12 | 回滚保护存在 | 版本/SVN 比较逻辑可见 | 版本号大不等于有保护 |

### 判定口径

- 1–4 任一项 `fail` → 不能写“Secure Boot 策略完整”。
- 5–8 任一项 `unverified` → 只能写“未验证启动信任”，不能写“可绕过”。
- 9–12 属于加固面；单独缺失不构成漏洞，但要写进建议。

## 10. TPM event log 重放走查（命令级）

> 目标：证明“event log 里的哈希链能重放到当前 PCR”，而不是“有 event log”。

```bash
# 1) 导出 event log（Linux；Windows 可用 Get-WinEvent -LogName 'Microsoft-Windows-TPM-WMI' 辅助）
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements > work/eventlog.txt
tpm2_eventlog --eventlog-version=2 /sys/kernel/security/tpm0/binary_bios_measurements \
  > work/eventlog-v2.txt

# 2) 读当前 PCR（只读）
tpm2_pcrread sha256:0,2,4,7,11 > work/pcr.txt
cat work/pcr.txt

# 3) 找关键事件：固件代码、boot manager、Secure Boot 策略
 grep -nE 'EV_EFI_BOOT_SERVICES_APPLICATION|EV_EFI_VARIABLE_AUTHORITY|EV_SEPARATOR' \
  work/eventlog.txt | head -20

# 4) 对目标 PE 算哈希，和 event log 中的 digest 比
sha256sum work/fv/PE32.efi
```

| 检查 | 通过长什么样 | 不通过时 |
| --- | --- | --- |
| event log 可解析 | 有 PCR 索引、事件类型、digest 三列 | 空文件/格式错 → `blocked_at: parse` |
| PCR 重放 | 重放结果与 `tpm2_pcrread` 当前值逐字节一致 | 不一致 → 先查 TPM 是否启用/日志是否截断 |
| 组件哈希 | 目标 PE 的 SHA256 = event log 中对应 digest | 不等 → 该组件未被度量或被替换 |
| 策略事件 | 有 `EV_EFI_VARIABLE_AUTHORITY` 对应 db/dbx | 无 → 不能声称“策略被度量” |
| 时间 | event log 时间与固件版本/更新记录吻合 | 跳变 → 写“可能清空/重置” |

**失败判据**：TPM 未启用（`/dev/tpm0` 不存在）→ 写 `blocked_at: no-tpm`；PCR 全 0 → 写“未度量/被 reset”，
不写“启动链可信”；event log 只有头部 → 写“日志截断”，不写“无度量”。

## 11. 命令与“通过长什么样”（本文件最小复验）

```bash
# 组件层：一个 PE 的身份
python Tool/skill/firmware-iot/scripts/fw-repro.py --file work/PE32.efi --json \
  | jq '{primary, machine: .pe.machine, uefi: .pe.is_uefi, sections: (.pe.sections|length)}'

# 固件卷层：FV/FFS 是否可解析
uefi-firmware-parser -b -o work/fv work/spi.bin > work/fv.log 2>&1; echo "rc=$?"
grep -cE 'FV|FFS|PE32' work/fv.log

# 变量层：只读列出 PK/KEK/db/dbx
chipsec_util uefi var-list 2>/dev/null | grep -E 'PK|KEK|db|dbx' | head

# 签名链：目标 PE 的 SHA256 是否在 dbx
sha256sum work/PE32.efi | cut -d' ' -f1
```

**通过长什么样**：

| 层 | 通过 | 不通过 |
| --- | --- | --- |
| PE | `primary=pe`、`uefi=true`、节数 ≥3 | `file` 不识别/节表为 0 |
| FV | `FV`/`FFS`/`PE32` 计数 ≥1，日志无解析异常 | 只有 `_FVH` 字符串 |
| 变量 | PK/KEK/db/dbx 至少三项可读 | 全部读不到 → 权限/驱动问题 |
| 签名 | 目标哈希能在 dbx 或 db 中找到对应条目 | 找不到 → 不能下“可加载/被吊销”结论 |

## 这一篇算"用对了"吗

- [ ] 我先分类输入（单 PE / 更新包 / SPI dump / 变量 / event log），没有混用判据
- [ ] 我的 Secure Boot 结论至少基于“变量 + 签名链”两类证据，而不是只看一个 `.efi`
- [ ] 我给 12 项判据逐项填了 `pass/fail/na/unverified`，没有留空
- [ ] 我没有把 PCR 全 0 或 event log 为空写成“启动链可信/不可信”
- [ ] 所有写操作（变量/flash）都在备份与单独授权之后，默认只读
- [ ] 我能说出这份固件“信任谁”，以及这个结论的证据在哪一行
