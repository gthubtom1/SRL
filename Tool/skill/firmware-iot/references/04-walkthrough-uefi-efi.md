# 04 真实案例走查：从 UEFI PE 到 Broadcom 固件 blob

> 配套 `firmware-iot/SKILL.md`、案例 `Tool/cases/firmware-iot03`、`firmware-iot04`。
> **范围**：只拿到单个 `.efi` 或 vendor firmware blob，没有 rootfs、没有设备时的静态走查。
> 结论边界：本节只覆盖本样本的 J1/J2/J3；结论不外推到“设备可被攻破”。
>
> 目标：用**可复跑**的命令回答三件事——这是什么、从哪来、下一步该做什么。
> 环境：Windows + Git Bash，`binwalk`/`7z`/`file`/`strings` 可用；`unsquashfs`/`ubireader` 缺失。

## 0. 案例坐标

| 项 | 案例 04（UEFI） | 案例 03（Broadcom） |
|---|---|---|
| 输入 | `Tool/cases/firmware-iot04/input/SecConfig.efi` | `Tool/cases/firmware-iot03/input/43341b0rtecdc.bin` |
| 来源 | 本机 `C:/Windows/System32/SecConfig.efi` | 本机 `DriverStore/.../bcmdhd64.inf_amd64_.../43341b0rtecdc.bin` |
| 大小 | 1346960 字节 | 406260 字节 |
| SHA256 | `820a15d9746c2877484f203f1d4678001d9a60173b3bfd6bf05884d41bba623e` | `3dc1138c4795caeada1f66937516a7411c0b24f50c51336f208fad7963455a3f` |
| 结论 | PE32+ x86-64 boot application，9 节 | Broadcom BCM43341 固件，FWID `01-97a5222f` |
| 达成 | E0/E1（格式与版本），J1/J2/J3 未达成 | E0/E1（固件身份），J1/J2/J3 未达成 |

## 1. 先固定哈希与格式（两条命令）

```bash
sha256sum Tool/cases/firmware-iot04/input/SecConfig.efi
file Tool/cases/firmware-iot04/input/SecConfig.efi
binwalk Tool/cases/firmware-iot04/input/SecConfig.efi | head -12
```

原始输出（截取）：

```text
820a15d9746c2877484f203f1d4678001d9a60173b3bfd6bf05884d41bba623e  SecConfig.efi
SecConfig.efi: PE32+ executable for MS Windows 1.00 (boot application), x86-64, 9 sections
0       0x0        Windows PE binary, machine type: Intel x86-64
1150656 0x118EC0   CRC32 polynomial table, little endian
1182464 0x120B00   SHA256 hash constants, little endian
1191936 0x123000   AES S-Box
```

判读：

- `MZ`+`PE\0\0`、x86-64、9 sections → 主格式是 PE，不是文件系统容器。
- `binwalk` 后续的 CRC32/SHA256/AES 命中是**代码里的常量表**，不是嵌套固件；
  它们能帮助判断“这是密码学/校验相关组件”，不能当作容器偏移。

## 2. 用本域脚本做结构化分诊

```bash
python `Tool/skill/firmware-iot/scripts/fw-triage.py` \
  --file Tool/cases/firmware-iot04/input/SecConfig.efi --json \
  > Tool/cases/firmware-iot04/artifacts/triage.json

python Tool/skill/firmware-iot/scripts/fw-repro.py \
  --file Tool/cases/firmware-iot04/input/SecConfig.efi \
  --out-dir work/fw-case04 --json \
  > Tool/cases/firmware-iot04/artifacts/repro.json
```

`fw-triage` 人类可读输出的关键片段：

```text
fw-triage 1.1.0  Tool/cases/firmware-iot04/input/SecConfig.efi (1.3 MiB)
sha256 820a15d9746c2877484f203f1d4678001d9a60173b3bfd6bf05884d41bba623e
[entropy] overall=6.489 max_block=8.000 high_block_ratio=0.01 sampled=1.3 MiB
[containers]
  +0x00000000  pe         PE/COFF (DOS MZ header)                    [high]
  +0x00002a42  gzip       gzip stream                                [high]
  +0x0000489b  jffs2      JFFS2 node magic 0x1985 (BE)               [medium]
```

`fw-repro` 的 `pe` 段（JSON 摘录）：

```json
{
  "primary": "pe",
  "pe": {
    "machine": "x86-64",
    "subsystem": "Windows boot application (UEFI-era)",
    "subsystem_id": 16,
    "is_uefi": true,
    "sections": [
      {"name": ".text", "raw_offset": 1024, "raw_size": 1091584, "entropy": 6.491},
      {"name": ".rdata", "raw_offset": 1122304, "raw_size": 143360, "entropy": 5.338},
      {"name": ".rsrc", "raw_offset": 1311232, "raw_size": 22528, "entropy": 3.398}
    ]
  },
  "extraction": {"status": "not-applicable"},
  "verdict": "UEFI boot component (x86-64, Windows boot application (UEFI-era)): firmware, not a rootfs."
}
```

注意两件事：

1. `subsystem_id=16` 不是经典的 EFI 10/11/12/13，但 `file` 与节名（`TRANSIT`/`PAGER32C`）
   都指向 Windows/UEFI 启动组件；脚本按 `is_uefi` + `uefi_clues` 标注，不硬套。
2. `extraction.status=not-applicable` 是**正确降级**：没有 rootfs 可解，不要为了“看起来有产出”
   去 `7z x` 一个 PE 并把解出的资源目录当固件文件系统。

## 3. Broadcom 固件 blob：weak 签名与 strong 标签的冲突

```bash
sha256sum Tool/cases/firmware-iot03/input/43341b0rtecdc.bin
python `Tool/skill/firmware-iot/scripts/fw-triage.py` \
  --file Tool/cases/firmware-iot03/input/43341b0rtecdc.bin --json \
  > Tool/cases/firmware-iot03/artifacts/triage.json
python Tool/skill/firmware-iot/scripts/fw-repro.py \
  --file Tool/cases/firmware-iot03/input/43341b0rtecdc.bin \
  --out-dir work/fw-case03 --json \
  > Tool/cases/firmware-iot03/artifacts/repro.json
```

`fw-triage` 输出（截取）：

```text
fw-triage 1.1.0  Tool/cases/firmware-iot03/input/43341b0rtecdc.bin (396.7 KiB)
sha256 3dc1138c4795caeada1f66937516a7411c0b24f50c51336f208fad7963455a3f
[entropy] overall=7.055 max_block=7.097 high_block_ratio=0.00 sampled=396.7 KiB
[containers]
  +0x000473f1  jffs2      JFFS2 node magic 0x1985 (BE)               [medium]
  +0x0004aafa  jffs2      JFFS2 node magic 0x1985 (BE)               [medium]
  +0x0004dae7  bzip2      bzip2 stream                               [high]
[credential clues] 0
  (none in scanned strings; absence is not proof)
```

只看 triage 会得出“bzip2 + JFFS2”的错误结论。`fw-repro` 增加 BRCM 标签与尾部元数据：

```json
{
  "primary": "brcm",
  "brcm": {
    "tag_offsets": [252828, 252980, 253132, 254156],
    "tail_meta": {
      "version": "6.10.225.19",
      "fwid": "01-97a5222f",
      "date": "2015-08-07 00:30:31",
      "pdt": "Ucode Ver: 764.1115 FWID: 01-97a5222f"
    },
    "header_dwords": [0, 1317, 1101, 1101, 1101, 1101, 1101, 1101]
  },
  "extraction": {"status": "not-applicable"},
  "verdict": "vendor firmware blob (Broadcom BRCM tags): segment/entropy analysis only; no filesystem and no service evidence."
}
```

判读：

- 偏移 `0x3dbbc`（252828）起的 4 个 `BRCM` 标签是**strong 证据**，尾部 `FWID` 与日期可交叉验证版本。
- `bzip2` 是压缩数据流里的偶然魔术；`JFFS2 0x1985` 是典型 weak 误报。两者都不构成 rootfs。
- 头部 8 个 dword（`0, 1317, 1101...`）像长度/偏移表；在拿到整片 SPI dump 时，
  可按这些长度字段切 ucode/CLM 段，而不是让 `binwalk -e` 递归猜。

## 4. 结论（能写与不能写）

能写：

- `SecConfig.efi` 是 PE32+ x86-64 的 UEFI 时代启动应用，9 个节，`.text` 熵 6.491；
  未发现可解文件系统，未读取固件卷或 Secure Boot 变量。
- `43341b0rtecdc.bin` 是 Broadcom BCM43341 Wi-Fi 固件，版本 6.10.225.19 / FWID 01-97a5222f，
  标签偏移 252828 起；没有 rootfs，J1/J2/J3 未达成。

不能写：

- “固件已解包”“rootfs 中有弱口令”“设备存在命令注入”——这些都没有证据。
- “高熵说明加密”——这两个样本的熵来自代码/压缩段，不是加密结论。
- “UEFI 组件 = 启动链可信/不可信”——没有 db/dbx/KEK/PK 与签名验证，不能判断。

## 5. 边界与下一步

| 样本 | 下一步 | 需要的前置 |
|---|---|---|
| `SecConfig.efi` | 导出 UEFI 变量与固件卷，核对 dbx 是否覆盖该 PE 的哈希；`chipsec`/`uefi-firmware-parser` 解析 FV | 授权主机、管理员权限、可回滚的变量备份 |
| `43341b0rtecdc.bin` | 拿整片 SPI dump，按 BRCM 头长度切段；对 ucode/CLM 做版本与熵对照 | 设备所有权、SPI 编程器/夹子、两次一致 dump |
| 两者 | 若目标是 J1/J2，必须补 rootfs 或真机 UART；静态 PE/blob 不足以闭环 | 见 `hardware-interfaces.md`、`emulation-and-fuzz.md` |

## 6. 失败判据（本走查专用）

- `fw-repro` 的 `primary` 落在 `jffs2`/`bzip2` 而输入明明是 PE/BRCM → 先检查 strong/weak 分层，
  不要把弱签名当容器。
- `extraction.status=extract-failed` 且 `attempts[].tool=7z` → 说明该偏移不是可解容器；
  回到格式识别，不要连续换 7z 参数。
- 版本/FWID 提取不到 → 用 `strings -a -n 6` 搜 `Version:`/`FWID:`/`PDT`，并记录偏移；
  仍没有就只写“未识别版本”，不要猜。
- 任何一步需要写闪存/改 UEFI 变量但没有备份 → 停止，先做只读备份。

## 7. 复跑命令汇总

```bash
# 1) 重算哈希
sha256sum Tool/cases/firmware-iot03/input/*.bin Tool/cases/firmware-iot04/input/*.efi

# 2) 结构化分诊 + 复现
python `Tool/skill/firmware-iot/scripts/fw-triage.py` --file <sample> --json > /tmp/triage.json
python Tool/skill/firmware-iot/scripts/fw-repro.py --file <sample> --out-dir work/fw-repro --json > /tmp/repro.json

# 3) 案例验收（字段/hash/refs/lessons）
python Tool/skill/firmware-iot/scripts/fw-accept.py
```

预期：两条命令均 rc=0；`fw-accept` 对 `firmware-iot03/04` 报 PASS（`real`），
`firmware-iot05` 报 PASS（`fixture`）。若 `fw-accept` 报 hash mismatch，
说明案例产物被改动，必须重跑而不是改 JSON 里的哈希。
