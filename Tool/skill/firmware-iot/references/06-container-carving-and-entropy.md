# 06 容器切分与熵分析：别让两字节魔术骗了你

> 配套 `firmware-iot/SKILL.md`、`references/firmware-unpack.md`、脚本 `fw-triage.py`/`fw-repro.py`。
> **范围**：判断“这是什么容器、从哪个偏移切、切出来值不值得解”，以及处理裸 firmware blob。
> 用法：熵与魔术只是**线索**；结论要走到解包/仿真产物，本文是线索到证据的衔接页。

## 0. 为什么单独讲切分

固件现场最常见的两类错误：

1. **把 weak 签名当容器**：JFFS2 的 `0x1985`、gzip 的 `1f 8b`、tar 的 `ustar`
   在压缩数据/PE 资源/随机填充里都会出现；
2. **在错误偏移上解包**：厂商头（长度/CRC/机型）没剥掉，`unsquashfs`/`ubireader`
   自然报 `bad magic`，于是误判“加密/魔改”。

解决顺序固定为：**分类 → strong/weak 分层 → 算偏移 → 切 → 解 → 验证目录树**。
任何一步跳过，后面都是猜。

## 1. 魔术分层表

| 类型 | 魔术/特征 | 典型偏移 | 强度 | 误报风险 |
|---|---|---|---|---|
| SquashFS LE | `hsqs` | 0 或厂商头后 | strong | 低；但要确认版本/块大小 |
| SquashFS BE/变体 | `sqsh`/`qshs`/`shsq` | 同上 | strong | 变体可能需 `sasquatch` |
| UBI | `UBI#` | 0 或 NAND 页边界 | strong | 偏移/OOB 错时仍报 bad magic |
| CramFS | `45 3d cd 28`（LE）/`28 cd 3d 45`（BE） | 0 | strong | 低 |
| JFFS2 | `85 19`/`19 85` | 节点边界 | **weak** | 高；必须校验节点头/长度/CRC |
| ZIP | `PK\x03\x04` | 0 或自解压包内 | strong | 需确认中央目录完整 |
| gzip | `1f 8b` | 0 或嵌入 | medium | 压缩数据中常见；解压失败即误报 |
| XZ | `fd 37 7a 58 5a 00` | 0/嵌入 | medium | 同上 |
| bzip2 | `BZh` | 0/嵌入 | medium | 三字节，误报率高 |
| Zstd | `28 b5 2f fd` | 0/嵌入 | medium | 低 |
| tar | 偏移 257 处 `ustar` | 0 | strong | 需校验 header checksum |
| cpio newc | `070701`/`070702` | 0/嵌入 | strong | 低 |
| U-Boot uImage | `27 05 19 56` | 0 | strong | 低；注意头长度字段 |
| DTB | `d0 0d fe ed` | 0/嵌入 | strong | 低 |
| TRX | `HDR0` | 0 | strong | 厂商变体多，需看长度字段 |
| PE/COFF | `MZ` + `PE\0\0` | 0 | strong | `.efi`/驱动常见；不是 rootfs |
| ELF | `7f 45 4c 46` | 0 | strong | 裸二进制，不是 rootfs |
| Broadcom | `BRCM` 标签 + 尾部 `FWID:` | 段边界 | strong（厂商） | 需结合长度表；不是文件系统 |

机检：`fw-triage --json` 在 `containers[]` 里给 `confidence`（`high`/`medium`），
`fw-repro` 再按 `filesystem > boot-image > binary > stream > weak-signature` 分层选 `primary`。
**weak 命中永远不能单独决定主格式。**

## 2. 熵怎么看才不误导

`fw-triage` 输出三类值：

```json
{"overall": 7.055, "max_block": 7.097, "high_block_ratio": 0.0,
 "sampled_bytes": 406260, "sample_truncated": false}
```

- `overall`：整体熵（0–8）。>7.2 常见于压缩/加密/已打包文件系统；<6.0 多为明文/元数据。
- `max_block`：4 KiB 块的最大熵。单块 8.0 只说明该块接近随机，不代表全盘加密。
- `high_block_ratio`：熵 ≥7.2 的块占比。**它比 overall 更能区分“局部压缩”与“全盘加密”**：
  - 高 overall + 低 ratio → 局部压缩/资源段（如 PE 的 `.text`/压缩资源）；
  - 高 overall + 高 ratio → 更像全盘压缩/加密；
  - 低 overall + 有 strong 魔术 → 未压缩文件系统/明文脚本。

样例对照（本仓真实案例）：

| 样本 | overall | max_block | high_ratio | 主格式 | 解释 |
|---|---:|---:|---:|---|---|
| `SecConfig.efi` | 6.489 | 8.000 | 0.01 | PE | 代码+资源，局部高熵 |
| `43341b0rtecdc.bin` | 7.055 | 7.097 | 0.00 | BRCM blob | 固件代码/压缩段，无全盘随机 |
| 合成 OTA zip | 7.9+ | 8.0 | 高 | ZIP | 已压缩归档，属正常 |

结论：**熵只用来分流，不用来定性“加密”**。无 strong 魔术 + 高 ratio + 无厂商头，
才转解密/硬件路线。

## 3. 从偏移切：三种可靠做法

### 3.1 用现成工具按签名切

```bash
binwalk --dd='.*' -C work/raw fw.bin      # 只切不执行
binwalk -e --run-as=root -C work/ext fw.bin
7z l fw.bin                                # 先看能不能识别
```

`binwalk --dd` 的产物文件名带偏移，适合做“候选清单”；不要直接对每个候选跑解包，
先用 `file`/`fw-repro` 复核。

### 3.2 用标准库按偏移切（可审计、跨平台）

```python
from pathlib import Path
src = Path("fw.bin").read_bytes()
off = 0x3dbbc                      # 来自 triage/repro 的 offset
Path("work/part.bin").write_bytes(src[off:])
print("carved", len(src) - off)
```

`fw-repro.py` 在 `primary.offset > 0` 时会自动切到 `carved-0x<off>.bin`，
并把切出文件的 SHA256 写进 JSON，方便复算。

### 3.3 厂商头：先算负载偏移，再切

- TRX：`HDR0` + length + crc32 + flags + version/offset 表；按 length 切。
- U-Boot uImage：64 字节头，`ih_size` 是负载长度（大端），负载从 0x40 开始。
- Broadcom：头部 dword 表（如 `0, 1317, 1101...`）给出段长度/偏移；
  尾部 `FWID:`/`Version:`/`PDT` 用于交叉验证。
- 厂商自定义头：找 `magic + version + length + crc + model` 五元组；
  用 `xxd` 看头 256 字节，再用两个不同版本比对字段变化。

判据：切出的长度与头字段一致；切出物有可解释的 strong 魔术；
否则回到“这是裸 blob/加密流”的路线。

## 4. 真实例子：Broadcom blob 的“假 bzip2”

```bash
python Tool/scripts/fw-triage.py --file 43341b0rtecdc.bin --json
python Tool/skill/firmware-iot/scripts/fw-repro.py --file 43341b0rtecdc.bin --json
```

triage 报：

```text
+0x0004dae7  bzip2  bzip2 stream  [high]
```

但 `fw-repro` 的主格式是 `brcm`：`BRCM` 标签在 252828/252980/253132/254156，
尾部 `FWID: 01-97a5222f`、`Version: 6.10.225.19`。
如果把 `0x4dae7` 当 bzip2 去解，`bz2` 会报 `Invalid data stream`——
这就是**medium 签名在固件代码区误报**的典型。

处理原则：

1. 记录误报偏移与失败原因（这也是证据）；
2. 用厂商标签/长度表解释真实结构；
3. 不因为一个 medium 命中就否定 strong 主格式。

## 5. 解包后的“目录树判据”

切出来只是第一步。无论 SquashFS/UBI/CramFS/JFFS2/zip/tar，最终都要满足：

```text
rootfs/
├── bin/ 或 usr/bin/        # 至少一个可执行（busybox/init/sh）
├── etc/                    # passwd/shadow/inittab/init.d 至少一类
├── lib/ 或 usr/lib/        # 动态库或静态 busybox
└── www/ 或 htdocs/         # 有 Web 管理面时
```

机检：

```bash
find rootfs -maxdepth 2 -type d | sort
file rootfs/bin/busybox 2>/dev/null
readelf -h rootfs/bin/busybox 2>/dev/null | head -12
```

失败判据：

- 只有 `squashfs-root/` 但缺 `/etc`/`/bin` → 可能还有第二层容器/厂商头；
- 只有 kernel/DTB → 不是 rootfs；
- busybox 架构与 SoC 不一致 → 切错镜像或拿错型号。

## 6. 失败判据（切分/熵专用）

| 现象 | 判定 | 改走哪条 | 代价 |
|---|---|---|---|
| strong 魔术在多个偏移重复 | 可能是嵌套容器/厂商头重复 | 先切最外层，解出后再看内层；记录每层 hash | 多轮解包 |
| 只有 weak 命中（JFFS2/gzip） | 不能定主格式 | 用 `fw-repro` 分层；找厂商头/strong 标签 | 可能白跑 |
| 切出物 `file` 不识别 | 偏移/长度错或加密 | 回头核对头字段；用两个版本比对 | 需要更多样本 |
| 熵高但 high_ratio 低 | 局部压缩，不是全盘加密 | 找节/段边界，按段分析 | 低 |
| 熵高且 high_ratio 高、无魔术 | 可能全盘压缩/加密 | 转厂商头/解密点/UART/SPI | 高，可能无法离线 |
| 7z 报 `Cannot open the file as archive` | 该偏移不是可解容器 | 回到格式识别；不要连换 7z 参数 | 低 |
| 解出目录但缺 `/etc`/`/bin` | 不是完整 rootfs | 查第二层容器/厂商头；换 `sasquatch`/`ubireader` | 中 |

## 7. 边界

- 切分与熵分析是**侦察**；没有目录树/服务/漏洞证据时，只能写 E0/E1。
- 厂商头字段可能随版本变化；用两个以上样本交叉验证，不凭单样本猜格式。
- 不在原始镜像上反复写/改；所有 carve、解包、补丁只在 `work/` 副本。
- 不把“切出一个高熵段”写成“加密固件已解密”；解密需要密钥/算法/明文验证。
