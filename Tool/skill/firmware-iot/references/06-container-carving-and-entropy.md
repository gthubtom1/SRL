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
python Tool/skill/firmware-iot/scripts/fw-triage.py --file 43341b0rtecdc.bin --json
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

## 8. 厂商头字段差分法：用两个样本代替猜

> 单样本只能“描述头长什么样”，两个样本才能“证明哪个字段是长度/偏移”。

### 8.1 取头与对齐

```bash
for f in fw-a.bin fw-b.bin; do
  echo "== $f"; stat -c '%s' "$f"; xxd -l 256 "$f" | head -16
done
```

把两个版本的头按 4 字节一组排成表，标出：

| 列 | 含义 | 变化规律 |
| :-: | --- | --- |
| `magic` | 厂商/格式标识 | 应相同 |
| `version` | 版本/格式版本 | 可能相同或递增 |
| `length` | 负载长度 | 应与文件大小差为常数 |
| `crc` | 头或负载校验 | 每次不同，改一字节后重算验证 |
| `model` | 型号/FWID | 同型号相同 |
| `offset[]` | 段偏移表 | 随段长度线性变化 |

### 8.2 用长度字段验证切分

```python
from pathlib import Path
import struct

for name in ("fw-a.bin", "fw-b.bin"):
    data = Path(name).read_bytes()
    # 假设 +0x10 是 BE u32 负载长度，+0x14 是负载起始偏移
    length = struct.unpack(">I", data[0x10:0x14])[0]
    start = struct.unpack(">I", data[0x14:0x18])[0]
    print(name, "size", len(data), "len", length, "start", hex(start),
          "size-start", len(data) - start, "match", length == len(data) - start)
```

**判据**：`length == file_size - start` 在两个样本上同时成立；只在一个样本成立可能是巧合。
**失败**：长度是“包含头”还是“不含头”分不清 → 用 CRC 字段验证两种解释，哪种能过就用哪种。

### 8.3 差分时的三个陷阱

1. **字段宽度**：BE/LE、u16/u32、有符号/无符号；用 `xxd -e` 与 `-g4` 对照看。
2. **对齐填充**：厂商常按 0x100/0x1000 对齐，长度字段可能是“对齐前”或“对齐后”。
3. **尾部元数据**：`FWID`/`Version`/`CRC` 可能在文件尾而不是头；先 `tail -c 512 | strings`。

## 9. weak 签名的二次确认算法

> `0x1985`/`1f8b`/`BZh` 这类短魔术不能单独定格式。二次确认分三步，任一步失败就降为“误报候选”。

```text
步骤 1（密度）：在候选偏移 ±0x1000 内统计同一魔术出现次数。
  - JFFS2 节点通常成串出现（≥3 且间隔合理）；
  - 随机数据里偶发 1–2 次，间隔无规律。

步骤 2（结构）：按格式头读关键字段并做范围检查。
  - JFFS2：magic + nodetype + totlen + hdr_crc；totlen 必须在 [min, 0x100000]，hdr_crc 必须匹配。
  - gzip：magic + CM=8 + FLG 合法 + 解压后长度合理。
  - bzip2：BZh + block size '1'..'9' + 解压不报错。

步骤 3（邻接）：切出候选并看前后是否连续。
  - 真文件系统：节点/块首尾相接，直到分区边界；
  - 误报：切出一小段后立刻是别的高熵数据或 0xFF。
```

| 结果 | 判定 | 写法 |
| --- | --- | --- |
| 三步全过 | 可升级为 strong | “在 0x… 处确认为 JFFS2 节点区” |
| 只有步骤 1 过 | weak 候选 | “存在 0x1985 命中，未确认” |
| 步骤 2 失败 | 误报 | “误报，原因：totlen/crc 不符” |
| 无法切出 | 未验证 | “无法验证，缺 OOB/截断” |

## 10. 命令与“通过长什么样”（切分复验）

```bash
FW=work/fw-audit/orig.bin

# 1) 分层：strong/weak 分开看
python Tool/skill/firmware-iot/scripts/fw-triage.py --file "$FW" --json \
  | jq '{entropy, strong: [.containers[]|select(.confidence=="high")], weak: [.containers[]|select(.confidence!="high")]|length}'

# 2) 主格式与切出物
python Tool/skill/firmware-iot/scripts/fw-repro.py --file "$FW" --out-dir work/carve --json \
  | jq '{primary, offset, carved_sha256, extraction: .extraction.status}'

# 3) 切出物二次识别
find work/carve -maxdepth 1 -type f -name 'carved-*' -print -exec file {} \;

# 4) 解包后的目录树（只有真 rootfs 才有）
find work/carve/rootfs -maxdepth 2 -type d 2>/dev/null | sort | head -20
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| 分层 | strong ≥1，weak 数量单独列出 | 用 weak 当 `primary` |
| 切分 | `offset > 0` 时 `carved_sha256` 非空且可复算 | 切出 0 字节/哈希缺失 |
| 二次识别 | `file` 与 `primary` 一致 | 不一致 → 回到头字段 |
| 目录树 | 有 `/etc` + `/bin` + `/lib` | 只有 kernel/DTB |
| 误报 | 误报偏移与原因入证据 | 只字不提误报 |

## 这一篇算"用对了"吗

- [ ] 我能区分“魔术命中”与“容器确认”，没有用 weak 签名定主格式
- [ ] 我用两个样本验证过至少一个长度/偏移字段，而不是只看单样本
- [ ] 我记录了误报偏移与失败原因，它们也是证据
- [ ] 我的 `primary` 与 `file`/厂商标签一致，冲突时做了人工核对
- [ ] 切出物做过目录树判据，没有把“切出一个段”当“拿到 rootfs”
- [ ] 我没有把高熵或弱签名直接写成“加密/文件系统”
