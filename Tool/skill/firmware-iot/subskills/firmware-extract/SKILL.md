---
name: firmware-extract
description: "固件容器切分、文件系统提取与 RTOS 基址候选验证；区分 UBI/UBIFS，按实际镜像类型验收。"
metadata:
  version: "2.1.0"
  target_runtimes: "Linux / RTOS / UEFI 固件；工具平台依赖须核验"
---

# 固件切分、提取与基址

输入包含镜像来源、型号/构建、大小与 SHA256；物理 dump 另记芯片、读法、擦除块/页/OOB/ECC 布局。原件封存，操作工作副本。先读 [解包深度方法](../../references/firmware-unpack.md)、[容器与熵](../../references/06-container-carving-and-entropy.md)、[文件系统审计](../../references/filesystem-and-credentials.md)。

## 优先用已有入口

从源码根执行（静态解析/解包，不启动设备代码）：

```bash
python Tool/skill/firmware-iot/scripts/fw-triage.py --file work/input/fw.bin --json
python Tool/skill/firmware-iot/scripts/fw-repro.py --file work/input/fw.bin --out-dir work/fw-extract --json
```

核工具版本、支持范围与外部提取器依赖。binwalk v2/v3 的参数、插件与依赖不同，先 `binwalk --help`；签名扫描可给候选，递归解包须在隔离分析环境、非特权账户、明确输出目录中进行，不为提取请求 root。`-E`/`-M` 等旧参数不能默认跨版本通用。高熵也可能是压缩，magic 命中不能单独确认分区。

## 按真实格式分流

| 格式 | 结构核对与提取路线 | 失败边界 |
|---|---|---|
| SquashFS | `hsqs`/`sqsh` 与端序、superblock、bytes_used、压缩算法一致；当前 unsquashfs 支持时提取 | 非标准压缩可能需 sasquatch；提取部分文件不证明完整 |
| CramFS | 按 magic 端序、superblock、大小、版本与相应 CRC 核验；提取器能力先查 | magic 的字节顺序不能只凭文件后缀判断 |
| JFFS2 | 节点 magic、长度、CRC、擦除块布局；相应 jefferson 版本 | 两字节签名只是弱候选；NAND OOB/ECC 可能需预处理 |
| UBI 容器 | `UBI#` 是 erase counter header；核 PEB、VID header、volume 表和更新状态，再选卷 | UBI 不是 UBIFS；卷可能是其他格式或静态数据 |
| UBIFS | 节点 magic 常为 `31 18 10 06`（小端 0x06101831）；核 superblock、master、LEB 与日志 | 当前 ubireader 支持才提取；不能把容器直接当文件系统挂载 |
| U-Boot uImage/FIT | 先 `dumpimage -l work/uImage`，核 legacy header CRC/data CRC 或 FIT 的节点、hash/签名与组件边界 | `dumpimage -T ... -p ...` 的类型和索引须按当前头与工具帮助确定，不能固定 firmware 类型剥所有镜像 |
| RTOS/裸机/UEFI | 向量、代码/数据区域、重定位或 FV/FFS 结构；转相应 ISA/容器分析 | 没有 rootfs 很正常，不能套 Linux 目录标准 |

切分表记录源 offset、length、格式置信度、提取命令、子资产哈希与错误；检查范围不越界、不重叠或明确解释重叠。保留未提取区域，不能把提取失败写成“空分区”。压缩包路径穿越/符号链接不允许写出工作目录。

## 基址是候选假设

Cortex-M 的初始 SP/Reset 向量规则不适用于所有 ARM/MIPS/RISC-V；Thumb 位与映射区域需核。依据多组独立字符串/数据引用、有效分支目标、函数边界与向量布局排候选，记录 VA、文件偏移、装载地址的转换。高 16 位相同或部分 ASCII 指向正确不足以唯一确认基址。

## 正反例与交付

正例：UBI 卷表自洽，提取目标 UBIFS 卷后文件解析与节点范围一致；或 RTOS 无文件系统但代码映射与关键函数交叉引用已验证。反例：只有 Linux 风格目录名而缺服务/库，或截断 SquashFS 尾部；报告“部分提取”，不能称完整恢复。

Linux rootfs 按声明分区/文件清单与解析完整性验收，RTOS 按区域/架构/基址置信度验收；都不要求发现或提取口令。秘密只记安全位置/类别与调用路径，不读取真实凭据、Salt 或私钥，也不先散列后脱敏。仿真需另读 [QEMU 条件](../emulation-qemu/SKILL.md)，提取成功不证明服务运行。

ELF 服务交 softseep、设备接口交 web-pentest、报文交 protocol-plugin，子资产保留镜像到文件的来源链，结果归同一 project/version/run。同形失败两次换容器/布局假设，不重复盲解包。
