# Firmware & IoT 知识库 — 固件解包、文件系统与硬件接入

> Board：`firmware-iot`。配套技能：`Tool/skill/firmware-iot/SKILL.md`。
> 只回答“能否拿到可分析的文件系统、跑起关键服务、复现一个可验证的问题”；解包成功不等于分析成功。

## 这个板卡管什么

- OTA/分区/UART/U-Boot/SPI 获取固件，`binwalk`/`ubireader`/`unsquashfs`/`jefferson` 解包。
- 文件系统审计：账号、shadow、私钥/证书、启动脚本、服务链、NVRAM/MTD 引用。
- UART/JTAG/SPI 接线与判据，QEMU user/system 与 FirmAE/Firmadyne 仿真，最小 NVRAM/`/dev` 桩。
- 不负责：纯二进制算法还原（`ida-reverse`）、云原生/内网（`ad-cloud`）、
  应用层 Web 漏洞（`web-pentest`）。

当前技术页：

- [01 解包与文件系统](techniques/01-unpack-and-filesystem.md)
- [02 UART 与仿真](techniques/02-uart-and-emulation.md)

## 怎么用

1. 副本、哈希、元信息，先只读判断容器：

```bash
FW=firmware.bin
OUT=work/fw-audit
mkdir -p "$OUT"
cp --reflink=auto "$FW" "$OUT/orig.bin"
sha256sum "$OUT/orig.bin" | tee "$OUT/orig.sha256"
file "$OUT/orig.bin"
binwalk "$OUT/orig.bin" | head -50
python Tool/scripts/fw-triage.py --file "$OUT/orig.bin" --json
```

2. 按信号选页：

| 信号 | 先读 |
|---|---|
| SquashFS/UBI/JFFS2/CramFS/cpio、需要账号与启动链 | `01-unpack-and-filesystem.md` |
| 有 UART 焊盘、U-Boot 提示、需要跑服务 | `02-uart-and-emulation.md` |
| 高熵无签名、疑似加密/厂商头 | 技能 `references/firmware-unpack.md` 第 6 节 |
| 需要 fuzz 或完整系统仿真 | 技能 `references/emulation-and-fuzz.md` |

3. 每个结论落到证据：镜像哈希、偏移、工具版本、`文件:行号`、串口日志、HTTP 响应。
   工具/参数随发行版变化（`binwalk`、`sasquatch`、FirmAE），按本机版本核对。

4. 三选一闭环：能进 shell、能跑起关键服务并真实回包、能复现一个可验证问题。
   仅“进程存在”或“内核启动”不算。

## 和哪个技能配合

| 场景 | 技能路径 |
|---|---|
| 主流程、五步闭环、验收与边界 | `Tool/skill/firmware-iot/SKILL.md` |
| 静态反汇编、定位解析器/命令注入点 | `Tool/skill/ida-reverse/SKILL.md` |
| 固件里的 Web/CGI 漏洞验证 | `Tool/skill/web-pentest/SKILL.md` |
| 固件中泄露的云凭据/K8s token | `Tool/skill/ad-cloud/SKILL.md` |
| 二进制补丁/版本差异 | `Tool/skill/binary-diff/SKILL.md` |

## 边界

- 仅对自有或明确授权的固件/设备操作；不接第三方设备、不扫公网、不写他人闪存。
- 上电前量电压、共地、确认 IO 电平；1.8V 芯片必须用 1.8V 适配器。
- 凭据/私钥只留路径、指纹、用途与验证命令，不把明文写进报告。
