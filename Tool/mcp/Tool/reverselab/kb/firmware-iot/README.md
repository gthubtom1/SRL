# Firmware & IoT 知识库 — 固件解包、文件系统、仿真与硬件接入

> Board：`firmware-iot`。配套技能：`Tool/skill/firmware-iot/SKILL.md`。
> 只回答“能否拿到可分析的文件系统、跑起关键服务、复现一个可验证的问题”；解包成功不等于分析成功。

## 这个板卡管什么

- OTA/分区/UART/U-Boot/SPI 获取固件，`binwalk`/`ubireader`/`unsquashfs`/`jefferson` 解包。
- 文件系统审计：账号、shadow、私钥/证书、启动脚本、服务链、NVRAM/MTD 引用。
- 容器切分与熵：strong/weak 魔术、厂商头、裸 blob（BRCM/TRX/uImage）。
- UEFI/Secure Boot：PE/TE、固件卷、PK/KEK/db/dbx、TPM 度量。
- UART/JTAG/SPI 接线与判据，QEMU user/system 与 FirmAE/Firmadyne 仿真，最小 NVRAM/`/dev` 桩。
- 不负责：纯二进制算法还原（`ida-reverse`）、云原生/内网（`ad-cloud`）、
  应用层 Web 漏洞（`web-pentest`）、APK（`apkseep`）。

## 技术页（逐篇）

- [01 解包与文件系统](techniques/01-unpack-and-filesystem.md)
- [02 UART 与仿真](techniques/02-uart-and-emulation.md)
- [03 OTA 与签名校验](techniques/03-ota-and-signature.md)
- [04 UEFI 与 Secure Boot 速查](techniques/04-uefi-secureboot.md)
- [05 容器切分与熵速查](techniques/05-container-carving.md)
- [06 失败判据](techniques/06-failure-criteria.md)
- [容器识别与解包决策](techniques/07-container-triage.md)
- [凭据与启动链审计](techniques/08-credentials-and-boot-chain.md)

## 三条硬判据

1. **J1 能进 shell**：UART 登录/SSH/telnet 会话或 QEMU 串口提示符；不是只看到 U-Boot 横幅。
2. **J2 能跑起关键服务**：监听端口 + 进程 + 真实业务响应（动态 HTML/JSON/CGI/协议回包）。
3. **J3 能复现漏洞**：可重复请求/PoC + 前后对比 + 日志/崩溃现场；不是字符串猜测。

每条都要写证据：命令、`文件:行号`、请求/响应、串口日志或哈希。
“解包成功”“FirmAE success”“binwalk 识别出签名”都不是判据。

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
python Tool/scripts/fw-triage.py --file "$OUT/orig.bin" --json | tee "$OUT/triage.json"
```

2. 按信号选页：

| 信号 | 先读 |
|---|---|
| SquashFS/UBI/JFFS2/CramFS/cpio，需要账号与启动链 | `01-unpack-and-filesystem.md` |
| 有 UART 焊盘、U-Boot 提示、需要跑服务 | `02-uart-and-emulation.md` |
| OTA/升级包、签名/回滚保护 | `03-ota-and-signature.md` |
| `.efi`/FV/Secure Boot/TPM | `04-uefi-secureboot.md` |
| 裸 blob、熵高、魔术不确定 | `05-container-carving.md` |
| 连续失败、需要换路线 | `06-failure-criteria.md` |
| 只知道容器类型、需要决策树 | `07-container-triage.md` |
| 已有 rootfs，要查账号/密钥/服务链 | `08-credentials-and-boot-chain.md` |

3. 每个结论落到证据：镜像哈希、偏移、工具版本、`文件:行号`、串口日志、HTTP 响应。
   工具/参数随发行版变化（`binwalk`、`sasquatch`、FirmAE），按本机版本核对。

4. 三选一闭环：能进 shell、能跑起关键服务并真实回包、能复现一个可验证问题。
   仅“进程存在”或“内核启动”不算。

## 失败判据（速记）

- 只有容器魔术、没有 `/etc`+`/bin`+`/lib` → 解包未完成。
- 全盘高熵、无 strong 魔术 → 可能加密/厂商容器，转硬件/解密路线。
- 只有 hash、无登录入口 → 不写“弱口令”。
- 仿真进程在但端口无业务回包 → 不是 J2。
- 漏洞只在字符串/版本号 → 不是 J3。
- 同一手法连续 2 次失败 → 换路线或汇报。

完整表：`techniques/06-failure-criteria.md`；技能侧另有
`Tool/skill/firmware-iot/references/02-failure-criteria.md`。

## 和哪个技能配合

| 场景 | 技能路径 |
|---|---|
| 主流程、五步闭环、验收与边界 | `Tool/skill/firmware-iot/SKILL.md` |
| 静态反汇编、定位解析器/命令注入点 | `Tool/skill/ida-reverse/SKILL.md` |
| 固件里的 Web/CGI 漏洞验证 | `Tool/skill/web-pentest/SKILL.md` |
| 固件中泄露的云凭据/K8s token | `Tool/skill/ad-cloud/SKILL.md` |
| 二进制补丁/版本差异 | `Tool/skill/binary-diff/SKILL.md` |
| APK/Android 侧 | `Tool/skill/apkseep/SKILL.md` |

## 边界

- 仅对自有或明确授权的固件/设备操作；不接第三方设备、不扫公网、不写他人闪存。
- 上电前量电压、共地、确认 IO 电平；1.8V 芯片必须用 1.8V 适配器。
- 凭据/私钥只留路径、指纹、用途与验证命令，不把明文写进报告。
- 单个 PE/裸 blob 不能证明启动链可信或设备可利用；必须回到服务/漏洞证据。
