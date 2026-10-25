# 01 判据表：固件/IoT 什么时候算“打下来了”

> 配套 `firmware-iot/SKILL.md`、`Tool/config/firmware-iot-matrix.json`。
> **范围**：路由器/摄像头/NAS/工控网关等嵌入式 Linux/RTOS 固件，以及 UEFI/裸 firmware blob。
> 路由：APK/DEX 由 `apkseep` 承担；桌面 PE/ELF 算法题由 `softseep`/`ida-reverse` 承担；纯云 API 由 `web-pentest` 承担。
>
> 本域只认三种闭环：**J1 能进 shell、J2 能跑起关键服务、J3 能复现漏洞**。
> “解包成功”“binwalk 识别出 12 个签名”“FirmAE 说 success”都不是判据。

## 0. 先固定证据坐标

任何结论先写清四元组，缺一项就不入判据表：

```text
镜像：<path>  sha256=<64 hex>  size=<bytes>
容器：<type>@<offset>  工具=<name + version>
解包：<rootfs path>  文件数/关键目录=/etc /bin /lib /www
运行：<真机|qemu-user|qemu-system|FirmAE>  <启动命令>  <网络参数>
```

机检入口（本仓脚本，离线只读）：

```bash
python Tool/skill/firmware-iot/scripts/fw-triage.py --file fw.bin --json     # 魔术/熵/凭据线索/建议命令
python Tool/skill/firmware-iot/scripts/fw-repro.py --file fw.bin --json
python Tool/skill/firmware-iot/scripts/fw-accept.py       # 案例字段/hash/refs 复算
```

## 1. 判据表（场景 → 可机检判据 → 证据形态 → 误报风险）

| 场景 | 输入面 | 判据（可机检） | 证据形态 | 误报风险 |
|---|---|---|---|---|
| 固件获取/OTA 包 | 厂商下载页、App 抓包、OTA URL | 两次下载 `sha256` 一致；`Content-Length` 与落盘长度一致；首层有已知魔术或被 `file` 识别 | 下载命令、HTTP 头、两次哈希、文件大小 | CDN 分块/压缩传输导致长度不等；需解压后再比 |
| 容器识别 | 原始镜像 | `fw-triage --json` 的 `containers[].type` 至少一个 strong 类型且 offset 可解释；weak 命中（JFFS2 0x1985）必须二次确认节点头 | triage JSON：offset/type/confidence/entropy | 压缩数据/PE 资源里随机出现 `hsqs`、`UBI#`、`0x1985`；高熵≠加密 |
| 文件系统解包 | SquashFS/UBI/CramFS/JFFS2 | 解出目录树含 `/etc` + `/bin`（或 `/usr/bin`）+ `/lib`；`bin/busybox` 或 init 存在且 `file` 架构自洽 | `unsquashfs -ll`/`ubireader` 日志、目录树、busybox `file` 输出 | 只切出 kernel/DTB 或空目录；厂商魔改压缩导致 unsquashfs 报错并非镜像坏 |
| 账号可用性 | `/etc/passwd`、`/etc/shadow`、`/etc/sudoers` | `passwd` 第二字段为空 或 shadow hash 已破解，且能在仿真/真机完成一次登录（会话输出 `id`） | `awk` 输出 + 登录会话日志/串口录屏 | 只有 hash 未破解是素材；`x` 不是空口令；`!`/`*` 是锁定 |
| 私钥/证书 | `/etc`、`/www`、`/usr` 下 `.pem/.key/.p12` | `openssl pkey -in k -noout` 与 `openssl x509 -in c -noout` 配对；证书指纹与用途（设备身份/OTA/云）记录 | 文件路径 + 指纹 + 用途 + 验证命令 | 公钥、CA 证书、示例占位符不是私钥；文件名像 key 不代表有私钥 |
| 启动与服务链 | inittab/rcS/init.d/procd/systemd/nvram | 能画出“开机 → 服务 → 运行用户 → 监听地址 → 可控参数”，每跳有 `文件:行号` | `grep -RIn` 命中行 + 进程/端口/用户快照 | 脚本存在但被条件/看门狗禁用；服务启动后立即退出 |
| Web/CGI 命令注入 | `/www/cgi-bin`、LuCI、升级接口 | 可控参数到达 `system/popen/execve`，请求返回命令输出或产生可重复副作用（文件/进程/回连） | 请求/响应原文、时间戳、前后对比、服务日志 | 字符串出现 `system(` 不等于可达；白名单/转义/权限会阻断 |
| qemu-user 单程序 | 单个 CGI/busybox | `chroot rootfs qemu-<arch> /bin/sh -c 'id; cat /etc/passwd'` 有预期输出；目标 CGI 能跑出业务响应 | 命令 + 输出 + `readelf -h` 架构 | 能跑 `/bin/sh` 不代表目标 CGI 可跑；缺库/`/proc` 会假失败 |
| qemu-system/FirmAE 整机 | kernel + rootfs | 内核挂根 + init 启动 + 服务监听 + **真实协议回包**；四者同时成立 | 串口日志、`ss -lntp`、`curl -i` 响应 | 自动仿真报 success 但只有静态页；hostfwd 指错端口；看门狗反复重启 |
| 网络服务验证（J2） | 设备自身 HTTP/管理协议 | 端口监听 + 进程存在 + 响应含动态业务字段（JSON/CGI/登录挑战），三者同一时刻 | `ss`/`netstat` + `ps` + `curl -i` 原文 | 端口开放但 404/502；只有静态占位页；反向代理到别的服务 |
| 漏洞复现（J3） | 已定位入口 | 同一输入重复 ≥2 次得到相同结果；有请求/响应、日志或崩溃现场；影响可描述 | PoC 脚本 + 两次运行日志 + 版本/配置 | 一次性崩溃可能是 OOM/看门狗；仅版本旧不算漏洞；仿真内“可能”不算 |
| UEFI/裸 firmware blob | `.efi`、`rtecdc.bin`、SPI dump | PE/ELF 架构与 subsystem 可解析；BRCM/TRX/厂商头字段自洽；版本/FWID 可提取 | `fw-repro --json` 的 `pe`/`brcm` 段 + `binwalk` 输出 | 裸 blob 没有 rootfs，不能套用解包判据；节熵高不等于加密 |
| 硬件接口 | UART/JTAG/SPI 焊盘 | UART 落到 `#`/`$` 或改到 `bootargs`；JTAG 识别 SoC 且读回镜像与 SPI dump 哈希一致 | 串口日志、IDCODE、两次读取 SHA256 | 乱码是波特率/地线问题；能读 IDCODE 不等于能读全片 |

## 2. 判据分级（报告里必须写等级）

| 等级 | 含义 | 可写进结论的措辞 | 不可写 |
|---|---|---|---|
| E0 | 只有文件/字符串观察 | “发现候选字符串/候选容器” | “存在漏洞”“可登录” |
| E1 | 解包出 rootfs 并定位到 `文件:行号` | “静态确认配置/脚本/二进制中存在该逻辑” | “设备可被利用” |
| E2 | 仿真或真机完成一次只读验证 | “在 <环境> 中复现，命令与输出如下” | “生产设备同样成立” |
| E3 | 可重复的 J3（两次以上一致） | “在 <版本/配置> 下可重复复现，影响为 …” | 超出授权范围的持久化/批量利用 |

机检建议：把 E1 的每条命中写成 `{kind, path, line, snippet(redacted)}`，
`fw-repro.py` 已按此结构输出；E2/E3 另存请求/响应与时间戳。

## 3. 失败判据（看到即降级）

- 只有容器魔术、没有完整 `/etc`+`/bin`+`/lib` → 不算解包完成，转 `02-failure-criteria.md` 第 1 行。
- 只有 shadow hash、没有可用登录入口 → 只算 E0/E1 素材，不写“弱口令”。
- 仿真里进程存在但端口无业务回包 → 不算 J2，先补 NVRAM/`/dev`/Web 根桩或转真机只读。
- 漏洞只停留在字符串/版本猜测 → 不算 J3，转黑盒测绘或放弃该 CVE。
- 裸 firmware blob（BRCM/TRX/单 PE）没有 rootfs → 走 `06-container-carving-and-entropy.md`，不要套文件系统判据。
- rehosting 成功：`rootfs_complete=true`、`init_chain_ok=true`、`rehost_blocker=none`，且目标服务有真实协议回包；FirmPilot/Khost 恢复只算手段，不算判据。
- rehosting 失败：7 类 `rehost_blocker`（rootfs/init/nvram/watchdog/net/arch-abi/mcu-periph）任一未消解 → 不算 J2，按 `02-failure-criteria.md` 第 ①/②/④ 行分流。

## 4. 边界

- 仅对自有或明确授权的固件/设备操作；不接第三方设备、不扫公网、不写他人闪存。
- 凭据/私钥只留路径、指纹、用途与验证命令，不把明文写入报告或案例。
- “仿真成功”只对当前环境成立；跨设备结论必须重新取证。
- 判据表是**下限**：任何一条不满足就降级，不许用“经验上应该可以”补齐。

## 附：上游技能卡索引（24 张）

> 上游 = `mukul975/Anthropic-Cybersecurity-Skills`（818 技能库）。本表只回答一件事：这条上游技能在本域**落到哪张卡、哪篇 reference、判据是什么**。

| 上游技能 | 本域任务卡 | 落点 reference | 一句话判据 |
|---|---|---|---|
| `performing-plc-firmware-security-analysis` | PLC 固件安全分析（源：performing-plc-firmware-security-analysis） | `Tool/skill/firmware-iot/references/firmware-unpack.md` | 能定位到运行时服务/配置/账号并有文件:行号；或能起仿真并真实回包 |
| `performing-scada-hmi-security-assessment` | SCADA HMI 固件与 Web 面评估（源：performing-scada-hmi-security-assessment） | `Tool/skill/firmware-iot/references/filesystem-and-credentials.md` | 能画出 开机→服务→用户→端口→参数 链路，并有请求/响应证据 |
| `performing-ics-asset-discovery-with-claroty` | ICS 资产发现与固件指纹（源：performing-ics-asset-discovery-with-claroty） | `Tool/skill/firmware-iot/references/01-criteria.md` | 资产-型号-固件版本三者可对应，且证据等级标为 E0/E1 |
| `implementing-ics-firewall-with-tofino` | 工控防火墙与固件升级通道（源：implementing-ics-firewall-with-tofino） | `Tool/skill/firmware-iot/references/firmware-unpack.md` | 升级通道有完整性/签名证据，且策略与实际流量一致 |
| `detecting-modbus-protocol-anomalies` | Modbus 异常与嵌入式服务（源：detecting-modbus-protocol-anomalies） | `Tool/skill/firmware-iot/references/emulation-and-fuzz.md` | 同一异常输入可重复触发响应差异，且有抓包/日志 |
| `detecting-modbus-command-injection-attacks` | Modbus 命令注入与参数拼接（源：detecting-modbus-command-injection-attacks） | `Tool/skill/firmware-iot/references/01-criteria.md` | 可控寄存器值到达危险函数，且有可重复输出或副作用 |
| `performing-s7comm-protocol-security-analysis` | S7comm 协议与固件服务（源：performing-s7comm-protocol-security-analysis） | `Tool/skill/firmware-iot/references/emulation-and-fuzz.md` | 服务响应与固件实现一致，且有版本/配置证据 |
| `detecting-dnp3-protocol-anomalies` | DNP3 异常与固件日志（源：detecting-dnp3-protocol-anomalies） | `Tool/skill/firmware-iot/references/01-criteria.md` | 异常帧导致可重复的日志/响应差异，且排除网络因素 |
| `detecting-attacks-on-scada-systems` | SCADA 攻击检测与固件证据（源：detecting-attacks-on-scada-systems） | `Tool/skill/firmware-iot/references/02-failure-criteria.md` | 告警与设备侧证据能对应，且有命令/日志时间戳 |
| `performing-firmware-extraction-with-binwalk` | binwalk 固件提取与目录树验证（源：performing-firmware-extraction-with-binwalk） | `Tool/skill/firmware-iot/references/firmware-unpack.md` | 目录树完整且 busybox/init 架构与 SoC 一致 |
| `performing-firmware-malware-analysis` | 固件恶意代码与持久化排查（源：performing-firmware-malware-analysis） | `Tool/skill/firmware-iot/references/emulation-and-fuzz.md` | 能定位持久化点与外联目标，且有文件:行号/网络证据 |
| `auditing-uefi-firmware-with-chipsec` | chipsec 审计 UEFI 固件（源：auditing-uefi-firmware-with-chipsec） | `Tool/skill/firmware-iot/references/05-uefi-and-secure-boot.md` | FV 可解析且变量/签名链证据自洽 |
| `detecting-secure-boot-bypass` | Secure Boot 绕过检测（授权）（源：detecting-secure-boot-bypass） | `Tool/skill/firmware-iot/references/05-uefi-and-secure-boot.md` | 能指出策略缺口与对应证据（变量/哈希/日志） |
| `validating-tpm-measured-boot-attestation` | TPM 度量启动验证（源：validating-tpm-measured-boot-attestation） | `Tool/skill/firmware-iot/references/05-uefi-and-secure-boot.md` | event log 可重放到当前 PCR，关键组件哈希一致 |
| `performing-hardware-security-module-integration` | HSM/安全芯片与固件密钥（源：performing-hardware-security-module-integration） | `Tool/skill/firmware-iot/references/filesystem-and-credentials.md` | 密钥不出 HSM 且固件调用路径可证据化 |
| `implementing-hardware-security-key-authentication` | 硬件安全密钥认证与固件（源：implementing-hardware-security-key-authentication） | `Tool/skill/firmware-iot/references/hardware-interfaces.md` | 认证流程可重复，固件侧校验有日志/协议证据 |
| `performing-iot-security-assessment` | IoT 设备安全评估（固件优先）（源：performing-iot-security-assessment） | `Tool/skill/firmware-iot/references/01-criteria.md` | 至少一条 J1/J2/J3 有证据，且标明等级 |
| `performing-bluetooth-security-assessment` | 蓝牙固件与协议评估（源：performing-bluetooth-security-assessment） | `Tool/skill/firmware-iot/references/hardware-interfaces.md` | 配对流程与固件版本可复现，异常有抓包证据 |
| `detecting-bluetooth-low-energy-attacks` | BLE 攻击检测与固件响应（源：detecting-bluetooth-low-energy-attacks） | `Tool/skill/firmware-iot/references/hardware-interfaces.md` | 异常包导致可重复的固件侧响应/日志 |
| `performing-wireless-security-assessment-with-kismet` | 无线评估与 Kismet 取证（源：performing-wireless-security-assessment-with-kismet） | `Tool/skill/firmware-iot/references/hardware-interfaces.md` | 证据可复现且来源合法，固件版本与配置一致 |
| `performing-wifi-password-cracking-with-aircrack` | Wi-Fi 口令与固件默认凭据（授权）（源：performing-wifi-password-cracking-with-aircrack） | `Tool/skill/firmware-iot/references/04-walkthrough-uefi-efi.md` | 口令可验证且能完成一次授权连接；否则只算候选 |
| `performing-wireless-network-penetration-test` | 无线网络渗透测试与固件面（源：performing-wireless-network-penetration-test） | `Tool/skill/firmware-iot/references/01-criteria.md` | 管理面访问或配置缺陷可重复，且有请求/响应 |
| `implementing-usb-device-control-policy` | USB 设备控制策略与固件（源：implementing-usb-device-control-policy） | `Tool/skill/firmware-iot/references/hardware-interfaces.md` | 策略与实测一致，允许/拒绝都有日志 |
| `implementing-ot-network-traffic-analysis-with-nozomi` | OT 流量分析与固件版本关联（源：implementing-ot-network-traffic-analysis-with-nozomi） | `Tool/skill/firmware-iot/references/01-criteria.md` | 资产-协议-固件版本可对应，差异有证据 |
