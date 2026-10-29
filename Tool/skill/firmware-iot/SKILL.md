---
name: firmware-iot
description: "分析这个固件/路由器/摄像头/NAS 的固件，解包看文件系统，有没有后门/硬编码口令/命令注入/签名校验缺陷；能不能仿真跑起来 (.bin/.img/.trx/.squashfs/.ubi，UART/JTAG/SPI，QEMU/FirmAE)。"
license: MIT
compatibility: Linux 主机优先（binwalk/ubireader/unsquashfs/QEMU 原生）；Windows 可经 WSL2 或 Tool/scripts/tool-run.ps1 启动外部工具。硬件侧需 USB-TTL、逻辑分析仪、SPI 编程器/夹子，电压匹配 1.8V/3.3V。
metadata:
  version: "2.0.0"
  category: firmware-iot
  hard_gates: "只读备份 / 先判芯片与接口 / 上电前量电压 / 设备与镜像清单由 scope 声明 / 三判据闭环"
---

# firmware-iot — 固件 / IoT / 硬件接入

> 按用户目标处理结构审查、关键服务、协议/升级或硬件问题；只在需要时推进到仿真/真机，不强制每份固件发现漏洞或连硬件。
> 不把“解包成功”当成功，也不把“仿真起内核”当成功；判据见第三节，失败分流见第四节。
> 仅对自有或明确授权的设备/固件操作。上电、短接、写闪存都可能变砖，先备份再动手。

---

## 阶段契约（与 softseep 一致，**先判再做**）
> **域契约**（判型→裁定+M1–M4→按上限执行→停手问）：见 `Tool/skill/seep-router/SKILL.md`（唯一口径：判型→选域→上限 M1–M4→按当前路线核缺件）。本文件不复制。
- 项目登记、证据、验收与接续按 router 第 5 步；`case_state.py` 仅用于需要专业过闸的单案。
- 只执行当前目标需要的阶段；缺不可替代输入才问 A/B/C，已有授权不重复询问。参考与配方不能扩大用户目标；示例案例通过只证明工具自检，不能代替当前项目验收。

## 一、范围与路由（边界）

**本域输入面**

- 路由器、交换机、摄像头、NVR、NAS、打印机、智能家居、工控网关等**嵌入式 Linux/RTOS 固件**。
- 厂商 OTA 包、官网下载固件、SPI/NAND/eMMC 闪存镜像、UART/U-Boot 转储。
- UEFI 固件组件：`.efi`、固件卷（FV）、Secure Boot 变量、TPM 度量。
- 裸 firmware blob：Broadcom `BRCM`/TRX/uImage/单 PE/ELF（只做格式与版本判据）。
- 目标问题：默认/硬编码凭据、私钥与证书、启动脚本提权、Web/CGI 命令注入、
  未授权接口、调试口暴露、OTA 签名缺失、Secure Boot 策略缺陷。

**相邻域与路由**

> 载体→域 的映射**只看一处**：`Tool/skill/seep-router/SKILL.md`（本文件不再复写，避免两份表漂移）。
> 本域只补一句：固件样本若同时是 APK 容器/纯 PE，按 router 判型后再回来。
- 第三方设备/网段/闪存写入清单由 `scope` 声明，清单内按任务执行。
- 不把“解包成功”“FirmAE success”“binwalk 识别出 12 个签名”当作交付。

## 配方（照这个跑）

输入面命中下面某行时，先照该配方的命令序列跑，再回来对判据；配方正文只在 playbooks 一处，本文件只指路。

- 固件解包、rootfs 判据、分区表与 OTA 包 → `Tool/playbooks/firmware-extract.md`
- 固件仿真/rehosting 起不来、init 链或服务不监听 → `Tool/playbooks/firmware-emulate.md`

## 上限怎么说（对客户）

- **只能看懂结构**：`解开了文件系统，能指出硬编码凭据/后门脚本在哪个文件哪一行，但没在设备上跑过`
- **能改到能用**：`改了配置/去掉了后门并重新打包，装上后能进后台，或服务确实在跑、能拿到真实业务响应`
- **能完全自己接管**：`漏洞能稳定复现（同一输入两次一致），并且 UART 读到 shell、SPI 两次 dump 哈希一致——这台设备可以自己反复验证`
- **卡点通常是**：`全盘高熵、没有可识别容器（加密/厂商私有头），或者要硬件而手上没有：缺 UART/JTAG、不敢刷写`

> 依据：本文件 §三 判据表（固件身份/解包完整/后台可达/稳定复现/硬件接口；内部档位见账本）+ §四 失败判据（高熵无 strong 魔术、仿真无业务回包）

## 二、前置检查（3 件；缺的是**技术条件**就换路，不是等授权）

1. **授权与归属**：设备/固件可获取（默认视为已受权沙箱资产，不问授权）；明确测试窗口与回滚清单。
2. **只读备份**：原始镜像 + SHA256 + 获取命令/URL；所有解包/补丁只在副本上做。
3. **可恢复性**：知道变砖后的恢复路径（SPI 夹子/编程器、U-Boot TFTP、厂商恢复模式）；
   上电前量 VCC-GND 与 IO 电平，确认 1.8V/3.3V。

补充记录（不满足不阻塞，但必须写“未验证”）：型号、PCB 丝印、SoC、闪存型号、
UART/JTAG/SPI 焊盘、启动链、固件加密/签名迹象。

## 三、判据表（5–8 类，确认 / 疑似）

| 类别 | 确认（可写进结论） | 疑似（只能写线索） | 证据形态 |
|---|---|---|---|
| 固件身份 | SHA256 稳定；strong 容器/厂商标签 + 版本/FWID 自洽 | 只有文件名/型号字符串 | 哈希、偏移、版本串、`fw-repro` JSON |
| 解包完整 | 目录树含 `/etc`+`/bin`(或 `/usr/bin`)+`/lib`；busybox/init 架构自洽 | 只切出 kernel/DTB/单个 PE；目录“看起来有东西” | `unsquashfs -ll`/`ubireader` 日志、目录树、`file` 输出 |
| 账号可用（内部档位 J1，对外说「能进后台，验证了弱口令」） | 用户提供的测试口令或合成 canary 完成一次登录，会话输出 `id` | 只有账号名/hash/字符串，没有登录入口 | 登录会话/串口录屏 + 测试账号来源 |
| 服务可用（内部档位 J2，对外说「服务确实在跑，能拿到真实业务响应」） | 端口监听 + 进程 + **真实业务响应** 同一时刻 | 进程在但端口不通/502/只有静态页 | `ss -lntp` + `ps` + `curl -i` 原文 |
| 漏洞复现（内部档位 J3，对外说「漏洞能稳定复现（同一输入两次一致）」） | 同一输入重复 ≥2 次一致；有请求/响应/日志/崩溃现场 | 字符串/版本猜测；“仿真里可能” | PoC + 两次运行日志 + 版本/配置 |

> **对客户只说三句话，不要报 J1/J2/J3**：J1 →「能进后台，验证了弱口令」；J2 →「服务确实在跑，能拿到真实业务响应」；J3 →「漏洞能稳定复现（同一输入两次一致）」。
| 凭据/密钥 | 证书公钥元数据/信任配置与验证路径对应；签名验证仅用合成测试密钥，不读取真实私钥 | 只有 `.pem/.key` 文件或示例占位符 | `openssl` 指纹 + 用途 + 验证命令 |
| UEFI/Secure Boot | FV 可解析 + 变量可读 + 签名链/度量链能验证 | 只有单个 `.efi` 或节熵 | `fw-repro` PE 段、变量二进制、event log |
| 硬件接口 | UART 落到 shell/改 bootargs；JTAG 读回与 SPI dump 哈希一致 | 有焊盘但无输出/IDCODE | 串口日志、IDCODE、两次读取 SHA256 |

**判据分级**（报告必须写等级）：

- **E0** 字符串/魔术观察；**E1** 解包后定位到 `文件:行号`；
- **E2** 仿真/真机完成一次只读验证；**E3** 可重复 J3。

## 四、失败判据（看到即降级）

> 完整表见 `references/02-failure-criteria.md`；这里只列高频触发。

| 现象 | 判定 | 改走哪条 |
|---|---|---|
| 只有容器魔术，没有完整 `/etc`+`/bin`+`/lib` | 解包未完成 | 算厂商头真实偏移；换 `sasquatch`/`ubireader`/`jefferson`/`7z` |
| 全盘高熵、无 strong 魔术 | 可能加密/厂商容器 | 找解密点/U-Boot 解密；转 UART/JTAG 在线读 |
| 只有 shadow hash、无登录入口 | 凭据未验证 | 只记录账户存在/x/锁定等元数据；不读取 hash，转接口或串口路线，不写“弱口令” |
| `passwd` 第二字段 `x` / shadow `!` | 不是空口令/被锁定 | 只核安全账户元数据/锁定状态与认证路径；不读取 shadow/NVRAM/云凭据或私钥内容 |
| 仿真进程在但端口无业务回包 | 不是 J2 | 补 NVRAM/`/dev`/Web 根桩；或转真机只读 |
| 漏洞只在字符串/版本号 | 不是 J3 | 黑盒测绘/动态跟踪/最小 PoC；两次一致才算 |
| 裸 blob（BRCM/TRX/单 PE） | 无 rootfs | 走 `06-container-carving-and-entropy.md`，不套文件系统判据 |
| 同一手法连续 2 次失败 | 路线不通 | 换路线或汇报；不在真机反复写 |

## 五、模型常见失误（≥8 条）

> 完整 21 条与“错误动作→为什么错→正确动作”见 `references/03-model-pitfalls.md`。

1. `binwalk` 识别出签名就宣布“解包成功”——没有目录树就不是 rootfs。
2. 熵 >7.2 就判“加密”——SquashFS/UBI/压缩 kernel 本身高熵，先看 `high_block_ratio`。
3. 搜到 `85 19` 就写“JFFS2 分区”——两字节弱签名必须校验节点头/长度/CRC。
4. 对裸 firmware blob 套“解出 /etc 才算成功”——判据用错会假失败/假成功。
5. `strings | grep password` 命中就写“硬编码口令”——没有 `文件:行号` 与可用性验证不算。
6. 把 `passwd` 的 `x` 当空口令——口令在 shadow，空字段/锁定要分清。
7. 仿真进程起来就写“服务已跑通”——J2 要端口+进程+真实业务响应。
8. 在错误架构/端序上硬调 QEMU——先 `readelf -h` 看 Machine/Data。
9. 忽略 NVRAM、`/dev/mtd`、看门狗——服务启动即退出常是缺桩。
10. UART 乱码就换板子——先量电压/共地、交换 TX/RX、试多档波特率。
11. 把示例密钥当设备身份——`openssl` 配对 + 设备实际接受才算。
12. 把失败包装成“部分成功”——按失败判据写现象/判定/改走哪条/代价。

## 六、流程（分阶段，每阶段有完成判据）

### 阶段 1：获取与固定证据

```bash
FW=firmware.bin; OUT=work/fw-audit
mkdir -p "$OUT"; cp --reflink=auto "$FW" "$OUT/orig.bin"
sha256sum "$OUT/orig.bin" | tee "$OUT/orig.sha256"
file "$OUT/orig.bin"; stat -c '%s bytes' "$OUT/orig.bin"
python Tool/skill/firmware-iot/scripts/fw-triage.py --file "$OUT/orig.bin" --json > "$OUT/triage.json"
```

完成判据：哈希、大小、来源、容器候选（strong/weak）齐全。
失败判据：文件不可读/被截断；只有 high 熵无魔术 → 转阶段 2 的厂商头/硬件路线。

### 阶段 2：切分与解包

```bash
python Tool/skill/firmware-iot/scripts/fw-repro.py --file "$OUT/orig.bin" \
  --out-dir "$OUT/repro" --json > "$OUT/repro.json"
binwalk -e --run-as=root -C "$OUT/ext" "$OUT/orig.bin"
unsquashfs -d "$OUT/rootfs" -f "$OUT/ext/part.bin"        # SquashFS
ubireader_extract_files -o "$OUT/ubi-root" "$OUT/ubi.ubi"  # UBI
```

完成判据：`find rootfs -maxdepth 2` 能看到 `/etc`、`/bin` 或 `/usr/bin`、`/lib`；
`bin/busybox`/init 的架构与 SoC 一致。
失败判据：只切出 kernel/DTB；`unsquashfs` 报 unsupported compression → 换 `sasquatch`；
工具缺失 → 继续 strings/熵/硬件路线，并记 `blocked_at: "tool-missing"`。

### 阶段 3：文件系统审计

```bash
# 只列候选文件路径，不输出匹配行或真实秘密
grep -RIlE 'root:|admin:|password|passwd|shadow|telnetd|dropbear|httpd|nvram' "$ROOT/etc" | head -80
find "$ROOT" -type f \( -name 'id_rsa*' -o -name '*.pem' -o -name '*.key' -o -name 'authorized_keys' \) -print
cat "$ROOT/etc/inittab" "$ROOT/etc/init.d/rcS" 2>/dev/null
grep -RInE 'system\(|popen\(|execve\(' "$ROOT/www" "$ROOT/usr/lib/lua" 2>/dev/null | head -40
```

完成判据：能画出“开机 → 服务 → 运行用户 → 监听地址 → 可控参数”，每跳有 `文件:行号`；
敏感项只记位置、类别与配置/调用数据流，不读取后散列脱敏；可用性仅合成 canary 证明。
失败判据：只有敏感候选而无入口/引用链；合成测试凭据无法登录；启动脚本指向的服务不监听且无日志解释。

### 阶段 4：仿真或真机验证

```bash
# qemu-user（单程序）
sudo chroot "$ROOT" /usr/bin/qemu-mipsel-static /bin/sh -c 'id'
# qemu-system（整机，示意；参数按镜像调整）
qemu-system-mipsel -M malta -kernel vmlinux -hda rootfs.img \
  -append "root=/dev/sda console=ttyS0" -nographic
# 服务验证（J2）
ss -lntp; ps w | grep -E 'httpd|uhttpd|cgi'; curl -i http://127.0.0.1:80/
```

完成判据：J1 有 shell 会话；J2 端口+进程+真实业务响应；J3 可重复 PoC。
失败判据：内核 panic/根挂载失败/架构错；服务启动即退出 → 补桩或转真机只读；
端口通但 502/静态页 → 不算 J2。

### 阶段 5：硬件接口（UART → JTAG → SPI）

```text
USB-TTL GND -> 板 GND（必须）
USB-TTL RX  -> 板 TX（交叉）
USB-TTL TX  -> 板 RX（交叉）
USB-TTL VCC -> 不接（除非电压一致且明确需要）
```

常用波特率：115200（最常见）、57600、38400、9600；8N1，无流控。
完成判据：UART 落到 `#`/`$` 或改到 `bootargs`；JTAG 识别 SoC 且读回哈希一致；
SPI 两次读取 SHA256 一致。
失败判据：无输出/乱码 → 先量电压/共地、交换 TX/RX、换波特率；
仍不行 → 静态分析 + 仿真，不反复焊。

### 阶段 6：UEFI / 裸 blob（可选分支）

```bash
python Tool/skill/firmware-iot/scripts/fw-repro.py --file SecConfig.efi --json
binwalk SecConfig.efi | head -20
uefi-firmware-parser -b -o work/fv fw.bin     # 有 FV 时
chipsec_util uefi var-list                    # 授权主机，只读
```

完成判据：PE/FV/变量/签名链至少两类证据自洽；版本/FWID 可复算。
失败判据：只有单个 PE；FV 解析不出；变量读不到 → 记 `blocked_at`，不写“Secure Boot 可绕过”。

### 阶段 7：交付与验收

```bash
python Tool/skill/firmware-iot/scripts/fw-accept.py
python Tool/scripts/domain-gate.py --domain firmware-iot
```

完成判据：案例字段/hash/refs 全 PASS；报告里写清「做到哪一步」用的是四句话中的哪一句（内部档位只进账本），以及证据在哪。
失败判据：`fw-accept` 报 hash mismatch/phantom ref → 重跑产物，不改 JSON 哈希。

## 七、参考索引（逐篇）

| 文件 | 用途 |
|---|---|
| `references/01-criteria.md` | 判据表：场景/输入面/可机检判据/证据形态/误报风险；E0–E3 分级；§5 判定会、§6 评分样例 |
| `references/02-failure-criteria.md` | 失败判据：现象/判定/改走哪条/代价（≥14 行）；§失败归因五问、§时窗、§lessons |
| `references/03-model-pitfalls.md` | 21 条模型常见失误：错误动作→为什么错→正确动作；§纠偏命令 |
| `references/04-walkthrough-uefi-efi.md` | 真实走查：SecConfig.efi + Broadcom rtecdc.bin，含原始输出与复跑命令；§8 最短路径 |
| `references/05-uefi-and-secure-boot.md` | UEFI PE/TE、固件卷、PK/KEK/db/dbx、TPM 度量、更新包回滚；§9 12 项判据、§10 event log 重放 |
| `references/06-container-carving-and-entropy.md` | strong/weak 魔术、熵解读、厂商头切分、Broadcom 误报案例；§8 两样本差分、§9 weak 二次确认 |
| `references/firmware-unpack.md` | 解包主参考：获取/容器/解包/仿真/交付清单；§9 端到端走查（时间盒） |
| `references/filesystem-and-credentials.md` | rootfs 审计：账号、shadow、私钥/证书、启动链、服务入口；认证数据流与合成证据、NVRAM/overlay |
| `references/emulation-and-fuzz.md` | qemu-user/system、FirmAE、NVRAM/`/dev` 桩、fuzz 接线；§11 环境/依赖/时序三类失败 |
| `references/hardware-interfaces.md` | UART/JTAG/SPI 接线、电压、波特率、IDCODE、恢复路线；无线/近场（802.11 握手·PMKID·WPA3·企业级·WPS、BLE、802.15.4、Z-Wave、sub-GHz/LoRaWAN、NFC）判据表与失败判据；**无线能力按 §八的 `tool-acquire.py --tool <tool_id> --json` 逐项探活** |

矩阵：`Tool/config/firmware-iot-matrix.json`（14 条，match/criteria/fail/tools/pitfalls）。
路由片段：`Tool/skill/firmware-iot/pack.json`（词边界，避免抢 Web/APK 词）。

## 八、脚本用法

```bash
# 分诊：魔术/熵/脱敏凭据线索/建议命令（只读，不执行样本）
python Tool/skill/firmware-iot/scripts/fw-triage.py --file fw.bin --json > work/triage.json

# 切分+解包+rootfs 证据：stdlib 优先，外部工具次之；缺工具 blocked_at=tool-missing
python Tool/skill/firmware-iot/scripts/fw-repro.py --file fw.bin \
  --out-dir work/fw-repro --json > work/repro.json

# 案例验收：字段/evidence_kind/hash 复算/refs/lessons[0] rc=
python Tool/skill/firmware-iot/scripts/fw-accept.py --json

# 无线/近场能力枚举：WiFi monitor / 蓝牙 / SDR / 802.15.4 / NFC（只读，≤10s，不需要 --target）
# 输出 probes[name=radio]：wifi/bluetooth/subghz/nfc + blocked_at（no-monitor-mode|no-radio|no-wifi|…）
python Tool/scripts/tool-acquire.py --tool <tool_id> --json   # 逐工具探活（无批量开关）
python Tool/scripts/tool-acquire.py --selftest   # 离线自检：只测判定/解析函数，无硬件访问

# 三个脚本都有离线自检（rc=0，最后一行含 "ok": true）
python Tool/skill/firmware-iot/scripts/fw-triage.py --self-test
python Tool/skill/firmware-iot/scripts/fw-repro.py --self-test
python Tool/skill/firmware-iot/scripts/fw-accept.py --self-test
```

失败行为：`{"ok": false, "blocked_at": "<input|tool-missing|extract>", "reason": "..."}`，rc=1/2；
不抛裸栈。路径由 `--root`/`__file__` 推导，不依赖宿主 HOME；诊断中的路径只反映实际传入的
`--file`/`--root` 或推导出的运行根。

## 九、任务卡入口

- 24 张任务卡：`Tool/prompts/domains/firmware-iot.md`（源技能名取自
  `Tool/config/taskcard-sources.json` 的 `firmware-iot`）。
- 用法：按触发词选卡 → 照“步骤”跑 → 用“判据/失败判据”决定继续或换路线 → 在
  `reference` 指向的文件里找完整命令。

## 十、KB board 入口

- `Tool/mcp/Tool/reverselab/kb/firmware-iot/README.md`
- 技术页：`techniques/01-unpack-and-filesystem.md`、`02-uart-and-emulation.md`、
  `03-ota-and-signature.md`、`04-uefi-secureboot.md`、`05-container-carving.md`、
  `06-failure-criteria.md`。

## 十一、边界

- **不是 APK**：Android 应用/DEX/SO 走 `apkseep`；本技能只处理设备固件与嵌入式 rootfs。
- **不是 PE 算法题**：桌面 PE/.NET/普通 ELF 走 `softseep`；UEFI 组件只做固件判据。
- **不是纯 Web**：只测云端 API/前端时走 Web 技能；本技能的网络验证仅围绕设备自身服务。
- **硬件接入范围由 `scope` 声明**：设备清单由用户提供，清单内按任务执行；闪存写入按授权单。
- **“解包即成功”是误判**：有 shell/服务/漏洞证据才算完成，否则只算侦察。
- 硬件操作先备份、先量电压、先共地；写操作只在授权且可恢复的设备上做。
- 所有结论标明 E0–E3 与 J1/J2/J3；未验证项写“未验证”，不臆造。

## 子技能（按需读，不常驻）

本域相关子技能放在 `subskills/` 目录中（按需读取，零预载）：
当前由主域 SOP 统一覆盖，保留标准槽位供后续细分子技能敏捷挂载。
