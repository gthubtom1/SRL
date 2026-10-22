---
name: firmware-iot
description: 【固件/IoT/硬件】路由器、摄像头、NAS、嵌入式设备的固件获取、解包、文件系统审计、QEMU/FirmAE 仿真、UEFI/Secure Boot 与 UART/JTAG/SPI 硬件接入。以“能进 shell、能跑起关键服务、能复现漏洞”为硬判据，覆盖 OTA/闪存/UART dump、binwalk/ubireader/unsquashfs、凭据与启动脚本、容器切分与熵、引脚与波特率判断，并给出缺工具时的结构化降级。
license: MIT
compatibility: Linux 主机优先（binwalk/ubireader/unsquashfs/QEMU 原生）；Windows 可经 WSL2 或 Tool/scripts/tool-run.ps1 启动外部工具。硬件侧需 USB-TTL、逻辑分析仪、SPI 编程器/夹子，电压匹配 1.8V/3.3V。
metadata:
  version: "2.0.0"
  category: firmware-iot
  hard_gates: "只读备份 / 先判芯片与接口 / 上电前量电压 / 设备与镜像清单由 scope 声明 / 三判据闭环"
---

# firmware-iot — 固件 / IoT / 硬件接入

> 只回答一件事：**这份固件或这台设备，能不能拿到可分析的文件系统、跑起关键服务、并复现一个可验证的问题。**
> 不把“解包成功”当成功，也不把“仿真起内核”当成功；判据见第三节，失败分流见第四节。
> 仅对自有或明确授权的设备/固件操作。上电、短接、写闪存都可能变砖，先备份再动手。

---

## 一、范围与路由（边界）

**本域输入面**

- 路由器、交换机、摄像头、NVR、NAS、打印机、智能家居、工控网关等**嵌入式 Linux/RTOS 固件**。
- 厂商 OTA 包、官网下载固件、SPI/NAND/eMMC 闪存镜像、UART/U-Boot 转储。
- UEFI 固件组件：`.efi`、固件卷（FV）、Secure Boot 变量、TPM 度量。
- 裸 firmware blob：Broadcom `BRCM`/TRX/uImage/单 PE/ELF（只做格式与版本判据）。
- 目标问题：默认/硬编码凭据、私钥与证书、启动脚本提权、Web/CGI 命令注入、
  未授权接口、调试口暴露、OTA 签名缺失、Secure Boot 策略缺陷。

**相邻域与路由**

- APK/AAB、DEX/SO、重打包 → `apkseep`。
- 桌面 PE/ELF 算法题、纯逆向 → `softseep` / `ida-reverse` / `binary-diff`。
- 纯云 API/前端 → `web-pentest`；内网身份 → `ad-cloud`。
- 第三方设备/网段/闪存写入清单由 `scope` 声明，清单内按任务执行。
- 把“解包成功”“FirmAE success”“binwalk 识别出 12 个签名”当作交付。

## 二、前置检查（3 件，缺一停）

1. **授权与归属**：设备/固件属于自己或书面授权范围；明确测试窗口与回滚清单。
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
| 账号可用（J1） | 空/弱口令或已破解 hash，且完成一次登录，会话输出 `id` | 只有 hash/字符串，没有登录入口 | 登录会话/串口录屏 + `awk` 输出 |
| 服务可用（J2） | 端口监听 + 进程 + **真实业务响应** 同一时刻 | 进程在但端口不通/502/只有静态页 | `ss -lntp` + `ps` + `curl -i` 原文 |
| 漏洞复现（J3） | 同一输入重复 ≥2 次一致；有请求/响应/日志/崩溃现场 | 字符串/版本猜测；“仿真里可能” | PoC + 两次运行日志 + 版本/配置 |
| 凭据/密钥 | 私钥与证书配对，且设备/云/OTA 实际接受 | 只有 `.pem/.key` 文件或示例占位符 | `openssl` 指纹 + 用途 + 验证命令 |
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
| 只有 shadow hash、无登录入口 | 凭据未破解 | 记录素材；转接口绕过/串口 shell；不写“弱口令” |
| `passwd` 第二字段 `x` / shadow `!` | 不是空口令/被锁定 | 同时读 passwd+shadow；找 NVRAM/云账号/authorized_keys |
| 仿真进程在但端口无业务回包 | 不是 J2 | 补 NVRAM/`/dev`/Web 根桩；或转真机只读 |
| 漏洞只在字符串/版本号 | 不是 J3 | 黑盒测绘/动态跟踪/最小 PoC；两次一致才算 |
| 裸 blob（BRCM/TRX/单 PE） | 无 rootfs | 走 `06-container-carving-and-entropy.md`，不套文件系统判据 |
| 同一手法连续 2 次失败 | 路线不通 | 换路线或汇报；不在真机反复写 |

## 五、模型常见失误（≥8 条）

> 完整 12 条与“错误动作→为什么错→正确动作”见 `references/03-model-pitfalls.md`。

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
python Tool/scripts/fw-triage.py --file "$OUT/orig.bin" --json > "$OUT/triage.json"
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
grep -RInE 'root:|admin:|password|passwd|shadow|telnetd|dropbear|httpd|nvram' "$ROOT/etc" | head -80
find "$ROOT" -type f \( -name 'id_rsa*' -o -name '*.pem' -o -name '*.key' -o -name 'authorized_keys' \) -print
cat "$ROOT/etc/inittab" "$ROOT/etc/init.d/rcS" 2>/dev/null
grep -RInE 'system\(|popen\(|execve\(' "$ROOT/www" "$ROOT/usr/lib/lua" 2>/dev/null | head -40
```

完成判据：能画出“开机 → 服务 → 运行用户 → 监听地址 → 可控参数”，每跳有 `文件:行号`；
凭据/密钥有路径、指纹、用途（脱敏）。
失败判据：只有 hash 无入口；私钥无法配对；启动脚本指向的服务不监听且无日志解释。

### 阶段 4：仿真或真机验证

```bash
# qemu-user（单程序）
sudo chroot "$ROOT" /usr/bin/qemu-mipsel-static /bin/sh -c 'id; cat /etc/passwd'
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

完成判据：案例字段/hash/refs 全 PASS；报告写清 J1/J2/J3 中了哪条、证据在哪。
失败判据：`fw-accept` 报 hash mismatch/phantom ref → 重跑产物，不改 JSON 哈希。

## 七、参考索引（逐篇）

| 文件 | 用途 |
|---|---|
| `references/01-criteria.md` | 判据表：场景/输入面/可机检判据/证据形态/误报风险；E0–E3 分级 |
| `references/02-failure-criteria.md` | 失败判据：现象/判定/改走哪条/代价（≥14 行） |
| `references/03-model-pitfalls.md` | 12 条模型常见失误：错误动作→为什么错→正确动作 |
| `references/04-walkthrough-uefi-efi.md` | 真实走查：SecConfig.efi + Broadcom rtecdc.bin，含原始输出与复跑命令 |
| `references/05-uefi-and-secure-boot.md` | UEFI PE/TE、固件卷、PK/KEK/db/dbx、TPM 度量、更新包回滚 |
| `references/06-container-carving-and-entropy.md` | strong/weak 魔术、熵解读、厂商头切分、Broadcom 误报案例 |
| `references/firmware-unpack.md` | 解包主参考：获取/容器/解包/仿真/交付清单 |
| `references/filesystem-and-credentials.md` | rootfs 审计：账号、shadow、私钥/证书、启动链、服务入口 |
| `references/emulation-and-fuzz.md` | qemu-user/system、FirmAE、NVRAM/`/dev` 桩、fuzz 接线 |
| `references/hardware-interfaces.md` | UART/JTAG/SPI 接线、电压、波特率、IDCODE、恢复路线；无线/近场（802.11 握手·PMKID·WPA3·企业级·WPS、BLE、802.15.4、Z-Wave、sub-GHz/LoRaWAN、NFC）判据表与失败判据 |

矩阵：`Tool/config/firmware-iot-matrix.json`（14 条，match/criteria/fail/tools/pitfalls）。
路由片段：`Tool/config/routing-fragments/firmware-iot.json`（词边界，避免抢 Web/APK 词）。

## 八、脚本用法

```bash
# 分诊：魔术/熵/凭据线索/建议命令（只读，不执行样本）
python Tool/scripts/fw-triage.py --file fw.bin --json > work/triage.json

# 切分+解包+rootfs 证据：stdlib 优先，外部工具次之；缺工具 blocked_at=tool-missing
python Tool/skill/firmware-iot/scripts/fw-repro.py --file fw.bin \
  --out-dir work/fw-repro --json > work/repro.json

# 案例验收：字段/evidence_kind/hash 复算/refs/lessons[0] rc=
python Tool/skill/firmware-iot/scripts/fw-accept.py --json

# 三个脚本都有离线自检（rc=0，最后一行含 "ok": true）
python Tool/scripts/fw-triage.py --self-test
python Tool/skill/firmware-iot/scripts/fw-repro.py --self-test
python Tool/skill/firmware-iot/scripts/fw-accept.py --self-test
```

失败行为：`{"ok": false, "blocked_at": "<input|tool-missing|extract>", "reason": "..."}`，rc=1/2；
不抛裸栈。路径由 `--root`/`__file__` 推导，不含本机绝对路径。

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
- **不是 PE 算法题**：桌面 PE/.NET/普通 ELF 走 `softseep`/`ida-reverse`；UEFI 组件只做固件判据。
- **不是纯 Web**：只测云端 API/前端时走 Web 技能；本技能的网络验证仅围绕设备自身服务。
- **硬件接入范围由 `scope` 声明**：设备清单由用户提供，清单内按任务执行；闪存写入按授权单。
- **“解包即成功”是误判**：有 shell/服务/漏洞证据才算完成，否则只算侦察。
- 硬件操作先备份、先量电压、先共地；写操作只在授权且可恢复的设备上做。
- 所有结论标明 E0–E3 与 J1/J2/J3；未验证项写“未验证”，不臆造。
