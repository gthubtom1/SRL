# 硬件接口参考（UART / JTAG / SPI）

> 配套 `firmware-iot/SKILL.md`。只对自有或明确授权的设备操作。
> **上电前先量电压、先共地、先备份**；不确定电平时使用电平转换，不把 USB-TTL 的 VCC 接到板上。

## 0. 开板前检查

```text
1. 断电，拍照记录 PCB 丝印、芯片型号、测试点、排针定义。
2. 万用表通断档：确认 GND 测试点与 USB-TTL GND 相通。
3. 上电量 VCC-GND：1.8V / 3.3V / 5V，记录；查 SoC datasheet 确认 IO 电平。
4. 确认存储芯片封装（SOP8/SOP16/TSOP48/BGA/eMMC）与电压。
5. 准备恢复手段：SPI 编程器/夹子、U-Boot TFTP、厂商恢复模式、可替换同型号设备。
```

判据：电压与芯片型号明确；GND 可靠；有可回滚的完整镜像。缺一项就先别焊线。

## 1. 找 UART 焊盘

- 常见布局：4/5 个裸露焊盘一排，丝印 `TX RX GND VCC` 或只标 `J1`。
- 断电通断：GND 与屏蔽罩/电容负极相通；VCC 与稳压输出相通。
- 上电电压：VCC 固定高；TX 在启动瞬间有轻微波动；RX 常被上拉为高。
- 无法确定时用逻辑分析仪/示波器抓启动瞬间，找周期性方波（TX）。
- 判据：找到 **GND + 一个待定 TX + 一个待定 RX**，且待定脚电压不超过 IO 电平。

## 2. UART 接线与串口

```text
USB-TTL GND  -> 板 GND          （必须）
USB-TTL RX   -> 板 TX           （交叉）
USB-TTL TX   -> 板 RX           （交叉）
USB-TTL VCC  -> 不接            （除非明确需要且电压一致）
```

```bash
# Linux
ls -l /dev/serial/by-id/
picocom -b 115200 -8 -n -l /dev/ttyUSB0
# 或
screen /dev/ttyUSB0 115200
# 记录原始日志
python - <<'PY'
import serial, sys, time
s = serial.Serial('COM3', 115200, timeout=0.2)  # Windows 示例
end = time.time() + 30
while time.time() < end:
    data = s.read(4096)
    if data: sys.stdout.buffer.write(data); sys.stdout.flush()
PY
```

- 参数：**8N1、无流控**；波特率依次试 `115200 → 57600 → 38400 → 9600`。
- 打开串口后给设备**重新上电**，抓完整启动日志；启动时连按回车、`Ctrl-C`、`Esc`、`x` 尝试中断 U-Boot。
- 判据：日志可读（非乱码），能看到 U-Boot/内核行，最终出现 `#`、`$`、`login:` 或 U-Boot 提示符。
- 乱码但字符有规律：波特率不对；完全无输出：TX/RX 接反、GND 未共、焊盘不是 UART、或控制台被关闭。
- 只有输出不能输入：只接了 TX，补 RX；或 RX 被其他外设占用。

### 2.1 常见 U-Boot 中断与利用

```text
# 启动瞬间发送，提示符可能是 =>
U-Boot> printenv
U-Boot> setenv bootargs ${bootargs} init=/bin/sh
U-Boot> boot
# 或读闪存到内存后 tftp 回传
U-Boot> sf probe 0; sf read 0x80000000 0x50000 0x200000
U-Boot> tftpboot 0x81000000 dump.bin
```

判据：能修改 `bootargs` 并进入单用户/`init=/bin/sh`；或成功把分区传到主机且长度/校验一致。
注意：`init=/bin/sh` 可能因只读根、看门狗、服务缺失而不稳定；失败时改回原 `bootargs`。

### 2.2 UART 登录判据

- 有账号密码：先试固件里找到的默认/硬编码凭据（`/etc/passwd`、`/etc/shadow`、NVRAM 默认值）。
- 无密码提示：可能直接是 root shell，记录提示符与 `id` 输出。
- 登录后先只读采集：`cat /proc/cpuinfo`、`cat /proc/mtd`、`mount`、`ps w`、`netstat -lntp`。
- 判据：拿到交互 shell，并能执行 `id`/`uname -a`；这才是 J1 成立。

## 3. JTAG / SWD

| 信号 | 常见丝印 | 说明 |
|---|---|---|
| TCK/SWCLK | TCK, CLK | 时钟 |
| TMS/SWDIO | TMS, DIO | 模式/数据 |
| TDI | TDI | 数据输入（JTAG） |
| TDO/SWO | TDO, SWO | 数据输出 |
| TRST | TRST | 复位（常可省） |
| GND/VREF | GND, VCC | 必须共地；VREF 用于电平检测 |

```bash
# 先扫描 IDCODE，确认 TAP 链；interface 按编程器改（ftdi/ft2232/jlink/stlink）
openocd -f interface/ftdi/ft2232.cfg \
  -c "adapter speed 1000; transport select jtag; scan_chain" \
  -c "shutdown"

# 命中后按 SoC 选 target cfg
openocd -f interface/ftdi/ft2232.cfg -f target/<soc>.cfg \
  -c "init; halt; flash banks; flash read_bank 0 dump.bin 0 0x1000000; shutdown"
```

判据：`scan_chain` 出现预期 IR/IDCODE；`halt` 后能读寄存器/内存；`flash read_bank` 的长度与闪存容量一致。
扫不到 IDCODE：检查 VREF/GND、TCK 速率（先降到 100–500 kHz）、引脚定义、SoC 是否关闭 JTAG、是否需要上电时序。

## 4. SPI 闪存读取

| 引脚 | 常见丝印 | 连接 |
|---|---|---|
| CS# | CS, CE# | 片选 |
| CLK | CLK, SCK | 时钟 |
| MOSI | DI, SI | 主机 → 芯片 |
| MISO | DO, SO | 芯片 → 主机 |
| VCC/GND | VCC, GND | 1.8V/3.3V 严格匹配 |

```bash
# 板上夹子直读（先断电，或按芯片要求）
flashrom -p ch341a_spi -r spi-1.bin
flashrom -p ch341a_spi -r spi-2.bin
sha256sum spi-1.bin spi-2.bin

# 识别芯片
flashrom -p ch341a_spi --flash-name

# 写回只在有完整备份且确认电压后做
# flashrom -p ch341a_spi -w restore.bin
```

判据：两次读取哈希一致；`--flash-name` 与丝印一致；镜像首部有预期的 U-Boot/固件签名。
板上直读失败/数据漂移：SoC 仍在驱动总线，需断电、按住复位、或焊下芯片；1.8V 芯片必须用 1.8V 适配器，否则可能损坏。

## 5. 逻辑分析仪辅助

```bash
# 例：sigrok/PulseView CLI，采样率至少 4× 波特率
sigrok-cli -d <driver>:conn=/dev/ttyACM0 --config samplerate=1m \
  --channels D0,D1 --time 2s -o uart.sr
```

- 用途：确认 TX 波特率、找 JTAG 时钟、看 SPI 片选时序。
- 判据：能测出位宽并反推波特率（`baud ≈ 1 / 位宽`），或看到 SPI 读命令 `0x03/0x0B`。

## 6. 变砖与恢复

1. **先恢复供电与串口**，确认 U-Boot 是否仍启动；有 U-Boot 就有 TFTP/USB 恢复机会。
2. U-Boot 可用：`tftpboot` + `sf write`/`nand write` 写回备份；先擦除再写，注意分区偏移。
3. U-Boot 不可用：SPI 夹子/编程器写回完整备份；NAND 需处理坏块与 OOB。
4. 写回后校验：`sha256sum` 与备份一致，串口日志恢复，关键服务可访问。
5. 判据：设备恢复原状或达到预期状态；恢复过程与命令写入报告。

## 7. 接口选择速查

| 目标 | 首选 | 次选 | 风险 |
|---|---|---|---|
| 拿 shell | UART | 固件仿真 + 默认凭据 | 接错电压烧 SoC |
| 读全片 | SPI 编程器 | JTAG + flash read | 夹子接触不良、1.8V 混接 |
| 改启动参数 | UART + U-Boot | JTAG halt | 写坏环境变量 |
| 动态调试服务 | 真机 shell / QEMU | gdbserver + qemu | 看门狗复位 |
| 恢复 | SPI 写回 | U-Boot TFTP | 分区偏移写错 |

## 8. 验收清单

- [ ] 电压、GND、引脚定义有照片/记录；USB-TTL 电平匹配。
- [ ] UART 日志完整，能复现登录/中断 U-Boot；或明确记录失败现象与下一步。
- [ ] JTAG IDCODE / SPI 芯片型号与容量有输出；两次读取哈希一致。
- [ ] 原始镜像与恢复镜像均有 SHA256；写操作有回滚方案。
- [ ] 真机只做授权范围内的只读/低影响验证；未造成不可逆损坏。

## 无线与近场（802.11 / BLE / 802.15.4 / Z-Wave / sub-GHz）

> 位置：`firmware-iot` 的物理层延伸。固件解包告诉你"设备信任谁"，无线侧告诉你"这层信任能不能从空中打掉"。
> 硬件前提写在每节开头：没有对应硬件就**明确记 `blocked_at=no-radio`**，不许用"理论上可以"冒充已验证。

### 0-A. 先跑本机能力探针（先确认"能不能做"，再谈"怎么做"）

本章所有判据都依赖射频硬件。动手前先花 10 秒问一句：**这台机器现在有哪几样仪器？**

```bash
python `probe_matrix`（S4 已删：一次性） --radio-only --json                  # ≤10s，不需要 --target
python `probe_matrix`（S4 已删：一次性） --radio-only --out work/<case>/radio.json
python `probe_matrix`（S4 已删：一次性） --self-test                          # 离线自检：只测判定/解析函数，无硬件访问
```

探针只做能力枚举：**不进入 monitor mode、不调用主动扫描、不发送任何射频、不改网卡状态**，
缺命令/缺权限/超时都返回结构化 `blocked`，不抛裸栈。结果挂在探针矩阵的
`probes[name=radio]` 里（与 baseline/external/network 同一份 JSON）。

| 字段 | 含义 |
| :-- | :-- |
| `wifi` | `{present, monitor_capable, iface, adapters}`；`monitor_capable=false/true/null` 三态，`null` = 未判定（不是不支持） |
| `bluetooth` | `{present, adapters, stack}`；`present` 只认适配器/控制器，枚举器与服务设备不算 |
| `subghz` | SDR / sub-GHz / 802.15.4 / BLE sniffer 的 USB VID:PID 命中（RTL-SDR `0bda:2838`、HackRF `1d50:6089`、CC2531 `0451:16a8`、nRF52 `1915:520f` 等） |
| `nfc` | Proxmark3 `9ac4:4b8f`、ACR122U `072f:2200`、PN533 `04cc:2533` 等读卡器命中 |
| `blocked_at` / `reason` | 卡在哪一步 + 人话原因（见下表） |
| `read_only` | 恒为 `true`：本探针不做任何模式切换或发射 |

`blocked_at` 取值与处置：

| `blocked_at` | 含义 | 改走哪条 / 代价 |
| :-- | :-- | :-- |
| `null` | 至少一条 802.11 monitor 路径可用 | 按 §1 做抓包/握手；仍先确认授权与 WIPS 观测 |
| `no-monitor-mode` | 有 WiFi，但平台/驱动没有 monitor mode（Windows 原生 NDIS 最常见） | 外置可 monitor 网卡（AR9271/RTL8812AU/MT7612U）+ Linux 侧或专用驱动；否则 802.11 判据记不可用 |
| `monitor-unverified` | 有 WiFi，但当前手段判定不了 monitor | Linux 装 `iw` 后重跑；macOS/受限驱动换外置卡；未判定 ≠ 不支持 |
| `no-wifi` | 只有 BLE/SDR/802.15.4/NFC，没有 WiFi | 802.11 路线记不可用，转 §2/§3/§4 的近场路线 |
| `no-radio` | 一张无线/近场硬件都没有 | 本章全部判据记 `blocked_at=no-radio`，转固件侧/有线侧或外接适配器 |
| `command-missing` | 枚举命令缺失（`iw`/`iwconfig`/`lsusb`/`hciconfig`…） | 装 iproute2+iw+usbutils+bluez 后重跑；**缺命令不等于没硬件** |
| `no-permission` | 枚举被拒（需 root/管理员） | 提权会话重跑；探针本身仍只读 |
| `timeout` | 10s 预算内没枚举完 | 拆开重跑/降低负载；不得写成"无硬件" |
| `probe-error` | 探针内部异常 | 看 `commands`/`evidence` 排查；不代表目标不可分析 |

两条使用纪律：

1. **枚举到 ≠ 能打**：`present=true` 只说明接口在场。BLE 能不能注入、网卡能不能注入、NFC 能不能克隆，都要另做验证（见各节判据）。
2. **结论要带 `radio.json`**：报告里写清网卡型号/`iface`/`monitor_capable`/`blocked_at`，否则别人复跑不出来。

### 0. 判据总表（先看这张，再决定动不动硬件）

| 场景 | 输入面 | 可机检判据（PASS 长什么样） | 证据形态 | 误报风险 |
| :-- | :-- | :-- | :-- | :-- |
| WPA2-PSK 口令强度 | AP 的 4 次 EAPOL 握手 **或** PMKID | `hashcat -m 22000` 返回 `Status: Cracked`；或 `aircrack-ng` 显示 `KEY FOUND` | `.hc22000` + crack 输出 + 时间戳 | 抓到的是不完整握手（缺 M1/M2）→ 必然"跑不出"，不算口令强 |
| PMKID 可获取性 | AP 的 RSN IE（`RSN PMKID` 支持） | `hcxdumptool` 输出 `PMKID` 行且长度 32 hex | `.pcapng` + PMKID 十六进制 | AP 不返回 PMKID 不代表口令强，只说明该路径不可用 |
| WPA3-SAE 降级 | 过渡模式（WPA2/WPA3 混合） | 能连到 WPA2 侧且与 WPA3 侧同口令 → 降级成立 | 两次关联的 assoc 帧 + 同一 PSK 验证 | 纯 WPA3 网络无降级面，判 `na` |
| WPA-Enterprise 凭据 | EAP 类型 = PEAP/MSCHAPv2 | `asleap`/`hashcat -m 5500` 拿到明文口令 | 挑战/响应 `challenge:response` 对 + crack 输出 | EAP-TLS 只有证书，无口令可破 → 记 `blocked_at=mutual-tls` |
| WPS PIN | AP 开启 WPS 且 `WSC IE` 可读 | `reaver` 显示 `WPS PIN: '12345670'` 或 Pixie Dust 在 ≤60s 出 PSK | `reaver` 日志 + 出 PIN 时间 | 锁定（`WPS Locked: Yes`）→ 只能等冷却或判不可用 |
| BLE 未授权写 | GATT 服务的可写 characteristic | 无配对状态下 `gatttool -b <MAC> --char-write-req -a <HANDLE> -n <VAL>` 返回成功 | ATT Write 响应 + 设备侧状态变化截图 | 写成功但设备忽略值 → 只算"接口可达"，不算"控制成立" |
| BLE 配对降级 | 配对特性（Just Works / 无 MITM 保护） | 中间人配对成功且两端不报错 | 两段配对日志 + 时间线 | 需要同时具备两块可注入的射频，缺一记 `blocked` |
| Zigbee/Thread 入网密钥 | 抓到的 802.15.4 帧（入网交互） | 从 Transport Key 帧解出 NWK Key，能解出后续加密载荷 | 解密后的明文 APS 帧 | 用默认 TC Link Key（ZigbeeAlliance09）解不开 → 目标已换 key，改走 sniff-after-join |
| Z-Wave S0/S2 | 配对过程中的帧 + 设备 DSK | S0：解出 `Network Key`；S2：DSK 校验通过 | 抓包 + 解密后的命令帧 | S2 带 DSK 的可信配对不可破 → 判 `na` |
| sub-GHz / LoRaWAN 重放 | 固定码遥控 **或** ABP 会话 | 重放后设备执行同一动作；ABP 帧计数器未单调 → 可重放 | 两次抓包 + 设备动作 | OTAA 每次入网换密钥 → 重放无效，改走 `Join-Accept` 重放 |
| NFC/RFID 克隆 | 卡片 UID + 扇区数据 | 克隆卡在原设备上通过校验（门禁开、消费成功） | dump 文件 + 现场验证记录 | 只读 UID 的门禁克隆 UID 即可；带加密扇区的要密钥 |

### 1. 802.11：从"能抓"到"能证"

硬件：支持 monitor mode + 包注入的网卡（ath9k_htc / MT7612U 一类）；`iw dev` 能看到 `type monitor` 才算可用。

```bash
## 1) 进入监听（先确认接口名与信道）
sudo airmon-ng start wlan0
sudo airodump-ng wlan0mon --band abg -w work/<case>/scan

## 2) 定向抓握手（BSSID 与信道从 scan 结果取）
sudo airodump-ng wlan0mon --bssid <BSSID> -c <CH> -w work/<case>/cap

## 3) 主动踢一次以催握手（会留痕，先确认授权与 WIPS 情况）
sudo aireplay-ng --deauth 3 -a <BSSID> -c <CLIENT> wlan0mon

## 4) 转 hashcat 格式并离线跑（本机不做在线爆破）
hcxpcapngtool -o work/<case>/hs.hc22000 work/<case>/cap-01.cap
hashcat -m 22000 work/<case>/hs.hc22000 <WORDLIST> --status --status-timer 10
```

判定要点：
- **握手完整性**：`hcxpcapngtool` 输出里 `EAPOL pairs written to 22000 hash file` 必须是 1 以上；为 0 就是没抓到可用握手。
- **PMKID 与握手是两条独立路径**：PMKID 不需要客户端在场，优先试。
- **WPA3 纯模式**：SAE 的 `Commit/Confirm` 交换无法离线爆破，只能走"过渡模式降级"或"客户端侧漏洞"，不要把 SAE 抓包当 WPA2 握手去跑 hashcat。

### 2. BLE / Classic：先枚举，再验证"有没有鉴权"

硬件：CSR4.0 / nRF52 一类可注入的适配器；`bluetoothctl` + `gatttool`/`bettercap` 足够做枚举。

```bash
## 枚举 + 读 GATT
sudo bettercap -iface hci0 -eval "ble.recon on"
gatttool -b <MAC> --primary
gatttool -b <MAC> --characteristics

## 关键验证：未配对状态下能不能写
gatttool -b <MAC> --char-write-req -a <HANDLE> -n <HEX_VALUE>
```

判定要点：**"写成功"只证明 ATT 层没鉴权，必须再确认设备侧行为变化**（锁开、灯亮、状态位翻转）。只写成功不改行为 → 记 `hypothesis`，不记 proven。
Classic（SPP/HFP）走 `sdptool browse <MAC>` 看服务面；配对降级看是否接受 `Just Works`。

### 3. 802.15.4（Zigbee / Thread）

硬件：CC2531/CC2652 + `zigbee2mqtt` 或 `whsniff` + Wireshark 的 Zigbee 解析器。

判定要点：
- 抓 `Transport Key` 帧解 NWK Key：只有拿到 key 之后解出的 APS 载荷才算证据。
- 默认 TC Link Key（`ZigbeeAlliance09`）能解开入网交互 → 说明用的是默认信任锚，可直接推出网络密钥。
- 解不开 → 目标已启用自定义 link key，改走"入网后嗅探 + 已知明文攻击"或转固件侧找 key（`references/filesystem-and-credentials.md`）。

### 4. Z-Wave / sub-GHz / LoRaWAN

- Z-Wave：Zniffer 抓配对帧；S0 的 `Network Key` 随 `Security Scheme 0` 帧以固定异或流下发，可离线解；S2 带 DSK 的可信配对基本不可破，判 `na`。
- sub-GHz（315/433/868/915）：先判"固定码还是滚动码"——连续两次按下抓到的码相同 = 固定码，重放成立；不同 = 滚动码，需要 `RollJam` 类双向压制，代价高。
- LoRaWAN：ABP 会话固定，帧计数器（FCnt）不增即重放成立；OTAA 每次入网新密钥，只能打 `Join-Accept` 重放或设备端漏洞。

```bash
## sub-GHz 固定码对照
hackrf_transfer -r work/<case>/press1.iq -f <FREQ_HZ> -s 1000000 -n 4000000
hackrf_transfer -r work/<case>/press2.iq -f <FREQ_HZ> -s 1000000 -n 4000000
## 两次样本比特流一致 → 固定码；不一致 → 滚动码
```

### 5. 失败判据（现象 → 判定 → 改走哪条 → 代价）

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| `hcxpcapngtool` 输出 0 组 EAPOL，PMKID 也为空 | 抓包面不成立 | 换注入位置/换网卡；或改客户端侧（已控主机上读 `wpa_supplicant.conf`） | 需物理靠近或已控端点 |
| hashcat 跑满字典无结果 | 口令不在字典内 | 换规则/掩码（`-a 3`）；或判"口令强度足够"并停 | 算力与时间，可能数天 |
| WPS `Locked: Yes` | AP 侧锁定 | 等冷却窗口（通常 60s–数小时）；或放弃 WPS 路线 | 时间不可控 |
| BLE 写 characteristic 返回 `Insufficient Authentication` | 有鉴权 | 先解配对（Just Works 可 MITM）；或走固件侧找配对逻辑 | 需双射频 |
| 802.15.4 抓不到 Transport Key | 设备已入网且不回放入网帧 | 等重新入网/断电重启；或改固件侧取 key | 需触发条件与窗口 |
| Z-Wave S2 + DSK | 可信配对 | 判 `na`，转设备端或云端接口 | 无解，止损 |
| NFC 扇区读失败 | 扇区受密钥保护 | 已知密钥字典 / 嵌套攻击 / 转读卡器侧 | 需额外硬件与时间 |
| 任何无线电操作被 WIPS 告警或目标侧断网 | 已产生可观测痕迹 | 停手、记录时间点、回报用户 | 授权与 OPSEC 风险 |

### 6. 模型常见失误（本节专治"看起来很懂"）

1. **把"抓到包"当"破解成功"**：没有 `KEY FOUND`/`Status: Cracked` 就不算，抓包只是输入面。
2. **PMKID 拿不到就断言口令强**：只说明该 AP 不返回 PMKID，握手路径可能仍然可打。
3. **拿 WPA3 抓包喂 hashcat -m 22000**：SAE 不是 PSK，跑不出来不是字典问题。
4. **BLE 写成功就宣布"未授权控制"**：必须补设备侧行为证据。
5. **用默认 TC Link Key 解不开就判"加密不可破"**：可能是自定义 key，固件里常有。
6. **忽略痕迹**：deauth、WPS 爆破、BLE 泛洪都会被 WIDS/终端日志记录，动手前先确认授权范围与可观测性。

### 7. 与固件侧的接合点

- 无线侧拿到的是"空中接口信任模型"；固件侧（`references/filesystem-and-credentials.md`）拿到的是"设备内部信任锚"（预置 PSK、link key、云 token）。
- 两边结论冲突时，以**可复现的那一侧**为准：能重放出动作的算 proven，只在固件里看到常量算 hypothesis（可能未被使用）。
- 交付时把射频条件写清：网卡型号、信道、距离、是否注入、是否触发告警——否则别人复跑不出来。
