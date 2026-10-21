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
