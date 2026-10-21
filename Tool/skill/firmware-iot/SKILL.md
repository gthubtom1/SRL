---
name: firmware-iot
description: 【固件/IoT/硬件】路由器、摄像头、NAS、嵌入式设备的固件获取、解包、文件系统审计、QEMU/FirmAE 仿真与 UART/JTAG/SPI 硬件接入。以“能进 shell、能跑起关键服务、能复现漏洞”为硬判据，覆盖 OTA/闪存/UART dump、binwalk/ubireader/unsquashfs、凭据与启动脚本、引脚与波特率判断，并给出缺工具时的降级路线。
license: MIT
compatibility: Linux 主机优先（binwalk/ubireader/unsquashfs/QEMU 原生）；Windows 可经 WSL2 或 Tool/scripts/tool-run.ps1 启动外部工具。硬件侧需 USB-TTL、逻辑分析仪、SPI 编程器/夹子，电压匹配 1.8V/3.3V。
metadata:
  version: "1.0.0"
  category: firmware-iot
  hard_gates: "只读备份 / 先判芯片与接口 / 上电前量电压 / 不碰第三方设备 / 三判据闭环"
---

# firmware-iot — 固件 / IoT / 硬件接入

> 只回答一件事：**这份固件或这台设备，能不能拿到可分析的文件系统、跑起关键服务、并复现一个可验证的问题。**
> 不把“解包成功”当成功，也不把“仿真起内核”当成功；判据见第三节。
> 仅对自有或明确授权的设备/固件操作。上电、短接、写闪存都可能变砖，先备份再动手。

---

## 一、适用

- 路由器、交换机、摄像头、NVR、NAS、打印机、智能家居、工控网关等**嵌入式 Linux/RTOS 固件**。
- 厂商 OTA 包、官网下载固件、SPI/NAND/eMMC 闪存镜像、UART/U-Boot 转储。
- 目标问题：默认/硬编码凭据、私钥与证书、启动脚本提权、Web/CGI 命令注入、未授权接口、调试口暴露、OTA 签名缺失。
- 不适用：APK/AAB（走 `apkseep`）、桌面 PE/ELF（走通用二进制/`softseep`）、纯云 API（走 Web/后端技能）。

## 二、前置：芯片与接口判断（先判后拆）

| 判断项 | 怎么拿 | 对后续的影响 |
|---|---|---|
| SoC/CPU 架构 | 丝印、`/proc/cpuinfo`、固件内 ELF `file`/`readelf -h` | MIPS/ARM/x86、32/64 位、大小端决定 QEMU 与交叉工具 |
| 存储介质 | 板载 SPI NOR（8/16 pin）、NAND、eMMC、SD | 决定 dump 方式：`flashrom` / `nanddump` / `dd` |
| 调试口 | 板上 3/4/5 个裸露焊盘，TX/RX/GND 常并排 | UART 控制台通常是最快 shell 入口 |
| JTAG/SWD | 10/20 pin 排针或测试点，TCK/TMS/TDI/TDO | 可读全片、停机、改启动参数；优先级低于 UART |
| 电压 | 万用表量 VCC-GND，查 SoC datasheet | **3.3V 与 1.8V 混接会烧 SoC**；不确定先上电平转换 |
| 启动链 | U-Boot 横幅、分区表、`mtdparts` | 决定从 U-Boot 读闪存还是离线解包 |
| 固件加密/签名 | 熵值、`binwalk` 是否只识别出容器头、OTA 校验逻辑 | 加密镜像先找解密点/密钥，不要盲拆 |

**前置门（缺一不可）**：

1. 目标归属与授权明确；设备可断电、可恢复，重要数据已备份。
2. 已记录型号、PCB 丝印、SoC、闪存型号、电压、串口焊盘位置。
3. 已有**只读备份**（至少一份原始镜像 + SHA256），后续所有操作在副本上做。
4. 知道变砖后的恢复路径（SPI 夹子/编程器、U-Boot TFTP、厂商恢复模式）。

## 三、五步闭环

> 每步都有完成判据；判据不满足就停在该步换手法，不带着“大概能行”往下走。

### 第 1 步：固件获取（OTA / 闪存 / UART dump）

| 路线 | 典型动作 | 完成判据 |
|---|---|---|
| 厂商下载/OTA | 官网支持页、App 抓包取 OTA URL、`curl -O`；记录版本与哈希 | 拿到完整包，`file`/`binwalk` 能识别容器或文件系统 |
| 在线设备 | `cat /proc/mtd` → `dd if=/dev/mtdX of=/tmp/x.bin`；`nanddump`/`mtd_debug` | 分区表与镜像长度一致，回读哈希稳定 |
| UART/U-Boot | 中断启动，`md.b`/`sf read`/`nand read` + `tftpboot` 传到主机 | 传输完成且 CRC/长度校验通过 |
| 离线闪存 | SOP8 夹子/焊下芯片，`flashrom -p ch341a_spi -r dump.bin` | 两次读取 SHA256 一致；含 OOB/坏块信息时另存 |
| eMMC/SD | `dd if=/dev/mmcblk0 of=... bs=1M` 或读卡器 | 分区表可解析，首扇区有 MBR/GPT |

- 先判断是否加密/压缩：`binwalk -E` 看熵；高熵不代表加密，SquashFS/UBI 本身也高熵。
- OTA 包可能是外层容器（tar/zip/厂商头），先剥壳再解文件系统。
- 每次获取都留 `sha256sum` 与来源 URL/命令，写入案例 `facts.jsonl` 或报告。

### 第 2 步：解包（binwalk / ubireader / unsquashfs）

```bash
binwalk -e --run-as=root firmware.bin          # 递归提取，产物在 _firmware.bin.extracted/
binwalk --dd='.*' firmware.bin                  # 只按签名切分，避免误执行
ubireader_extract_images -o ubi_out firmware.bin
ubireader_extract_files -o ubi_root ubi_out/*.ubi
unsquashfs -d rootfs -f rootfs.squashfs
```

判据：能得到 **根目录结构**（`/bin`、`/etc`、`/lib`、`/www` 或 `/usr`），且 `bin/busybox` 或 init 可识别。
只切出内核/DTB 不算解包完成；只有 `squashfs-root` 但缺 `/etc` 也要查是否还有第二层容器。

### 第 3 步：文件系统分析（凭据 / 密钥 / 启动脚本）

优先顺序：**启动链 → 账号与密钥 → 网络服务 → 升级机制**。

```bash
grep -RInE 'passwd|shadow|admin|root:|token|secret|api[_-]?key' etc usr/etc 2>/dev/null
find . -name 'id_rsa' -o -name '*.pem' -o -name '*.key' -o -name 'authorized_keys'
cat etc/inittab etc/init.d/rcS etc/passwd etc/shadow 2>/dev/null
grep -RInE 'telnetd|dropbear|httpd|lighttpd|uhttpd|goahead|nvram|mtd' etc init* 2>/dev/null
file bin/busybox bin/* 2>/dev/null | head -40
```

- 启动脚本常泄露：调试串口、默认关闭的 telnet、写死的管理员密码、从 NVRAM 取值的命令注入点。
- Web/CGI 是重点：`/www/cgi-bin`、`/usr/lib/lua/luci`、固件升级接口、`system()`/`popen()` 调用链。
- 私钥/证书要记录用途（设备身份、OTA 签名、云连接），不要只当字符串。
- 判据：能画出“开机 → 起哪些服务 → 哪个服务以 root 跑 → 入口参数是否可控”的最小链路。

### 第 4 步：仿真（QEMU / FirmAE / chroot）

| 方式 | 适用 | 命令骨架 | 判据 |
|---|---|---|---|
| qemu-user + chroot | 单文件/单个 CGI 快速验证 | `qemu-mipsel -L rootfs rootfs/bin/sh` | 能执行目标程序，`ldd` 依赖齐全 |
| qemu-system | 有内核 + rootfs，需完整网络 | `qemu-system-mipsel -M malta -kernel vmlinux -hda rootfs.img -append "root=/dev/sda console=ttyS0" -nographic` | 内核起、根挂载、能登录 |
| FirmAE/Firmadyne | 厂商镜像自动仿真 | `./run.sh -r <arch> firmware.bin` | 自动起网络、Web 可访问 |
| 真机 chroot | 已有 shell/固件可写 | `chroot rootfs /bin/sh` | 服务能起、端口可连 |
| 静态/半仿真 | 仿真失败时 | Ghidra/IDA + 手工补 NVRAM/`/dev` 桩 | 关键函数可验证输入输出 |

- 仿真失败最常见原因：NVRAM 未初始化、`/dev/mtd` 缺失、`/proc` 依赖、看门狗、硬件专用 ioctl。
- 先补“最小桩”：`nvram` 读写、`mtd` 分区、`/etc/TZ`、随机数设备；不要一上来追全部外设。
- 判据：能进 shell，且**关键服务真的监听并响应**（`curl`/`nc` 有业务回包），不是进程活着而已。

### 第 5 步：硬件接口（UART / JTAG / SPI）

**UART（首选）**：

1. 断电，万用表找 GND；上电量候选焊盘：VCC 固定高、TX 上电瞬间有波动、RX 常为高。
2. **只接 GND/TX/RX，不接 VCC**；USB-TTL 电平选 3.3V 或 1.8V，与板子一致。
3. 常用波特率：`115200`（最常见）、`57600`、`38400`、`9600`；8N1，无流控。
4. 打开串口抓完整启动日志，启动时连按回车/`Ctrl-C`/`Esc` 尝试中断 U-Boot。
5. 判据：看到 U-Boot 或内核日志，并能落到 `#`/`$` shell；或成功修改 `bootargs`。

**JTAG/SWD**：先用 `openocd` 扫描 IDCODE，确认 TAP 链；再接 `flash read`。判据是能稳定识别 SoC 并读出与 SPI dump 一致的镜像。
**SPI**：`flashrom -p ch341a_spi -r a.bin`，再读一次比对；板上直读失败时断电、加 1.8V 适配器或焊下芯片。

## 四、判据（三选一即为闭环，全部要有证据）

| # | 判据 | 可接受证据 | 不成立的表现 |
|---|---|---|---|
| J1 | **能进 shell** | UART 登录录屏/日志、SSH/telnet 会话、QEMU 串口提示符 | 只看到 U-Boot 横幅、登录框但无凭据、仿真内核 panic |
| J2 | **能跑起关键服务** | 服务进程 + 监听端口 + 真实业务响应（HTTP/CGI/管理协议） | 进程在但端口不通、502、只有静态页 |
| J3 | **能复现漏洞** | 可重复的请求/PoC、前后对比、日志或崩溃现场、影响说明 | 只凭字符串猜测、只在仿真里“可能”、无法重复 |

- 三条不必全中；但**报告必须写明中了哪条、证据在哪**。J3 未达成时，J1/J2 仍是有效交付。
- 漏洞复现优先在仿真或隔离网络内做；真机测试只做只读/低影响验证，禁止破坏性写入。

## 五、工具与降级

| 能力 | 首选 | 备选/降级 |
|---|---|---|
| 识别与切分 | `binwalk` | `file`、`dd` + 手工偏移、`7z`、`foremost` |
| UBI | `ubireader_extract_images` / `ubireader_extract_files` | `ubi_reader` Python 包、手工解析 UBI EC/VID 头 |
| SquashFS | `unsquashfs` | `sasquatch`（非标/厂商魔改）、`binwalk -e` |
| JFFS2/CramFS | `jefferson` / `cramfsck` | `binwalk`、手工按魔术找节点 |
| 用户态仿真 | `qemu-<arch>` | `qemu-static` + `chroot`、`proot` |
| 系统级仿真 | `qemu-system-<arch>` | FirmAE / Firmadyne、真机 chroot |
| 硬件调试 | `openocd` | J-Link/ST-Link 官方工具、逻辑分析仪、SPI 编程器 |
| 串口 | `picocom`/`minicom`/PuTTY | `screen /dev/ttyUSB0 115200`、Python `pyserial` |

**缺工具时不要停工、不要用 `-h` 盲试探二进制**：

1. 先查本机：`seep_tool_discover(tool_id, target)` / `tool_autodiscover`，读 `Tool/config/tool-capabilities.json`。
2. 需要自启宿主：`powershell -File Tool/scripts/tool-run.ps1 -Tool <tool> -Target <target>`。
3. 仍缺则走替代链（上表右列）或容器/WSL；安装需用户确认，白名单外不自动装。
4. 每个替代方案在报告里标注“降级原因 + 已验证到什么程度”，不假装等价。

## 六、坑（高频，按出现顺序）

1. **固件头校验**：厂商头含长度/CRC/型号，截断或改字节会导致升级拒绝或解包偏移错。先按头部字段算真实负载偏移，保留原头。
2. **JFFS2/UBI 变体**：带 OOB、坏块、LEB 重映射；直接 `dd` 或普通解压会缺文件。用 `ubireader`/`nanddump`，保留 OOB。
3. **SquashFS 魔改**：LZMA/XZ 变体、非标准块大小、厂商自定义压缩；`unsquashfs` 报错时换 `sasquatch`，仍失败再看内核源码里的解压器。
4. **掉电写坏**：U-Boot 环境、NVRAM、正在写的 JFFS2 分区。任何写操作前备份；真机只读优先，写测试用可恢复设备。
5. **串口电压**：3.3V TTL 接 1.8V 板会烧；RS-232 电平（±12V）不能直接接 TTL。共地、只接 TX/RX/GND。
6. **TX/RX 接反**：能收到乱码或完全无输出；交换 TX/RX 再试，先确认 GND。
7. **波特率误判**：115200 看到乱码不代表没控制台，依次试 57600/38400/9600；逻辑分析仪可直接测位宽。
8. **仿真“假成功”**：进程起来但 NVRAM 空、Web 目录缺失、CGI 权限不对；必须用真实请求验证。
9. **架构/字节序拿错**：MIPS big-endian 与 little-endian 的 QEMU 不同；`readelf -h` 确认后再选。
10. **OOB/ECC 丢失**：NAND dump 不带 OOB 时 UBI 可能挂载失败；优先 `nanddump -o` 或整片含 OOB 备份。
11. **看门狗复位**：仿真/真机调试时喂狗线程缺失会反复重启；先定位 `watchdog` 或禁用其启动项（仅在副本上）。
12. **OTA 签名校验**：改 rootfs 后必须重算签名或关闭校验；没有密钥时不要声称“可持久化”。

## 七、验收

交付前逐项打勾，缺项写“未验证”，不臆造：

- [ ] 固件来源、型号、版本、SHA256、获取命令/URL 齐全；原始镜像只读保存。
- [ ] 解包产物有完整根目录，记录所用工具与版本；非标格式注明变体与绕法。
- [ ] 账号/密钥/启动脚本/服务入口有清单，敏感值脱敏但保留定位（文件:行号）。
- [ ] J1/J2/J3 至少一条达成，证据可复现（命令、请求、日志、截图/串口记录）。
- [ ] 仿真或真机环境可重建：架构、内核、网络配置、NVRAM/桩、启动命令。
- [ ] 真机操作有备份与恢复方案；未造成不可逆写入；测试范围符合授权。
- [ ] 报告写明边界：哪些是观察、哪些是推断、哪些未验证。

## 八、边界

- **不是 APK**：Android 应用、DEX/SO、重打包走 `apkseep`；本技能只处理设备固件与嵌入式根文件系统。
- **不是 PE**：Windows PE/.NET/桌面 ELF 走 `softseep`、`ida-reverse` 或通用二进制技能；不要用 binwalk 硬套。
- **不是纯 Web**：只测云端 API/前端时走后端复刻或 Web 技能；本技能的网络验证仅围绕设备自身服务。
- **不做未授权硬件接入**：不接第三方设备、不扫公网、不写他人闪存；不提供绕过厂商授权/计费的攻击步骤。
- **不做“解包即成功”**：没有 shell/服务/漏洞证据时，只能算侦察，不得标为完成。
- 详细命令与判据见 `references/firmware-unpack.md`、`references/hardware-interfaces.md`、`references/filesystem-and-credentials.md`、`references/emulation-and-fuzz.md`；离线体检用 `Tool/scripts/fw-triage.py`。
