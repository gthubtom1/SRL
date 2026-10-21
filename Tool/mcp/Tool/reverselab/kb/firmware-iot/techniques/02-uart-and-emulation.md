# 02 UART 与仿真

> 配套 `firmware-iot/SKILL.md`、`references/hardware-interfaces.md`、
> `references/emulation-and-fuzz.md`。只对自有或明确授权的设备/固件操作；上电前先量电压、共地。
## 0. 开板前检查

断电拍照记录丝印/型号；万用表确认 GND 与 USB-TTL 共地；上电量 VCC（1.8/3.3/5V）
并核对 IO 电平；确认存储封装/电压与 SPI 编程器或 U-Boot 恢复手段，有完整镜像备份后再焊线。
**成功判据**：电压、GND、引脚定义有记录，且有恢复方案。
**失败判据**：电压不明、GND 不可靠、没有备份就上电或写闪存。

## 1. UART 接线与抓日志

```text
USB-TTL GND -> 板 GND        （必须）
USB-TTL RX  -> 板 TX         （交叉）
USB-TTL TX  -> 板 RX         （交叉）
USB-TTL VCC -> 不接          （除非明确需要且电压一致）
```

```bash
ls -l /dev/serial/by-id/
picocom -b 115200 -8 -n -l /dev/ttyUSB0
# 或 screen /dev/ttyUSB0 115200
```

```python
import serial, sys, time
s = serial.Serial('COM3', 115200, timeout=0.2)  # Windows 示例
end = time.time() + 30
while time.time() < end:
    data = s.read(4096)
    if data:
        sys.stdout.buffer.write(data); sys.stdout.flush()
```

- 参数 8N1、无流控；波特率依次试 `115200 → 57600 → 38400 → 9600`。
- 打开串口后给设备重新上电，抓完整启动日志；启动时连按回车、`Ctrl-C`、`Esc`、`x` 尝试中断 U-Boot。
- 乱码但有规律 = 波特率不对；完全无输出 = TX/RX 反、GND 未共、焊盘不是 UART、控制台关闭。

**成功判据**：日志可读，能看到 U-Boot/内核行，最终出现 `#`、`$`、`login:` 或 U-Boot 提示符。
**失败判据**：只有乱码、只能看到输出不能输入、或始终无输出且未排查接线。

## 2. U-Boot 与登录

```text
U-Boot> printenv
U-Boot> setenv bootargs ${bootargs} init=/bin/sh
U-Boot> boot
U-Boot> sf probe 0; sf read 0x80000000 0x50000 0x200000
U-Boot> tftpboot 0x81000000 dump.bin
```

- 地址/长度按实际 `mtdparts` 调整；`init=/bin/sh` 可能因只读根、看门狗、服务缺失不稳定，失败改回原 `bootargs`。
- 登录后先只读采集：`cat /proc/cpuinfo`、`cat /proc/mtd`、`mount`、`ps w`、`netstat -lntp`。

**成功判据**：能修改 `bootargs` 进单用户/`init=/bin/sh`，或把分区传到主机且长度/校验一致；
交互 shell 能执行 `id`/`uname -a`。
**失败判据**：只能看到启动日志、无法输入；或传输文件长度与读取长度不符。

## 3. qemu-user + chroot（最快验证单程序）

```bash
sudo apt install qemu-user-static
cp /usr/bin/qemu-mipsel-static "$ROOT/usr/bin/" 2>/dev/null || true
sudo chroot "$ROOT" /usr/bin/qemu-mipsel-static /bin/sh -c 'id; uname -a'
QEMU_LD_PREFIX="$ROOT" qemu-mipsel-static "$ROOT/bin/busybox" sh -c 'id'
```

- 架构按 `readelf -h` 选 `qemu-mips*`/`qemu-arm*`/`qemu-aarch64*`；端序错了会 `Exec format error`。
- `readelf -l "$ROOT/bin/busybox" | grep interpreter` 确认动态加载器；缺库补 `lib/` 或用 static qemu。
- 需要 `/proc`、`/dev/urandom`、`/dev/mtd` 时做 bind mount 或最小桩，不改原始 rootfs。

**成功判据**：chroot 内能执行 `id`、读 `/etc/passwd`、运行目标 CGI 并返回预期输出。
**失败判据**：只能执行 `/bin/sh`；目标程序报 `Exec format error`/`No such file or directory`
（多为架构/解释器/库缺失）。

## 4. qemu-system 与 FirmAE

```bash
qemu-system-mipsel -M malta -m 256M -kernel "$OUT/vmlinux" \
  -drive file="$OUT/rootfs.img",format=raw \
  -append "root=/dev/sda console=ttyS0" \
  -netdev user,id=n0,hostfwd=tcp::8080-:80 -device e1000,netdev=n0 -nographic

./run.sh -r mipsel "$OUT/orig.bin"   # FirmAE，参数以本机版本为准
```

- `root=` 必须与镜像内设备名一致（`/dev/sda`、`/dev/vda`、`/dev/mtdblock3`）。
- `console=` 与内核配置一致；没输出时试 `ttyS0`/`ttyAMA0`/`ttyS1`。
- 常见修复：分区布局、NVRAM 初始化、`/init` 或 `linuxrc`、看门狗、网络推断。

**成功判据**：内核日志走到根挂载，出现 login/init 输出，宿主 `curl` 能拿到业务响应。
**失败判据**：内核 panic/`Unable to mount root`、init 不存在、服务只绑 `127.0.0.1`
而 hostfwd 打不到、FirmAE 反复重启且 `qemu.*.log` 未读。

## 5. 最小桩与服务验证

```bash
mkdir -p "$ROOT/var/nvram" "$ROOT/dev"
cat > "$ROOT/etc/nvram.conf" <<'EOF'
lan_ipaddr=192.168.1.1
lan_netmask=255.255.255.0
http_username=admin
EOF
[ -e "$ROOT/dev/urandom" ] || sudo mknod "$ROOT/dev/urandom" c 1 9
[ -e "$ROOT/dev/null" ]    || sudo mknod "$ROOT/dev/null" c 1 3

curl -sv --max-time 5 http://127.0.0.1:8080/ | head -40
nc -vz 127.0.0.1 8080
```

- 桩值来自固件默认值/字符串，不凭空造生产配置；`/dev/mtd` 用普通文件桩并标注“非真实写操作”。
- 进程存在 ≠ 服务可用：必须有真实协议响应（HTML/JSON/登录页/CGI 输出）。

**成功判据**：端口监听 + 进程 + 真实业务响应；记录监听地址、启动命令、运行用户、请求样例。
**失败判据**：只有端口开放但 404/502、只有静态占位页、或 hostfwd 到错误端口。

**误报/边界**：仿真里“可能可利用”不等于设备可利用；J3 必须有可重复证据。
真机只做授权范围内的只读/低影响验证，写操作必须有完整备份与回滚方案。
