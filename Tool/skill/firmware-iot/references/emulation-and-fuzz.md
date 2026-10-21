# 仿真与 fuzz（emulation-and-fuzz）

> 配套 `firmware-iot/SKILL.md`。仿真只服务于一个目标：**让目标服务在可回滚的环境里真实响应请求**，再用最小输入验证/复现问题。
> 约定 `ROOT=work/fw-audit/rootfs`、`OUT=work/fw-audit/emu`；原始镜像只读。

## 0. 先选模式，不要一上来就 FirmAE

| 目标 | 首选 | 备选 | 判据 |
|---|---|---|---|
| 跑单个 CGI/busybox | `qemu-user` + `chroot` | `qemu-user` + `-L`、`proot` | 目标程序输出 `id`/`uname -a` |
| 跑完整 init/网络服务 | `qemu-system-*` | FirmAE/Firmadyne | 内核挂根、服务监听、真实回包 |
| 厂商镜像自动仿真 | FirmAE | Firmadyne 手工四步 | 自动推断网络 + Web 可达 |
| 已有真机 shell | 真机 `chroot` | 只读挂载 | 服务能起、端口可连 |
| 仿真反复失败 | 静态/半仿真 | IDA/Ghidra + NVRAM/`/dev` 桩 | 能解释关键函数输入输出 |

先确认：架构/端序（`readelf -h`）、内核版本、rootfs 设备名、init 路径、NVRAM 依赖、看门狗。
失败判据：内核 panic、根挂载失败、init 不存在、服务进程活着但端口无响应——都不算“仿真成功”。

## 1. qemu-user + chroot（最快验证单程序）

```bash
# 以 MIPS LE 为例；ARM/AArch64 换 qemu-arm/qemu-aarch64
sudo apt install qemu-user-static
cp /usr/bin/qemu-mipsel-static "$ROOT/usr/bin/" 2>/dev/null || true
sudo chroot "$ROOT" /usr/bin/qemu-mipsel-static /bin/sh -c 'id; uname -a'

# 不 chroot 时指定库前缀
QEMU_LD_PREFIX="$ROOT" qemu-mipsel-static "$ROOT/bin/busybox" sh -c 'id'
```

要点：

- `-static` 版不依赖宿主库，chroot 里优先用；`readelf -l "$ROOT/bin/busybox" | grep interpreter` 确认加载器路径，缺库时补 `lib/` 或把 qemu 放进 rootfs。
- 单程序通过 ≠ 整机可起：CGI 还依赖 `PATH_INFO`、环境变量、Web 用户、`/tmp` 权限。
- 需要 `/proc`、`/dev/urandom`、`/dev/mtd` 时先 bind mount 或做最小桩，不改原始 rootfs。

完成判据：`chroot` 内能执行 `id`、读取 `/etc/passwd`、运行目标 CGI 并返回预期输出。
失败判据：只能执行 `/bin/sh`、目标程序 `Exec format error`/`No such file or directory`（多为解释器/库缺失）。

## 2. qemu-system：完整系统与网络

```bash
# MIPS Malta 示例；ARM 常用 -M virt，具体 machine 以 qemu-system-<arch> -M help 为准
qemu-system-mipsel -M malta -m 256M \
  -kernel "$OUT/vmlinux" \
  -drive file="$OUT/rootfs.img",format=raw \
  -append "root=/dev/sda console=ttyS0" \
  -netdev user,id=n0,hostfwd=tcp::8080-:80 \
  -device e1000,netdev=n0 \
  -nographic
```

- `root=` 必须与镜像内设备名一致（`/dev/sda`、`/dev/vda`、`/dev/mtdblock3`）；`console=` 与内核配置一致，无输出时试 `ttyS0`/`ttyAMA0`/`ttyS1`。
- 双向网络用 tap/bridge；`user` 模式只能 hostfwd，适合单端口验证。内核缺驱动时换厂商内核或补 initramfs，不要用宿主内核硬套厂商 rootfs。
- 登录失败先看 init 是否起 getty、`/etc/inittab` 是否 `askfirst`、shadow 是否可用。

完成判据：内核日志走到根挂载，出现 login/init 输出，宿主 `curl` 能拿到业务响应。
失败判据：内核起但 rootfs panic、init 不存在、网络设备未识别、服务只绑定 `127.0.0.1` 而 hostfwd 打不到。

## 3. FirmAE / Firmadyne：自动化与日志

```bash
# FirmAE（参数以本地版本为准）
./run.sh -r mipsel /path/to/firmware.bin
# 结果通常在 scratch/<id>/，看 qemu.*.log 与 run.sh
```

Firmadyne 手工链：`extractor.py` → `getArch.sh` → `makeImage.sh` → `inferNetwork.sh` → `scratch/<id>/run.sh`。

失败定位顺序：

1. `qemu.*.log` 有无 `Kernel panic`/`Unable to mount root`；镜像是否缺 `/init` 或 `linuxrc`；
2. 网络推断是否把 `eth0` 配错网段；NVRAM 是否为空导致服务启动即退出；
3. 看门狗是否在几十秒后复位。

完成判据：FirmAE 报告网络可用，且从宿主 `curl`/`nc` 得到真实协议响应；仅“虚拟机进程存在”不算。
失败判据：反复重启、Web 端口拒绝、只有静态占位页。

## 4. 最小桩：NVRAM、mtd、设备节点

```bash
# 只读副本上做
mkdir -p "$ROOT/var/nvram" "$ROOT/dev"
# 依据固件里的默认值/字符串补键，不要凭空造生产配置
cat > "$ROOT/etc/nvram.conf" <<'EOF'
lan_ipaddr=192.168.1.1
lan_netmask=255.255.255.0
http_username=admin
EOF

# 常见缺失设备
[ -e "$ROOT/dev/urandom" ] || sudo mknod "$ROOT/dev/urandom" c 1 9
[ -e "$ROOT/dev/null" ]    || sudo mknod "$ROOT/dev/null" c 1 3
```

- `nvram` 是壳脚本/库时，替换为读取 `nvram.conf` 的桩，而不是改每个调用点。
- `/dev/mtd` 缺失会让升级/分区逻辑提前退出：用普通文件桩并记录“非真实写操作”。看门狗只在同一副本里禁用启动项或喂狗。

## 5. 服务探测：进程活着不算成功

```bash
# 从宿主看
nmap -Pn -sT -p- --min-rate 1000 127.0.0.1
curl -sv --max-time 5 http://127.0.0.1:8080/ | head -40
curl -sv --max-time 5 http://127.0.0.1:8080/cgi-bin/luci | head -40
nc -vz 127.0.0.1 8080
# 在 guest 内确认监听与用户
netstat -lntp 2>/dev/null || ss -lntp
ps w | head -40
```

判据分级：

| 级别 | 证据 |
|---|---|
| J2 候选 | 端口监听 + 进程 + 真实业务响应（动态 HTML/JSON/登录页/CGI 输出） |
| 仅侦察 | 端口开放但 404/502、只有静态文件、没有业务逻辑 |
| 假成功 | 进程存在、端口未监听；或 hostfwd 到错误端口 |

- 每个服务记录：监听地址、端口、启动命令、运行用户、配置文件、请求样例；有认证时先试默认/空口令，否则只测未授权面。
- 留证：`tcpdump -ni any -s0 -w "$OUT/svc.pcap" 'port 8080'`。

## 6. fuzz 接线：先找解析器，再接 harness

### 6.1 选目标

```bash
# 入口线索
grep -RInE 'system\(|popen\(|execve\(|sprintf\(|strcpy\(|sscanf\(' "$ROOT/www" "$ROOT/usr" 2>/dev/null | head -80
strings -a "$ROOT/usr/sbin/httpd" | grep -Ei 'Content-Length|boundary|upload|soap|upnp|rtsp' | head
```

优先目标：HTTP 表单/上传、UPnP/SOAP、mDNS、RTSP、管理协议、OTA 校验、CGI 参数解析。
先确认输入从 socket/文件到危险函数的路径，再决定 fuzz 面；不要对整台设备盲扫。

### 6.2 本地 harness

```bash
# AFL++ QEMU 模式（目标为异构架构时）
afl-fuzz -Q -i "$OUT/corpus" -o "$OUT/afl" -- "$ROOT/usr/sbin/target" @@

# 有源码/可重编译时优先 instrumented build
CC=afl-clang-fast ./configure --disable-shared && make -j
afl-fuzz -i "$OUT/corpus" -o "$OUT/afl" -- ./target @@
```

- `-Q` 需 AFL++ 的 QEMU 支持；MIPS/ARM 先确认 `afl-qemu-trace` 可执行。
- 文件型输入先做最小合法样本；网络型用 `aflnet`/`boofuzz`/自写 Python harness 重放。
- 字典加入协议关键字（`Content-Length:`、`SOAPAction:`、`Authorization:`、边界串）。
- 崩溃样本必须可重放：记录输入、命令行、环境、架构、库版本。

### 6.3 网络 fuzz 最小接线

```python
# 示意：只对授权目标，先建立基线再变异
import socket, sys
HOST, PORT = "127.0.0.1", 8080
def send(payload: bytes):
    s = socket.create_connection((HOST, PORT), timeout=3)
    s.sendall(payload)
    data = s.recv(4096)
    s.close()
    return data
base = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
print(send(base)[:80])
```

- 先跑通基线请求再对单字段变异，不要并发轰炸；记录响应码/长度/崩溃，区分“协议错误”与“内存破坏”。
- 有 ASAN 先看 sanitizer 报告；无符号用 `gdb-multiarch`/core + `addr2line` 定位。

### 6.4 判据与停止条件

- **有效**：同一输入可重复触发崩溃/越界/命令注入，且有请求/响应/日志/核心转储。
- **疑似**：只出现一次崩溃、无法重放、或只是服务重启（先查看门狗/oom）。
- **无效**：仅版本号旧、仅字符串匹配、仅“可能溢出”。
- 同一目标同一手法最多 2 次；第二次失败即停，换路线或汇报。不在生产设备/公网/未授权网段跑 fuzz。

## 7. 证据与清理

- 保存：启动命令、内核/串口日志、网络配置、NVRAM 桩、请求样例、崩溃输入、工具版本。
- 可重建步骤：架构、machine、kernel、drive、root=、console、hostfwd/tap、init 修补。
- 清理：停 QEMU/FirmAE、删临时 tap/bridge、还原副本；真机只做只读验证。报告注明哪些是仿真观察、哪些真机验证、哪些未验证。

## 8. 常见失败与处理

| 现象 | 原因 | 处理 |
|---|---|---|
| `Exec format error` | qemu 架构/端序错 | `readelf -h` 重选 `qemu-mips*`/`qemu-arm*` |
| `No such file or directory` | 动态加载器/库缺失 | 查 `interpreter`，补 `lib/` 或用 static qemu |
| 内核 panic `Unable to mount root` | `root=`/驱动/分区错 | 换 `root=`、补 initramfs、核对镜像布局 |
| 服务起后立即退出 | NVRAM/`/dev`/配置缺失 | 补最小桩，读服务 stderr |
| 端口通但 502/404 | Web 根/CGI 路径/权限错 | 查 `DocumentRoot`、`cgi-bin`、执行位 |
| FirmAE 反复重启 | 看门狗/网络推断错 | 读 `qemu.*.log`，先禁用看门狗（副本） |
| fuzz 无崩溃 | harness 没进解析器/输入不合法 | 先做覆盖率/基线，再调 corpus |

## 9. 边界

- 仅在授权固件/设备/隔离网络内仿真与 fuzz；不接第三方设备、不打公网。
- 不改原始镜像；所有桩、补丁、启动脚本只存在于工作副本。
- 不把“仿真里可能”写成“设备可利用”；J3 必须有可重复证据。
