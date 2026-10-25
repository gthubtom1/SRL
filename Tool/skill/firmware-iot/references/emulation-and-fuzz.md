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
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
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
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
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
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
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
- 同一目标同一手法最多 2 次；第二次失败即停，换路线或汇报。fuzz 只在授权网段/实验设备上跑。

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

## 9. Rehosting 失败归因（FirmPilot / Khost 2026）

> 解包成功不等于能 rehost。失败时先归因，再决定补桩、换路线还是放弃；不要用“再跑一次 FirmAE”代替证据。
> FirmPilot（arXiv 2607.14903，2026-07）把恢复拆成**证据引导的依赖/服务/设备节点**三类；Khost（USENIX Security 2026）用 **KVM 近原生**跑 MCU 固件。前者给顺序，后者给 CPU/内存语义，二者都不自动补外设。

每次失败先填六个字段，缺字段的结论一律降级：

| 字段 | 取值 | 用途 |
|---|---|---|
| `rehost_blocker` | `none/rootfs/init/nvram/watchdog/net/arch-abi/mcu-periph` | 归因主类，只允许一个主值 |
| `rootfs_complete` | `true/false` + 已解分区/偏移 | ① 根文件系统是否完整 |
| `init_chain_ok` | `true/false` + 断点 `文件:行` | ② init 链是否走到目标服务 |
| `nvram_stub` | `none/file/lib/dev` | ③ NVRAM/mtd/设备节点桩形态 |
| `watchdog_mitigated` | `true/false` + 方式 | ④ 看门狗是否已隔离 |
| `arch_abi` | `mipsel-o32/armv7-eabi/aarch64/...` | ⑥ 架构/端序/ABI 是否匹配 |

```text
rehosting 失败
├─ ① rootfs_complete=false ── 重切分区/合并 overlay ── 缺 busybox 即放弃整机
├─ ② init_chain_ok=false ─── 补依赖/最小 init ─────── 依赖不可得→qemu-user
├─ ③ nvram_stub=none ─────── nvram.conf+lib 桩 ───── 补 2 次仍崩→静态
├─ ④ watchdog_mitigated=false 副本禁 wdt/喂狗 ───── 硬件层→短窗口
├─ ⑤ 网络/IP 不通 ────────── 驱动/NIC/hostfwd ───── 无驱动→单端口/真机
├─ ⑥ arch_abi 不符 ──────── readelf 对齐 qemu ──── SIGILL→Unicorn/静态
└─ ⑦ mcu-periph ─────────── Khost + MMIO 桩 ───── 无 datasheet→转硬件
```

| 支 | 现象 | 判定 | 修复动作 | 放弃判据 |
|---|---|---|---|---|
| ① rootfs 不完整 | 内核挂根后 `/bin/sh`/`/etc/inittab` 缺失，或只解出 kernel+单个分区 | `rootfs_complete=false`，`rehost_blocker=rootfs`；记录已解分区/偏移 | `ubireader`/`sasquatch` 重切，合并 `rootfs_data`/overlay，从 OTA 或真机 dump 补缺失分区；`find "$ROOT" -maxdepth 2` 清点 | 换 2 种容器工具仍无 `/bin/busybox` 或 `/etc/inittab`，且无备份 → 只做静态/半仿真 |
| ② init 链断 | 串口停在 `Starting ...` 无 shell；`/etc/init.d/rcS` 调用的 `/sbin/xxx` 不存在 | `init_chain_ok=false`，`rehost_blocker=init`；记录断点 `文件:行` | `grep -RIn` 依赖链并跨分区补齐；副本用最小 init 直接 exec 目标服务，保留原链日志 | 依赖位于未解出分区且无替代实现，或改 2 次 init 仍无监听 → 转 qemu-user 单程序 |
| ③ NVRAM/mtd 桩缺失 | 服务读 `nvram_get`/`/dev/nvram`/`/dev/mtd*` 返回空后退出 | `nvram_stub=none`，`rehost_blocker=nvram`；记录缺失键/设备 | 按固件默认值与字符串造 `nvram.conf`+shell/lib 桩；`/dev/mtd*` 用只读普通文件桩，记录“非真实写” | 键空间不可枚举、补桩 2 次仍崩溃 → 静态还原配置读取逻辑，不再追整机 |
| ④ 看门狗复位 | 启动 30–90 s 后整机重启、端口消失；串口出现 reset 源 | `watchdog_mitigated=false`，`rehost_blocker=watchdog`；记录复位间隔 | 副本注释 `watchdog`/`wdt` 启动项；`/dev/watchdog` 桩返回成功并定时喂狗；串口确认 | 看门狗在 bootloader/硬件层且无寄存器/串口访问，禁用有 brick 风险 → 只做短窗口请求 |
| ⑤ 网络/IP 不通 | guest 无 `eth0`、无 IP，服务只绑 `127.0.0.1`；hostfwd 打不到 | `rehost_blocker=net`；记录 NIC 模型/网段/监听地址 | 核对内核驱动与 `/etc/network/interfaces`；qemu 换 NIC 模型，tap/bridge 或 hostfwd；guest 内 `ip addr`/`ss -lntp` | 厂商内核无该 NIC 驱动且换内核不能挂根，或网络推断 2 次仍不通 → 单端口 user 模式/真机只读 |
| ⑥ 架构/ABI 不匹配 | `Exec format error`/`Illegal instruction`/syscall 号错 | `arch_abi` 与镜像不符，`rehost_blocker=arch-abi`；记录 `readelf -h/-A` | 对齐端序与 ABI（mips/mipsel、armv5/armv7、o32/n32），换 matching `qemu-<arch>` 或厂商内核；注意 FP/EABI | 自定义 ABI/协处理器指令 qemu 无实现，换 2 次 arch 仍 SIGILL → Unicorn 片段或纯静态 |
| ⑦ MCU 外设无模型 | 裸机/RTOS 启动即卡 UART/SPI/I2C 初始化，无 `/dev` 可补 | `rehost_blocker=mcu-periph`；记录卡住的外设/寄存器 | 用 Khost 的 KVM 近原生执行 CPU/内存，按 datasheet 给 UART/SPI/I2C 最小 MMIO 桩（ready/空 FIFO）；先跑到主循环 | 外设时序/中断强耦合且无 datasheet/逻辑分析仪波形，2 次桩仍卡初始化 → 放弃整机，转硬件接口/UART 在线 |

**FirmPilot 的顺序**：先证 rootfs，再证 init，再补 NVRAM/设备节点，最后才动网络和外设；每次只补“证据最强”的一个节点，补完立即重跑并记录字段变化。
**Khost 的边界**：KVM 近原生让 CPU/内存语义接近真机，但 UART/SPI/I2C 仍要模型；`Khost 起来了` 不等于外设可用。

记录示例：

```json
{"rehost_blocker":"init","rootfs_complete":true,"init_chain_ok":false,
 "nvram_stub":"file","watchdog_mitigated":false,"arch_abi":"mipsel-o32"}
```

报告口径：只写“在 <环境> 下服务有/无真实回包”，不写“仿真失败=固件没漏洞”；放弃也是结论，必须带上述字段与已试命令 rc。

## 10. 边界

- 仅在授权固件/设备/隔离网络内仿真与 fuzz；不接第三方设备、不打公网。
- 不改原始镜像；所有桩、补丁、启动脚本只存在于工作副本。
- 不把“仿真里可能”写成“设备可利用”；J3 必须有可重复证据。

## 11. 仿真失败的三类原因：环境 / 依赖 / 时序

> §9 按 `rehost_blocker` 归因（rootfs/init/nvram/…）；本节按**可观测现象**归因，用于快速分流。
> 先判类，再进 §9 的具体支，避免一上来就改 QEMU 参数。

### 11.1 环境类：宿主/虚拟化/网络

| 现象 | 先查 | 命令 | 判定 |
| --- | --- | --- | --- |
| QEMU 进程起但无串口输出 | `console=`、`-nographic`、内核是否带该串口驱动 | `qemu-system-<arch> -M help`；串口日志 | 环境不通 → 换 ttyS0/ttyAMA0 |
| tap/bridge 创建失败 | 权限、`/dev/net/tun`、残留接口 | `ls -l /dev/net/tun`；`ip link` | 环境 → 改 user 模式单端口 |
| 宿主 CPU 不支持该加速 | KVM/TCG 选择 | `qemu-system-<arch> -accel help` | 环境 → 用 TCG 慢跑 |
| 磁盘镜像被宿主占用 | loop 设备/挂载残留 | `losetup -a`；`mount \| grep rootfs` | 环境 → 释放后再起 |

### 11.2 依赖类：库/设备/配置

| 现象 | 先查 | 命令 | 判定 |
| --- | --- | --- | --- |
| `Exec format error` | 架构/端序 | `readelf -h bin/busybox` | 依赖/ABI → 换 qemu |
| `No such file or directory` | loader/库缺失 | `readelf -l \| grep interpreter`；`ldd`（交叉时用 qemu `-L`） | 依赖 → 补库/静态 qemu |
| 服务启动即退 | NVRAM/`/dev`/配置 | 看 stderr；`strace -f`（副本） | 依赖 → 补桩 |
| `/dev/mtd*` 不存在 | 设备节点 | `ls -l /dev/mtd*` | 依赖 → 普通文件桩 |
| `/proc` 空 | 未挂 proc | `mount -t proc proc /proc`（副本） | 依赖 → 补挂载 |

### 11.3 时序类：启动顺序/看门狗/竞态

| 现象 | 先查 | 命令 | 判定 |
| --- | --- | --- | --- |
| 30–90 s 后整机复位 | 看门狗 | 串口复位源；`dmesg \| grep -i wdt` | 时序 → 副本禁用/喂狗 |
| 服务在 init 尚未就绪时启动 | init 顺序 | `grep -RIn` 启动脚本；日志时间戳 | 时序 → 调整顺序/加等待 |
| 网络服务时有时无 | DHCP/路由竞态 | guest `ip addr`；宿主 `ip route` | 时序 → 固定 IP/延迟请求 |
| 第一次请求 502，第二次正常 | 后端未就绪 | 两次 `curl` + 服务日志 | 时序 → 预热后再取证 |

### 11.4 三类归因的决策树

```text
仿真失败
├─ 完全没有串口/内核输出 ─────── 环境类
├─ 有内核输出但挂根/init 失败 ─── 依赖类（rootfs/init）
├─ 能起机但服务退出/端口不通 ─── 依赖类（nvram/dev）或时序类（watchdog）
└─ 服务短暂可用后消失 ──────── 时序类
```

记录时只写一个主类 + 一个 `rehost_blocker`，两者可以不同（例：主类=时序，blocker=watchdog）。

## 12. 命令与“通过长什么样”（仿真最小复验）

```bash
ROOT=work/fw-audit/rootfs
OUT=work/fw-audit/emu

# 1) 架构/loader 先对齐
readelf -h "$ROOT/bin/busybox" | grep -E 'Machine|Data'
readelf -l "$ROOT/bin/busybox" 2>/dev/null | grep -i interpreter

# 2) 单程序基线（必须能跑出 id）
sudo chroot "$ROOT" /usr/bin/qemu-mipsel-static /bin/sh -c 'id; uname -a'

# 3) 整机启动（参数按镜像调整），日志留档
qemu-system-mipsel -M malta -m 256M -kernel "$OUT/vmlinux" \
  -drive file="$OUT/rootfs.img",format=raw \
  -append "root=/dev/sda console=ttyS0" \
  -netdev user,id=n0,hostfwd=tcp::8080-:80 -device e1000,netdev=n0 \
  -nographic 2>&1 | tee "$OUT/qemu.log"

# 4) 服务三件套（另开终端）
ss -lntp | grep 8080
curl -isS --max-time 5 http://127.0.0.1:8080/ | sed -n '1,15p'
curl -isS --max-time 5 http://127.0.0.1:8080/cgi-bin/luci | sed -n '1,10p'
```

**通过长什么样**：

| 检查 | 通过 | 不通过（归到哪类） |
| --- | --- | --- |
| 单程序 | `id` 输出 `uid=`，`uname` 架构正确 | `Exec format error` → 环境/ABI |
| 内核 | 日志走到 `VFS: Mounted root` | panic → 依赖（root/驱动） |
| init | 出现 getty/login 或目标服务启动行 | 停在 `Starting...` → 依赖/时序 |
| 服务 | 端口 + 进程 + 动态响应 | 502/静态页 → 依赖（Web 根/CGI） |
| 稳定 | 连续 3 分钟无复位 | 60 s 复位 → 时序（看门狗） |

## 这一篇算"用对了"吗

- [ ] 我先按“环境/依赖/时序”分了三类，再决定改 QEMU 参数还是补桩
- [ ] 我的单程序验证与整机验证分开写，没有用 qemu-user 冒充整机
- [ ] J2 有端口、进程、动态响应三件套，且时间戳在同一窗口
- [ ] 我知道 30–90 s 复位多半是看门狗，不会写“固件不稳定”
- [ ] 所有桩/补丁只在副本，原镜像哈希未变
- [ ] 失败时我写了主类 + `rehost_blocker`，并给出已试命令的 rc
