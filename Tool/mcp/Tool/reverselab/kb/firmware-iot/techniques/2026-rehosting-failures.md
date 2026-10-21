# 2026 战例：固件再托管（rehosting）失败面分类

> 战例 KB-FW-2026-03 · 收录 2026-10-20 · 单篇 ≤200 行 · 只写“卡在哪、怎么证”，不复述仿真教程。

## 来源与日期

- FirmPilot（2026-07 公开预印本）：用 LLM 生成外设/服务桩以加速固件再托管，报告里给出成功率与失败簇。
- Khost，USENIX Security '26：内核感知的 Linux 固件再托管，重点在自定义内核模块与启动链保真。
- FirmAE/Firmadyne 作为基线对照（2019–2025 沿用），其 `success` 判定长期被误当“跑起来了”。
- 本页为公开材料 + 既有 board 经验的失败面蒸馏；不含本机仿真记录，阈值需在目标固件上重测。

## 场景

入口信号（任一条出现，就进入 rehosting 评估而不是继续 `binwalk`）：

- 已解出文件系统，但服务在 QEMU 里起不来，或起来后只返回 404/连接重置。
- 启动脚本依赖 `/dev/nvram`、`/proc/xxx`、私有 ioctl、GPIO/LED、看门狗。
- 内核是厂商魔改版（`vermagic` 与 mainline 不符），或关键逻辑在 `.ko` 里。
- 有 secure boot / 签名校验 / 双分区回滚，镜像不可直接替换。

失败面先分类，再决定是否值得继续投入：

| 失败面 | 典型现象 | 是否可绕过 |
| :-- | :-- | :-- |
| 启动链校验 | 卡在 U-Boot 校验，或内核 panic 于 dm-verity | 通常不可，转静态/硬件 |
| 私有内核模块 | 模块加载失败、ioctl 返回 ENOTTY | 可打桩，工作量大 |
| NVRAM/HAL 缺失 | 服务读到空配置后退出 | 可最小桩 |
| 多阶段用户空间 | init 脚本互相拉起，缺一环全挂 | 可，需按依赖排序 |
| 看门狗复位 | 起来 30–120s 后重启 | 可屏蔽定时器 |
| 架构/字节序不支持 | `qemu-system-*` 无对应 target | 不可，转静态 |

## 命令

```bash
# 0) 先固化输入与容器判定
sha256sum firmware.bin; python Tool/scripts/fw-triage.py --file firmware.bin --json
binwalk firmware.bin | head -30
file squashfs-root/bin/busybox squashfs-root/lib/modules/*/*.ko 2>/dev/null

# 1) 启动链与内核保真
strings -a firmware.bin | grep -m5 -E 'U-Boot|Linux version|vermagic'
cat squashfs-root/etc/inittab 2>/dev/null; ls squashfs-root/etc/init.d/ 2>/dev/null
grep -RInE 'nvram|watchdog|/dev/(gpio|mem|mtd)' squashfs-root/etc | head -20

# 2) 跑一次并留完整串口/内核日志（失败也要留档）
timeout 300 qemu-system-arm -M virt -kernel zImage -drive file=rootfs.ext4,format=raw \
  -append 'console=ttyS0 root=/dev/vda rw' -nographic -serial mon:stdio \
  2>&1 | tee evidence/qemu-boot.log

# 3) 基线工具（有则用，结论必须回落到 J1/J2/J3）
#    FirmAE: ./run.sh <firmware> ；Khost: 按论文 artifact 的 runner
#    跑完比对：进程表、监听端口、真实业务响应三件是否同时成立
ss -lntp 2>/dev/null; ps -ef | head -20
curl -sS -m 5 -o /dev/null -w '%{http_code}\n' http://127.0.0.1:80/

# 4) 打桩后复测同一请求，确认差异只来自桩
strace -f -e trace=openat,ioctl -p "$(pgrep -f httpd | head -1)" 2>&1 | head -40
```

## 判据表

| 字段 | 取值 | 成立阈值 | 证据 |
| :-- | :-- | :-- | :-- |
| `rehost_blocker` | `boot-verify` / `vendor-ko` / `nvram-hal` / `multi-stage` / `watchdog` / `arch-unsupported` / `none` | 必须落到单一枚举值，并附首条报错日志行号 | `qemu-boot.log` + `evidence/blocker.txt` |
| `boot_to_userspace` | `true/false` | `true` 需看到 init 完成、非仅 U-Boot 横幅 | 串口末 50 行 |
| `service_listen` | 端口集合 | ≥1 个业务端口处于 LISTEN，且进程可指认 | `ss -lntp` 输出 |
| `business_response` | HTTP 码 + body sha256 | 与真机/公开固件行为一致（动态字段归一化后一致） | `curl` 输出 + 归一化哈希 |
| `stub_set` | 桩文件名与覆盖的路径/ioctl | 每个桩都有“缺它就挂”的对照实验 | `stubs/` + 对照日志 |
| `kernel_fidelity` | `mainline` / `vendor-patched` | 与 `vermagic` 一致；`vendor-patched` 时不得宣称“等价真机” | `uname -a`（仿真内） |
| `time_to_service` | 秒 | 记录真实值，>300s 视为不可用于批量 triage | 计时表 |

只有 `service_listen` 与 `business_response` 同时成立，才允许写“再托管可用”；
`rehost_blocker` 非 `none` 时，结论只能是“部分可用 + 明确卡点”。

## 失败判据

- 只看到 U-Boot 横幅或内核启动日志，就写“仿真成功” → 判否，J1 未达。
- FirmAE 报 `success` 但端口无业务响应，或响应是 busybox 默认页 → 判否（工具口径 ≠ 判据）。
- 打桩后服务起来了，但桩自身返回硬编码数据 → 标 `stub-faked`，不得用于漏洞结论。
- 同一固件两次启动行为不同（看门狗/随机 MAC/时间戳）→ 先固化熵源，再谈复现。
- 私有 `.ko` 无法加载且无法反编译出 ioctl 语义 → 停，转静态分析或硬件接入。
- 触发厂商激活/授权服务器校验、需要外网回连 → 不做绕过，记录 `license-gate`。
- 镜像被改写后哈希变化却仍声称“原件复现” → 证据链断，作废。

> 边界：只处理授权获取的固件；不提供绕过 secure boot 的步骤；`stub_set` 必须可回退（原件只读）；
> 仿真结论不等价于真机结论，凡涉及硬件时序的漏洞必须在真机复核。

## 与 reference 的关系

- 仿真方法与最小桩：[emulation-and-fuzz.md](../../../../../../../Tool/skill/firmware-iot/references/emulation-and-fuzz.md)。
- 解包与文件系统：[firmware-unpack.md](../../../../../../../Tool/skill/firmware-iot/references/firmware-unpack.md)。
- 失败判据：[02-failure-criteria.md](../../../../../../../Tool/skill/firmware-iot/references/02-failure-criteria.md)。
- 同 board 邻近篇：[02-uart-and-emulation.md](02-uart-and-emulation.md)（J1/J2 的原始口径）、
  [06-failure-criteria.md](06-failure-criteria.md)（停机与改走）、
  [07-container-triage.md](07-container-triage.md)（先定容器再谈仿真）。
