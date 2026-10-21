# 03 模型常见失误：固件/IoT 域的 13 个坏习惯

> 配套 `firmware-iot/SKILL.md`。每条固定三段：**错误动作 → 为什么错 → 正确动作**。
> **适用**：让模型在解包、仿真、硬件和结论表达上少走弯路。
> **不适用**：替代真实工具输出；下面每条都要用命令/文件:行号落地。

### 1. 看到 `binwalk` 识别出签名就宣布“解包成功”

- 错误动作：贴一段 `binwalk fw.bin` 输出，说“已提取固件”。
- 为什么错：签名只是偏移线索；没有 `/etc`+`/bin`+`/lib` 的目录树，就没有可审计的 rootfs。
- 正确动作：跑 `binwalk -e`/`unsquashfs`/`ubireader` 后 `find rootfs -maxdepth 2`，确认关键目录与 `bin/busybox`，再写结论。

### 2. 把高熵直接判成“加密”

- 错误动作：熵 > 7.2 就写“镜像已加密，无法分析”。
- 为什么错：SquashFS/UBI/压缩 kernel 本身高熵；填充区也会拉高整体熵。
- 正确动作：同时看分块熵、strong 魔术、厂商头与字符串；无魔术才转解密/硬件路线（见 `06-container-carving-and-entropy.md`）。

### 3. 把 JFFS2 的 `0x1985` 当铁证

- 错误动作：在任意二进制里搜到 `85 19` 就写“发现 JFFS2 分区”。
- 为什么错：两字节序列在随机/压缩数据里高频出现，必须校验节点头、长度、CRC 与连续布局。
- 正确动作：用 `fw-triage` 的 `confidence` 字段区分 weak；再用 `jefferson`/`jffs2dump` 解出树才确认。

### 4. 对裸 firmware blob 套用“文件系统判据”

- 错误动作：拿到 Broadcom `rtecdc.bin` 或单个 `.efi`，仍要求“解出 /etc 才算成功”。
- 为什么错：这类输入是 vendor blob / PE 组件，本来就没有 rootfs；判据用错会得出假失败或假成功。
- 正确动作：先分类（PE/ELF/BRCM/TRX/裸流），改用节熵、版本/FWID、签名链判据；明确 J1/J2/J3 未达成。

### 5. 用 `strings | grep password` 的结果当凭据结论

- 错误动作：`strings` 命中 `password=` 就写“存在硬编码口令”。
- 为什么错：字符串可能来自帮助文本、测试样例、压缩资源；没有 `文件:行号` 与可用性验证就不是凭据。
- 正确动作：解包后在 rootfs 内定位到具体文件与行，脱敏记录；能否登录另做 J1 验证。

### 6. 把 `passwd` 第二字段 `x` 当空口令

- 错误动作：看到 `root:x:0:0` 就写“root 无口令”。
- 为什么错：`x` 表示口令在 `/etc/shadow`；空口令是第二个字段为空，锁定是 `!`/`*`。
- 正确动作：同时读 passwd 与 shadow，按 `awk -F:` 判空/锁定/UID0，再做登录验证。

### 7. 仿真进程起来就写“服务已跑通”

- 错误动作：`ps` 看到 `httpd` 或 FirmAE 打印 success，就宣布 J2。
- 为什么错：J2 要求端口监听 + 进程 + **真实业务响应** 同时成立；静态页/502 不算。
- 正确动作：`ss -lntp` + `ps` + `curl -i` 同一时刻取证；没有动态字段就继续补桩或转真机。

### 8. 在错误架构/端序上硬调 QEMU

- 错误动作：MIPS BE 镜像用 `qemu-mipsel`，报 `Exec format error` 后反复换参数。
- 为什么错：架构/端序由 ELF header 决定，选错时任何参数都不会成功。
- 正确动作：`readelf -h bin/busybox` 确认 `Machine`/`Data`，再选 `qemu-mips`/`qemu-mipsel`/`qemu-arm`/`qemu-aarch64`。

### 9. 忽略 NVRAM、`/dev/mtd`、看门狗这三类“环境桩”

- 错误动作：仿真里服务启动即退出，就断言“固件坏了/服务不可用”。
- 为什么错：厂商服务强依赖 NVRAM 键值、MTD 分区、`/proc`、随机数与看门狗喂狗。
- 正确动作：从固件字符串/默认配置提取桩值，补最小 `/dev` 与 nvram 脚本；副本上禁用看门狗并记录。

### 10. UART 乱码就换板子/放弃

- 错误动作：第一次串口输出乱码，判定“没有控制台”。
- 为什么错：乱码通常来自波特率、共地、TX/RX 接反或电平不匹配，不是没有 UART。
- 正确动作：先量 GND/VCC 与 IO 电平，只接 GND/TX/RX；依次试 115200/57600/38400/9600；必要时逻辑分析仪测位宽。

### 11. 把“解包出的示例密钥”当有效设备身份

- 错误动作：在 `/etc/ssl` 看到 `-----BEGIN PRIVATE KEY-----` 就写“设备私钥泄露，可伪造 OTA”。
- 为什么错：可能是测试密钥、占位符、已吊销证书；没有配对、链验证与设备侧接受证据就不能下结论。
- 正确动作：`openssl pkey`/`x509` 配对，记录指纹与用途；在授权环境验证设备/云是否接受，否则只写“候选”。

### 12. 把失败包装成“部分成功”

- 错误动作：解包失败但写“已获取固件结构”，或仿真失败写“服务基本可用”。
- 为什么错：这会让下游误判 J1/J2/J3 已达成，污染案例库与报告。
- 正确动作：按 `02-failure-criteria.md` 写清现象、判定、改走哪条、代价；`outcome` 用 `partial`/`failed`，并给出下一条路线的前置条件。

### 13. 把 `unsquashfs` 的 rc=0 当成“拿到 rootfs”

- 错误动作：`unsquashfs -d rootfs fw.bin` 退 0，就写“已解包 rootfs，可以开始审计”。
- 为什么错：rc=0 只说明镜像头部可读且能建文件；镜像可能是截断的分割块、只有元数据的空壳、或里面根本没有 init 与 shell。没有目录语义证据就写“rootfs”会把 J1 做成假成功。
- 正确动作：三门同时过才算拿到 rootfs：① `/etc/inittab` 或 `/etc/init.d/` 存在；② `/bin/sh` 或 `/bin/busybox` 存在且 `file` 显示目标架构 ELF；③ `/lib` 下有与其匹配的 `ld-musl*/ld-uClibc*/ld-linux*`。再用 `chroot rootfs /bin/sh -c id`（或 `qemu-<arch> -L rootfs`）能跑出 `uid=0`。缺哪门就写 `partial` 并注明（对应 J1 未达成）。

## 自检清单

交付前对每条结论问三句：

1. 这是观察、推断还是验证？（对应 `01-criteria.md` 的 E0–E3）
2. 证据能不能让另一个人照着命令复跑？
3. 如果去掉“应该/可能/大概”，结论还成立吗？

三句里有一句答不上来，就降级表述或补证据。

## 边界

- 这些失误不是“人品问题”，而是流程缺环；用脚本与判据表把缺环变成可机检项。
- 不把本文件当命令手册；具体命令见 `firmware-unpack.md`、`hardware-interfaces.md`、`emulation-and-fuzz.md`。
