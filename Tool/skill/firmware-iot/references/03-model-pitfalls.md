# 03 模型常见失误：固件/IoT 域的 21 个坏习惯

> 配套 `firmware-iot/SKILL.md`。每条固定三段：**错误动作 → 为什么错 → 正确动作**。
> **范围**：让模型在解包、仿真、硬件和结论表达上少走弯路。
> 用法：每条都要用命令/文件:行号落地；本文是纠偏清单，真实工具输出才是证据。

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

### 14. 把“解包出目录”当“文件系统审计完成”

- 错误动作：`unsquashfs` 出目录后直接写“已完成文件系统分析”，不列启动链、不看服务。
- 为什么错：解包只是拿到输入面；没有“开机 → 服务 → 用户 → 端口 → 参数”的链路，仍然只是 E0/E1。
- 正确动作：按 `filesystem-and-credentials.md` §7 画链路，每个节点给 `文件:行号`；画不出就写“未完成”。

### 15. 只扫 `/etc`，不看 NVRAM、overlay 与 `rootfs_data`

- 错误动作：只审 `rootfs/etc/passwd`，结论写“无额外账号”。
- 为什么错：OpenWrt/UBI 设备常在 `rootfs_data` 覆盖层、NVRAM、`/etc/config` 里存实际口令与云 token；主 rootfs 可能是出厂默认。
- 正确动作：解 UBI 的 `rootfs_data`、读 NVRAM 默认值、对比 `etc/config` 与 `etc/passwd`；把覆盖层路径写进证据。

### 16. 把 qemu-user 能跑 `/bin/sh` 当“整机可仿真”

- 错误动作：`qemu-mipsel -L rootfs /bin/sh` 成功，就写“固件可仿真，服务可跑”。
- 为什么错：qemu-user 只证明单程序与库匹配；init、内核、网络、NVRAM、看门狗都没参与。
- 正确动作：把 qemu-user 定位为“单程序验证”；整机必须 qemu-system/FirmAE 过“挂根 + init + 监听 + 业务回包”四关。

### 17. 在 rootfs 里直接跑厂商二进制，不看 loader/ABI

- 错误动作：`chroot rootfs /usr/sbin/httpd` 报 `No such file or directory`，就写“二进制损坏”。
- 为什么错：多数是动态 loader 路径不存在（`/lib/ld-uClibc.so.0`）或 ABI 不匹配，不是文件坏。
- 正确动作：`readelf -l | grep interpreter`、`readelf -A` 看 ABI；补 loader/库或用 static qemu；记录 `file` 与 `readelf -h`。

### 18. 凭据扫描只 grep 明文，不看编码/分段/配置引用

- 错误动作：`grep -ri password` 无结果就写“无硬编码凭据”。
- 为什么错：凭据可能是 base64、十六进制、分段拼接、NVRAM 默认、编译进二进制的常量，或只在 `config` 里引用。
- 正确动作：按 `filesystem-and-credentials.md` 的扫描判据做多编码解码 + 二进制 strings + 配置引用追踪；无命中写“未发现”，不写“不存在”。

### 19. 把“服务监听 0.0.0.0”当“外网可达”

- 错误动作：`ss` 看到 `0.0.0.0:80` 就写“管理面暴露在公网”。
- 为什么错：设备可能在 NAT/防火墙后，或该端口只对 LAN 网桥开放；监听地址不等于路由可达。
- 正确动作：写清监听地址、绑定网卡、防火墙规则、测试点位置；没有从外部测过就标 `inferred`。

### 20. 把 UART 有输出当“能中断 bootloader”

- 错误动作：串口能看到 U-Boot 日志，就写“可改 bootargs”。
- 为什么错：很多厂商关闭 U-Boot 控制台/按键窗口，或设置了 `bootdelay=0`；只读日志不等于可输入。
- 正确动作：上电瞬间连按中断键，确认出现提示符并可 `printenv`；不能中断就只写“可读日志”，转 SPI/JTAG。

### 21. 把固件版本号当“补丁级别”

- 错误动作：版本字符串 `1.2.3` 比 CVE 修复版本旧，就写“存在该漏洞”。
- 为什么错：厂商常 backport 修复但不改版本号；也可能改了版本号却未修。
- 正确动作：定位到具体函数/二进制差异，或拿到厂商 changelog；版本只作线索（E0），不单独定漏洞。

## 21 条速查（打印版）

| # | 一句话 | 对应正确动作 |
| :-: | --- | --- |
| 1 | 签名 ≠ rootfs | 看 `/etc`+`/bin`+`/lib` |
| 2 | 高熵 ≠ 加密 | 看 `high_block_ratio` + 魔术 |
| 3 | `0x1985` ≠ JFFS2 | 校验节点/CRC |
| 4 | 裸 blob 不套 fs 判据 | 先分类 |
| 5 | `grep password` ≠ 凭据 | 文件:行号 + 可用性 |
| 6 | `x` ≠ 空口令 | 读 shadow |
| 7 | 进程在 ≠ J2 | 端口+业务响应 |
| 8 | 架构错，参数白调 | `readelf -h` |
| 9 | 启动即退，先补桩 | NVRAM/`/dev`/看门狗 |
| 10 | 乱码先量电压 | 共地/交叉/波特率 |
| 11 | 示例密钥 ≠ 设备身份 | 配对 + 设备接受 |
| 12 | 失败要写字段 | 现象/判定/改走/代价 |
| 13 | rc=0 ≠ rootfs 完整 | 三门 + `id` |
| 14 | 有目录 ≠ 审计完成 | 画服务链 |
| 15 | 只看 `/etc` 会漏 | NVRAM/overlay |
| 16 | qemu-user ≠ 整机 | 四关 |
| 17 | 跑不起来先看 loader | `readelf -l/-A` |
| 18 | 明文 grep 会漏 | 多编码 + 二进制 |
| 19 | 监听 ≠ 可达 | 路由/防火墙 |
| 20 | 有日志 ≠ 能输入 | 中断提示符 |
| 21 | 版本旧 ≠ 有漏洞 | 函数/差异 |

## 纠偏命令：把“我觉得”变成“我验证了”

```bash
ROOT=work/fw-audit/rootfs

# 1) 三门判据（对应第 13 条）
test -e "$ROOT/etc" && test -d "$ROOT/bin" -o -d "$ROOT/usr/bin" && test -d "$ROOT/lib" \
  && echo "rootfs-gate: pass" || echo "rootfs-gate: fail"
file "$ROOT/bin/busybox" 2>/dev/null
readelf -l "$ROOT/bin/busybox" 2>/dev/null | grep -i interpreter

# 2) 架构/ABI（第 8、17 条）
readelf -h "$ROOT/bin/busybox" | grep -E 'Machine|Data'
readelf -A "$ROOT/bin/busybox" 2>/dev/null | head

# 3) 服务三件套（第 7、16 条）
ss -lntp 2>/dev/null | head
ps w 2>/dev/null | grep -E 'httpd|uhttpd|cgi' | grep -v grep
curl -isS --max-time 5 http://127.0.0.1:80/ | sed -n '1,12p'

# 4) 凭据扫描的多编码入口（第 18 条）
grep -RInE 'password|passwd|secret|token|api[_-]?key' "$ROOT/etc" "$ROOT/www" 2>/dev/null | head -40
strings -a "$ROOT/usr/sbin/httpd" 2>/dev/null | grep -Ei 'passwd|secret|token' | head
```

**通过长什么样**：

| 反失误 | 通过 | 不通过 |
| --- | --- | --- |
| rootfs 三门 | 三行都是 pass，busybox 有 ELF 头 | 缺 `/lib` 或 `file` 报 data |
| 架构 | `Machine/Data` 与 qemu 选择一致 | 不一致 → 换 qemu 而非换参数 |
| J2 | `curl` 有设备字段/JSON/登录挑战 | 只有 `It works!` |
| 凭据 | 命中能定位到 `文件:行号` | 只有字符串列表 |
| 结论 | 每条能指回上面某条命令 | 只有“经验上应该” |

## 失误 → 命令 → 通过标准（速查）

| 失误 | 一条纠偏命令 | 通过标准 |
| :-: | --- | --- |
| 1 签名当 rootfs | `find rootfs -maxdepth 2 -type d` | 有 `/etc`+`/bin`+`/lib` |
| 2 高熵当加密 | `jq .entropy triage.json` | 同时看 `high_block_ratio` |
| 3 `0x1985` 当 JFFS2 | `jefferson -d out part.bin` | 节点可解、目录完整 |
| 4 裸 blob 套 fs | `file fw.bin` | 先分类再选判据 |
| 5 字符串当凭据 | `awk -F: '$3==0' etc/passwd` | `文件:行号` + 可用性 |
| 6 `x` 当空口令 | `cat etc/shadow` | 空字段/`!` 分开 |
| 7 进程在当 J2 | `ss -lntp; curl -i` | 端口+进程+动态响应 |
| 8 架构错 | `readelf -h bin/busybox` | Machine/Data 与 qemu 一致 |
| 9 启动即退当坏固件 | `strace -f ./svc` | 缺 NVRAM/`/dev` 可定位 |
| 10 乱码换板 | `picocom -b 57600` | 可读日志 |
| 11 示例密钥当身份 | `openssl pkey -pubout` | 配对 + 设备接受 |
| 12 失败包装成功 | `fw-accept.py` | `outcome=partial/failed` |
| 13 rc=0 当完整 | `file rootfs/bin/busybox` | ELF + loader 匹配 |

```bash
# 把这张表变成一次体检（缺工具时输出 blocked，不抛栈）
ROOT=work/fw-audit/rootfs
for c in "etc/passwd" "bin/busybox" "lib"; do
  test -e "$ROOT/$c" && echo "ok  $c" || echo "MISS $c"
done
readelf -h "$ROOT/bin/busybox" 2>/dev/null | grep -E 'Machine|Data' || echo "MISS readelf"
ss -lnt 2>/dev/null | grep -E ':(80|443|23|22) ' || echo "no-svc-port"
```

**通过长什么样**：三行 `ok`、`Machine/Data` 与目标架构一致、至少一个预期端口；任何 `MISS` 都回到对应条目，而不是继续往下写结论。

## 最后一条：把“知道”变成“能复跑”

知道一个坑，不等于不会踩。把本文对应条目写成一条命令，粘进自己的检查清单：

```bash
# 例：每次交付前跑一次 rootfs 三门，而不是靠记忆
ROOT=work/fw-audit/rootfs
test -d "$ROOT/etc" && test -d "$ROOT/lib" && file "$ROOT/bin/busybox" >/dev/null \
  && echo PASS || echo FAIL
```

命令失败，就回到对应条目；命令不存在，说明你还没真正会用。

## 这一篇算"用对了"吗

- [ ] 我能说出本次分析中“观察/推断/验证”各是哪一条，没有混写
- [ ] 我至少避开了 21 条里的三条，并能指出当时差点踩的是哪条
- [ ] 我的每个结论都能被另一个人用本文的命令复跑
- [ ] 我没有把“解包成功/qemu 能跑/端口监听”当成闭环
- [ ] 我把“未验证”写在了报告里，而不是用“应该可以”盖过去
- [ ] 我删掉了所有没有命令或 `文件:行号` 支撑的形容词
