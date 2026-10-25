# 固件解包与仿真参考（firmware-unpack）

> 配套 `firmware-iot/SKILL.md`。所有命令默认在**副本**上执行；原始镜像保持只读。
> 约定：`FW=firmware.bin`、`OUT=work/<task>/unpack`。每步记录工具版本与输出哈希。

## 0. 先采集元信息

```bash
mkdir -p "$OUT" && cp --reflink=auto "$FW" "$OUT/orig.bin"
sha256sum "$OUT/orig.bin" | tee "$OUT/orig.sha256"
file "$OUT/orig.bin"
stat -c '%s bytes' "$OUT/orig.bin"
binwalk "$OUT/orig.bin" | head -50
```

判据：

- 有明确容器/文件系统签名（SquashFS、UBI、JFFS2、CramFS、cpio、tar、gzip、uImage）。
- 只有高熵且无已知签名 → 可能加密/厂商自定义，转第 6 节，不要反复 `binwalk -e`。

## 1. 固件获取与完整性

### 1.1 厂商包 / OTA

```bash
# 从设备/App 抓到的 URL 直接取，保留响应头
curl -fL --retry 3 -D "$OUT/ota.headers" -o "$OUT/ota.bin" "$OTA_URL"
sha256sum "$OUT/ota.bin"
# 外层可能是 zip/tar/厂商容器
7z l "$OUT/ota.bin" 2>/dev/null || tar -tvf "$OUT/ota.bin" 2>/dev/null | head
```

判据：长度与 OTA 响应 `Content-Length` 一致；解出的镜像能被 `binwalk` 识别；版本号与设备当前版本可对应。

### 1.2 在线设备分区转储

```bash
cat /proc/mtd
# 例：mtd0: 00040000 00010000 "u-boot"
dd if=/dev/mtd3 of=/tmp/rootfs.bin bs=4096
sha256sum /tmp/rootfs.bin
# 需要 OOB 时
nanddump -o -f /tmp/nand.bin /dev/mtd3
```

判据：`/proc/mtd` 的长度与 dump 文件大小一致；连续两次 dump 哈希一致；NAND 场景保留 OOB。

### 1.3 U-Boot 读取

```text
sf probe 0
sf read 0x80000000 0x50000 0x200000   # 地址/长度按实际 mtdparts 调整
md.b 0x80000000 0x40
```

判据：主机收到的文件长度等于读取长度；首部有 SquashFS/UBI 魔术；必要时用 `crc32` 比对。

### 1.4 SPI 闪存离线读取

```bash
flashrom -p ch341a_spi -r "$OUT/spi-1.bin"
flashrom -p ch341a_spi -r "$OUT/spi-2.bin"
sha256sum "$OUT/spi-1.bin" "$OUT/spi-2.bin"
```

判据：两次读取哈希一致；芯片型号与丝印一致；1.8V 芯片必须使用 1.8V 适配器。板上直读不稳定时断电或焊下芯片。

## 2. binwalk：识别、切分、递归

```bash
binwalk "$OUT/orig.bin"                          # 只识别
binwalk -e --run-as=root -C "$OUT" "$OUT/orig.bin"  # 递归提取
binwalk --dd='.*' -C "$OUT/raw" "$OUT/orig.bin"      # 仅按签名切分
binwalk -E "$OUT/orig.bin" | head -40                 # 熵分析
```

判据：`_orig.bin.extracted/` 出现目录树或可挂载镜像；高熵区与文件系统偏移对应；递归层数 ≥2（容器 → 内核/rootfs → 可能的第二层 SquashFS）。整片高熵且无签名 → 转加密判断。

偏移修正：按 binwalk 的十进制偏移切分后 `file` 复判。

```bash
dd if="$OUT/orig.bin" of="$OUT/part.bin" bs=1 skip=<OFFSET> count=<LENGTH>
```

## 3. UBI / UBIFS

```bash
ubireader_display_info "$OUT/orig.bin" | head -80
ubireader_extract_images -o "$OUT/ubi" "$OUT/orig.bin"
ubireader_extract_files -o "$OUT/ubi_root" "$OUT/ubi/"*.ubi
```

判据：能列出卷（`rootfs`/`rootfs_data`/`kernel`）且卷内有完整根目录；`rootfs_data` 常含配置覆盖层，别漏。报 `bad magic` 时确认偏移（跳过厂商头）、是否含 OOB，再试 `--leb-start`/`--peb-start`。NAND 必须保留 OOB 与原始布局，否则 LEB 映射会失败。

## 4. SquashFS / JFFS2 / CramFS / cpio

### 4.1 SquashFS

```bash
unsquashfs -s "$OUT/rootfs.squashfs"          # 看版本/压缩/块大小
unsquashfs -d "$OUT/rootfs" -f "$OUT/rootfs.squashfs"
# 非标/厂商魔改
sasquatch -d "$OUT/rootfs-sas" "$OUT/rootfs.squashfs"
```

判据：`/etc`、`/bin`、`/lib`、`/www`（或 `/usr`）齐全；`bin/busybox` 可被 `file` 识别为对应架构 ELF。
`unsquashfs` 报 “invalid magic/unsupported compression” 时换 `sasquatch` 或从内核里确认压缩算法。

### 4.2 JFFS2

```bash
jefferson -d "$OUT/jffs2" "$OUT/rootfs.jffs2"
# 或
binwalk -e --run-as=root "$OUT/rootfs.jffs2"
```

判据：节点可解析、目录树完整；出现大量坏节点时检查是否混入 OOB/ECC 或镜像被截断。

### 4.3 CramFS / cpio / initramfs

```bash
cramfsck -x "$OUT/cramfs" "$OUT/rootfs.cramfs"
mkdir -p "$OUT/initramfs" && cd "$OUT/initramfs" && cpio -idmv < ../initramfs.cpio
```

判据：能拿到 init 脚本与 `/bin`；initramfs 常藏真实根文件系统或升级逻辑。

## 5. 文件系统审计最小集

```bash
ROOT="$OUT/rootfs"
grep -RInE 'root:|admin:|password|passwd|shadow' "$ROOT/etc" 2>/dev/null | head -60
cat "$ROOT/etc/passwd" "$ROOT/etc/shadow" 2>/dev/null
find "$ROOT" -type f \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' -o -name 'authorized_keys' \) -print
cat "$ROOT/etc/inittab" 2>/dev/null
find "$ROOT/etc" -maxdepth 3 -type f \( -name 'rcS' -o -name 'S*' -o -name '*.service' \) -print | head -40
grep -RInE 'telnetd|dropbear|httpd|uhttpd|goahead|lighttpd|nvram|system\(|popen\(' "$ROOT" 2>/dev/null | head -80
file "$ROOT/bin/busybox" "$ROOT"/bin/* 2>/dev/null | head -30
```

判据：能写出“开机脚本 → 启动的服务 → 运行用户 → 外部入口 → 可控参数”的链路；敏感项有文件:行号定位。

## 6. 加密 / 非标格式判断

- 高熵 + 无已知签名 + 头部随机：可能整包加密。找 U-Boot/内核里的解密函数、OTP/efuse 密钥、厂商升级工具。
- 头部有厂商结构体：按长度/CRC 字段切负载，保留原头；不要改头后回刷。
- 文件系统魔改：比对内核源码的 `squashfs` 解压器、厂商私有 `mtd` 驱动；必要时用内核自身挂载。
- 判据：能明确说出“加密算法/密钥来源/解密点”，或证据充分判定为不可离线解包并转入硬件/UART 路线。

## 7. 仿真：qemu-user / qemu-system / FirmAE

### 7.1 qemu-user + chroot（最快）

```bash
# 架构按 readelf 结果替换：mipsel/mips/arm/armeb/aarch64
cp /usr/bin/qemu-mipsel "$ROOT/usr/bin/" 2>/dev/null || true
sudo chroot "$ROOT" /usr/bin/qemu-mipsel /bin/sh
# 或指定解释器
qemu-mipsel -L "$ROOT" "$ROOT/bin/busybox" sh
```

判据：能执行 `busybox id`、`cat /etc/passwd`；缺库时报错能定位到具体 `.so`，补库后复测。

### 7.2 qemu-system（完整系统）

```bash
qemu-system-mipsel -M malta -m 256M -kernel "$OUT/vmlinux" \
  -drive file="$OUT/rootfs.img",format=raw \
  -append "root=/dev/sda console=ttyS0" \
  -netdev user,id=n0 -device e1000,netdev=n0 -nographic
```

判据：内核日志走到根挂载，出现登录提示或 init 输出；网络可从宿主访问（配合 hostfwd/tap）。
常见修复：`root=` 设备名、`console=`、init 路径、`/dev` 缺失、NVRAM 初始化。

### 7.3 FirmAE / Firmadyne

```bash
./run.sh -r mipsel "$OUT/orig.bin"     # FirmAE，参数以本地版本为准
# Firmadyne：extractor.py → getArch.sh → makeImage.sh → inferNetwork.sh → scratch/<id>/run.sh
```

判据：网络推断成功、Web 端口可访问；失败读 `scratch/<id>/qemu.*.log`，定位 NVRAM/分区/内核问题。

### 7.4 仿真判据（防“假成功”）

```bash
curl -sv --max-time 5 http://127.0.0.1:<PORT>/ | head -30
nc -vz 127.0.0.1 <PORT>
```

- 进程存在 ≠ 服务可用；必须有真实协议响应（HTML、JSON、登录页、CGI 输出）。
- CGI 要验证执行权限、解释器路径、`PATH_INFO`/查询参数是否可控。
- 记录可重建步骤：架构、内核、磁盘布局、网络参数、NVRAM 桩、启动命令。

## 8. 交付清单

- `orig.sha256`、原始镜像、解包目录、工具版本。
- 文件系统审计清单（文件:行号、脱敏值、用途）+ 仿真启动脚本与验证请求。
- J1/J2/J3 证据：串口日志、shell 会话、HTTP 响应、PoC 与复现步骤；失败日志与降级说明。

## 9. 端到端走查：从 `.bin` 到可审计 rootfs（时间盒版）

> 这一节把前面各节串成一条可执行流水线。每阶段有**入口、命令、门禁、失败去向、时间盒**；
> 任一阶段不过门禁就停下，需要先确认“先往下跑，回头再补”。

### 阶段 0：采集与坐标（5 min）

```bash
FW=firmware.bin; OUT=work/fw-e2e
mkdir -p "$OUT"; cp --reflink=auto "$FW" "$OUT/orig.bin"
sha256sum "$OUT/orig.bin" | tee "$OUT/orig.sha256"
file "$OUT/orig.bin"; stat -c '%s bytes' "$OUT/orig.bin"
python Tool/skill/firmware-iot/scripts/fw-triage.py --file "$OUT/orig.bin" --json > "$OUT/triage.json"
```

**门禁**：哈希非空、大小 > 0、`file` 能给出类型（哪怕是 data）。
**不过**：文件不可读/被截断 → 重采；不要从半截镜像开始。

### 阶段 1：分层与切分（10–20 min）

```bash
python Tool/skill/firmware-iot/scripts/fw-repro.py --file "$OUT/orig.bin" \
  --out-dir "$OUT/repro" --json > "$OUT/repro.json"
jq '{primary, offset, carved_sha256, extraction: .extraction.status}' "$OUT/repro.json"
find "$OUT/repro" -maxdepth 1 -type f -name 'carved-*' -exec file {} \;
```

**门禁**：`primary` 与 `file`/厂商标签一致；切出物有 magic。
**不过**：只有 weak → 回到 `06-container-carving-and-entropy.md` 做二次确认；不要直接 `binwalk -e`。

### 阶段 2：解包（15–60 min）

| 容器 | 命令 | 门禁 |
| --- | --- | --- |
| SquashFS | `unsquashfs -d "$OUT/rootfs" -f part.bin` | `/etc`+`/bin`+`/lib` |
| 魔改 SquashFS | `sasquatch -d "$OUT/rootfs" part.bin` | 同上 + `file busybox` |
| UBI | `ubireader_extract_files -o "$OUT/ubi" ubi.bin` | 卷列表 + `rootfs_data` |
| JFFS2 | `jefferson -d "$OUT/rootfs" part.bin` | 节点日志 + 目录树 |
| CramFS | `cramfsck -x "$OUT/rootfs" part.bin` | init + `/bin` |
| tar/cpio | `tar -xvf` / `cpio -idmv` | 条目名完整 |

**门禁**：`find "$OUT/rootfs" -maxdepth 2 -type d` 能看到关键目录；`bin/busybox` 或 `bin/sh` 是 ELF。
**不过**：只有 kernel/DTB → `02-failure-criteria.md` 第 1 行；`unsupported compression` → `sasquatch`/内核解压器。

### 阶段 3：审计（20–40 min）

```bash
ROOT="$OUT/rootfs"
# 账号
awk -F: '$3==0{print "uid0",$1}' "$ROOT/etc/passwd" 2>/dev/null
# 启动链
grep -RInE 'telnetd|dropbear|httpd|uhttpd|nvram|system\(|popen\(' "$ROOT/etc" 2>/dev/null | head -60
# 凭据/密钥
find "$ROOT" -type f \( -name '*.pem' -o -name '*.key' -o -name 'authorized_keys' \) -print
# Web 入口
find "$ROOT/www" "$ROOT/usr/lib/lua" -maxdepth 3 -type f 2>/dev/null | head -20
```

**门禁**：能画出“开机脚本 → 服务 → 用户 → 端口 → 参数”，每跳有 `文件:行号`。
**不过**：只有 hash 无入口 → 只能写候选；服务链断 → 在 `02-failure-criteria.md` 里归因。

### 阶段 4：验证（30–90 min）

```bash
# 单程序基线
sudo chroot "$ROOT" /usr/bin/qemu-mipsel-static /bin/sh -c 'id; uname -a'
# 服务三件套（仿真或真机）
ss -lntp; ps w | grep -E 'httpd|uhttpd|cgi' | grep -v grep
curl -isS --max-time 5 http://127.0.0.1:80/ | sed -n '1,15p'
```

**门禁**：J1 有 `id`；J2 端口+进程+动态响应；J3 两次一致。
**不过**：进程在但端口不通 → 补桩/看日志；端口通但静态页 → 不算 J2。

### 阶段 5：交付（10 min）

```bash
python Tool/skill/firmware-iot/scripts/fw-accept.py
python Tool/scripts/domain-gate.py --domain firmware-iot
```

**门禁**：字段/hash/refs/lessons 全 PASS；报告写清 J1/J2/J3 哪条成立、证据在哪、哪条未验证。
**不过**：hash mismatch/phantom ref → 重跑产物，不改 JSON 里的哈希。

### 总时间盒与止损

| 阶段 | 正常 | 超时动作 |
| --- | --- | --- |
| 0 采集 | 5 min | 文件不可读 → 重采 |
| 1 切分 | 20 min | 两工具不一致 → 人工看头 |
| 2 解包 | 60 min | 两次失败 → 转静态/硬件 |
| 3 审计 | 40 min | 画不出链 → 降级为侦察 |
| 4 验证 | 90 min | 环境问题 → 记录并转真机 |
| 5 交付 | 10 min | 门禁失败 → 修产物不修哈希 |

## 10. 命令与“通过长什么样”（端到端复验）

```bash
OUT=work/fw-e2e
# 一行体检：每项输出一个布尔/计数
echo "hash:   $(test -s "$OUT/orig.sha256" && echo ok || echo fail)"
echo "strong: $(jq '[.containers[]?|select(.confidence=="high")]|length' "$OUT/triage.json")"
echo "rootfs: $(test -d "$OUT/rootfs/etc" && test -d "$OUT/rootfs/lib" && echo ok || echo fail)"
echo "busybox:$(file -b "$OUT/rootfs/bin/busybox" 2>/dev/null | cut -c1-40)"
echo "uid0:   $(awk -F: '$3==0' "$OUT/rootfs/etc/passwd" 2>/dev/null | wc -l)"
echo "svc:    $(ss -lnt 2>/dev/null | grep -c ':80 ')"
```

**通过长什么样**：

| 输出行 | 通过 | 不通过 |
| --- | --- | --- |
| `hash` | `ok` | `fail` → 重采 |
| `strong` | ≥1 | 0 → 切分路线错 |
| `rootfs` | `ok` | `fail` → 解包未完成 |
| `busybox` | `ELF ... MIPS/ARM` | `data`/空 |
| `uid0` | ≥1 且可解释 | 0 但脚本有 root → 账号面异常 |
| `svc` | ≥1 且 `curl` 有动态字段 | 0 → 服务未起 |

## 这一篇算"用对了"吗

- [ ] 我按阶段跑，且每阶段过了门禁才进入下一阶段
- [ ] 我的 rootfs 有 `/etc`+`/bin`+`/lib`，busybox 架构与 SoC 一致
- [ ] 我能画出“开机 → 服务 → 用户 → 端口 → 参数”的链路
- [ ] 我没有把 `unsquashfs` rc=0 或 qemu-user 能跑 sh 当闭环
- [ ] 失败阶段写清了 `blocked_at`、已试命令 rc 与下一条路线
- [ ] 交付时 `fw-accept.py` 与 domain-gate 都 PASS，且未改 JSON 哈希
