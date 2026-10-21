# 01 解包与文件系统

> 配套 `firmware-iot/SKILL.md`、`references/firmware-unpack.md`、
> `references/filesystem-and-credentials.md`。所有命令在副本上执行，原始镜像只读。
## 0. 元信息与容器判定

```bash
FW=firmware.bin
OUT=work/fw-audit
mkdir -p "$OUT"
cp --reflink=auto "$FW" "$OUT/orig.bin"
sha256sum "$OUT/orig.bin" | tee "$OUT/orig.sha256"
file "$OUT/orig.bin"; stat -c '%s bytes' "$OUT/orig.bin"
binwalk "$OUT/orig.bin" | head -60
python Tool/scripts/fw-triage.py --file "$OUT/orig.bin" --json \
  | tee "$OUT/triage.json"
```

| 容器/文件系统 | 魔术 | 首选提取 | 完成判据 |
|---|---|---|---|
| SquashFS | `hsqs` / `sqsh` | `unsquashfs` / `sasquatch` | `/etc`、`/bin/busybox`、`/lib` 齐全 |
| UBI/UBIFS | `UBI#` | `ubireader_*` | 卷列表 + 卷内根目录 |
| JFFS2 | `85 19`（LE） | `jefferson` / `jffs2dump` | 节点可解析、目录树完整 |
| CramFS | `45 3d cd 28` | `cramfsck -x` / `7z` | 能读出 init 与 `/bin` |
| cpio/initramfs | `070701` | `cpio -idmv` | 有 init 脚本与 `/bin` |
| gzip/zstd/xz | `1f8b` / `28 b5 2f fd` | `gzip -dc` / `zstd -d` / `xz -dc` | 解压后出现下一层签名 |

**成功判据**：`file` 与 `binwalk` 对切片判断一致，切片首部魔术完整、尾部长度合理。
**失败判据**：只看到内核/DTB、没有根目录；把“解压出一个文件”当根文件系统。
## 1. binwalk 与手工切分

```bash
binwalk -e --run-as=root -C "$OUT" "$OUT/orig.bin"
binwalk --dd='.*' -C "$OUT/raw" "$OUT/orig.bin"   # 只按签名切分
binwalk -E "$OUT/orig.bin" | head -40             # 熵
dd if="$OUT/orig.bin" of="$OUT/part.bin" bs=1 skip=<OFFSET> count=<LENGTH>
file "$OUT/part.bin"
```

- 递归层数 ≥2：容器 → 内核/rootfs → 可能的第二层 SquashFS。
- 整片高熵且无已知签名 → 转加密/厂商头判断，不要反复 `binwalk -e`。

**成功判据**：`_orig.bin.extracted/` 出现可遍历目录树或可挂载镜像。
**失败判据**：只有高熵 blob、无文件系统签名，却继续宣称已解包。
## 2. SquashFS / UBI / JFFS2

```bash
unsquashfs -s "$OUT/rootfs.squashfs"
unsquashfs -ll "$OUT/rootfs.squashfs" | head
unsquashfs -d "$OUT/rootfs" -f "$OUT/rootfs.squashfs"
sasquatch -d "$OUT/rootfs-sas" "$OUT/rootfs.squashfs"   # 非标压缩

ubireader_display_info "$OUT/orig.bin" | head -100
ubireader_extract_images -o "$OUT/ubi" "$OUT/orig.bin"
ubireader_extract_files -o "$OUT/ubi-root" "$OUT/ubi/"*.ubi

jefferson -d "$OUT/jffs2" "$OUT/rootfs.jffs2"
cramfsck -x "$OUT/cramfs" "$OUT/rootfs.cramfs"
```

- SquashFS 先看 `-s` 的压缩算法/块大小；`unsupported compression` 时换 `sasquatch`，
  或从内核确认解压器，不要反复对同一镜像跑 `unsquashfs`。
- UBI 先确认 `UBI#` 偏移、PEB 大小、VID/EC 头；NAND dump 必须保留 OOB。
  卷名常见 `kernel`、`rootfs`、`rootfs_data`，配置/密码常在 `rootfs_data` 覆盖层。
- JFFS2 大量坏节点先查端序、OOB、是否从分区中间开始，不要先判镜像损坏。

**成功判据**：根目录可遍历，`bin/busybox` 架构与 SoC 一致，`etc` 中至少一个启动配置。
**失败判据**：只有空 `squashfs-root`、缺 `etc`；UBI 只能列出 EC 头、卷内全空。
## 3. 账号与凭据（只做可验证审计）

```bash
ROOT="$OUT/rootfs"
cat "$ROOT/etc/passwd"; cat "$ROOT/etc/shadow" 2>/dev/null
awk -F: '($3==0){print "UID0:",$1}' "$ROOT/etc/passwd"
awk -F: '($2=="" || $2=="!"){print "empty/locked:",$1}' "$ROOT/etc/shadow" 2>/dev/null
awk -F: '($7!~/(nologin|false)$/){print "shell:",$1,$7}' "$ROOT/etc/passwd"
grep -RInE '^[^:]+:\$[0-9a-z]+\$' "$ROOT/etc" 2>/dev/null
find "$ROOT" -type f \( -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' \
  -o -name 'authorized_keys' \) -print
```

- `passwd` 第二字段 `x` 表示看 shadow；空口令、UID 0 的非 root 账号是高价值线索。
- shadow 前缀：`$1$` MD5、`$5$` SHA-256、`$6$` SHA-512、`$y$` yescrypt、`$2*$` bcrypt；
  `!`/`*` 为锁定。只有“可登录弱口令/空口令 + 可复现登录”才算证据，单个 hash 只是素材。
- 私钥：`openssl x509 -in cert.pem -noout -subject -issuer -fingerprint -sha256`；
  用 `openssl x509 -noout -modulus` 与 `openssl rsa -noout -modulus` 比对是否配对。

**成功判据**：账号/密钥有 `文件:行号`、用途、是否配对，并在仿真/真机做过一次登录或认证验证。
**失败判据**：只有 hash 没有可用登录入口；把公钥/证书当私钥；只凭文件名猜用途。
## 4. 启动链与服务

```bash
sed -n '1,160p' "$ROOT/etc/inittab" 2>/dev/null
find "$ROOT/etc" -maxdepth 3 -type f \( -name 'rcS' -o -name 'rc.local' \
  -o -path '*/init.d/*' -o -name '*.service' \) -print | head -60
grep -RInE 'telnetd|dropbear|httpd|uhttpd|lighttpd|goahead|procd|nvram' \
  "$ROOT/etc" "$ROOT/usr/etc" 2>/dev/null | head -100
grep -RInE 'system\(|popen\(' "$ROOT/www" "$ROOT/usr" 2>/dev/null | head -60
```

- 关注 `inittab` 的 `::respawn:`/`::askfirst:`、`init.d/S*` 顺序、是否 root 运行。
- `nvram`/`mtd` 取值进入 `system()`/`popen()` 是命令注入高价值点；CGI 看 `/www/cgi-bin`。

**成功判据**：画出“开机脚本 → 服务进程 → 运行用户 → 监听端口 → 可控参数”链路，
且每个节点有 `文件:行号`。
**失败判据**：只列脚本名，没说明谁启动、以什么用户、是否可达。
## 5. 停止条件与证据

1. 解包报错但目录“看起来有东西”，没有 `etc`/`bin`/`lib` 完整链路。
2. 只拿到内核/DTB/单文件，没有根文件系统。
3. shadow 有 hash 但无可用登录入口，且没有授权破解。
4. 私钥/证书无法配对，或只有公钥。
5. 任何一步需要写原始闪存/OTA 分区但未做只读备份。

**误报/边界**：高熵不等于加密（SquashFS/UBI 本身也高熵）；固件里的示例/测试密钥
不等于有效凭据，必须在授权环境验证一次。
