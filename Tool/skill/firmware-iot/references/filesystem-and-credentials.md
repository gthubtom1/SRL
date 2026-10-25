# 文件系统与凭据（filesystem-and-credentials）

> 配套 `firmware-iot/SKILL.md` 与 `references/firmware-unpack.md`。所有命令在**副本**上执行，原始镜像只读。
> 目标不是“解包成功”，而是拿到可审计的 rootfs，并把账号、密钥、启动链定位到 `文件:行号`。

## 0. 输入、输出与证据

```bash
FW=firmware.bin
OUT=work/fw-audit
mkdir -p "$OUT"
cp --reflink=auto "$FW" "$OUT/orig.bin"
sha256sum "$OUT/orig.bin" | tee "$OUT/orig.sha256"
file "$OUT/orig.bin"; stat -c '%s bytes' "$OUT/orig.bin"
```

最低交付：

- `orig.bin` + SHA256 + 获取来源/命令；
- 解包目录树 + 每层容器偏移 + 工具版本；
- 账号/密钥/启动脚本清单（脱敏值 + 文件:行号）；
- 一条“开机 → 服务 → 运行用户 → 外部入口”的最小链路。

## 1. 容器判定与偏移

| 容器/文件系统 | 典型魔术 | 首偏移 | 首选提取 | 完成判据 |
|---|---|---|---|---|
| SquashFS LE/BE | `hsqs` / `sqsh` | 0 或厂商头后 | `unsquashfs` / `sasquatch` | `/etc`、`/bin/busybox`、`/lib` 齐全 |
| UBI/UBIFS | `UBI#` | 0 / 0x800 | `ubireader_*` | 卷列表 + 卷内根目录 |
| JFFS2 | `0x1985`（LE `85 19`） | 0 或分区内 | `jefferson` / `jffs2dump` | 节点可解析、目录树完整 |
| CramFS | `45 3d cd 28` | 0 | `cramfsck -x` / `7z` | 能读出 init 与 `/bin` |
| tar | `ustar` at +257 | 任意 | `tar -xvf` / `7z` | 条目名与长度一致 |
| gzip/zstd/xz | `1f8b` / `28 b5 2f fd` / `fd 37 7a 58 5a 00` | 0/嵌入 | `gzip -dc` / `zstd -d` / `xz -dc` | 解压后出现下一层签名 |

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
# 识别并保留所有候选偏移
binwalk "$OUT/orig.bin" | head -60
# 只切分，不执行
binwalk --dd='.*' -C "$OUT/raw" "$OUT/orig.bin"

# 已知偏移时手工切
dd if="$OUT/orig.bin" of="$OUT/part.bin" bs=1 skip=<OFFSET> count=<LENGTH>
file "$OUT/part.bin"
```

判据：`file` 与 `binwalk` 对切片的判断一致；切片首部有完整魔术，尾部长度合理。
失败判据：只看到内核/DTB、没有根目录；或 `unsquashfs` 报 `unsupported compression` 却继续宣称“已解包”。

## 2. SquashFS：先看超级块，再解

```bash
unsquashfs -s "$OUT/rootfs.squashfs"          # 版本、压缩算法、块大小
unsquashfs -ll "$OUT/rootfs.squashfs" | head  # 条目清单（不落盘）
unsquashfs -d "$OUT/rootfs" -f "$OUT/rootfs.squashfs"
```

- `-s` 里 `Compression lzma/xz/lzo/lz4/zstd` 决定换哪个解压器；厂商常用非标块大小或改过的 LZMA。
- `unsquashfs` 失败先换 `sasquatch`，再考虑 `binwalk -e` 或从内核源码确认解压器；不要反复 `unsquashfs` 同一镜像。
- 嵌入在厂商头后的 SquashFS：先按偏移 `dd` 切出，再 `unsquashfs -s` 复判；直接对整包执行会报 `invalid magic`。
- 解出后检查 `etc/init.d/rcS`、`etc/inittab`、`bin/busybox`、`lib/ld-*`、`www/cgi-bin`。

完成判据：根目录可遍历，`bin/busybox` 的架构与 SoC 一致，`etc` 中存在至少一个启动配置。
失败判据：只有 `squashfs-root` 空壳、缺 `etc`；或 `unsquashfs` 只列出 `lost+found`。

## 3. UBI/UBIFS：卷、LEB 与 OOB

```bash
ubireader_display_info "$OUT/orig.bin" | head -100
ubireader_extract_images -o "$OUT/ubi" "$OUT/orig.bin"
ubireader_extract_files -o "$OUT/ubi-root" "$OUT/ubi/"*.ubi
```

- 先确认 `UBI#` 偏移、PEB 大小、VID/EC 头是否完整；NAND dump 必须带 OOB（`nanddump -o`）或至少保留原始布局。
- 卷名常见 `kernel`、`rootfs`、`rootfs_data`；`rootfs_data` 是覆盖层，配置/密码常在这里，别只看 `rootfs`。
- 报 `bad magic` 时依次查：偏移是否跳过厂商头、是否缺 OOB、PEB/LEB 参数是否与 `mtdparts` 一致；不要先判定“加密”。
- 只拿到 `.ubi` 而没有卷内文件时，用 `ubireader_extract_files` 指定卷；仍失败则保留原始 dump，转真机/内核挂载。

完成判据：卷列表 + 至少一个卷内出现 `etc`/`bin`。
失败判据：只能列出 EC 头、卷内全是空目录；或把 OOB 当数据切分导致节点错位。

## 4. JFFS2 / CramFS / 压缩流

```bash
# JFFS2
jefferson -d "$OUT/jffs2" "$OUT/rootfs.jffs2"
jffs2dump -c -e "$OUT/jffs2.endian" "$OUT/rootfs.jffs2"  # 端序/节点统计
# CramFS
cramfsck -x "$OUT/cramfs" "$OUT/rootfs.cramfs"
7z x "$OUT/rootfs.cramfs" -o"$OUT/cramfs-7z"
# gzip / zstd / xz
gzip -dc "$OUT/blob.gz" > "$OUT/blob.out"
zstd -d "$OUT/blob.zst" -o "$OUT/blob.out"
xz -dc "$OUT/blob.xz" > "$OUT/blob.out"
```

- JFFS2 大量坏节点 ≠ 镜像损坏：先查端序、OOB、是否从分区中间开始；`jefferson` 的日志要保留。
- CramFS 是只读、块压缩；`cramfsck -x` 与 `7z` 结果不一致时，以能列出完整目录且 `file` 可识别 ELF 的为准。
- 压缩流解出后必须再次 `file`/`binwalk`，不要把“解压出一个文件”当成根文件系统。

## 5. `/etc/passwd`、`/etc/shadow`：只做可验证的账号审计

```bash
ROOT="$OUT/rootfs"
cat "$ROOT/etc/passwd"
cat "$ROOT/etc/shadow" 2>/dev/null
awk -F: '($3==0){print "UID0:",$1}' "$ROOT/etc/passwd"
awk -F: '($2=="" || $2=="!"){print "empty/locked:",$1}' "$ROOT/etc/shadow" 2>/dev/null
awk -F: '($7!~/(nologin|false)$/){print "shell:",$1,$7}' "$ROOT/etc/passwd"
grep -RInE '^[^:]+:\$[0-9a-z]+\$' "$ROOT/etc" 2>/dev/null
```

字段与判据：

- `passwd` 第二字段为 `x` 表示看 shadow；为空表示无口令（高危）；UID 0 的非 root 账号是后门/提权线索。
- `shadow` 第二字段：`$1$` MD5、`$5$` SHA-256、`$6$` SHA-512、`$y$` yescrypt、`$2*$` bcrypt；`!`/`*` 为锁定。
- 只有“可登录的弱口令/空口令 + 可复现登录”才算 J1 证据；仅有一个 hash 是素材，不是登录证据。
- 破解只在明确授权下做，并记录算法/字典/耗时；不要默认跑大字典。
- 同时查 `etc/sudoers`、`etc/sudoers.d/*`、`authorized_keys`、`.ssh/`、`etc/dropbear/`、`etc/passwd-`。

失败判据：shadow 为空但 passwd 仍写 `x`（账号不可用）；或 hash 破解出明文却无法在仿真/真机登录（可能 PAM/服务限制）。

## 6. 私钥、证书与设备身份

```bash
find "$ROOT" -type f \( -name '*.pem' -o -name '*.key' -o -name '*.crt' \
  -o -name '*.p12' -o -name '*.pfx' -o -name 'id_rsa*' -o -name 'authorized_keys' \) -print
grep -RInE -- 'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY|BEGIN CERTIFICATE' "$ROOT" 2>/dev/null | head -40
```

逐项确认用途：

```bash
openssl x509 -in cert.pem -noout -subject -issuer -dates -fingerprint -sha256
openssl pkey -in key.pem -pubout -outform PEM 2>/dev/null | head
# RSA 证书/私钥是否配对（EC 用 pkey -pubout 比对）
openssl x509 -in cert.pem -noout -modulus | openssl sha256
openssl rsa -in key.pem -noout -modulus 2>/dev/null | openssl sha256
```

分类判据：

| 类型 | 识别 | 影响 |
|---|---|---|
| 设备身份私钥 | 与设备证书/`client-cert` 配对 | 可冒充设备接入云/MQTT/管理端 |
| OTA 签名私钥 | 与升级包签名/公钥配对 | 可伪造固件；必须确认是否仅公钥在设备 |
| TLS 服务端私钥 | 与 `httpd`/`uhttpd` 证书配对 | 可解密/冒充本地服务 |
| SSH 主机/用户密钥 | `authorized_keys`、`dropbear` | 可免密登录，优先验证 |
| 云 AK/SK | `AKIA`/`ASIA`、`aws_secret_access_key` | 转 cloud 边界，先 `sts get-caller-identity` |

失败判据：只凭文件名猜测用途；把公钥/证书当私钥；或把测试/占位密钥当有效凭据。
私钥内容不写入报告、不回传；只留路径、指纹、用途和是否配对。

## 7. 启动脚本：把服务链画出来

```bash
sed -n '1,160p' "$ROOT/etc/inittab" 2>/dev/null
find "$ROOT/etc" -maxdepth 3 -type f \( -name 'rcS' -o -name 'rc.local' \
  -o -path '*/init.d/*' -o -name '*.service' \) -print | head -60
grep -RInE 'telnetd|dropbear|httpd|uhttpd|lighttpd|goahead|procd|start-stop-daemon|nvram' \
  "$ROOT/etc" "$ROOT/usr/etc" 2>/dev/null | head -100
```

重点：

- `inittab` 的 `::respawn:` / `::askfirst:` 行：哪个 getty、哪个 shell、是否 root。
- `init.d/S*` 的启动顺序、`start-stop-daemon` 参数、是否 `&` 后台、是否以 root 运行。
- `procd`/OpenWrt 的 `USE_PROCD=1`、`procd_open_instance`；`systemd` 的 `ExecStart=` 与 `User=`。
- `nvram`/`mtd` 取值是否进入 `system()`/`popen()`；这是命令注入的高价值点。
- Web/CGI：`/www/cgi-bin`、`/usr/lib/lua/luci`、升级接口、`PATH_INFO` 处理。

完成判据：画出“开机脚本 → 服务进程 → 运行用户 → 监听端口 → 可控参数”的链路，且每个节点有文件:行号。
失败判据：只列了脚本名，没有说明谁启动、以什么用户、是否可达。

## 8. 凭据线索分级

| 级别 | 例子 | 处理 |
|---|---|---|
| A（可直接验证） | 空口令、明文 `password=`、可用私钥、AK/SK | 在隔离环境验证一次，记录返回 |
| B（需组合） | shadow hash、`authorized_keys` + 可登录服务 | 先确认服务/账号可用，再决定是否破解 |
| C（仅线索） | 字符串里的 `secret`/`token`、注释掉的密码 | 定位到文件:行号，标注“未验证” |
| D（误报） | 公钥、证书、示例配置、占位符 | 排除并写明原因 |

不要把 C 当 A；不要把“发现私钥”直接写成“可入侵设备”。

## 9. 失败判据（出现任一条就停下换路线）

1. 解包报错但目录“看起来有东西”，没有 `etc`/`bin`/`lib` 完整链路。
2. 只拿到内核/DTB/单文件，没有根文件系统。
3. shadow 有 hash 但无可用登录入口，且没有授权破解。
4. 私钥/证书无法配对，或只有公钥。
5. 启动脚本指向的服务在仿真/真机均不监听，且没有日志解释。
6. 任何一步需要写入原始闪存/OTA 分区但未做只读备份。

## 10. 边界

- 仅对自有或明确授权的固件/设备操作；不接第三方设备、不扫公网、不写他人闪存。
- 不把凭据明文写进报告；证据只留指纹、路径、用途、验证命令。
- 账号破解、私钥滥用、OTA 伪造只在单独授权下进行；默认只做只读审计。
- 详细硬件接入见 `hardware-interfaces.md`，仿真与 fuzz 见 `emulation-and-fuzz.md`。

## 11. 硬编码凭据扫描判据：从 grep 到“可验证凭据”

> 目标：把“字符串里有个 password”降到“某个文件第 N 行有一个可用于登录的凭据”。
> 扫描只读副本；命中后先脱敏，再谈可用性。

### 11.1 扫描面（六类，缺一类就会漏）

| 面 | 命令/位置 | 典型命中 | 下一步 |
| --- | --- | --- | --- |
| 文本配置 | `grep -RInE` on `etc/` `www/` `usr/etc/` | `password=`、`admin:`、`token=` | 定位 `文件:行号` |
| 二进制常量 | `strings -a -n 4` + 上下文 | 拼接的 URL/账号/密钥 | 用 `rabin2 -zz` 或反汇编找引用 |
| 编码块 | base64/hex 长串 | `YWRtaW46…`、`0x…` | 解码后再判 |
| NVRAM/默认值 | `nvram.conf`、`defaults/`、`etc/config` | `http_username=admin` | 看服务是否读它 |
| 脚本拼接 | `system()`/`popen()` 附近 | `echo user:pass` | 追调用链 |
| 私钥/证书 | `*.pem/*.key/*.p12` | BEGIN PRIVATE KEY | `openssl` 配对 |

### 11.2 多编码解码（避免“grep 不到就写没有”）

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
ROOT=work/fw-audit/rootfs
# 1) 明文与常见键名
grep -RInE 'pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|admin' \
  "$ROOT/etc" "$ROOT/www" "$ROOT/usr/etc" 2>/dev/null | head -80

# 2) 长 base64/hex 串（只列候选，不自动解码全部）
grep -RInE '[A-Za-z0-9+/]{24,}={0,2}' "$ROOT/etc" 2>/dev/null | head -40

# 3) 二进制里的可打印串（先看长度与上下文）
find "$ROOT" -type f -perm -111 -size -8M 2>/dev/null | while read -r f; do
  strings -a -n 6 "$f" | grep -Ei 'password|passwd|secret|token|admin' >/dev/null && echo "$f"
done | head -20

# 4) 已知编码样本解码（把 <B64> 换成实际串；不要批量解码未知内容）
printf '%s' '<B64>' | base64 -d 2>/dev/null | head -c 200; echo
printf '%s' '<HEX>' | xxd -r -p 2>/dev/null | head -c 200; echo
```

### 11.3 判据阶梯：A/B/C/D 四级

| 级别 | 判据 | 允许写法 | 禁止写法 |
| --- | --- | --- | --- |
| A 可用 | 明文/空口令/可配对私钥，且完成一次登录或设备接受 | “在 <环境> 可用该凭据登录” | “所有设备都可用” |
| B 可验证 | shadow hash 可破解，或 token 能只读调用成功 | “hash 已破解/ token 可用（只读验证）” | “弱口令” |
| C 候选 | 只有 `文件:行号` + 字符串/编码块 | “发现候选凭据，未验证” | “硬编码口令” |
| D 误报 | 公钥、示例、占位符、帮助文本、已吊销 | “排除，原因 …” | 列入风险 |

### 11.4 四类高频误报（先排除再升级）

| 误报 | 识别方法 | 结论 |
| --- | --- | --- |
| `password=` 出现在 HTML 表单/帮助 | 看上下文标签/注释 | D：界面字段 |
| `-----BEGIN PUBLIC KEY-----` | `openssl pkey -pubin` 能读 | D：公钥 |
| `admin:admin` 在示例配置 | 文件名为 `.example`/`sample`，服务未引用 | D：示例 |
| base64 是图片/证书 | 解码后 magic 为 PNG/DER | D：非凭据 |

### 11.5 从命中到登录（J1）的最小链

1. 命中 → 定位文件与行，脱敏原值（保留前 2 后 2 或哈希前 12 位）。
2. 确认消费者：哪个服务/脚本读这个键（`grep -RIn` 键名）。
3. 确认算法：`shadow` 前缀、hash 格式、是否加盐。
4. 在副本/仿真里试一次登录；记录命令、响应、`id`。
5. 失败就降回 C，并写清失败原因（账号锁定/服务未起/算法不支持）。

## 12. NVRAM / overlay / `rootfs_data`：最容易漏的凭据层

| 位置 | 为什么重要 | 只读检查 |
| --- | --- | --- |
| UBI `rootfs_data` | 保存用户改过的配置/口令 | `ubireader_extract_files` 后 `find` |
| `/etc/config/*` | OpenWrt 实际运行配置 | `grep -RIn` 账号/密钥字段 |
| NVRAM 默认值 | 服务启动时读取 | `strings` 搜 `nvram_get` 键名 |
| `/etc/passwd-`/`shadow-` | 旧副本可能保留已删账号 | 与当前文件 diff |
| 云 provisioning | 设备首次联网写入 | `etc/` 下 `token`/`cert`/`mqtt` |

**判据**：主 rootfs 与覆盖层分别审计；两边账号/密钥集合的差集要能解释（出厂默认 vs 用户配置）。
**失败**：只审主 rootfs 就写“无额外账号” → 降级，补覆盖层。

## 13. 命令与“通过长什么样”（凭据审计复验）

```bash
ROOT=work/fw-audit/rootfs

# 1) 账号面：UID0/空/锁定分开
awk -F: '$3==0{print "uid0",$1}' "$ROOT/etc/passwd" 2>/dev/null
awk -F: '$2==""{print "empty-shadow",$1} $2 ~ /^[!*]/{print "locked",$1}' "$ROOT/etc/shadow" 2>/dev/null

# 2) 明文/编码候选（只列，不贴值）
grep -RInE 'pass(word|wd)?|secret|token|api[_-]?key' "$ROOT/etc" "$ROOT/www" 2>/dev/null | head -40

# 3) 私钥/证书与配对
find "$ROOT" -type f \( -name '*.pem' -o -name '*.key' -o -name '*.p12' \) -print
openssl x509 -in "$ROOT/etc/ssl/cert.pem" -noout -subject -fingerprint -sha256 2>/dev/null
openssl pkey -in "$ROOT/etc/ssl/key.pem" -pubout 2>/dev/null | head -3

# 4) 消费者：谁读这个键
grep -RIn 'http_username\|http_password' "$ROOT/etc" "$ROOT/usr" 2>/dev/null | head -20
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| 账号 | UID0 全有解释；空/锁定分开 | 把 `x` 当空口令 |
| 凭据 | 每条有 `文件:行号` + 消费者 | 只有字符串列表 |
| 密钥 | 私钥与证书能配对 | 把公钥当私钥 |
| 覆盖层 | `rootfs_data` 已审，差集有解释 | 只审主 rootfs |
| 结论 | A/B/C/D 分级明确 | 一律写“硬编码口令” |

## 这一篇算"用对了"吗

- [ ] 我的凭据命中都能指到 `文件:行号`，并且脱敏了原值
- [ ] 我区分了明文/编码/二进制/NVRAM 四类来源，没有只 grep 一次就下结论
- [ ] 我对每个候选都问了“谁在消费它”，没有把帮助文本当口令
- [ ] 我审了覆盖层/`rootfs_data`，能解释主 rootfs 与覆盖层的差集
- [ ] 私钥都做了配对与用途分类，没有把公钥/示例密钥当设备身份
- [ ] 没有登录证据的项我一律写成候选，没有写成“弱口令/可入侵”
