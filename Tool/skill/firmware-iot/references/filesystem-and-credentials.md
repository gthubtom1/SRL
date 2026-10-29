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

## 5. 账号与认证路径（不读取实际凭据）

仅选取用户名/UID/登录 shell 等安全字段，核对启动服务和认证代码/配置数据流；不打开 shadow、私钥、NVRAM 口令或真实密钥字段，不先读取再散列打码。

```bash
ROOT="$OUT/rootfs"
awk -F: '($3==0){print "UID0:",$1}' "$ROOT/etc/passwd"
awk -F: '($7!~/(nologin|false)$/){print "shell:",$1,$7}' "$ROOT/etc/passwd"
```

默认账户/文件存在只证明元数据线索，不能证明空口令、弱口令或已登录。需要行为验证时用自有测试设备合成账号/canary；缺设备或安全输入则保留可达性/可用性未知，不靠提取真实 hash 补证。

## 6. 证书与设备身份（公钥元信息）

可按文件名列出候选位置，但文件名不证明含私钥或可用；不读取真实私钥/p12、派生其公钥、配对或试用生产凭据。仅对已确认为公开证书的文件读取 subject/issuer/有效期/公钥指纹：

```bash
openssl x509 -in cert.pem -noout -subject -issuer -dates -fingerprint -sha256
```

设备身份、OTA、TLS/SSH、云接入的用途由配置引用/调用链/公开证书信任链判断。行为验证用自有隔离测试设备和临时合成密钥；缺安全验证只能写候选位置/用途推导，不能宣称设备可被冒充或固件可被伪造。

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

## 8. 结论分级与失败条件

| 级别 | 证据 | 允许结论 |
|---|---|---|
| 实测 | 自有测试设备/仿真中合成账户或 canary 的可复现结果 | 仅该测试环境的可达/拒绝与行为 |
| 配置/代码确认 | 文件位置、安全字段与消费者数据流可复查 | 认证路径/权限配置或敏感数据可能到达的 sink |
| 候选 | 文件名、变量名、未展开分支或编码块 | 未验证，列具体缺口 |
| 排除 | 公钥/证书/示例/帮助文本及未引用配置有依据 | 该候选不是已确认秘密或影响链 |

解包失败、缺分区/覆盖层、服务无监听或缺设备分别限定受影响结论；不能将局部未知升级成完整认证审计通过。原始镜像/闪存只读保留，运行仿真按已有目标运行许可与隔离要求；硬件写入前必须备份。

## 9. NVRAM / overlay / rootfs_data

主 rootfs、UBI rootfs_data、OpenWrt /etc/config、出厂 defaults、旧副本与 provisioning 可能有不同配置来源。先列目录/候选路径，核服务如何取值；不要读取真实口令/hash、私钥或云会话。未拿到覆盖层时明确未覆盖，不能宣称“没有额外账号”。

## 10. 验收

- 文件系统来源、分区、解包命令与结构检查可追溯；结构任务可以按已约定范围完成，解包不等于服务或漏洞已验证。
- 服务链包含开机入口、进程、用户、监听与可控输入，节点有位置证据；仅脚本名不足以证明运行时可达。
- 认证/身份风险区分配置事实、推导、候选与实测；不先读取秘密再散列脱敏，不将公开证书当私钥。
- 真正需要认证行为时用合成测试输入并留负对照；没有安全材料就保留未知和恢复条件。
- 原件未变，结果回到主域同一项目/版本/run。硬件接入见 `hardware-interfaces.md`，仿真见 `emulation-and-fuzz.md`，方法仍受当前目标与材料边界约束。
