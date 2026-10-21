# 凭据与启动链审计（credentials-and-boot-chain）

> 目标：从 rootfs 里把“账号 -> 密钥 -> 启动服务 -> 外部入口”连成一条可验证的链。
> 配套：`references/filesystem-and-credentials.md`、`Tool/skill/firmware-iot/SKILL.md`。

## 1. 账号：先看可用性，再看 hash

```bash
ROOT=rootfs
cat "$ROOT/etc/passwd"
cat "$ROOT/etc/shadow" 2>/dev/null
awk -F: '($3==0){print "UID0:",$1}' "$ROOT/etc/passwd"
awk -F: '($2=="" || $2=="!"){print "empty/locked:",$1}' "$ROOT/etc/shadow" 2>/dev/null
awk -F: '($7!~/(nologin|false)$/){print "shell:",$1,$7}' "$ROOT/etc/passwd"
```

| 观察 | 含义 | 下一步 |
|---|---|---|
| `passwd` 第二字段为空 | 无口令 | 在仿真/真机验证登录；高价值 |
| `passwd` 第二字段 `x` | 看 shadow | 继续查 shadow，不要直接判空口令 |
| shadow 为空/`!`/`*` | 账号不可用/锁定 | 不能当可用凭据 |
| UID 0 的非 root | 后门/提权线索 | 查启动脚本与 sudoers |
| shell 为 `/bin/sh` | 可交互 | 找登录入口（telnet/ssh/UART） |

hash 算法：`$1$` MD5、`$5$` SHA-256、`$6$` SHA-512、`$y$` yescrypt、`$2*$` bcrypt。
破解只在授权下做；仅拿到 hash 不能写成“登录成功”。

## 2. 密钥/证书：用途比文件名重要

```bash
find "$ROOT" -type f \( -name '*.pem' -o -name '*.key' -o -name '*.crt' \
  -o -name '*.p12' -o -name '*.pfx' -o -name 'id_rsa*' -o -name 'authorized_keys' \) -print
grep -RInE -- 'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY|BEGIN CERTIFICATE' "$ROOT" 2>/dev/null
```

```bash
openssl x509 -in cert.pem -noout -subject -issuer -dates -fingerprint -sha256
openssl pkey -in key.pem -pubout -outform PEM 2>/dev/null | head
# RSA 配对检查
openssl x509 -in cert.pem -noout -modulus | openssl sha256
openssl rsa -in key.pem -noout -modulus 2>/dev/null | openssl sha256
```

分类：

- 设备身份：与 `client-cert`/MQTT/云连接配对 -> 可冒充设备。
- OTA 签名：与升级包/公钥配对 -> 可伪造固件；先确认设备上是否只有公钥。
- TLS 服务端：与 `httpd`/`uhttpd` 配对 -> 可解密/冒充本地服务。
- SSH：`authorized_keys`/dropbear -> 优先验证免密登录。
- 云 AK/SK：`AKIA`/`ASIA` -> 转云身份验证，先 `sts get-caller-identity`。

报告只留路径、指纹、用途、是否配对；不复制私钥内容。

## 3. 启动链：从 inittab 到端口

```bash
sed -n '1,160p' "$ROOT/etc/inittab" 2>/dev/null
find "$ROOT/etc" -maxdepth 3 -type f \( -name 'rcS' -o -name 'rc.local' \
  -o -path '*/init.d/*' -o -name '*.service' \) -print
grep -RInE 'telnetd|dropbear|httpd|uhttpd|lighttpd|goahead|procd|start-stop-daemon|nvram' \
  "$ROOT/etc" "$ROOT/usr/etc" 2>/dev/null | head -100
```

要回答四个问题：

1. 谁启动服务（inittab/rcS/init.d/procd/systemd）？
2. 以什么用户运行（root？`User=`？`start-stop-daemon -c`？）？
3. 监听哪个地址/端口（`0.0.0.0` 还是 `127.0.0.1`）？
4. 外部参数是否进入 `system()`/`popen()`/`execve()`？

完成判据：一张最小链路图，每个节点有 `文件:行号`。
失败判据：只列脚本名，没有启动者/用户/端口；或服务在仿真/真机均不监听且无日志解释。

## 4. 常见组合

- 空 root 口令 + telnetd 自启 -> 直接 shell。
- `authorized_keys` + dropbear 自启 -> 免密登录。
- 私钥 + 云 MQTT/HTTPS -> 设备冒充或云端横向。
- Web CGI 以 root 跑 + `nvram` 值进 `system()` -> 命令注入。
- OTA 私钥在 rootfs + 升级不校验签名 -> 持久化风险（需单独授权验证）。

## 5. 证据分级

| 级别 | 例子 | 处理 |
|---|---|---|
| A 可直接验证 | 空口令、明文 password、可用私钥、AK/SK | 隔离环境验证一次，记录返回 |
| B 需组合 | shadow hash + 可登录服务 | 先确认入口，再决定是否破解 |
| C 仅线索 | 字符串 secret/token、注释密码 | 定位文件:行号，标“未验证” |
| D 误报 | 公钥、证书、示例占位 | 排除并写原因 |

## 6. 停止条件

- 只有 hash 未破解且无登录入口；
- 私钥/证书无法配对；
- 启动脚本指向的服务在仿真/真机均不可达；
- 下一步需要写原始闪存/OTA 分区但未备份/未授权。

## 7. 边界

仅对授权固件/设备操作；凭据脱敏；不做未授权破解、持久化、OTA 伪造。
