# 03 OTA 与签名校验

> 目标：判断一个 OTA/升级包**能不能拿到内层镜像、有没有签名/回滚保护、改完能不能被设备接受**。
> 配套：`references/firmware-unpack.md`、`references/06-container-carving-and-entropy.md`、
> `references/02-failure-criteria.md`。只对授权设备/固件操作，默认只读。

## 0. 入口信号

- 官网支持页/App 里出现 `update.bin`、`.pkg`、`.chk`、`.trx`、`.img`、`.cab`、`.zip`。
- 设备 OTA 请求（抓包）返回 `Content-Type: application/octet-stream`，带版本号/机型字段。
- 固件内更新器出现 `verify`、`signature`、`rsa`、`sha256`、`anti-rollback`、`svn` 字样。

## 1. 获取与固定证据

```bash
URL='https://vendor.example/fw/update.bin'   # 授权来源
curl -fL --retry 2 -o work/update.bin "$URL"
sha256sum work/update.bin | tee work/update.sha256
stat -c '%s bytes' work/update.bin
file work/update.bin
```

判据：两次获取哈希一致；落盘大小与 `Content-Length` 一致（压缩传输需解压后再比）；
来源 URL、时间、机型/版本写进案例。

## 2. 剥外层：exe/cab/zip/tar

```bash
7z l work/update.bin | head -40
7z x work/update.bin -owork/update
find work/update -maxdepth 2 -type f -printf '%s %p\n' | sort -nr | head -20
```

常见结构：自解压 exe → cab/zip → 厂商头 → kernel/rootfs/EC/ME。
判据：能列出内层文件名与大小；最大的 1–3 个文件通常是 kernel/rootfs/固件卷。
失败判据：只解出 readme/工具，没有镜像 → 换厂商专用解包器或从设备 OTA 抓包取原始包。

## 3. 厂商头与内层镜像

```bash
xxd -l 256 work/update/*.bin
binwalk work/update/*.bin | head -40
python Tool/scripts/fw-triage.py --file work/update/*.bin --json > work/triage.json
```

看五元组：`magic + version + length + crc + model`。
判据：长度字段与文件大小/段边界自洽；切出的镜像有 strong 魔术（SquashFS/UBI/TRX/uImage）。
失败判据：头字段对不上 → 可能还有一层压缩/加密，不要直接 `unsquashfs`。

## 4. 签名与回滚保护

检查包内与更新器：

```bash
find work/update -type f \( -name '*.sig' -o -name '*.p7b' -o -name '*.cat' -o -name '*.sha256' \) -print
grep -RInE 'verify|signature|rsa|sha256|anti.?rollback|svn|downgrade' work/rootfs 2>/dev/null | head -60
```

- 签名文件存在 ≠ 校验生效：要找到调用点（更新器二进制/脚本）与失败分支。
- 版本比较：记录当前版本、包版本、允许降级的最小版本（SVN/anti-rollback）。
- 只改 rootfs 不改签名，通常会被拒；没有私钥不要声称“可持久化”。

判据：能指出“校验函数/命令 + 失败行为 + 版本阈值”，并有 `文件:行号` 或反汇编地址。
失败判据：只有签名文件、找不到校验逻辑；或校验逻辑在 TEE/安全核内不可见 → 记为未验证。

## 5. 失败判据（本页）

| 现象 | 判定 | 改走哪条 |
|---|---|---|
| 两次下载哈希不同 | 传输/分块/缓存问题 | 换镜像源/加 `--compressed`，重下再比 |
| 7z 只解出工具/说明 | 不是完整 OTA 包 | 从设备 OTA 抓包取原始响应；找厂商专用格式 |
| 内层 `binwalk` 只有高熵无魔术 | 加密/自定义容器 | 找更新器解密点；转 UART/JTAG 在线读 |
| 有 `.sig` 但找不到校验调用 | 证据不足 | 反汇编更新器/查启动脚本；不要写“签名可绕过” |
| 改 rootfs 后升级被拒 | 签名/回滚保护生效 | 不伪造签名；转在线调试或授权密钥流程 |

## 6. 边界

- 仅下载授权来源的固件；不抓他人设备 OTA、不伪造厂商签名。
- 包内可能含第三方代码/密钥，报告只留路径、指纹、用途，不复制明文。
- OTA 分析通常只能到 E1；J1/J2 仍需解包后的服务或真机验证。
