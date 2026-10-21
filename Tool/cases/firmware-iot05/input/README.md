# 输入来源（fixture）

- 文件：`ota-fixture.zip`
- 类型：手工构造的教学夹具，不是任何真实设备固件。
- 内容：`rootfs/etc/passwd`（root 空口令）、`rootfs/etc/shadow`、`rootfs/etc/init.d/rcS`（telnetd）、
  `rootfs/www/cgi-bin/upgrade`（`system("tar -xzf $QUERY_STRING ...")`）、
  `rootfs/etc/ssl/private/device.key`（占位私钥，非真实密钥）。
- 构造：Python `zipfile`，固定时间戳 `2026-01-01 00:00:00`，便于哈希复现。
- 用途：验证 `fw-repro` 的 ZIP 解包、rootfs 扫描、脱敏与 file:line 证据链。

复现产物：

```bash
python Tool/scripts/fw-triage.py --file Tool/cases/firmware-iot05/input/ota-fixture.zip --json > artifacts/triage.json
python Tool/skill/firmware-iot/scripts/fw-repro.py --file Tool/cases/firmware-iot05/input/ota-fixture.zip --out-dir work/fw-case05 --json > artifacts/repro.json
```

边界：夹具结论不得写成真实设备漏洞；J1/J2 未达成。
