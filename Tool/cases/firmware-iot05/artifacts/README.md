# 产物说明（firmware-iot05 / fixture）

- `triage.json`：`python Tool/scripts/fw-triage.py --file Tool/cases/firmware-iot05/input/ota-fixture.zip --json`，rc=0。
- `repro.json`：`python Tool/skill/firmware-iot/scripts/fw-repro.py --file Tool/cases/firmware-iot05/input/ota-fixture.zip --out-dir work/fw-case05 --json`，rc=0。

关键结论：ZIP 解出 8 个文件；rootfs 扫描命中 root 空口令、shadow hash、telnetd、
uhttpd、`system("tar -xzf $QUERY_STRING ...")` 与占位私钥（已脱敏）。
以上均为夹具静态证据，J1/J2 未达成，禁止当作真实设备漏洞。
