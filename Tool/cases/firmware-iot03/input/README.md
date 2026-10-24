# 输入来源（real）

- 文件：`43341b0rtecdc.bin`
- 本机来源：`C:/Windows/System32/DriverStore/FileRepository/bcmdhd64.inf_amd64_e0bae6831f60ea5f/43341b0rtecdc.bin`
- 类型：Broadcom BCM43341 Wi-Fi 固件（vendor blob，无 rootfs）
- SHA256：`3dc1138c4795caeada1f66937516a7411c0b24f50c51336f208fad7963455a3f`
- 大小：406260 字节
- 复制命令：`cp <source> Tool/cases/firmware-iot03/input/43341b0rtecdc.bin`
- 授权：本机已安装驱动包中的固件文件，只读分析；不写设备、不联网。

复现产物：

```bash
python Tool/skill/firmware-iot/scripts/fw-triage.py --file Tool/cases/firmware-iot03/input/43341b0rtecdc.bin --json > artifacts/triage.json
python Tool/skill/firmware-iot/scripts/fw-repro.py --file Tool/cases/firmware-iot03/input/43341b0rtecdc.bin --out-dir work/fw-case03 --json > artifacts/repro.json
```
