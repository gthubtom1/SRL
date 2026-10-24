# 产物说明（firmware-iot04 / real）

- `triage.json`：`python Tool/skill/firmware-iot/scripts/fw-triage.py --file Tool/cases/firmware-iot04/input/SecConfig.efi --json`，rc=0。
- `repro.json`：`python Tool/skill/firmware-iot/scripts/fw-repro.py --file Tool/cases/firmware-iot04/input/SecConfig.efi --out-dir work/fw-case04 --json`，rc=0。

关键结论：`primary=pe`，PE32+ x86-64，9 节，`.text` 熵 6.491；
`subsystem=16`（Windows boot application, UEFI-era），`extraction=not-applicable`。
仅组件级 E0/E1；未读取 FV/Secure Boot 变量，J1/J2/J3 未达成。
