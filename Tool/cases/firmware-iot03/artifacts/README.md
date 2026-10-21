# 产物说明（firmware-iot03 / real）

- `triage.json`：`python Tool/scripts/fw-triage.py --file Tool/cases/firmware-iot03/input/43341b0rtecdc.bin --json`，rc=0。
- `repro.json`：`python Tool/skill/firmware-iot/scripts/fw-repro.py --file Tool/cases/firmware-iot03/input/43341b0rtecdc.bin --out-dir work/fw-case03 --json`，rc=0。

关键结论：`primary=brcm`，BRCM 标签偏移 252828/252980/253132/254156，尾部
`Version 6.10.225.19`、`FWID 01-97a5222f`；无 rootfs，J1/J2/J3 未达成。
`bzip2`/`jffs2` 命中是误报，已在 `repro.json` 的 `formats` 中保留供复核。
