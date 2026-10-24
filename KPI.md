# KPI —— 每次真实任务后手填一行（`docs/BLUEPRINT.md` §6）

> 规则：**填不出改善 → 不加任何东西**。`结果` 只能是 delivered / upper-bound / fail；
> `unknown` 一律记 fail。证据列写 MANIFEST 文件数 / facts 条数 / unknown 数。

| 日期 | 目标 | pack | 结果 | 证据 | 常驻 tok | 墙钟分 | ASK 次数 | 复现命令 |
| :-- | :-- | :-- | :-- | :-- | --: | --: | --: | :-- |
| 2026-10-24 | golden-crackme（crackerjack/a.exe，S5 witness 回放：重跑 13 条 claim 并声明 observed） | softseep | **delivered** | MANIFEST 5 文件 / facts 14 条 / unknown 1（F-013 已被实测推翻：rabin2 实为 5.9.8） | 12,669 | ~45 | 0 | `python Tool/scripts/gate.py --pack softseep` |

## 其余 8 个包为什么是 fail（不是"没做"，是"没有可背书的证据"）

| pack | 状态 | 卡在哪（可执行判据） |
| :-- | :-- | :-- |
| apkseep | fail | leaf-apk 6 条 claim，本轮可复验的是"无加固 / 载体身份 / smali 可编辑"等；F-104、F-105 依赖 `zipalign`、`aapt`（本机未安装）→ 无法复验 |
| malware-analysis | fail | leaf-pe-packed 19 条 claim 依赖 `upx`（本机未安装）+ 内存转储；无 upx 时只能复验静态部分，不足以整案通过 |
| pwn-crypto / firmware-iot / forensics-mobile / protocol-plugin / supply-chain-security / web-pentest | fail | 案例目录存在但 `facts.jsonl` 为空：从没在真实目标上跑过，没有 claim 可背书 |
