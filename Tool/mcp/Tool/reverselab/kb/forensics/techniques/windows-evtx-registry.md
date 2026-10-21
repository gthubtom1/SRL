# Windows EVTX 与注册表 hive：时间线的最小闭环

> **入口信号**：`*.evtx`、`NTUSER.DAT`/`*.hiv`，需要回答“某键何时被写、某事件何时发生”。
> **不适用**：没有权限/副本的 SAM/SYSTEM；把日志时间当本地时间直接排序。

## 1. EVTX 最小命令

```bash
cp "$WINDIR/System32/winevt/Logs/Application.evtx" input/Application.evtx
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file input/Application.evtx --json
python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input input/Application.evtx --out out/evtx.json
```

EVTX 记录：`**\0\0` + size + RecordId(u64) + FILETIME(u64) + Binary XML。`fs-timeline.py` 取 RecordId/FILETIME；语义（EventId/Provider）用 `wevtutil`/PowerShell 补。

## 2. 注册表最小命令

```bash
cmd //c "reg save HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer input/Explorer.hiv /y"
python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input input/Explorer.hiv --out out/registry.json
```

REGF：header last-write 0x0C、root cell 0x24、hive bins size 0x28；hbin 大小 +0x08；cell 有符号 int32；`nk` last-write 在 cell+8；名字压缩标志 0x20。

## 3. 确认判据

- EVTX 记录数/首末时间可复算；RecordId 连续或空洞有解释。
- 注册表键路径可由父指针重建；last-write 是 UTC 且与 hive 头时间不矛盾。
- 持久化项落到键+值+写入时间；不写“某键存在”就结束。
- 与文件系统/browser/内存时间线能按 UTC 对齐。
- 脏页：带 `LOG1/LOG2` 时说明是否合并；不带就标“可能落后”。

## 4. 失败判据

- EVTX 记录 0/时间跳变：日志清除/滚动，不写“没有发生”。
- hive 键级遍历 0：权限/空文件/加密；用 `reg save` 导可读子树。
- 键路径断链/父指针循环：标“路径不可重建”，只用键名。
- 时间纪元混用（1601/1970）：按字段类型重算并抽样对照。
- 反作弊/内核保护：停在线动态，转只读副本。

## 5. 边界

- 不 `reg load` 原 hive；用 `reg save` 副本。
- 不把 `RecordId` 当全局唯一事件 ID（跨通道会重复）。
- 报告写通道/Provider/EventId/RecordId/FILETIME 六件套。
- 相关：`Tool/skill/forensics-mobile/references/04-walkthrough-windows-evtx-registry.md`、`disk-and-filesystem.md`。

## 6. 输出模板

```json
{"time_utc":"2026-10-20T03:22:23.292580Z","actor":"Microsoft-Windows-AppReadiness",
 "action":"emit event record","object":"Application.evtx#record=59",
 "confidence":"observed","evidence_refs":["input/Application.evtx"],
 "command":"python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input input/Application.evtx"}
```

## 7. 关联检查

- EVTX 时间与文件系统 mtime/注册表 last-write 对齐；差整数小时先查时区。
- 注册表键路径与 `reg query` 的键名一致；值名/类型单独记录。
- hive 头时间晚于键时间属正常（头会更新）；反过来要查脏页/副本。
- 日志清除/滚动会留下 RecordId 空洞；不要用“没有记录”证明“没有发生”。
- 相关：`01-criteria.md`、`evidence-chain.md`、`Tool/cases/forensics03/`。
