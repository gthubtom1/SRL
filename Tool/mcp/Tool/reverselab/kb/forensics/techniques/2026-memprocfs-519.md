# 2026 战例：MemProcFS v5.19 的 `/sys/eventlog` 内存事件日志取证

> 战例 KB-FOR-2026-07 · 收录 2026-10-20 · 单篇 ≤200 行 · 只写导出与校验判据，不复述内存初检。

## 来源与日期

- MemProcFS 发布说明：v5.19（26H2 线，2026-08）把 `/sys/eventlog/` 的 EVTX 重建做进默认挂载，
  支持从内存页重建 `Security/System/Application` 通道并保留 RecordId。
- 对应文档章节：`/sys/eventlog`（虚拟文件系统视图）、`/forensic/eventlog`（时间线/CSV）。
- 2026 年取证实践：当磁盘 EVTX 被清空/仅剩 `Microsoft-Windows-Eventlog` 的 `AutoBackup` 缺失时，
  内存中的事件日志成为唯一可用源，但必须与磁盘/其余制品交叉。
- 本页为公开材料蒸馏，未附本机镜像证据；镜像版本/符号必须现场核对。

## 场景

入口信号：

- 磁盘上 `C:\Windows\System32\winevt\Logs\*.evtx` 缺失、被截断、或 `wevtutil cl` 痕迹明显。
- 有完整内存镜像（raw/dmp），且已能跑通基本进程/网络枚举（否则先做初检）。
- 需要回答“某次登录/服务安装/账户变更发生在何时”，且磁盘日志不可信。
- 攻击者使用 `wevtutil cl`、`Clear-EventLog`、或直接删文件；内存里仍有内存映射页。

前提与边界：

| 条件 | 要求 |
| :-- | :-- |
| 镜像完整性 | 有采集哈希与页数；截断镜像会产生“日志缺口”而非“无事件” |
| 符号/profile | MemProcFS 能自动下载或本地已有对应内核符号 |
| 时间基准 | 全流程 UTC，记录镜像采集时刻与时钟偏差 |
| 只读 | 原件只读，挂载点只写副本目录 |

## 命令

```bash
# 0) 固定镜像与工具版本（结论里要写）
sha256sum mem.raw | tee evidence/mem.sha256
memprocfs --version

# 1) 挂载（只读；-mount 指向空目录）
mkdir -p mnt
memprocfs -device mem.raw -mount mnt -forensic 1 -v

# 2) 找 eventlog 视图
ls mnt/sys/eventlog/
ls mnt/forensic/eventlog/ 2>/dev/null | head
# 典型：Security.evtx / System.evtx / Application.evtx（虚拟重建）

# 3) 导出（cp 到副本目录，不动挂载点）
cp mnt/sys/eventlog/Security.evtx evidence/from-mem-Security.evtx
sha256sum evidence/from-mem-Security.evtx | tee evidence/mem-evtx.sha256
python3 -c "import sys;d=open(sys.argv[1],'rb').read(8);print(d)" \
  evidence/from-mem-Security.evtx   # 期望 b'ElfFile\0'

# 4) 解析与时间线（仓库脚本，UTC）
python Tool/skill/forensics-mobile/scripts/fs-timeline.py \
  --input evidence/from-mem-Security.evtx --out out/timeline-mem.json

# 5) 与磁盘 EVTX / 其他制品交叉
python Tool/skill/forensics-mobile/scripts/forensics-check.py \
  --file evidence/from-mem-Security.evtx --json | tee evidence/evtx-check.json
python Tool/skill/forensics-mobile/scripts/forensics-check.py \
  --file evidence/disk-Security.evtx --json | tee evidence/disk-check.json
```

## 判据表

| 字段 | 取值 | 成立阈值 | 证据 |
| :-- | :-- | :-- | :-- |
| `eventlog_from_mem` | `true/false` + 通道列表 | `true` 需导出文件头为 `ElfFile\0`、可被解析器读出 ≥1 条记录 | `mem-evtx.sha256` |
| `channel_set` | `Security/System/Application` 子集 | 至少 1 个通道有可解析记录；缺失通道写“未重建”，不写“无事件” | `ls` 输出 |
| `record_id_range` | 起止 RecordId | 区间连续或有缺口清单；缺口必须与镜像截断/页缺失对应 | `records.json` |
| `record_count` | 可解析记录数 | 与 `forensics-check.py` 计数一致；两工具差 >5% 需解释 | 两个 JSON |
| `timestamp_utc` | 首/末事件时间 | 全部 UTC，且与镜像采集时刻不矛盾（不得晚于采集） | `timeline-mem.json` |
| `disk_cross_check` | 磁盘 EVTX 同 RecordId 是否一致 | 同 RecordId 的 `EventID/Subject/TimeCreated` 逐字段一致；不一致单列 | 双份解析结果 diff |
| `event_semantics` | 4624/4625/4688/7045 等 | 每条结论引用具体 EventID + 关键字段（LogonType、TargetUserName、ServiceName） | 事件原文 |
| `provenance` | 镜像哈希 + 工具版本 + 挂载参数 | 三件齐全，命令可重放 | `evidence/README` |

`eventlog_from_mem=true` 只说明“内存里能重建出可解析的 EVTX”，不等于“事件真实发生”；
真实发生必须由 `disk_cross_check` 或第二条独立证据（进程/网络/文件时间线）支撑。

## 失败判据

- 导出文件不是 `ElfFile\0` 头，或解析器读 0 条 → 重建失败，改走磁盘日志或 `$MFT` 时间线。
- 记录数远少于磁盘且缺口无规律 → 可能只抓到部分页，标“采样不全”，不写“日志被清空”。
- 同 RecordId 在内存与磁盘上字段冲突 → 以磁盘原件为准还是内存为准需另行判定；先单列冲突。
- 事件时间晚于镜像采集时间 → 时钟/时区错，先校准再入时间线。
- `wevtutil cl` 的 104 事件只在内存里出现、磁盘无对应 → 可作为“清理行为”的强证据，但需 1102/104 搭配。
- 只有 `/sys/eventlog` 目录存在、没有可解析记录 → 判否（目录存在不是证据）。
- 镜像截断/符号不匹配导致进程/网络都跑不通 → 先修镜像，不硬读 eventlog。
- 导出过程写了挂载点或原件 → 证据链污染，作废重采。

> 边界：只处理授权获取的镜像；不提供反取证；内存重建的 EVTX 是“派生证据”，报告中必须标注来源与
> 重建工具版本；不得把内存重建件当原件提交法庭/客户。

## 与 reference 的关系

- 内存取证方法：[memory-forensics.md](../../../../../../../Tool/skill/forensics-mobile/references/memory-forensics.md)。
- EVTX/注册表口径：[04-walkthrough-windows-evtx-registry.md](../../../../../../../Tool/skill/forensics-mobile/references/04-walkthrough-windows-evtx-registry.md)。
- 证据链四要素：[evidence-chain.md](../../../../../../../Tool/skill/forensics-mobile/references/evidence-chain.md)。
- 同 board 邻近篇：[memory-volatility-triage.md](memory-volatility-triage.md)（先跑通进程/网络）、
  [windows-evtx-registry.md](windows-evtx-registry.md)（RecordId/FILETIME 读法）、
  [failure-criteria.md](failure-criteria.md)（何时停）。
