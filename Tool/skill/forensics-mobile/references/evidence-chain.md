# 证据链：四要素、哈希链、案例字段与污染控制

> **范围**：任何要提交/复核的取证结论；尤其是内存、磁盘、EVTX、hive、浏览器 History、iOS/游戏客户端混合案例。
> 入口：探索性排查可先做临时观察；一旦写进报告，就按本页补齐证据链。
> 目标：第三方拿同样的证据与命令，能得到同样的结论；任何“换过/写过/缺时区”都能被看出来。

## 1. 四要素（每条结论必填）

| 要素 | 必填 | 示例 | 机检 |
|---|---|---|---|
| 时间 | UTC + 原时区/偏移 | `2026-10-20T03:14:07Z`（UTC+8，偏差 +2s） | `time_utc` 可解析 ISO |
| 主体 | 用户/进程/设备/账号 | `PID 4242 / alice / com.example.app` | `actor` 非空 |
| 动作 | 读取/写入/外联/执行/删除 | `POST https://example.invalid/api/upload` | `action` 非空 |
| 对象 | 路径/inode/URL/五元组/键 | `/home/alice/a.docx`（sha256 …） | `object` 非空 |
| 置信 | observed/inferred/unverified | `observed` | 枚举校验 |

```json
{"claim":"PID 4242 在 03:14Z 外联 203.0.113.9:443",
 "time_utc":"2026-10-20T03:14:07Z","actor":"PID 4242 (updater)",
 "action":"TLS connect + POST","object":"203.0.113.9:443 /api/upload",
 "confidence":"observed","evidence_refs":["mem.raw#pid=4242","capture#tcp.stream=7"],
 "command":"vol.py -f mem.raw windows.netscan.NetScan"}
```

规则：

- 缺主体或对象 → 不是结论，是线索；写 `unverified` 或删掉。
- 时间只有本地时间 → 先换算 UTC，保留原值与偏移；换算方法写清。
- 同一结论多源冲突 → 并列，标各自置信；不要挑“好看”的那个。

## 2. 哈希链（证据完整性）

```bash
# 采集端：原件 + 副本 + 清单
sha256sum input/* | tee input/SHA256SUMS
# 分析端：每次产物单独算，不覆盖 input/
sha256sum artifacts/* > artifacts/SHA256SUMS
```

要求：

- `input/` 只读；`artifacts/` 可写；产物不写回 `input/`。
- 案例 `artifacts[]` 里每个路径都有 64 位 sha256；门禁会复算，不一致即 FAIL。
- 大镜像可先 `--no-hash` 初检，但提交时必须补全或说明“未哈希原因”。
- 哈希算法、工具版本、命令、时间、操作者写进 `acquisition`/`lessons`。

最小案例字段（`Tool/cases/<id>/case.json`）：

```json
{
  "id": "forensics03", "domain": "forensics-mobile",
  "target_type": "真实 Windows 主机取证包", "evidence_kind": "real",
  "protection": [], "authority": "local", "goal_level": "L3",
  "outcome": "partial",
  "acquisition": {"method":"...","tool":"...","collected_at":"...Z",
                  "timezone":"UTC","clock_skew":"unknown"},
  "timeframe": {"start":"...Z","end":"...Z","clock_skew":"unknown"},
  "artifacts": [{"path":"artifacts/timeline.json","sha256":"..."}],
  "findings": [{"time_utc":"...Z","actor":"...","action":"...","object":"...",
                "confidence":"observed","evidence_refs":["input/..."]}],
  "lessons": ["跑的是 …，命令 …，rc=0；…"],
  "refs": ["Tool/skill/forensics-mobile/references/01-criteria.md"],
  "updated": "2026-10-21"
}
```

## 3. 采集记录（acquisition）

必填：`method`（live/copy/crash/export）、`tool`、`collected_at`、`timezone`、`clock_skew`、`source`、`readonly`。

补充建议：

- 设备/主机名、OS build、磁盘序列号（脱敏）、采集人、授权范围。
- 采集顺序：内存 → 网络 → 磁盘；断电/重启会毁掉易失证据。
- 采集工具版本与参数（`dd bs=...`、`ewfacquire -c ...`、`vol.py` 版本）。
- 若原件曾被挂载/运行/改时间戳，写“污染时间窗 + 影响范围”，不要隐瞒。

## 4. 时间线冲突处理

| 冲突 | 常见原因 | 处理 |
|---|---|---|
| 设备时间与服务器差整数小时 | 时区/夏令时 | 统一 UTC，保留原偏移；用登录/HTTP Date 校准 |
| 文件 mtime 早于创建时间 | 时间戳篡改/复制保留 | 并列 `$SI`/`$FN`，标“可能篡改” |
| EVTX 时间跳变/RecordId 空洞 | 日志清除/滚动 | 写“日志不完整”，不据此排因果 |
| 浏览器时间在 1601/1970 | 纪元换算错 | 按库类型重算，抽样对照 |
| 内存时间与磁盘时间差几分钟 | 采集顺序/缓存 | 写采集窗口，不强行对齐到秒 |
| ZIP/IPA 时间与安装时间不符 | DOS 时间/本地时区 | 只作参考，运行时间证据需另取 |

原则：**保留原值 + 统一 UTC + 显式偏差**；冲突不掩盖，写“无法判定顺序”。

## 5. 污染控制清单

- [ ] 原件只读；分析在副本；副本哈希与原件一致。
- [ ] SQLite 复制 `-wal/-shm/-journal`；用 `mode=ro&immutable=1`。
- [ ] 注册表用 `reg save` 导副本；不 `reg load` 原件；带 `LOG1/LOG2`。
- [ ] 镜像不写挂载；用 `icat`/`fls` 按偏移读；必要时 `ro,loop,noatime`。
- [ ] 不运行样本、不执行包内二进制、不 `chkdsk`。
- [ ] 导出对象按 `tcp.stream`/inode/记录号唯一命名，不覆盖。
- [ ] 每次写产物后重算哈希，更新案例。
- [ ] 对外分享前脱敏 URL 参数、用户名、SID、设备标识、Keychain 元数据。

## 6. 机检与人工复核

```bash
python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case Tool/cases/forensics03 --json
```

机检能证明：

- 字段齐全、domain/outcome/evidence_kind 自洽；
- artifacts 路径存在、sha256 复算一致、无 `../` 逃逸；
- acquisition/timeframe 字段齐全、时间可解析；
- findings 四要素/置信枚举/evidence_refs 存在；
- lessons[0] 写了命令与 rc；refs 指向真实文件；
- timeline.json 有 `ok=true` 且事件非空。

机检不能证明：

- 结论为真、时间未被篡改、主体归因正确；
- 工具没有 bug、哈希链覆盖了所有副本；
- 证据采集合法/授权充分。

所以最终报告仍需人工写：`observed/inferred/unverified`、反证、边界、代价。

## 7. 失败判据与边界

- 关键证据哈希不一致/原件被写 → 该链作废，重采或说明污染范围。
- 四要素缺主体或对象 → 降级为线索，不进结论段。
- 时间线缺时区/时钟偏差且无法补齐 → 只写“候选顺序”，不写因果。
- 采集记录缺 method/tool/collected_at/timezone → 不能证明“这是什么时候、怎么拿到的”。
- 只读边界被突破（注入/写内存/改文件） → 停，记录动作与影响。

> 相关：`01-criteria.md`、`02-failure-criteria.md`、`04-walkthrough-windows-evtx-registry.md`、`disk-and-filesystem.md`。

## 8. 证据链保真：哈希 + 来源 + 交接

> 哈希只回答“字节有没有变”；来源回答“从哪来”；交接回答“经过谁的手”。三者合起来才是保真。

### 8.1 三层记录

| 层 | 记录什么 | 放在哪 | 机检 |
| --- | --- | --- | --- |
| 采集 | 时间/人/工具/命令/源设备/时区/偏差 | `acquisition.json` | 字段非空 |
| 完整性 | 每个文件的 SHA256 + 大小 + 计算命令 | `input/SHA256SUMS` | `sha256sum -c` |
| 交接 | 谁在何时把哪些文件交给谁、存储位置/介质 | `custody.log` | 时间链单调、无缺口 |

### 8.2 交接日志模板

```text
2026-10-21T14:20:00Z  collect  alice  host-07  ->  evidence/case-x/input/   3 files  sha256: 89b33c08…
2026-10-21T14:26:00Z  transfer alice  evidence/case-x/input/ -> nas-01:/cases/x/  3 files  sha256: 89b33c08…
2026-10-21T15:02:00Z  analyze  bob    nas-01:/cases/x/ -> work/case-x/input/  3 files  sha256: 89b33c08…
```

**判据**：每次交接都有前后哈希（至少目的端复算）；时间单调；经手人/位置可追。
**失败**：只有“已拷贝”；哈希只在源端算；交接时间晚于分析时间。

### 8.3 证据链断点清单

| 断点 | 现象 | 补法 |
| --- | --- | --- |
| 采集前被改 | 哈希一致但来源不明 | 采集记录 + 设备日志交叉 |
| 传输损坏 | 源/目的哈希不同 | 重传；保留失败记录 |
| 分析污染 | 原件 mtime 变了 | 停；回到只读副本 |
| 产物覆盖 | `input/` 出现新文件 | 从备份恢复；重算全链 |
| 清单遗漏 | 有文件无哈希 | 补算；说明为何晚补 |
| 时间无基准 | 只有本地时间 | 记录时区/偏差；不能补就降级 |

## 9. 案例字段的最小可机检集

`evidence-accept.py` 只认字段，不认故事。最小集如下（JSON 片段）：

```json
{
  "id": "case-x",
  "domain": "forensics-mobile",
  "target_type": "real-host|memory|pcap|disk|ipa",
  "evidence_kind": "real|fixture|synthetic",
  "outcome": "confirmed|partial|failed",
  "acquisition": {"method": "copy", "tool": "dcfldd 1.9",
                  "collected_at": "2026-10-21T14:20:00Z",
                  "timezone": "UTC", "clock_skew": "+2s",
                  "source": "host-07", "readonly": true},
  "timeframe": {"start": "2026-10-08T22:15:25Z", "end": "2026-10-20T03:22:23Z"},
  "artifacts": [{"path": "artifacts/timeline.json", "sha256": "<64 hex>"}],
  "findings": [{"time_utc": "2026-10-20T03:14:07Z", "actor": "PID 4242",
                "action": "TLS connect", "object": "203.0.113.9:443",
                "confidence": "observed", "evidence_refs": ["input/mem.sha256"]}],
  "lessons": ["cmd=... rc=0"],
  "refs": ["Tool/skill/forensics-mobile/references/01-criteria.md"],
  "updated": "2026-10-21"
}
```

| 字段 | 通过 | 常见失败 |
| --- | --- | --- |
| `acquisition.timezone` | 非空 | 写“本地” |
| `artifacts[].sha256` | 64 hex 且复算一致 | 32 位/空 |
| `findings[].actor` | PID/用户/账号 | “未知”/“攻击者” |
| `findings[].object` | 路径/五元组/键 | “数据” |
| `outcome` | 与证据等级一致 | `confirmed` 但只有 E0 |
| `lessons[0]` | 含命令与 rc | “注意时间线” |

> 机检 PASS 只说明字段自洽；结论真假、时间未篡改、主体归因仍需人复核。

## 10. 命令与“通过长什么样”（保真复验）

```bash
CASE=work/case-x

# 1) 全链哈希
sha256sum -c "$CASE/input/SHA256SUMS" | tail -5
sha256sum -c "$CASE/artifacts/SHA256SUMS" 2>/dev/null | tail -5

# 2) 原件可写性
find "$CASE/input" -maxdepth 1 -type f -writable -print

# 3) 交接时间单调（假设日志两列 ISO 时间）
awk '{print $1}' "$CASE/custody.log" | sort -c && echo custody-ordered

# 4) 案例机检
python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case "$CASE" --json \
  | jq '{ok, checks, failures, warnings, artifacts, findings}'

# 5) 时间线非空
jq '{ok, events: .summary.events}' "$CASE/artifacts/timeline.json"
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| 输入哈希 | 全 OK | FAILED → 停 |
| 产物哈希 | 全 OK 且清单存在 | 缺清单 |
| 原件 | 无 writable 输出 | 可写 → 重新封存 |
| 交接 | `custody-ordered` | 时间倒流/缺行 |
| 案例 | `failures=[]` | 缺四要素/refs |
| 时间线 | `events>0` | 0 且无原因 |

> 最后一条提醒：`sha256sum -c` 只校验清单里的文件；清单本身也要受控（入库/只读/带版本），否则“改清单 + 改文件”可以一起骗过校验。
> 同理，`custody.log` 也要与案例一起封存；只存在个人笔记里的交接等于没有交接。
> 命令复跑时固定 `TZ=UTC` 与工具版本；否则同一命令在不同机器会给出不同时间列。

## 这一篇算"用对了"吗

- [ ] 我的每条结论都有时间/主体/动作/对象/置信五段
- [ ] 我同时保留了“哈希链”与“来源/交接”两类记录，不只算哈希
- [ ] `input/` 里没有任何可写文件，产物全部在 `artifacts/`
- [ ] 我的案例字段能被 `evidence-accept.py` 复算，且没有幻影 refs
- [ ] 我知道机检 PASS 不等于结论为真，报告里保留了反证与未验证项
- [ ] 对外分享前做了脱敏（URL 参数/用户名/SID/设备标识）
