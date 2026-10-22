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
