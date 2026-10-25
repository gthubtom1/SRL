# 04 · 真实案例走查：Windows EVTX + 注册表键名清单 + 浏览器 History

> **目标**：在一台本机 Windows 上，只读复制 AppReadiness 事件日志与 Edge History，并导出 Explorer 的**键名清单**（无值、无原始 hive），归一出 UTC 时间线，用案例验收脚本机检四要素。
> **范围**：本机/授权主机的 Windows 取证初检、时间线重建、证据链验收。
> 前置：授权设备、管理员权限（读 Security.evtx/SAM/SYSTEM 所需）、原始事件；浏览器 URL 只作线索，意图需其他证据。

## 1. 环境与授权

- 环境：Windows + Git Bash，Python 3.12；`fs-timeline.py` 纯标准库。
- 授权：本机所有者授权，仅分析自己的主机；不联网、不读取 cookies/Login Data。
- 只读：所有输入复制到案例 `input/` 后尝试 `chmod a-w`；Windows 上副本仍可能可写（以 check-*.json 的 readonly 为准），**原件**未挂载、未运行、未改时间戳。
- 采集时间：EVTX/History `2026-10-21T14:25:32Z`；键名清单导出 `2026-10-21T19:15:38Z`（主机本地 UTC+8，已换算）。
- 时钟偏差：未知；同一主机单源，未与 NTP/域控交叉校准。

## 2. 采集（命令可照着复跑）

```bash
mkdir -p input artifacts

# 1) EVTX：真实通道文件（只读复制）
cp "$WINDIR/System32/winevt/Logs/Microsoft-Windows-AppReadiness%4Operational.evtx" \
   input/AppReadiness.evtx

# 2) 注册表：只导「键名清单」（键路径，不含值/数据），不落原始 hive
powershell -NoProfile -Command "Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name" \
  | sed "s/^HKEY_CURRENT_USER//" > input/explorer-key-names.txt

# 3) 浏览器 History：只读复制（cookies/Login Data 留在原件）
cp "$LOCALAPPDATA/Microsoft/Edge/User Data/Default/History" input/History.sqlite

# 4) 封存为只读，并记录哈希
chmod a-w input/*
sha256sum input/* | tee artifacts/SHA256SUMS
```

采集结果（真实文件，哈希由 `sha256sum` 复算）：

| 文件 | 大小 | sha256（前 16 位） |
|---|---:|---|
| `input/AppReadiness.evtx` | 69632 | `a1e797541c1ae292` |
| `input/explorer-key-names.txt` | 5703 | `0ef13b7d6a8ca8fe` |
| `input/History.sqlite` | 249856 | `89b33c083d91b79d` |

权限边界（真实失败，不粉饰）：

- `%SystemDrive%/$MFT` 读取 `Permission denied`；`%WINDIR%/System32/config/{SOFTWARE,SYSTEM,SAM}` 同样 `Permission denied`（未提权、未绕过 ACL）。
- 改用 `fsutil fsinfo ntfsinfo C:` 只读查询卷元数据（NTFS 3.1、4096 B/cluster、1024 B/FileRecord、MFT start LCN `0xc0000`）。
- 注册表证据只保留**键名清单**（60 行键路径，无值、无数据）；原始 hive 含本机个人路径（PII），按脱敏纪律未入仓，也没有伪造 hive/MFT 内容。

## 3. 先做类型/时间范围初检

```bash
python Tool/skill/forensics-mobile/scripts/forensics-check.py \
  --file input/AppReadiness.evtx --json
```

原始输出片段（已截断）：

```json
{
  "ok": true,
  "type": "evtx",
  "format": "EVTX",
  "meta": {
    "chunk_count": 1,
    "record_count": 59,
    "first_record_utc": "2026-10-08T22:15:25.951311Z",
    "last_record_utc": "2026-10-20T03:22:23.292580Z"
  },
  "timeline": {
    "start_utc": "2026-10-08T22:15:25.951311Z",
    "end_utc": "2026-10-20T03:22:23.292580Z",
    "basis": "EVTX record FILETIME (100ns since 1601, UTC)",
    "timezone": "UTC"
  }
}
```

这一步只证明：文件是 EVTX、有 59 条记录、首末 FILETIME 可读。它不证明事件语义，也不证明日志未被清除。

## 4. 归一时间线

```bash
python Tool/skill/forensics-mobile/scripts/fs-timeline.py \
  --input input/AppReadiness.evtx \
  --input input/History.sqlite \
  --input input \
  --out artifacts/timeline.json
```

原始摘要（取自 `artifacts/timeline.json`）：

```json
{
  "ok": true,
  "summary": {
    "events": 69,
    "start_utc": "2026-10-08T22:15:25.951311Z",
    "end_utc": "2026-10-21T19:15:38.018519Z",
    "by_kind": {
      "evtx-record": 59,
      "browser-history": 7,
      "filesystem-mtime": 3
    },
    "timezone": "UTC"
  }
}
```

关键事件（节选，均为 UTC）：

```text
2026-10-20T03:20:24.110691Z  evtx-record       AppReadiness.evtx#chunk=0/record=57
2026-10-20T03:22:23.275618Z  evtx-record       AppReadiness.evtx#chunk=0/record=58
2026-10-20T03:22:23.292580Z  evtx-record       AppReadiness.evtx#chunk=0/record=59
2026-10-21T19:15:38.018519Z  filesystem-mtime  explorer-key-names.txt
2026-10-08T22:49:22.657877Z  browser-history   https://cn.bing.com/search?...
2026-10-08T23:13:51.105603Z  browser-history   https://www.hostbuf.com/?install_fs
```

注册表面（键名清单示例，**只有键路径，没有 last-write / 值**）：

```text
\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent
\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlers
\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\exe
```

> 为什么退化：原始 hive 里含本机账号路径（PII），按「凭据/隐私不落盘」纪律移出案例。
> 代价：**不能**再声称键写入时间与值内容；键结构仍可用于「哪些子树存在」的排查。

## 5. 机检案例证据链

```bash
python Tool/skill/forensics-mobile/scripts/evidence-accept.py \
  --case Tool/cases/forensics03 --json
```

输出（`checks` 数量会随案例字段略变，以实际运行为准）：

```json
{
  "ok": true,
  "case": "forensics03",
  "domain": "forensics-mobile",
  "checks": 114,
  "failures": [],
  "warnings": ["artifact 可写：…（应只读封存）"],
  "artifacts": 8,
  "findings": 4
}
```

说明：Windows 上 `chmod a-w` 不一定让 `os.access(..., W_OK)` 返回 False，所以 “artifact 可写” 是告警而不是失败；实际文件权限与哈希仍以 `ls -l`/`sha256sum` 为准。

## 6. 结论

- **observed**：EVTX 59 条记录、首末时间可复算；Edge History 7 条访问、时间纪元按 Chromium 1601us 换算；注册表键名清单 60 行（A–C 前缀样本：Accent / Advanced / AutoplayHandlers / ComDlg32）。
- **observed**：EVTX/History 的 mtime 为 `14:25:32.961Z` / `14:25:33.011Z`；键名清单在 `19:15:38.018Z` 导出（三者在 `timeline.json` 的 filesystem-mtime 事件里可见）。
- **inferred**：键名清单只说明子树存在（如 `ComDlg32\OpenSavePidlMRU`），不能把某次写入归因到具体程序；本案例没有进程树/pcap。
- **unverified**：浏览器访问与 AppReadiness 事件相隔 12 天，不能声称因果；URL 查询参数未脱敏前不适合外发。

## 7. 边界与还差什么

- 边界：单主机、单时区、无 NTP 校准；没有 Security.evtx（4624/4688）、$MFT/USN、pcap；没有管理员权限读 SAM/SYSTEM。
- 还差：补 Security/System 通道、$MFT 或 `fsutil usn readjournal`、注册表 `LOG1/LOG2`、Edge 的 `-wal/-shm`；做 NTP/登录日志时钟校准；对 URL 参数脱敏。
- 失败判据：EVTX 记录为 0/时间跳变 → 查日志清除；键名清单为空 → 查权限/键路径拼写；History 时间落在 1601/1643 → 查纪元换算；任一命中就停并写 `blocked_at`。

## 8. 复跑清单

- [ ] `forensics-check.py --file input/AppReadiness.evtx --json` rc=0，`record_count` 与首末时间一致。
- [ ] `fs-timeline.py --input ... --out artifacts/timeline.json` rc=0，`by_kind` 三类齐全（evtx-record / browser-history / filesystem-mtime）。
- [ ] `evidence-accept.py --case Tool/cases/forensics03 --json` rc=0，`failures` 为空。
- [ ] `sha256sum input/*` 与 `case.json` 的 artifacts 一致。
- [ ] 报告写明 observed/inferred/unverified 与边界。

> 相关：`01-criteria.md`、`02-failure-criteria.md`、`disk-and-filesystem.md`、`evidence-chain.md`；案例目录 `Tool/cases/forensics03/`。

## 9. 同类案例的可迁移判据（EVTX + hive + History）

| 判据 | 本案例 | 迁移到新主机时怎么验 | 不成立时 |
| --- | --- | --- | --- |
| 对象可钉住 | 3 个文件 + SHA256 | 重新复制 + `sha256sum` | 只写路径 → 不可复现 |
| 类型可识别 | EVTX/REGF-keynames/SQLite | `forensics-check.py` | 类型不明 → 先做文件头 |
| 时间可归一 | 3 类事件 UTC | `fs-timeline.py` 的 `by_kind` | 缺时区 → 只给候选顺序 |
| 主体可指认 | 本机用户/浏览器 | 补 SID/用户/进程 | 只有 URL → 线索 |
| 结论分级 | observed/inferred/unverified | 每条填置信 | 裸结论 → 删 |

> 最容易被跳过的是“对象可钉住”：换一台主机，`%LOCALAPPDATA%` 路径不同、History 可能被 Edge 占用。
> 先复制再哈希，不要在浏览器运行时直接读原库。

## 10. 时间线复核：三条独立校验

### 校验 1：源内单调性

```bash
jq -r '.events[] | [.time_utc,.source] | @tsv' artifacts/timeline.json \
  | awk '{ if ($1 < prev) print "NON-MONOTONIC", $0; prev=$1 }' | head
```

通过：同一源内不出现时间倒流（允许同秒）。不通过：先查 `ts_basis` 是否混了本地时间。

### 校验 2：首末时间 vs 源头自报

```bash
jq '{first: .meta.first_record_utc, last: .meta.last_record_utc}' <( \
  python Tool/skill/forensics-mobile/scripts/forensics-check.py --file input/AppReadiness.evtx --json)
jq '{start: .summary.start_utc, end: .summary.end_utc}' artifacts/timeline.json
```

通过：时间线的首末落在源头自报范围内（可有 mtime 例外）。不通过：检查是否漏源/重复计数。

### 校验 3：跨源先后与因果分开

| 关系 | 可以写 | 不能写 |
| --- | --- | --- |
| A 比 B 早 2 分钟 | “A 早于 B” | “A 导致 B” |
| 同一秒 | “同一时间窗口” | “同时发生” |
| 相差 12 天 | “无直接时间关联” | “无关” |

## 11. 命令与“通过长什么样”（本走查复验）

```bash
cd Tool/cases/forensics03

# 1) 哈希
sha256sum -c artifacts/SHA256SUMS 2>/dev/null || sha256sum input/*

# 2) 类型与时间范围
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file input/AppReadiness.evtx --json \
  | jq '{ok, type, records: .meta.record_count, first: .meta.first_record_utc, last: .meta.last_record_utc}'

# 3) 时间线
python Tool/skill/forensics-mobile/scripts/fs-timeline.py \
  --input input/AppReadiness.evtx --input input/History.sqlite --input input \
  --out artifacts/timeline.json
jq '{events: .summary.events, by_kind: .summary.by_kind, tz: .summary.timezone}' artifacts/timeline.json

# 4) 证据链接收
python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case . --json \
  | jq '{ok, checks, failures, warnings}'
```

**通过长什么样**：

| 步骤 | 通过 | 不通过 |
| --- | --- | --- |
| 哈希 | 3 个文件哈希可复算 | 缺 `SHA256SUMS` |
| 类型 | `record_count=59` 且首末可读 | 0 条/时间跳变 |
| 时间线 | `by_kind` 含 evtx/browser/filesystem | 只有一类 |
| 证据链 | `failures=[]`，`checks>0` | 缺 artifact/refs |
| 报告 | observed/inferred/unverified 齐全 | 只有“发现” |

## 这一篇算"用对了"吗

- [ ] 我先复制再哈希，没有在浏览器/注册表运行时直接读原件
- [ ] 我的时间线在三类源上都能解释 `by_kind`，且首末与源头自报一致
- [ ] 我做了至少一条独立校验（单调性/首末/跨源），没有只看事件数
- [ ] 我把“键名清单”与“键值/最后写入”的边界写清了
- [ ] 我的结论分 observed/inferred/unverified，没有把 12 天间隔写成因果
- [ ] 复跑命令与哈希都在案例目录里，别人能原地复现
