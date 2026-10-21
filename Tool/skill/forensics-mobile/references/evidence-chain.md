# 证据链与完整性

> 配套 `forensics-mobile/SKILL.md` 的 §A4。目标：**任何结论都能被第三方按同样命令复述，且能证明“这份证据没被换过”。**
> 只对自有或明确授权的镜像、抓包、设备操作；原件只读，分析在副本。

## 1. 四要素与结论格式

每条结论必须能填满：

| 要素 | 必填 | 示例 |
|---|---|---|
| 时间 | UTC + 原时区/偏移 | `2026-10-20T03:14:07Z`（设备 UTC+8，偏差 +2s） |
| 主体 | 用户/进程/设备/账号 | `PID 4242 / user alice / bundle com.example.app` |
| 动作 | 读取/写入/外联/执行/删除 | `POST https://example.invalid/api/upload` |
| 对象 | 路径/inode/URL/五元组/注册表键 | `/Users/alice/Documents/a.docx`（sha256 …） |

```json
{"claim":"PID 4242 在 03:14Z 外联 203.0.113.9:443",
 "time_utc":"2026-10-20T03:14:07Z","actor":"PID 4242 (updater.exe)",
 "action":"TLS connect + POST","object":"203.0.113.9:443 /api/upload",
 "confidence":"observed","evidence_refs":["mem.raw#pid=4242","capture.pcap#tcp.stream=7"],
 "command":"vol.py -f mem.raw windows.netscan.NetScan"}
```

**判据**：把 `command` 原样交给另一个人，他能得到同一对象/同一时间，且 `evidence_refs` 能定位到具体条目。

## 2. 采集与封存

```bash
mkdir -p case/{evidence,work,export,report}
cp --reflink=auto <image> case/evidence/ 2>/dev/null || cp <image> case/evidence/
sha256sum case/evidence/* | tee case/evidence/SHA256SUMS
stat -c '%n %s %y %a' case/evidence/* | tee case/evidence/STAT.txt
chmod 444 case/evidence/* 2>/dev/null
```

- 记录：采集人、采集时间、设备归属、采集工具/版本、写保护方式、存储介质编号。
- 内存先采、网络次之、磁盘最后；断电/重启会毁掉易失证据。
- 移动设备记录：型号、系统版本、越狱/root 状态、锁屏状态、飞行模式、时区。
- 云端/远端证据记录：账号、租户、API、导出时间、导出范围。

**判据**：`SHA256SUMS` + `STAT.txt` + 采集记录三件齐全，且原件权限为只读。

## 3. 哈希与副本策略

```bash
sha256sum evidence/mem.raw
sha256sum -c evidence/SHA256SUMS
cmp -n 1048576 evidence/mem.raw work/copy.raw && echo "first 1MiB identical"
```

- 大镜像可先算分段哈希（每 1GiB）再算全量；记录块大小与顺序。
- 工作副本命名带 `work/` 前缀；报告只引用 `evidence/` 的哈希。
- 每次导出/转换（pcap→json、内存→dump）都记录**输入哈希 → 命令 → 输出哈希**。
- 哈希不一致先停：可能是复制错误、坏道、或证据被改；不要“重新算一次”掩盖。

**判据**：输入/输出哈希链完整，任一步可重放；不一致有明确处置记录。

## 4. 时间线归一

```bash
# pcap：epoch → UTC
tshark -r capture.pcap -T fields -e frame.time_epoch -e frame.time | head
# 文件系统：bodyfile → UTC 时间线
fls -r -m "/" -o 2048 disk.img > bodyfile.txt
mactime -b bodyfile.txt -d -z UTC > timeline.csv
# 统一排序（示例：ISO8601 第一列）
sort -t',' -k1,1 timeline.csv > timeline.sorted.csv
```

- 所有时间存两份：原值 + UTC；保留时区、夏令时、NTP 偏差、文件系统精度。
- 时钟偏差用同一事件的多源时间对齐（登录日志/包时间/文件 mtime），不要直接改原值。
- 时间线冲突先查：时区、单位（秒/毫秒/100ns）、FAT 2s、APFS 纳秒、日志服务器延迟。
- 采集顺序也会造成“后发生的事件时间更早”，在报告中说明。

**判据**：任一时间点能回答“哪个证据源、原值多少、如何换算、误差多少”。

## 5. 完整性提示与常见污染

| 风险 | 检查 | 处置 |
|---|---|---|
| 原件被写 | `stat` mtime/权限、哈希复算 | 停，换副本，记录 |
| 直接挂载/打开 | 是否产生 `.journal`/`.wal`/`.shm` | 先复制三件套再打开 |
| SQLite 回写 | 打开后 mtime 变化 | 用只读 URI 或副本 |
| 内存镜像截断 | 文件大小 vs 声明大小 | 标“不完整”，限制结论 |
| pcap 丢包 | `capinfos` 的 dropped/truncated | 标“可能缺会话” |
| 时区混用 | 时间线原值/UTC 对照 | 统一并保留原值 |
| 证据脱敏 | token/密码/个人信息 | 报告打码，原始证据单独封存 |

```bash
# SQLite 只读打开（避免写 WAL）
sqlite3 'file:app.db?mode=ro&immutable=1' 'PRAGMA integrity_check; .tables'
```

**判据**：报告能说明“哪些动作可能改变证据”，以及为什么当前结论不受影响。

## 6. 证据链交付清单

- [ ] 来源、采集人/时间、工具/版本、授权范围。
- [ ] 原件只读 + SHA256 + 大小 + 存储位置。
- [ ] 工作副本与导出物的输入/输出哈希链。
- [ ] 时间线统一 UTC，保留原值、时区与偏差。
- [ ] 每条结论四要素齐全，标 observed/inferred/unverified。
- [ ] 失败/缺口单独列出，不用“dump 成功”代替结论。
- [ ] 敏感信息已脱敏，原始证据访问受控。
