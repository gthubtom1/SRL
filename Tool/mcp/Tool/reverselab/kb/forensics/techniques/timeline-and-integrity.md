# 时间线与证据完整性：四要素、哈希链、污染风险

> 目标：让第三方能按同样命令复述“谁在什么时候做了什么”，并证明证据没被换过。

## 1. 四要素

| 要素 | 必填 | 示例 |
|---|---|---|
| 时间 | UTC + 原时区/偏移 | `2026-10-20T03:14:07Z`（UTC+8，偏差 +2s） |
| 主体 | 用户/进程/设备/账号 | `PID 4242 / alice / com.example.app` |
| 动作 | 读取/写入/外联/执行/删除 | `POST https://example.invalid/api/upload` |
| 对象 | 路径/inode/URL/五元组/键 | `/home/alice/a.docx`（sha256 …） |

```json
{"claim":"PID 4242 在 03:14Z 外联 203.0.113.9:443",
 "time_utc":"2026-10-20T03:14:07Z","actor":"PID 4242 (updater)",
 "action":"TLS connect + POST","object":"203.0.113.9:443 /api/upload",
 "confidence":"observed","evidence_refs":["mem.raw#pid=4242","capture#tcp.stream=7"],
 "command":"vol.py -f mem.raw windows.netscan.NetScan"}
```

**判据**：把 `command` 交给另一个人，他能得到同一对象/时间，且引用能定位。

## 2. 采集与封存

```bash
mkdir -p case/{evidence,work,export,report}
cp --reflink=auto <image> case/evidence/ 2>/dev/null || cp <image> case/evidence/
sha256sum case/evidence/* | tee case/evidence/SHA256SUMS
stat -c '%n %s %y %a' case/evidence/* | tee case/evidence/STAT.txt
chmod 444 case/evidence/* 2>/dev/null
```

- 记录采集人、时间、设备归属、工具/版本、写保护、介质编号。
- 采集顺序：内存 → 网络 → 磁盘；断电/重启会毁易失证据。
- 移动设备记录型号/系统/越狱状态/锁屏/飞行模式/时区。
- 云端证据记录账号/租户/API/导出范围/导出时间。

**判据**：`SHA256SUMS` + `STAT` + 采集记录齐全，原件只读。

## 3. 哈希链

```bash
sha256sum evidence/mem.raw
sha256sum -c evidence/SHA256SUMS
# 大镜像可分段
split -b 1G evidence/mem.raw work/chunk-
sha256sum work/chunk-* > work/chunks.sha256
```

- 每次导出/转换记录：输入哈希 → 命令 → 输出哈希。
- 工作副本放 `work/`；报告只引用 `evidence/` 的哈希。
- 哈希不一致先停：复制错误、坏道或证据被改；不要“重算一次”掩盖。

**判据**：输入/输出哈希链完整，任一步可重放；不一致有处置记录。

## 4. 时间线归一

```bash
tshark -r capture.pcap -T fields -e frame.time_epoch -e frame.time | head
fls -r -m "/" -o 2048 disk.img > bodyfile.txt
mactime -b bodyfile.txt -d -z UTC > timeline.csv
sort -t',' -k1,1 timeline.csv > timeline.sorted.csv
```

- 所有时间存两份：原值 + UTC；保留时区/夏令时/NTP 偏差/文件系统精度。
- 用同一事件多源对齐时钟：登录日志/包时间/文件 mtime。
- 冲突先查时区、单位（秒/毫秒/100ns）、FAT 2s、APFS 纳秒、日志服务器延迟。
- 采集顺序会造成“后发生的事件时间更早”，报告中说明。

**判据**：任一时间点能回答“哪个证据源、原值多少、如何换算、误差多少”。

## 5. 污染风险

| 风险 | 检查 | 处置 |
|---|---|---|
| 原件被写 | stat/权限/哈希复算 | 停，换副本，记录 |
| 直接挂载/打开 | 产生 journal/wal/shm | 先复制三件套再开 |
| SQLite 回写 | 打开后 mtime 变化 | 只读 URI 或副本 |
| 内存截断 | 大小 vs 声明 | 标“不完整”，限制结论 |
| pcap 丢包 | capinfos dropped/truncated | 标“可能缺会话” |
| 时区混用 | 原值/UTC 对照 | 统一并保留原值 |
| 证据脱敏 | token/密码/个人信息 | 报告打码，原始证据封存 |

```bash
sqlite3 'file:app.db?mode=ro&immutable=1' 'PRAGMA integrity_check; .tables'
```

**判据**：报告说明“哪些动作可能改变证据”，以及为什么结论不受影响。

## 6. 交付清单

- [ ] 来源、采集人/时间、工具/版本、授权范围。
- [ ] 原件只读 + SHA256 + 大小 + 存储位置。
- [ ] 工作副本/导出物哈希链。
- [ ] 时间线 UTC，保留原值/时区/偏差。
- [ ] 每条结论四要素齐全，标 observed/inferred/unverified。
- [ ] 失败/缺口单列，不用“dump 成功”代替结论。
- [ ] 敏感信息脱敏，原始证据访问受控。
