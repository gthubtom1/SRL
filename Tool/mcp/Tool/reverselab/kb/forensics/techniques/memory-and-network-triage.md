# 内存与流量初检：Volatility3 / pcap 会话

> 目标：先回答“有哪些进程、连接、会话、对象”，再决定深挖哪条证据链。
> 只在自有/授权镜像上操作；原件只读，副本分析。

## 1. 内存镜像识别

```bash
file mem.raw
sha256sum mem.raw | tee mem.sha256
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file mem.raw
python3 vol.py -f mem.raw banners.Banners
python3 vol.py -f mem.raw windows.info.Info
```

- `banners` 定 OS/版本/架构；`info` 看 KDBG、系统时间、页面大小。
- 符号不匹配会全盘失败；Windows 用对应 ISF，Linux 用内核版本，macOS 用 dSYM。
- 记录镜像格式（raw/vmem/dmp/hiberfil/vmss）与是否截断。

**判据**：OS/版本/架构/系统时间明确，符号加载成功。

## 2. 进程与网络

```bash
python3 vol.py -f mem.raw windows.pslist.PsList
python3 vol.py -f mem.raw windows.psscan.PsScan
python3 vol.py -f mem.raw windows.cmdline.CmdLine
python3 vol.py -f mem.raw windows.netscan.NetScan
python3 vol.py -f mem.raw windows.malfind.Malfind
```

- `pslist` 活动链表 vs `psscan` 池扫描；差集是候选，不是定罪。
- 记录 PID/PPID/创建退出时间/会话/路径/SID；`cmdline` 空不等于无参数。
- `netscan` 看五元组/PID/状态/时间；与 pcap/防火墙日志对齐。
- `malfind` 看 RWX/私有可执行/无文件映射；dump 后单独哈希与二次分析。

**判据**：可疑外联落到 PID+进程路径+时间+对端；可疑页有 PID/基址/权限/哈希。

## 3. pcap 会话与对象

```bash
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file capture.pcap
python Tool/skill/protocol-plugin/scripts/pcap-summary.py --file capture.pcap --json
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap --export-objects http,export/http
```

- 先看首末包/会话，再按 `tcp.stream` 重组；不能只看单包。
- HTTP 对象导出后逐个算哈希；同名文件以 stream 建索引。
- DNS/TLS SNI 给出域名线索；没有 keylog 时只看元数据，不宣称明文。
- 大包先 `capinfos`/`editcap` 切片或强过滤，避免内存爆掉。

**判据**：会话双方/起止/协议/关键字段/对象哈希齐全，并与内存/磁盘时间线对齐。

## 4. 交叉验证

| 内存 | 流量 | 磁盘 |
|---|---|---|
| 进程/命令行 | DNS/TLS SNI | 程序安装路径/预取 |
| netscan 五元组 | 会话五元组 | 防火墙/代理日志 |
| malfind dump 哈希 | 导出对象哈希 | 落地文件哈希 |
| 注册表 hive | HTTP Host/URI | 浏览器历史/下载 |

- 时间先统一 UTC，保留原时区与 clock skew。
- 哈希相同是同一对象；不同先查压缩/编码/分片，不急着下“替换”结论。
- 缺一侧证据时标 `inferred`，不要用单源定罪。

**判据**：同一事件至少两源可对齐，或明确说明只有单源及局限。

## 5. 失败判据

- 两次 `banners/info` 失败或符号不匹配 → 停，先解决 profile。
- 镜像截断/格式不支持 → 只做 strings/carve，不写进程结论。
- pcap 只有单向流量或严重丢包 → 标“会话不完整”。
- TLS 无 keylog 且无进程内明文 → 只做元数据结论。
- 触发反作弊/内核保护 → 立即停，转离线副本或外部观测。
