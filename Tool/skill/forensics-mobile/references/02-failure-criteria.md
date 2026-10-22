# 02 · 失败判据表：看到什么就停/降级

> **范围**：取证对象已拿到、脚本已跑过一轮，但结果解释不了或不可信时。
> 入口：先完成一次采集再判失败；失败与“部分成功”分开写（`evidence-chain.md` 分级）。
> 用法：命中任一行 → 立刻停止升级结论，按“改走哪条”降级，并在报告写 `blocked_at` 与代价。

## 1. 失败判据主表

| 现象 | 判定 | 改走哪条 | 代价 |
|---|---|---|---|
| `vol.py` 报 `Unsatisfied requirement` / `Invalid profile` | 符号/ISF 与镜像版本不匹配 | 先 `banners.Banners` 定版本，再取对应 ISF/dSYM；仍不行走 `strings`+`bulk_extractor` | 时间成本 + 只能做字符串级线索，进程/网络结构不可信 |
| `pslist` 为空但镜像有 `KDBG`/`Windows` 字符串 | 结构偏移/版本不对或镜像被截断 | 换 `psscan`/`PoolScanner`，核对镜像大小与采集方式 | 可能把“没跑过”误判成“隐藏”；退出时间不可得 |
| MemProcFS `heap_recovered=false` 或 V3 `windows.heap` 为空 | 24H2+ 堆结构偏移未适配，或工具版本过旧 | 升 MemProcFS 5.19 重跑；仍空改 V3 `windows.heap`，再退 `psscan`+`malfind` | 进程堆/伪句柄不可得；只能做池扫描线索 |
| Win11 26H2 dump 在 MemProcFS <5.19 上崩溃或挂载目录为空 | 工具版本不支持 26H2 内核结构 | 升级 MemProcFS 5.19（2026-10-05）重跑；记录原版本与崩溃点 | 旧版输出不可用；不得写“镜像损坏/结构异常” |
| `/sys/eventlog` 与 `windows.eventlog` 均空，但磁盘 EVTX 有记录 | 内存日志未缓存/已滚动，或插件与 build 不匹配 | 以磁盘 EVTX 为准并注明“内存侧缺失”；核对 build/插件版本 | 内存侧日志归因缺位；不能写“日志被清除” |
| pcap `capinfos` 显示包数正常但重组无内容 | 截断/加密/分片/只抓单向 | `editcap -c` 切片、按 `tcp.stream` 逐流、检查 TLS keylog/进程内明文 | 会话结论降级为“只见元数据”；文件对象不可得 |
| `mmls` 有分区但 `fsstat -o` 报损坏 | `-o` 用了字节而非扇区，或镜像稀疏/加密 | 用 `mmls` 的 Start 扇区重试；`dd` 抽分区头核对；换 Autopsy | 误判文件系统损坏；需要重新采集或换工具 |
| `fls` 能列目录但 `icat` 内容乱码 | inode 复用/块被覆盖/压缩/加密 | 先校验 magic 与哈希；用 `blkls`+carve；标“不可恢复” | 已删文件结论不可用；只能给文件名/时间线索 |
| 时间线跨设备且相差整数小时 | 时区/夏令时未统一，或设备时钟漂移 | 全部转 UTC 并保留原值；用 NTP/登录日志估偏差；分设备列偏移 | 事件顺序可能反转；因果结论失效 |
| EVTX 记录数为 0 或首末时间跳变 | 日志被清除/滚动/复制不完整 | 查 `Security.evtx`/`System.evtx` 邻近通道；用 `wevtutil epl` 重新导出；查 `EventRecordID` 空洞 | 关键登录/进程事件缺失；只能声明“日志不可用” |
| hive 能读头但 `nk` 遍历为 0 | 权限只读到占位/空文件，或 hive 加密/损坏 | 用 `reg save` 导出可读子树；带 `LOG1/LOG2` 一起复制；换 `Registry Explorer` | 只能读头时间；键级时间线不可得 |
| History 时间落在 1601/1643/1970 年 | 时间纪元换算错（Chromium 1601us / FILETIME 100ns / Unix us 混用） | 按库类型选换算：Chromium `1601 + us`、Firefox `1970 + us`、FILETIME `1601 + 100ns` | 整条浏览器时间线错位；必须重算并标注修正 |
| iOS 二进制 `cryptid=1` | App Store 加密未脱壳 | 在授权测试机 dump 后再 `otool`/`nm`；否则只做包结构/签名/权限 | 静态符号与字符串不可信；不能据此判断逻辑 |
| `global-metadata.dat` 版本与 `GameAssembly` 不匹配 | Unity/IL2CPP 版本错配 | 用 `Il2CppDumper` 报的版本换对应 Unity 或 `Cpp2IL`；核对文件来源 | 输出为垃圾；字段/地址不可用 |
| AssetBundle 头不是 `UnityFS/UnityWeb/UnityRaw` | 加密/自定义容器/不是 Unity 资源 | 从二进制找 key/算法；或标“未解”，只做熵/字符串 | 资源内容不可得；不能声称“没有某资源” |
| 在线游戏出现 EAC/BattlEye/Vanguard/mhyprot | 反作弊/内核保护在运行 | 停止 attach/注入/读内存，改为外部抓包、日志、录屏；离线副本另做 | 线上动态结论不可得；但避免封号/蓝屏/法律风险 |
| 证据哈希与记录不一致，或原件 mtime 变了 | 证据被写/被替换/复制不完整 | 立即停；回到只读副本；重算全链哈希；记录污染时间窗 | 该证据链作废；需要重新采集或说明污染范围 |

## 2. 失败时的输出格式

脚本必须输出结构化失败，而不是裸栈：

```json
{"ok": false, "blocked_at": "symbols|permission|parse|tool-missing|evidence-chain", "reason": "具体原因"}
```

报告里对应写：

- **blocked_at**：卡在哪一步（采集/解析/归因/验收）。
- **已证实**：哪些字段/时间/哈希是 observed。
- **未证实**：哪些只能 inferred/unverified。
- **代价**：缺了哪类结论、需要补什么证据、重做范围多大。

## 3. 降级路线（按证据源）

| 能力 | 首选 | 降级 1 | 降级 2 | 何时停 |
|---|---|---|---|---|
| 内存 | volatility3 | Rekall / 崩溃转储解析 | `strings`+`bulk_extractor` | 两次换工具仍无进程/网络结构 |
| 流量 | tshark | tcpdump/Zeek/Scapy | `pcap-summary.py` 只做会话/片段 | TLS 无 keylog 且无进程内明文 |
| 磁盘 | sleuthkit | Autopsy | `dd`+foremost/photorec/debugfs | 分区/文件系统两次识别失败 |
| EVTX | 二进制记录解析（`fs-timeline.py`） | PowerShell `Get-WinEvent` | `wevtutil eql` 导出文本 | 日志被清除且无备份 |
| 注册表 | `reg save` + REGF 解析 | Registry Explorer / hivex | `reg query` 只读键值 | 权限/加密导致键级时间不可得 |
| iOS 包 | `unzip`+`plutil`+`codesign` | `llvm-objdump`/`rabin2` | 只做包结构与签名 | 加密二进制未脱壳 |
| IL2CPP | Il2CppDumper | Cpp2IL / Il2CppInspector | 只读 `global-metadata` 版本+字符串 | 版本不匹配且拿不到对应工具 |
| 资源 | AssetStudio | AssetRipper / UnityPy | 头/熵/字符串 | 加密且无 key |

## 4. 常见“假成功”

- `forensics-check.py` rc=0 只说明“文件可读、类型识别完成”，不说明“证据可信”。
- `unzip` 成功只说明“ZIP 完整”，不说明“iOS 包未被篡改/未加密”。
- `strings` 命中域名只说明“字符串存在”，不说明“运行时真的外联”。
- `fs-timeline.py` 事件数为 0 时 rc=2；若人为把空时间线当成功，属于伪造结论。
- `evidence-accept.py` PASS 只说明“案例元数据自洽”，不替代人工复核。

## 5. 边界

- 失败判据不是“免责声明”：命中后必须真的停/降级，并在产物里留下 `blocked_at`。
- 不把“工具缺失”写成“目标不存在”；缺工具就写 `tool-missing` 并给降级链。
- 不为了凑 `outcome: confirmed` 而忽略时区、哈希、加密状态。
- 反作弊/授权边界内的停止记录本身就是证据，必须保留时间、环境、触发点。

> 相关：`01-criteria.md`、`03-model-pitfalls.md`、`04-walkthrough-windows-evtx-registry.md`、`evidence-chain.md`。
