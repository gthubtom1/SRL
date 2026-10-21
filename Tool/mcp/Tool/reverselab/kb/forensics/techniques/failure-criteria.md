# 取证失败判据：看到什么就停/降级

> **入口信号**：脚本 rc=0 但结果解释不了；时间线断裂；符号/版本/权限报错。
> **不适用**：还没采集就预判失败；把失败粉饰成“部分成功”。

## 1. 失败判据表

| 现象 | 判定 | 改走哪条 | 代价 |
|---|---|---|---|
| volatility `Unsatisfied requirement` | 符号/版本不匹配 | `banners` 定版本→取 ISF；再不行 `strings` | 结构级结论不可得 |
| `pslist` 空但有系统字符串 | 截断/加密/偏移错 | `psscan`/换工具/核对镜像 | 可能把“没跑”误判“隐藏” |
| pcap 重组无内容 | 截断/加密/单向 | 切片/逐流/keylog | 降为元数据 |
| `fsstat -o` 报损坏 | 偏移用了字节 | 用 `mmls` 扇区重试 | 误判损坏，需重采 |
| `icat` 内容乱码 | inode 复用/块覆盖 | `blkls`+carve，标不可恢复 | 已删文件结论作废 |
| 时间线差整数小时 | 时区/夏令时/NTP | 统一 UTC，保留偏移 | 因果顺序可能反转 |
| EVTX 记录 0/跳变 | 日志清除/滚动 | 查邻近通道/重新导出 | 关键事件缺失 |
| hive 键级遍历 0 | 权限/空文件/脏页 | `reg save` 副本+LOG | 只剩头时间 |
| History 落在 1601/1643/1970 | 纪元换算错 | Chromium 1601us / Firefox 1970us / FILETIME 100ns | 整条浏览器线错位 |
| iOS `cryptid=1` | 未脱壳 | 授权测试机 dump；否则只做包结构 | 静态符号不可信 |
| IL2CPP 版本不匹配 | 元数据/二进制错配 | 换对应工具/版本 | 输出垃圾 |
| AssetBundle 头异常 | 加密/非 Unity | 找 key/算法；或标未解 | 资源不可得 |
| 在线出现 EAC/BattlEye/Vanguard | 反作弊在运行 | 停 attach，转外部观测 | 线上动态结论不可得 |
| 哈希不一致/原件被写 | 证据污染 | 停，重采/说明范围 | 证据链作废 |

## 2. 结构化失败

```json
{"ok": false, "blocked_at": "symbols|permission|parse|tool-missing|evidence-chain", "reason": "..."}
```

报告写：卡在哪、已证实什么、未证实什么、代价与补证计划。

## 3. 降级链

| 能力 | 首选 | 降级 1 | 降级 2 |
|---|---|---|---|
| 内存 | volatility3 | Rekall/崩溃转储 | strings+bulk_extractor |
| 流量 | tshark | Zeek/Scapy | `pcap-summary.py` 会话 |
| 磁盘 | sleuthkit | Autopsy | dd+foremost/debugfs |
| EVTX | 二进制记录解析 | PowerShell Get-WinEvent | wevtutil 文本 |
| 注册表 | `reg save`+REGF | Registry Explorer | `reg query` |
| iOS | unzip+plutil+codesign | llvm-objdump/rabin2 | 只做包结构 |
| IL2CPP | Il2CppDumper | Cpp2IL/Inspector | 只读版本+字符串 |
| 资源 | AssetStudio | AssetRipper/UnityPy | 头/熵/字符串 |

## 4. 边界

- 命中就停/降级，并在产物留 `blocked_at`。
- 不把“工具缺失”写成“目标不存在”。
- 不为了 `confirmed` 忽略时区/哈希/加密。
- 相关：`Tool/skill/forensics-mobile/references/02-failure-criteria.md`、`01-criteria.md`。
