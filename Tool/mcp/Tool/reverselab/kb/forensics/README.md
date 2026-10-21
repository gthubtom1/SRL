# Forensics 知识库 — 取证 / iOS·macOS / 游戏客户端（R26）

内存、流量、磁盘与移动/游戏客户端的证据链卡片。
技能入口：`Tool/skill/forensics-mobile/SKILL.md`。
铁律：**原件只读、副本分析、全程哈希、时间统一 UTC、结论四要素**。

## 入口

- [内存与流量初检](techniques/memory-and-network-triage.md) — Volatility3、pcap 会话、对象导出
- [时间线与证据完整性](techniques/timeline-and-integrity.md) — 四要素、哈希链、污染风险

## 10 分钟初检

```bash
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file evidence/mem.raw
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file evidence/capture.pcap --json
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file evidence/disk.img --no-hash
sha256sum evidence/* | tee evidence/SHA256SUMS
```

1. 记录来源、采集人/时间、工具/版本、授权范围。
2. `file`/magic 判类型；原件只读，先复制。
3. 选证据源：内存 → 流量 → 磁盘（易失性优先）。
4. 建 UTC 时间线，保留原时区/时钟偏差。
5. 每条结论填时间/主体/动作/对象，标 observed/inferred/unverified。

## 硬判据

- **内存**：进程起止/父子/命令行/外联可列；可疑页 dump 可复现。
- **流量**：会话双方/起止/协议/关键字段；导出对象有哈希；与内存/磁盘对齐。
- **磁盘**：时间线能定位 inode/路径/操作；`icat` 可复现内容。
- **iOS/macOS**：包目录/签名/权限/框架齐全；二进制与数据文件对应。
- **游戏**：字段/方法/资源/内存偏移对齐；在线只读观测。
- **证据**：哈希链完整，四要素齐全，第三方能按命令复述。

## 失败判据（何时停）

- 两次换工具仍无法识别镜像/分区/文件系统。
- 符号/profile 不匹配，或镜像截断/格式不支持。
- 时间线缺时区/时钟偏差且无法补齐。
- 四要素缺主体或对象，关键证据哈希不一致，或原件被写。
- 触发反作弊/内核保护/账号风控。
→ 停并报“未闭环”，不把 dump/解包成功当结论。

## 工具降级

| 能力 | 首选 | 降级 |
|---|---|---|
| 内存 | volatility3 | Rekall、strings+bulk_extractor、崩溃转储 |
| 流量 | tshark | tcpdump、Zeek、Scapy、pcap-summary.py |
| 磁盘 | sleuthkit | Autopsy、dd+foremost/photorec、debugfs |
| Mach-O | otool/nm/codesign | llvm-objdump、rabin2、jtool2 |
| IL2CPP | Il2CppDumper/AssetStudio | Cpp2IL、Il2CppInspector、AssetRipper/UnityPy |

细节：`Tool/skill/forensics-mobile/references/` 下 forensics、ios-macos-and-game、memory-and-volatility、evidence-chain。
