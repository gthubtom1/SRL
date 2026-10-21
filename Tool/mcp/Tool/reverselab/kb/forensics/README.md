# Forensics 知识库 — 取证 / iOS·macOS / 游戏客户端（R26）

内存、流量、磁盘、Windows 制品与移动/游戏客户端的证据链卡片。
技能入口：`Tool/skill/forensics-mobile/SKILL.md`。
铁律：**原件只读、副本分析、全程哈希、时间统一 UTC、结论四要素**。

## 入口

- [内存镜像初检](techniques/memory-volatility-triage.md) — Volatility3、pslist/psscan、malfind、降级
- [pcap 会话与对象](techniques/network-pcap-objects.md) — 会话重组、HTTP 对象、DNS/TLS
- [磁盘与文件系统](techniques/disk-filesystem-timeline.md) — mmls/fsstat/fls/icat、$MFT、mactime
- [Windows EVTX 与注册表](techniques/windows-evtx-registry.md) — 记录 FILETIME、REGF/nk、键路径
- [iOS/macOS 制品](techniques/ios-macos-artifacts.md) — IPA、Mach-O、Keychain、plist、SQLite
- [Unity IL2CPP/AssetBundle](techniques/unity-il2cpp-assetbundle.md) — 元数据、dump.cs、资源清单
- [证据链四要素](techniques/evidence-chain.md) — 时间/主体/动作/对象、哈希链、污染控制
- [失败判据](techniques/failure-criteria.md) — 看到什么就停/降级、代价表

## 10 分钟初检

```bash
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file evidence/AppReadiness.evtx --json
python Tool/skill/forensics-mobile/scripts/fs-timeline.py \
  --input evidence/AppReadiness.evtx --input evidence/Explorer.hiv \
  --input evidence/History.sqlite --input evidence --out out/timeline.json
python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case Tool/cases/forensics03 --json
sha256sum evidence/* | tee evidence/SHA256SUMS
```

1. 记录来源、采集人/时间、工具/版本、授权范围。
2. `file`/magic 判类型；原件只读，先复制。
3. 选证据源：内存 → 流量 → 磁盘（易失性优先）。
4. 建 UTC 时间线，保留原时区/时钟偏差。
5. 每条结论填四要素，标 observed/inferred/unverified。

## 三条硬判据

- **内存/流量**：进程起止/父子/命令行/外联可列；会话双方/起止/协议/关键字段；导出对象有哈希；与磁盘时间线对齐。
- **磁盘/日志**：时间线能定位 inode/路径/操作；`icat` 可复现内容；EVTX/hive 的 RecordId/last-write 可复算。
- **iOS/游戏**：包目录/签名/权限/框架齐全；二进制与数据文件对应；IL2CPP 字段/地址/资源/偏移能对齐。

## 失败判据（何时停）

- 两次换工具仍无法识别镜像/分区/文件系统。
- 符号/profile 不匹配，或镜像截断/格式不支持。
- 时间线缺时区/时钟偏差且无法补齐。
- 四要素缺主体或对象，关键证据哈希不一致，或原件被写。
- iOS 加密二进制未脱壳；IL2CPP 元数据版本不匹配；AssetBundle 加密未解。
- 在线游戏出现反作弊/内核保护。
→ 停并报“未闭环”，不把 dump/解包成功当结论。详见 [failure-criteria](techniques/failure-criteria.md)。

## 工具降级

| 能力 | 首选 | 降级 |
|---|---|---|
| 内存 | volatility3 | Rekall、strings+bulk_extractor、崩溃转储 |
| 流量 | tshark | tcpdump、Zeek、Scapy、pcap-summary.py |
| 磁盘 | sleuthkit | Autopsy、dd+foremost/photorec、debugfs |
| EVTX | 二进制记录解析（fs-timeline.py） | PowerShell Get-WinEvent、wevtutil |
| 注册表 | reg save + REGF 解析 | Registry Explorer、hivex、reg query |
| Mach-O | otool/nm/codesign | llvm-objdump、rabin2、jtool2 |
| IL2CPP | Il2CppDumper/AssetStudio | Cpp2IL、Il2CppInspector、AssetRipper/UnityPy |

## 邻域边界

- Android APK/DEX/SO/脱壳 → `apkseep`；PE 通用逆向 → `softseep`；恶意样本行为定性 → `malware-analysis`。
- 本 board 只做取证与关系说明：不注入、不改内存、不绕过授权/反作弊、不做反取证。
- 对外分享前脱敏：URL 参数、用户名、SID、设备序列号、Keychain 元数据。

## 案例

- `Tool/cases/forensics01` — pcap HTTP 登录会话（fixture）
- `Tool/cases/forensics02` — 应用日志外联/执行（fixture）
- `Tool/cases/forensics03` — 真实 Windows EVTX + HKCU hive + Edge History（real）
- `Tool/cases/forensics04` — iOS IPA/Mach-O/Keychain（fixture）
- `Tool/cases/forensics05` — Unity IL2CPP/AssetBundle（fixture）

细节：`Tool/skill/forensics-mobile/references/` 下 `01-criteria.md`、`02-failure-criteria.md`、`03-model-pitfalls.md`、`04-walkthrough-windows-evtx-registry.md`、`memory-forensics.md`、`network-pcap-and-log.md`、`disk-and-filesystem.md`、`ios-macos-artifacts.md`、`game-client-il2cpp.md`、`evidence-chain.md`。
