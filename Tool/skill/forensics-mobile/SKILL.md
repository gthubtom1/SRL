---
name: forensics-mobile
description: "分析这个内存镜像/流量包/磁盘镜像/事件日志/注册表；或 iOS IPA/Mach-O/Keychain、Unity Mono/IL2CPP/AssetBundle 取证。要时间线 + IOC + 可复现结论。"
license: MIT
compatibility: Linux/WSL2 优先（volatility3、tshark、sleuthkit 原生）；macOS 提供 otool/codesign/security；iOS 动态侧需授权测试机与 frida-server；Windows 支持 EVTX/REGF 二进制解析与 reg save。
metadata: {version: "2.0.0", category: forensics-mobile, hard_gates: "授权与来源 / 只读副本+哈希 / 统一 UTC / 四要素可复述"}
---

# forensics-mobile — 取证 / iOS·macOS / 游戏客户端

> 只回答一件事：**这份内存、流量、磁盘、日志或客户端，能不能还原出「谁在什么时候做了什么」，且第三方能按同样命令复述。**
> “看到可疑字符串”不是结论；结论必须带来源、时间、主体、动作与哈希。仅对自有或明确授权的镜像、设备、客户端操作。

## 阶段契约（与 softseep 一致，**先判再做**）

① 先摸清能不能测（仪器/授权位置/是否服务端权威）→ ② 给**裁定**（可赢 / 部分可赢 / 不可赢）+ **交付上限 M1–M4**（定义见 `softseep/SKILL.md`「交付级」表，别自创口径） → ③ 按上限执行。
- 用户说"要源码级/成品级"是**愿望**，不是判据：判不上去就**说清卡在哪一轴**，给能到的那一级。
- 用户只要低级别、但发现能更高 → 主动告知，由用户定。**不许硬冲，也不许静默降级。**
- 命中任一 **卡点**（要用户手里的凭据 / 需物理动作 / 只可能从真实进程取证据且目标反自动化 / 同形状失败 2 次）→
  **停下来给 A/B/C 卡**，写明：几步、我在监控什么、我保证不动什么、我拿到什么。
- 空目录/首次开工由 **Agent 自己** `case_state.py init`，不要求用户敲命令。

## 1. 范围与路由

**本域输入面**

- 内存镜像/崩溃转储：进程、命令行、网络连接、模块、注入页、内存 hive。
- 流量：pcap/pcapng 会话重组、HTTP 对象导出、DNS/TLS SNI、应用/代理日志。
- 磁盘：分区表、文件系统、inode、已删文件、`$MFT`/USN、mactime 时间线。
- Windows 制品：EVTX 记录时间线、注册表 hive 键最后写入、浏览器 History。
- 主机遥测与反取证残留：ETW provider / ETW-TI / 内核回调 / AMSI / Sysmon 事件字段，以及日志清除、USN 日志删除、Prefetch 缺失、时间戳篡改的**自证痕迹与补偿证据**（检测侧，不写规避）。
- iOS/macOS：IPA 包结构、Mach-O、签名/entitlements、Keychain/plist/SQLite。
- Unity 客户端：Mono/IL2CPP 判定、`global-metadata`、`dump.cs`、AssetBundle、运行时只读字段。

**相邻域与路由**

- Android APK/DEX/SO、脱壳、重打包 → `apkseep`；PE 通用逆向 → `softseep`。
- 恶意样本行为定性/家族归类 → `malware-analysis`；授权旁路/计费/功能解锁 → `01`–`05`。
- 设备/账号/云资源清单由 `scope` 声明；在线反作弊对抗、注入/挂钩/改内存、反取证按对应授权任务执行。

## 2. 前置检查（3 件）

1. **授权与来源**：镜像/抓包/设备/客户端归属明确；采集人、时间、方式、工具版本、时区、时钟偏差已记录。
2. **只读副本**：原件只读封存；分析全在副本；`sha256sum` 与大小写入案例；`input/` 不写、产物进 `artifacts/`。
3. **问题一句话**：先写可判定目标（“还原 03:14Z 哪个 PID 读取了哪个文件并外联哪里”），再选证据源。

> 采集顺序：内存 → 网络 → 磁盘。断电/重启会毁掉易失证据；磁盘镜像最后做，避免写入。

## 3. 判据表（确认 / 疑似）

| 类别 | 确认（可机检） | 疑似（需补证） | 误报风险 |
|---|---|---|---|
| 内存进程 | `pslist`+`psscan` 有 PID/PPID/命令行/start/exit；dump 页可识别 | 只有进程名；差集无解释 | 退出时间缺失≠没运行；JIT/打包器 RWX |
| 内存网络 | 五元组+PID+时间；与 pcap 一侧对齐 | 只有 `strings` 域名；只有连接无进程 | NAT/代理；共享 IP |
| 流量会话 | 双向 `tcp.stream`、请求/响应关键字段、对象 SHA256 | 只有单向包；只有 DNS/SNI | 分块/压缩未重组；同端口多连接 |
| 磁盘/文件系统 | `mmls` Start 与 `fsstat -o` 一致；`fls` 路径/inode/MACB；`icat` 内容可校验 | 只有文件名；`icat` 乱码 | 偏移用字节；inode 复用；FAT 2s |
| 时间线 | 统一 UTC、保留原时区/偏差；冲突并列；可排序 | 只有本地时间；差整数小时 | 纪元混用；采集顺序/缓存 |
| Windows 日志/hive | EVTX 记录数/首末 FILETIME/RecordId 可复算；hive 键路径+last-write 可复算 | 只读到 hive 头；日志有空洞 | 日志清除/滚动；脏页未合并 |
| 浏览器 History | `urls`+`visits` 行数/时间可复算；只读打开；不读 cookie | 时间落在 1601/1643/1970 | 纪元换算错；缺 WAL |
| iOS/macOS | 包结构/签名/entitlements/框架齐全；Mach-O 架构/UUID/cryptid | 只有文件名；`cryptid=1` 未脱壳 | ZIP 时间本地/2s；未脱壳符号不可信 |
| 游戏客户端 | 元数据版本匹配；`dump.cs` 字段/方法/地址对齐；资源属于哪个 bundle | 只有头/字符串；偏移未复验 | 版本漂移；AssetBundle 加密 |
| 证据链 | 四要素齐全；哈希复算一致；原件只读；案例机检 PASS | 只有日志单源；哈希未算 | 日志可伪造；机检≠结论为真 |

判据表的机检边界：

- `forensics-check.py` 证明“类型/头/时间范围/可提取对象”，不证明“谁做的”。
- `fs-timeline.py` 证明“时间戳存在且能排序”，不证明“未被篡改”。
- `evidence-accept.py` 证明“案例字段/哈希/四要素格式齐全”，不证明“结论为真”。

## 4. 失败判据（看到即降级）

完整表见 `references/02-failure-criteria.md`；高频命中：

- `vol.py` 符号/版本不匹配，两次换工具仍无进程/网络结构 → `blocked_at: symbols`。
- pcap 重组无内容、只有单向、TLS 无 keylog → 内容结论降为“元数据/时序”。
- `fsstat -o` 报损坏但 `mmls` 有分区 → 先查 `-o` 是扇区不是字节。
- `icat` 内容乱码/块被覆盖 → 标“不可恢复”，不引用内容。
- 时间线缺时区/时钟偏差、事件差整数小时 → 只写“候选顺序”，不写因果。
- EVTX 记录 0/RecordId 空洞、hive 键级遍历 0 → 写“日志/键不完整”，不写“没发生”。
- 浏览器时间落在 1601/1643/1970 → 纪元换算错，重算并对照。
- iOS `cryptid=1` 未脱壳；IL2CPP 版本不匹配；AssetBundle 加密未解 → 停静态结论。
- 在线出现 EAC/BattlEye/Vanguard/mhyprot → 停 attach/读内存，转外部观测。
- 哈希不一致/原件被写 → 证据链作废，重采或说明污染范围。

## 5. 模型常见失误（≥8 条）

完整版见 `references/03-model-pitfalls.md`。

1. **工具跑通=证据闭环**：`pslist` 有输出就写“进程正常”。→ 必须 `pslist`/`psscan` 差集 + 命令行 + 时间。
2. **strings 命中=外联**：看到域名就下结论。→ 必须五元组 + PID + 时间，找不到标 `inferred`。
3. **单包=会话**：只看请求不看响应。→ `tcp.stream` 双向重组 + 状态码 + 对象哈希。
4. **时间纪元混用**：Chromium `visit_time` 当 FILETIME 除 10，得到 1643 年。→ 按库类型换算并抽样对照。
5. **分区偏移用字节**：`fsstat -o` 失败就写“镜像损坏”。→ 用 `mmls` 的扇区号。
6. **直接打开原库/原 hive**：污染 WAL/锁文件。→ 复制三件套；`mode=ro&immutable=1`；`reg save`。
7. **iOS 加密二进制当明文**：`cryptid=1` 还写“没有某功能”。→ 先脱壳或只写包结构/签名。
8. **IL2CPP 版本错配继续 dump**：输出空表还写“没有该方法”。→ 读 magic/version，核对二进制/Unity 版本。
9. **AssetBundle 头=可解**：看到 `UnityFS` 就承诺全导出。→ 先小样本；失败标“未解”。
10. **在线游戏直接 attach**：触发封号/蓝屏。→ 先识别反作弊；线上只做外部观测。
11. **只写“可疑”**：没有主体/对象/时间。→ 四要素齐全才进结论段。
12. **日志单源当真**：应用日志写 `curl` 就认定上传。→ 至少两个独立源交叉。
13. **产物覆盖原证据**：timeline 写进 `input/`。→ `input/` 只读，产物进 `artifacts/`，重算哈希。
14. **未解写成不存在**：AssetBundle 解不开就写“没有该资源”。→ 写 `blocked_at: tool-missing` 与降级链。

## 6. 流程（分阶段 + 完成判据）

### 阶段 0：接收与封存

- 记录来源/授权/采集人/时间/工具/时区/时钟偏差；`sha256sum`；原件只读。
- 完成判据：`input/` 只读；哈希与大小入案例；问题写成一句可判定的话。

### 阶段 1：分诊（forensics-check）

```bash
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file evidence/AppReadiness.evtx --json
```

- 识别类型/格式/时间范围/可提取对象；判断走内存/流量/磁盘/iOS/游戏哪条链。
- 完成判据：类型有 magic 依据；时间范围与采集记录不矛盾；降级原因写明。

### 阶段 2：深挖（按证据源）

- 内存：`banners`→`pslist`/`psscan`→`cmdline`/`netscan`/`malfind`→dump 哈希。
- 流量：`capinfos`→`conv,tcp`→`follow`/`export-objects`→对象哈希。
- 磁盘：`mmls`→`fsstat -o`→`fls`/`mactime`→`icat` 校验。
- Windows：EVTX 记录时间线；`reg save` + REGF 键 last-write；History 只读。
- iOS/游戏：IPA/Mach-O/Keychain；Mono/IL2CPP 判定；AssetBundle 头/资源。
- 完成判据：每条链有“时间/主体/动作/对象”；至少一个独立源交叉。

### 阶段 3：归一时间线

```bash
python Tool/skill/forensics-mobile/scripts/fs-timeline.py \
  --input evidence/AppReadiness.evtx --input evidence/Explorer.hiv \
  --input evidence/History.sqlite --input evidence --out artifacts/timeline.json
```

- 统一 UTC；保留原时区/时钟偏差；冲突并列；标注 `timestamp_basis`。
- 完成判据：`summary.by_kind` 覆盖所有源；首末时间可复算；warnings 写明截断/权限。

### 阶段 4：证据链验收

```bash
python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case Tool/cases/forensics03 --json
```

- 检查字段/哈希/四要素/refs/timeline；失败输出 `blocked_at` 与 `reason`。
- 完成判据：`ok=true`、`failures=[]`；人工复核 observed/inferred/unverified。

### 阶段 5：报告与降级

- 写清：证据来源/哈希、命令/版本、时间线、四要素、边界、代价、未闭环项。
- 完成判据：第三方按命令能复跑；缺工具/权限/加密项有 `blocked_at`；未污染证据。

## 7. 参考索引（逐篇）

| 篇 | 用途 |
|---|---|
| `references/01-criteria.md` | 判据总表（场景/输入面/判据/证据形态/误报风险） |
| `references/02-failure-criteria.md` | 失败判据表（现象/判定/改走哪条/代价） |
| `references/03-model-pitfalls.md` | 15 条模型常见失误与纠偏 |
| `references/04-walkthrough-windows-evtx-registry.md` | 真实 Windows EVTX+hive+History 走查 |
| `references/memory-forensics.md` | 内存镜像/Volatility3/进程/网络/注入/hive |
| `references/network-pcap-and-log.md` | pcap 会话/对象导出/DNS/TLS/应用日志 |
| `references/disk-and-filesystem.md` | 分区/inode/$MFT/EVTX/REGF/History 时间线 + 主机遥测与反取证痕迹判据（§10） |
| `references/ios-macos-artifacts.md` | IPA/Mach-O/Keychain/plist/SQLite/越狱检测 |
| `references/game-client-il2cpp.md` | Unity Mono/IL2CPP/AssetBundle/运行时只读 |
| `references/evidence-chain.md` | 四要素/哈希链/案例字段/污染控制 |

## 8. 脚本用法

```bash
# 1) 类型/头/时间范围/可提取对象初检（只读）
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file evidence/AppReadiness.evtx --json
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file evidence/capture.pcap --out out/

# 2) evtx/hive/History/文件系统 → UTC 时间线 JSON
python Tool/skill/forensics-mobile/scripts/fs-timeline.py \
  --input evidence/Explorer.hiv --input evidence/History.sqlite --out artifacts/timeline.json
python Tool/skill/forensics-mobile/scripts/fs-timeline.py --self-test

# 3) 案例证据链四要素/哈希/refs 机检
python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case Tool/cases/forensics03 --json
python Tool/skill/forensics-mobile/scripts/evidence-accept.py --self-test
```

- 兼容入口：`python `Tool/skill/forensics-mobile/scripts/forensics-check.py` --file ...` 转发到技能内脚本。
- 所有脚本：`--help` rc=0；`--self-test` 离线 rc=0 且打印 `{"ok": true, ...}`；失败输出 `{"ok": false, "blocked_at": "...", "reason": "..."}` rc=2。
- 路径由 `__file__`/`--root` 推导，不硬编码本机绝对路径；只读，不联网写操作。

## 9. 任务卡入口

- 24 张卡：`Tool/prompts/domains/forensics-mobile.md`
- 覆盖：内存（01–04）、时间线（05–08）、磁盘/NTFS（09–11）、Windows 制品（12–17）、浏览器/邮件/USB（18–20）、iOS/移动（21–23）、容器（24）。
- 每张卡六段：触发词/前置/步骤/判据/失败判据/reference。

## 10. KB board 入口

- `Tool/mcp/Tool/reverselab/kb/forensics/README.md`
- 技术卡：`memory-volatility-triage.md`、`network-pcap-objects.md`、`disk-filesystem-timeline.md`、`windows-evtx-registry.md`、`ios-macos-artifacts.md`、`unity-il2cpp-assetbundle.md`、`evidence-chain.md`、`failure-criteria.md`。
- 案例：`Tool/cases/forensics01`–`forensics05`（含 `real` 的 `forensics03`）。

## 11. 边界

- **Android/授权旁路由邻域承担**：APK/DEX/SO、脱壳、重打包 → `apkseep`；License/计费/功能解锁 → `01`–`05`。
- **采集范围由 `scope` 声明**：设备/账号/云资源清单由用户提供，清单内按任务执行；取证只读副本，只做可复算证据链（采集→校验→关联）。
- **只读观测**：原件只读、副本分析、全程哈希；任何写操作都必须停并记录。
- **失败即停**：缺时区/主体/对象、哈希不一致、原件被写、加密未解、版本不匹配 → 报“未闭环”，不把 dump/解包成功当结论。
- **机检≠结论**：脚本 PASS 只证明格式/哈希自洽；结论真伪、归因强度、证据链强度仍需人工复核。
