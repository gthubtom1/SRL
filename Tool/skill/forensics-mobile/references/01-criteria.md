# 01 · 判据表：什么算“取证闭环”

> **适用**：内存镜像、pcap、磁盘/分区镜像、Windows EVTX/注册表、iOS/macOS 应用包、Unity 客户端。
> **不适用**：Android APK/DEX/SO（走 `apkseep`）、授权旁路与反作弊对抗（不在本域）、纯恶意样本行为定性（走 `malware-analysis`）。
> 所有判据都要求“输入可哈希、命令可复跑、结论可被第三方复述”；只看到字符串不算。

## 1. 判据总表

| 场景 | 输入面 | 判据（可机检） | 证据形态 | 误报风险 |
|---|---|---|---|---|
| 内存进程还原 | `mem.raw` / `*.dmp` | `pslist` 与 `psscan` 的 PID 差集可解释；进程有 start/exit、PPID、命令行 | 进程表 JSON/CSV + 模块基址 + dump 文件哈希 | 退出时间缺失被误判“没运行”；符号不匹配导致空表 |
| 内存注入/隐藏 | 可执行私有页 | `malfind` 命中 `MZ`/ELF 头且页权限 `RWX`；能 dump 并二次识别 | 页 dump 的 SHA256 + 虚拟地址 + 所属 PID | JIT/浏览器/打包器也会 RWX；仅 `MZ` 不等于恶意 |
| 流量会话 | `*.pcap` / `*.pcapng` | 双向会话五元组、起止 epoch、协议、请求/响应关键字段齐全 | 会话表 + 导出对象 + 对象 SHA256 | 只看单向包、同端口多连接合并、NAT 后主体不明 |
| HTTP 对象 | pcap + `--export-objects` | 导出文件可打开且哈希稳定；同名对象以 `tcp.stream` 建索引 | `export/http/*` + 哈希清单 | 分块/压缩传输未重组；对象被覆盖 |
| DNS/TLS 外联 | pcap | DNS qname、TLS SNI、时间与客户端 IP 同时存在 | 时间序列 CSV | CDN/共享 IP；DoH 只看到 IP |
| 磁盘分区 | `disk.img` / `*.E01` | `mmls` 的 Start 扇区与 `fsstat -o` 成功；分区表与文件系统一致 | 分区表 + `fsstat` 输出 | `-o` 误用字节偏移 → 假“文件系统损坏” |
| 文件系统时间线 | 分区镜像 | `fls -r -m` 生成 bodyfile，`mactime -z UTC` 可排序；能定位 inode/路径/MACB | bodyfile + timeline.csv | FAT 2s、APFS 纳秒、时区混用；inode 复用 |
| 已删文件恢复 | 未分配空间 | `fls` 标 `(deleted)` 且 `icat` 取回内容 magic/哈希可校验 | 恢复文件 + inode + 哈希 | 块被覆盖；只凭文件名判断内容 |
| Windows 事件日志 | `*.evtx` | 记录 FILETIME 单调、RecordId 连续；事件数/首末时间可复算 | timeline.json + 原始 evtx 哈希 | 日志被清除/滚动；时区显示成本地时间 |
| 注册表 hive | `*.hiv` / `NTUSER.DAT` | `regf` 头有效、hbin 可遍历、nk 键最后写入可重建路径 | 键路径 + last-write UTC + hive 哈希 | 脏页未合并（需 LOG1/LOG2）；权限导致只读到旧副本 |
| 浏览器 History | `History` / `places.sqlite` | 只读打开，`urls`+`visits` 行数与时间可复算；不读取 cookies | URL + visit_time UTC + 行数 | 时间纪元混用（1601us vs Unix us）；同步/去重表 |
| iOS 应用包 | `*.ipa` | `Payload/*.app` 结构、`Info.plist`、签名/entitlements、框架清单齐全 | 目录树 + plist + codesign 输出 | ZIP 时间戳是本地时间/2s 精度；未脱壳二进制不可信 |
| Mach-O | `Mach-O`/`Fat` | `LC_UUID`、架构切片、`LC_ENCRYPTION_INFO.cryptid`、依赖库可列 | `otool`/`llvm-objdump` 输出 | `cryptid=1` 时符号/字符串是加密态 |
| Keychain/plist/DB | `keychain-2.db` / `*.plist` / `*.sqlite` | 表结构/完整性检查通过；WAL/SHM 一起复制；不伪造明文 | schema + 行数 + 完整性 | 直接打开原库改写 WAL；`NSKeyedArchiver` 未解归档 |
| Unity Mono | `Assembly-CSharp.dll` | 能定位类/方法/字段并与配置或协议字段对上 | 反编译源码 + 字段表 | 依赖缺失导致类型解析失败 |
| IL2CPP | `GameAssembly` + `global-metadata.dat` | 元数据 magic/版本与二进制匹配；`dump.cs` 地址可落到反汇编 | dump.cs + script.json + 地址 | 版本错配得到垃圾输出；更新后偏移漂移 |
| AssetBundle | `*.unity3d` / `*.bundle` | 头为 `UnityFS/UnityWeb/UnityRaw`；CAB/资源清单可导出 | 资源清单 + 导出文件哈希 | 加密/自定义压缩直接解析是乱码 |
| 游戏字段链路 | 客户端 + 运行时 | 服务器下发 → 客户端字段 → 内存偏移 → UI/上报四段能连起来 | 字段表 + 偏移 + 抓包 | 只看到内存值，缺来源与去向 |
| Linux/主机产物（auditd、journald、PST/OST、USB） | `audit.log`/journal/`/proc`、`*.pst`、`USBSTOR`+`setupapi.dev.log` | `auditd.record.type=EXECVE` 与同 event 的 `SYSCALL` 的 `auid/uid/pid/exe` 可配对；`journald.entry._PID`/`__REALTIME_TIMESTAMP` 非空；`proc.exe_deleted` 与 `ss.pid` 一致；`pst.messages[].submit_time_utc`/`attachment_sha256` 齐；`usb.first_connect_utc`/`last_connect_utc` 且 `usb.evidence_sources[]` ≥2 | 审计原文 + journal JSON + 导出消息 + 注册表键时间 | `auid=4294967295` 当真实用户；USBSTOR last-write 当首连；OST 缓存不全 |
| 云与容器（CloudTrail/Flow Log/K8s） | CloudTrail JSON、VPC Flow、`kubectl get events -o json` | `cloudtrail.eventName`/`sourceIPAddress`/`userIdentity.arn` 三项非空；`flow.start`/`end`/`action` 齐且非 `NODATA`；`k8s_event.involvedObject` 可指认；`container.upperdir_sha256` 有值 | 事件 JSON + 流日志行 + 可写层快照哈希 | `invokedBy`/服务名被当主体；Flow 60s 窗口被当单包时间 |

## 2. 三类硬判据（按证据源）

### 2.1 内存/流量：能复述“谁在何时做了什么”

- 进程：PID、PPID、镜像路径、命令行、start/exit、用户 SID/UID 至少五项。
- 网络：五元组 + 首末时间 + 协议 + 进程归属（`netscan`/`netstat` 与 pcap 对齐）。
- 结论必须能落到“某 PID 在某个 UTC 时间连接了某地址并发送了某对象”，而不是“发现可疑 IP”。

### 2.2 磁盘/日志：能定位“哪个对象在何时被怎样操作”

- 文件：路径 + inode + MACB 时间 + 哈希；已删文件另标恢复来源。
- 日志：通道 + EventId + RecordId + FILETIME；跨日志用 UTC 对齐。
- 注册表：键路径 + last-write + hive 来源；持久化项要能指到值。

### 2.3 iOS/macOS/游戏：能说明“二进制与数据/资源的关系”

- 包：Bundle ID、签名 Team ID、entitlements、框架/插件、数据文件。
- 二进制：架构、UUID、加密状态、敏感 API、依赖库。
- 游戏：`global-metadata` 版本、`dump.cs` 方法、AssetBundle 资源、运行时字段偏移四者对得上。

## 3. 机检入口

```bash
# 类型/时间线/可提取对象初检
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file evidence/AppReadiness.evtx --json

# evtx / hive / History / 文件系统 → UTC 时间线
python Tool/skill/forensics-mobile/scripts/fs-timeline.py \
  --input evidence/AppReadiness.evtx --input evidence/Explorer.hiv \
  --input evidence/History.sqlite --input evidence --out out/timeline.json

# 案例证据链四要素机检
python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case Tool/cases/forensics03 --json
```

判据表的机检边界：

- `forensics-check.py` 只证明“类型/头/时间范围/可提取对象”，不证明“谁做的”。
- `fs-timeline.py` 只证明“这些时间戳存在且能排序”，不证明“时间戳未被篡改”。
- `evidence-accept.py` 只证明“案例字段/哈希/四要素格式齐全”，不证明“结论为真”。
- 三者都通过仍要人工写 `observed/inferred/unverified`，并保留反证。

## 4. 失败判据（摘要）

出现以下任一情况，停止升级结论，转到 `02-failure-criteria.md` 对应条目：

- 镜像/分区/文件系统两次换工具仍无法识别。
- 时间线缺时区/时钟偏差，且无法从采集记录补齐。
- 四要素缺主体或对象；关键证据哈希不一致；原件被写。
- iOS 二进制 `cryptid=1` 未脱壳；IL2CPP 元数据版本不匹配。
- 在线环境出现反作弊/内核保护，继续 attach 可能封号或蓝屏。

## 5. 边界

- 只做只读观测：不挂载可写、不运行样本、不注入、不改内存、不改时间戳。
- 不提供反取证、隐蔽驻留、绕过授权/反作弊的手法。
- 证据价值 = 可复现性 × 完整性 × 归因强度；缺一项就降级为“线索”而不是“结论”。
- 对外分享前脱敏：URL 查询参数、用户名、SID、设备序列号、Keychain 元数据。

> 相关：`04-walkthrough-windows-evtx-registry.md`（真实案例）、`memory-forensics.md`、`disk-and-filesystem.md`、`ios-macos-artifacts.md`、`game-client-il2cpp.md`、`evidence-chain.md`。

## 附：上游技能卡索引（24 张）

> 上游 = `mukul975/Anthropic-Cybersecurity-Skills`（818 技能库）。本表只回答一件事：这条上游技能在本域**落到哪张卡、哪篇 reference、判据是什么**。

| 上游技能 | 本域任务卡 | 落点 reference | 一句话判据 |
|---|---|---|---|
| `performing-memory-forensics-with-volatility3-plugins` | 内存镜像与 Volatility3 插件链（源：performing-memory-forensics-with-volatility3-plugins） | `Tool/skill/forensics-mobile/references/02-failure-criteria.md` | 进程起止/父子/命令行/外联可列；dump 可二次识别 |
| `performing-memory-forensics-with-volatility3` | Windows 内存进程与网络归因（源：performing-memory-forensics-with-volatility3） | `Tool/skill/forensics-mobile/references/memory-forensics.md` | 连接能落到 PID+时间+五元组；主体（用户/SID）明确 |
| `analyzing-memory-dumps-with-volatility` | 崩溃转储与休眠文件解析（源：analyzing-memory-dumps-with-volatility） | `Tool/skill/forensics-mobile/references/memory-forensics.md` | 能说明崩溃进程/模块/异常时间；与 EVTX/转储头一致 |
| `extracting-memory-artifacts-with-rekall` | Rekall/strings 降级内存取证（源：extracting-memory-artifacts-with-rekall） | `Tool/skill/forensics-mobile/references/02-failure-criteria.md` | 至少一条线索能被独立源验证；报告写明降级链 |
| `performing-timeline-reconstruction-with-plaso` | Plaso 时间线重建（源：performing-timeline-reconstruction-with-plaso） | `Tool/skill/forensics-mobile/references/disk-and-filesystem.md` | 事件 UTC 可排序；来源/对象/主体/动作齐全；可复算 |
| `building-super-timelines-with-plaso` | 超级时间线（多源合并）（源：building-super-timelines-with-plaso） | `Tool/skill/forensics-mobile/references/evidence-chain.md` | 跨源事件能对齐；冲突有解释；不掩盖矛盾 |
| `generating-forensic-timelines-with-hayabusa` | Hayabusa EVTX 时间线（源：generating-forensic-timelines-with-hayabusa） | `Tool/skill/forensics-mobile/references/04-walkthrough-windows-evtx-registry.md` | 事件数/首末时间可复算；规则命中可解释 |
| `building-incident-timeline-with-timesketch` | Timesketch 事件时间线协作（源：building-incident-timeline-with-timesketch） | `Tool/skill/forensics-mobile/references/evidence-chain.md` | 查询可复现；事件到原始证据可追溯 |
| `analyzing-disk-image-with-autopsy` | Autopsy 磁盘镜像分析（源：analyzing-disk-image-with-autopsy） | `Tool/skill/forensics-mobile/references/02-failure-criteria.md` | 能定位 inode/路径/时间；导出内容哈希可校验 |
| `acquiring-disk-image-with-dd-and-dcfldd` | dd/dcfldd 采集磁盘镜像（源：acquiring-disk-image-with-dd-and-dcfldd） | `Tool/skill/forensics-mobile/references/disk-and-filesystem.md` | 镜像哈希与源一致（或说明坏扇区）；大小/扇区数一致 |
| `analyzing-mft-for-deleted-file-recovery` | $MFT 与已删文件恢复（源：analyzing-mft-for-deleted-file-recovery） | `Tool/skill/forensics-mobile/references/disk-and-filesystem.md` | 内容可校验；`$SI`/`$FN` 时间并列；inode 复用被识别 |
| `analyzing-windows-registry-for-artifacts` | Windows 注册表取证（源：analyzing-windows-registry-for-artifacts） | `Tool/skill/forensics-mobile/references/memory-forensics.md` | 键路径/last-write 可复算；持久化项到键+值 |
| `analyzing-windows-amcache-artifacts` | Amcache 程序执行痕迹（源：analyzing-windows-amcache-artifacts） | `Tool/skill/forensics-mobile/references/disk-and-filesystem.md` | 程序路径+哈希+时间齐全；与其它执行痕迹一致 |
| `analyzing-windows-shellbag-artifacts` | ShellBag 目录访问痕迹（源：analyzing-windows-shellbag-artifacts） | `Tool/skill/forensics-mobile/references/disk-and-filesystem.md` | 目录路径+最后写入+用户可复述 |
| `analyzing-lnk-file-and-jump-list-artifacts` | LNK/JumpList 最近文件（源：analyzing-lnk-file-and-jump-list-artifacts） | `Tool/skill/forensics-mobile/references/disk-and-filesystem.md` | 目标路径/卷/时间可复述；与文件系统时间线一致 |
| `analyzing-prefetch-files-for-execution-history` | Prefetch 执行历史（源：analyzing-prefetch-files-for-execution-history） | `Tool/skill/forensics-mobile/references/disk-and-filesystem.md` | 程序名+路径+运行次数+最后运行时间齐全 |
| `parsing-artifacts-with-eric-zimmerman-tools` | Eric Zimmerman 工具链解析（源：parsing-artifacts-with-eric-zimmerman-tools） | `Tool/skill/forensics-mobile/references/disk-and-filesystem.md` | 导出字段可追溯到原始记录；时间 UTC 可排序 |
| `analyzing-browser-forensics-with-hindsight` | 浏览器 History 取证（Hindsight）（源：analyzing-browser-forensics-with-hindsight） | `Tool/skill/forensics-mobile/references/04-walkthrough-windows-evtx-registry.md` | URL+访问时间+行数可复算；不读取 cookie/Login Data |
| `analyzing-outlook-pst-for-email-forensics` | Outlook PST 邮件取证（源：analyzing-outlook-pst-for-email-forensics） | `Tool/skill/forensics-mobile/references/01-criteria.md` | 邮件时间/主体/对象/附件哈希齐全 |
| `analyzing-usb-device-connection-history` | USB 设备连接历史（源：analyzing-usb-device-connection-history） | `Tool/skill/forensics-mobile/references/disk-and-filesystem.md` | 设备标识+连接时间+用户可复述 |
| `performing-mobile-device-forensics-with-cellebrite` | 移动设备取证（Cellebrite 类）（源：performing-mobile-device-forensics-with-cellebrite） | `Tool/skill/forensics-mobile/references/ios-macos-artifacts.md` | 提取范围/哈希/时间可复述；数据与应用对应 |
| `analyzing-ios-app-security-with-objection` | iOS 应用安全分析（Objection）（源：analyzing-ios-app-security-with-objection） | `Tool/skill/forensics-mobile/references/ios-macos-artifacts.md` | 检测点位置+设备状态+检测结果；不伪造“已绕过” |
| `reverse-engineering-ios-app-with-frida` | Frida 逆向 iOS 应用（只读）（源：reverse-engineering-ios-app-with-frida） | `Tool/skill/forensics-mobile/references/ios-macos-artifacts.md` | 二进制函数→运行时值→文件/网络链路可复述 |
| `analyzing-docker-container-forensics` | Docker/容器取证（源：analyzing-docker-container-forensics） | `Tool/skill/forensics-mobile/references/evidence-chain.md` | 容器 ID/镜像/挂载/日志时间可复述；文件哈希可校验 |
