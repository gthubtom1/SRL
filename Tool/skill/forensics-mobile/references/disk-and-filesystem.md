# 磁盘 / 文件系统取证：分区、inode、$MFT 与时间线

> **范围**：`disk.img`、`*.E01`、分区镜像、`$MFT`/`$UsnJrnl` 副本、Windows EVTX、注册表 hive、浏览器 History。
> 前置：授权设备；分析在副本上进行（原件只读封存）；`fls` 列表只是目录线索，文件内容需另行恢复。
> 目标：把“哪个对象、在哪个时间、被谁怎样操作”落到分区/文件系统/inode/键/记录级，并能用命令复现。

## 1. 先确认镜像完整性

```bash
sha256sum disk.img | tee disk.img.sha256
stat -c '%n %s %y' disk.img
file disk.img
# E01 用 ewfinfo/ewfverify；dd 镜像核对采集记录与扇区数
```

- 记录采集方式（`dd`/`dcfldd`/`FTK Imager`/`ewfacquire`）、块大小、是否跳过坏扇区。
- 原件只读；所有挂载用 `ro,loop,noatime`，或干脆不挂载，直接用 sleuthkit 按偏移读。

## 2. 分区表与文件系统

```bash
mmls disk.img
fsstat -o 2048 disk.img
fls -r -p -o 2048 disk.img > out/fls.txt
```

- `mmls` 的 `Start` 是**扇区号**；`-o` 用它，不是字节偏移。偏移错会得到“文件系统损坏”的假象。
- `fsstat` 记录文件系统类型、块大小、inode 范围、$MFT/$LogFile 位置；这些决定后续 `icat`/`istat` 参数。
- 多分区镜像要分别做；不要假设“第一个分区就是系统盘”。

## 3. 目录树、已删文件、inode

```bash
fls -r -m "/" -o 2048 disk.img > out/bodyfile.txt
mactime -b out/bodyfile.txt -d -z UTC > out/timeline.csv
fls -r -d -o 2048 disk.img | head -50          # 只看 deleted
istat -o 2048 disk.img 12345                   # inode 元数据
icat  -o 2048 disk.img 12345 > out/recovered.bin
```

判据：

- `fls` 能给出路径、inode、`(deleted)` 标记、MACB 时间。
- `icat` 取回的内容 magic/哈希可校验；否则标“不可恢复”。
- inode 复用：同一 inode 在时间线上出现多次时，必须区分“旧文件残留”与“新文件”。

## 4. NTFS 深水区：$MFT / $UsnJrnl / $LogFile

```bash
# 只读复制（不可读时用 fsutil 查询元数据，不写盘）
cp '/c/$MFT' out/MFT.bin 2>/dev/null || true
fsutil fsinfo ntfsinfo C:
fsutil volume diskfree C:

# 用 sleuthkit 按 MFT 记录号取文件
icat -o 2048 disk.img 12345 > out/from-mft.bin
```

- `$MFT` 记录号 = inode；记录里同时有 `$STANDARD_INFORMATION` 与 `$FILE_NAME` 两套时间，可能不一致（时间戳篡改的线索）。
- `$UsnJrnl:$J` 记录创建/删除/重命名/写入，是“文件系统操作日志”；解析时注意 USN 记录可回绕。
- `$LogFile` 是事务日志，脏页/崩溃恢复会用到；不要在没有副本时让系统挂载。
- `fsutil` 只读查询可用于确认簇大小/可用空间；`fsutil usn readjournal` 需要权限，读不到就写 `blocked_at: permission`。

## 5. Windows 事件日志（EVTX）

```bash
# 只读复制；原件在 %WINDIR%/System32/winevt/Logs/
cp "$WINDIR/System32/winevt/Logs/Security.evtx" input/Security.evtx
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file input/Security.evtx --json
python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input input/Security.evtx --out out/evtx.json
```

- EVTX 记录结构：`**\0\0` + size + RecordId(u64) + FILETIME(u64) + Binary XML；`fs-timeline.py` 至少能稳定取出 RecordId/FILETIME。
- 事件语义（EventId/Provider/Level/Task）需要 Binary XML 解码；本域脚本只做时间线，语义用 `wevtutil`/PowerShell 补充。
- 常见通道：Security（4624/4625/4688/4672）、System（7045 服务）、Application、PowerShell/Operational、TaskScheduler/Operational。
- 日志滚动/清除会留下 `EventRecordID` 空洞；时间跳变要写“可能清除/时区变化”，不要直接排因果。

## 6. 注册表 hive（REGF）

```bash
# 只读导出当前用户子树（不修改原 hive）
# 通用做法（分析真实 hive）；若案例要入库，注意 hive 常含本机账号路径（PII），
# 可退化为「键名清单」：Get-ChildItem ... | Select Name（无值、无原始 hive）
cmd //c "reg save HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer input/Explorer.hiv /y"
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file input/Explorer.hiv --json
python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input input/Explorer.hiv --out out/registry.json
```

- REGF 头：`regf`、header last-write（0x0C）、root cell（0x24）、hive bins size（0x28）。
- hbin 头 `hbin`，大小在 +0x08；cell 大小为有符号 int32，负值表示已分配；`nk` 键的最后写入在 cell+8。
- 键名压缩标志 `0x20`：置位用 Latin-1，否则 UTF-16LE。
- 脏页/事务：同时复制 `.LOG1/.LOG2`；只读头可能落后于最新事务。
- 持久化面：Run/RunOnce、Services、IFEO、Winlogon、AppInit_DLLs、TaskScheduler、UserAssist、ShellBags、USBSTOR。

## 7. 浏览器 History（只读；cookie 留在原件）

```bash
cp "$LOCALAPPDATA/Microsoft/Edge/User Data/Default/History" input/History.sqlite
python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input input/History.sqlite --out out/history.json
```

- Chromium/Edge：`urls` + `visits`，`visit_time` 是 **1601 起的微秒**；Firefox：`moz_places` + `moz_historyvisits`，`visit_date` 是 **1970 起的微秒**。
- 只查 URL/visit_time/title，不读 `cookies`/`Login Data`；需要登录态证据时单独授权并脱敏。
- `-wal/-shm` 一起复制；直接用 `mode=ro&immutable=1` 打开，避免创建/回写。

## 8. 统一时间线

```bash
python Tool/skill/forensics-mobile/scripts/fs-timeline.py \
  --input input/Security.evtx --input input/Explorer.hiv \
  --input input/History.sqlite --out out/timeline.json
fls -r -m / -o "$OFF" "$IMG" > out/bodyfile.txt
mactime -b out/bodyfile.txt -d -z UTC > out/disk-timeline.csv
```

注意：`fs-timeline.py` 接受原始 evtx/hive/sqlite/目录，不直接吃 bodyfile，也不把前一次生成的 timeline JSON 当输入；bodyfile 用 `mactime -z UTC` 转 CSV 后再与 JSON 在独立合并步骤中对齐。合并规则：

- 主键：`time_utc`；同一时间用 `source/object` 稳定排序。
- 保留原值：设备时区、文件系统精度（FAT 2s、APFS 纳秒）、时钟偏差。
- 冲突：同一对象多套时间（`$SI` vs `$FN`）要并列，不取“看起来合理”的那个。

## 9. PST/OST 邮件与 USB 设备史

```bash
readpst -o out/pst -D -M mailbox.pst        # libpst：-D 分离附件，-M 输出 mbox
pffinfo mailbox.pst                         # libpff：类型/版本/加密状态
pffexport -m all -t out/pff mailbox.pst     # 逐条消息导出（含可恢复项）
```

- PST/OST 同为 `!BDN` 容器；OST 是 profile 缓存，条目可能不全，必须与服务器侧或导出件对照。加密（compressible encryption）先用 `pffinfo` 判，再决定是否能读。
- 每条消息取：`PidTagClientSubmitTime`/`PidTagDeliveryTime`、`PidTagSenderSmtpAddress`、`PidTagDisplayTo`、`PidTagSubject`、附件 SHA256。删邮件看 `pffexport` 的可恢复/未分配项，不能只导活动文件夹。
- USB 设备：`SYSTEM\CurrentControlSet\Enum\USBSTOR\<device>\<instance>`（`VID_xxxx&PID_xxxx` + 序列号）；子键 last-write 是“最后写入”，不等于连接时间；`Properties\{83da6326-...}\0064`/`0065` 分别是首连/末连时间（8 字节 SYSTEMTIME）。
- `setupapi.dev.log` 的 `>>> [Device Install (DiInstallDevice) - USB\VID_...]` 段带时间戳与驱动路径，是 USBSTOR 之外的独立源；`Kernel-PnP` 事件 400/410/420 给接入/断开。
- `Windows Portable Devices\Devices`、`MountedDevices`、`EMDMgmt` 补设备卷与挂载点；首连时间取“首连属性 + setupapi 最早段 + PnP 事件”三者中最早的一个，不能只看 USBSTOR 键 last-write。
- 时间基准不同：PST 内 `PidTagClientSubmitTime` 是 UTC 的 FILETIME；USBSTOR `0064/0065` 存的是**本地时间**的 SYSTEMTIME（无时区）。要拿 `ControlSet001\Control\TimeZoneInformation` 换算，否则首连时间会偏整数小时。
- 只读：先把 PST 复制到 `input/` 再 `readpst`/`pffexport` 到 `out/`；hive 用 `reg save` 导出副本，不在原机 `reg query` 当唯一来源（live 键值可被后续写入改掉）。
- 附件单独算 SHA256 并 `file` 二次识别；导出目录按 message id/序号分层，同名附件不覆盖。
- 设备史不能反推“拷走了哪个文件”：USBSTOR/setupapi 只证明连接；拷贝行为要靠 `$UsnJrnl`、ShellBag、LNK（带卷序列号）与文件系统时间线对应。

**判据**：`pst.messages[]` 每条有 `submit_time_utc`/`sender`/`subject`/`attachment_sha256`；`usb.devices[].instance_id`、`usb.first_connect_utc`、`usb.last_connect_utc` 均非空，且 `usb.evidence_sources[]` ≥2。

**失败判据**：`pffinfo` 报加密且无凭据 → `blocked_at: encrypted`，不写“无该邮件”；OST 条目为 0 → 先查 profile/凭据，不写“没有记录”；USBSTOR 无 `0064/0065` → 用 setupapi/PnP 补，仍无就标“无首连时间”；`setupapi.dev.log` 已轮转（只剩尾部）→ 写“日志截断”，不写“未连接”。

## 10. 主机遥测与反取证痕迹（检测侧判据）

> **口径（先读这一段）**：本节只做两件事 ——（1）说清一台主机上有哪些遥测源、**哪些动作会被记下来**、取证时怎么读；
> （2）说清**痕迹被清掉之后，清理动作本身还会留下什么**。
> 本节**不写**规避/致盲手段：不写 patch `EtwEventWrite`、不写注销 provider、不写摘内核回调、不给免杀/擦除命令。
> 需要「怎么绕过某遥测」的属于 `01`–`05` 的授权任务；本域只交付**自身可观测性识别**与**痕迹还原**。

采信顺序：**先独立源，后聚合源**。聚合源（EDR 控制台、SIEM 告警）能改能删；
独立源（`$MFT`/`$UsnJrnl`/Prefetch/Amcache/SRUM 副本、WEC 转发件、VSS 快照）改起来更贵，所以冲突时以独立源为准，并把冲突写进报告。

### 10.1 遥测源总表

| 遥测源 | 记录什么 | 什么动作会触发 | 取证时怎么读 | 被清理后的补偿证据 |
|---|---|---|---|---|
| ETW `Microsoft-Windows-Kernel-Process` | 进程/线程 创建·退出（Image/PID/PPID/SessionId/退出码），**不含命令行** | 任意 `CreateProcess`/`NtCreateUserProcess`、线程创建 | `logman query providers` 取 GUID 后 `xperf`/`wpr -start` 或读已落盘的 `.etl` | 4688/Sysmon 1 的命令行；`$MFT` 里 exe 的时间线；Prefetch last-run |
| ETW `Microsoft-Windows-Kernel-File` / `-Registry` | Create/Read/Write/Rename/Delete（FileObject、FileName、FileKey）；RegCreateKey/RegSetValue/RegDeleteValue（KeyName、RelativeName） | 任意文件/注册表操作（含只读打开） | 同上，或 `wpr -start FileIO -start Registry` 采集后离线解析 | `$UsnJrnl` 文件级记录；REGF 键 last-write；`$MFT` 的 `$SI`/`$FN` |
| ETW `Microsoft-Windows-Threat-Intelligence`（ETW-TI） | 跨进程内存分配/写入、句柄请求、驱动加载等**高价值原语**（谁对谁做了什么） | 远端线程注入、跨进程 `VM_WRITE`、`ObOpenObject` 争权限 | 仅 PPL/反恶意软件签名的 EDR 能开；取证侧读 EDR 导出的 TI 事件或厂商日志 | Sysmon 8/10 + 4688 的调用栈/父子关系；内存镜像里的 `malfind` 页 |
| 内核回调（`PsSetCreateProcessNotifyRoutineEx`/`PsSetCreateThreadNotifyRoutine`/`PsSetLoadImageNotifyRoutine`/`ObRegisterCallbacks`/`CmRegisterCallbackEx`） | 进程/线程/镜像加载、句柄打开、注册表 pre-post 回调 | 进程启动、DLL/驱动加载、`OpenProcess` 拿句柄、reg 写 | **用户态看不到注册者**；只能枚举驱动（见 §10.3）与签名，推断「谁在监听」 | 7045/7036/7034 的服务与驱动变更；`fltmc filters`；驱动文件与签名 |
| minifilter（`FltRegisterFilter`）+ WFP callout | 文件 I/O 的**路径+内容上下文**（可拦可记）、TCP 连接元数据 | 任何落盘/重命名/删除；任何出站连接 | `fltmc filters`/`fltmc instances` 只列已挂载过滤器；内容层看厂商日志 | Sysmon 11/23/26；`$UsnJrnl`；pcap 侧五元组与进程对应 |
| AMSI（`AmsiScanBuffer`/`AmsiScanString`） | **提交扫描的内容原文 + 扫描结论**，但 AMSI 自身不落盘 | PowerShell 输入、VBScript/JScript（`wscript`/`cscript`/`mshta`）、Office VBA、`.NET` `Assembly.Load(byte[])` | 留痕在 provider 侧：Defender `1116/1117`、`MPLog-*.log`；脚本原文另见 4104 | PowerShell 4104/4103；`ConsoleHost_history.txt`；进程命令行（4688） |
| PowerShell ETW（`Microsoft-Windows-PowerShell`，GUID `a0c1853b-5c40-4b15-8766-3cf1c58f985a`） | 400/403 引擎状态、4103 模块日志（Payload+ContextInfo）、4104 脚本块（ScriptBlockText/Id/Path/MessageNumber） | 需要 `ScriptBlockLogging`/`ModuleLogging` 策略开启；任意脚本执行 | `Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational'` | 4688 命令行、`Preface`/`ConsoleHost_history.txt`、AMSI 命中的 `MPLog` 片段 |
| 安全审计 4688/4689/4624/4672/4656/4663/4719 | 进程创建（**命令行只在开了 IncludeCommandLine 时才有**）、进程退出、登录、特权分配、对象访问、审计策略变更 | 受 `auditpol` 策略控制；进程创建要开「审核进程创建」 | `wevtutil qe Security /q:"*[System[(EventID=4688)]]" /f:text` | Sysmon 1、Kernel-Process、Prefetch、`$UsnJrnl` |
| Sysmon（独立通道 `Microsoft-Windows-Sysmon/Operational`） | 见 §10.2 逐事件字段 | 见 §10.2 | 通道文件 + `sysmonconfig.xml`（配置本身是证据） | 系统自带的 Kernel-* ETW、Security 审计、文件系统时间线 |
| 执行痕迹：Prefetch / Amcache / ShimCache / SRUM / BAM / UserAssist | 程序跑过没跑过、跑了多久、加载了哪些文件/卷序列号 | 每次执行；Prefetch 还记 last-run 时间与引用文件 | `PECmd`、`AmcacheParser`、`AppCompatCacheParser`、`SrumECmd`（离线解析副本） | 见 §10.4 第 4 行：删 `.pf` 只删掉一层 |

### 10.2 Sysmon 事件 ID 与关键字段

> 前提：**Sysmon 的配置决定它记什么**。先读 `sysmonconfig.xml`（含 `FileCreateTime`、`ProcessAccess`、`PipeEvent`、`DnsQuery` 等开关），
> 再看通道；配置里没开的项，「没记录」≠「没发生」。

| ID | 名称 | 关键字段 | 覆盖的动作 |
|---|---|---|---|
| 1 | Process Create | `Image` `CommandLine` `ParentImage` `ParentCommandLine` `User` `IntegrityLevel` `Hashes` | 起进程（含父子关系与完整命令行） |
| 2 | File creation time changed | `Image` `TargetFilename` `CreationUtcTime` `PreviousCreationUtcTime` | **时间戳篡改**（需配置开启） |
| 3 | Network connection | `Image` `Protocol` `SourceIp/Port` `DestinationIp/Port` `DestinationHostname` | TCP/UDP 出站，与进程绑定 |
| 5 | Process terminated | `Image` `ProcessGuid` | 进程退出（补 1 的生命周期） |
| 6 | Driver loaded | `Image` `Signature` `SignatureStatus` `Signed` `Hashes` | 驱动注册/加载（内核回调注册者的线索） |
| 7 | Image loaded | `Image` `ImageLoaded` `Signature` `Hashes` | DLL/模块加载（含未签名/侧载） |
| 8 | CreateRemoteThread | `SourceImage` `TargetImage` `NewThreadId` `StartAddress` `StartModule` `StartFunction` | 远端线程（注入） |
| 10 | Process accessed | `SourceImage` `TargetImage` `GrantedAccess` `CallTrace` | 句柄请求（`0x1010`/`0x1fffff` 等），`CallTrace` 给调用栈 |
| 11 | File created | `Image` `TargetFilename` `CreationUtcTime` | 落盘 |
| 12 / 13 | Registry create·delete / set value | `EventType` `TargetObject` `Details` | 自启、服务、策略、IFEO 改写 |
| 15 | FileCreateStreamHash | `Image` `TargetFilename` `Hash` `Contents` | **ADS 落盘**（`file:stream`） |
| 17 / 18 | Pipe created / connected | `PipeName` `Image` | 命名管道（横向、C2 通道） |
| 22 | DNS query | `QueryName` `QueryResults` `Image` | 域名解析与进程绑定 |
| 23 / 26 | FileDelete (archived / logged) | `Image` `TargetFilename` `Archived` `Hashes` `User` | 删除（`Archived=true` 时内容被归档，可复原） |
| 25 | ProcessTampering | `Image` `Type` | 进程镂空/镜像替换 |
| 16 / 255 | Config change / Sysmon error | `Configuration` / `Description` | 配置被改、自身异常（**被致盲的线索**） |

### 10.3 只读枚举：谁在这台机器上「看着」

```powershell
logman query -ets                       # 当前 ETW 会话（含 EventLog-* 与厂商会话）
logman query providers | Select-String -Pattern 'Kernel-|Threat|Sysmon|PowerShell'
wevtutil gli Security                   # 通道启用状态/记录数/创建时间（清空后 creation≈清空时刻）
driverquery /v /fo csv > artifacts/drivers.csv
fltmc filters > artifacts/minifilters.txt
Get-CimInstance Win32_SystemDriver | Where-Object State -eq 'Running' |
  Select-Object Name,DisplayName,PathName,StartMode
```

```bash
# 文件系统侧（只读查询，不写盘）
fsutil usn queryjournal C:      # UsnJournalID / NextUsn / LowestValidUsn / MaximumSize
fsutil fsinfo ntfsinfo C:       # 簇大小 / MFT 起始 LCN
fsutil fsinfo volumeinfo C:     # 卷序列号，用于和 Prefetch 里的卷信息对齐
```

- `fltmc`/`driverquery` 只能证明「现在挂着谁」，不能证明「刚才还有谁」；后者靠 7045/7036 与 Sysmon 6。
- `fsutil usn queryjournal` 的 `UsnJournalID` 是随机值：**采集时记一次基准**，事后变了就是被删过/重建过（见 §10.4 第 3 行）。

### 10.4 反取证动作 → 它自己留下什么 → 补偿证据

| 清理动作 | 它自己留下的痕迹 | 补偿证据（清不掉的部分） |
|---|---|---|
| `wevtutil cl Security` / `Clear-EventLog` | Security `1102`（清空）、System `104`（清空）、`EventRecordID` 从 1 重来、`wevtutil gli` 的 creation time ≈ 清除时刻 | WEC/转发到 collector 的副本；`Security.evtx` 自身的 `$MFT`+USN 记录（`DATA_TRUNCATION`/`DATA_OVERWRITE`）；`wevtutil.exe-*.pf`；VSS 快照；EDR 本地缓存 |
| 停 EventLog 服务 / 改审计策略（`auditpol`） | Security `1100`（服务停止）、`4719`（策略变更）、System `7036` 服务状态 | 服务键 last-write；**清 Security 不动 System**，System/PowerShell 通道仍在；计划任务与 Run 键 |
| `fsutil usn deletejournal /d` | `queryjournal` 的 `UsnJournalID` 变化 + `NextUsn` 归零；`$Extend\$UsnJrnl:$J` 有效数据被清 | `$LogFile` 事务；`$MFT` 时间线（`$SI`/`$FN`）；VSS；`fsutil.exe-*.pf`；4688 命令行（若审计开）；采集时的 journal 基准 |
| 删 `*.pf` / 关 Prefetch（`EnablePrefetcher=0`） | SYSTEM hive 该值 + 键 last-write；SysMain `7036`/`7034`；USN 里 `*.pf` 的 `FILE_DELETE`；MFT **未使用记录仍留文件名** | Amcache（首次见到/PE 元数据）、ShimCache/AppCompatCache（执行证据）、SRUM（`SRUDB.dat`）、BAM、UserAssist |
| Timestomp（改属性 / 直写 `$SI`） | `$SI` 与 `$FN` 不一致；四时间相等或为 0/1601；USN `BASIC_INFO_CHANGE`；Sysmon 2 | Prefetch 内嵌 last-run 与文件 mtime 矛盾；`$LogFile`；该文件的 `DATA_OVERWRITE` 记录；Amcache 首见时间 |
| 停/卸 EDR 服务或 minifilter 驱动 | System `7045`（新服务）/`7036`/`7034`；`fltmc filters` 少了一条；服务键 last-write；驱动文件 mtime | EDR 云端心跳断点（网络侧）；Sysmon 6 历史；残留驱动文件与签名状态；`Win32_SystemDriver` 的 `State` |
| 清 PSReadLine / bash history | `ConsoleHost_history.txt` 缺失或 mtime 晚于会话；USN `FILE_DELETE` | PowerShell `4104`（若开且未被清）、`4103`；`$MFT` 未使用记录；4688 命令行 |
| ADS 藏文件（`type x > a.txt:s`） | `dir /r`、`Get-Item -Stream *` 可见；MFT 里 `$DATA` 命名流；USN `STREAM_CHANGE` | 卷用量与可见文件大小的差值；`$MFT` 中带 `:stream` 的条目；Sysmon 15 的 `Contents` 哈希 |
| 只删不擦（`del`/`Remove-Item`） | USN `FILE_DELETE`；MFT 记录转未分配但内容可能仍在 | `fls -d` + `icat` 恢复；Prefetch/ShimCache 仍证明它跑过；`$LogFile` |

**读表方式**：每一行都是「清理动作 → 自证痕迹 → 还能从哪补」。报告里只写前两列 = 只说「可能被清过」；
必须写到第三列的具体来源（文件名/事件 ID/键路径），才算**还原**。

### 10.5 判据与失败判据

- **确认**：清理动作有**自证痕迹**（1102/104、`UsnJournalID` 变、Sysmon 2）+ **一个独立源**（`$MFT`/Prefetch/转发副本）时间对得上。
- **疑似**：只有一处缺口（如某通道记录数异常少、某 `.pf` 缺失），且缺基准；写「窗口内有缺口」，不写「被清除」。
- **失败判据**：`Security.evtx` 记录为 0 且无转发副本 → 写 `blocked_at: log-cleared`，**不写「没发生」**；
  `$UsnJrnl` 不可读/已回绕（`NextUsn` ≫ `LowestValidUsn`）→ 写「文件级记录不可用」，改用 `$MFT`+Prefetch+SRUM；
  无 Sysmon 通道 → 写「无 Sysmon」，不得用 4688 缺失推「没执行」；
  缺时区/时钟偏差 → 只给候选顺序（见 §8 与 `02-failure-criteria.md`）。

### 10.6 边界

- **只读**：`logman`/`wevtutil`/`fltmc`/`driverquery`/`fsutil ... queryjournal` 都是查询；不 `logman stop`、不清日志、不动服务。
- **只给检测侧**：本节只写「会被记下什么」与「清掉之后怎么还原」，不给 hook/patch/provider 注销/回调摘除/日志清洗的任何步骤；这类需求按越界处理，转授权任务域。
- **配置即证据**：Sysmon 配置、审计策略（`auditpol /get /category:*`）、ETW autologger 注册表项都要随案例封存，否则「没记录」无法解释。
- **时间基准**：ETW 事件时间来自内核时钟，与文件系统 `$SI`（用户态可改）、Prefetch last-run（内核写）精度不同；对齐时写明来源与精度。

## 11. 失败判据

- `mmls`/`fsstat` 两次换工具仍无法识别分区/文件系统 → 停，`blocked_at: parse`。
- `-o` 偏移错误导致“损坏” → 回到 `mmls` 重取，不要写“镜像损坏”。
- 已删文件 `icat` 内容乱码/块被覆盖 → 标“不可恢复”，不引用其内容。
- hive 只读到头、键级遍历为 0 → 检查权限/LOG/副本，写 `blocked_at: permission`。
- EVTX 记录为 0/RecordId 空洞 → 说明日志清除/滚动，不写“没有发生”。
- 时间线缺时区/时钟偏差且无法补齐 → 降级为“候选顺序”，不写因果。

## 12. 边界

- 只读：不挂载可写、不 `chkdsk`、不 `reg load` 原 hive、不在原件上跑程序。
- 不把 `fls` 的“存在”当“内容可恢复”；不把 `strings` 命中当“用户打开过”。
- 不绕过 BitLocker/EFS/账号权限；无密钥就写“加密不可读”，不伪造明文。
- 对外分享前脱敏路径中的用户名、SID、设备序列号、URL 查询参数。

> 相关：`01-criteria.md`、`02-failure-criteria.md`、`memory-forensics.md`、`ios-macos-artifacts.md`、`evidence-chain.md`。

## 13. 从采集到时间线的 8 步（磁盘专用）

| 步 | 动作 | 命令 | 门禁 |
| :-: | --- | --- | --- |
| 1 | 封存原件 | `sha256sum` + 只读 | 哈希入清单 |
| 2 | 识别容器 | `file`/`ewfinfo` | E01/dd/raw 分清 |
| 3 | 分区表 | `mmls` | Start 扇区可读 |
| 4 | 文件系统 | `fsstat -o <start>` | 类型/块大小/inode 范围 |
| 5 | 目录与 inode | `fls -r -p -o <start>` | 路径可遍历 |
| 6 | 时间线 | `fls -m` + `mactime -z UTC` | MACB 可排序 |
| 7 | 已删恢复 | `fls -d` + `icat` | 内容 magic/哈希 |
| 8 | 交叉 | 与 EVTX/USN/内存对齐 | 至少两源 |

**最容易错的两步**：第 4 步 `-o` 使用 `mmls` 给出的 Start 扇区（不是字节偏移）；第 8 步把文件 mtime 当“用户操作时间”（复制/安装也会改 mtime）。

### 13.1 文件系统差异（判据别混用）

| 文件系统 | 时间精度 | 已删恢复 | 常见坑 |
| --- | --- | --- | --- |
| NTFS | 100 ns | `$MFT`/`$UsnJrnl` 成功率高 | `$SI` vs `$FN` 两套时间 |
| FAT32 | 2 s | 目录项 + 簇链 | 时区/DST 偏移 |
| ext4 | ns | journal/inode | ext4 延迟分配 |
| APFS | ns | 快照/APFS 特性 | 加密卷需密钥 |
| HFS+ | s | catalog/extents | 与 APFS 混用 |

## 14. 命令与“通过长什么样”（磁盘最小复验）

```bash
IMG=evidence/disk.img; OFF=2048

# 1) 镜像与分区
sha256sum "$IMG"
mmls "$IMG" | head -10

# 2) 文件系统与目录
fsstat -o "$OFF" "$IMG" | head -12
fls -r -p -o "$OFF" "$IMG" | head -20

# 3) 时间线
fls -r -m / -o "$OFF" "$IMG" > out/bodyfile.txt
mactime -b out/bodyfile.txt -d -z UTC | head -15

# 4) 已删文件
fls -r -d -o "$OFF" "$IMG" | head -10
icat -o "$OFF" "$IMG" 12345 > out/recovered.bin && file out/recovered.bin
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| 分区 | `mmls` 有 Start/长度 | 只有“DOS partition”而无偏移 |
| 文件系统 | `fsstat` 出版本/块/inode | 报 bad magic → 核对 `-o` |
| 目录 | `fls` 有路径 + inode | 只有根目录 |
| 时间线 | `mactime` 有 UTC 时间列 | 本地时间未标 |
| 恢复 | `file` 识别出类型 | 乱码 → 标不可恢复 |

## 这一篇算"用对了"吗

- [ ] 我的 `-o` 用的是 `mmls` 的 Start 扇区，不是字节偏移
- [ ] 我能区分 `$SI`/`$FN` 两套时间，没有取“看起来合理”的那个
- [ ] 我的已删文件要么有内容哈希，要么明确标了“不可恢复”
- [ ] 我知道 mtime 不等于用户操作时间，至少与日志/USN 交叉一次
- [ ] 时间线统一 UTC 并保留原时区/精度
- [ ] 我没有在原镜像上挂载可写或跑 `chkdsk`
