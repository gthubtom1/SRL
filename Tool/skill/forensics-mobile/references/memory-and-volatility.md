# 内存镜像与 Volatility3

> 配套 `forensics-mobile/SKILL.md` 的 §A1。目标：**从内存镜像还原进程、网络、注入页与时间线，并给出可复现命令**。
> 只在自有或明确授权的镜像上操作；先复制、算哈希，再分析。

## 1. 识别镜像与符号

```bash
file mem.raw
ls -lh mem.raw
sha256sum mem.raw | tee mem.sha256
python3 vol.py -f mem.raw banners.Banners
python3 vol.py -f mem.raw windows.info.Info
```

- `banners.Banners` 先定 OS/版本/架构；Windows 还要看 KDBG、系统时间、页面大小。
- 符号不匹配会全盘失败：Windows 用对应 ISF，Linux 用对应内核版本，macOS 用 dSYM。
- 记录镜像大小、采集方式（裸内存/崩溃转储/休眠文件/虚拟机快照）、是否截断。
- 原始内存可能是 `raw`/`vmem`/`dmp`/`hiberfil.sys`/`vmss`；不同格式支持的插件不同。

**判据**：`banners` 与 `info` 能给出 OS、版本、架构、系统时间；符号加载成功。

## 2. 进程与命令行

```bash
python3 vol.py -f mem.raw windows.pslist.PsList
python3 vol.py -f mem.raw windows.psscan.PsScan
python3 vol.py -f mem.raw windows.pstree.PsTree
python3 vol.py -f mem.raw windows.cmdline.CmdLine
python3 vol.py -f mem.raw windows.getsids.GetSIDs
```

- `pslist` 走活动链表；`psscan` 扫池标签。差集里的进程可能是已退出、隐藏或被 rootkit 摘链。
- 记录 PID、PPID、创建/退出时间、会话、镜像路径、SID；退出时间缺失不等于没运行。
- `cmdline` 为空可能是权限/换出，不等于无参数；与 `psscan`、`handles` 交叉。
- 父子关系异常（`winword.exe` 拉起 `powershell.exe`）是线索，不是定罪；要结合命令行与网络。

**判据**：能列出进程起止时间、父子关系、命令行、用户，并对差集给出解释或标 `unverified`。

## 3. 网络与外联

```bash
python3 vol.py -f mem.raw windows.netscan.NetScan
python3 vol.py -f mem.raw windows.netstat.NetStat
```

- 记录五元组、状态、所属 PID、创建时间；与 pcap/防火墙日志对齐。
- `netscan` 能扫到已关闭/残留连接；`netstat` 依赖内核结构，二者互补。
- 外联时间与 DNS/TLS SNI 对齐时注意时钟偏差与 NAT。

**判据**：每个可疑外联能落到 PID + 进程路径 + 时间 + 对端；缺一项标 `inferred`。

## 4. 注入与恶意页

```bash
python3 vol.py -f mem.raw windows.malfind.Malfind
python3 vol.py -f mem.raw windows.vadinfo.VadInfo --pid <pid>
python3 vol.py -f mem.raw windows.dlldump.DllDump --pid <pid> --base <base>
python3 vol.py -f mem.raw windows.dumpfiles.DumpFiles --pid <pid>
```

- `malfind` 看 `PAGE_EXECUTE_READWRITE`、无文件映射、`MZ`/ELF 头；可疑页 dump 后单独哈希与二次分析。
- `vadinfo` 看 VAD 权限/类型/私有内存；`dlllist` 看未签名/路径异常模块。
- 反射注入/DLL 侧加载/进程镂空常表现为“私有可执行内存 + 无对应文件”。
- dump 出的页可能是压缩/加密载荷；先 `file`/`strings`/熵，再决定是否反编译。

**判据**：可疑页有 PID、基址、权限、大小、dump 文件哈希，并能与进程/网络/磁盘证据关联。

## 5. 注册表、服务与持久化

```bash
python3 vol.py -f mem.raw windows.registry.hivelist.HiveList
python3 vol.py -f mem.raw windows.registry.printkey.PrintKey --key "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
python3 vol.py -f mem.raw windows.svcscan.SvcScan
python3 vol.py -f mem.raw windows.scheduled_tasks.ScheduledTasks 2>/dev/null
```

- 持久化点：Run/RunOnce、服务、计划任务、WMI 订阅、启动文件夹、IFEO、AppInit_DLLs。
- 注册表项要记录最后写入时间（如可取得）与所属 hive；内存中的 hive 可能未落盘。
- 服务看二进制路径、启动类型、运行账户；路径带空格/引号异常是线索。

**判据**：能说明“重启后如何继续存在”，并给出注册表键/服务名/任务路径。

## 6. Linux / macOS 速查

```bash
python3 vol.py -f mem.raw linux.pslist.PsList
python3 vol.py -f mem.raw linux.bash.Bash
python3 vol.py -f mem.raw linux.malfind.Malfind
python3 vol.py -f mem.raw mac.pslist.PsList
python3 vol.py -f mem.raw mac.bash.Bash
python3 vol.py -f mem.raw mac.malfind.Malfind
```

- Linux 注意内核版本与符号；`linux.bash` 可恢复命令历史，`linux.malfind` 看可执行匿名映射。
- macOS 注意 SIP/签名、`launchd`、`LaunchAgents/Daemons`、Keychain 访问。
- 跨平台结论不要互套插件名；先确认 profile。

**判据**：平台/内核/符号匹配，命令与输出路径可复现。

## 7. 失败判据与降级

- `banners`/`info` 两次失败或符号不匹配 → 停，先解决 profile；不要盲跑插件。
- 镜像截断/格式不支持 → 标“不完整”，只做字符串/ carve，不写进程结论。
- `pslist` 与 `psscan` 差集无法解释 → 标 `unverified`，不直接写“隐藏进程”。
- `malfind` 命中但 dump 失败 → 记录页表/权限证据，改用外部只读工具，不反复 attach。
- 触发反作弊/内核保护/蓝屏 → 立即停，转离线副本或外部观测。
- 无符号/无工具时降级：`strings` + `bulk_extractor` + 崩溃转储解析；报告标注“降级 + 验证程度”。

> 关联：`references/forensics.md`（内存/流量/磁盘命令）、`references/evidence-chain.md`（哈希/时间线/四要素）。
