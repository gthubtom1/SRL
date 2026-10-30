# 内存取证：从镜像到“谁在何时做了什么”

> **范围**：Windows/Linux/macOS 的内存镜像、崩溃转储、休眠文件、虚拟机快照（`mem.raw`、`*.dmp`、`*.vmem`、`hiberfil.sys`）。
> 前置：有采集记录的内存样本、授权设备、磁盘/流量/日志交叉证据；内存单独不足以做恶意定性。
> 目标：把易失证据变成可复述的进程/网络/模块/注册表时间线，并明确哪些是 `observed`、哪些只是 `inferred`。

`Tool/skill/forensics-mobile/scripts/forensics-check.py` 只做类型/哈希/文件时间与有限前缀标记初检，`hints` 是标记偏移，`extractables` 是后续清单，不是进程、模块、句柄或注入页解析。下文实体结论须由匹配格式、符号和插件的实际解析器取得。所有命令先核本机版本及插件 `--help`；minidump/core/完整物理镜像不能混用链路。真实内存可能含凭据，若工具不能在读取前限制到安全区域，仅接用户侧筛选的安全输出，不先全量 dump 再脱敏。

## 当前工具路线、采集与恢复

先用 `python Tool/skill/forensics-mobile/scripts/forensics-check.py --help` 核初检参数；`--self-test` 包含伪内存标记反例，只证明初检不会凭字符串产生实体。实体路线先运行本机 `vol --help`，从实际列表选 Windows info/pslist/psscan/dlllist/netscan 等插件，再核插件帮助；离线符号缺失时停止该层，不隐式下载，不安装工具或拿近似构建替代。MemProcFS 未发现时写通道缺失，不写已交叉验证。

用户侧安全采集应提供镜像格式/大小/采集时段/OS build/符号身份/工具版本、所用插件、退出码与安全实体表。允许输出 PID、PPID、进程创建时间、模块基址/路径别名、连接五元组和状态；命令行、环境、内存页与 registry 内容可能含秘密，不要求全量导出。没有可在采集前限定字段的通道时仅接预筛选安全输出。

正例：同一镜像的进程列表与扫描输出可按 PID+创建时间关联，模块属于该实体，再与独立 EVTX/磁盘时间线对齐；确认解析出的实体与关联范围。反例：伪造 KDBG/PID 字符串、缺符号、截断镜像、pslist 空表或同 PID 不同创建时间均不能证明进程存在/隐藏/不存在。pslist 与 psscan 同源，不算独立行为证据。

交付初检/实体解析/行为推断三层，逐层附原始安全输出、支持和反证。缺符号保存缺失标识、插件错误及未完成项，状态保持 blocked；恢复核同一 project/version/run 的镜像哈希和符号身份，变更镜像另开当前运行，不能混接旧实体。安全日志可交现有 `Tool/skill/forensics-mobile/scripts/fs-timeline.py`（先核 `--help`）；恶意判断交 `Tool/skill/malware-analysis/SKILL.md`，不由字符串初检代替。

## 1. 采集与封存

内存是第一优先级：断电/重启会丢失进程、连接、未落盘文件、注入页。

```bash
# 只读副本 + 哈希（采集端完成；分析端只碰副本）
sha256sum mem.raw | tee mem.raw.sha256
stat -c '%n %s %y' mem.raw
cp --reflink=auto mem.raw /evidence/copy/mem.raw   # 或 dd 只读

# 记录：采集人/时间/主机名/OS build/时区/工具/授权范围
```

最小采集记录字段：`host`、`os_build`、`capture_start_utc`、`capture_end_utc`、`operator`、`method`（live/agent/crash/hypervisor）、`timezone`、`clock_skew`、`sha256`、`size`。

## 2. 先定版本，再选符号

```bash
python3 vol.py -f mem.raw banners.Banners
python3 vol.py -f mem.raw windows.info.Info        # KDBG、系统时间、架构
python3 vol.py -f mem.raw windows.pslist.PsList
python3 vol.py -f mem.raw windows.psscan.PsScan
```

判据：

- Windows 以实际支持的 `windows.info`、layer/符号信息核系统构建、架构与采集时间；`banners` 主要用于 Linux/macOS 内核 banner，不保证返回 Windows NT build。
- `pslist` 与 `psscan` 都能跑；两者 PID 差集是“隐藏/已退出”的候选，不是定罪。
- 符号缺失时先定 build，再取对应 ISF；不要拿相近版本硬跑。

## 3. 进程、命令行、父子关系

```bash
python3 vol.py -f mem.raw windows.pslist.PsList > out/pslist.txt
python3 vol.py -f mem.raw windows.psscan.PsScan > out/psscan.txt
python3 vol.py -f mem.raw windows.cmdline.CmdLine > out/cmdline.txt
python3 vol.py -f mem.raw windows.getsids.GetSIDs > out/sids.txt
python3 vol.py -f mem.raw windows.dlllist.DllList --pid 4242 > out/dll-4242.txt
```

把三张表按 PID 合并：

| 字段 | 来源 | 用途 |
|---|---|---|
| PID/PPID | `pslist`/`psscan` | 进程树、孤儿进程 |
| ImageFileName | `pslist` | 路径与伪装名（`svch0st.exe`） |
| CreateTime/ExitTime | `pslist` | 起止时间；ExitTime 缺失只说明“未正常退出” |
| CommandLine | `cmdline` | 参数、临时目录、编码命令 |
| SID/User | `getsids` | 主体归因 |
| Modules | `dlllist` | 未签名/异常路径 DLL |

判据：能回答“哪个 PID、以哪个用户、在什么时间、用什么命令行启动；加载了哪些模块”。缺 CommandLine 时标 `inferred`，不要用文件名猜。

## 4. 网络连接与监听

```bash
python3 vol.py -f mem.raw windows.netscan.NetScan > out/netscan.txt
python3 vol.py -f mem.raw windows.netstat.NetStat > out/netstat.txt
```

- `netscan` 能给出 `Proto/LocalAddr/ForeignAddr/State/PID/Owner/Created`；`netstat` 是另一种扫描路径，二者差集可提示连接被隐藏。
- 与 pcap 对齐：同一五元组在内存里应有 PID/时间，在 pcap 里应有首末包；只有一侧就标 `unverified`。
- 外联结论必须落到“PID + 时间 + 五元组 + 进程路径”，不能只写“发现 C2 IP”。

## 5. 注入、隐藏与可执行页

```bash
python3 vol.py -f mem.raw windows.malfind.Malfind > out/malfind.txt
python3 vol.py -f mem.raw windows.hollowprocesses.HollowProcesses
python3 vol.py -f mem.raw -o out/dump windows.dumpfiles.DumpFiles --pid 4242
```

判据：

- `malfind` 页有 `MZ`/ELF 头、权限含 `R-X`/`RWX`、所属 PID 与模块路径不符 → 候选。
- 浏览器/JIT/打包器/汉化补丁也会产生可执行私有页；必须结合签名、命令行、网络、磁盘落地文件排除。
- dump 出的文件要单独算 SHA256，并用 `file`/`rabin2`/`strings` 二次识别；能复现才算证据。

## 6. 注册表与持久化（内存中的 hive）

```bash
python3 vol.py -f mem.raw windows.registry.hivelist.HiveList
python3 vol.py -f mem.raw windows.registry.printkey.PrintKey --key 'Software\Microsoft\Windows\CurrentVersion\Run'
python3 vol.py -f mem.raw windows.registry.userassist.UserAssist
```

- 内存 hive 可能比磁盘 hive 新（未落盘），也可能只是缓存；必须与磁盘 hive 的 last-write 对比。
- `Run`/`RunOnce`/服务/计划任务/IFEO/Winlogon 是持久化面；写“某键存在”不够，要写“哪个进程在何时写入/读取”。
- 内存 hive 未落盘时，`dumpfiles` 或 `hivedump` 导出后再用离线 REGF 解析（见 `disk-and-filesystem.md`）。

## 7. Linux / macOS

```bash
python3 vol.py -f linux.mem linux.pslist.PsList
python3 vol.py -f linux.mem linux.bash.Bash
python3 vol.py -f linux.mem linux.malfind.Malfind
python3 vol.py -f mac.mem mac.pslist.PsList
python3 vol.py -f mac.mem mac.bash.Bash
python3 vol.py -f mac.mem mac.malfind.Malfind
```

- Linux 关注 `bash` 历史、`elfs`、`lsmod`、`sockstat`；macOS 关注 `kevents`、`ifconfig`、`mount`、`trustedbsd`。
- 符号/内核版本不匹配时输出会空；先 `banners`，再取 ISF/dSYM。
- 容器/云主机的内存镜像可能只含宿主机视角；容器内进程需结合 cgroup/namespace 证据。

## 8. 时间线归一

把内存事件写成统一字段：

```json
{"time_utc":"2026-10-20T03:14:07Z","actor":"PID 4242 (updater.exe)",
 "action":"TCP connect","object":"203.0.113.9:443",
 "confidence":"observed","evidence_refs":["mem.raw#pid=4242","capture.pcap#tcp.stream=7"],
 "command":"vol.py -f mem.raw windows.netscan.NetScan"}
```

- 时间来源：进程 CreateTime、连接 Created、文件对象时间、注册表 last-write；都转 UTC。
- 精度：Windows FILETIME 100ns，但插件输出可能截断到秒；不要伪造更高精度。
- 时钟偏差：内存里的 `SystemTime`、主机日志、采集机时间三者不一致时，写偏移范围，不强行对齐。

## 9. Linux 取证：auditd / journald / 进程与包管理

Linux 上“谁在何时做了什么”靠三源对照：内核审计（auditd）、systemd 日志（journald）、`/proc` 活体快照。

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
ausearch -i -m EXECVE -ts 2026-10-20 03:00:00 | head -80      # argv 全量
aureport -x --summary                                        # 被执行程序排行
journalctl --since "2026-10-20 03:00" -o json | head -3       # 结构化字段
journalctl _PID=4242 -o json | jq '{t:.__REALTIME_TIMESTAMP,u:._UID,c:._COMM}'
ls -l /proc/*/exe 2>/dev/null | grep deleted                  # 已删但仍在跑
tr '\0' ' ' </proc/4242/cmdline; ls -l /proc/4242/cwd /proc/4242/root
ss -lntp; ss -tnp state established                           # 套接字 → pid
```

- `ausearch -m EXECVE` 只给 `argc`/`a0..aN`；主体在同一个 audit event 的 `SYSCALL` 记录里：`auid`/`uid`/`pid`/`comm`/`exe`/`ppid`。`auid=4294967295`（unset）表示审计未随登录会话，不能当真实用户。
- `journalctl` 结构化字段：`_PID`、`_UID`、`_COMM`、`_EXE`、`_SYSTEMD_UNIT`、`_BOOT_ID`、`_TRANSPORT`；先确认存储路径：`/run/log/journal` 易失，`/var/log/journal` 持久。`journalctl --verify` 看 FSS 封印是否断裂。
- `/proc/<pid>/exe` 带 `(deleted)`：二进制已删但进程在跑（升级/藏匿常见形态）；`/proc/<pid>/root`、`/proc/<pid>/mountinfo` 是容器边界的入口。
- 包管理面：`/var/log/dpkg.log`、`/var/log/apt/history.log`、`rpm -qa --last`、`dnf history`；完整性用 `dpkg -V`/`rpm -Va`（行首 `5` = 内容摘要变更）。包安装时间与文件 mtime 交叉可判“二进制是否被替换”。
- 容器内取证：宿主读 `/proc/<pid>/mountinfo` 的 `upperdir=`（overlay 可写层），`nsenter -t <pid> -m -p` 后只读观察；容器内 `journalctl` 可能直通宿主或完全不写，先确认 `/run/systemd/journal` 是否挂载。
- 时间源对齐：audit 用 `time=`（epoch 秒）、journal 用 `__REALTIME_TIMESTAMP`（µs epoch）、`/proc` 只能靠文件 mtime 与 `/proc/uptime`+boot time 反推。三者精度不同，产物里写 `ts_basis`，不要拉平成同一精度。
- 补充源：`last -F`/`wtmp`（登录会话，对应 `auid`）、`/var/log/auth.log`、`~/.bash_history`（有 `HISTTIMEFORMAT` 才有时间）；它们能补 `auid` 归属，但都可被编辑，不能单独立论。
- 采集顺序：先整盘 `dd`/`acquire`（`/proc`、`/run` 在内存盘上，一重启就没），再做 `/proc` 与 `ss` 快照；采集记录要写 `order` 与每步 UTC 时间。

**判据**：四要素齐全——`time_utc`（audit `time=` / journal `__REALTIME_TIMESTAMP` 转 UTC）、`actor`（`auid|uid` + `pid` + `comm`，或 `_UID` + `_PID`）、`action`（`type=EXECVE|SYSCALL`）、`object`（`exe` 路径 / `a0..aN` / 套接字）。`ss -lntp` 的 pid 要与 `/proc/<pid>/exe` 对上。

**失败判据**：`auditctl -l` 为空 → 写“无审计面”（`blocked_at: audit-off`），不写“没执行”；`auid=unset` 却写成具体用户 → 降为 `inferred`；日志只在 `/run` 且已重启 → 标“不跨重启”；`/proc` 与 `ss` 的 pid 不一致（namespace 视角差异）→ 写“命名空间不同视图”，不写“套接字归属不明”。

## 10. MemProcFS / Volatility 3 的版本与交叉核验

本参考不把未经当前环境核实的发行版本、系统支持表或插件名当作工具基线。记录实际程序版本、帮助输出、镜像格式、系统构建与符号来源；按帮助列出的插件/虚拟文件路径选择实体解析。命令形态与版本差异见 `Tool/skill/malware-analysis/subskills/memory-forensics/SKILL.md`。

MemProcFS 的设备、挂载位置与取证输出参数按当前程序帮助核验，挂载动作只在获准测试环境进行，不执行或写入镜像内文件。Volatility 的输出目录属于全局选项，置于插件名之前；`windows.heap`、`windows.eventlog`、`windows.hollowprocesses` 等名称不能假定每版都提供，未列出就记不支持并选择现有替代，不把命令失败归因于目标保护。

| 需要回答的问题 | 必须记录的实际证据 | 不足时如何报告 |
|---|---|---|
| 进程/模块/句柄归属 | 实际插件、PID/创建时间、模块映射、句柄表及镜像哈希 | 插件或格式不支持则未知，不用初检字符串补字段 |
| 内存日志/hive/堆 | 当前工具实际支持的路径/插件与解析输出 | 未支持、缺页与解析失败分开，不要求虚构同名字段 |
| 两工具差异 | 同镜像、时刻、对象身份与关键字段的交集/差集 | 差集保留并解释；单一解析器的直接观察不因未跑第二工具而自动消失 |

空输出不能证明无实体或日志已清除；差异可能来自采集时刻、符号、残留对象或解析覆盖。无匹配符号/插件时停止深度结论，列出可恢复条件；只有已证支持条件不满足时才建议具体版本适配，不按未经核实的版本号强制升级。

## 11. 失败判据

- `banners`/`windows.info` 两次换工具仍无法定版本 → 停，`blocked_at: symbols`。
- `pslist`/`psscan` 都空但镜像有系统字符串 → 可能截断/加密/格式不符，停，别写“没有进程”。
- 关键连接只有内存侧或只有 pcap 侧 → 结论降为 `inferred`，不写“已外联”。
- `malfind` 命中但无法 dump/二次识别 → 只写“候选页”，不写“注入成功”。
- 反作弊/内核保护在线环境 → 停止 attach/读内存，转外部观测。

## 12. 边界

- 只读：不写内存、不注入、不挂钩、不加载驱动；动态验证只在离线副本/授权测试机。
- 不把内存里的字符串当“用户看过/执行过”；没有进程/时间/路径就不算。
- 只做只读内存取证：进程/网络/模块/注入页 + 哈希；产物按 `evidence-chain.md` 留痕。
- 内存结论必须与磁盘/流量/日志至少一个独立源交叉；否则标 `unverified`。

> 相关：`01-criteria.md`、`02-failure-criteria.md`、`03-model-pitfalls.md`、`disk-and-filesystem.md`、`evidence-chain.md`。

## 13. 内存镜像取证走查：十步到时间线

| 步 | 动作 | 命令 | 门禁 |
| :-: | --- | --- | --- |
| 1 | 哈希/大小/采集记录 | `sha256sum mem.raw` | 哈希 + 时间 + 主机名 |
| 2 | 定版本 | Windows 用实际 `windows.info`；Linux/macOS 依格式核 banner/符号 | build/架构可读 |
| 3 | 进程 | `pslist` + `psscan` | 两者都能跑 |
| 4 | 差集 | `comm`/`jq` 比 PID | 每个差集有解释 |
| 5 | 命令行/用户 | `cmdline` + `getsids` | 主体可指认 |
| 6 | 网络 | `netscan` + `netstat` | 五元组 + PID + 时间 |
| 7 | 注入 | `malfind` + dump | 页可二次识别 |
| 8 | 持久化 | `hivelist` + `printkey` | 键 + 值 + 时间 |
| 9 | 交叉 | pcap/磁盘/EVTX | 至少两源 |
| 10 | 时间线 | JSON 统一字段 | 四要素齐全 |

**最容易漏的是第 4 步**：只跑 `pslist` 会漏掉已退出/隐藏进程；只跑 `psscan` 会把已退出进程当“正在运行”。

### 13.1 差集解释模板

```text
PID 4242：pslist 无 / psscan 有 → 已退出或链表被摘；CreateTime=…，ExitTime=…
PID 5150：两者都有，但 cmdline 为空 → 可能权限/结构问题；标 inferred
PID 6262：pslist 有 / psscan 无 → 采集时刚创建，池扫描未覆盖；标 observed-partial
```

**判据**：每个差集 PID 都有“为什么不在另一张表”的解释；没有解释就写“未归因”。

## 14. 命令与“通过长什么样”（内存最小复验）

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
MEM=evidence/mem.raw
python3 vol.py -f "$MEM" banners.Banners
python3 vol.py -f "$MEM" windows.pslist.PsList > out/pslist.txt
python3 vol.py -f "$MEM" windows.psscan.PsScan > out/psscan.txt
python3 vol.py -f "$MEM" windows.netscan.NetScan > out/netscan.txt

# 差集（按 PID 第一列；实际列位以输出为准）
comm -3 <(sort -n out/pslist.txt | awk 'NR>2{print $1}') \
         <(sort -n out/psscan.txt | awk 'NR>2{print $1}') | head

# 两工具交叉（若装了 MemProcFS）
memprocfs -device "$MEM" -mount /mnt/mem 2>/dev/null && ls /mnt/mem/sys/proc | head
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| 版本 | `banners` 出版本 | 报符号缺失 |
| 进程 | 两张表都有输出 | 一张空 → 解释或降级 |
| 差集 | 每个 PID 有解释 | 直接写“隐藏进程” |
| 网络 | 五元组 + PID + 时间 | 只有 IP |
| 注入 | dump 文件 `file` 可识别 | 只有 `malfind` 行 |
| 交叉 | pcap/磁盘至少一源 | 单源 → `unverified` |

## 这一篇算"用对了"吗

- [ ] 我先定版本再选符号，没有拿相近 profile 硬跑
- [ ] 我跑了 `pslist` 与 `psscan`，并对差集逐 PID 解释
- [ ] 我的外联结论能落到 PID + 时间 + 五元组，不是只写 IP
- [ ] `malfind` 命中后我做了 dump + 二次识别，没有直接写“注入”
- [ ] 内存结论至少与 pcap/磁盘/EVTX 之一交叉
- [ ] 我没有把内存里的字符串当“用户看过/执行过”
