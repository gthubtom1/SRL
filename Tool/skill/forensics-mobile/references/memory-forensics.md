# 内存取证：从镜像到“谁在何时做了什么”

> **适用**：Windows/Linux/macOS 的内存镜像、崩溃转储、休眠文件、虚拟机快照（`mem.raw`、`*.dmp`、`*.vmem`、`hiberfil.sys`）。
> **不适用**：没有采集记录的“网上下的内存样本”；未授权设备；把内存当唯一证据给恶意定性（需磁盘/流量/日志交叉）。
> 目标：把易失证据变成可复述的进程/网络/模块/注册表时间线，并明确哪些是 `observed`、哪些只是 `inferred`。

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

- `banners` 能给出 NT build/version；`windows.info` 的 `SystemTime` 与采集记录不差得离谱。
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
python3 vol.py -f mem.raw windows.dumpfiles.DumpFiles --pid 4242 --dump-dir out/dump
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

## 10. 失败判据

- `banners`/`windows.info` 两次换工具仍无法定版本 → 停，`blocked_at: symbols`。
- `pslist`/`psscan` 都空但镜像有系统字符串 → 可能截断/加密/格式不符，停，别写“没有进程”。
- 关键连接只有内存侧或只有 pcap 侧 → 结论降为 `inferred`，不写“已外联”。
- `malfind` 命中但无法 dump/二次识别 → 只写“候选页”，不写“注入成功”。
- 反作弊/内核保护在线环境 → 停止 attach/读内存，转外部观测。

## 11. 边界

- 只读：不写内存、不注入、不挂钩、不加载驱动；动态验证只在离线副本/授权测试机。
- 不把内存里的字符串当“用户看过/执行过”；没有进程/时间/路径就不算。
- 不绕过反作弊、不隐藏痕迹、不提供反取证手法。
- 内存结论必须与磁盘/流量/日志至少一个独立源交叉；否则标 `unverified`。

> 相关：`01-criteria.md`、`02-failure-criteria.md`、`03-model-pitfalls.md`、`disk-and-filesystem.md`、`evidence-chain.md`。
