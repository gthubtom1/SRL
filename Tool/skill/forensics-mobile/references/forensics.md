# 取证速查（内存 / 流量 / 磁盘）

> 配套 `forensics-mobile/SKILL.md`。仅在自有或明确授权的镜像上操作。
> 铁律：**原件只读、副本分析、全程哈希、时间统一 UTC**。下面所有命令假定当前目录为案例工作区，镜像文件名已替换为 `<image>`。

## 0. 工作区与基线

```bash
mkdir -p case/{evidence,work,export,report}
cp --reflink=auto <image> case/evidence/ 2>/dev/null || cp <image> case/evidence/
sha256sum case/evidence/* | tee case/evidence/SHA256SUMS
date -Is | tee case/run.start
vol.py --version; tshark -v | head -1; fls -V | head -1
```

- 记录采集人、采集时间、设备时区、UTC 偏移、镜像工具与版本。
- 原件放只读介质或 `chmod 444`；所有命令输出重定向到 `case/work/`，不覆盖原件。
- 先写“要回答的问题”，再决定采哪几类证据；问题变了要新增证据源，不要硬套旧结论。

## 1. 内存镜像（Volatility3）

### 1.1 识别与进程

```bash
vol.py -f mem.raw banners.Banners
vol.py -f mem.raw windows.info.Info
vol.py -f mem.raw windows.pslist.PsList
vol.py -f mem.raw windows.psscan.PsScan
vol.py -f mem.raw windows.pstree.PsTree
vol.py -f mem.raw windows.cmdline.CmdLine
```

- `pslist` 走活动链表，`psscan` 扫池标签；差集里的进程可能是已退出、隐藏或被 rootkit 摘链。
- 记录 PID、PPID、创建/退出时间、会话 ID、镜像路径；退出时间缺失不等于没运行。
- `cmdline` 为空可能是权限/页换出，不等于无参数；结合 `psscan` 与 `handles` 交叉验证。

### 1.2 注入与恶意页

```bash
vol.py -f mem.raw windows.malfind.Malfind
vol.py -f mem.raw windows.malfind.Malfind --pid <pid> --dump
vol.py -f mem.raw windows.dlllist.DllList --pid <pid>
vol.py -f mem.raw windows.handles.Handles --pid <pid>
```

- `malfind` 判据：`PAGE_EXECUTE_READWRITE`、无文件映射、页首为 `MZ`/ELF、含 shellcode 特征。
- 误报来源：JIT、.NET/CLR、浏览器沙箱、加壳程序；必须结合 `dlllist` 的路径与签名判断。
- dump 出的区域单独算哈希，用 `file`、`strings`、`objdump`/`ndisasm` 二次确认。

### 1.3 命令行、文件与网络

```bash
vol.py -f mem.raw windows.dumpfiles.DumpFiles --pid <pid>
vol.py -f mem.raw windows.netscan.NetScan
vol.py -f mem.raw windows.netstat.NetStat
vol.py -f mem.raw windows.registry.hivelist.HiveList
```

- `dumpfiles` 导出缓存文件后核对 `MZ`/PDF/ZIP 等 magic；内存里的文件可能被截断。
- 网络记录要写五元组、状态、所属进程与时间；仅见端口不能证明通信内容。
- Linux 用 `linux.pslist`/`linux.bash`/`linux.malfind`/`linux.proc.Maps`；macOS 用 `mac.pslist`/`mac.bash`/`mac.malfind`。
- 判据：进程、命令行、外联、落地文件四者能互相印证，且时间顺序不矛盾。

### 1.4 符号与降级

```bash
# Windows：确认版本后从符号服务器取 ISF
vol.py -f mem.raw windows.info.Info | grep -iE 'NTBuildLab|NtMajorVersion|NtMinorVersion'
# Linux：先看 banner，再取对应内核的符号
vol.py -f mem.raw banners.Banners
```

- 符号缺失时不要猜插件输出；降级到 `strings -el`、`bulk_extractor`、手工页表遍历只能作辅助。
- 崩溃转储（minidump）与全内存镜像插件不同；先 `file` 判断格式，再选工具。

## 2. 流量（pcap 会话重组与对象导出）

### 2.1 规模与概览

```bash
capinfos capture.pcap
tshark -r capture.pcap -q -z io,phs
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -Y 'http.request' -T fields -e frame.time_epoch -e ip.src -e http.host -e http.request.uri
```

- 先看包数、时长、平均速率；超过内存预算就切片：

```bash
editcap -c 200000 capture.pcap part.pcap
# 或按时间/主机过滤
tshark -r capture.pcap -Y 'ip.addr==10.0.0.5' -w host.pcap
```

### 2.2 会话重组

```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,7
tshark -r capture.pcap -Y 'tcp.stream eq 7' -T fields -e frame.time_epoch -e ip.src -e tcp.srcport -e tcp.len
```

- `tcp.stream` 编号在同一文件内稳定；切片后编号会变，报告里同时写五元组。
- 重组看双向流：请求行/头/体、响应码/头/体；压缩体（gzip/br）先解再读。
- TLS 只能看 SNI、证书、JA3/JA4 与包长时序；没有会话密钥不要声称看到明文。

### 2.3 对象导出与哈希

```bash
mkdir -p export/http
tshark -r capture.pcap --export-objects http,export/http
tshark -r capture.pcap --export-objects smb,export/smb 2>/dev/null
find export -type f -exec sha256sum {} + | tee export/SHA256SUMS
```

- 同名对象会加后缀；以 `frame.number`/`tcp.stream` 建索引，避免张冠李戴。
- 导出对象先 `file` 判型，再决定是否打开；恶意样本在隔离环境处理。
- 判据：能列出“谁在何时向谁请求了什么、返回了什么、落地文件哈希是多少”。

### 2.4 与其它证据对齐

- DNS/TLS SNI 的时间戳用于定位首次外联；HTTP 对象时间用于定位上传/下载完成点。
- 与内存 `netscan` 的套接字、磁盘浏览器的缓存文件交叉比对，三者一致才升为 `observed`。

## 3. 磁盘（分区 / 时间线 / 已删文件）

### 3.1 分区与文件系统

```bash
mmls disk.img
fsstat -o <start_sector> disk.img
fls -o <start_sector> disk.img
```

- `mmls` 的 Start 列是**扇区**；`-o` 传这个值。GPT 备份表在盘尾，别只看头部。
- `fsstat` 记录块大小、inode 范围、时间精度；FAT 的 2 秒精度会影响时间线结论。

### 3.2 时间线

```bash
fls -r -m "/" -o <start_sector> disk.img > bodyfile.txt
mactime -b bodyfile.txt -d -z UTC > timeline.csv
```

- `-m "/"` 给挂载点前缀，路径才完整；`-d` 输出 ISO 时间，`-z UTC` 统一时区。
- 时间线要标 MACB：Modified/Accessed/Changed/Birth；不同文件系统缺失项不同。
- 判据：能筛出“某时间段内被创建/修改/删除”的路径与 inode，并与内存/流量事件对齐。

### 3.3 已删文件与未分配空间

```bash
fls -r -p -o <start_sector> disk.img | grep -i deleted
icat -o <start_sector> disk.img <inode> > recovered.bin
tsk_recover -o <start_sector> disk.img recovered/
blkls -o <start_sector> disk.img > unallocated.blk
bulk_extractor -o bulk unallocated.blk
```

- `icat` 按 inode 取回；先 `file` 与哈希，再判断是否被覆盖/截断。
- `tsk_recover` 只恢复未删文件，不等于“全部已删”；已删靠 `fls (deleted)` 与 `icat`。
- HFS+/APFS 有扩展属性、克隆、快照；`fls` 看不到的，查 `fsstat` 与快照工具。
- 判据：恢复文件的内容、路径、时间三者能自洽，或被明确标为“部分恢复”。

### 3.4 完整性

- 每个导出文件算 SHA256；报告附 `SHA256SUMS` 与生成命令。
- 不在原件上挂载写模式；Linux 用 `mount -o ro,loop`，Windows 用只读挂载工具。

## 4. 证据链模板

```text
结论：<一句话，含主体/动作/对象>
时间：2026-10-20T03:14:22Z（设备本地 11:14:22 +08:00，时钟偏差 +3s）
来源：mem.raw（SHA256 ...），vol.py 3.x，windows.cmdline
证据：PID 4242，父 PID 1000，命令行 "powershell -enc ..."
佐证：pcap tcp.stream 7 在 03:14:25 向 10.0.0.9:443 发送 1.2MB
置信：observed（进程与命令行直接可见；外联内容未解密，内容部分为 inferred）
反证/缺口：未取得 TLS 明文；进程退出时间缺失
```

- 每条结论一段，按时间排序；`observed` 与 `inferred` 分开写。
- 第三方按“来源 + 命令 + 参数”能复现，才算证据链成立。
