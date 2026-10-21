---
name: forensics-mobile
description: 【取证 / iOS·macOS / 游戏客户端】内存镜像、pcap 流量、磁盘镜像的事件还原与证据链，iOS `.ipa`/Mach-O/Keychain/plist/数据库与 Frida attach，Unity Mono/IL2CPP/AssetBundle/进程内存的客户端取证。以“能还原谁在什么时候做了什么、能说明二进制与数据的关系”为硬判据，覆盖 Volatility3/tshark/sleuthkit/otool/codesign 与只读观测边界，并给出缺工具时的降级路线。
license: MIT
compatibility: Linux/WSL2 优先（volatility3、tshark、sleuthkit 原生）；macOS 提供 otool/codesign/security；iOS 动态侧需授权测试机与 frida-server；Windows 可经 Tool/scripts/tool-run.ps1 启动外部工具。
metadata: {version: "1.0.0", category: forensics-mobile, hard_gates: "授权与来源 / 只读副本+哈希 / 统一时间基准 / 证据链可复述"}
---

# forensics-mobile — 取证 / iOS·macOS / 游戏客户端

> 只回答一件事：**这份内存、流量、磁盘或客户端，能不能还原出「谁在什么时候做了什么」，且第三方能按同样命令复述。**
> “看到可疑字符串”不是结论；结论必须带来源、时间、主体、动作与哈希。仅对自有或明确授权的镜像、设备、客户端操作。

## 〇、范围与前置门

- **在范围内**：内存/崩溃转储、pcap、磁盘与分区镜像；iOS/macOS 应用包；Unity 客户端。
- **不在范围内**：Android APK/DEX/SO（走 `apkseep`）；客户端授权旁路（走 `01`–`05`）；未授权设备与账号。

1. **授权与来源**：镜像/抓包/设备归属明确，采集时间、采集人、采集方式已记录。
2. **只读副本**：原件只读保存，分析全在副本；`sha256sum` 与大小写入案例。
3. **时间基准**：记录采集端/设备时区、UTC 偏移与时钟偏差；时间线统一 UTC 并保留原值。
4. **问题一句话**：先写可判定的目标（“还原 03:14 谁从哪台主机读取了哪个文件”），再选证据源。

> 采集顺序：内存 → 网络 → 磁盘。断电/重启会毁掉易失证据；磁盘镜像最后做，避免写入。

## A. 取证：内存 / 流量 / 磁盘

### A1 内存镜像（Volatility3）

```bash
python3 vol.py -f mem.raw windows.info.Info            # 版本、架构、KDBG、系统时间
python3 vol.py -f mem.raw windows.pslist.PsList        # 活动进程树
python3 vol.py -f mem.raw windows.psscan.PsScan        # 含已退出/隐藏进程
python3 vol.py -f mem.raw windows.cmdline.CmdLine      # 命令行参数
python3 vol.py -f mem.raw windows.malfind.Malfind      # 可疑可执行内存页
python3 vol.py -f mem.raw windows.dumpfiles.DumpFiles --pid <pid>
```

- Linux：`linux.pslist`/`linux.bash`/`linux.malfind`；macOS：`mac.pslist`/`mac.bash`/`mac.malfind`；符号缺失先 `banners.Banners` 定版本再取 ISF/dSYM。`pslist` 与 `psscan` 差集、`malfind` 页的 `MZ`/ELF 头、`cmdline` 与父进程不符，是“隐藏/注入”候选，不是定罪。
- 判据：能列出进程起止时间、父子关系、命令行、外联五元组，并把可疑页 dump 成可二次分析的文件。

### A2 流量（pcap 会话重组与对象导出）

```bash
capinfos capture.pcap
tshark -r capture.pcap -q -z conv,tcp
tshark -r capture.pcap -Y "tcp.stream eq 7" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.len
tshark -r capture.pcap --export-objects http,export/http
tshark -r capture.pcap -Y "dns || tls.handshake.extensions_server_name" -T fields -e frame.time_epoch -e dns.qry.name -e tls.handshake.extensions_server_name
```

- 大包先 `editcap -c 200000` 切片或按 `-Y` 过滤再重组；会话重组看**双向字节流**，不能只看单包；HTTP 对象导出后逐个算哈希，同名文件以 `tcp.stream` 建索引。
- 判据：能给出会话起止时间、双方、协议、请求/响应关键字段、导出对象 SHA256，并与内存/磁盘时间线对齐。

### A3 磁盘（分区 / 时间线 / 已删文件）

```bash
mmls disk.img                                   # 分区表与扇区偏移
fsstat -o 2048 disk.img                         # 文件系统类型、块大小、inode 范围
fls -r -p -o 2048 disk.img > fls.txt            # 递归目录项（含 deleted 标记）
fls -r -m "/" -o 2048 disk.img > bodyfile.txt   # 供 mactime 使用
mactime -b bodyfile.txt -d -z UTC > timeline.csv
icat -o 2048 disk.img <inode> > recovered.bin   # 按 inode 取回内容
tsk_recover -o 2048 disk.img recovered/         # 批量恢复未删文件
```

- `-o` 是**扇区偏移**，来自 `mmls` 的 Start 列，偏移错会得到“文件系统损坏”的假象；已删文件看 `fls` 的 `(deleted)` 与 inode 复用，`icat` 取回后核对 magic/哈希，未分配空间用 `blkls`+`bulk_extractor` 找残余。
- 判据：时间线能定位具体 inode/路径/操作（创建、修改、访问、重命名），并能用 `icat` 复现文件内容。

### A4 证据链四要素

证据链四要素：**时间**（UTC + 原时区 + 时钟偏差）、**主体**（用户/进程/设备/账号，含 SID/UID/Bundle ID）、**动作**（读取/写入/外联/执行/删除，含命令或协议）、**对象**（路径/inode/URL/五元组/注册表键，含哈希）。
每条结论标 `observed`/`inferred`/`unverified`；时间线冲突先查时区、NTP、文件系统精度（FAT 2s、APFS 纳秒）与采集顺序，不掩盖矛盾。

## B. iOS / macOS

### B1 `.ipa` 解包

```bash
unzip -q app.ipa -d ipa/
plutil -p ipa/Payload/App.app/Info.plist
codesign -d --entitlements :- ipa/Payload/App.app
unzip -p app.ipa 'Payload/*.app/embedded.mobileprovision' | strings | head
```

- 关注 `Frameworks/`、`PlugIns/`、`Assets.car`、`*.momd`、`*.sqlite`；`Info.plist` 的 URL Scheme、ATS、`UIBackgroundModes` 是行为与网络入口。判据：目录树、签名与 entitlements、权限声明、内嵌框架清单齐全，能回答“这个包会碰哪些数据与能力”。

### B2 Mach-O 分析

```bash
file AppBinary
otool -hv AppBinary                 # 头、CPU、PIE/栈保护标志
otool -l AppBinary | grep -A6 LC_ENCRYPTION_INFO
otool -L AppBinary                  # 依赖库与 @rpath
nm -m AppBinary | head -50          # 符号与可见性
codesign -dv --verbose=4 AppBinary  # 签名、Team ID、CDHash
```

- `cryptid 1` = App Store 加密，静态分析前需在**授权测试机**脱壳；未脱壳的 `otool`/`strings` 不可信。记录 `LC_UUID`、`LC_BUILD_VERSION`、架构切片（arm64/arm64e）。判据：能说明二进制加载了哪些库、调用了哪些敏感 API、与哪个数据文件/网络端点对应。

### B3 越狱检测与绕过的取证视角

- 常见检测面：`/Applications/Cydia.app`、`/var/jb`、`/bin/bash`、`sshd`、`cydia://`、`fork`/`posix_spawn`、`sysctl`、`dyld` 镜像名、沙盒外可写、`DYLD_INSERT_LIBRARIES`。
- 记录三件事：**检测点在哪**（类/方法/字符串/路径）、**设备状态**（越狱/注入）、**检测结果**（真假及 UI/网络行为）。
- 绕过只作为“验证检测点”的实验，在自有测试机、离线账号进行；记录基线与副作用，不得用于规避反作弊、绕过授权或隐藏痕迹。
- 判据：指出每个检测实现的位置与证据，说明绕过改变了哪条控制流，而不是只说“过了检测”。

### B4 Keychain / plist / 数据库

```bash
security dump-keychain -d login.keychain-db | head -100          # macOS 授权账户
plutil -p Library/Preferences/com.example.app.plist
python3 -c "import plistlib;print(plistlib.load(open('x.plist','rb')))"
sqlite3 app.db '.tables'
sqlite3 app.db 'PRAGMA integrity_check; SELECT * FROM sqlite_master;'
sqlite3 app.db '.recover' | head -50
```

- iOS Keychain 在 `keychain-2.db`，受保护类密钥保护；无授权测试机只做结构与元数据说明，不伪造明文。SQLite 必看 `-wal`/`-shm`/`-journal`，已删记录常残留，先复制三件套再打开；plist 有二进制/XML 两种，`NSKeyedArchiver` 需先解归档。
- 判据：能说明数据由哪个进程/API 写入、存在哪个文件、保留多久（数据保护等级/备份策略）。

### B5 Frida 在 iOS 上的 attach

```bash
frida-ps -Uai
frida -U -f com.example.app -l hook.js --no-pause
frida-trace -U -f com.example.app -m "-[NSURLSession dataTaskWithRequest:*]"
```

- 先确认 `frida-server` 架构/版本与 iOS 匹配；attach 失败先查签名、端口、进程是否被看门狗重启。只读优先，写内存/改返回值只用于验证检测点并记录。
- 判据：把“二进制函数 → 运行时参数/返回值 → 落盘文件/网络请求”连成一条链。

## C. 游戏客户端

### C1 Unity Mono（`Assembly-CSharp.dll`）

```bash
find App.app -name 'Assembly-CSharp.dll' -o -name 'globalgamemanagers'
ilspycmd Assembly-CSharp.dll -o decompiled/
monodis --assembly Assembly-CSharp.dll
```

- `Managed/` 下缺 `Assembly-CSharp.dll` 通常意味着 IL2CPP；同目录的 `UnityEngine.*.dll`/`mscorlib.dll` 用于补依赖。
- 判据：定位数值/协议/存档字段对应的类与方法，并与配置或网络包字段对上。

### C2 IL2CPP（`global-metadata.dat`）

```bash
Il2CppDumper GameAssembly.dll global-metadata.dat out/
ls out/   # dump.cs、il2cpp.h、script.json、stringliteral.json、DummyDll/
```

- 元数据版本必须与 `GameAssembly`/`UnityFramework` 匹配；不符先取对应 Unity 版本或换 Cpp2IL。
- `script.json` 给函数地址，`stringliteral.json` 给字面量；配合 IDA/Ghidra 的 `il2cpp.h` 落地址。
- 判据：把 `dump.cs` 的字段/方法与二进制地址、运行时内存值三者对齐。

### C3 资源包（AssetBundle）

```bash
xxd -l 64 bundle | head        # 期望 UnityFS/UnityWeb/UnityRaw
AssetStudioModCLI bundle -o export/
# 或 AssetRipper / UnityPy
```

- 先看头部与 Unity 版本；加密/自定义压缩的包直接解析是乱码，需从二进制找 key/算法，找不到如实标“未解”。
- 导出后核对 `CAB-*`、Texture2D、TextAsset、AudioClip、Mesh 与 `manifest` 的对应关系。
- 判据：说明资源属于哪个 bundle、被谁引用、运行时如何加载。

### C4 进程内存特征

- 离线：对自有进程做 minidump/`gcore`，按模块基址 + 偏移定位字段；记录模块哈希与偏移来源。
- 在线只读：`Process.enumerateModules()`、`Memory.scan()` 读已知特征（金币数、等级、token 前缀），**不写、不挂钩、不注入**。
- 判据：数值链路完整——服务器下发 → 客户端字段 → 内存偏移 → 显示/上报；缺一环标 `inferred`。

### C5 反作弊存在时的“只读观测”边界

- 识别 EAC、BattlEye、Vanguard、mhyprot 等内核态/用户态组件；先看进程、驱动、服务与启动参数。
- **在线环境只做外部观测**：抓包、日志、公开客户端文件、录屏；不 attach、不注入、不读进程内存、不调试。
- 动态分析用**离线副本/私服/授权测试服**，报告写明环境差异；不把离线结论当线上结论。判据：动作可审计，可能触发反作弊就停止并记录原因。

## D. 工具与降级

| 能力 | 首选 | 降级链 |
|---|---|---|
| 内存镜像 | `volatility3` | Rekall、`strings`+`bulk_extractor`、崩溃转储解析 |
| 流量 | `tshark` | `tcpdump`、Zeek、Scapy、`tcpflow` |
| 磁盘 | `sleuthkit` | Autopsy、`dd`+`foremost`/`photorec`、`debugfs` |
| Mach-O | `otool`、`nm`、`codesign` | `llvm-objdump`、`rabin2`、`jtool2`、`ldid` |
| iOS 动态 | `frida` | `lldb`、Xcode Instruments、系统日志 |
| IL2CPP / 资源 | `Il2CppDumper`、`AssetStudio` | Cpp2IL、Il2CppInspector、AssetRipper、UnityPy |

**缺工具时不 `-h` 盲试探**：① 查本机 `seep_tool_discover(tool_id, target)` / `tool_autodiscover`，读 `Tool/config/tool-capabilities.json`；② 需自启宿主用 `powershell -File Tool/scripts/tool-run.ps1 -Tool <tool> -Target <target>`；③ 仍缺走降级链或容器/WSL，安装需确认；④ 报告标注“降级原因 + 验证程度”，不假装等价。

## E. 坑（高频）

1. **profile/符号不匹配**：Windows 版本与 ISF 不符会全盘失败；先 `windows.info` 再选符号。
2. **大 pcap 撑爆内存**：先 `capinfos`，`editcap` 切片或强过滤，再逐流重组；只看单包会漏上传/响应码。
3. **分区偏移错**：`mmls` 的 Start 是扇区不是字节；`-o` 用错会误判文件系统损坏。
4. **时间线混时区**：设备/采集机/日志服务器时区不同，统一 UTC 并保留原值。
5. **已删文件当完好**：inode 复用与块覆盖会错位，先校验 magic/哈希再引用。
6. **iOS 加密二进制 / Frida 错配**：`cryptid 1` 未脱壳时符号不可信，必须先 dump；frida-server 与客户端版本/架构不匹配会 attach 失败或崩溃。
7. **反作弊触发**：在线游戏 attach/注入可能封号或蓝屏；先识别，再决定只读观测或离线。
8. **Unity 版本错配**：IL2CPP 元数据与 AssetBundle 强绑定 Unity 版本，错版本得到垃圾输出。
9. **AssetBundle 加密 / SQLite 回写 / 证据污染**：能读 `UnityFS` 不等于能解 Asset；直接打开数据库会改 WAL；在原件上挂载/运行/改时间戳会毁掉可信度。先复制，解不开就标未解，全程哈希。

## F. 验收

- [ ] 镜像/包/pcap 来源、采集时间、大小、SHA256 齐全，原件只读；工具与版本、完整命令、输出路径可复现，降级项标注原因。
- [ ] 时间线统一 UTC，含时区与时钟偏差说明。
- [ ] 每条结论具备时间/主体/动作/对象四要素，并标注 observed/inferred/unverified。
- [ ] A/B/C 至少一条硬判据达成：A=能复述谁在何时做了什么；B=能说明二进制与数据的关系；C=能对齐字段/资源/内存链路。
- [ ] 反作弊或授权边界内的动作有停止记录；未污染证据、未影响他人。

## G. 边界

- **不做 Android / 客户端授权旁路**：APK/DEX/SO、脱壳、重打包走 `apkseep`；License/计费/功能解锁走 `01`–`05`；本技能只做取证与关系说明。
- **不做未授权采集与反作弊对抗**：不碰第三方设备/账号/云资源；不注入、不挂钩、不改内存、不加载驱动；不提供隐蔽驻留或反取证手法。
- **不把“dump 成功”当结论**：没有证据链与判据只能算素材。

> 命令与判据细节：`references/forensics.md`（内存/流量/磁盘）、`references/ios-macos-and-game.md`（iOS/macOS/游戏客户端）。
