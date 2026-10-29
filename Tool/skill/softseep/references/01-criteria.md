# 逆向判据表：从「看起来像」到「可机检成立」

> 范围：Windows PE / .NET / Go / Rust / ELF / Mach-O / ARM64 客户端，授权、补丁、脱壳、算法还原、注入、驱动与网络鉴权。
> 路由：纯黑盒服务端渗透由 `web-pentest` 承担、无线信号与物理侧信道由各自领域卷承担。
> 用法：每一行先选「场景」，再按「输入面」准备最小样本，最后用「判据（可机检）」拿证据。
> **判据不是结论。** 判据只回答「这条证据是否成立」，结论还要写清边界与反证。

---

## 1. 判据表的读法

| 列 | 含义 | 不合格的写法 |
| :--- | :--- | :--- |
| 场景 | 我要证明的那一件事 | 「分析一下这个程序」 |
| 输入面 | 证明它所需的最小输入/样本/进程状态 | 「有 exe 就行」 |
| 判据（可机检） | 命令、字节、返回码、哈希、窗口文本、断点命中 | 「看起来像」「经验上」 |
| 证据形态 | 原始输出落盘成什么 | 「截图在脑子里」 |
| 误报风险 | 这条判据最容易把什么误判成什么 | 「应该不会错」 |

**三条硬规则**

1. 一条结论至少两条独立证据：静态字节 + 动态行为，或两份不同工具的输出。
2. 证据必须可复算：命令、输入哈希、输出哈希、时间、退出码。
3. 判据成立 ≠ 路线可赢；路线可赢还要过「失败判据表」与「缺件经济学」。

---

## 2. 主判据表

| 场景 | 输入面 | 判据（可机检） | 证据形态 | 误报风险 |
| :--- | :--- | :--- | :--- | :--- |
| 授权权威判定：服务端审核还是本地裁决 | 目标 EXE/DLL、抓包、断网运行 | 断网后核心功能仍可用，且本地无签名验签调用 → 本地裁决；断网即失效且响应含服务端签名/会话令牌 → 服务端权威。辅以 `strings`/导入表查 `winhttp/ws2_32/CryptVerifySignature` 与 `license` 字符串 | pcap/JSONL、断网前后窗口标题与功能截图、导入表 CSV、`sha256` | 把「本地缓存可用」误判为「本地权威」；把「有网络请求」误判为「服务端裁决」 |
| 授权权威判定：客户端是否真的验签 | 许可文件/响应包、客户端二进制 | 改 1 字节签名后客户端拒绝 → 真验签；改后仍通过 → 只解析不验签。再 patch 验签调用返回值，观察功能是否仍受签名影响 | 改动前后请求/文件哈希、进程返回码、窗口文本 | 客户端「验了但不看返回」；签名只覆盖部分字段 |
| 补丁生效：文件级补丁 | 原文件、补丁清单、目标版本 | 补丁后文件哈希变化；目标偏移字节等于 `new`；`patch-verify.py` 返回 `ok:true`；目标进程出现预期行为（窗口/功能/返回码） | patch manifest、前后字节 hex、`sha256`、运行日志 | 补丁写进了错误版本；写入后未重算校验和/签名；只验证文件不验证行为 |
| 补丁生效：内存级补丁 | 运行中进程、模块基址、目标 RVA | 用 `ReadProcessMemory` 回读目标 RVA，字节等于补丁字节；目标行为变化；进程存活超过两个心跳周期 | 内存 hex dump、模块基址、RVA、PID、存活时长 | 只看到「注入成功」日志；补丁被守护线程回写；ASLR 导致基址算错 |
| 壳是否脱掉 | 磁盘 PE、内存镜像、节表 | 磁盘节熵仍 >7.5 但内存镜像出现原始节名/明文导入/可读字符串 → 已脱；`OEP` 落在原 `.text` 且 IAT 可解析 → 已还原；磁盘与内存一致且仍高熵 → 未脱 | 节表 CSV、熵剖面、`dump` 文件哈希、IAT 修复日志 | 把「能运行」当「已脱壳」；把内存 dump 的错位节表当原始 PE |
| 壳是否脱掉：VM 保护 | 代码段、VM entry、stub | 识别 `.vmp0/.vmp1/.themida` 节名、VM entry 的 pushad/上下文切换、字节码解释循环；若反编译只得到 dispatcher 而无业务语义 → VM 未还原 | 节名、VM entry RVA、反编译片段、trace 日志 | 把普通混淆/控制流平坦化误判为 VM；把「静态不可读」误判为「不可脱」 |
| 算法还原正确性：离线可构造 | 校验函数、常量表、样本输入输出 | 独立实现（Python/C）对 N≥10 组输入输出全部一致；构造出的许可被原客户端接受；错误输入被拒绝。必须用**非同源实现**交叉验证 | 测试向量 CSV、`pytest` 输出、客户端接受/拒绝日志 | 同源 Generate/Verify 自洽掩盖错误；只测一组；把「能生成」当「算法正确」 |
| 算法还原正确性：签名/公钥 | 公钥 blob、验签调用、签名样本 | 公钥指纹（SHA256/模数位宽）与客户端运行时读到的一致；替换公钥后旧签名失败、新签名通过；原始样本仍通过原公钥 | 公钥 hex、模数、运行时内存读值、验签返回码 | 公钥有多份副本；只改磁盘未改运行时解密结果；把哈希校验当签名 |
| PE 结构：真实节表与入口 | 磁盘文件 | `e_lfanew` 指向 `PE\0\0`；节表 `VirtualAddress/SizeOfRawData` 自洽；入口 RVA 落在可执行节；`SizeOfImage` 覆盖所有节 | PE 头解析 JSON、节表 CSV | 伪造节表（`RawSize=0`、节名重复）；把 overlay 当节 |
| .NET：托管程序集与 IL | EXE/DLL | 数据目录 14 非零；`BSJB` 元数据根；`#~`/`#Strings`/`#US`/`#Blob` 可解析；`ldstr`/方法体可读 | 元数据 CSV、IL dump、`ilspycmd` 输出 | ReadyToRun/AOT 无 IL；混淆器把方法体搬进资源 |
| Go/Rust：符号与运行时 | 二进制 | Go：`gopclntab` 可恢复函数名，`runtime.main`/`moduledata` 可定位；Rust：panic 字符串、`core::`/`alloc::` 符号、`rust_eh_personality`；剥离后仍有特征字符串与调用图 | 函数表、字符串表、调用图 DOT | 把 C++ 异常表当 Rust；把 Go 的接口表当 C++ vtable |
| 网络授权：会话绑定 | 登录/心跳请求与响应 | 多次会话令牌均不同；服务端回填时间戳；响应体随会话变化但长度恒定 → 会话绑定。三项均不命中才可尝试金样回放 | JSONL 请求/响应、令牌差异表、重放结果 | 把随机 nonce 当会话绑定；把 CDN 缓存当服务端签名 |
| 补丁工程：等长与重定位 | 原指令、补丁指令、模块基址 | 补丁长度 ≤ 原指令槽；`jmp rel32` 目标在 ±2GB；`call [rip+disp32]` 的 disp 按**下一条指令**计算；ASLR 开启时不得写绝对 VA | 反汇编前后对照、重定位表、基址记录 | 用绝对地址写死；`rel32` 少算 5 字节；跨节跳转超过 rel32 可达范围 |
| 注入：模块与线程 | 目标进程、注入器日志 | 目标进程模块列表出现注入模块；`CreateRemoteThread`/`QueueUserAPC` 返回成功；模块入口被执行（日志/断点）；目标未崩溃 | 模块列表、线程起始地址、日志、进程存活 | 只看到注入器返回 0；DLL 依赖缺失导致 DllMain 失败；位数不匹配 |
| 驱动/内核：结构与既有运行证据 | `.sys`、用户提供的设备/日志 | 静态入口/dispatch/IOCTL 数据流与来源明确的既有日志互证；当前指南不执行安装/加载驱动或改签名策略 | 文件哈希、代码位置、已提供的设备/返回码/日志 | 静态可读不证明加载/通信；缺动态条件保留未验证 |
| ARM64：调用约定与栈帧 | ARM64 二进制/进程 | 前 8 个整数参数在 X0–X7，第 9 个起入栈；返回地址在 LR(X30)；帧指针 X29；`stp x29,x30,[sp,#-N]!` 识别栈帧；`blr xN` 为间接调用 | 反汇编、寄存器快照、栈回溯 | 套用 x64 RCX/RDX；把 `x8` 当返回地址；忽略 PAC/BTI |
| macOS Mach-O：加载与签名 | Mach-O/`.app` | `MH_MAGIC_64`/`FAT_CIGAM`；`LC_SEGMENT_64`、`LC_MAIN`、`LC_CODE_SIGNATURE` 可解析；`codesign -dvvv` 显示签名链；`otool -L` 列出依赖 | Mach-O 头 JSON、`codesign` 输出、依赖列表 | 把 fat binary 当单架构；忽略 hardened runtime |
| ELF：动态链接与入口 | ELF 文件 | `\x7fELF`；`e_entry` 落在可执行段；`.dynamic` 含 `DT_NEEDED`；`readelf -h/-S/-d` 可解析；PIE 时记录基址 | ELF 头、段表、依赖、基址 | 把静态链接当动态；忽略 RELRO/PIE |
| 符号可用性：ELF/Mach-O/JAR | 二进制/JAR、符号表 | ELF：`readelf -SW` 有 `.symtab` 且 `nm --defined-only` 输出 `FUNC`，仅 `.dynsym` 时 `symbols.symtab_present=false`。Mach-O：`LC_SYMTAB.nsyms>0` 且 `stroff` 落 `__LINKEDIT`。JAR：`javap -p -c` 有 `Code`，`MANIFEST.MF` 的 `Main-Class` 命中类条目 | `readelf`/`nm -m`/`javap` 原始输出 + `symbols.symtab_present`/`symbols.dynsym_count` | 把 `.symtab` 存在当「符号可用」；把 `nsyms>0` 当内部函数名可恢复 |
| 驱动/内核：观测面层级 | `.sys`/驱动、内核调试器 | ring3：`DeviceIoControl` 返回 `STATUS`、`signtool verify /kp /v`；ring0：`EPROCESS.DebugPort`、`KiDebugRoutine`、`ObRegisterCallbacks` 回调址落非系统模块；`kernel.pg_109=false` 且连续 ≥30 min 稳定 | 调试器 `dt`/`!analyze -v` 输出 + `kernel.debugport`/`kernel.ob_callback` + IOCTL 返回码、签名状态 | 把「句柄被拒」当内核回调证据；把加载成功当补丁成立；未记录 `testsigning`/`g_CiOptions` |

---

## 3. 判据成立后的三问

1. **这条证据支持哪条路线？** 补丁 / 算号 / 公钥替换 / 取载荷 / 中继 / 不可行。
2. **反证是什么？** 如果结论错，最可能错在哪一步？把反证也写成命令。
3. **边界是什么？** 版本、架构、签名状态、断网/联网、安装版/便携版，必须逐条写。

---

## 4. 失败判据（本表自身的）

- 判据只有「是/否」没有命令 → 不合格，退回重写。
- 证据只有截图没有原始输出 → 降级为 `[inferred]`，不得写「已确认」。
- 两条证据来自同一工具的同一次输出 → 视为一条，不算交叉。
- 哈希未复算、时间未记录、退出码未记录 → 结论不可复现。

---

## 5. 边界

- 本表覆盖「客户端本地可观测」的判据；服务端内部逻辑、云端密钥、真实用户数据不在内。
- 版本绑定：所有 RVA/偏移只在记录的 SHA256 上成立；换版本必须重跑判据。
- 授权前提：仅用于已授权样本与沙箱；判据不是绕过授权的手段。

---

## 6. 判型走查：PE / ELF / Mach-O 各一条命令

> 为什么单列：§2 全是「判据」，但判据要能立起来，先得知道手里这个文件**是哪种容器、几位、什么子系统**。
> 判型错一次，后面所有偏移/RVA/调用约定的判据全部作废。本节每个格式只给一条命令 + 一个「通过长什么样」。
> 三者的共同前提：先落 SHA256 与 `file` 输出，再开始解析头；**不要先开反编译器**。

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
S="<样本>"; OUT="work/<case>/triage"; mkdir -p "$OUT"
sha256sum "$S" | tee "$OUT/sha256.txt"
file "$S" | tee "$OUT/file.txt"
head -c 4 "$S" | xxd | tee "$OUT/magic.txt"
```

### 6.1 PE：头部三件（Magic / Machine / Subsystem）

```bash
python - "$S" <<'PY'
import struct, sys, json
p = sys.argv[1]; d = open(p, 'rb').read()
assert d[:2] == b'MZ', "not MZ"
e = struct.unpack_from('<I', d, 0x3c)[0]
assert d[e:e+4] == b'PE\0\0', "e_lfanew 未指向 PE\0\0"
mach, nsec, _, _, _, optsz, chars = struct.unpack_from('<HHIIIHH', d, e+4)
opt = e + 24
magic = struct.unpack_from('<H', d, opt)[0]
sub = struct.unpack_from('<H', d, opt+68)[0]
img = struct.unpack_from('<I', d, opt+56)[0]
secs = {}
so = opt + optsz
for i in range(nsec):
    b = so + 40*i
    name = d[b:b+8].rstrip(b'\0').decode('latin-1')
    vsize, vaddr, rsize, raddr = struct.unpack_from('<IIII', d, b+8)
    secs[name] = {"vaddr": hex(vaddr), "vsize": vsize, "raw": rsize}
print(json.dumps({"format": "PE32+" if magic == 0x20b else "PE32",
                  "machine": hex(mach), "subsystem": sub, "size_of_image": hex(img),
                  "sections": len(secs), "names": list(secs)[:8]}, ensure_ascii=False))
PY
```

**通过长什么样**（x64 控制台程序）：

```json
{"format":"PE32+","machine":"0x8664","subsystem":3,"size_of_image":"0x13000","sections":16,"names":[".text",".rdata",".data",".pdata",".rsrc"]}
```

判读：`machine=0x8664` → x64（`0x14c`=x86、`0xAA64`=ARM64，此时必须改读 `08-symbol-recovery.md` 的 ARM64 路径）；
`subsystem=3` 是 GUI（`2`=CUI），它决定「窗口/控制台」这条动态证据怎么取；`format=PE32` 却按 Win64 读 `RCX` 参数
→ 整段反汇编判断作废。

**失败判据**：只信 `file` 的 `PE32+ executable (GUI) x86-64` 一行（不知 `SizeOfImage`/节数）；`e_lfanew` 越界或指向非 `PE\0\0`；
有 `.vmp0/.themida/.enigma1` 节就当成「普通 PE」继续静态读。

### 6.2 ELF：头 / 节 / 动态依赖

```bash
readelf -h "$S" | tee "$OUT/elf-head.txt"
readelf -SW "$S" | head -20 | tee "$OUT/elf-sections.txt"
readelf -d "$S" 2>/dev/null | head -12 | tee "$OUT/elf-dynamic.txt"
readelf -sW "$S" | awk '$4=="FUNC"' | wc -l | tee "$OUT/elf-func-count.txt"
```

**通过长什么样**：

```text
Class:   ELF64
Type:    DYN (Position-Independent Executable file)
Machine: AArch64
Entry point address: 0x1c400
```

```text
  [28] .symtab  SYMTAB  0000... 000a1f30 0x9a1c0   ...
```

判读：`Type=DYN` + `Entry` 非 0 → PIE，运行期基址必变，静态算出的绝对地址一律不可用；
`Machine` 决定调用约定（AArch64 读 `X0–X7`，x86-64 读 `RDI/RSI/...`）；`.symtab` 存在且 `FUNC` 计数 >0 才谈「符号可用」，
只有 `.dynsym` 时按 `08-symbol-recovery.md` §8.1 走导出名 + `.eh_frame`。

**失败判据**：把 `Type=DYN` 当「不能静态分析」；`readelf -d` 空（静态链接）却按 `DT_NEEDED` 去找 libc；
只看到 `.dynsym` 就断言「无符号可用」（内部函数不可得，但导出名仍是真证据）。

### 6.3 Mach-O：魔数 / slice / 加载命令

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
python - "$S" <<'PY'
import struct, sys, json
p = sys.argv[1]; d = open(p, 'rb').read()
MAG = {b'\xcf\xfa\xed\xfe': ('MH_MAGIC_64', '<', 32), b'\xce\xfa\xed\xfe': ('MH_MAGIC', '<', 28),
       b'\xfe\xed\xfa\xcf': ('MH_MAGIC_64', '>', 32), b'\xfe\xed\xfa\xce': ('MH_MAGIC', '>', 28)}
FAT = {b'\xca\xfe\xba\xbe': 'FAT_MAGIC', b'\xbe\xba\xfe\xca': 'FAT_CIGAM'}
h = d[:4]
if h in FAT:
    n = struct.unpack_from('>I', d, 4)[0]
    archs = [hex(struct.unpack_from('>I', d, 8 + 20*i + 4)[0]) for i in range(min(n, 8))]
    print(json.dumps({"format": FAT[h], "slices": n, "cputypes": archs})); sys.exit(0)
name, en, hdr = MAG[h]
ncmds = struct.unpack_from(en + 'I', d, 16)[0]
NAMES = {0x19: 'LC_SEGMENT_64', 0x1: 'LC_SEGMENT', 0x2: 'LC_SYMTAB', 0x1b: 'LC_UUID',
         0x1d: 'LC_CODE_SIGNATURE', 0x80000028: 'LC_MAIN', 0x80000022: 'LC_DYLD_INFO_ONLY'}
found, off = [], hdr
for _ in range(ncmds):
    cmd, size = struct.unpack_from(en + 'II', d, off)
    if cmd in NAMES: found.append(NAMES[cmd])
    off += size
print(json.dumps({"format": name, "ncmds": ncmds, "load_cmds": found}, ensure_ascii=False))
PY
```

**通过长什么样**（arm64 单架构）：

```json
{"format":"MH_MAGIC_64","ncmds":19,"load_cmds":["LC_SEGMENT_64","LC_SYMTAB","LC_DYLD_INFO_ONLY","LC_CODE_SIGNATURE","LC_MAIN"]}
```

**通过长什么样**（通用包多架构）：

```json
{"format":"FAT_MAGIC","slices":2,"cputypes":["0x1000007","0x100000c"]}
```

判读：`FAT_MAGIC` → **必须逐 slice 判**（x86_64 与 arm64 的指令、调用约定、可用工具都不同），单看第一个 slice 会得出错误结论；
有 `LC_MAIN` 才谈入口偏移（老二进制可能只有 `LC_UNIXTHREAD`）；有 `LC_CODE_SIGNATURE` 就说明签名数据在文件尾部，
改动任何字节都会让签名失效——这直接决定「文件补丁」还是「内存补丁」（`09-patch-engineering.md` §7）。

**失败判据**：把 fat 包当单架构；看到有签名就直接改文件并期望还能跑；用 `MH_MAGIC`（32 位）的头部长度去解析 64 位文件。

### 6.4 三格式共同的三条失败判据

1. 没落 `sha256` 就开始解析——之后所有偏移都无法绑定到具体版本。
2. 判型结论只有 `file` 一行，没有头字段（Machine / Type / ncmds 三个头字段）。
3. 判型正确但**没写下游影响**：几位决定寄存器、子系统决定取证方式、PIE/fat 决定补丁形态；缺这三句，判型等于没做。

---

## 7. 判据 → 最小命令 → 落盘（本表怎么用起来）

§2 的判据要落地，每个场景至少配一条命令和一个文件。缺一行就不是工程证据，是笔记。

| 判据类别（§2 对应行） | 最小命令 | 落盘 | 通过条件 |
| :-- | :-- | :-- | :-- |
| 授权权威（本地/服务端） | 断网跑一次 + 抓包一次 | `net_off.txt` / `net_on.pcap` | 断网功能差异可解释 |
| 客户端是否真验签 | 改 1 字节签名复跑 | `sig_edit.log` | 改动后拒绝 或 功能仍受签名影响 |
| 补丁生效（文件级） | `patch-verify.py --file --manifest` | `verify.json` | `ok:true` 且行为符合 |
| 补丁生效（内存级） | 回读目标 RVA | `rva_read.txt` | 回读字节等于补丁字节 |
| 壳是否脱掉 | 节熵 + 内存镜像对比 | `sections.csv` | 内存出明文节名/导入 |
| 算法还原正确性 | 独立实现跑 N≥10 组向量 | `vectors.csv` | 全一致 + 客户端接受 |
| 符号可用性 | `readelf -sW` / `nm --defined-only` | `syms.txt` | `FUNC` 计数与命名空间记录 |
| 网络授权（会话绑定） | 两次登录 + 金样回放 | `sessions.jsonl` | 三判据命中或明确不命中 |

口径提醒：本表只列「命令」，判据内容以 §2 为准，不要在这里抄第二份（两份会漂移）。

## 这一篇算"用对了"吗

- [ ] 动手前先落 `sha256` 与 `file`，判型结论带具体头字段而不是「看起来像 PE」。
- [ ] PE 写了 `Machine`/`Subsystem`/`SizeOfImage`；ELF 写了 `Class`/`Type`/`Machine`/`Entry`；Mach-O 写了魔数与是否 fat。
- [ ] 每条判型结论都写了**下游影响**（几位 → 寄存器；PIE → 地址不可硬编码；fat → 逐 slice）。
- [ ] §7 的每一行都能指出一个已落盘文件，且文件里有关键字节/字段原文。
- [ ] 判型失败时按 `02-failure-criteria.md` 换路，而不是硬着头皮继续反编译。

## 附：上游技能卡索引（24 张）

> 上游 = `mukul975/Anthropic-Cybersecurity-Skills`（818 技能库）。本表只回答一件事：这条上游技能在本域**落到哪张卡、哪篇 reference、判据是什么**。

| 上游技能 | 本域任务卡 | 落点 reference | 一句话判据 |
|---|---|---|---|
| `reverse-engineering-malware-with-ghidra` | Ghidra 样本函数图与入口定位（源：reverse-engineering-malware-with-ghidra） | `Tool/skill/softseep/references/01-criteria.md` | 入口到关键节点的调用路径可打印；每个命名函数能说出「字符串/常量/调用者」依据；关键函数有反编译片段 |
| `reverse-engineering-rust-malware` | Rust 样本符号与 panic 路径定位（源：reverse-engineering-rust-malware） | `Tool/skill/softseep/references/08-symbol-recovery.md` | 能定位到业务入口与至少一个网络/文件/加密函数；panic 路径与业务路径可区分；函数名有依据 |
| `reverse-engineering-dotnet-malware-with-dnspy` | .NET 程序集与 dnSpy/ILSpy 静态解剖（源：reverse-engineering-dotnet-malware-with-dnspy） | `Tool/skill/softseep/references/01-criteria.md` | 关键方法可读或明确标注为加密 stub；字符串/字段/调用链能指向授权或行为；版本/强名称记录 |
| `reverse-engineering-ransomware-encryption-routine` | 勒索加密例程与密钥流还原（源：reverse-engineering-ransomware-encryption-routine） | `Tool/skill/softseep/references/01-criteria.md` | 算法/模式/密钥派生可写成伪代码；测试文件加密结果可复算；密钥来源（本地/外发）明确 |
| `reverse-engineering-android-malware-with-jadx` | Android 样本 Jadx 入口与 Native 桥（源：reverse-engineering-android-malware-with-jadx） | `Tool/skill/softseep/references/01-criteria.md` | 入口→关键逻辑→数据来源链可画；native 库与 Java 调用点对应；权限/广播/服务有证据 |
| `performing-static-malware-analysis-with-pe-studio` | PE Studio 静态 triage 与可疑面清单（源：performing-static-malware-analysis-with-pe-studio） | `Tool/skill/softseep/references/01-criteria.md` | 每个可疑面至少一条可机检证据；高熵节/无签名/异常导入有记录；不把「可疑」写成「恶意」 |
| `analyzing-golang-malware-with-ghidra` | Go 二进制 gopclntab 与函数名恢复（源：analyzing-golang-malware-with-ghidra） | `Tool/skill/softseep/references/08-symbol-recovery.md` | 函数名恢复有依据；入口到关键行为路径可打印；接口表/字符串不被误读为 C++ vtable |
| `analyzing-linux-elf-malware` | Linux ELF 动态链接与入口分析（源：analyzing-linux-elf-malware） | `Tool/skill/softseep/references/07-disassembly-deep-read.md` | 入口在可执行段；依赖/符号/缓解策略明确；动态行为有 strace/日志 |
| `analyzing-packed-malware-with-upx-unpacker` | UPX/压缩壳脱壳与 OEP 判据（源：analyzing-packed-malware-with-upx-unpacker） | `Tool/skill/softseep/references/09-patch-engineering.md` | 内存出现原节名/明文导入；OEP 落在原 `.text`；IAT 可解析；dump 哈希记录 |
| `analyzing-bootkit-and-rootkit-samples` | Bootkit/rootkit 启动链与持久化面（源：analyzing-bootkit-and-rootkit-samples） | `Tool/skill/softseep/references/10-anti-debug.md` | 持久化链每一跳有路径/键值/文件证据；启动顺序可解释；清除后复验 |
| `analyzing-linux-kernel-rootkits` | Linux 内核 rootkit 模块与 hook 面（源：analyzing-linux-kernel-rootkits） | `Tool/skill/softseep/references/10-anti-debug.md` | 隐藏模块/被 hook 的函数有地址/字节证据；行为差异可复现；清理后可复验 |
| `analyzing-uefi-bootkit-persistence` | UEFI bootkit 持久化与固件面（源：analyzing-uefi-bootkit-persistence） | `Tool/skill/softseep/references/08-symbol-recovery.md` | 固件组件/变量有偏移/哈希证据；启动链可解释；Secure Boot 状态明确 |
| `extracting-credentials-from-memory-dump` | 内存转储中的凭据与密钥提取（源：extracting-credentials-from-memory-dump） | `Tool/skill/softseep/references/license-validation.md` | 命中地址/结构/上下文可解释；凭据/密钥可复现但不外泄；转储 region 表完整 |
| `detecting-fileless-malware-techniques` | 无文件/内存加载样本的检测面（源：detecting-fileless-malware-techniques） | `Tool/skill/softseep/references/01-criteria.md` | 异常有基线对照；检测规则可命中测试样本且不误报基线；证据可复现 |
| `deobfuscating-powershell-obfuscated-malware` | PowerShell 混淆解码与脚本还原（源：deobfuscating-powershell-obfuscated-malware） | `Tool/skill/softseep/references/03-model-pitfalls.md` | 每层解码可复算；最终脚本可读；危险调用（下载/执行/持久化）有定位 |
| `performing-binary-exploitation-analysis` | 二进制利用面与缓解策略核对（源：performing-binary-exploitation-analysis） | `Tool/skill/softseep/references/07-disassembly-deep-read.md` | 崩溃可复现；偏移/可控数据有调试器证据；缓解策略与利用可行性一致 |
| `exploiting-ms17-010-eternalblue-vulnerability` | MS17-010/EternalBlue 漏洞面核对（源：exploiting-ms17-010-eternalblue-vulnerability） | `Tool/skill/softseep/references/01-criteria.md` | 目标版本/补丁状态可机检；隔离靶场行为可复现；不影响真实网络 |
| `implementing-memory-protection-with-dep-aslr` | DEP/ASLR 等内存保护实现核对（源：implementing-memory-protection-with-dep-aslr） | `Tool/skill/softseep/references/01-criteria.md` | 声明与实际一致/差异有证据；关键模块 ASLR/CFG 状态明确；不把「编译选项」当「运行时已启用」 |
| `performing-thick-client-application-penetration-test` | 厚客户端鉴权链路与补丁点收敛（源：performing-thick-client-application-penetration-test） | `Tool/skill/softseep/references/04-walkthrough-project-a.md` | 状态字/返回值/UI 三重证据一致；补丁后功能闭环且稳定；可回滚 |
| `performing-mobile-app-certificate-pinning-bypass` | 移动端证书固定绕过与流量观测（源：performing-mobile-app-certificate-pinning-bypass） | `Tool/skill/softseep/references/license-validation.md` | 绕过可复现；流量可解密；不破坏 App 其它功能；证据含请求/响应 |
| `analyzing-windows-registry-for-artifacts` | Windows 注册表取证与授权状态定位（源：analyzing-windows-registry-for-artifacts） | `Tool/skill/softseep/references/01-criteria.md` | 键值变化可复现；与授权/持久化/试用期有因果关系；before/after 文件哈希记录 |
| `analyzing-prefetch-files-for-execution-history` | Prefetch/执行历史与样本落地核对（源：analyzing-prefetch-files-for-execution-history） | `Tool/skill/softseep/references/08-symbol-recovery.md` | 时间线多源一致；执行次数/路径有原始字段；时区/格式说明清楚 |
| `building-patch-tuesday-response-process` | 补丁响应流程与版本回归（源：building-patch-tuesday-response-process） | `Tool/skill/softseep/references/09-patch-engineering.md` | `patch-verify.py` 通过；关键功能回归通过；回滚后哈希/行为恢复 |
| `implementing-patch-management-workflow` | 补丁管理工作流与跨版本迁移（源：implementing-patch-management-workflow） | `Tool/skill/softseep/references/09-patch-engineering.md` | 新版本唯一命中；RVA/偏移差可解释；回归通过；manifest 版本化 |
