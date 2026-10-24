# 反调试识别与绕过参考（unpack-loop / references）

> 配套：`Tool/skill/_pending/unpack-loop/SKILL.md`、``probe_matrix`（S4 已删：一次性）`、`Tool/skill/malware-analysis/scripts/dump-restore.py`。
> 本文是**判据手册**，不是"一键绕过脚本合集"。每条技术都给出：识别特征 → 探测点 → 绕过 → 失败判据 → 工具 → 误判风险。
>
> **三条从实战复盘写死的结论（先看）**
> 1. **完整性校验壳禁用软件断点（int3 / 0xCC）**：`0xCC` 会改掉被校验的字节 → CRC/哈希失败 → 页守卫自毁。**先试硬件断点 DR0–DR3**；若目标又检测 DR 寄存器，再考虑外部读内存 / Intel PT / 补丁校验函数。
> 2. **仪器不可用不是停工理由**：进程内读解密页会触发 `PAGE_GUARD`，但**外部 `ReadProcessMemory`** 往往可用；注入被检测就退到外部观测与网络层。探针矩阵必须记录"为什么不能"，不许静默跳过。
> 3. **"静默失败"比崩溃更危险**：进程活着、界面正常，但**不再发网络请求**，通常说明 `send/connect/HttpSendRequest` 之前的检测点把路径掐了。用"基线 vs 仪器"的网络行为对照 + `ExitProcess` 断点来判定，而不是看进程是否还在。

---

## 一、静态反调试（启动早期就读 PEB / TLS）

> 特征：检测发生在 `main/WinMain` 之前或最前面几条指令；不依赖调试器 API 的返回值，而是直接读内存结构。

### 1.1 PEB.BeingDebugged

| 维度 | 内容 |
|---|---|
| **识别特征** | 导入/字符串：`IsDebuggerPresent`、`BeingDebugged`；汇编：x86 `fs:[0x30]` / x64 `gs:[0x60]` 后 `movzx eax, byte ptr [reg+2]`；常见于入口 `push ebp` 之前的小段 stub。 |
| **探测点** | 入口点、TLS callback、CRT 初始化之前；`IsDebuggerPresent` 的调用点；读 `fs/gs` 段寄存器的指令。 |
| **绕过手法** | 附加后把 `PEB+2` 置 0（ScyllaHide / TitanHide 自动做）；或 hook `IsDebuggerPresent` 返回 0；也可在壳解压前静态 patch 该分支（注意自校验）。 |
| **失败判据** | 进程在 OEP 前退出（退出码常见 `0/1/0xC0000005`）；`IsDebuggerPresent` 返回非 0；TLS/入口断点未命中就被杀。 |
| **工具** | x64dbg + ScyllaHide/TitanHide；Frida `Interceptor`；`probe_matrix.py` 的 `x64dbg/frida-*` 对比。 |
| **误判风险** | 崩溃报告器、DRM、部分 .NET/Java 运行时也读 `BeingDebugged`；正常程序退出不一定等于检测。以"基线能活、挂仪器就死"为判据。 |

### 1.2 PEB.NtGlobalFlag

| 维度 | 内容 |
|---|---|
| **识别特征** | 汇编读 `PEB+0x68`（x86）/ `PEB+0xBC`（x64），与 `0x70` 比较（`FLG_HEAP_ENABLE_TAIL_CHECK|FLG_HEAP_ENABLE_FREE_CHECK|FLG_HEAP_VALIDATE_PARAMETERS`）；字符串 `NtGlobalFlag`。 |
| **探测点** | 入口 stub、TLS callback、堆操作之前；`RtlCreateHeap` / `HeapCreate` 附近。 |
| **绕过手法** | 把 `NtGlobalFlag` 清 0；ScyllaHide 的 PEB 修复；或在调试器启动前设置 `_NO_DEBUG_HEAP=1`（只对部分场景有效）。 |
| **失败判据** | 清掉 `BeingDebugged` 后仍然退出；反汇编能看到 `cmp [peb+0x68], 0x70` 且分支走向退出。 |
| **工具** | x64dbg 内存窗口 / ScyllaHide；`dump-restore.py pe-info` 只做静态提示，不能替代运行期验证。 |
| **误判风险** | 某些系统/兼容层会设置全局标志；值不等于 `0x70` 不代表没有检测，可能只取其中一位。 |

### 1.3 PEB.ProcessHeap->Flags / ForceFlags

| 维度 | 内容 |
|---|---|
| **识别特征** | 从 `PEB.ProcessHeap` 再读 `Flags`（x86 `+0x0C`，x64 `+0x14`）/ `ForceFlags`（x86 `+0x10`，x64 `+0x18`）；正常 `ForceFlags==0`，调试时 `Flags` 可能缺少 `HEAP_GROWABLE(0x2)`。字符串 `ForceFlags`、`ProcessHeap`。 |
| **探测点** | 第一次堆分配前；壳申请内存/解密之前；TLS callback。 |
| **绕过手法** | 修 `Flags=2`、`ForceFlags=0`；ScyllaHide；或用不触发调试堆的启动方式（仍不能绕过显式检查）。 |
| **失败判据** | 修 `BeingDebugged/NtGlobalFlag` 后仍死；堆标志分支命中；进程在第一次 `VirtualAlloc` 前退出。 |
| **工具** | x64dbg + ScyllaHide；Process Hacker 查看堆（仅辅助）。 |
| **误判风险** | 程序自己调用 `HeapSetInformation` 会改变标志；不同 Windows 版本的堆布局有差异，先确认位数再下结论。 |

### 1.4 TLS callback 早检

| 维度 | 内容 |
|---|---|
| **识别特征** | PE 数据目录第 9 项（`IMAGE_DIRECTORY_ENTRY_TLS`）非 0；节名 `.tls`；`AddressOfCallBacks` 指向的数组中存在回调；字符串 `TlsCallback`、`IMAGE_TLS_CALLBACK`。 |
| **探测点** | **在入口点之前**下断：x64dbg 选项 "Break on TLS callbacks"；或手动在 TLS callback 地址下断。 |
| **绕过手法** | 让调试器在 TLS 阶段就中断并修 PEB；把回调数组改成 0（注意自校验）；或在回调返回后立刻 patch 检测结果。 |
| **失败判据** | 只在 OEP 下断，结果进程从未到达 OEP；TLS 断点命中后继续运行立即退出；回调里出现 `ExitProcess`。 |
| **工具** | x64dbg（TLS callback 断点）、PE-bear / CFF Explorer 查看数据目录、`dump-restore.py pe-info` 看 TLS 目录。 |
| **误判风险** | 正常 CRT/延迟加载也使用 TLS；有 TLS 不等于恶意，关键看回调里是否做反调试/解密。 |

---

## 二、动态反调试（调用 API / 读寄存器 / 计时 / 异常）

> 特征：检测发生在运行期，往往在解压/解密完成后；靠 API 返回值、线程上下文、时间差或异常行为判断。

### 2.1 NtQueryInformationProcess（ProcessDebugPort / DebugObjectHandle / DebugFlags）

| 维度 | 内容 |
|---|---|
| **识别特征** | 导入：`NtQueryInformationProcess`、`ZwQueryInformationProcess`；字符串 `ProcessDebugPort`、`ProcessDebugObjectHandle`、`ProcessDebugFlags`；常量 `7`、`0x1E`、`0x1F`；常见封装 `CheckRemoteDebuggerPresent`。 |
| **探测点** | `ntdll!NtQueryInformationProcess` 入口；调用前第二个参数（InformationClass）；返回后的 `ProcessDebugPort` 输出缓冲区。 |
| **绕过手法** | Hook `NtQueryInformationProcess`：class 7 返回 `0`/`-1` 视语义、class `0x1E` 返回 `STATUS_PORT_NOT_SET`、class `0x1F` 返回非 0；ScyllaHide 勾选对应项；若目标直接 syscall，则需 patch syscall stub 或内核层。 |
| **失败判据** | 断点命中后输出仍是"被调试"值；进程在第一次查询后退出；hook 后目标检测 ntdll 前 5 字节被改（见 4.2）。 |
| **工具** | x64dbg + ScyllaHide；Frida；API Monitor；`probe_matrix.py` 的 `x64dbg/frida-attach`。 |
| **误判风险** | .NET/CLR、崩溃上报、性能工具也调用该 API；只看导入不能定罪，必须看 InformationClass 和返回值用法。 |

### 2.2 CheckRemoteDebuggerPresent / DebugActiveProcess

| 维度 | 内容 |
|---|---|
| **识别特征** | 导入 `CheckRemoteDebuggerPresent`、`DebugActiveProcess`、`DebugActiveProcessStop`；字符串 `CheckRemoteDebuggerPresent`；参数常为 `GetCurrentProcess()`。 |
| **探测点** | API 入口与输出 `BOOL*`；`DebugActiveProcess` 调用点（自调试反附加）。 |
| **绕过手法** | Hook 返回 `TRUE` 但输出置 `FALSE`；或直接 patch 分支；自调试场景需先阻止其创建调试关系（ScyllaHide/TitanHide）。 |
| **失败判据** | 输出缓冲区为 `TRUE`；进程在调用后拒绝附加；`DebugActiveProcess` 成功导致后续调试器无法附加。 |
| **工具** | ScyllaHide、TitanHide、Frida、API Monitor。 |
| **误判风险** | 合法程序也用 `CheckRemoteDebuggerPresent` 做崩溃保护；返回值被反转使用的情况要读汇编确认。 |

### 2.3 硬件断点寄存器检测（DR0–DR3 / DR6 / DR7）

| 维度 | 内容 |
|---|---|
| **识别特征** | 导入 `GetThreadContext`、`NtGetContextThread`、`SetThreadContext`；汇编 `mov eax, dr0..dr3`（仅 Ring0）/ `CONTEXT.Dr0` 偏移访问；字符串 `Dr0`、`Dr7`、`HardwareBreakpoint`。 |
| **探测点** | 线程创建后、关键解密函数前；`GetThreadContext(CONTEXT_DEBUG_REGISTERS)` 的调用点；异常处理里检查 `Dr6`。 |
| **绕过手法** | 优先用**硬件断点**（对完整性壳），但若目标检查 DR，则改用外部 `ReadProcessMemory` / 内存快照 / Intel PT；或 patch 掉 DR 检查；ScyllaHide/TitanHide 可隐藏 DR。 |
| **失败判据** | 设了 DR0–DR3 后目标立即退出/跳转异常；`GetThreadContext` 返回的 `Dr0..Dr3` 非 0 且随后走退出分支。 |
| **工具** | x64dbg 硬件断点、ScyllaHide/TitanHide、WinDbg（内核）、`probe_matrix.py` 的 `external`。 |
| **误判风险** | 性能分析器/崩溃转储也读线程上下文；某些保护只在特定线程检查，别用主线程结果代替全部。 |

### 2.4 时序检测（RDTSC / QPC / GetTickCount）

| 维度 | 内容 |
|---|---|
| **识别特征** | 指令 `rdtsc`、`rdtscp`；导入 `QueryPerformanceCounter`、`GetTickCount`、`GetTickCount64`、`timeGetTime`；字符串 `timing`、`rdtsc`；两次读数相减后与阈值比较。 |
| **探测点** | 连续两次时间读取之间；单步/断点命中后的时间差；解密循环前后的计时。 |
| **绕过手法** | Hook 时间 API 返回固定步进；patch 阈值比较；ScyllaHide "protect time"；避免在计时窗口内下断/单步；用硬件断点减少停顿。 |
| **失败判据** | 单步一次后进程退出；时间差远大于正常阈值；hook 后仍走退出分支（可能用了 `rdtsc` 直读）。 |
| **工具** | x64dbg + ScyllaHide、Frida、API Monitor、`probe_matrix.py`。 |
| **误判风险** | 虚拟机/低性能机器本身时间抖动大；正常性能统计也用 QPC。必须在同一台机器做基线对照。 |

### 2.5 异常与 SEH / VEH 探测

| 维度 | 内容 |
|---|---|
| **识别特征** | 导入 `SetUnhandledExceptionFilter`、`AddVectoredExceptionHandler`、`RaiseException`、`DebugBreak`、`OutputDebugString`；指令 `int3`、`int 0x2D`、`ud2`；字符串 `vectored`、`unhandled`；自调试（`CreateProcess` + `DEBUG_ONLY_THIS_PROCESS`）。 |
| **探测点** | 异常分发链；`SetUnhandledExceptionFilter` 返回值；`OutputDebugString` 后 `GetLastError`；`int3` 被谁吞掉。 |
| **绕过手法** | 让异常按目标预期传递（不要用调试器"忽略"掉）；hook 异常注册 API；ScyllaHide 的 exception 选项；对自调试先阻断 `DebugActiveProcess`。 |
| **失败判据** | `int3` 命中后目标没有按预期恢复而是退出；异常处理器未被调用；`OutputDebugString` 后走退出分支；进程"消失"但调试器没收到退出事件。 |
| **工具** | x64dbg（异常设置）、WinDbg、ScyllaHide、Frida。 |
| **误判风险** | C++/SEH 异常是正常控制流；`OutputDebugString` 在无调试器时本来就会失败，不能单凭失败判定反调试。 |

---

## 三、页保护与自校验（脱壳失败的重灾区）

> 特征：壳把解密后的页设为 `PAGE_GUARD/PAGE_NOACCESS`，或在运行期反复校验代码/数据；任何"改字节"的调试手法都会被抓。

### 3.1 VirtualProtect + PAGE_GUARD

| 维度 | 内容 |
|---|---|
| **识别特征** | 导入 `VirtualProtect`、`VirtualProtectEx`、`NtProtectVirtualMemory`；常量 `0x40`（`PAGE_GUARD`）、`0x01`（`PAGE_NOACCESS`）、`0x04/0x20/0x40` 组合；字符串 `guard page`；异常处理器里 ` ExceptionInformation[0]` 判断读/写/执行。 |
| **探测点** | `VirtualProtect` 调用点及返回值；`STATUS_GUARD_PAGE_VIOLATION (0x80000001)` 异常；`VirtualQuery` 看到的保护属性。 |
| **绕过手法** | **不要进程内读解密页**；用外部 `ReadProcessMemory` 在目标进程外取快照；用硬件断点而非 int3；必要时 patch `VirtualProtect` 去掉 `PAGE_GUARD`（会被 `VirtualQuery` 自检发现）；或让异常处理器正常跑完再读。 |
| **失败判据** | 在目标进程内 `ReadProcessMemory/ memcpy` 后目标自毁；guard 异常反复触发/死循环；dump 到的页全是 0 或旧数据。 |
| **工具** | `dump-restore.py dump --pid`（外部 RPM）、`probe_matrix.py` 的 `external`、x64dbg 硬件断点、Process Hacker。 |
| **误判风险** | JIT/浏览器/CRT 也用 guard page 做栈增长/按需提交；关键是"访问解密区就死"的对照，不是看到 `PAGE_GUARD` 就下结论。 |

### 3.2 MEM_MAPPED 重映射 / 双视图比对

| 维度 | 内容 |
|---|---|
| **识别特征** | 导入 `NtMapViewOfSection`、`CreateFileMapping`、`MapViewOfFile`、`NtCreateSection`；字符串 `MEM_MAPPED`、`MapViewOfFile`；同一文件/节被映射两次，一份执行、一份校验。 |
| **探测点** | `NtMapViewOfSection` 的 `SectionHandle` 与 `BaseAddress`；`VirtualQuery` 的 `Type==MEM_MAPPED`；两份视图的字节差异。 |
| **绕过手法** | 找到"执行视图"而非"校验视图"再 dump；patch 比对逻辑；在映射完成后用外部读；避免修改任一视图（改执行视图会被另一视图发现）。 |
| **失败判据** | dump 到的是映射前的加密副本；修改执行视图后校验视图触发退出；两份视图内容不一致却仍走退出分支。 |
| **工具** | x64dbg（句柄/内存映射）、Process Hacker、`dump-restore.py`、WinDbg `!vad`。 |
| **误判风险** | 正常程序用内存映射加载资源/数据库；双视图本身不是恶意，需看是否做逐字节比较。 |

### 3.3 CRC / 哈希自校验

| 维度 | 内容 |
|---|---|
| **识别特征** | 字符串 `CRC32`、`crc32`、`MD5`、`SHA1`、`SHA256`、`checksum`、`integrity`；导入 `CryptHashData`、`BCryptHash`、`RtlComputeCrc32`；代码里有按节/按页循环读取并累加/xor 的循环；常量表（CRC32 表）。 |
| **探测点** | 校验函数入口/返回值；被校验区间的起止；校验失败后的分支（常见 `ExitProcess`/`TerminateProcess`）。 |
| **绕过手法** | patch 校验函数返回"成功"；改期望哈希；让校验读原始备份而不是被修改页；**最稳的是不改被校验字节**（硬件断点/外部读）。dump 后重建时重算校验或去掉校验调用。 |
| **失败判据** | 改了任意字节后目标退出；校验函数返回值恒为失败；断点命中校验循环后进程自毁；dump 文件与内存镜像哈希不一致。 |
| **工具** | IDA/Ghidra 找校验循环、x64dbg 条件断点、`dump-restore.py`（dump/rebuild 后比对）、`probe_matrix.py`。 |
| **误判风险** | 正常更新器/安装包也校验自身；高熵数据不一定是代码；校验可能只覆盖部分节，别假设全镜像。 |

### 3.4 int3 / 0xCC 字节校验（**软件断点禁忌**）

| 维度 | 内容 |
|---|---|
| **识别特征** | 代码里出现 `0xCC` 扫描循环、`repne scasb` 找 `0xCC`；字符串 `breakpoint`、`int3`、`0xCC`；CRC 覆盖 `.text`；调试器下断后目标立刻退出。 |
| **探测点** | 下软件断点前后同一地址的字节；校验循环读取的地址范围；`ExitProcess` 调用栈。 |
| **绕过手法** | **禁用 int3**，改用硬件断点 DR0–DR3；或外部读内存；或在非校验区下断；或 patch 掉 `0xCC` 扫描/CRC（会引入新字节，需同步改校验）。 |
| **失败判据** | 下 `int3` 后目标在断点命中前/后自毁；同一地址在调试器里显示 `0xCC` 而磁盘文件是原指令；dump 的代码段出现非预期 `0xCC`。 |
| **工具** | x64dbg 硬件断点、`dump-restore.py`（比对 dump 与磁盘字节）、`probe_matrix.py` 的 `x64dbg/external`。 |
| **误判风险** | 编译器填充/对齐本来就有 `0xCC`；`int3` 也可能是正常陷阱指令。要看是否在运行期扫描并与已知哈希比较。 |

---

## 四、注入与挂钩检测（Frida / ScyllaHide / 调试器自身暴露）

> 特征：目标枚举模块、线程、堆或扫描 API 前几个字节，发现"不该存在的东西"就退出或改变行为。

### 4.1 模块枚举找 frida-agent / 调试器模块

| 维度 | 内容 |
|---|---|
| **识别特征** | 导入 `CreateToolhelp32Snapshot`、`Module32First/Next`、`EnumProcessModules`、`LdrEnumerateLoadedModules`、`NtQuerySystemInformation`；字符串 `frida`、`frida-agent`、`frida-gadget`、`gum-js-loop`、`gmain`、`linjector`、`ScyllaHide`、`TitanHide`、`dbghelp`、`dbgcore`；遍历 `PEB->Ldr` 的 `InLoadOrderModuleList`。 |
| **探测点** | 模块快照 API 返回后；`PEB->Ldr` 链表遍历；模块名比较循环；注入后第一次模块枚举。 |
| **绕过手法** | 用外部观测代替注入；改注入模块名/路径（frida-gadget 自定义名）；早期 hook 枚举 API 过滤；内核层隐藏（TitanHide）；避免在目标启动早期注入。 |
| **失败判据** | 注入后目标立即退出/不联网；模块枚举断点命中后走退出分支；`frida` 输出 "Failed to spawn/attach"；基线正常、注入即死。 |
| **工具** | `probe_matrix.py`（`frida-spawn`/`frida-attach`/`external` 对照）、Frida、Process Hacker、x64dbg。 |
| **误判风险** | 安全软件/输入法/浏览器插件也枚举模块；`dbghelp.dll` 可能被正常崩溃上报加载；必须做"注入 vs 不注入"对照。 |

### 4.2 Inline hook 扫描

| 维度 | 内容 |
|---|---|
| **识别特征** | 读 `ntdll/kernel32` 函数前 5–16 字节并与磁盘副本比较；特征字节 `E9 xx xx xx xx`（jmp rel32）、`FF 25`（jmp [rip]）、`push/ret`、`0xCC`；字符串 `hook`、`inline hook`、`detour`、`trampoline`；检查 syscall stub 是否为 `mov r10, rcx; mov eax, SSN; syscall`。 |
| **探测点** | API 首次调用前；`NtQueryInformationProcess`/`NtProtectVirtualMemory` 等敏感函数入口；`GetProcAddress` 返回地址与磁盘导出表对比。 |
| **绕过手法** | 用硬件断点/ETW/Intel PT 等"不改字节"的观测；hook 后恢复原 prologue 供扫描（需 trampoline 在别处）；使用直接/间接 syscall；TitanHide 隐藏 hook；外部读内存。 |
| **失败判据** | hook 后目标退出或拒绝服务；扫描循环命中被 hook 的函数；hook 一个 API 后另一个 API 行为异常（目标做了交叉校验）。 |
| **工具** | x64dbg、ScyllaHide/TitanHide、Frida、IDA/Ghidra。 |
| **误判风险** | Windows 热补丁/兼容层、杀软、输入法都会改 API 前几字节；不能只看 `E9` 就判定恶意。 |

### 4.3 线程与堆扫描 / 私有可执行页

| 维度 | 内容 |
|---|---|
| **识别特征** | 导入 `Thread32First/Next`、`NtQuerySystemInformation(SystemProcessInformation/SystemThreadInformation)`、`VirtualQueryEx`、`HeapWalk`；字符串 `thread`、`heap`、`RWX`；检查线程起始地址是否在已知模块外、是否存在 `PAGE_EXECUTE_READWRITE` 私有页、堆块数量/标志异常。 |
| **探测点** | 注入后新线程创建；`VirtualAlloc` 后保护属性；堆枚举前后；线程快照的 `dwSizeOfStack`/`tpBaseOfStack` 异常。 |
| **绕过手法** | 不在目标内创建线程（用现有线程/外部读）；避免 RWX（先 RW 再 RX）；TitanHide 隐藏线程/内存；用内核驱动；或干脆不注入。 |
| **失败判据** | 注入线程一创建目标就退出；`VirtualQuery` 发现 RWX 后走退出分支；线程快照中出现未知模块地址后被杀。 |
| **工具** | Process Hacker、x64dbg、TitanHide、`probe_matrix.py`。 |
| **误判风险** | JIT/浏览器/游戏引擎大量使用 RWX 和私有线程；单看 RWX 误判率很高，必须结合"注入前后差异"。 |

---

## 五、环境检测（VM / 用户名 / 驱动 / 进程黑名单）

> 特征：不直接问"有没有调试器"，而是判断"这是不是分析环境"；常在启动最早期完成，失败就静默退出或不发请求。

### 5.1 虚拟机特征（CPUID / 注册表 / 驱动 / MAC / SMBIOS）

| 维度 | 内容 |
|---|---|
| **识别特征** | 指令 `cpuid`（leaf 1 ECX bit 31 hypervisor present；leaf `0x40000000` vendor）；字符串 `VMware`、`VirtualBox`、`VBox`、`QEMU`、`KVM`、`Xen`、`Hyper-V`、`Microsoft Hv`、`Sandboxie`、`vmci`、`vmmouse`、`vmhgfs`、`VBoxGuest`、`VBoxMouse`；MAC 前缀 `00:05:69`、`00:0C:29`、`00:1C:14`、`00:50:56`、`08:00:27`、`00:15:5D`、`52:54:00`；WMI `Win32_ComputerSystem` 的 Manufacturer/Model。 |
| **探测点** | 启动最早期；`cpuid` 指令；注册表 `HKLM\HARDWARE\DESCRIPTION\System\BIOS`、`HKLM\SYSTEM\CurrentControlSet\Services`；驱动枚举；`GetAdaptersInfo`/`GetAdaptersAddresses`。 |
| **绕过手法** | 换裸机；改 VM 配置隐藏 hypervisor（不一定可靠）；改注册表/SMBIOS/MAC；删除/改名 VM 驱动与服务；patch 检测函数。 |
| **失败判据** | 同一 exe 在裸机正常、在 VM 静默退出/不发请求；`cpuid` 后走退出分支；检测到 VM 驱动名后行为改变。 |
| **工具** | `probe_matrix.py` 的 `baseline/network` 对照、Pafish 类检测思路、Process Hacker、Autoruns。 |
| **误判风险** | 云主机/企业 VDI 本身就是 VM；安全软件也会枚举驱动；必须用"同机基线"排除环境噪声。 |

### 5.2 用户名 / 机器名 / 域名黑名单

| 维度 | 内容 |
|---|---|
| **识别特征** | 导入/字符串 `GetUserNameW`、`GetComputerNameW`、`GetUserNameExW`、`USERNAME`、`COMPUTERNAME`、`USERDOMAIN`；黑名单字符串 `admin`、`test`、`user`、`sandbox`、`malware`、`virus`、`cuckoo`、`analysis`、`debug`、`reverse`、`DESKTOP-`、`WIN-`、`PC-`、`VIRTUAL`。 |
| **探测点** | 启动时读取环境变量/用户名；注册表 `Environment`；`GetUserNameW` 返回缓冲区。 |
| **绕过手法** | 改用户名/机器名/域名；hook API 返回白名单值；在独立测试账户下运行；注意改机器名需要重启。 |
| **失败判据** | 换用户名后行为变化；字符串黑名单命中后退出；基线在默认用户下正常、在 `sandbox` 用户下静默。 |
| **工具** | `probe_matrix.py`、Process Monitor、Frida。 |
| **误判风险** | 企业机器名常含 `PC-`/`DESKTOP-`；`admin` 是合法管理员名；不能仅凭字符串存在就判定。 |

### 5.3 驱动与反作弊（Vanguard / ACE / EAC / BattlEye）

| 维度 | 内容 |
|---|---|
| **识别特征** | 驱动/服务名 `vgk.sys`、`vgc.exe`、`ACE-BASE.sys`、`SGuard.sys`、`EasyAntiCheat.sys`、`BEDaisy.sys`；设备名 `\\.\Vanguard`、`\\.\ACE`；导入 `NtLoadDriver`、`NtQuerySystemInformation`；内核回调 `ObRegisterCallbacks`、`PsSetCreateProcessNotifyRoutine`、minifilter。 |
| **探测点** | 驱动枚举/服务查询；`NtQuerySystemInformation(SystemModuleInformation)`；设备打开；进程创建回调（内核层）。 |
| **绕过手法** | 不在装有反作弊的机器上做（最稳）；测试机卸载/禁用对应服务（注意许可与风险）；内核调试/驱动隐藏（TitanHide 等，超出常规范围）；改走外部网络层/协议层。 |
| **失败判据** | 目标启动即被驱动拦截/蓝屏/强制退出；调试器附加被内核拒绝；`NtQuerySystemInformation` 返回被过滤。 |
| **工具** | WinDbg（内核）、Process Hacker、Autoruns、`probe_matrix.py`（环境探针只报现象，内核对抗另立任务）。 |
| **误判风险** | 普通安全软件也有驱动和回调；反作弊可能只在游戏启动时加载；不要把"有驱动"直接等同于"针对你"。 |

### 5.4 进程黑名单（调试器/抓包/监控工具）

| 维度 | 内容 |
|---|---|
| **识别特征** | 导入 `CreateToolhelp32Snapshot`、`Process32First/Next`、`EnumProcesses`、`NtQuerySystemInformation`；字符串 `x64dbg.exe`、`x32dbg.exe`、`ollydbg.exe`、`ida.exe`、`ida64.exe`、`windbg.exe`、`cdb.exe`、`processhacker.exe`、`procmon.exe`、`procexp.exe`、`wireshark.exe`、`fiddler.exe`、`tcpview.exe`、`cheatengine.exe`、`dnspy.exe`、`de4dot.exe`、`frida.exe`、`scylla.exe`。 |
| **探测点** | 进程快照返回的 `PROCESSENTRY32.szExeFile`；窗口枚举 `EnumWindows` + 窗口标题；服务/驱动枚举。 |
| **绕过手法** | 改调试器/工具可执行文件名；用不常见工具；在另一台机器远程调试；内核隐藏进程；外部网络层观测。 |
| **失败判据** | 改名后不再退出；基线正常、打开某工具后目标退出；进程快照断点命中后走退出分支。 |
| **工具** | `probe_matrix.py`（仪器矩阵）、Process Hacker、x64dbg。 |
| **误判风险** | 杀软/管理工具也枚举进程；黑名单可能只匹配窗口标题；改名可能影响工具自身功能。 |

---

## 六、六列矩阵（技术 → 特征 → 可靠性 → 处置 → 工具 → 误判）

> 可靠性是"该特征作为判据的可信度"，不是"绕过成功率"。处置列默认遵循：**完整性壳用硬件断点**（int3 会改字节、破坏校验）。

| 技术 | 识别特征 | 可靠性 | 处置 | 脚本/工具 | 误判风险 |
|---|---|---|---|---|---|
| PEB.BeingDebugged | `IsDebuggerPresent`；`fs:[0x30]+2` / `gs:[0x60]+2` | 高 | 清 `PEB+2`；hook 返回 0 | x64dbg+ScyllaHide、`probe_matrix.py` | 崩溃上报/DRM 也读；需基线对照 |
| PEB.NtGlobalFlag | 读 `PEB+0x68`/`+0xBC`，比较 `0x70` | 高 | 清 0；修调试堆标志 | ScyllaHide、x64dbg | 系统/兼容层可能设置；可能只查一位 |
| Heap Flags/ForceFlags | `ProcessHeap+0x0C/0x14`、`+0x10/0x18` | 中高 | `Flags=2`、`ForceFlags=0` | ScyllaHide、Process Hacker | 程序自身改堆标志；版本布局差异 |
| TLS callback 早检 | TLS 目录第 9 项非 0；`.tls`；`AddressOfCallBacks` | 高 | 在 TLS 阶段断下并修 PEB；清回调数组 | x64dbg TLS 断点、PE-bear | 正常 CRT/延迟加载也用 TLS |
| NtQueryInformationProcess | `ProcessDebugPort(7)`、`DebugObjectHandle(0x1E)`、`DebugFlags(0x1F)` | 高 | hook 返回非调试值；ScyllaHide | ScyllaHide、Frida、API Monitor | .NET/性能/崩溃工具也用 |
| CheckRemoteDebuggerPresent | 导入 + `GetCurrentProcess()` + `BOOL*` | 高 | hook 输出 `FALSE` | ScyllaHide、Frida | 合法崩溃保护也用；返回值可能反转 |
| 硬件断点寄存器检测 | `GetThreadContext` + `CONTEXT.Dr0..Dr7` | 高 | 改外部读/Intel PT；隐藏 DR；patch 检查 | TitanHide、WinDbg、`probe_matrix.py` | 性能分析器也读上下文；只查特定线程 |
| 时序 RDTSC/QPC | `rdtsc`、`QueryPerformanceCounter`、阈值比较 | 中 | 固定时间步进；patch 阈值；避免单步 | ScyllaHide、Frida | VM/慢机抖动；正常性能统计 |
| 异常/SEH/VEH 探测 | `SetUnhandledExceptionFilter`、`int3`、`int 0x2D` | 中高 | 让异常按预期传递；hook 注册 API | x64dbg 异常设置、ScyllaHide | C++/SEH 正常控制流；ODS 无调试器本就失败 |
| `PAGE_GUARD` 保护 | `VirtualProtect(...,0x40)`、`STATUS_GUARD_PAGE_VIOLATION` | 高 | 外部 `ReadProcessMemory`；硬件断点；让异常跑完 | `dump-restore.py dump`、`probe_matrix external` | JIT/CRT 也用 guard；访问解密区才死 |
| MEM_MAPPED 双视图 | `NtMapViewOfSection`、同一 Section 两个 Base | 中高 | 找执行视图再 dump；patch 比对 | x64dbg、WinDbg `!vad`、Process Hacker | 正常资源映射也用；未必做逐字节比较 |
| CRC/哈希自校验 | `CRC32/MD5/SHA*`、按节循环、CryptHashData | 高 | patch 校验返回值/期望值；不改被校验字节 | IDA/Ghidra、x64dbg、`dump-restore.py` | 更新器/安装包也校验；覆盖范围可能部分 |
| int3 字节校验 | 扫描 `0xCC`、CRC 覆盖 `.text`、下断即死 | 高 | **禁用 int3**，用 DR0–DR3/外部读 | x64dbg 硬件断点、`dump-restore.py` | 编译器对齐填充也有 `0xCC` |
| 模块枚举找 Frida | `frida-agent`、`gum-js-loop`、`Module32First`、PEB Ldr | 高 | 外部观测；改模块名；hook 枚举；内核隐藏 | `probe_matrix.py`、Frida、TitanHide | 安全软件/插件也枚举模块 |
| Inline hook 扫描 | 比较 API 前 5–16 字节；`E9`、`FF25`、`0xCC` | 高 | 硬件断点/ETW/PT；恢复 prologue；直接 syscall | x64dbg、ScyllaHide、IDA | 热补丁/杀软也改 API 前几字节 |
| 线程/堆/RWX 扫描 | `Thread32First`、`VirtualQueryEx`、`PAGE_EXECUTE_READWRITE` | 中 | 不注入；避免 RWX；TitanHide；外部读 | Process Hacker、TitanHide | JIT/浏览器大量 RWX/私有线程 |
| VM 特征（CPUID/驱动/MAC） | hypervisor 位、`VMware/VBox/QEMU`、VM 驱动、MAC 前缀 | 中高 | 换裸机；改 VM 配置/注册表/MAC；patch | `probe_matrix.py`、Autoruns | 云主机/VDI 本身是 VM；安全软件也枚举驱动 |
| 用户名/机器名黑名单 | `GetUserNameW`、`COMPUTERNAME`、`sandbox/test/admin` | 中 | 改用户名/机器名；hook API；独立账户 | `probe_matrix.py`、Frida | 企业命名常含 `PC-/DESKTOP-`；admin 合法 |
| 驱动/反作弊 Vanguard/ACE | `vgk.sys`、`ACE-BASE.sys`、`BEDaisy.sys`、内核回调 | 高 | 换无作弊环境；外部/协议层；内核对抗 | WinDbg、Autoruns、Process Hacker | 普通安全软件也有驱动；未必针对你 |
| 进程黑名单 | `Process32Next` + `x64dbg/ida/wireshark/frida` | 高 | 改工具名；换工具；远程调试；内核隐藏 | `probe_matrix.py`、Process Hacker | 杀软/管理工具也枚举；可能只匹配窗口标题 |
| 父进程检测 | 检查父 PID/父进程名不是 explorer；`NtQueryInformationProcess(ProcessBasicInformation)` | 中高 | 用 explorer 启动；`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` 指定父进程 | `probe_matrix.py baseline`、Process Hacker | 服务/计划任务启动也非 explorer；需基线 |
| 自调试反附加 | `CreateProcess(DEBUG_ONLY_THIS_PROCESS)`、`DebugActiveProcess` | 高 | 阻断调试关系；ScyllaHide/TitanHide | x64dbg、ScyllaHide | 崩溃保护也可能自调试 |
| 窗口/标题枚举 | `EnumWindows`、`FindWindow`、`GetWindowText` + 调试器标题 | 中 | 改窗口标题；隐藏窗口；内核隐藏 | x64dbg、Process Hacker | 正常程序也枚举窗口 |
| 网络静默失败 | 进程活着但 `connect/send` 未命中；基线有请求、仪器无请求 | 高 | 先定位被掐断的 API；延后注入；外部抓包 | `probe_matrix.py network`、`dump-restore.py` | 服务器/网络本身故障；需基线对照 |

**至少 15 行已满足；本表 24 行，覆盖五大类。**

---

## 七、脱壳/绕过的完成判据（不要自欺）

### 7.1 金标准：ExitProcess / exit 断点

> **在 `ExitProcess` / `exit` 下断，未提前命中 = 没有漏检。**

操作顺序：

1. 在以下出口全部下断（有哪个下哪个，能下尽下）：
   - `kernelbase!ExitProcess`、`kernel32!ExitProcess`
   - `ntdll!RtlExitUserProcess`、`ntdll!NtTerminateProcess`
   - CRT `exit`、`_exit`、`abort`、`quick_exit`
   - `kernel32!TerminateProcess`（目标可能直接调用）
2. 让目标**完整跑完启动路径**：TLS → 入口 → 解压/解密 → 首个窗口/首个网络请求/授权检查。
3. 观察断点命中时机与调用栈：
   - **在预期的主逻辑/主窗口/首个请求之前命中** → 还有反调试/自校验没绕过；调用栈往下找检测函数，回到对应小节处置。
   - **跑完全程都没有提前命中**，只在正常关闭时命中（或一直不命中）→ 才能说"这一轮没有漏检"。
4. 如果进程**直接消失且所有出口断点都没命中**：说明还有更底层的退出路径没覆盖（直接 syscall `NtTerminateProcess`、`int 0x2E`、栈破坏、内核杀进程）。补 `ntdll!NtTerminateProcess` / 内核回调 / WER 观测，不能算通过。

### 7.2 网络静默失败的判据

- 基线（不挂仪器）：能观察到 `connect/send/WSAConnect/HttpSendRequest/WinHttpSendRequest` 或抓包有出站。
- 挂仪器后：进程仍在、界面正常，但上述 API 断点不命中、抓包无出站 → **路径在更早的检测点被掐断**，不是"程序本来就不联网"。
- 处置：回退到更晚的注入时机；先让首个请求发出再 attach；或改用外部抓包/代理；仍不行则按"仪器不可用"转路线 B。

### 7.3 产物判据（与 SKILL 七步流水线对应）

| 阶段 | 完成判据 |
|---|---|
| OEP | 落在原镜像的节内；后续执行不跳回壳 dispatcher；能看到正常编译器序言与导入引用 |
| dump | 文件能被 IDA/`dump-restore.py pe-info` 打开；节表合理；不是全 0/全 `0xCC` |
| PE 重建 | `SizeOfImage`/`SizeOfHeaders`/`PointerToRawData`/`SizeOfRawData` 自洽；壳节已清且 OEP 不在其中 |
| IAT | `dump-restore.py iat` 显示未解析 = 0；Scylla 里 unresolved = 0 |
| 干净机器 | 无调试器/无注入的独立环境能启动到主界面或发出预期请求；行为与基线一致 |

> 只要有一条不满足，就不能写"脱壳完成"。失败两次 → 按 SKILL 的两次熔断换路线，不许第三次变种硬试。
