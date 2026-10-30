# 反调试识别与决策（逆向域单列卷）

> 范围：拿到 PE/ELF/Mach-O 客户端，需要判断「它怎么发现调试器/虚拟机」以及「我该用哪种观测手段」。
> 路由：脱壳流程本身见 `Tool/skill/unpack-loop/references/anti-debug.md`（OEP/内存 dump/页守卫）；本卷讲**识别与决策**，那卷讲**脱壳流程**，两篇互补。
> 铁律：**先识别，再选仪器；两次失败就停。** 不要在同一个反调试点上反复裸 attach，那只会把证据打没。

---

## 1. 决策总表（先看这张）

| 现象 | 最可能的检测层 | 首选观测 | 不要做 |
| :--- | :--- | :--- | :--- |
| 双击能跑，调试器一挂就退出 | PEB.BeingDebugged / `IsDebuggerPresent` | 静态改 PEB 或 ScyllaHide；或外部观测 | 连续换三个调试器裸 attach |
| 进程启动即崩，窗口都没出 | TLS callback / 入口前自检 / 父进程检查 | 先在 TLS callback 下断；外部 Procmon | 直接 patch 入口 |
| 单步几步就退出 | `rdtsc`/QPC 时间差 / 硬件断点 DRx | 硬件断点改软件断点、时间函数 hook | 一直单步 |
| 下 `0xCC` 断点就崩/自毁 | `int 3`/`0xCC` 扫描、CRC 自检 | 硬件断点/外部读内存/Intel PT | 继续用软件断点 |
| 一读代码段就崩 | `PAGE_GUARD` / 页属性自检 | 外部 `ReadProcessMemory`；改属性前先备份 | 在进程内 `VirtualProtect` 后硬读 |
| 一注入就退 | 模块枚举 / 线程枚举 / 驱动回调 | 早启动注入/手动映射/外部观测 | 反复注入同一个 DLL |
| 断网才正常，联网就退 | 网络心跳 + 反调试联动 | 抓包 + 断网对照 | 只改本地内存 |
| 在虚拟机里必退 | CPUID/注册表/设备名/时序 | 裸机复现或改 VM 指纹 | 在 VM 里硬猜 |

---

## 2. PEB.BeingDebugged

**识别特征（x64）：**

```asm
mov rax, gs:[0x60]        ; PEB
movzx eax, byte ptr [rax+0x02]  ; BeingDebugged
test eax, eax
jne  debugger_detected
```

x86 用 `fs:[0x30]`。也可能通过 `IsDebuggerPresent()` 导入调用。

**对抗：**

- 静态：把 `jne` 改 `jmp`/`nop`，或把 `BeingDebugged` 置 0。
- 动态：ScyllaHide/TitanHide 隐藏 PEB；或外部写 PEB（需权限）。
- 判据：改后目标继续执行；`BeingDebugged` 读回 0；不是只改 API 返回值。

**二次检测风险：** 高。很多样本同时读 PEB 和调 `IsDebuggerPresent`，只改 API 会漏；有的在 TLS callback 里再读一次。

---

## 3. NtGlobalFlag

**识别特征：**

```asm
mov rax, gs:[0x60]
mov eax, [rax+0xBC]       ; NtGlobalFlag (x64)
test eax, 0x70            ; FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS
jne  debugger_detected
```

x86 偏移 `0x68`。调试器启动的进程常带 `0x70`。

**对抗：** 把 `NtGlobalFlag` 清 0；或用插件在进程创建时改。静态 patch 检测分支也可以。

**二次检测风险：** 中。可能和 Heap flags 一起查；只清一个仍会被另一条命中。

---

## 4. Heap flags

**识别特征：**

```asm
; PEB.ProcessHeap -> Heap->Flags / ForceFlags
mov rax, gs:[0x60]
mov rax, [rax+0x30]       ; ProcessHeap
cmp dword ptr [rax+0x70], 0   ; Flags
cmp dword ptr [rax+0x74], 0   ; ForceFlags
```

正常进程 `Flags` 常为 2（`HEAP_GROWABLE`），`ForceFlags` 为 0；调试时可能带 `0x40000062` 等。

**对抗：** 清 `Flags/ForceFlags`；或 patch 检测分支。注意不要破坏堆本身。

**二次检测风险：** 中高。堆标志被改后，堆管理器行为可能异常；有的样本会交叉校验。

---

## 5. `NtQueryInformationProcess` 各 class

| Class | 名称 | 用途 | 典型检测 |
| ---: | :--- | :--- | :--- |
| 0 | `ProcessBasicInformation` | 父进程/PEB 地址 | 父进程检查、PEB 读 |
| 7 (0x07) | `ProcessDebugPort` | 指针宽度的调试端口值 | 查询成功后非 0 表示调试端口存在（常见为全 1） |
| 30 (0x1E) | `ProcessDebugObjectHandle` | 调试对象句柄 | 查询成功且句柄有效才是调试对象证据；未调试时常返回 `STATUS_PORT_NOT_SET` (0xC0000353) |
| 31 (0x1F) | `ProcessDebugFlags` | `ULONG` 调试标志 | 查询成功后 0 表示调试信号；非 0（常为 1）是常见未调试值，语义与前两项相反；这是输出值，不是 NTSTATUS |
| 32 (0x20) | `ProcessHandleTracing` | 句柄追踪 | 不与上述三类调试输出混用 |

**识别：** 导入 `NtQueryInformationProcess`，或动态解析；调用后比较返回 `NTSTATUS` 与输出缓冲区。

**返回语义：** 函数返回的是 `NTSTATUS`，不是调试端口/句柄/flags 本身。先核状态、输出类型与长度，再解释输出缓冲区；查询失败时缓冲区可能未写，预填 0 不能证明「未调试」。class 1/2/3 分别为 `ProcessQuotaLimits`/`ProcessIoCounters`/`ProcessVmCounters`，不能用于上述调试查询。

**对抗：** 在已获准的副本调试中按实际 class 和状态处理，或核调用后的分支。不能统一把返回寄存器清零：`NTSTATUS=0` 仅表示成功，且 `ProcessDebugFlags(0x1F)` 的输出 0 反而是调试信号。单项输出不能证明所有调试检测均已避开。

**反例核对：** class 7 返回 `STATUS_INFO_LENGTH_MISMATCH`，输出仍为预填 0 → 查询失败，结论未知；class 0x1F 成功并输出 0 → 调试信号；class 0x1E 返回 `STATUS_PORT_NOT_SET` → 未获得调试对象，不能解释成「NTSTATUS 非零所以被调试」。

**二次检测风险：** 高。可能同时查 `DebugPort`/`DebugObjectHandle`/`DebugFlags` 三个 class，只 hook 一个会漏；也可能直接 syscall 绕过用户态 hook。

---

## 6. `CheckRemoteDebuggerPresent`

**识别特征：** 导入 `CheckRemoteDebuggerPresent`，第二参数输出 `BOOL`；常与 `IsDebuggerPresent` 成对出现。

函数返回非 0 只表示查询成功；成功后第二参数输出非 0 才表示检测到调试器。函数失败时输出未知，不能把预填 0 当未调试证据。

**对抗：** hook 函数把输出置 0；或 patch 比较分支。

**二次检测风险：** 中。可能用 `NtQueryInformationProcess(ProcessDebugPort)` 做等价检查。

---

## 7. 硬件断点 DRx

**识别特征：**

内核态/驱动里才能直接读写 DRx（`mov rax, dr0` 属特权指令，用户态执行立即 `#GP`，不会“读出值”）：

```asm
; 适用于 ring0（驱动/反调试内核模块）
mov rax, dr0
mov rbx, dr1
or    rax, rbx
mov rcx, dr2
or    rax, rcx
mov rdx, dr3
or    rax, rdx
jnz   debugger_detected
```

用户态样本走的是 API：`GetThreadContext`/`NtGetContextThread` 读 `CONTEXT.Dr0–Dr3`/`Dr7`，目标线程需先 `SuspendThread`（且不能是当前线程自己）。看到 `import GetThreadContext` + 随后比较 `+0x48`（x64 `CONTEXT` 的 `Dr0` 偏移）就是这条路。

**判据：** `Dr0–Dr3` 任一非零 = 有硬件断点；`Dr7` 的 L/G 位说明哪些槽启用。反调试器常在 `main` 早期查一次，命中就退出或改行为。

**对抗：**

- 改用软件断点（但会被 `0xCC` 扫描发现）；或
- 用外部调试器/Intel PT/ETW；或
- hook `GetThreadContext`（以及 `NtGetContextThread`，只 hook 前者易被绕过）把 DRx 清零——用户态 hook 不到 `mov dr`，驱动层检测只能靠外部/内核手段绕。
**判据：** 目标继续执行；断点仍能命中（如果 hook 了 GetThreadContext，可能自己的断点也失效）。

**二次检测风险：** 高。硬件断点是很多壳的「最后一根稻草」；清 DRx 可能让你的调试器失去控制。

---

## 8. `int 3` / `0xCC` 扫描

**识别特征：**

- 扫描函数头/关键代码段，统计 `0xCC` 字节；正常代码也可能有 `0xCC` 填充，所以通常配合「函数头前 N 字节哈希」。
- 检测 `INT3` 指令（`0xCD 0x03`）或调试异常处理。

**对抗：**

- 硬件断点（不写 `0xCC`）；
- 外部读内存/Intel PT；
- patch 扫描函数或让扫描跳过你的断点地址。
**判据：** 不再触发自毁；断点仍有效。

**二次检测风险：** 高。壳可能对代码段做 CRC；软件断点必然改字节，硬件断点又可能被 DRx 检测。两条路要一起考虑。

---

## 9. 时间差：`rdtsc` / `QueryPerformanceCounter`

**识别特征：**

```asm
rdtsc
; ... 一段代码 ...
rdtsc
sub eax, saved_low
cmp eax, threshold
ja  debugger_detected
```

或 `QueryPerformanceCounter`/`GetTickCount`/`timeGetTime` 前后差值；单步/断点会放大时间差。

**对抗：**

- hook 时间函数返回固定增量；
- 用硬件断点减少停顿；
- patch 比较阈值/分支。
**判据：** 单步不再触发；目标行为正常。

**二次检测风险：** 中高。可能多点采样、取最小值、用 `rdtscp` 或内核时间；只 hook 一个 API 会漏。

---

## 10. VEH / SEH 反调试

**识别特征：**

- `AddVectoredExceptionHandler` 注册 handler，故意触发 `INT3`/`0xC0000005`，在 handler 里检查 `CONTEXT`/异常地址/调试寄存器。
- x86 栈链 SEH：`FS:[0]` 注册 `EXCEPTION_REGISTRATION_RECORD`；x64 用 `.pdata` + `__try/__except`。
- handler 可能修改 `EIP/RIP` 跳过检测，或直接 `ExitProcess`。

**对抗：**

- 找到 handler，patch 其判断/返回值；
- 避免触发它（硬件断点/外部观测）；
- 注意 VEH 优先级：先注册的 handler 先执行。
**判据：** 异常被正常处理；目标不退出；不是简单屏蔽所有异常（可能破坏正常 SEH）。

**二次检测风险：** 高。可能注册多个 VEH，或在 handler 里再做时间/DRx 检查。

---

## 11. TLS callback 自检

**识别特征：**

- PE 数据目录 9（TLS）非空；`AddressOfCallBacks` 指向回调数组。
- 回调在 `EntryPoint` 之前执行，常做 PEB 检查、解密、反调试、完整性自检。
- 用 `dumpbin /headers` 或 PE 解析器看 TLS Directory；x64dbg 在 TLS callback 下断。

**对抗：**

- 先在 TLS callback 下断，确认它做了什么；
- patch 回调或跳过（注意可能影响解密）；
- 用「系统断点」而不是入口断点。
**判据：** 能到入口；解密/初始化仍完成。

**二次检测风险：** 高。TLS callback 可能有多条，且互相校验；跳过一条会导致后续解密失败。

---

## 12. 父进程检查

**识别特征：**

- `NtQueryInformationProcess(ProcessBasicInformation)` 取 `InheritedFromUniqueProcessId`；
- 比较父进程名是否为 `explorer.exe`/`services.exe`/开发工具；
- 或枚举进程快照，查调试器/分析工具进程名。

**对抗：**

- 从 `explorer.exe` 启动（或伪造父进程）；
- hook 查询函数返回期望父进程；
- patch 比较分支。
**判据：** 目标继续；父进程名符合预期。

**二次检测风险：** 中。可能同时查命令行、窗口标题、模块列表。

---

## 13. 窗口/驱动/进程枚举

**识别特征：**

- `FindWindowA/W` 查 `OllyDbg`、`x64dbg`、`IDA`、`Wireshark` 窗口类/标题；
- `EnumWindows`/`GetWindowText` 遍历；
- `CreateToolhelp32Snapshot`/`Process32First/Next` 查进程名；
- `EnumDeviceDrives`/`NtQuerySystemInformation` 查驱动/调试对象；
- 注册表/服务枚举查分析工具。

**对抗：**

- 改窗口标题/类名（有些工具可配置）；
- hook 枚举函数过滤；
- 在另一个会话/桌面运行。
**判据：** 不再命中；目标行为正常。

**二次检测风险：** 中。可能组合多个枚举结果；只隐藏一个名字会漏。

---

## 14. VM 检测

| 面 | 特征 | 对抗 | 二次检测风险 |
| :--- | :--- | :--- | :--- |
| CPUID | `CPUID.1.ECX[31]` hypervisor present；`0x40000000` 厂商串 `VMwareVMware`/`VBoxVBoxVBox`/`KVMKVMKVM` | 裸机；或 hypervisor 隐藏（不一定可行） | 高：多处 CPUID/时序交叉 |
| 注册表 | `HKLM\SYSTEM\...\Enum\PCI` 含 `VEN_15AD`(VMware)/`VEN_80EE`(VBox)；`HKLM\HARDWARE\DESCRIPTION\System\BIOS` 厂商 | 改 VM 配置/注册表 | 中 |
| 设备名 | `\\.\VBoxGuest`、`VMware Tools`、`vmtoolsd` 服务、`VBoxService` | 卸载/改名 | 中 |
| MAC/PCI | OUI `00:0C:29`/`00:50:56`(VMware)、`08:00:27`(VBox) | 改 MAC | 低 |
| 时序 | `rdtsc` 在 VM 中偏移/抖动异常 | 裸机 | 高 |
| 硬件 | CPU 核心数/内存/磁盘型号异常 | 调整 VM | 低 |
| 固件 | SMBIOS/DMI 字符串 `VMware`/`VirtualBox` | 改 DMI | 中 |

**判据：** 在裸机/改指纹后通过；不是只改一个注册表键。

---

## 15. 逐条对抗后的「二次检测」判据

改完一个检测点，必须问：

1. **同一信息是否还有第二条读取路径？**（API vs 直接读 PEB vs syscall）
2. **是否有多点采样？**（时间差取多次最小值、CPU 核心逐一查）
3. **是否有交叉校验？**（PEB 与 API 结果比对、DRx 与 `0xCC` 扫描比对）
4. **是否有延迟触发？**（几秒后/心跳时/退出前再查）
5. **改完是否引入新异常？**（堆标志、页属性、线程上下文）

**判据：** 目标在「基线 / 改后 / 再改回」三种状态下行为可解释；不是「这次没崩就算过」。

---

## 16. 仪器选择矩阵

| 检测层 | 软件断点 | 硬件断点 | 外部读内存 | Frida | 纯静态 |
| :--- | :---: | :---: | :---: | :---: | :---: |
| PEB/API | 可用（需隐藏） | 可用 | 可用 | 可用 | 可用 |
| `0xCC` 扫描/CRC | ❌ | ✅ | ✅ | ⚠️（可能改页） | ✅ |
| DRx 检测 | ✅ | ❌ | ✅ | ⚠️ | ✅ |
| 时间差 | ⚠️ | ✅ | ✅ | ⚠️ | ✅ |
| TLS callback | ✅（系统断点） | ✅ | ⚠️ | ⚠️ | ✅ |
| 驱动/内核 | ❌ | ⚠️ | ✅ | ❌ | ✅ |

**决策：** 先选「不改目标字节」的观测；必须改时，先备份、后验证、两次失败就停。

---

## 17. 驱动/内核观测面

> ring3 只能看「结果」，ring0/离线才能看「机制」；先声明自己在哪一层，再决定结论强度。

| 观测点 | 机制 | ring3 可见 | ring0/离线可见 | 判据 |
| :--- | :--- | :--- | :--- | :--- |
| 进程/线程回调 | `PsSetCreateProcessNotifyRoutine(Ex)`、`ObRegisterCallbacks`（`OB_OPERATION_HANDLE_CREATE`） | ❌ 只看得到「句柄被拒/进程被拦」的结果 | ✅ 回调数组/`_OBJECT_TYPE.CallbackList` 指向非系统模块 | 回调地址落在非 `ntoskrnl/CI/AV` 模块，卸载后行为消失 |
| 调试器挂接 | `EPROCESS.DebugPort`、`KiDebugRoutine` | ⚠️ 间接：`NtQueryInformationProcess(ProcessDebugPort)` | ✅ `DebugPort != 0`；`KiDebugRoutine != 0` | 清零后 attach 不再被杀；重启后复现 |
| 内核代码防护 | PatchGuard 周期校验、DSE `g_CiOptions` | ❌ | ⚠️ 需绕过/禁用，代价是 `0x109` | 改前记录 `g_CiOptions`；改后 ≥10 分钟不蓝屏 |
| 设备通信 | `IoCreateDevice`/`IoCreateSymbolicLink`；`IRP_MJ_DEVICE_CONTROL` | ✅ `CreateFile("\\\\.\\X")` + `DeviceIoControl` | ✅ dispatch 表指向 | 返回 `ERROR_SUCCESS` 且输出缓冲区符合结构 |
| 映像/签名 | `WinVerifyTrust`、`ci.dll`、测试签名 | ✅ `signtool verify /kp /v` | ✅ `g_CiOptions`/代码完整性策略 | 正式签名 vs `TESTSIGNING` 状态明确 |

**判据（按层）**：

- ring3 可行：`DeviceIoControl` 的返回码/输出结构；`NtQueryInformationProcess(ProcessDebugPort)`；`signtool verify /kp /v`。
- ring0 可行（需调试器/驱动）：`EPROCESS.DebugPort`、`KiDebugRoutine`、`_OBJECT_TYPE.CallbackList`、`IRP_MJ_DEVICE_CONTROL` 派发地址。
- 回调：`ObRegisterCallbacks` 的 `PreOperation` 落在非 `ntoskrnl/CI/AV` 模块，且卸载后拦截行为消失 → 才算证据。
- IOCTL：先从 dispatch 枚举 `IoControlCode`，再用 ring3 逐个试；返回 `STATUS_INVALID_DEVICE_REQUEST (0xC0000010)` 说明码不对，不是驱动不存在。
- 枚举面：`sc query type= driver`、`DriverQuery /v`、`fltmc` 与 `\Driver` 目录交叉，单看一处会被 rootkit 过滤。
- PatchGuard/DSE：改内核代码/SSDT 后 `CRITICAL_STRUCTURE_CORRUPTION (0x109)`，或加载返回 `0xC0000428` → 先查 `g_CiOptions` 与测试签名状态。

**失败判据**：

- 只看到「句柄被拒/进程起不来」就断言存在内核回调 → 不合格，ring3 分不清回调与 ACL/杀软。
- `DebugPort` 清零后 attach 成功但重启复现 → 只是运行时补丁，不能写「无反调试」。
- 驱动加载失败未记录签名状态（正式/测试/未签名）与 `bcdedit` 的 `testsigning` → 结论不可复算。
- 依赖 PatchGuard 被关闭才稳定 → 明确写「需禁用 PG」，不得当通用方案。
- 无内核调试环境时，用离线镜像/`!analyze -v` 的 `MODULE_NAME` 代替，不得凭字符串猜驱动。

---

## 18. 失败判据

| 现象 | 判定 | 改走哪条 |
| :--- | :--- | :--- |
| attach 即退，换调试器仍退 | PEB/API/TLS 层检测 | 先静态识别检测点；用 ScyllaHide/外部观测；不要第三次裸 attach |
| 单步几步就退 | 时间差/DRx | 改硬件断点或 hook 时间函数 |
| 下 `0xCC` 就崩 | 代码段 CRC/`int3` 扫描 | 硬件断点/外部读/Intel PT |
| 读代码段就崩 | `PAGE_GUARD`/页属性自检 | 外部 `ReadProcessMemory`；改属性前备份 |
| 注入就退 | 模块/线程枚举/驱动回调 | 早启动/手动映射/外部观测 |
| VM 里必退 | CPUID/注册表/设备/时序 | 裸机或改 VM 指纹；不要只改一个键 |
| 改完一个点仍退 | 二次检测/交叉校验 | 按第 15 节逐条排查；不要加更多补丁掩盖 |

---

## 19. 与 unpack-loop 的分工

- **本篇（识别与决策）**：判断检测层、选仪器、评估二次检测、决定「继续/换路/停手」。
- **`unpack-loop/references/anti-debug.md`（脱壳流程）**：OEP 定位、页守卫处理、内存 dump、IAT 修复、壳自毁后的恢复。
- 两篇都读的顺序：先本篇第 1 节决策表 → 需要脱壳时转 unpack-loop → 回到本篇第 15 节做二次检测复核。

---

## 20. 边界

- 本卷只在已授权样本与沙箱内使用；生产环境的绕过按 `scope` 与授权单执行。
- 反调试技术演进快；表是「识别线索」，不是穷举。
- 任何对抗都要记录「改了什么、为什么、改后行为、是否触发二次检测」；没有记录等于没做。
- 反调试不是越狱比赛：目标是拿到可复现证据，不是把目标改成另一个程序。

---

## 21. 2026 结构判据（CET / .pdata / KDP）

| 判据 | 看什么 | 失败即停 |
| :--- | :--- | :--- |
| 影子栈/CET | `ret` 目标与 shadow stack top 不一致 / `0xC0000409` | 停止 `ret` 伪造，改 call-preceded + `jmp` |
| `.pdata` 空洞 | 返回地址落在无 `RUNTIME_FUNCTION` 覆盖的 RVA | 记 `pdata_gap`；ETW-Ti 回溯异常即停 |
| KDP | `!pte` 只读、`!pool` 受保护、写 fault | 不要把 KDP 页当普通数据页改 |

- 细节：[CET/LACUNA](../../../mcp/Tool/reverselab/kb/windows/techniques/2026-cet-lacuna-pdata.md)（影子栈 + `.pdata` 假栈）、
  [26H2](../../../mcp/Tool/reverselab/kb/windows/techniques/2026-win11-26h2-kernel.md)（HVCI/KCET/KDP）、
  [VMP UltraLock](../../../mcp/Tool/reverselab/kb/windows/techniques/2026-vmp-ultralock.md)（TitanHide/DRx 反检测）。

**通过长什么样**：本页给的是方法/边界，没有固定期望输出；执行后按末尾「这一篇算用对了」逐条自检，任何一条不成立就说明这一步没做对。
