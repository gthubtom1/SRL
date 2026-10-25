# 反调试 / 反虚拟化矩阵（可枚举 · 每条五字段）

> 加载时机：单步/断点/启动行为异常，或判为 C/D 类壳（虚拟化、商业反作弊）。
> **格式**：每条 = Trigger（看到什么）· Observation（实际观察到什么）· Inference（说明什么）·
> Action（怎么做）· Constraint（什么情况下这条不成立）。**没有 Constraint 的条目不可信**。
>
> 编号规则：`AD-n` 反调试、`AV-n` 反虚拟化。新增条目**只加编号不改旧号**（否则引用会断）。

## 一、基础检测（用户态 API / PEB）

| # | Trigger | Observation | Inference | Action | Constraint |
| :-: | :-- | :-- | :-- | :-- | :-- |
| AD-1 | 启动即退出、无输出 | 退出码非 0、时间 <1s | 极可能在 EP/TLS 做环境检测 | 先下 TLS callback 断点，再看 EP | 也可能是缺依赖 DLL（先看是否 `0xc0000135`） |
| AD-2 | 打了 `IsDebuggerPresent` 一处仍崩 | 还有其他检测点 | 单点 patch 不够 | 搜 PEB 访问（`fs:[30h]`/`gs:[60h]`）与 `NtGlobalFlag` | 有的样本根本没调这个 API |
| AD-3 | 断 `IsDebuggerPresent` 从未命中 | 但行为仍像检测到调试器 | 可能直接读 PEB，不走 API | 在 PEB.BeingDebugged 处下内存读断点 | 也可能用 `CheckRemoteDebuggerPresent` |
| AD-4 | 堆相关异常 | `NtGlobalFlag` 含 0x70 相关位 | 堆调试标志被用作检测 | 读 PEB+0xBC（x86）/0xBC（x64 视版本）核对 | 32/64 位偏移不同，先确认位数 |
| AD-5 | `CheckRemoteDebuggerPresent` 返回 1 | 但进程看起来没被调 | 可能被 hook 或反着用 | 追该 API 的返回值消费点 | 某些加固壳会伪造返回值反向判断 |
| AD-6 | 断 Win32 API 不命中 | Native API 仍被调用 | 走 `Nt*`/`Zw*` 直连 | 断 `ntdll` 层：`NtQueryInformationProcess` 的三类信息 | 序号导入/直接 syscall 会绕过断点 |
| AD-7 | `NtQueryInformationProcess` 命中 | InfoClass = ProcessDebugPort / DebugObjectHandle / DebugFlags | 经典三段检测 | 分别看返回值：非 0/句柄有效/flags=0 都表示被调试 | 不同 Windows 版本对这三个的支持不同 |

## 二、异常与 SEH/VEH

| # | Trigger | Observation | Inference | Action | Constraint |
| :-: | :-- | :-- | :-- | :-- | :-- |
| AD-8 | 异常发生后程序不崩 | 异常被吞、继续跑 | 用异常做控制流/检测 | 断 `AddVectoredExceptionHandler` / `SetUnhandledExceptionFilter` | 正常程序也用 VEH，别见 VEH 就判恶意 |
| AD-9 | INT3（CC）行为异常 | 断点命中但后续逻辑跳变 | 可能检测 0xCC | 改用硬件断点（不写代码段） | 硬件断点可能被 DR 检测（见 AD-29） |
| AD-10 | 长断点 `CD 03` 也可疑 | 与 CC 行为不同 | 双形式反调试 | 在 CC/CD 两种位置都试 | 有些编译器真的会生成 CD 03 |
| AD-11 | `INT 2D` 出现 | 调试器下与正常运行行为不同 | Windows 特有反调试 | 跳过该指令或 hook 异常分发 | 仅 Windows 用户态 |
| AD-12 | `ICEBP`（F1）出现 | 触发单步异常 | 检测单步 | 改为"跑一段再断" | 少数指令集/模拟器不触发 |
| AD-13 | SEH 链被改写 | 异常后走到自定义处理 | 用 SEH 隐藏流程 | 读 `EXCEPTION_REGISTRATION` 链 | x64 用表驱动异常（`.pdata`），无链 |

## 三、时间检测

| # | Trigger | Observation | Inference | Action | Constraint |
| :-: | :-- | :-- | :-- | :-- | :-- |
| AD-14 | 单步很慢时崩 | 两条 `rdtsc` 差值超阈值 | 时间差检测 | 改用硬件断点，减少中断次数 | 真机也可能因调度抖动误判 |
| AD-15 | `GetTickCount`/`QPC` 成对出现 | 差值被比较 | 时钟差检测 | 追比较分支的消费点（不是只 patch） | 不同版本 API 精度不同 |
| AD-16 | `Sleep(N)` 后立刻判断 | 实测 < N | 检测时间加速/沙箱 | 看是否 hook 了 Sleep；或换真实时长测试 | 虚拟机时钟漂移也会触发 |
| AD-17 | `Trap Flag` 被设置 | 单步异常频繁 | 用 TF 检测调试 | 在 `pushfq/popfq` 处断点观察 | 某些壳自用单步做混淆 |
| AD-18 | 时间源不止 RDTSC | 还有 RDTSCP/APIC/QPC | 多点交叉验证 | 找汇聚点（多个读数比到同一阈值） | 只处理一处会被下一处抓住 |

## 四、环境与工具特征

| # | Trigger | Observation | Inference | Action | Constraint |
| :-: | :-- | :-- | :-- | :-- | :-- |
| AD-19 | 枚举窗口/进程 | 命中 x64dbg/WinDbg/IDA 类名 | 工具指纹检测 | 改窗口类/进程名（**仅测试环境**） | 高级样本不看这些 |
| AD-20 | 读父进程 | 父进程是调试器而非 explorer | 启动链检测 | 用 `launch-gui.ps1 -Mode shell`（explorer 父进程） | 从 IDE 启动的正常程序也会被误判 |
| AD-21 | 读命令行 | 含 `-debug`/沙箱参数 | 参数检测 | 用零参数启动 | 服务启动也常带参数 |
| AD-22 | 只在 x64dbg 下崩 | 换调试器正常 | 调试器特征（模块/窗口类/内存） | 逐项对照：加载的 DLL、窗口类名 | 也可能是插件差异 |
| AD-23 | 读 CPUID/MSR | 判断真实机 vs 虚拟化 | 环境真实性检测 | 见 AV-1/AV-6 | 云主机也有 hypervisor（见 AV-1 约束） |

## 五、硬件痕迹

| # | Trigger | Observation | Inference | Action | Constraint |
| :-: | :-- | :-- | :-- | :-- | :-- |
| AD-24 | 硬件断点失效 | 设了 dr 但从不命中 | 检测/清除 DR | 读 DR0–DR7（或用 VEH 观察） | 上硬件层前**必须问用户**（L3） |
| AD-25 | DR 状态被读 | 代码访问 `mov eax, dr6` 类指令 | 主动检查断点 | 在特权指令处断点（需管理员） | 用户态读 DR 会触发异常 |
| AD-26 | 断点后代码变样 | 原字节被还原 | 自修改/自校验（见 AD-27/28） | 对比内存与文件字节 | 与热补丁类软件易混 |

## 六、线程与调试对象

| # | Trigger | Observation | Inference | Action | Constraint |
| :-: | :-- | :-- | :-- | :-- | :-- |
| AD-27 | 主线程正常但逻辑断点无效 | 断点不命中、异常看不到 | `ThreadHideFromDebugger` | 断 `NtSetInformationThread(ThreadHideFromDebugger)` | 参数值 0x11 |
| AD-28 | 暂停后逻辑变化 | 调试器暂停→行为不同 | 检测 Debug Object | 看 `ProcessDebugObjectHandle` 是否有效 | 某些壳只在暂停时检查一次 |
| AD-29 | 线程调度被打乱 | 锁竞争/APC 顺序变化 | 用调度差异检测 | 记录线程启动顺序做基线 | 高负载下正常程序也会乱 |
| AD-30 | 内核调试相关 | `KdDebuggerEnabled` 非 0 | 内核级检测 | 需内核层观测（L3，先问用户） | 用户态 patch 无效 |

## 七、自修改与完整性

| # | Trigger | Observation | Inference | Action | Constraint |
| :-: | :-- | :-- | :-- | :-- | :-- |
| AD-31 | 断点被清 | 0xCC 被写回原字节 | 扫描代码段找 0xCC | 改用硬件断点 | 会触发 AD-24 |
| AD-32 | 代码执行后恢复原样 | 静态字节 ≠ 运行时字节 | 自修改代码 | 内存 dump 后对比 | 需在目标进程内取（不是文件） |
| AD-33 | 改一处就崩 | 触发了 CRC/哈希校验 | 完整性自校验 | 先找校验链，再决定改哪 | 壳可能多点校验 |

## 八、深层与环境（反虚拟化）

| # | Trigger | Observation | Inference | Action | Constraint |
| :-: | :-- | :-- | :-- | :-- | :-- |
| AV-1 | `CPUID` leaf 1 | ECX bit31=1 | 存在 hypervisor | 读 leaf 0x40000000 看厂商串 | **云主机同样置位，不能单凭它判"分析环境"** |
| AV-2 | 读注册表 BIOS/System | 含 VMware/VBox/Hyper-V 串 | 固件指纹 | 定位读取点与匹配逻辑 | 单串命中不足以判定（需多特征） |
| AV-3 | `Sleep` 前后时间差 | 明显短于预期 | 时间加速/沙箱 | 追时钟源（RDTSC/QPC/GetTickCount） | 见 AD-16 约束 |
| AV-4 | 枚举硬件设备 | 设备数/型号异常 | 虚拟设备特征 | 记录设备基线，与真机对比 | 云主机设备本就精简 |
| AV-5 | 检查调试/分析工具进程 | 命中沙箱进程名 | 环境保护 | 清单化对照 | 易误报（用户自己开的工具） |
| AV-6 | 时序/性能计数器异常 | 指令周期与真机差异大 | 用性能计数器识别虚拟化 | 与 AV-1/AV-2 交叉验证 | 需同一台真机基线 |

## 九、使用纪律（不做就会白忙）

| 情形 | 必须做 |
| :-- | :-- |
| 同一检测点连试 2 次无进展 | **停手换路**（两击熔断）；不要 patch 第 3 次 |
| 发现多个检测点 | 先找**汇聚点**（同一 flag/错误处理函数），不要逐个 patch |
| 想 patch 反调试点 | 先确认检测结果**如何影响控制流**（退出/降功能/假数据/延迟） |
| 上硬件层 / 内核层 | **先问用户**（L3 副作用）；记录工具/版本/时间窗/哈希 |
| 判为"不可绕" | 明写 BLK-7（我不被允许做）或 BLK-8（目标不支持），给两条出路 |

## 九bis. 复合指纹：编号不是孤立的

> 单个编号只能说明“有这种检测”。真实壳是**成组**出现的；识别组合比识别单点有用。

| 组合 | 含义 | 处置顺序 | 判定通过 |
| :-- | :-- | :-- | :-- |
| AD-2 + AD-4 + AD-7 | 经典用户态反调试套装（PEB + 堆标志 + 原生查询） | 先清 PEB/堆，再 hook 原生查询 | 三处均不再触发退出 |
| AD-6 + AD-27 | 走原生 API + 隐藏线程 | 先看线程是否被隐藏（否则断点永远不命中） | 能看到目标线程被调试 |
| AD-9 + AD-31 + AD-33 | 完整性壳套装（扫 int3 + 写回 + CRC） | **换硬件断点**，不改字节 | 不再自毁；两次 dump 一致 |
| AD-14 + AD-15 + AD-18 | 多点时序交叉校验 | 固定时间源/减少中断；不要只 hook 一处 | 时间差不再异常 |
| AD-24 + AD-14 | 商业保护（查 DR + 时序） | 改外部采样；不上硬件断点 | 目标行为与基线一致 |
| AD-19 + AD-20 + AD-22 | 反注入/反调试器套装 | 改工具名/父进程；或外部观测 | 注入后不再被掐 |
| AV-1 + AV-2 + AV-4 | 反沙箱/反虚拟机套装 | 换环境（先问用户）或做环境对照 | 同一 exe 在两种环境行为可解释 |
| AV-3 + AD-16 | 时间加速检测 | 关加速/换真实时长 | 行为不再随时间跳变 |
| AD-1 + AD-33 | 启动即退 + 自校验 | 先定位校验链，不要先 patch 退出点 | 能找到 fail 汇聚点 |

**判据**：报告里应写“命中组合 X（含编号 a/b/c）”，而不是罗列十几个编号；
组合的处置顺序按表中列，因为先处置后面的会白做（例如先 hook 原生 API，但线程已隐藏 → 断点不命中）。

## 九ter. 编号到脱壳阶段的映射（决定什么时候该查哪条）

| 脱壳阶段 | 优先排查的编号 | 为什么 |
| :-- | :-- | :-- |
| 启动/TLS 前 | AD-1/2/4、AV-1/2、AD-20 | 这一段一失败就静默退出，后面什么都看不到 |
| 解密循环中 | AD-14/15/16、AD-31/33 | 时间检测与自校验都在写内存时触发 |
| 跳向 OEP 前后 | AD-6/7/24/25、AD-27 | 交接点是最常检查调试器的地方 |
| IAT 填充期 | AD-33、AD-19/22 | 填表会改内存，容易触发校验；工具指纹也在这时查 |
| 首网络请求前 | AD-23、AV-5/6、AD-1 | “静默不联网”常在这里发生 |

**用法**：走到哪个阶段就先查那一行的编号，不要一上来把 33 条全过一遍。

## 十、从现象到编号：可复制的检索命令

> 矩阵不是用来读的，是用来**定位编号**的。下面三步能把“感觉有反调试”变成“命中 AD-7 + AD-14”。

```bash
# 1) 导入表：把 API 名字对到编号候选（只读）
rabin2 -i target.exe | grep -Ei 'IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess|\\
GetThreadContext|SetUnhandledExceptionFilter|AddVectoredExceptionHandler|OutputDebugString|\\
QueryPerformanceCounter|GetTickCount|CreateToolhelp32Snapshot|Process32|EnumProcesses|\\
NtSetInformationThread|NtQueryVirtualMemory|VirtualProtect|CreateProcess|DebugActiveProcess'

# 2) 字符串：反虚拟机/工具指纹（ASCII + UTF-16 两遍）
strings -a target.exe | grep -Ei 'vmware|virtualbox|vbox|qemu|hyper-v|sandbox|cuckoo|\\
ollydbg|x64dbg|windbg|ida|wireshark|frida|scylla|titanhide|dr0|dr7|rdtsc|cpuid'
strings -a -el target.exe | grep -Ei 'vmware|virtualbox|sandbox|debug|x64dbg|frida'

# 3) 节/入口异常：高熵可执行节或入口不在 .text
rabin2 -S target.exe | head -20
rabin2 -e target.exe
```

**通过长什么样 / 期望输出**（示例，不是模板）：

```text
0x004012a0 GLOBAL DEFAULT  FUNC IsDebuggerPresent
0x00401310 GLOBAL DEFAULT  FUNC QueryPerformanceCounter
VMwareVMware
\\.\x64dbg
```

判读映射（看到即写编号，不要写“有反调试”）：

| 输出里的证据 | 候选编号 | 还要补的确认 |
| :-- | :-- | :-- |
| `IsDebuggerPresent` / `CheckRemoteDebuggerPresent` | AD-2 / AD-5 | 找调用点与消费分支 |
| `NtQueryInformationProcess` | AD-6 / AD-7 | 看 InfoClass 常量（7/0x1E/0x1F） |
| `QueryPerformanceCounter`+`GetTickCount` 同时出现 | AD-15 | 找两次读数相减的比较 |
| `rdtsc` 字节串/反汇编 | AD-14 | 同一函数内两次 |
| `GetThreadContext` / `dr0` 字符串 | AD-24 / AD-25 | 看是否 `CONTEXT_DEBUG_REGISTERS` |
| `SetUnhandledExceptionFilter` / `AddVectoredExceptionHandler` | AD-8 | 看异常是否被吞 |
| `CreateToolhelp32Snapshot`+工具名 | AD-19 | 看是否比较进程名 |
| `GetParentProcessId`/`NtQueryInformationProcess(0)` + 工具名 | AD-20 | 看是否限定 explorer |
| `VMware/VBox/QEMU` 串 | AV-2 | 看是“仅存在”还是“匹配后跳转” |
| `cpuid`（`0F A2`）+ `0x40000000` 比较 | AV-1 | 取厂商串 |
| 节熵 >7.2 且导入极少 | （无编号）→ 回 `packers-quickref.md` | — |

**约束**：**字符串存在 ≠ 会被用**。每一条候选都必须找到“读取 → 比较 → 跳转”三件中的至少两件，
否则只能算“带了这个字符串”。资源里的字符串/未引用代码里的导入不算证据。

## 十一、Evidence 字段机检表（报告里每条编号必须能对应上）

| 编号类 | 必填 evidence | 可机检形式 | 无此项就降级为 |
| :-- | :-- | :-- | :-- |
| AD-1~AD-7 | 导入/调用地址 + 返回值或分支 | `rabin2 -i` 行 + 反汇编地址 | “疑似反调试” |
| AD-8~AD-13 | 异常注册点 + 处理器行为 | 地址 + 异常类型 | “有异常处理” |
| AD-14~AD-18 | 两次时间读数地址 + 阈值常量 | 反汇编 + 常量值 | “可能有时序检测” |
| AD-19~AD-23 | 枚举 API + 黑名单字符串 + 分支 | 字符串偏移 + 地址 | “有工具名” |
| AD-24~AD-26 | DR 访问指令/上下文调用 + 消费点 | 反汇编 `mov reg, drN` | “可能查 DR” |
| AD-27~AD-30 | 信息类/线程隐藏参数 + 效果 | 参数常量（如 0x11） | “可能隐藏线程” |
| AD-31~AD-33 | 内存/文件字节差异 | 两路哈希对照 | “可能自校验” |
| AV-1~AV-6 | 检测点 + 阈值/字符串 + 行为差异 | 命令输出 + 基线对照 | “可能有环境检测” |

**判据**：报告里写了一个编号，就必须有它那一行的 evidence；
缺了就按最后一列降级。**降级不是丢脸，乱定级才是。**

## 十二、汇聚点定位法：多个编号归一到一处

> 典型壳会同时用三五种检测。逐个 patch 会输，因为改不完；找**汇聚点**只会有一个或两个。

| 汇聚形式 | 形态 | 怎么找 | 怎么处置 |
| :-- | :-- | :-- | :-- |
| 错误处理函数 | 多个检测 → `call fail` / `jmp fail` | 交叉引用（`axt`）指向同一地址 | 在 fail 处下断，看谁调它 |
| 全局标志 | 检测结果写同一全局变量 | 搜对同一地址的写 | 观察标志被谁读 |
| 单一返回值 | 多个检测最终都落到同一个 `ret` | 看函数出口 | 改返回处比改每个检测便宜 |
| 静默失效 | 不退出，而是“不联网/不弹窗” | 网络/UI 层断点对照 | 别执迷于“它为什么没崩” |

```bash
# 用 r2 的交叉引用找汇聚点（只读）
r2 -A -q -c 'axt @ 0x401230; s 0x401230; pdf' target.exe
# 多个 AD 编号的调用点都在这里汇合 → 这里就是处置点
```

**通过长什么样 / 期望输出**：`axt` 列出 ≥3 条来自不同函数的 `call 0x401230` →
这就是汇聚点；只处置它会比逐个 patch 检测点少改 70% 以上的字节。
**约束**：改汇聚点等于改变控制流，必须先确认它不被 CRC 覆盖（见 AD-33）；
否则用内存补丁而不是磁盘补丁。

## 十三、新增编号的规则（只加不改）

| 规则 | 理由 |
| :-- | :-- |
| 只追加 `AD-n+1`/`AV-n+1`，不重排、不改旧号 | 其他文档/账本按编号引用 |
| 每条必须五字段齐（Trigger/Observation/Inference/Action/Constraint） | 缺 Constraint 的条目不可信 |
| 新条目必须写出“在哪篇 reference 有展开” | 避免矩阵膨胀成技术手册 |
| 同义条目合并到旧编号的 Constraint | 否则矩阵会变成重复清单 |
| 新增后必须回写 `packers-quickref.md` 的判型表（若影响判型） | 两份表不能相互矛盾 |

**判据**：新增条目后，用 `grep -c '^| AD-'` 与 `grep -c '^| AV-'` 各数一遍，编号连续且无重复才算合格。

## 十三bis. 编号台账（评审时最省事的一步）

```bash
grep -c '^| AD-' Tool/skill/unpack-loop/references/anti-debug-matrix.md
grep -c '^| AV-' Tool/skill/unpack-loop/references/anti-debug-matrix.md
grep -n '^| AD-' Tool/skill/unpack-loop/references/anti-debug-matrix.md | tail -3
```

**通过长什么样 / 期望输出**：

```text
30
6
217:| AD-31 | 断点被清 | …
218:| AD-32 | 代码执行后恢复原样 | …
219:| AD-33 | 改一处就崩 | …
```

判读：两个计数与最后一行的编号对得上（`AD-33` → 共 33 条时应有 9 条在 十一 章节的 Evidence 表里不计） → 编号连续。
**约束**：计数只用来查“有没有重号/断号”，不能拿计数当“覆盖度”；覆盖度要看你的样本命中了哪几条。

## 十四、这一篇算"用对了"吗

- [ ] 我能指出命中的具体编号（例如"AD-7 + AD-14"），而不是"有反调试"
- [ ] 每条我引用的判据，都读了它的 **Constraint**（知道什么情况下不成立）
- [ ] 我找到了汇聚点，而不是逐个 patch
- [ ] 同一检测点失败 2 次我就停手了
- [ ] 上硬件/内核层之前问过用户
