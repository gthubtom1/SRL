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

## 十、这一篇算"用对了"吗

- [ ] 我能指出命中的具体编号（例如"AD-7 + AD-14"），而不是"有反调试"
- [ ] 每条我引用的判据，都读了它的 **Constraint**（知道什么情况下不成立）
- [ ] 我找到了汇聚点，而不是逐个 patch
- [ ] 同一检测点失败 2 次我就停手了
- [ ] 上硬件/内核层之前问过用户
