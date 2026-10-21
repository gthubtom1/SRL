# GLOSSARY — 跨域缩写中英对照（20 条）

> 用途：报告/战例里出现缩写时，先在这里对齐口径，再回 board 看细节。
> 口径：中文名取“本仓库使用义”，不是词典义；个别 2026 年新代号尚无稳定全称，
> 按公开材料给出最短可核描述，待一手论文/通告补全。条目按域聚合，不按字母序。

| # | 缩写 | 英文全称 / 公开名 | 中文（本仓库口径） | 落点 |
| :-- | :-- | :-- | :-- | :-- |
| 1 | VMP | VMProtect | 虚拟机保护壳；把关键代码编译为私有 VM 字节码 | `pe-reverse`、`plugin` |
| 2 | UltraLock | VMProtect Ultra (max) mode | VMP 最高强度档：虚拟化+变异+反调试叠加 | `pe-reverse` |
| 3 | CET | Intel Control-flow Enforcement Technology | 硬件控制流保护：shadow stack + IBT | `pwn-crypto`、`windows` |
| 4 | KCET | Kernel CET | 内核态 CET（影子栈/IBT），用户态 EXP 的额外闸门 | `pwn-crypto`、`windows` |
| 5 | HVCI | Hypervisor-Protected Code Integrity | 虚拟化代码完整性；内核页不可写+不可执行 | `windows`、`malware-analysis` |
| 6 | KDP | Kernel Data Protection | 内核数据只读保护（与 HVCI 配套） | `windows` |
| 7 | ESC17 | ADCS ESC #17 | ADCS 经 HTTPS WSUS 终结后中继到 Web Enrollment 的链路 | `ad-cloud` |
| 8 | FSOP | File Stream Oriented Programming | 用 `_IO_FILE`/vtable 链把控制流接到函数指针 | `pwn-crypto` |
| 9 | RDD | Remote Dynamic Dependency | 安装/运行期从远端解析、不进 lockfile 的依赖 | `supply-chain` |
| 10 | A2A | Agent2Agent protocol | 智能体间互操作协议（能力卡/任务/消息） | `general`、`protocol` |
| 11 | MCP | Model Context Protocol | 模型上下文协议：工具/资源/提示的宿主接口 | 全仓 `Tool/mcp` |
| 12 | LACUNA | （2026 研究代号） | 证据缺口定位：内存/日志缺失段的系统性标注 | `forensics` |
| 13 | FirmAE | Firmware Analysis Environment | 固件自动仿真框架（Firmadyne 后继） | `firmware-iot` |
| 14 | Khost | Kernel-aware rehosting (USENIX '26) | 内核感知的固件再托管，保留厂商内核语义 | `firmware-iot` |
| 15 | MIPS | Microprocessor without Interlocked Pipeline Stages | 常见嵌入式指令集（含大小端/软浮点变体） | `firmware-iot`、`pwn-crypto` |
| 16 | ABI | Application Binary Interface | 调用约定/寄存器/栈布局契约；跨版本偏移的根 | `pwn-crypto`、`reverse` |
| 17 | ADCS | Active Directory Certificate Services | AD 证书服务；ESC1–ESC17 的母体 | `ad-cloud` |
| 18 | WSUS | Windows Server Update Services | Windows 更新分发；HTTPS 端点可作中继落点 | `ad-cloud` |
| 19 | EVTX | Windows Event Log (binary XML) | 事件日志二进制格式；`ElfFile\0` 头、RecordId | `forensics` |
| 20 | VAD | Virtual Address Descriptor | 进程虚拟地址描述树；内存取证找隐藏模块 | `forensics` |

## 补充：成对出现的三个“别混”

- **`tcache` / safe-linking**：前者是每线程小块缓存（2.26+），后者是 2.32+ 的 `fd` 异或编码；
  写 “2.34 无 hook” 时两者都要提，否则偏移对不上。
- **`bytenode` / `.jsc`**：`bytenode` 是加载器/编译器，`.jsc` 是产物；版本闸门看的是 V8 而非 Node。
- **`RFCLLM` / `PSMBENCH`**：前者是“LLM 生成协议状态机”的方法，后者是验收基准；
  方法产出只能算候选边，基准的 `edge_coverage`/`llm_unverified` 才是判据。

> 维护：新增缩写先在本表占一行（英文全称可写“公开名”），再在对应 board 的战例里引用；
> 同一缩写在不同域含义冲突时，加域前缀（如 `SC-RDD` / `AD-ESC17`）。
