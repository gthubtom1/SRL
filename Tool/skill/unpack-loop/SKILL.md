---
name: unpack-loop
description: "这个软件加壳了怎么脱/脱壳/dump 内存/OEP 怎么找/反调试怎么过/IAT 怎么修 (.exe/.dll/.sys，UPX/ASPack/VMProtect/Themida/ACE 等商业壳与自研壳)。加壳软件脱壳与内存转储闭环：壳识别 → 反调试对抗 → OEP 定位 → dump → IAT 修复 → 复验。"
license: MIT
compatibility: Windows 10/11 x64 的 PE；Android DEX/SO 由 apkseep，ELF/Mach-O 由 softseep 承担，pe-sieve 解析的是 Windows PE，不能解析 ELF。依赖 seep MCP + 可选 x64dbg / pe-sieve / Scylla / ScyllaHide / Frida。
metadata:
  version: "1.1.0"
  category: unpacking
  hard_gates: "两阶段熔断 / 判据驱动 / 完整性壳用硬件断点 / 仪器不可用转外部 / 探测走能力表"
---

# unpack-loop — 脱壳与内存转储闭环

> **本技能只回答一件事**：这个目标**能不能脱、该怎么脱、脱完能否回答主域当前问题**。
> 它**不是**一条必须走完的流水线 —— 壳的种类决定路线，硬走会浪费时间、甚至把靶机搞崩。
>
> 主域按用户目标决定是否需要脱壳及交付形式；本技能返回技术判断、材料身份与证据到同一项目。授权成品任务需要旧方法时按源码路径读取 `Tool/skill/_pending/00-analysis/SKILL.md`，它仅是可选参考。

---

## 配方（照这个跑）

输入面命中下面某行时，先照该配方的命令序列跑，再回来对判据；配方正文只在 playbooks 一处，本文件只指路。

- APK 加固脱壳闭环（壳识别 → dump → 重建）→ `Tool/playbooks/apk-unpack.md`
- 壳/自毁阻断时改走授权旁路交付 → `Tool/playbooks/license-bypass-deliver.md`
- 样本加壳高熵时的脱壳分支 → `Tool/playbooks/malware-triage.md`
- 追版遇到新增壳先过壳 → `Tool/playbooks/version-migrate.md`

## 上限怎么说（对客户）

- **只能看懂结构**：`判出了壳的类型与反调试面（哪一类壳、哪些检测点），但 dump 点没找对、导入表还是坏的`
- **能改到能用**：`OEP 找对、dump 件的头/区段/导入表都修回来了，一启动就退的问题没了，关键判定点能改能验证`
- **能完全自己接管**：`这套壳以后你自己能重复：修完的导入表能列全、相邻功能仍正常，当前样本的复现步骤与适用边界清楚；换样本须重新验证`
- **卡点通常是**：`VMProtect/Themida 虚拟化 + 完整性校验壳——下个软件断点就把校验字节改了、进程自毁，只能转运行期路线拿结论`

> 依据：本文件 §二 路线 A（七步流水线 + 完成判据）/ §三 路线 B（只能运行期）/ §四 常见壳差异对待

## 〇、铁律（先看，违反即停）

1. **判据驱动，不是步骤驱动**：每阶段只问"完成判据满足了吗？"，不满足就升级/换路线，**不硬推**。
2. **两阶段熔断（两次失败即停）**：
   - 第一级：同一阶段、同类尝试失败 **2 次** → 停，汇报，换手法或换阶段；
   - 第二级：同一路线换过 2 种手法仍不满足判据 → 升级路线（A→B）或退出，**第三次直接换路线**。
3. **探测走能力表**：`-h` / 无参运行会崩、会触发自毁；工具是否可用走 `Tool/scripts/tool-acquire.py --sweep`（工具探活） / `tool_autodiscover`。
4. **先快照后动手**：VM 快照 + 目标目录备份；**单变量**（一次只改一处）。
5. **联网优先隔离**：发现外连先用 `seep_pcap_extract` 看端点，避免"一启动就上报"。
6. **完整性校验壳禁用 int3，先试硬件断点**：软件断点会把 `0xCC` 写进被校验的字节 → CRC/哈希失败 → 页守卫自毁。**首选 DR0–DR3 硬件断点**；若目标又检测 DR 寄存器，再转外部 `ReadProcessMemory` / Intel PT / 补丁校验函数。详见 `references/anti-debug.md`。
7. **先检查可替代观测面**：x64dbg 被检测、Frida 被掐、进程内读解密页触发 guard，都不等于"不能做"。转**外部读内存**（`dump-restore.py dump`）、**网络层**（抓包/代理/回放）、**静态 + 行为**观测。探针记录必须写明"为什么不能"；替代路线也缺必要能力时诚实报告 blocked，不无限换路。
8. **失败两次换手法**：同一种绕过/断点/注入方式第二次失败，就换一类手法；参数微调式硬试视为重复同一条路径。

---

## 〇bis、症状索引（命中即停下来读那一篇，别继续试）

> 这是**停止信号**表：看到右边的现象，先加载左边那一篇，再决定下一个命令。
> 连续两次同样现象 → 换路（两击熔断）。

| 现象（你现在看到的） | 先读哪一篇 | 为什么不能硬试 |
| :-- | :-- | :-- |
| 熵高 / 节名畸形（`.(D6`）/ 标准节 RawSize=0 | **先跑 `scripts/unpack-triage.py <样本>`**，再读 `references/packers-quickref.md` | 不知道是哪类壳就 dump，等于赌 |
| 单步就崩 / 找不到 OEP / 跳过去全是垃圾指令 | `references/oep-locate.md` | dump 点错了，IAT 一定坏，后面全白做 |
| dump 后 PE 头坏 / 区段 RawSize=0 / EP 不在代码节 | `references/dump-and-rebuild.md` | 取错内存区，重建也救不回来 |
| `rabin2 -i` 导入为空或条数明显不对 | `references/iat-repair.md` | 不修 IAT，dump 件一启动就退 |
| 出现巨大 switch/跳转表 + 一段无意义数据区（虚拟化） | `references/vm-bytecode.md` | 对 VM 字节码做 capstone 必然得到垃圾 |
| 断点不命中 / dr 被清 / 壳检测到调试器 | `references/hw-observation.md` + **`references/anti-debug-matrix.md`**（按编号定位） | 软件层已失效，继续试只会被熔断 |
| 壳要联网/服务端校验通过才解密 | 回 `seep-router`（判型：服务端权威） | 这是"钥匙在别人手里"，不是脱壳问题 |


## 一、入口判定门（必须先过）

用 `seep_packer_detect <target>`，拿到：节名/节熵、反调试导入、反 VM 字符串、是否 CLR。
再回答三个问题：

| 问题 | 取值 | 影响 |
|---|---|---|
| Q1 壳类型 | 压缩壳（UPX/ASPack/MPRESS）/ 加密壳（Themida/Enigma）/ 虚拟机壳（VMProtect/.NET Reactor）/ 仅混淆（.NET/JS） | 决定路线 |
| Q2 反调试强度 | 无 / 用户态（IsDebuggerPresent、PEB、时钟）/ 内核级（反附加、驱动保护） | 决定要不要 ScyllaHide/TitanHide，以及能不能用注入 |
| Q3 权威在哪 | 纯离线 / 有外连（云端授权） | 决定"脱了值不值" |

**判定门输出（三选一，写进报告）：**

| 路线 | 条件 | 目标 |
|---|---|---|
| **A 可脱** | 压缩壳 / 加密壳且反调试可绕 | 拿到可分析的 dump，回主线做鉴权审计 |
| **B 只能运行期** | 虚拟机壳 / 反调试过强 / dump 后不可重建 | **放弃完整脱壳**，改内存补丁 / API Hook / 行为观察 |
| **C 建议放弃** | 壳+联网权威+关键逻辑全在云端 | 转协议层（`seep_pcap_extract` + `seep_http_replay`）或直接给结论 |

> **主模型按用户目标作出继续或停止的判断**：本技能返回“能不能脱、脱了有没有用”的技术结论。
> Q3 与 A/B/C 路线都是主域决策的证据；需要专业单案判据时再使用 `case_state.py verdict`。
> 不要求其他任务先经过授权成品的阶段零。

> **先判脱壳价值**：鉴权判定在云端时，脱壳再完美也拿不到结论 —— 这是最常见的时间黑洞。

---

## 二、路线 A（可脱）—— 七步流水线 + 完成判据

> 七步不是"必须全走"：压缩壳可能第 1、3、4、7 步就够；重建失败可回退。
> 但每一步的**判据**必须满足，不能"看起来像"就往下走。
>
> 步骤间有**回退边**，受"两阶段熔断"约束。探针矩阵先行：
>
> ```bash
> python Tool/scripts/tool-acquire.py --tool ida --json > work/<task>/tool-probe.json
> ```

| # | 步骤 | 一句话 | 核心判据 |
|---|---|---|---|
| 1 | 壳指纹 | 壳候选/入口节/CLR | 已知家族附依据；证据不足写未知，不能从高熵或节名独断壳名 |
| 2 | 仪器验证 | 哪些调试/注入/外部读/抓包真能用 | 至少 1 种非 baseline 仪器可用，且知道"为什么另一种不能用" |
| 3 | OEP 定位 | 找到原程序入口 | OEP 在原镜像节内，后续不跳回 dispatcher |
| 4 | dump | 从内存取镜像 | dump 能被 IDA / `pe-info` 打开，节表合理 |
| 5 | PE 重建 | 展开节、修 raw 指针、清壳节 | `SizeOfImage/Headers/RawPtr/RawSize` 自洽，壳节已清且 OEP 不在其中 |
| 6 | IAT 重建 | Scylla 补导入 | `dump-restore.py iat` 未解析 = 0；Scylla unresolved = 0 |
| 7 | 干净机器验证 | 脱离仪器复跑 | 独立环境能启动到主界面/发出预期请求，行为与基线一致 |

### 2.1 步骤 1：壳指纹

- 动作：`seep_packer_detect` + `seep_r2_info`（入口段、节名、熵）+ `python Tool/skill/malware-analysis/scripts/dump-restore.py pe-info <target>`。
- **完成判据**：记录有依据的壳候选或未知 + 入口所在节 + CLR/TLS/异常目录/高熵节；不编造家族名。
- 失败升级：判不出 → `seep_r2_cmd(binary_path="<当前目标绝对路径>", command="iR", analyze=false)` 找内嵌载荷（有些"壳"其实是资源里的第二个 PE）；仍判不出 → 按"自定义壳"处理，直接进步骤 2 用行为判定。
- 卡点：`pe-info` 只是静态提示，不能替代 `seep_packer_detect` 的判壳结论。

### 2.2 步骤 2：仪器验证（先于任何断点/注入）

- 动作：
  ```bash
  python Tool/scripts/tool-acquire.py --tool ida --json
  python Tool/skill/malware-analysis/scripts/dump-restore.py pe-info <target>
  ```
  上述命令仅验证工具就绪/静态 PE，不会验证目标反调试。获得当前目标运行许可后才分别做基线与所需仪器对照，记录 `ok | partial | blocked | killed`、证据和原因；需要单案账时用 `case_state.py instrument`。
- **完成判据**：至少 1 种非 baseline 仪器可用（`ok/partial`）；并且明确写出：
  - 目标是否能裸启动、存活多久、退出码/窗口；
  - x64dbg 是否被检测/自毁；
  - Frida spawn/attach 是否被杀、是否导致"静默不联网"；
  - 外部句柄/读内存是否可用；
  - 是否有出站、抓包工具是否可用。
- 失败升级：注入被阻断时检查外部观测/网络层；仍无必要观测能力则报告缺口，不能把路线 B 当必然成功。
- 卡点：DLL 不能直接启动，baseline 会明确报"需要宿主进程"；这不是脚本失败，是设计内卡点。

### 2.3 步骤 3：OEP 定位

- 手法（按成本排序，完整性壳**先硬件断点**）：
  1. 硬件执行断点（DR0–DR3）落在原镜像 `.text`；
  2. ESP 定律 / 栈上返回地址；
  3. 内存写断点（只对非校验页）；
  4. 外部读内存 + 节熵变化定位解密完成点；
  5. 单步跟（只在确认没有时序检测时用）。
- **完成判据**：
  - OEP 落在**原镜像的节**（不是壳节/dispatcher）；
  - 从 OEP 继续执行**不跳回**壳的解压/解密循环；
  - 到达路径、后续代码及调用目标能解释运行库初始化或约定业务，记录导入/延迟导入与重定位是否就绪；
  - 固定序言、节名及连续指令数只作线索。无栈帧/尾调用入口也可能成立；能反汇编的壳 stub 仍不成立。按 `references/oep-locate.md` 交叉核验，独立运行另验重建与功能。
- 失败升级：2 次找不到 → 切路线 B（不追求 OEP），或用"运行期补丁 + 行为观察"交付。
- 卡点：VMProtect/Themida 的 OEP 可能被虚拟化，不要为"形式上的 OEP"死磕。

### 2.4 步骤 4：dump

- 动作（任选，优先不触发目标内 guard 的方式）：
  ```bash
  # 外部 ReadProcessMemory（推荐；不注入、不改目标字节）
  python Tool/skill/malware-analysis/scripts/dump-restore.py dump --pid <pid> --out work/<task>/dump.bin
  # 或 pe-sieve / x64dbg + Scylla 插件
  pe-sieve /pid <pid> /dmode 3 /out <dir>
  ```
- **完成判据**：dump 文件能被 `dump-restore.py pe-info` / IDA 正常解析；节表合理；不是全 0、全 `0xCC` 或仍是高熵加密数据。
- 失败升级：dump 出来熵仍 > 7 且无导入 → 还没到 OEP，回步骤 3；读内存失败 → 换 `external` 方式/降低权限/在解密完成后 dump。
- 卡点：`dump` 子命令只做模块镜像 dump；IAT/节修复在后续步骤，不要期待一步到位。

### 2.5 步骤 5：PE 重建（节展开 / 修 raw 指针 / 清壳节）

- 动作：
  ```bash
  python Tool/skill/malware-analysis/scripts/dump-restore.py rebuild --dump work/<task>/dump.bin --out work/<task>/rebuilt.exe
  ```
  脚本会：按 `SectionAlignment` 展开节、修 `PointerToRawData/SizeOfRawData`、更新 `SizeOfImage/SizeOfHeaders`、按节名清壳节（加 `--clear-entropy` 时同时按熵清；始终保留入口节和数据目录所在节）。
- **完成判据**：
  - `pe-info` 显示 `SizeOfImage/SizeOfHeaders/SectionAlignment/FileAlignment` 自洽；
  - 每个节的 `PointerToRawData + SizeOfRawData` 不越界、不重叠；
  - 壳节已清（或被明确保留并说明原因），且 **OEP 不在被清节内**；
  - IDA/`pe-info` 能打开重建后的文件，入口 RVA 仍有效。
- 失败升级：重建后不能加载 → 回步骤 4 检查 dump 布局（`raw`/`virtual`），用 `--layout` 显式指定；仍失败 → 路线 B。
- 卡点：清壳节是启发式，脚本会打印被清列表；若 OEP/导入落在其中，必须 `--no-clear` 或手工保留。

### 2.6 步骤 6：IAT 重建（Scylla，unresolved = 0）

- 动作：
  ```bash
  python Tool/skill/malware-analysis/scripts/dump-restore.py iat --dump work/<task>/rebuilt.exe
  ```
  未解析项用 Scylla（x86/x64）自动搜索 + 手工补；必要时按 `seep_r2_cmd(binary_path="<当前目标绝对路径>", command="afl", analyze=true)` 的 `sym.imp.*` 交叉核对。
- **完成判据**：
  - `iat` 输出未解析 = 0；
  - Scylla 里 unresolved = 0，导入表能保存；
  - 重建文件能被加载器/IDA 接受，导入函数名成组出现。
- 失败升级：IAT 大量缺失且无规律 → 路线 B；少量缺失 → 手工补，补两次仍不行按熔断换手法。
- 卡点：Scylla 是外部 GUI 工具，脚本只报现状，不假装自动修复。

### 2.7 步骤 7：干净机器验证

- 动作：把重建产物复制到**无调试器、无注入、无 ScyllaHide** 的独立 VM/机器；快照后运行；对照基线记录：
  - 能否启动到主界面/主逻辑；
  - 是否发出与基线一致的网络请求；
  - 是否仍自毁/退出/报错；
  - 节熵、导入数量、`seep_packer_detect` 复测是否还判为壳。
- **完成判据**：目标能启动到主界面/主逻辑 + 行为与基线一致 + 熵显著下降 + 反调试特征消失（或至少不再触发）。
- 失败升级：只在仪器下能跑、干净机器不能 → 回步骤 5/6 修 PE/IAT，或承认"只能运行期"转路线 B。
- 卡点：干净机器验证必须人工准备环境；脚本不能替代。

---

## 三、路线 B（只能运行期）—— 不脱壳也能交付

> 范围：VMProtect / Themida 强保护 / 内核反调试 / dump 不可重建。**目标是拿到"结论"，不是拿到"干净 PE"**。

| 手法 | 工具 | 产出 |
|---|---|---|
| 内存补丁 | x64dbg 直接改内存 / `seep_mem_strings` 定位字符串 | 验证"改这一处能否放行" |
| API Hook | Frida / 代理 DLL | 拦截鉴权函数返回值 |
| 行为观察 | `seep_mem_strings` + `seep_pcap_extract` | 授权判定发生在哪一层 |
| 资源/内嵌载荷 | `seep_r2_cmd(binary_path="<当前目标绝对路径>", command="iR", analyze=false)` | 真正的功能体可能不在主 PE |
| 外部读 + 网络层 | `dump-restore.py dump` / 代理 / 回放 | 不注入也能拿到关键数据/协议 |

**完成判据**：对主域问题给出有证据的运行期结果及限制；运行期观察/补丁不能冒充可独立运行的脱壳产物，也不自动扩展为授权旁路。

---

## 四、常见壳的差异对待（别一把钥匙开所有锁）

| 壳 | 特征 | 正确打法 | 常见坑 |
|---|---|---|---|
| **UPX** | `.UPX0/.UPX1` + `UPX!` 串 | `upx -d` 一行搞定 | 改过头的 UPX（头损坏）要手工修 |
| **ASPack / MPRESS** | `.aspack/.adata`、`.MPRESS1` | 脱壳机或 ESP 定律 | 导入表常被压缩，需 Scylla 修 |
| **Themida / WinLicense** | `.themida/.winlice`、VM 段 | ScyllaHide + 尽量运行期 | 静态脱壳成功率低，别死磕 |
| **VMProtect** | `.vmp0/.vmp1` | **不追求脱壳**，走路线 B | 关键函数被虚拟化，dump 也无法还原语义 |
| **.NET 混淆（Reactor/Babel）** | `has_clr=true` | dnSpy/de4dot 反编译（外部）+ IL 还原 | 别用 PE 脱壳思路 |
| **自定义壳（自研）** | 无已知节名、熵高 | 资源剥离 + 内存 dump + 行为 | 优先找"第二段 PE" |

---

## 五、工具映射（缺了先探测，按能力表执行）

| 需求 | 调用 | 缺了怎么办 |
|---|---|---|
| 判壳/反调试 | `seep_packer_detect` | 注册不代表依赖就绪；失败时用静态 PE 线索，结论保留未知 |
| 段/熵/架构 | `seep_r2_info` / `dump-restore.py pe-info` | 前者需 r2；后者为标准库 PE 初检 |
| 仪器对照 | 当前目标基线与调试/注入/外部观测分别记录 | `tool-acquire.py --tool <id> --json` 仅证明工具状态，不代替对照 |
| 内存 dump | `dump-restore.py dump --pid N --out F` 或 `pe-sieve /pid N /dmode 3 /out D` | 外部 RPM 优先；pe-sieve 可 `seep_ensure_tool("pe-sieve")` |
| PE 重建 | `dump-restore.py rebuild --dump F --out G` | 纯标准库；清壳节为启发式 |
| IAT 现状 | `dump-restore.py iat --dump F` | 纯标准库；修复仍需 Scylla 人工 |
| 调试/断点 | x64dbg（**完整性壳用硬件断点**） | `seep_tool_discover("x64dbg")` → `plan_control`；探针矩阵先验证 |
| IAT 修复 | Scylla（外部） | 表外工具：只报路径 + 联网查文档，**不 `-h` 试探** |
| 反反调试 | ScyllaHide / TitanHide | 同上 |
| 解码字符串 | `floss` | 已进能力表（headless） |
| 资源载荷 | `seep_r2_cmd(binary_path="<当前目标绝对路径>", command="iR", analyze=false)` | 需 r2；资源枚举不等于载荷已导出 |
| 活体字符串 | `seep_mem_strings` | 内置（Windows） |
| 反编译 | `seep_r2_decompile` | 需 r2 及相应反编译后端；不可用时仅给反汇编/静态范围 |
| 抓包/回放 | `seep_pcap_extract` / `seep_http_replay` | 分别核对解析/重放依赖与范围；工具探活不证明已抓到目标流量 |

---

## 六、反调试速查（详见 `references/anti-debug.md`）

五类反调试与最小处置：

| 类别 | 典型特征 | 首选处置 |
|---|---|---|
| 静态 | `IsDebuggerPresent`、`NtGlobalFlag`、HeapFlags、TLS callback | ScyllaHide/TitanHide + TLS 阶段断点；清 PEB 字段 |
| 动态 | `NtQueryInformationProcess`、`CheckRemoteDebuggerPresent`、DR 检测、RDTSC、SEH/VEH | Hook API/固定时间；**完整性壳用 DR0–DR3**；异常按预期传递 |
| 页保护/自校验 | `PAGE_GUARD`、`MEM_MAPPED`、CRC、`0xCC` 扫描 | **外部 ReadProcessMemory**；不改被校验字节；patch 校验返回值 |
| 注入/挂钩 | 模块枚举找 `frida-agent`、inline hook 扫描、线程/堆/RWX 扫描 | 不注入/外部观测；改模块名；TitanHide；恢复 prologue |
| 环境 | VM 特征、用户名/机器名黑名单、驱动/反作弊、进程黑名单 | 换裸机/改环境；外部/网络层；不在反作弊机器上硬碰 |

**退出断点只是一种观测**：未命中不能证明没有反调试或静默失败。结合当前目标基线、功能、网络与退出行为判断；进程消失且断点未命中时，退出路径仍未覆盖。

---

## 七、报告模板（交付时照抄）

```markdown
## 脱壳结论
- 壳类型：<UPX/Themida/VMProtect/.NET/自定义>
- 判定门：Q1=<..> Q2=<..> Q3=<..> → 路线 <A/B/C>
- 仪器矩阵：baseline=<..> x64dbg=<..> frida-spawn=<..> frida-attach=<..> external=<..> network=<..>
- 七步执行：1 壳指纹 / 2 仪器 / 3 OEP / 4 dump / 5 重建 / 6 IAT / 7 干净机器
  - 完成到第 <n> 步；哪些判据满足、哪些被熔断（附证据）
- 产物：dump=<路径> rebuilt=<路径> IAT 修复=<日志> 校验=<熵/导入/启动/网络>
- 反调试处置：<用了哪些手法；ExitProcess 是否提前命中；有无静默失败>
- 对鉴权审计的影响：<可直接审计 / 仅运行期 / 转协议层 / 建议放弃>
- 未做与为什么：<如"VMProtect 关键函数虚拟化，静态脱壳无意义">
```

---

## 七bis、参考索引（逐篇）

| 文件 | 用途 |
| :-- | :-- |
| `references/packers-quickref.md` | 判壳证据链、壳指纹扩展表、熵/导入数值阈值、A 类解包 |
| `references/anti-debug.md` | 反调试判据手册（识别特征→探测点→绕过→失败判据）与三条铁律命令化 |
| `references/anti-debug-matrix.md` | AD/AV 编号矩阵、复合指纹、现象→编号检索、Evidence 机检表 |
| `references/oep-locate.md` | OEP 五法、熵时间序列、假 OEP 六特征、候选打分与记录模板 |
| `references/dump-and-rebuild.md` | dump 形态选择、差分稳定性、分段读、对齐修复、自检不变量 |
| `references/iat-repair.md` | IAT 范围推导、thunk 合法性校验、delay/bound/序号处理、复验三层 |
| `references/hw-observation.md` | 硬件断点预算、ETW/WPR、Intel PT、观测记录字段、失败判据 |
| `references/vm-bytecode.md` | VM 识别、跳转表提取、handler 工作表、解释器骨架、函数级还原 |
| `references/ace-and-commercial-walkthrough.md` | D/C 类（ACE/反作弊/商业壳）走查：M1–M4 上限、AC-n 失败判据 |
| `references/integrity-and-rollback.md` | 完整性对抗（CRC/自修复/服务端校验）与回滚设施/演练 |
| `references/lessons.md` | 本域踩坑台账 UL-n（现象/根因/动作/约束）、假进展识别、复盘模板 |

## 八、与其他技能的关系

- 判型入口为 `seep-router`，Windows PE 由主域按需要调用本技能；
- Android 侧壳/加固走 `apkseep`（DEX 脱壳、VMP 差分），本技能只管 **Windows PE**；
- 完成后将 dump/重建身份、步骤与未知返回主域；仅当前目标涉及许可时读 `Tool/skill/softseep/references/license-validation.md`；
- 当前项目目标与适用验收决定继续或停止，归档参考按需读取。

## 什么时候停（判废条件）

- 壳判定证据不足 2 条（只有熵高 / 只有畸形节名）→ 不算判出壳，回 `seep-router` 重判
- 反调试两击不清（同类检测连续两次命中且无法绕过）→ 停，报告"卡在 AD-x"，不上硬件层
- 安装内核驱动/修改整机反作弊配置按现行系统副作用边界处理；进程内 DR0–DR3 硬件断点属于调试动作，按已有目标运行/调试许可执行，不能误列为装驱动
- dump 出来的镜像 IAT 无法解析（导入表全 0 且无 Scylla 可用）→ 上限只到 M1（结构说明）
- 同一 dump 路线两次失败 → 换路线（OEP 法 ↔ 内存扫描），第三次仍失败即判废
