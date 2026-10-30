---
name: softseep
description: "分析这个 exe/dll/sys/so/elf/dylib/软件/程序/这是什么壳/有没有加固/能不能改/能不能打补丁/做成源码级 (.exe/.dll/.sys/.so/.elf/.dylib/.bin，含 .NET/Go/Rust/Electron/wasm/Unity-PC)。通用二进制（PE/ELF/Mach-O）逆向与补丁手艺；判型与上限见 seep-router。 这软件要卡密怎么绕过/授权校验在哪。"
license: MIT
compatibility: Windows 10 / Windows 11 x64 为主。支持 Python 3.8+，搭配 C/C++ 编译器（Zig/MSVC）或 radare2/IDA Pro 逆向套件。跨平台等价路径见 `references/license-validation.md` §1 平台对照表。
metadata:
  role: domain
  references_dir: skills/softseep/references/
  last_split_pass: "2026-09-23"
---

# softseep — 通用二进制域（PE / ELF / Mach-O / .NET / Go / Rust / Electron / wasm）

> **本文件是「通用二进制」这一个域的手艺**（不是域入口）。判型/选域/上限在 `seep-router`；本文件只讲 PE/ELF/Mach-O（含 .NET/Go/Rust/Electron/wasm）具体怎么做。

---

> **判型 / 选域 / 上限（M1–M4）/ 必问三件** → 见 `Tool/skill/seep-router/SKILL.md`（唯一口径）。本文件只讲**通用二进制（PE/ELF/Mach-O/.NET/Go/Rust/Electron/wasm）**的具体手艺。

## 🧭 本领域专业子技能导航（Sub-Skills Index）

本域相关子技能放在 `subskills/` 目录中（按需读取，零预载）。当任务具备以下特征时，按路径加载对应子技能：

| 技能名称 | 核心功能与解决的问题 | 触发场景 / 适用特征 | 所属相对路径 |
| :--- | :--- | :--- | :--- |
| **exe-reverse** | Windows PE 深度分析、节区重排、IAT 修复、特征码滑窗扫描、补丁回读断言 | 分析 `.exe`/`.dll`、遇反分析代码、需要精准补丁断言 | `subskills/exe-reverse/SKILL.md` |
| **multiver-aob** | 多版本 AOB 共同稳定区自动计算、汉明距离定位、双态唯一性 1/1 强校验 | 软件升级导致代码非均匀漂移、需要输出跨版本特征码 | `subskills/multiver-aob/SKILL.md` |
| **ida-reverse** | IDA Pro 无缝协同、反编译伪代码提取、交叉引用分析 | 复杂控制流平坦化、函数级深入语义分析 | `subskills/ida-reverse/SKILL.md` |
| **binary-diff** | 跨版本二进制差分比对、函数匹配、符号迁移 | 补丁分析、版本差异定位 | `subskills/binary-diff/SKILL.md` |
| **license-bypass**| 客户端授权逻辑识别、卡密弹窗跳过、本地凭据状态定位 | 绕过注册框、去除试用期锁定 | `subskills/license-bypass/SKILL.md` |
| **unpack-pe** | Windows PE 判壳脱壳、OEP 唯一定位、转储与 IAT 修复 | UPX/ASPack/加密壳识别、内存转储、修复损坏导出/导入表 | subskills/unpack-pe/SKILL.md |

## 调度总流程

```
用户说大白话（不需要懂术语、不需要选类型、不需要指定平台）
  → ① G-Auth 授权门              （能不能测）
  → ② seep-router 按用户目标与材料选主辅域
        · 本域只确认二进制平台、保护及当前问题
        · 项目登记与接续按 router 第 5 步；需要时调用子技能
  → ③ 找对应 reference / MCP 工具（本域内）
  → ④ 执行 → 三段式报告
```

### ③bis-0 副作用层级（动手前第一条，比判型更早）

**判"能不能做"，不判"命令长什么样"；等价做法同层同禁**（换个名字绕不改性质）。

- **L0/L1 可写**：目标文件（case/work 目录）、进程内存 —— 逆向唯一该动的地方。
- **L2 可做先备还原**：HKCU 单键、**仅对该进程**生效的代理/环境变量。
- **L3 不做**：网卡 IP/路由/DNS/全局代理、`iptables·nft·pf` NAT、**系统 hosts**、驱动、服务、引导、
  防火墙、策略、计划任务、系统信任根、HKLM —— 出事要重装或重启。
- **L4 不做**：分区、格式化、删卷影、清事件日志。

命中 L3/L4 **不是甩一句"规则禁止"**，按序答：① 说清工程后果（整机副作用 + 回滚代价）→
② 给同目的的低层做法（进程内 hook / 进程级参数 / 整机丢 VM）→ ③ 给能到哪一级（M1–M3）→
④ 当前路线确需系统改动时保留静态结果，说明所缺环境与用户侧条件。
**不给系统改动的执行路径**；现有进程级通道需核实际副作用和当前 scope。
细则：`AGENTS.md` §四点五 第 9 条；接管假服务端三档见 `references/license-validation.md` §5.3。

**三条铁律**：
1. **门控不可绕过** —— 先 G-Auth，再按 router 的判型结论走；本域内的方法按需加载；
2. **判型归 `seep-router`，本文件不重复** —— 用户说大白话，由 router 归类；
   **绝不把"请选择平台/类型"的选择题甩回给用户**；
3. **判型不可跳过** —— 不先判平台与类型就开工 = 违规（错平台代价是整轮工作作废）。

---

## 【G-Auth】授权门 —— 指针

> **唯一事实源：`Tool/prompts/AGENTS.md` §六 + 扩展注入的边界锚。本节不重复规则正文。**
> 已授权的工作区产物写入、已有工具和任务必要操作自主执行；运行客户目标及整机副作用按现行规则处理，不把每次文件写入另设许可门。

## 范围与路由（边界）

**本域输入面**：已授权的 Windows PE / .NET / Go / Rust / Linux ELF / macOS Mach-O / ARM64 客户端；授权校验、补丁本地化、脱壳、算法还原、协议分析、样本研判、UI 显示层、加固对抗、逆向测绘。

**相邻域与路由**：

> 载体→域 的映射**只看一处**：`Tool/skill/seep-router/SKILL.md`（本文件不再复写）。
- 加壳脱壳闭环 → `Tool/skill/unpack-loop/SKILL.md`（脱壳闭环）（本技能只做判型、判据与补丁；反调试识别见 `references/10-anti-debug.md`，脱壳流程见那卷）。
- 生产环境与真实用户数据按 `scope` 清单执行；凭据外泄一律停并上报。

**边界**：本技能默认目标是**受权沙箱资产**；仅当用户明确声明「不属于我 / 没有授权」时停在门口确认一次。操作边界按上述 G-Auth 指针，不重复索取已有授权。

---

## 配方（照这个跑）

输入面命中下面某行时，先照该配方的命令序列跑，再回来对判据；配方正文只在 playbooks 一处，本文件只指路。

- 卡密/授权旁路并交付可用成品 → `Tool/playbooks/license-bypass-deliver.md`
- 接自有授权平台（离线公钥验签 / 在线票据）→ `Tool/playbooks/license-hookup.md`
- UI 改版去品牌（EXE / APK）→ `Tool/playbooks/ui-rebrand.md`
- 软件更新后的跨版本追版（AOB 滑窗）→ `Tool/playbooks/version-migrate.md`
- 开工前的逆向测绘 / 壳与权威判定 → `Tool/playbooks/reverse-survey.md`
- 反作弊驱动的兼容性分析（驱动侧）→ `Tool/playbooks/anti-cheat-forensics.md`
- 固件仿真里的环境副作用记账 → `Tool/playbooks/firmware-emulate.md`
- .NET / Electron 插件与 asar 拆解 → `Tool/playbooks/plugin-analysis.md`

## 上限怎么说（对客户）

- **只能看懂结构**：`只告诉你它是哪个壳/哪种保护（或本地校验还是服务端校验）、关键判定大概在哪个函数，原件一个字节没动`
- **能改到能用**：`改完能跑、原功能还在：补丁字节能回读、目标行为真的变了、进程过了两个心跳，原件哈希未变`
- **能完全自己接管**：`授权/算法这条链你能自己接手：独立实现 N≥10 组输入输出一致，客户端接受你新生成的值、拒绝错的`
- **卡点通常是**：`权威在服务端（有在线校验/卡密），或者目标带反作弊/反调试驱动——本地补丁改不出服务端授权`

> 依据：本文件 判据表（授权权威/补丁生效/壳是否脱掉/算法还原）+ 范围与路由（相邻域与路由）

## 前置检查（3 件）

1. **目标指纹**：记录路径代号、SHA256、架构/位数、版本、签名状态；没有指纹的结论不可复算。
2. **判型预检**：有本地样本先跑 `python Tool/skill/softseep/scripts/preflight-classify.py <path> --hint`，把 `platform/type/protection` 并入判型。
3. **证据出口**：准备 `work/<task>/exports/` 或案例 `artifacts/`，约定命名（hash/offset/log）；先想好证据怎么落盘，再动手。

---

## 判据表（本域 6 类）

> 完整表见 `references/01-criteria.md`；这里只给「确认」与「疑似」的分界。
> **确认** = 两条独立证据、可复算；**疑似** = 单条线索/未复现，只能写「疑似」。

| 类别 | 确认（可机检） | 疑似（降级） |
| :--- | :--- | :--- |
| 授权权威 | 断网/联网对照 + 签名/会话令牌证据；本地状态字或服务端签名至少一条闭环 | 只看到本地许可文件/只看到网络请求 |
| 补丁生效 | 回读目标 RVA 字节 = 补丁值；目标行为变化；进程存活 ≥2 个心跳周期 | 只看到注入器返回 0 / 只看到日志「成功」 |
| 壳是否脱掉 | 候选入口的控制流/初始化与恢复代码语义对应；导入、映射及剩余壳依赖已核，dump 来源可追；独立运行另验功能 | 只有原节名、固定 prologue、可反汇编或目标能启动 |
| 算法还原 | 独立实现 N≥10 组输入输出一致；客户端接受新生成值、拒绝错误值 | 同源 Generate/Verify 互验通过；只测一组 |
| 结构/符号 | PE/ELF/Mach-O 头与节/段自洽；PDB GUID/Age 匹配；RTTI/vtable 有构造函数证据 | 只有 `sub_xxx` + 一条字符串；FLIRT 低置信命中 |
| 动态观测/反调试 | 基线 vs 仪器行为差异可复现；改一个检测点后目标继续且无二次检测 | 只 attach 一次成功/失败；只改一个 API 返回值 |

**使用**：先选行，再按「确认」列准备最小输入；如果只能拿到「疑似」列，结论必须降级，不能写「已绕过/已脱壳/已还原」。

---

## 失败判据（看到即降级/换路）

> 完整表见 `references/02-failure-criteria.md`；这里只列高频十条。

| 现象 | 判定 | 改走哪条 |
| :--- | :--- | :--- |
| 改完立刻崩（0xC0000005/0xC0000374） | 等长/重定位/栈平衡破坏 | 等长改写；trampoline；只改条件跳转 |
| 补丁后几秒到几十秒才崩 | 跳过初始化/守护回写 | 保留原函数体；改判据分支/状态字 |
| 字符串全乱码 | 加密/压缩未解 | 先脱壳/等 OEP 后 dump |
| 反编译只有 dispatcher | VM/强平坦化 | 运行期取功能/取载荷；patch 判定点 |
| 断网即失效，联网恢复 | 服务端权威/心跳覆盖 | 协议层：抓包/中继/端点接管 |
| 只改 UI 或 `license_type` 无效 | 状态源未找到 | 重建鉴权链路；找真正状态字 |
| 一 attach 就退，换调试器仍退 | PEB/API/TLS 反调试 | 先识别检测层；两次失败就停 |
| 下 `0xCC` 就崩 | 代码段 CRC/int3 扫描 | 硬件断点/外部读/Intel PT |
| 补丁后签名/校验失败 | 未重算/未处理签名 | 重算 checksum；明确签名策略 |
| keygen 生成码被拒 | 归一化/签名/第二校验 | 独立实现逐字符对照；查自引用 |

**三条熔断**：同形失败 2 次或连续无新增证据时换正交路线；内存补丁累计崩 2 次停手；attach 被反调试打掉 2 次先过反调试。

---

## 模型常见失误（≥8 条，详见 `references/03-model-pitfalls.md`）

1. **把 x64 前 4 个参数当栈传** → Win64 前 4 个在 `RCX/RDX/R8/R9`，栈上是影子空间 → 按寄存器读，第 5 个起 `[rsp+0x28]`。
2. **把 `mov rax,[rcx]` 当虚表调用** → 可能只是首字段/d-pointer → 看构造函数、`.rdata`、RTTI 再下结论。
3. **DllMain 中做复杂初始化/跨堆写 BSTR** → loader lock/堆损坏 → 保持最小初始化，将工作移到加载完成后的显式入口；创建线程也有风险，不能当通用补救。见 [Microsoft DLL 最佳实践](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices)。
4. **只改 UI 不改 `license_type`/状态字** → UI 是消费者，重启/心跳回退 → 找当前目标的状态源；案例地址只在该案例有效。
5. **补丁后不重算校验和/不处理签名** → 自检/签名失败 → manifest + checksum + 签名策略。
6. **把「能运行」当「壳已脱掉」** → 仍可能依赖壳/动态导入 → 按 `subskills/unpack-pe/SKILL.md` 核控制流、映射、导入与剩余依赖；节名/序言不是必要判据。
7. **反调试未过时反复裸 attach** → 触发自毁/污染证据 → 两次失败就停，先识别检测层。
8. **`jmp rel32` 少算 5 字节 / `call [rip+x]` 按当前指令算** → 跳飞 → `disp = target - (addr + insn_len)`。
9. **用绝对 VA 写补丁忽略 ASLR** → 换次启动就崩 → 文件用 RVA/偏移，内存用 `base + RVA`。
10. **把 `ret` 当万能补丁** → 跳过初始化/延迟崩 → 优先改条件跳转/状态字；trampoline 保留原函数。
11. **同源 keygen 自验通过就交付** → 共享错误被掩盖 → 用客户端黑盒 + 独立实现交叉验证。
12. **ARM64 套 x64 调用约定** → 参数/返回地址全错 → 按 AAPCS64 读 `X0–X7`、`X29/X30`。

---

## 流程（分阶段，每阶段有完成判据）

| 阶段 | 动作 | 完成判据 |
| :--- | :--- | :--- |
| S0 判型 | 平台/类型/保护/权威四问；跑 preflight | 判型行写出，保护指纹有证据 |
| S1 结构 | PE/ELF/Mach-O 头、节/段、导入/导出、资源 | 结构 JSON/表落盘；异常节/高熵有记录 |
| S2 静态 | 符号/函数图/字符串/常量/调用图 | 关键函数有 RVA + 命名依据 + 反编译片段 |
| S3 动态 | 基线/断点/Hook/Procmon/网络 | 基线 vs 仪器行为差异可复现 |
| S4 保护 | 壳/VM/反调试/完整性自检 | 脱壳或运行期取功能判据成立；不成立写卡点 |
| S5 授权/算法 | 状态源、验签、算法、keygen/patch 路线 | 路线四分决策 + 证据；失败按 02 换路 |
| S6 补丁/交付 | manifest、等长、校验、回滚、回归 | `patch-verify.py` 通过；功能/稳定/回滚三测 |
| S7 报告 | 12 节骨架 + 证据分级 + 边界 | 每个结论能指到证据文件/命令/哈希 |

---

## 【前置门控】开测四问与七道门（许可/激活/卡密类目标优先过此关）

> 完整细节见 `references/license-validation.md`。本节只保留**决策所需的门控与路由**。
> **原则**：先定权威归属，再选打法。门是通用骨架，案例仅示范一条路径。

### 开测即答的「四问」（任何客户端通用）

| # | 问题 | 为什么问 |
|---|---|---|
| ① | **权威在哪** —— 校验是服务器审核，还是纯本地判定（离线许可/签名验证）？ | 决定"能不能本地改完就赢" |
| ② | **本地能否完成握手** —— 能**伪造成立**，还是**只能中继**上游？ | 决定结论措辞，防把"能中继"吹成"已绕过" |
| ③ | **有无捷径** —— 后门 / 调试开关 / 环境变量 / 隐藏参数？ | 零成本路径，先试再打补丁 |
| ④ | **功能是否与校验分离** —— 真功能能否脱离校验单取即用（DLL/脚本/资源）？ | 指向**性价比最高**的一路（取载荷），最常被忽略 |

### 七道门（G0–G6）

> **只在这一处定义**：`Tool/skill/softseep/references/license-validation.md` §0「执行顺序门」。
> 本文件不再复制表格（上一版两份逐字重复，已合并）。做授权/卡密类目标时按 R2 → `subskills/license-bypass/SKILL.md`（阶段① 授权旁路），
> 由它在需要时加载该参考卷。

### 门 → 决策树映射

> 同样只在 `references/license-validation.md` §0 定义（本文件不复制，避免两份漂移）。

### 通用禁令

> 同样只在 `references/license-validation.md` §0 定义（「未过 G2 不得批量改内存」等五条）。
> 本文件不复制，避免两份漂移。

### 退出/升级判据（防死磕）

- 同形失败 **2 次**或连续无新增证据 ⇒ 挂起转下一路（竞速类"必输"路径直接放弃）；
- 内存补丁累计崩 **2 次** ⇒ 停改内存，转网络层；
- 金样回放连续静默退出 ⇒ 判会话绑定，转中继；
- 三大路径（离线改 / 回放 / 中继+取载荷）全不通 ⇒ 记为**"现象级 / 需人工深逆"**，附**已排除项**与证据，**勿无限重试**。

---

## 参考索引 —— 何时加载哪个 reference

> **按需加载，不预先全读。** 判型后只加载对应文件。

- **开头必看**：`01-criteria.md`（选场景/可机检判据，§6 PE/ELF/Mach-O 判型走查）、`03-model-pitfalls.md`（26 条错误动作 + 判型自检）
- **卡住/崩**：`02-failure-criteria.md`（按现象换路，三条熔断）
- **平台/补丁**：`windows-sop.md`（补丁/脱壳/代理 DLL/UI 验收）、`07-disassembly-deep-read.md`、`09-patch-engineering.md`
- **授权/许可**：`license-validation.md`（16 节全量手册）
- **对抗**：`10-anti-debug.md`（反调试/反 VM 决策）、`08-symbol-recovery.md`（PDB/GUID/FLIRT/RTTI）
- **照案例复跑**：`04-walkthrough-project-a.md`

### MANUAL/ 战术手册索引（按需查阅）

> MANUAL/ 存放深度专项 SOP，由 Agent 在触碰对应信号时主动加载。

| 手册 | 触发条件 | 核心内容 |
| :--- | :--- | :--- |
| `MANUAL/ANTI-DEBUG.md` | G0/G1 检测到 `IsDebuggerPresent`、`NtQueryInformationProcess`、驱动级检测、时序反调试等信号 | 全量反调试绕过字典、代理 DLL 打桩框架、内核层 SOP 与两击熔断规则 |
| `MANUAL/UNPACKING.md` | G0/G1 检测到 `MPRESS/UPX/Themida/.vmp` 节名，或 `seep_auto_triage` 熵值 > 7.2 | 壳类型速查表、OEP 定位三策略、Scylla 内存 Dump 全流程、VMP 动态 trace 路线 |
| `MANUAL/POC-VALIDATION.md` | G4/G5 生成 PoC 后（Frida 脚本 / Smali 补丁 / 代理 DLL）必读 | 三阶段闭环验证模型、Frida 自愈映射表、Smali/DLL 本地加载器、断网铁证流程 |
| `MANUAL/IDA-PRO.md` | 用户询问 IDA Pro 接入或 ida MCP 无法启动时 | IDA 安装配置、install-ida.ps1、Radare2 降级路线 |
| `MANUAL/PREREQUISITES.md` | 首次部署或环境报错时 | Python/Node/JDK/ADB 版本要求与修复指引 |
| `MANUAL/PROMPT-LAYERS.md` | 要改提示词 / 换人格卡 / 排查「人格与规则打架」时 | 五层装配顺序（实测坐标）、人格卡兼容矩阵、迁出内容存档、G-Auth 统一裁决 |

### 快速对应

| 你要做的事 | 加载 |
| :--- | :--- |
| 打内存补丁 / 写代理 DLL | `windows-sop.md` + `references/07-disassembly-deep-read.md` |
| 判"该走补丁还是算号" | `KB 11-project-paradigms/01-project-patterns-a-j.md`（九型 + D2.5 三问） |
| 许可/激活/卡密专项 | `license-validation.md` |
| 出加固方案 | `references/windows-sop.md` §纵深防御 |
| UI 文案/状态验收 | `KB 14-ui-verification/01-ui-acceptance.md` |
| 找现成脚本 | `references/windows-sop.md` §工具 |

---

## 脚本用法

```bash
# 判型预检（只读；--hint 一行喂给判型）
python Tool/skill/softseep/scripts/preflight-classify.py <sample> --hint
python Tool/skill/softseep/scripts/preflight-classify.py <sample>

# 案例验收：复算 artifacts sha256 / refs 存在 / 补丁清单完整性
python Tool/skill/softseep/scripts/reverse-accept.py
python Tool/skill/softseep/scripts/reverse-accept.py --case Tool/cases/项目A

# 补丁验收：等长/偏移/补丁后哈希/回滚
python Tool/skill/softseep/scripts/patch-verify.py --file app.exe --manifest patch.json
python Tool/skill/softseep/scripts/patch-verify.py --file app.exe --manifest patch.json --out app.patched.exe
python Tool/skill/softseep/scripts/patch-verify.py --file app.exe --manifest patch.json --out app.rolled.exe --rollback
```

三个脚本都支持 `--help`（rc=0）与 `--self-test`（离线 rc=0，输出含 `"ok"`）；失败一律输出 `{"ok": false, "blocked_at": ..., "reason": ...}` 且 rc=2。

---

## 任务卡入口

- 24 张任务卡：`Tool/prompts/domains/softseep.md`（源名取自 `Tool/config/taskcard-sources.json` 的 `softseep` 列表）
- 每卡六段：触发词 / 前置 / 步骤 / 判据 / 失败判据 / reference；按卡名或触发词选卡。

---

## KB board 入口

- Board 索引：`Tool/mcp/Tool/reverselab/kb/pe-reverse/README.md`
- 逐篇技术索引：`Tool/mcp/Tool/reverselab/kb/pe-reverse/README.md`
- 失败判据（KB 版）：`Tool/mcp/Tool/reverselab/kb/pe-reverse/techniques/15-decision/failure-criteria.md`
- 内存数值/指针链、ESP/W2S/Overlay：按目标读 `Tool/mcp/Tool/reverselab/kb/general/techniques/cheating/01-memory-hacking.md` 或 `Tool/mcp/Tool/reverselab/kb/general/techniques/cheating/03-esp-wallhack-rendering.md`；先分客户端/服务端权威，再核当前工具、地址生命周期、功能与恢复证据，不照搬其中系统级路线。
- Unreal 平台交接：`Tool/mcp/Tool/reverselab/kb/apk-reverse/techniques/02-native/03-ue4-offset-hunting.md` 是 UE4 移动端参考，Android 由 apkseep 主导；不能据此宣布 PC/UE5 全版本已验证。
- ELF/JVM 运行时线索：`Tool/mcp/Tool/reverselab/kb/re_pattern_elf-analysis.md`、`Tool/mcp/Tool/reverselab/kb/re_pattern_languages-compiled.md`；先核架构/构建及实际工具，资料存在不代表完整 ELF 重建或 JAR 重包运行已验收。
- 项目范式 A–J：`.../techniques/11-project-paradigms/01-project-patterns-a-j.md`
- 报告骨架：`.../techniques/13-report-template/01-report-skeleton.md`
- UI 验收：`.../techniques/14-ui-verification/01-ui-acceptance.md`

---

## 领域协作

主辅域由 router 与正式 pack 注册表提供候选，Agent 按目标裁定；物理目录不是调用禁区。子技能可借辅域，资产身份、原始安全输出、已证/未知与结果返回同一 project/version/run。只做当前目标需要的阶段；方法存在、工具就绪和真实任务见证分别报告，不以子技能库存提升成熟度。真实凭据/Token/Key/Salt/私钥由用户操作，不进入 Agent；参考中的秘密提取或系统改动不作为当前执行指引。

**子技能（按需读，不常驻）**：见正文顶部【子技能导航表】，按需读取 `subskills/exe-reverse`、`subskills/multiver-aob`、`subskills/ida-reverse`、`subskills/binary-diff`、`subskills/license-bypass`。
