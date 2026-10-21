---
name: unpack-loop
description: 加壳软件脱壳与内存转储闭环。当目标是加壳/加密壳/虚拟机保护（UPX、ASPack、Themida、VMProtect、Enigma、.NET 混淆壳等），或需要判断"这个壳值不值得脱、能不能继续做白盒鉴权审计"时使用。先判壳再选路线（可脱 / 只能运行期打补丁 / 建议放弃），每阶段有完成判据与两次熔断，绝不硬走固定流程。
license: MIT
compatibility: Windows 10/11 x64（主力）；Linux ELF 加壳可走 pe-sieve 替代路线。依赖 seep MCP + 可选 x64dbg / pe-sieve / Scylla / ScyllaHide。
metadata:
  version: "1.0.0"
  category: unpacking
  hard_gates: "两次熔断 / 判据驱动 / 禁止 -h 试探"
---

# unpack-loop — 脱壳与内存转储闭环

> **本技能只回答一件事**：这个目标**能不能脱、该怎么脱、脱完能不能继续做鉴权审计**。
> 它**不是**一条必须走完的八步流水线 —— 壳的种类决定路线，硬走会浪费时间、甚至把靶机搞崩。

---

## 〇、铁律（先看，违反即停）

1. **判据驱动，不是步骤驱动**：每阶段只问"完成判据满足了吗？"，不满足就升级/换路线，**不硬推**。
2. **两次熔断**：同一阶段同类尝试失败 **2 次** → 停，汇报，换路线或退出，禁止第三次变种。
3. **禁止 `-h` / 无参试探**任何调试器/壳/目标二进制（会崩、会触发自毁）。
4. **先快照后动手**：VM 快照 + 目标目录备份；**单变量**（一次只改一处）。
5. **联网优先隔离**：发现外连先用 `seep_pcap_extract` 看端点，避免"一启动就上报"。

---

## 一、入口判定门（必须先过）

用 `seep_packer_detect <target>`，拿到：节名/节熵、反调试导入、反 VM 字符串、是否 CLR。
再回答三个问题：

| 问题 | 取值 | 影响 |
|---|---|---|
| Q1 壳类型 | 压缩壳（UPX/ASPack/MPRESS）/ 加密壳（Themida/Enigma）/ 虚拟机壳（VMProtect/.NET Reactor）/ 仅混淆（.NET/JS） | 决定路线 |
| Q2 反调试强度 | 无 / 用户态（IsDebuggerPresent、PEB、时钟）/ 内核级（反附加、驱动保护） | 决定要不要 ScyllaHide/TitanHide |
| Q3 权威在哪 | 纯离线 / 有外连（云端授权） | 决定"脱了值不值" |

**判定门输出（三选一，写进报告）：**

| 路线 | 条件 | 目标 |
|---|---|---|
| **A 可脱** | 压缩壳 / 加密壳且反调试可绕 | 拿到可分析的 dump，回主线做鉴权审计 |
| **B 只能运行期** | 虚拟机壳 / 反调试过强 / dump 后不可重建 | **放弃完整脱壳**，改内存补丁 / API Hook / 行为观察 |
| **C 建议放弃** | 壳+联网权威+关键逻辑全在云端 | 转协议层（`seep_pcap_extract` + `seep_http_replay`）或直接给结论 |

> **裁定权归 `00-analysis`**：本技能只回答"**能不能脱、脱了有没有用**"。Q3（权威在哪）与 C 路线（建议放弃）
> 是**给阶段零裁定的输入**，不是本技能自己下的结论；"值不值得继续做成品"由 `case_state.py verdict` 定
> （可赢 / 部分可赢 / 不可赢）。阶段零未出裁定时，本技能只输出 A/B/C 的技术判断 + 证据。

> **不做无意义的脱壳**：如果鉴权判定在云端，脱壳再完美也拿不到结论 —— 这是最常见的时间黑洞。

---

## 二、路线 A（可脱）—— 阶段图 + 完成判据

> 阶段之间有**回退边**：某阶段判据不满足，可退回上一阶段换手法，但受"两次熔断"约束。

### A1 判壳确认
- 动作：`seep_packer_detect` + `seep_r2_info`（看入口段、节名、熵）
- **完成判据**：能说出壳名/家族 + 入口所在节 + 是否 CLR
- 失败升级：判不出 → 用 `seep_pe_resources` 找内嵌载荷（有些"壳"其实是资源里的第二个 PE）

### A2 反反调试
- 动作：ScyllaHide / TitanHide（外部，动态探测路径后调用）；或用 `seep_r2_strings` 定位反调试字符串后静态 patch 掉检测
- **完成判据**：调试器能附着且目标不退出、不重启、行为不降级
- 失败升级：内核级保护 → 直接切 **路线 B**

### A3 定位 OEP
- 手法（按成本排序）：ESP 定律 → 内存写断点（`.text` 段）→ 硬件断点 → 单步跟
- **完成判据**：`seep_r2_disasm` 在 OEP 处能看到**像正常编译器生成的序言**（`push ebp/mov ebp,esp` 或 `sub rsp,`）+ 导入表引用
- 失败升级：2 次找不到 → 切 **路线 B**（不追求 OEP）

### A4 内存 dump
- 动作：`pe-sieve /pid <pid> /dmode 3 /out <dir>`，或 x64dbg + Scylla 插件 dump
- **完成判据**：dump 文件能被 `seep_pe_resources`/`seep_r2_info` 正常解析（不是全 0、节表合理）
- 失败升级：dump 出来熵仍 >7 且无导入 → 说明还没到 OEP，回 A3

### A5 IAT 修复
- 动作：Scylla（x86/x64）自动搜索 + 手动补；或脚本重建
- **完成判据**：`seep_r2_functions` 里能看到成组的 `sym.imp.*`；dump 可被加载器接受
- 失败升级：IAT 大量缺失且无规律 → **路线 B**

### A6 校验与回归
- 动作：节熵对比、导入表数量、能否启动、`seep_packer_detect` 复测是否还判为壳
- **完成判据**：目标能启动到主界面/主逻辑 + 熵显著下降 + 反调试特征消失
- **交付物**：`work/<task>/exports/` 下 dump、IAT 修复日志、校验报告

### A7 回到主线
- 转 `seep_decompile_auto` 反编译 → 判鉴权模型 → 决定 patch / keygen / relay
- **完成判据**：能定位到授权判定函数或网络校验点

---

## 三、路线 B（只能运行期）—— 不脱壳也能交付

> 适用：VMProtect / Themida 强保护 / 内核反调试 / dump 不可重建。**目标是拿到"结论"，不是拿到"干净 PE"**。

| 手法 | 工具 | 产出 |
|---|---|---|
| 内存补丁 | x64dbg 直接改内存 / `seep_mem_strings` 定位字符串 | 验证"改这一处能否放行" |
| API Hook | Frida / 代理 DLL | 拦截鉴权函数返回值 |
| 行为观察 | `seep_mem_strings` + `seep_pcap_extract` | 授权判定发生在哪一层 |
| 资源/内嵌载荷 | `seep_pe_resources` | 真正的功能体可能不在主 PE |

**完成判据**：能给出"特权判定点 + 可复现的绕过方式（哪怕是运行期）"—— 这已经够交付。

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

## 五、工具映射（缺了先探测，禁止硬试）

| 需求 | 调用 | 缺了怎么办 |
|---|---|---|
| 判壳/反调试 | `seep_packer_detect` | 内置，永远可用 |
| 段/熵/架构 | `seep_r2_info` | 内置 |
| 内存 dump | `pe-sieve /pid N /dmode 3 /out D` | `seep_tool_install("pe-sieve")`（已收录绿色包） |
| 调试/断点 | x64dbg | `seep_tool_discover("x64dbg")` → `plan_control` |
| IAT 修复 | Scylla（外部） | 表外工具：只报路径 + 联网查文档，**不 `-h` 试探** |
| 反反调试 | ScyllaHide / TitanHide | 同上 |
| 解码字符串 | `floss` | 已进能力表（headless） |
| 资源载荷 | `seep_pe_resources` | 内置 |
| 活体字符串 | `seep_mem_strings` | 内置（Windows） |
| 反编译 | `seep_decompile_auto` | 内置（r2 保底） |

---

## 六、报告模板（交付时照抄）

```markdown
## 脱壳结论
- 壳类型：<UPX/Themida/VMProtect/.NET/自定义>
- 判定门：Q1=<..> Q2=<..> Q3=<..> → 路线 <A/B/C>
- 路线执行：A1..A7 哪些完成、哪些被熔断（附判据证据）
- 产物：dump=<路径> IAT 修复=<日志> 校验=<熵/导入/启动>
- 对鉴权审计的影响：<可直接审计 / 仅运行期 / 转协议层 / 建议放弃>
- 未做与为什么：<如"VMProtect 关键函数虚拟化，静态脱壳无意义">
```

---

## 七、与其他技能的关系

- 判型入口仍是 `softseep`（本技能由它的「脱壳/解包」类型分发进来）；
- Android 侧壳/加固走 `apkseep`（DEX 脱壳、VMP 差分），本技能只管 **Windows PE**；
- 脱壳完成后回到 `client-license-validation-bypass` 做鉴权审计。
