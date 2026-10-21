---
id: "windows/2026-themida-vm-bypass"
title: "Themida VM 函数级绕过：hook dispatch、走原生分支、失败回退脱壳"
title_en: "Themida VM Function-Level Bypass: Dispatch Hook, Native Branch, Unpack Fallback"
summary: >
  不脱壳、不修 VM，只针对被 Themida 虚拟化的单个函数：定位 VM entry 与 dispatch，
  hook 分派器、跳过 VM 段走原生分支，或用 Themidie 过反调试；失败时回退整壳 dump。
board: "windows"
category: "techniques"
signals: ["Themida", "VM dispatch", "VMEnter", "Themidie", "native branch", "WinLicense"]
mcp_tools: ["kb_router", "workspace_write_text"]
keywords: ["Themida", "VM bypass", "dispatch hook", "VMExit", "Themidie", "unpack"]
difficulty: "advanced"
tags: ["Themida", "VM", "anti-debug", "unpack", "windows"]
language: "zh-CN"
last_updated: "2026-10-20"
related_articles: []
---
# Themida VM 函数级绕过：hook dispatch、走原生分支、失败回退脱壳

> 出处：52pojie 2026-06-05《绕过 Themida VM 保护的函数（不需要脱壳、不需要修 VM）》。
> 目标不是还原 VM，而是让**单个被保护函数**返回业务结果；仅用于授权样本。

## 1. 边界与结论

Themida 把函数入口改成跳板：保存上下文 → 进入 VM → 取字节码 → dispatch 到
handler → `VMEXIT` 回原生代码。函数级绕过不修 handler、不重建字节码，只做三件事：

| 手段 | 改什么 | 何时用 |
| :--- | :--- | :--- |
| hook VM dispatch | 在分派器处记录/改 VIP | 需要观察 VM 执行到哪 |
| 跳过 VM 段 | 把 VIP 指向 `VMEXIT` 或原生分支 | 只关心函数返回值 |
| Themidie | 过反调试/隐藏调试器 | VM 前就被反调试杀掉 |

如果函数没有可用的原生孪生分支，或 VM 退出会破坏调用者栈，停止硬绕，回退到
第 7 节整壳 dump。**不要为了一个函数把整个 VM 重写。**

## 2. 判型

```powershell
diec.exe sample.exe
dumpbin /headers sample.exe | Select-String "themida|winlice|VM"
dumpbin /imports sample.exe | Select-String "VirtualProtect|GetTickCount|NtQuery"
```

```python
import pefile, math
pe = pefile.PE("sample.exe")
for s in pe.sections:
    d = s.get_data(); n = len(d) or 1
    ent = -sum((d.count(bytes([i]))/n) * math.log2(d.count(bytes([i]))/n)
               for i in range(256) if d.count(bytes([i])))
    print(s.Name.rstrip(b"\0"), hex(ent)[:6], hex(s.Characteristics))
```

判型：`.themida`/`.winlice` 高熵可写可执行、入口点在壳段、导入表有
`VirtualProtect`/`GetTickCount`/`NtQueryInformationProcess`；IDA 中目标函数只剩
一段跳向壳段的 stub。

## 3. VM entry 与 dispatch

典型布局（地址/偏移因版本而异，必须现场确认）：

```text
call target
  └─ stub: pushfq/push regs; mov ctx, ...; jmp VMEnter
       └─ VMEnter: 初始化 VM_CONTEXT；vip = bytecode
            └─ dispatch: handler = table[opcode]; call handler; loop
                 └─ VMEXIT: 恢复 regs; ret
```

需要现场确认的三个量：

- `vm_entry`：目标函数 stub 跳入壳段的地址；
- `dispatch`：`jmp/call [table+opcode*8]` 的分派器；
- `vip_off`：`VM_CONTEXT` 中指向当前字节码的偏移（对比两次 hit 的上下文即得）。

```text
bp <protected_func>
run
r
dq @rsp
; 单步进入 stub，记录 jmp 的壳段目标 = vm_entry
```

## 4. hook dispatch

### 4.1 观察

```js
const base = Module.getBaseAddress("sample.exe");
const dispatch = base.add(0x123456);          // <dispatch RVA>
Interceptor.attach(dispatch, { onEnter(args) {
  const ctx = args[0];                        // 以现场寄存器为准
  console.log("ctx", ctx, "vip", ctx.add(0x??).readPointer());
}});
```

若 `args[0]` 不是上下文，改看 `this.context.rcx/rdx`，或在 x64dbg 的 dispatch
断点处 `dq @rcx`、`dq @rdx` 对比两次命中，找出 VIP 槽。

### 4.2 跳过 VM 段

```js
// 把 VIP 直接指向 VMEXIT（或原生分支），让 dispatch 立即收尾
const ctx = ptr("0x...");                     // dispatch 处记录的上下文
Memory.writePointer(ctx.add(0x??), ptr("0x..."));   // <vip_off>, <vmexit>
```

```text
; x64dbg 等价：在 dispatch 命中后改 VIP 槽，再放行
bp <dispatch>
run
dq @rcx
; 在 dump 窗口把 VIP 槽改成 <vmexit>，然后 run
```

判据：`vm_entry_bypassed=true` 且 `native_branch_taken=true`——业务返回值出现，
调用者栈平衡（`rsp` 与进入前一致），没有走进 handler 循环。

## 5. 直接走原生分支

有些 Themida 版本为同一函数保留原生实现（授权/非授权、旧 CPU、特定参数分支），
或在 VM 前用条件跳转选择「虚拟化 / 原生」。

```text
; 在 VM entry 前的分支处下断
bp <pre_vm_branch>
run
r
; 若条件是“是否进入 VM”，强制走原生侧
; x64dbg: set eflags / set rip 到 <native_branch>
set rip, <native_branch>
run
```

判据：`native_branch_taken=true`，且 `native_branch` 地址不在壳段、执行的是正常
函数序言（`push rbp; mov rbp,rsp` 或 `sub rsp,imm`），不是另一个 VM stub。

## 6. Themidie 过反调试

Themidie 是 x64dbg 插件，用于隐藏调试器、修 Themida 常见反调试检查。先确认已加载：

```powershell
Get-ChildItem -Recurse .\x64dbg\release\x64\plugins -Filter *Themidie*
Select-String .\x64dbg\release\x64\x64dbg.log -Pattern "Themidie|Anti-Debug"
```

在 x64dbg 菜单 `Plugins -> Themidie` 启用 Anti-Debug/Hide，再附加目标；日志出现
插件加载和 bypass 记录才算生效。插件不可用时用 ScyllaHide 的对应 profile 替代，
但不要同时开两套隐藏驱动——会互相暴露。

判据：附加后不再在 VM entry 前退出；`NtQueryInformationProcess`/
`NtSetInformationThread` 的检测分支走正常路径，而不是直接 `ExitProcess`。

## 7. 失败回退：整壳 dump

函数级绕过失败（无原生分支、VM 退出破坏栈、反调试无法过）时，停止硬绕：

```powershell
procdump64.exe -accepteula -ma sample.exe out\sample.dmp
pe-sieve64.exe /pid <pid> /out out /imp 3
```

然后在 x64dbg 到 OEP，用 Scylla dump + 修 IAT；或对 `out\sample.dmp` 做
`pe_unmapper` + 导入重建。回退判据：dump 能启动、IAT 调用不跳 0、目标函数可读。

## 8. 判据字段

| 字段 | 取值 | 证据 |
| :--- | :--- | :--- |
| `vm_entry_bypassed` | `true/false` | 目标函数未进入 handler 循环即返回业务结果 |
| `dispatch_hook` | `module+0x...` / `null` | 分派器地址与命中次数；Frida/x64dbg 日志 |
| `native_branch_taken` | `true/false` | 原生分支 RVA 与执行到的函数序言 |
| `fallback_unpack` | `true/false` | dump 路径、OEP、IAT 修复结果、dump 哈希 |

## 9. 失败判据

| 现象 | 判定 | 改走哪条 |
| :--- | :--- | :--- |
| `dispatch_hook` 从不命中 | 分派器地址错/VM 走另一条路径 | 回到 VM entry 重新单步，别猜 |
| 改 VIP 后崩溃 | `vip_off` 错或 VMEXIT 需要额外上下文 | 用两次 hit 对比上下文，或回退脱壳 |
| 原生分支不存在 | 该版本全虚拟化 | 放弃函数级，走第 7 节 |
| 附加即退出 | 反调试在 VM 前 | 先 Themidie/ScyllaHide，再谈 hook |
| dump 起不来 | OEP/IAT 错或壳自校验 | 换 dump 时机；两次失败即停 |
| 只对当前参数有效 | 绕过了分支而非函数 | 记录参数，改走通用脱壳 |

## 10. 出处与延伸

- 52pojie（2026-06-05）《绕过 Themida VM 保护的函数（不需要脱壳、不需要修 VM）》，
  `https://www.52pojie.cn/`（站内检索标题）。
- 反调试决策：`Tool/skill/softseep/references/10-anti-debug.md`；
  整壳 dump 流程见 `Tool/mcp/Tool/reverselab/kb/pe-reverse/techniques/05-crypto-unpack/01-pe-unpack-dump.md`。
