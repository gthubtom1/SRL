---
id: "windows/2026-cet-lacuna-pdata"
title: "CET 影子栈与 LACUNA Chain：用 .pdata 空洞构造假栈"
title_en: "CET Shadow Stack and LACUNA Chain: Fake Frames from .pdata Gaps"
summary: >
  Intel CET/KCET 影子栈使 return-address 伪造失效；LACUNA Chain 改用 .pdata
  RUNTIME_FUNCTION 空洞与 call-preceded gadget 构造结构合法的假栈，绕过 ETW-Ti
  与内核回调的栈回溯。给出影子栈、空洞、call-preceded、ETW-Ti 四类检测面。
board: "windows"
category: "techniques"
signals: ["CET", "KCET", "shadow stack", "LACUNA", ".pdata", "ETW-Ti", "stack spoof"]
mcp_tools: ["kb_router", "workspace_write_text"]
keywords: ["CET", "shadow stack", "LACUNA Chain", "pdata gap", "ETW-Ti", "call-preceded"]
difficulty: "advanced"
tags: ["CET", "stack-spoofing", "ETW-Ti", "windows", "kernel"]
language: "zh-CN"
last_updated: "2026-10-20"
related_articles: []
---
# CET 影子栈与 LACUNA Chain：用 .pdata 空洞构造假栈

> 出处：LACUNA Chain（0xmaz.me，2026-06）；SSTIC/BH 2026 影子栈与内核栈回溯分析。
> 仅用于已授权红队/防御验证；CET 开启时不要用裸 `ret` 伪造地址。

## 1. 结论

CET（用户态）与 KCET（内核态）把返回地址同时写入**影子栈**；`ret` 时硬件比较
普通栈顶与影子栈顶，不一致即 fault。于是「覆盖返回地址 → ret」的经典伪造失效。

LACUNA Chain 不再直接伪造 `ret` 目标，而是：

1. 在 `.pdata` 的 `RUNTIME_FUNCTION` **空洞**（未被任何函数区间覆盖的 RVA）里
   选返回地址；
2. 用 **call-preceded** gadget（地址前一条指令是 `call`）让帧看起来像真实调用；
3. 按 x64 调用约定拼出可被 unwinder/ETW-Ti 接受的假栈帧。

它主要骗过**栈回溯/ETW-Ti/内核回调**，不是无条件绕过 CET：CET 仍要求影子栈
与真实 `call` 对应，最终跳转要用 `jmp` 而不是伪造 `ret`。

## 2. 机制

```text
call f            ; CPU: push retaddr to normal stack + shadow stack
f: ... ret        ; CPU: compare [rsp] vs shadow_stack.top; mismatch -> #CP
```

- CET 用户态：`endbr64` + 影子栈；进程策略可用
  `PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY` 查询/关闭。
- KCET：内核栈也有影子栈，内核回调/ETW-Ti 的栈回溯受保护。
- `.pdata`：`IMAGE_DIRECTORY_ENTRY_EXCEPTION` 指向 `RUNTIME_FUNCTION[]`，
  每项 `{BeginAddress, EndAddress, UnwindInfoAddress}`；不覆盖的 RVA 就是空洞。
- ETW-Ti：`Microsoft-Windows-Threat-Intelligence` 在敏感 API 上做内核栈回溯，
  依赖 unwind 信息判断调用来源。

## 3. LACUNA 构造步骤

1. 解析 `.pdata`，得到所有 `[Begin,End)`；在 `.text` 内取补集，得到空洞列表。
2. 在空洞中选返回地址，要求目标字节前是 `E8 rel32` 或 `FF /2`（call-preceded）。
3. 构造帧：`[rsp]=retaddr`、`[rsp+8]=next frame`，保持 `rbp` 链与 16 字节对齐；
   每个假帧的返回地址都落在空洞内。
4. 控制流：每一跳用真实 `call` 进入 gadget，末跳用 `jmp`；不要用 `ret` 跳到
   影子栈里不存在的地址。
5. 只在目标线程/进程的 ETW-Ti 栈回溯窗口内生效；退出时恢复原栈与 `rbp`。

## 4. 可复制命令

### 4.1 查 CET / 影子栈

```powershell
winchecksec.exe sample.exe
Get-ProcessMitigation -Name sample.exe | Select-String "ShadowStack|CET"
dumpbin /headers sample.exe | Select-String "CET"
```

### 4.2 列 `.pdata` 空洞

```python
import pefile
pe = pefile.PE("sample.exe")
text = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
lo, hi = text.VirtualAddress, text.VirtualAddress + text.Misc_VirtualSize
r = sorted((e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION)
cur = lo
for b, e in r:
    if e <= lo or b >= hi: continue
    if b > cur: print("gap", hex(cur), hex(b))
    cur = max(cur, e)
if cur < hi: print("gap", hex(cur), hex(hi))
```

### 4.3 找 call-preceded 地址

```python
import pefile
b = open("sample.exe", "rb").read(); pe = pefile.PE("sample.exe")
for i in range(len(b) - 5):
    if b[i] == 0xE8:
        t = pe.get_rva_from_offset(i + 5) + int.from_bytes(b[i+1:i+5], "little", signed=True)
        print(hex(t))          # t 前一条指令是 call，可作为候选返回地址
```

`FF /2`（`call [mem]`）需按 ModRM 解码；先用 `E8` 缩小范围，再在 IDA 里确认。

### 4.4 ETW-Ti 栈回溯

```powershell
logman create trace TiTrace -p "{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}" 0xffffffffffffffff 0xff -o ti.etl -ets
# 触发目标操作
logman stop TiTrace -ets
tracerpt ti.etl -o ti.xml -of XML
Select-String ti.xml -Pattern "StackWalk|CallStack|Threat"
```

判据：Ti 事件里的调用栈是否包含假帧、是否在空洞地址处停止/跳过；只有
`etw_ti_unwind=blocked/partial` 且假帧未被还原，才算 LACUNA 生效。

## 5. 检测面

| 检测点 | 看什么 | 结论 |
| :--- | :--- | :--- |
| 影子栈不匹配 | `ret` 目标 != shadow stack top；`#CP`/`0xC0000409` | `shadow_stack_ok=false`，CET 已拦截 |
| `.pdata` 无覆盖 | 返回地址落在 `RUNTIME_FUNCTION` 空洞 | `pdata_gap=<rva 区间>`，高度可疑 |
| 非 call-preceded | 返回地址前不是 `E8`/`FF /2` | `frame_call_preceded=false`，栈回溯异常 |
| ETW-Ti unwind | Ti 栈回溯完整/部分/被阻断 | `etw_ti_unwind=full/partial/blocked` |

## 6. 判据字段

| 字段 | 取值 | 证据 |
| :--- | :--- | :--- |
| `shadow_stack_ok` | `true/false` | `ret` 与影子栈顶一致；不一致记录 fault 码 |
| `pdata_gap` | `0x...-0x...` / `null` | 空洞区间与落入其中的返回地址 |
| `frame_call_preceded` | `true/false` | 返回地址前一条指令是否为 `call` |
| `etw_ti_unwind` | `full/partial/blocked` | ETW-Ti 事件中的调用栈深度与是否见假帧 |

## 7. 失败判据

| 现象 | 判定 | 改走哪条 |
| :--- | :--- | :--- |
| CET 开启后 `ret` 伪造即崩 | 影子栈不匹配 | 改 call-preceded + `jmp` 链，或关闭该进程 CET |
| 扫不到任何空洞 | `.pdata` 覆盖完整 | 放弃 LACUNA，换模块/换栈回溯面 |
| 假帧被 ETW-Ti 还原 | 帧结构或 `rbp` 链不合法 | 按第 3 节重建；两次失败即停 |
| 返回地址非 call-preceded | 回溯启发式命中 | 换 gadget，不要硬拼 |
| KCET 在内核启用 | 用户态 LACUNA 不适用 | 转内核侧研究或放弃该路径 |
| 合法 leaf 函数也在空洞 | 误报 | 结合 call-preceded 与栈深度复核 |

## 8. 出处与延伸

- LACUNA Chain（0xmaz.me，2026-06），`https://0xmaz.me/`（站内检索标题）。
- SSTIC/BH 2026 影子栈与内核栈回溯分析；Intel CET 规范（`RDSSP`/`INCSSP`/
  `WRSS` 与 `#CP`）。
- 反调试/仪器选择：`Tool/skill/softseep/references/10-anti-debug.md`。
