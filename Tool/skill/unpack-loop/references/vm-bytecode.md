# VM / 字节码还原：识别解释器循环，重建指令集

> 加载时机：判为 **C 类（虚拟化）**，或静态分析里出现"大量小函数 + 一个巨大 switch/跳转表 +
> 一段看不出语义的数据区"。来源参考：yaklang/hack-skills 的 `vm-and-bytecode-reverse`（已按我们的判据重写）。
> 铁律：**字节码不是机器码**。对 VM 字节码做 capstone 反汇编，得到的一定是垃圾。

## 0. 先确认"这确实是个 VM"（三条证据）

| # | 证据 | 怎么看 |
| :-: | :-- | :-- |
| 1 | **取指循环**：一个循环里反复读同一数据区的下一个字节 | 数据区基址 + 递增的索引变量（`pc`/`ip`） |
| 2 | **分派结构**：`switch(op)` 或 `jmp [table + op*8]` | 跳转表条目数 ≈ 指令集大小（常见 0x20–0x100） |
| 3 | **操作数消费**：case 内部按固定字节数读操作数 | `pc += 1 + operand_bytes` |

只有 1 条 → 可能是普通解析器（JSON/协议）；三条齐才按 VM 处理。

## 1. 五类分派器识别表

| 二进制特征 | VM 类型 | 起点 |
| :-- | :-- | :-- |
| `while(1){ switch(bytecode[pc++]) }` | switch 分派（CTF 最常见） | 逐 case 映射语义 |
| `jmp [table + opcode*8]` | 跳转表分派（优化过的商业保护） | dump 表 → 逐 handler 分析 |
| 字节值上的嵌套 if-else | if 链分派 | 与 switch 等价，只是语法不同 |
| 大量 push/pop | 栈式 VM | 先定 push/pop/算术三类 |
| `reg[X] = ...` 数组下标 | 寄存器式 VM | 把寄存器下标映射到语义 |
| 二维网格 + 方向输入 | 迷宫题 | 提取网格 → BFS/DFS |

## 2. 五步法（每步都要留证据）

| 步 | 做什么 | 判据（做到什么算完成） |
| :-: | :-- | :-- |
| 1 | **找分派器** | 能指出那个循环的地址 + 分派变量的来源 |
| 2 | **映射操作码** | 每个 opcode：操作类型 / 操作数字节数 / 操作数类型 / 副作用 |
| 3 | **提取字节码** | 拿到 (起始偏移, 长度)，并说明"凭什么长度是这么多" |
| 4 | **写反汇编器** | 能输出完整指令流，未知 opcode ≤ 5% |
| 5 | **还原语义** | 能说清"输入 → 变换 → 比较"的链路，最好能一行 Python 复算 |

## 3. 反汇编器模板（可直接改）

```python
# 最小可用：把 opcode 表填成你从第 2 步读出来的真实语义
OPCODES = {
    0x00: ("nop", 0), 0x01: ("push", 1), 0x02: ("pop", 0), 0x03: ("add", 0),
    0x04: ("sub", 0), 0x05: ("xor", 0), 0x06: ("cmp", 0),
    0x07: ("jmp", 2), 0x08: ("je", 2), 0x09: ("jne", 2),
    0x0A: ("mov", 2), 0x0B: ("load", 1), 0x0C: ("store", 1),
    0x0D: ("print", 0), 0x0E: ("read", 0), 0xFF: ("halt", 0),
}

def disasm(code, base=0):
    pc, out = 0, []
    while pc < len(code):
        op = code[pc]
        if op not in OPCODES:
            out.append((base + pc, "UNKNOWN_%02x" % op, []))
            pc += 1
            continue
        name, n = OPCODES[op]
        out.append((base + pc, name, list(code[pc + 1:pc + 1 + n])))
        pc += 1 + n
    return out

# 用：for addr, name, args in disasm(bytecode): print(hex(addr), name, args)
```

**判据**：未知 opcode 超过 5% → 说明指令表还没读全，别急着"还原算法"。

## 4. 还原语义的三条捷径

| 捷径 | 怎么做 | 什么时候用 |
| :-- | :-- | :-- |
| **找输入点** | 定位 `read` 类 opcode 的调用点，反推它写到哪个寄存器/栈位 | 有输入校验的题 |
| **找比较点** | 搜 `cmp` + 条件跳转，看比较的两个来源 | 输出"正确答案"的题 |
| **模拟执行** | 用 Python 实现 VM 解释器，把字节码跑一遍（比逆向快） | 数据流复杂但 opcode 已全 |

模拟执行的判据：**同一输入两次运行结果一致**（我们 `case_state.py repro` 可验）。

## 5. 商业保护（VMProtect/Themida）与 CTF VM 的区别

| 维度 | CTF VM | 商业保护 |
| :-- | :-- | :-- |
| 分派器 | 可读、结构清晰 | 混淆（多级分派、跳转表加密、handler 变形） |
| 指令集 | 固定 | 每次编译可不同 |
| 可行目标 | 还原完整指令流 | **函数级**：只还原目标函数，标注不可还原区域 |
| 判据 | 能一行 Python 复算 | 能给"该函数输入→输出"的等价比对 |

**不要承诺"完整 devirtualise 商业保护"**——写进 `limitations` 的事，报告里也要说。

## 6. 跳转表提取：一次拿全 handler 地址

> 对于 `jmp [table + op*8]` 型分派器，最贵的动作是“一个 case 一个 case 点进去看”。
> 先 dump 整张表，再按地址批量反汇编，能省一个数量级的时间。

```python
#!/usr/bin/env python3
# 输入：dump 文件 + 跳转表偏移（文件偏移）+ 条目数；输出：每项的 VA 与首字节
import struct, sys
p, tbl_off, n, base = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0), int(sys.argv[4], 0)
d = open(p, "rb").read()
fmt = "<Q" if len(sys.argv) < 6 or sys.argv[5] == "64" else "<I"
ent = 8 if fmt == "<Q" else 4
for i in range(n):
    v = struct.unpack_from(fmt, d, tbl_off + i * ent)[0]
    off = v - base if v >= base else None
    head = d[off:off + 8].hex() if off and off < len(d) else "out-of-file"
    print(f"op {i:#04x} -> {v:#x}  head={head}")
```

**通过长什么样 / 期望输出**：

```text
op 0x00 -> 0x401230  head=8bff558bec83
op 0x01 -> 0x4012a0  head=508b4504
op 0x02 -> 0x401310  head=6a006800
```

判据（三条全过才能继续）：

1. 所有地址都落在**同一可执行节**内（出现 `out-of-file`/落在数据节 → 表偏移或条目数错）；
2. 条目数 ≈ 你从分派器看到的边界检查常量（`cmp op, 0xNN` 的 `0xNN`+1）；
3. 每个 `head` 都能反汇编出 ≥3 条正常指令（骡字节/乱码说明表加密或索引错位）。

**约束**：表可能是运行期解密的。表内容是垃圾时，先找壳对该区的写操作（或外部采样），
**不要**对加密表硬调偏移。

## 7. handler 语义工作表（一张 CSV 跑完全部 handler）

> 不写工作表的结果：做到第 40 个 handler 时忘了前 20 个的含义。

| 列 | 含义 | 必填 |
| :-- | :-- | :-: |
| `op` | 操作码（十进制/十六进制一致） | ✅ |
| `mne` | 你给的名字（`push_imm`） | ✅ |
| `operand` | 操作数字节数（0/1/2/4） | ✅ |
| `stack_in` | 消费栈深（−N） | ✅ |
| `stack_out` | 产生栈深（+N） | ✅ |
| `side_effect` | 读写内存/输出/退出/系统调用 | ✅ |
| `handler_va` | handler 地址（§6 的产出） | ✅ |
| `evidence` | 凭什么这么判（关键指令片段） | ✅ |
| `confidence` | high/medium/low | ✅ |

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
# 工作表用 CSV 管，方便脚本与统计（不引入依赖）
printf 'op,mne,operand,stack_in,stack_out,side_effect,handler_va,evidence,confidence\n' > code.csv
python - <<'PY'
import csv
rows = [
    (0x01, "push_imm", 4, 0, 1, "none", "0x4012a0", "mov eax,[esi]; add esi,4; push eax", "high"),
    (0x02, "pop", 0, 1, 0, "none", "0x401310", "sub esp,4; mov [esp],eax", "high"),
    (0x0D, "print", 0, 1, 0, "output", "0x4019a0", "call [import:printf]", "high"),
]
with open("code.csv", "a", newline="") as f:
    csv.writer(f).writerows(rows)
print("rows:", len(rows))
PY
```

**通过长什么样 / 期望输出**：`rows: 3`，且 `code.csv` 表头与列顺序和上表一致（能被脚本直接读）。

判据：`confidence=low` 的行数 ≤ 总条数的 10%；超了说明基础指令集都没看清楚，别写反汇编器。

## 8. 模拟器骨架：让虚拟机帮你算，而不是你手算

> §3 是**反汇编器**（字节码 → 文本）；这里给**解释器**（字节码 → 结果）。
> 两者分开写：反汇编器用于阅读，解释器用于验证“我的理解对不对”。

```python
#!/usr/bin/env python3
# 栈式 VM 解释器骨架：op 表与 §7 的 code.csv 一致时才可用
class VM:
    def __init__(self, code, out=None):
        self.code, self.pc, self.stack, self.out = code, 0, [], out if out is not None else []
        self.regs = [0] * 16
        self.trace = []
        self.ops = {
            0x00: ("nop", 0, self.o_nop), 0x01: ("push", 4, self.o_push),
            0x02: ("pop", 0, self.o_pop),   0x03: ("add", 0, self.o_add),
            0x04: ("sub", 0, self.o_sub),   0x05: ("xor", 0, self.o_xor),
            0x06: ("cmp", 0, self.o_cmp),   0x0D: ("print", 0, self.o_print),
            0xFF: ("halt", 0, self.o_halt),
        }
    def u32(self):
        v = int.from_bytes(self.code[self.pc:self.pc + 4], "little"); self.pc += 4; return v
    def o_nop(self): pass
    def o_push(self): self.stack.append(self.u32())
    def o_pop(self): self.stack.pop()
    def o_add(self): b, a = self.stack.pop(), self.stack.pop(); self.stack.append((a + b) & 0xFFFFFFFF)
    def o_sub(self): b, a = self.stack.pop(), self.stack.pop(); self.stack.append((a - b) & 0xFFFFFFFF)
    def o_xor(self): b, a = self.stack.pop(), self.stack.pop(); self.stack.append(a ^ b)
    def o_cmp(self): b, a = self.stack.pop(), self.stack.pop(); self.regs[0] = int(a == b)
    def o_print(self): self.out.append(self.stack.pop())
    def o_halt(self): self.pc = len(self.code)
    def run(self, limit=100000):
        while self.pc < len(self.code) and limit > 0:
            op = self.code[self.pc]; self.pc += 1
            if op not in self.ops:
                raise SystemExit(f"unknown op {op:#x} at {self.pc-1:#x}")
            name, _, fn = self.ops[op]
            before = list(self.stack)
            fn(); limit -= 1
            self.trace.append((self.pc, name, before, list(self.stack)))
        return self.out
```

**通过长什么样 / 期望输出**：`vm.run()` 不抛 `unknown op`，且同一输入两次运行 `out` 完全一致。

| 现象 | 含义 | 动作 |
| :-- | :-- | :-- |
| 抛 `unknown op` | 指令表未读全 | 回 §7 补行，不要把未知 op 当 nop |
| 栈下溢 | 操作数个数/顺序错 | 回看 handler，不要改解释器“将就” |
| 死循环（limit 耗尽） | 跳转/循环计数未实现 | 先补 `jmp/jcc`，再跑 |
| 输出不对但能跑 | 字节序/符号/位宽错 | 用一条已知输入的输出做单步对比 |

**约束**：模拟器只能证明“你对指令集的理解自洽”，**不能**证明“这就是程序的真实行为”；
真实行为仍需动态侧（或与 `case_state.py repro` 的可重现证据对齐）。

## 9. 未知 opcode 的处理策略（不要一律当 nop）

| 现象 | 最可能原因 | 正确动作 | 错误动作 |
| :-- | :-- | :-- | :-- |
| 全流只有 1–2 个未知 op | 读到未覆盖的扩展指令 | 回 handler 补一个 case | 当 nop 跳过 |
| 未知 op 集中在头部 | 起始偏移选错 | 重找字节码入口 | 改表强行适配 |
| 未知 op 周期性出现 | 指令集参数化（每次运行不同） | 记录版本，标“部分还原” | 继续猜 |
| 未知 op 后全变乱码 | 长度判断错（漏了操作数） | 修正 `operand` 列后重跑 | 逐字节兜底输出垃圾 |

判据：未知率 ≤5%（与 §3 一致）；超了需要先确认写“指令集已还原”。

## 10. 商业保护（VMProtect/Themida）的函数级判据

| 问题 | 可行答法 | 不可行答法 |
| :-- | :-- | :-- |
| 这个函数输入输出是什么关系？ | 给“输入 → 输出”等价比对（表/脚本） | “已还原算法” |
| 它校验了什么？ | 指出比较点 + 预期值来源 | “有加密校验” |
| 能不能去虚拟化？ | “函数级局部还原，其余标不可还原” | “已完整 devirtualise” |
| 变量在哪？ | 指出运行时内存位置与取值时刻 | “在 VM 寄存器里”（没给映射） |

**失败判据**：

- 只能给出“执行到某地址后返回值变了”，却说不出输入输出关系 → 不算函数级还原；
- 依赖单次运行的随机结果 → 不可复现，不能进报告；
- 两次尝试（换手法）仍无法定位输入输出边界 → 停，写 `route=C, blocked_at=virtualized`；
- 只拿到 handler 地址而没有任何语义行（§7 的 `code.csv` 为空） → 只算“找到 VM”，不算“还原 VM”。

## 11. 这一篇算"用对了"吗

- [ ] 三条证据齐（取指循环 / 分派结构 / 操作数消费），不是"看起来像"
- [ ] 我有 opcode 表，且未知率 ≤5%
- [ ] 我提取了字节码，并说明长度依据
- [ ] 我能说清"输入 → 变换 → 比较"链路（或明确写"只能到指令流"）
- [ ] 若是商业保护，我没声称"完整还原"
