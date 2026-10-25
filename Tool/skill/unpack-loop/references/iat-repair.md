# IAT 修复：让 dump 件重新"认得"系统函数

> 加载时机：`dump-and-rebuild.md` 完成、`rabin2 -i` 报导入为空或明显错误。
> 判据底线：**修完必须能列出与原始程序量级相当的导入**，否则不算修好。

## 0. 为什么 dump 出来的 IAT 是坏的

壳在运行时会：① 先清空原始 IAT；② 解密代码；③ **边跑边填**导入。所以在 OEP 那一刻，
IAT 里可能只有"已经被调用过"的那部分，其余的仍是 0 或壳的地址。

**所以"IAT 坏了"是正常现象，不是 dump 失败。** dump 失败是指"PE 头/区段都坏了"。

## 1. 修复三步（顺序不能反）

| 步 | 做什么 | 判据 |
| :-: | :-- | :-- |
| **1** | 确定 IAT 的**范围**（起始 RVA + 大小） | 能在 dump 件的 `IMAGE_DIRECTORY_ENTRY_IAT` 里读到，或从 OEP 附近反汇编里推出 |
| **2** | **重建导入**：自动搜索 + 手工补 | 每个 DLL 至少一条函数；总数与原始程序量级相当 |
| **3** | **写回 + 复验** | `rabin2 -i` 能列出、地址落在导入表内、程序能加载 |

## 2. 工具与用法（GUI 通道，按需确认）

| 工具 | 用途 | 注意 |
| :-- | :-- | :-- |
| **Scylla** | IAT 自动搜索 + 修复 + 转储 | x86/x64 两版；要求目标**处于暂停状态** |
| **pe-sieve** | dump 时同时尝试恢复部分导入 | 与 Scylla 互为独立证据（两路一致 = E3） |
| **手工** | 从 OEP 附近找 `call [IAT slot]`，反查目标函数 | 只在自动搜索失败时用；每一步记地址 |

**GUI 属"需确认"档**：需要用户把工具打开/停在主界面，或由我们按启动纪律拉起（`tool-run.ps1 -Tool scylla`）。
**不要**为了省事写脚本去调 `SendKeys` 之类（会被 `cmd-guard` 拦，也确实不可靠）。

## 3. 自动搜索失败时的三种情况

| 情况 | 症状 | 处理 |
| :-- | :-- | :-- |
| **间接跳转表**（`jmp [reg]`） | Scylla 找到的函数很少 | 手工在 OEP 附近反汇编，找 `call qword ptr [rip+X]`，把 X 指的位置填进 IAT |
| **延迟导入（delay load）** | 只有少数 DLL | 单独处理 `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`；可先留空，程序首次调用时由系统解析 |
| **壳自己的 thunk** | 搜出来的地址落在壳节里 | 说明 IAT 还没填完 → 回 `oep-locate.md`，dump 点太早 |

```bash
# IAT 修复后的复验（只读）
rabin2 -i fixed.exe | head -30   # 能列出与原始程序量级相当的导入
rabin2 -I fixed.exe             # 静态加载无告警
```

## 4. 复验（缺一不可）

| # | 检查 | 通过 |
| :-: | :-- | :-- |
| 1 | `rabin2 -i <fixed>` | 能列出 ≥ 原始程序导入量级的函数；无解析异常 |
| 2 | 每条的地址在 `.idata`/导入表范围内 | 不是壳节地址 |
| 3 | 静态加载（`rabin2 -I`）无告警 | — |
| 4 | 动态（**需用户同意**）：在隔离环境跑 | 能进主界面、关键功能不崩 |
| 5 | 与 `pe-sieve` 的恢复结果对比 | 两路一致 → E3；不一致 → 写清差在哪 |

## 5. 常见"假修好"

| 假象 | 原因 | 怎么识别 |
| :-- | :-- | :-- |
| 导入条数对了，但程序一启动就退 | 函数地址填错（指向壳的跳板） | 抽查 3 条：`rabin2 -i` 的地址 vs 内存里实际指向 |
| 只有序数导入（ordinal）没有名字 | 原程序用序号导入 | 保留序号即可，不算坏 |
| 能跑但功能缺失 | 部分延迟导入没填 | 对比原始程序调用清单 |

## 6. IAT 范围推导：用 thunk 密度找起始与长度

> 不知道 IAT 在哪时，不要猜。代码里的 `call [imp]`（`FF 15`）与 `jmp [imp]`（`FF 25`）
> 会把引用地址聚集到同一个区间，**那个区间的密度峰就是 IAT**。

```python
#!/usr/bin/env python3
# 扫 FF15/FF25 找 thunk 热区：x64 按 rip+rel32 算目标；x86 按绝对地址
# 注意：生产用时要先按节表限定到可执行节（这里为篇幅简化为全文件）
import struct, sys
p = sys.argv[1]
bits64 = (len(sys.argv) < 4) or (sys.argv[3] == "64")
d = open(p, "rb").read()
hits = {}
for i in range(len(d) - 6):
    if d[i] == 0xFF and d[i + 1] == 0x15:
        rel = struct.unpack_from("<i", d, i + 2)[0]
        tgt = (i + 6 + rel) if bits64 else rel & 0xFFFFFFFF
        if (tgt >> 12) == ((i + 6) >> 12) or not bits64:  # 同页优先，x86 用绝对地址
            hits[tgt] = hits.get(tgt, 0) + 1
slots = sorted(hits)
print("candidates:", len(slots))
for t in slots[:20]:
    print(f"{t:#x} refs={hits[t]}")
```

**通过长什么样 / 期望输出**：

```text
candidates: 214
0x140020010 refs=3
0x140020018 refs=1
0x140020020 refs=7
```

判读：当大量目标地址**连续、步长为 8（x64）或 4（x86）、并且落在同一节**时，
这个区间就是 IAT；取 `min..max` 视为初界，再向两端扩到第一个非法值（0/非模块地址）为止。
**通过标准 = 能说出 `IAT RVA 起 = 0x20010、结束 = 0x20xxx、共 N 项`**，而不是“在 .idata 里”。

**约束**：扫描必须限定到可执行节，否则资源里的 `FF 15` 字节（图片/字串）会产生假峰。

## 7. thunk 合法性校验：地址到底指向哪个模块

> Scylla 的“自动搜索”会给出候选；判据不是“看着对”，而是每个 thunk 地址都能落到
> 某个已加载模块的范围内（而且不在壳节）。

```python
#!/usr/bin/env python3
# 输入：修复后的 dump + 模块范围表（从 x64dbg 的 Memory Map / Process Hacker 导出）
# 模块范围表格式（纯文本）：0x7ffb00000000 0x7ffb00100000 kernel32.dll
import struct, sys
mods = []
for line in open(sys.argv[2], encoding="utf-8"):
    a, b, name = line.split()
    mods.append((int(a, 16), int(b, 16), name))
iat_base, n = int(sys.argv[3], 16), int(sys.argv[4])
d = open(sys.argv[1], "rb").read()
bad = 0
for i in range(n):
    v = struct.unpack_from("<Q", d, iat_base + i * 8)[0]
    if v == 0:
        continue
    m = [x[2] for x in mods if x[0] <= v < x[1]]
    if not m:
        bad += 1
        print(f"slot{i:03d} {v:#x} -> ORPHAN")
print("orphans:", bad, "of", n)
sys.exit(0 if bad == 0 else 2)
```

**通过长什么样 / 期望输出**：

```text
orphans: 0 of 187
```

| 结果 | 含义 | 动作 |
| :-- | :-- | :-- |
| `orphans: 0` | 全部指向已加载模块 | 可以进动态复验 |
| ✓ 少量 `ORPHAN` 且地址在同一节 | 可能是延迟导入未填 | 单独列出来，标记 `delay` |
| 大量 `ORPHAN` 且地址集中在壳范围内 | 填的是壳的跳板地址 | 回 `oep-locate.md`，dump 太早 |
| 地址为 0 的比例高 | IAT 未填完 | 同上 |

## 8. 三类特殊导入：延迟 / 绑定 / 序号

| 类型 | 识别 | 修复要点 | 常见坑 |
| :-- | :-- | :-- | :-- |
| **Delay Import** | 存在 `IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`（目录 13）；节名 `.didat` | 可以**不填**：首次调用由系统解析 | 把 delay 当普通 import 填，会重复/冲突 |
| **Bound Import** | 目录 11 非空，含时间戳+模块名 | 重建时**清空目录 11** | 保留绑定时间戳会使加载器拒绝（绑定校验失败） |
| **Ordinal Import** | `Name == NULL`，`Hint/Name` 低 16 位是序号 | 保留序号即可，不需要名字 | 拿序号去猜名字，猜错就崩 |
| **Forwarder** | 导出项落在 `.idata` 且内容是 `"DLL.Func"` | 保持原样，不要当成 thunk 覆盖 | 手工覆盖会断转发链 |

**判据**：三类至少各查一次（看三个目录是否非空 + 看是否有序号导入）；
没查就写“已完整修复导入”，属于假声明。

## 9. 修复后的复验：三层才算完成

| 层 | 命令 | 通过条件 |
| :-: | :-- | :-- |
| 静态符号 | `rabin2 -i fixed.exe` | 能列出 `dll!func`，数量与原件量级相当 |
| 地址合法性 | 本文 §7 脚本 | `orphans: 0`（或剩余项已归类为 delay） |
| 加载验证 | `rabin2 -I` + （同意后）隔离环境启动 | 无解析告警；能跑到主界面/首个请求 |

```bash
# 一次性跑前两层（第三层需人工/隔离环境）
rabin2 -i work/task/rebuilt.exe | head -20
rabin2 -i work/task/rebuilt.exe | wc -l
python check-thunks.py work/task/rebuilt.exe mods.txt 0x20010 187
```

**约束**：`check-thunks.py` 的模块表必须来自**同一台机器同一次运行**；拿别人的地址表校验自己的 dump，
结果不可信。

## 10. IAT 修复的失败签名（命中即回上游）

| 签名 | 判定 | 回哪 |
| :-- | :-- | :-- |
| 导入条数正常但首个 API 调用就崩 | 填了壳跳板 | 回 `oep-locate.md` |
| `rabin2 -i` 报乱码函数名 | thunk 指向非导入表 | 检查 IAT 起址是否错位 4/8 字节 |
| 部分 DLL 名字合理但函数名全是序号 | 原本就是序号导入 | 保留，不是失败 |
| Scylla unresolved 永远不归零 | 目标跨进程注入/分段解密 | 转路线 B（运行期 hook） |
| 两路（Scylla / pe-sieve）结果差异 >30% | 至少一路错 | 记 `confidence=medium`，写清差异，不硬定 |
| 修完能跑但功能缺失 | 延迟导入/插件导入未填 | 对比原始导入清单，补 delay |

## 9bis. 批量补表：把“缺 N 个”变成 N 行工作表

> 手工补表最容易在“记不住补到哪了”上翻车。做法：先把缺失项写成一张工作表，再逐行消。

| 步 | 动作 | 产物 |
| :-: | :-- | :-- |
| 1 | 用 `rabin2 -i` 导出当前导入，与原件/预期清单做差 | `missing.tsv` |
| 2 | 对每个缺失地址，在 OEP 附近找消费点（`call [addr]`） | 地址 → 调用上下文 |
| 3 | 对每个调用上下文，反推 API（参数形状/字符串/返回值用法） | 候选 `dll!func` |
| 4 | 批量写入（Scylla 粘贴 / 脚本直接改 IAT） | `fixed2.exe` |
| 5 | 重跑 §7 的 `orphans` 校验 + §9 三层复验 | 证据 |

```bash
# 1) 差集（原件有、dump 没有的 dll!func）
rabin2 -i original.exe | awk '{print $NF}' | sort -u > work/task/orig.txt
rabin2 -i rebuilt.exe  | awk '{print $NF}' | sort -u > work/task/now.txt
comm -23 work/task/orig.txt work/task/now.txt > work/task/missing.txt
wc -l work/task/missing.txt
```

**通过长什么样 / 期望输出**：

```text
missing.txt 行数：0   ← 差集为空，导入已对齐
missing.txt 行数：12  ← 有 12 个待补；每个必须能指到候选 dll!func
```

判据：**`missing` 每行都有候选来源**（调用上下文/字符串/交叉引用）；
没有来源的行不要“猜一个差不多的”，宁可标 `unresolved`。

**约束**：`awk '{print $NF}'` 依赖 `rabin2 -i` 的输出列数；先 `head -1` 看列格式，
不然会拿错列并得到假差集。

## 10bis. 三个边界：Wow64 / 转发导出 / 静态链接

| 边界 | 现象 | 处理 |
| :-- | :-- | :-- |
| Wow64（32 位目标跑在 64 位系统） | 模块地址 32 位，但你用了 64 位脚本 | 地址宽度、`IMAGE_THUNK_DATA` 都是 4 字节；别用 `<Q` |
| 转发导出（`DLL.A -> DLL.B!Func`） | thunk 指向的模块里那个函数实际在另一个 DLL | 保留转发，不要当成错误地址 |
| 静态链接 CRT | 导入极少（几十条）但功能完整 | 拿 `runtime`/`go.` 字符串/`__libc` 类特征排除“壳”误判 |
| 注入式加载器 | 导入表在内核/反射加载器里手写，没有 IAT | 不追求 IAT，转行为/内存（路线 B） |

**判据**：遇到这四种情况时，先写一句“这属于 X 边界”再动手；
否则很容易把“链接方式”当成“导入修复失败”。

**修复完成的最小证据链（照抄进报告）**：

```text
1) IAT 范围：RVA 0x20010–0x20A60，共 187 项（来源：FF15 密度扫描 + Scylla 交叉）
2) 自动手段：Scylla unresolved=0（日志 screenshot/导出）
3) 独立校验：check-thunks.py orphans=0，模块表来自 x64dbg 同次运行
4) 差集：与原件的 dll!func 差集为 0（或剩余 3 项标 delay）
5) 未做：未在干净机器实跑（需用户同意）→ 结论上限 E2
```

缺第 1 项 → 无法复现；缺第 3 项 → 只有一路证据（最多 E2）；
缺第 5 项 → 不得写“能跑”。

## 11. 这一篇算"用对了"吗

- [ ] 我能说出 IAT 的起始 RVA 与大小（不是"大概在 .idata"）
- [ ] 我至少用了**两种独立方法**（自动搜索 + 手工/pe-sieve 交叉）
- [ ] 复验 5 项里，第 1、2 项我一定做了；若声称"能跑"，第 4 项有证据
- [ ] 我没有把壳自己的跳板当地址填进去
