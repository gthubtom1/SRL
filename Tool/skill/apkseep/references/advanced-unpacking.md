# Advanced Unpacking — 拆分目录（2 篇，内容无损）

> 本篇范围：原 593 行脱壳边界文档的入口页；正文拆成 2 篇，保留全部原有小节与证据说明。
> 前后篇：本页是目录；从 [advanced-unpacking-1-shapes-and-active-invocation.md](advanced-unpacking-1-shapes-and-active-invocation.md) 开始。

原文件按 `##` 小节拆分，小节标题与内容未摘要化。

| 子篇 | 覆盖小节 | 行数 |
|---|---|---|
| [advanced-unpacking-1-shapes-and-active-invocation.md](advanced-unpacking-1-shapes-and-active-invocation.md) | dump 四形态、抽取测量、FART/Youpk 主动调用、`frida-dexdump` 边界 | 265 |
| [advanced-unpacking-2-root-dump-and-vmp-boundary.md](advanced-unpacking-2-root-dump-and-vmp-boundary.md) | frida 被拒时的 root 侧 dump、分层下探、真实 Dex VMP 边界、决策摘要 | 336 |

---

## 本页怎么用：先判形态，再选子篇

本页是**入口页 + 判定/体检层**：它负责回答「我手上这一堆 dump 到底属于四形态里的哪一种」，
以及「在花掉一个内存窗口之前，能不能先把它否掉」。两个子篇才是正文（FART 循环、root 侧 dump）。

| 你观察到的现象 | 先读 | 为什么不能反过来 |
|---|---|---|
| 内存里出现整块 `dex\n035` / `dex\n039`，`frida` 还 attach 得上 | 子篇 1（形态 + 主动调用） | 子篇 2 的前提是「frida 已被拒」；能 attach 时先走便宜的 |
| `frida` attach 被拒、进程不到 2 秒就死、或 dump 到一半 `script has been destroyed` | 子篇 2（root 侧 dump） | 子篇 1 的 FART 循环**依赖** attach 与主动调用，环境不成立时它一行也跑不了 |
| 每个 dex 都能完整解析、类都在，但方法体是 `return-void` / nop 填充 | 先跑本页 §体检，再看子篇 1 的测量小节 | 「解析通过」不等于「内容在」。这是本域最贵的一次误判：它让人以为脱壳成功了 |
| 方法体在，但反汇编器输出乱码 / 私有 opcode | `vmp-differential-analysis.md` | 本页的形态判定能排除抽取壳，但私码表不在本页，也不在子篇里 |
| 整类是 `native` 声明，`Java_*` 符号一个都没有 | `java2c-and-jni-sinking.md` | 这里**没有 dex 可 dump**，一天后再看也一样；先排除掉，再谈内存 |
| 壳的 `Application` 是第三方类，明文 dex 很小 | `packers.md` → `code-virtualization-and-custom-linkers.md` | 脱壳只是第一层；脱出来之后读不读得懂是另一层问题 |

**一句话判据**：本页的四个子问题全部可以用**命令输出里的数字**回答，没有一个是「看起来像」。
凡是靠感觉定性的（"这应该是抽取壳"），都还没到可以花窗口的程度。

## 三个可数指标，决定走哪条路

脱壳讨论最常见的失败是：**把一个"能量化的问题"当成了"经验问题"**。实际上只需要三个数字：

| # | 指标 | 从哪来 | 它决定什么 |
|---|---|---|---|
| 1 | `stub%` / `emptied%`（平凡方法体占比） | `dex_dump_validate.py` | 抽取壳 vs 完整镜像。它是**双峰**的，不是阈值；见子篇 1 |
| 2 | 唯一镜像数（sha256 去重后） | 同一支命令的 dedupe 段 | 你手上有几个"版本"；重复 dump 会被误当成多个证据 |
| 3 | `native` 方法数 ÷ `Java_*` 符号数 | `java2c_probe.py` | 这个目标到底有没有可 dump 的 dex |

三个数字都取到之后，"我要不要开一个 root 窗口"才是可判的。

## 命令块 A：一次 dump 体检（先量化，再谈恢复）

```bash
# 1) 结构 + 去重 + 平凡体占比 + 候选排序，一次全出
python scripts/dex_dump_validate.py ./dumps --json > dumps.json

# 2) 人读版（表格 + ranking + verdict）
python scripts/dex_dump_validate.py ./dumps

# 3) 只关心某个包前缀是否真的在里面（计数，不是"我看到了"）
python scripts/dex_dump_validate.py ./dumps --find 'Lcom/example/app/'
```

期望输出（形态，数字取自你自己的目标，不要抄这里）：

```
== dex dump validation: 11 file(s), 9 parse, 2 rejected ==
name                             size  sha256[:12]   ver cksum sig  class noco code  stub% erased% emptied%
0x7f001000+0x1a4c00.dex       1723392  3f9a2c71b0e4  39  ok    ok    4210  118  4092  96.4%   0.0%   96.4%
0x7f200000+0x0c1000.dex        790528  b71e04aa92c1  39  ok    ok    1880   44  1836   3.1%   0.0%    3.1%
classes2.dex                    54024  9c02ff31d7ab  35  ok    ok     310    2   308   1.9%   0.0%    1.9%

dedupe: 3 unique image(s) among 9 valid file(s)

ranking (most likely original first):
  1. classes2.dex        stub%=1.9  erased%=0.0  min/erased=0  cksum=ok sig=ok classes=310
  2. 0x7f200000+...dex   stub%=3.1  erased%=0.0  ...
  3. 0x7f001000+...dex   stub%=96.4 erased%=0.0  ...  <-- SKELETON: emptied%=96, extraction-shell shape

verdict: classes2.dex is the best-supported candidate for the original (3 copy(ies) in this set)
```

**怎么读这张表**（判据，不是解释）：

- `REJECTED:` 行 → 那不是 dex，或截断。`--trim` 只救「页对齐导致尾部多出来的」那一种，救不了短于自身
  `file_size` 的截断；被拒绝的样本**不进**排序，别拿它当"最小的一份"。
- `stub%` 在 90% 附近 → 抽取壳形态。此时"类都在"是真的，"方法体在"是假的。
- `stub%` 在个位数 → 这是候选原镜像；再看 `class` 数是否覆盖你在 dex 字符串里见过的类前缀。
- `dedupe` 行 → 只保留唯一镜像去排序。**同一镜像的 3 份拷贝是 3 条证据还是 1 条**，这里给出答案。
- `minimal-form bodies` 行出现时，说明还有一层 `const/4 + return` 截断，`stub%` 列看不见它（子篇 1 的
  `code_item` 陷阱）；这种镜像也不能当原镜像。

## 通过长什么样

| 检查 | 命令 | 通过 | 不通过意味着什么 |
|---|---|---|---|
| 结构合法 | `dex_dump_validate.py <dir>` | 每个候选 `cksum=ok sig=ok`，`class>0` | 头部两字段没重算，或 dump 起点偏了（子篇 2 §地址算术） |
| 内容在 | 同上，看 `stub%` / `emptied%` | 候选原镜像 `stub%` 个位数 | 抽取壳；恢复方法体是另一条路线，不是"再多 dump 几次" |
| 唯一性 | 同上，看 `dedupe` | 唯一镜像数 ≤ 你预期的 dex 数 | 你在重复 dump 同一块内存，或者在 dump 已释放的区间 |
| 覆盖面 | `--find 'Lcom/example/app/'` | 命中数与字符串表里该前缀的类数同数量级 | 主 dex 还没拿到；此时任何"脱壳完成"都是假话 |
| 不是 Java2C | `java2c_probe.py --apk <apk>` | `native` 密度在 0.0x% 量级，且 `Java_*` 与 native 方法数 1:1 | 密度到几十 % ⇒ 先读 `java2c-and-jni-sinking.md`，别开窗口 |

## 命令块 B：内存里找 dex，而不是"猜一段区间"

```bash
# 从一份 /proc/<pid>/mem 导出、或任何原始内存捕获里，按各自头部声明的尺寸切出 dex
python scripts/dex_mem_scan.py ./captures --dump ./dumps --json

# 捕获很大时，缩小块、并设一个下限挡掉散落的假 magic
python scripts/dex_mem_scan.py ./captures --chunk-size 8388608 --min-size 4096 --dump ./dumps
```

通过的样子：`--dump` 目录里出现的文件名形如 `<capture>+0x<offset>.dex`；每个文件再回到命令块 A 去判。
**不要跳过这一步的判**：`dex_mem_scan.py` 只保证"头部声明了一个尺寸"，不保证那尺寸里的内容是 code。

## 命令块 C：先把 Java2C 这条死路排除掉

```bash
python scripts/java2c_probe.py --apk ./target.apk --json > j2c.json
```

通过的样子（`observed` 分离度）：普通 JNI 目标的 native 声明密度是 **0.03–0.04%**，Java2C 形态的
fixture 是 **82.76%**；同时 dex 的 native 方法数与 `.so` 里 `Java_*` 符号数按 ABI 一一对应。
两组数字都在，才可以继续谈 dump；只有一个数字时，你只是有了一个 `inferred` 猜想。

## 三条硬约束（违反任一条，结论作废）

1. **dump 不是证据，"结构 + 内容 + 唯一性"同时成立才是。** 只凭"我 dump 到一个 dex"下结论，等于
   把「字节存在」当成「代码可达」。
2. **窗口是资源，先算成本再开。** 子篇 2 §limits 给了要预算的项（内存压力、进程存活时间、写出速度）。
   没算过就开窗口，通常会得到半份不可用的 dump 和一句"这个目标加固很深"。
3. **抽取壳与 VMP 是两个终点，不是两个台阶。** 抽取壳有恢复路线（主动调用 / 补方法体），VMP 的私码
   表是另一个课题（`vmp-differential-analysis.md`）。把两者混在一起谈，会让"再试一次"变成无限循环。

## 与邻页的分工（避免重复劳动）

| 问题 | 归谁 |
|---|---|
| 这个包是不是壳？壳入口类叫什么？ | `packers.md`（dex 侧识别） |
| 没有壳，dex 可读，但重签名包启动即死 | `code-virtualization-and-custom-linkers.md` |
| 类是 `native`，没有 `Java_*` | `java2c-and-jni-sinking.md` |
| 方法体在但解不出来（私码） | `vmp-differential-analysis.md` |
| dump 的**四种形态**与主动调用循环 | 子篇 1 |
| frida 被拒后的 root 侧 dump、分层下探 | 子篇 2 |

## 记录模板（一次 dump 落账）

```
goal:            <要拿到哪一层的代码，为什么>
capture:         <怎么来的：frida / /proc/<pid>/mem / 文件>  时间窗 <t0..t1>
images:          <唯一镜像数> 份；sha256[:12] 列表
stub%:           <候选原镜像的 stub% / emptied%>      判据：个位数 vs >=50%
coverage:        --find '<包前缀>' → <命中数>，dex 字符串表里该前缀 <N> 条
excluded:        Java2C(密度 <x>%) / 非 dex 区间 <清单>
next:            <子篇 1 主动调用 | 子篇 2 root dump | 停止并说明边界>
```

## 常见误判：六个"看着像成功"的形态

每一个都真实发生过，且都在**下一步**才暴露。判断它们不需要新工具，只需要把已经跑过的输出再读一遍。

**① "解析通过"当成"内容在"。** `dex_dump_validate` 打印 `cksum=ok sig=ok class=4210`，看起来一切正常。
判据：`stub%` 或 `emptied%` 是否是双峰里的高那一峰。动作：读 §体检 的 `SKELETON` 标记，然后换路线
（主动调用 / root 侧），而不是"再 dump 一次看看"。

**② 重复 dump 当成多份证据。** 三次 dump 得到三个文件名，内容同一。判据：`dedupe` 段的唯一镜像数。
动作：只留一份，并在记录里写"1 个镜像 / 3 次观察"，否则后续每一条推断都会被自己重复计数。

**③ 把 `classesN.dex` 的文件名当成顺序。** 文件名里的 N 与加载顺序、与"哪个是主 dex"都没有稳定关系，
尤其在壳自己重排过之后。判据：`class` 数、`--find` 命中数、以及字符串表里该包前缀的类数三者是否一致。
动作：用数字排序，不用文件名排序。

**④ 把一段 `r--s` 的 `base.apk` 映射当成 dex。** APK 是 zip，里面有 dex，但映射本身不是 dex。
判据：`dex_mem_scan` 报的是"在捕获里找到 magic"还是"从文件头解析出结构"；`dex_dump_validate` 是否
`REJECTED`。动作：走子篇 2 §"先读 map 再选字节"，而不是对着 zip 区间切片。

**⑤ 把"方法体是 nop"解释成"被加密了，所以需要解密器"。** nop 填充通常意味着**这块镜像被主动清过**
（壳在抽取后擦除），不是"密文"。判据：`erased%` 列 > 0 且 `stub%` 低。动作：这在子篇 1 的
`code_item` 陷阱里有专门处理，先读它再决定是否要重建方法体。

**⑥ 把"这个目标加固很深"当成结论。** 它通常是三个具体失败之一被合并成了一句概括：
窗口太短、写出太慢、或者读错了区间。判据：你的记录里有没有 `capture 来源 + 时间窗 + 区间 + 出字节速率`。
动作：补上这四项，再判断"深"不"深"；缺项时那句结论是 `unverified`。

## 花窗口之前的三个成本实验

开一个 root 侧窗口的代价不是"跑一条命令"，而是**进程可能只活 2 秒**。先用三个便宜实验估一下它值不值：

| 实验 | 怎么做 | 读什么 | 结论 |
|---|---|---|---|
| 生命期 | `adb shell "su -c 'pidof <pkg>'"` 每 500 ms 采一次，采 20 次 | 第一次采到空的时间 | 生命期 < 5 s ⇒ 交换/写出的窗口更小，先减输出量 |
| 内存压力 | `adb shell "su -c 'cat /proc/<pid>/status'"` 看 `VmRSS` / `VmSize` | RSS 与可用内存的比例 | 大面积读会让目标被回收，先按区间分片 |
| 写出速率 | 先写 1 MiB 到目标目录并计时 | 每 MiB 的毫秒数 | 用它反推"我能在死前写出多少"，把要 dump 的区间按这个预算排序 |

三个数字都拿到之后，"dump 全部"通常会变成"dump 这两个区间"，而后者才是能跑完的那一个。

## 什么时候该停手并写边界

不是每一次脱壳都该有结果。下面四种情况下，**写边界比继续试更专业**，因为这四种都不是"再努力一点"能解决的：

- 目标在 `stub%` 高那一峰，且主动调用循环跑不起来（Android 12–16 的经典 hook 限制，见子篇 1）——
  恢复方法体需要改 ART 或私有运行时，超出本域。
- dump 出来的镜像 `stub%` 低，但方法体解码成私有 opcode —— 这是 VMP，路线在
  `vmp-differential-analysis.md`，且它的终点往往是"成本高于收益"。
- 进程生命期短到连一次完整区间写出都放不下，且没有任何办法延长（壳的定时自杀，见
  `native-tamper-and-suicide.md`）—— 此时该做的是**先解决死亡**，不是先解决 dump。
- 你要的答案其实不需要脱壳：字符串、端点、配置项往往在 APK 的可见 dex 或资源里就够用
  （`recon.md` §extract strings）。

边界要写成一句可复核的话：*"在 <时间窗> 内用 <方法> 拿到 <N> 份唯一镜像，其中 <M> 份为抽取壳形态；
方法体恢复未做，因为它需要 <具体机制>，本域由用户提供。"* ——这句话比"加固很强，脱壳失败"有用一百倍。

## 走一遍：从"我 dump 到 11 个 dex"到"能交付的那一句"

这是一条**判定链**，不是教程。每一步的产物都是下一步的输入；任何一步拿不出数字，就停在那一步。

**第 1 步 — 数个数。**
```bash
ls -l ./dumps | wc -l
python scripts/dex_dump_validate.py ./dumps | grep -E 'dedupe|verdict'
```
产出：`11 file(s)` / `3 unique image(s)`。如果唯一数远小于文件数，你已经知道后面只需要看 3 份。

**第 2 步 — 判结构。**
同一条命令的表格里，`REJECTED` 有几行、`cksum/sig` 是否全 ok。产出：可用候选清单（这里假设 6 份）。

**第 3 步 — 判内容。**
读候选的 `stub%` / `emptied%`。产出：**分堆**。`>=50%` 的一堆是抽取壳形态（这里假设 4 份），
个位数的一堆是候选原镜像（假设 2 份）。

**第 4 步 — 判覆盖面。**
```bash
python scripts/dex_dump_validate.py ./dumps/classes2.dex --find 'Lcom/example/app/' --find 'okhttp3/'
```
两个 `find` 命中数都非零，且与 `recon` 阶段记下的类前缀数量同数量级。产出：**主镜像认定**。

**第 5 步 — 判"是否另有解释"。**
`java2c_probe.py --apk` 给出 native 密度；密度在 0.0x% 量级、`Java_*` 与 native 方法数 1:1
⇒ Java2C 排除。产出：一句可复核的排除记录。

**第 6 步 — 分岔。**
- 若第 3 步里**没有**个位数 `stub%` 的镜像 ⇒ 全堆都是抽取壳 ⇒ 去子篇 1 的主动调用循环，或按
  §什么时候该停手 写边界。
- 若第 4 步的 `--find` 命中数明显偏少 ⇒ 主 dex 还缺 ⇒ 子篇 2 的区间选择。
- 若第 5 步的密度到几十 % ⇒ 停，转 `java2c-and-jni-sinking.md`。

**第 7 步 — 只有到这一步才花窗口。** 用 §成本实验 的三个数字把区间按预算排序，然后一次只读一个区间
（单变量纪律，`long-task-discipline.md`）。

**第 8 步 — 落账。** 用 §记录模板 写六行；其中"next"必须是**一个**动作，不是一个方向。

这条链里最容易跳掉的是第 5 步和第 7 步。前者省下来的是"花两天找不存在的 dex"，后者省下来的是
"一次窗口里读了四个区间，然后分不清是哪个区间读坏了"。

## 这一篇算"用对了"吗

- [ ] 我先用三个数字（stub% / 唯一镜像数 / native 密度）定性，再决定要不要花一个内存窗口
- [ ] 我跑过 `dex_dump_validate.py`，并且能说出候选原镜像的 `stub%` 与 `dedupe` 结果
- [ ] 我确认过被 `REJECTED` / 被截断的镜像没有进入排序，也没被当成"最小的一份"
- [ ] 我排除过 Java2C（或明确写下"尚未排除"），没有把"没有 dex"当成"dump 得不够深"
- [ ] 我能说出这次到底是抽取壳还是 VMP，以及它们各自的恢复路线与终点
- [ ] 我的记录里有 capture 来源、时间窗、sha256 前缀和下一步，别人能照着重放
