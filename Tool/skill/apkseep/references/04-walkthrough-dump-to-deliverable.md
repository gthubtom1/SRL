# 04 walkthrough —— 从「我 dump 到一堆 dex」到「能交付的那一句」

> 本篇是以下文件的归并索引：`references/advanced-unpacking.md` §走一遍：从"我 dump 到 11 个 dex"到"能交付的那一句"、
> §记录模板、§花窗口之前的三个成本实验、§通过长什么样、
> `references/advanced-unpacking-1-shapes-and-active-invocation.md` §The four shapes a dump can be、
> `references/advanced-unpacking-2-root-dump-and-vmp-boundary.md` §Read the map before choosing the bytes、§Limits to budget for、
> `references/verification.md` §The claim ladder、§The control build rule、
> `references/patch-audit.md` §Command block: the audit as a sequence, in the order that fails fastest、
> `references/repack-and-sign.md` §Pipeline、§Verify the build, not just the signature、
> `references/long-task-discipline.md` §Keep a live record、§Bound every wait、
> `references/handoff-boundaries.md` §A boundary record, in six lines、
> `references/pitfalls.md` §按代价排序：先修哪几条。
>
> **本篇不新增步骤**：八步链条逐条搬自 `advanced-unpacking.md` §走一遍（该节自己写明"这是一条**判定链**，不是教程"）。
> 文中出现的具体数字若标了「这里假设」，就是原文的示例数字，**不许抄进报告**；只有标了来源案例的数字才是实测值。
> 末尾两条是仓库里真实回放过的案例，用来对照"每一站长什么样"。

## 这条链的性质：任何一步拿不出数字，就停在那一步

原文口径（`advanced-unpacking.md` §走一遍）：**每一步的产物都是下一步的输入**。八个步骤的顺序不是习惯，
是"越便宜的先做"排序：前四步全是离线静态，第六步开始才花设备窗口。

| 步 | 做什么 | 产物（要有数字） | 代价 |
|---|---|---|---|
| 1 | 数个数（文件数 / 唯一镜像数） | `N file(s)` / `M unique image(s)` | 秒级，离线 |
| 2 | 判结构（`REJECTED` 几行、`cksum`/`sig`） | 可用候选清单 | 秒级，离线 |
| 3 | 判内容（`stub%` / `emptied%`） | **分堆**：抽取壳形态 vs 候选原镜像 | 秒级，离线 |
| 4 | 判覆盖面（`--find` 类前缀） | 主镜像认定 | 秒级，离线 |
| 5 | 排除 Java2C（native 密度） | 一句可复核的**排除记录** | 秒级，离线 |
| 6 | 分岔（去主动调用 / 去 root dump / 停手写边界） | 一个方向 | 决策 |
| 7 | 才花窗口，且一次只读一个区间 | 一份可用的 dump | 分钟级，需设备 |
| 8 | 落账（六行记录） | `next` 必须是**一个动作** | 分钟级 |

## 第 1–2 步：数个数、判结构

```bash
# 第 1 步：数个数
ls -l ./dumps | wc -l
python Tool/skill/apkseep/scripts/dex_dump_validate.py ./dumps | grep -E 'dedupe|verdict'

# 第 2 步：同一条命令的表格里，REJECTED 有几行、cksum/sig 是否全 ok
python Tool/skill/apkseep/scripts/dex_dump_validate.py ./dumps
```

产出（原文示例，**「这里假设」的数字，不许抄**）：`11 file(s)` / `3 unique image(s)`。
唯一数远小于文件数时，后面只需要看 3 份 —— 这一步就省掉了 2/3 的后续工作。

`REJECTED:` 行表示那不是 dex，或截断。`--trim` 只救"页对齐导致尾部多出来"的那一种，
救不了短于自身 `file_size` 的截断；被拒样本**不进**排序，别拿它当"最小的一份"。

## 第 3–4 步：判内容、判覆盖面（决定要不要花窗口的两步）

```bash
# 第 4 步：覆盖面（两个前缀都查，命中数要与 recon 阶段记下的类数量同数量级）
python Tool/skill/apkseep/scripts/dex_dump_validate.py ./dumps/classes2.dex \
    --find 'Lcom/example/app/' --find 'okhttp3/'
```

第 3 步读的是 `stub%` / `emptied%` 两列：**`>=50%` 的一堆是抽取壳形态，个位数的一堆是候选原镜像**。
原文强调它是**双峰**而不是阈值 —— 旧稿里"几十个百分点"的判据已被实测推翻并删除
（`references/evidence-summary.md` §The capability matrix）。

通过的形态（`advanced-unpacking.md` §通过长什么样）：

| 检查 | 通过 | 不通过意味着什么 |
|---|---|---|
| 结构合法 | 每个候选 `cksum=ok sig=ok`、`class>0` | 头部两字段没重算，或 dump 起点偏了 |
| 内容在 | 候选原镜像 `stub%` **个位数** | 抽取壳；恢复方法体是另一条路线，不是"再多 dump 几次" |
| 唯一性 | 唯一镜像数 ≤ 你预期的 dex 数 | 在重复 dump 同一块内存，或在 dump 已释放的区间 |
| 覆盖面 | `--find` 命中数与字符串表里该前缀的类数同数量级 | 主 dex 还没拿到；此时任何"脱壳完成"都是假话 |

## 第 5 步：排除 Java2C（这一步最常被跳掉）

```bash
python Tool/skill/apkseep/scripts/java2c_probe.py --apk ./target.apk --json > j2c.json
```

判据（`advanced-unpacking.md` §命令块 C）：普通 JNI 目标的 native 声明密度 **0.03–0.04%**，
Java2C 形态 fixture **82.76%**；同时 dex 的 native 方法数要与 `.so` 里 `Java_*` 符号数按 ABI 一一对应。
**两组数字都在，才可以继续谈 dump**；只有一个数字时，你手上只是一个 `inferred` 猜想。

跳过这一步的代价是原文点名的："省下来的是花两天找不存在的 dex"。

## 第 6 步：分岔（三条出口，只有一条通向继续）

- 第 3 步里**没有**个位数 `stub%` 的镜像 ⇒ 全堆都是抽取壳 ⇒ 去主动调用循环，
  或按 `02-failure-criteria.md` §3 写边界。
- 第 4 步的 `--find` 命中数明显偏少 ⇒ 主 dex 还缺 ⇒ 回到区间选择（先读 map 再选字节）。
- 第 5 步的密度到几十 % ⇒ **停**，转 `references/java2c-and-jni-sinking.md`。

## 第 7 步：只有到这一步才花窗口，且一次只读一个区间

开窗之前先跑三个便宜实验（`advanced-unpacking.md` §花窗口之前的三个成本实验）：
生命期、内存压力、写出速率。三个数字都拿到之后，"dump 全部"通常会变成"dump 这两个区间"。

```bash
# 生命期：每 500 ms 采一次，采 20 次；第一次采到空的时间就是生命期
adb shell "su -c 'pidof <pkg>'"
# 内存压力
adb shell "su -c 'cat /proc/<pid>/status'" | grep -E 'VmRSS|VmSize'
```

**单变量纪律**（`long-task-discipline.md`）：一次只读一个区间。原文的教训是
"一次窗口里读了四个区间，然后分不清是哪个区间读坏了"。

## 第 8 步：落账 —— 六行，`next` 必须是一个动作

（来源：`advanced-unpacking.md` §记录模板，原样保留）

```
goal:            <要拿到哪一层的代码，为什么>
capture:         <怎么来的：frida / /proc/<pid>/mem / 文件>  时间窗 <t0..t1>
images:          <唯一镜像数> 份；sha256[:12] 列表
stub%:           <候选原镜像的 stub% / emptied%>      判据：个位数 vs >=50%
coverage:        --find '<包前缀>' > <命中数>，dex 字符串表里该前缀 <N> 条
excluded:        Java2C(密度 <x>%) / 非 dex 区间 <清单>
next:            <主动调用 | root dump | 停止并说明边界>
```

## 之后：从"有镜象"到"能交付"，是另一条链

拿到镜像只是 `01-criteria.md` §2 的 Rung 0。接下来是一条**逐级爬 Rung** 的链，
每一级都有必须存在的证据（来源：`references/verification.md` §The claim ladder）：

```bash
# Rung 1：结构完整（类集合一致、ACC_INTERFACE 零漂移、未改的类逐字节相同）
python Tool/skill/apkseep/scripts/dex_classdiff.py baseline.dex patched.dex

# Rung 1.5：补丁是否"合法"（verifier 层是静态检查看不见的一层）
python Tool/skill/apkseep/scripts/dex_check_verifier.py out.apk

# Rung 2：重打包 + 签名（顺序：先签名，再对齐 —— 反过来会让对齐失效）
python Tool/skill/apkseep/scripts/repack.py --apk original.apk --out control.apk

# 只动了想要的 entry 吗（整包视角，不是只看我改的那一段）
python Tool/skill/apkseep/scripts/apk_diff.py original.apk out.apk --summary
```

**对照组先跑**（`verification.md` §The control build rule）：同一条管线、**零补丁**。

- 对照组也失败 ⇒ 管线/环境/设备的问题，停止调试补丁。
- 对照组通过、打了补丁的失败 ⇒ 补丁被牵连；逐个 dex 回滚定位。

`patch-audit.md` §Command block 给的顺序就是"失败最快"的顺序：
① 这个构建能不能加载（verifier 合法性，与你的意图无关）→ ② 改动是否只动了目标（类集合 + access flags）
→ ③ 目标指令是否在目标偏移上真的变了（解码，别肉眼看）→ ④ 头部是否按序重算 → ⑤ 声明的目标之外有没有东西移动。

交付形态的边界（`handoff-boundaries.md` §A boundary record, in six lines）：把六行写进记录，
特别是最后两行 `not determined` 与 `falsifier` —— 一次没写出来的"未确定"会变成隐含断言。

## 两个真实回放过的站台（仓库内证据，不是示例数字）

| 案例 | 走到哪一站 | 实测数字（来自案例记录，不是本文档的例子） |
|---|---|---|
| `Tool/cases/apkseep08` | 第 1–2 步 + 加固定性（**没到脱壳**） | 100 MB 原件、6 个 dex、52 个 so、包名/类名随机化；`StubApp` 命中但上下文是 `com.google.android.launcher/.StubApp` ⇒ 不是 360 加固 |
| `Tool/cases/apkseep07` | 第 1 步 + 加固定性 + 静态边界 | 16 个壳特征计数全 0（不是商业壳）；保护是 native 反调试（ptrace+fork）+ root 检测 + 字符串隐藏；secret 明文在 dex 与 so 均不存在 ⇒ 静态只能拿结构 |
| `Tool/cases/leaf-apk` | Rung 1→2（改 smali → 重打包 → 对齐 → 签名） | 单 dex 1931680B、零 so；16 个加固特征串全 0；链路闭环后 `zipalign -c` 通过、`jarsigner -verify` rc=0；**未做到 Rung 3/4**（无在线设备、样本无广告 SDK） |

最后一行是这一篇最该被记住的一句：**"改得动、打得回、签得上"不等于"装上能跑、行为变了"**。
`leaf-apk` 的案例记录自己写明"未验证（诚实缺口）"，这正是 `01-criteria.md` §2 要求报告写 Rung 等级的原因。

## 这一篇算「用对了」吗

- [ ] 我按 1→2→3→4→5 跑完了离线四步 + Java2C 排除，才考虑开窗口
- [ ] 我的记录里有 `stub%`、唯一镜像数、`--find` 命中数三个数字
- [ ] 我没有把原文示例里的「这里假设」数字抄成自己的结论
- [ ] 我开窗前跑过生命期/内存/写出速率三个成本实验
- [ ] 我在写"完成了"之前，说得出自己停在哪个 Rung，以及下一级的证据是什么
- [ ] 我留了对照组（同管线、零补丁），并记录了两边各自的结果
