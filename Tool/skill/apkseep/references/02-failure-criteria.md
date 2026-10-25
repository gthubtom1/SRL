# 02 失败判据 —— 什么时候必须停手、改走哪一条

> 本篇是以下文件的归并索引：`SKILL.md` §Stop conditions、§The workflow, end to end（Two-strike rule）、
> `references/pitfalls.md` §按代价排序：先修哪几条、§三个反模式、
> `references/pitfalls-1-packaging-and-dex.md` … `references/pitfalls-5-verification-and-decoding.md`（P1–P42）、
> `references/detection-and-anti-analysis.md` §Step 2: if it *is* detection, decide by cost, not by pride、
> §Step 2B、§Step 4: when the tool cannot work here at all、§Step 6、
> `references/coverage-and-limits.md` §Not covered、§Dependencies this skill does not ship、
> `references/advanced-unpacking.md` §什么时候该停手并写边界、
> `references/advanced-unpacking-2-root-dump-and-vmp-boundary.md` §Limits to budget for、§What this route cannot do、
> `references/java2c-and-jni-sinking.md` §Failure modes、
> `references/packers.md` §Reading the rejection signal、
> `references/native-tamper-and-suicide.md` §The rule、
> `references/verification.md` §The control build rule、
> `references/handoff-boundaries.md` §The four ways a boundary gets crossed wrongly、
> `references/long-task-discipline.md` §Refuted (do NOT retry)。
>
> **本篇不新增判据**：每一行都能指回上面某个文件已有的一句话；查不到来源的行一律不写。

## 0. 三条总规则（先记住这三条，再看表）

（来源：`SKILL.md` §Stop conditions；`long-task-discipline.md` §Long-context decay）

1. **同形失败第二次就回分类，不许跑第三次变体。** 两次同形失败说明模型错了，不是参数需要调。
2. **"改了没效果" = 诊断错了，不是补丁运气不好。** 回分类，不要在同一个假设上试第三个变体。
3. **"没有报错"永远不是成功判据。** 见 `01-criteria.md` §2 的 Rung 4 —— 要直接观察被改的那个功能。

## 1. 失败判据表（现象 → 判据 → 不许得出的结论 → 改走）

| # | 现象 | 判据（可观察/可机检） | 不许得出的结论 | 改走 | 来源 |
|---|---|---|---|---|---|
| F1 | 重打包后启动即死、`SIGSEGV`、寄存器全 0、`pc=0` | 先看是不是**蓄意崩溃桩**：加载一个小常量再当指针用 | "加固壳拒绝了我" | `native-tamper-and-suicide.md`（先定位机制，再谈补丁）→ 若是 `JNI_OnLoad` 返回 `JNI_ERR`，读 `packers.md` §Reading the rejection signal | `pitfalls-4` P34；`SKILL.md` §Symptom index |
| F2 | 日志显示 **Java 层**签名校验通过，进程仍然死 | Java 层的"签名杀手"是诱饵；真正的检查在 native 侧 | "校验已经被我绕过了" | `code-virtualization-and-custom-linkers.md` §A Java-layer "signature killer" is a decoy | `SKILL.md` §Symptom index |
| F3 | 删掉一个库后校验过了，但报 `UnsatisfiedLinkError: dlopen failed: library "X" not found` | 报错文本是 **你自己的** 依赖缺失 | "目标检测到了我" | 先 grep 崩溃里的 `linker` / `CANNOT LINK` / `dlopen` / `not found` | `packers.md` §Reading the rejection signal |
| F4 | 整个类是裸 `native` 声明、`Java_*` 搜不到 | 导出 `JNI_OnLoad` 且零 `Java_*` ⇒ 动态注册或 Java2C：**此时没有任何 dex 可 dump** | "dump 得不够深，再 dump 一次" | `java2c-and-jni-sinking.md` §The JNI boundary（读 `.so`，不是读内存） | `dynamic-frida-2-failures-and-anti-instrumentation.md`；`SKILL.md` §Symptom index |
| F5 | dump 完整解析、类都在、方法体是 `return-void`/nop | `stub%` 落在高那一峰 | "脱壳成功了" | `advanced-unpacking-1-...md`（FART 主动调用），或按 §3 写边界 | `advanced-unpacking.md` §常见误判 ① |
| F6 | 方法体在，但解出来是私有 opcode | 静态判据只能**排除** VMP，不能判定 | "这是 VMP，所以做不到" | `vmp-differential-analysis.md`；终点常是"成本高于收益" | `advanced-unpacking-2-...md` §The honest boundary: real Dex VMP |
| F7 | 进程只活 1–2 秒，一个内存窗口都放不下 | 生命期 < 5 s ⇒ 先把输出量减下来，或先解决死亡 | "目标加固很深" | 先 `native-tamper-and-suicide.md` 解决死亡，再谈 dump | `advanced-unpacking.md` §什么时候该停手并写边界 |
| F8 | 工具 attach 失败/attach 即死/attach 后零事件，且报错提到 tracer/ptrace/debugger | 设备用翻译层跑另一个 ABI：这是**环境事实**，不是目标特性 | "目标有反调试，我要加第 N 个绕过模块" | 用一次干净复现把环境事实写下来（`Step 6` 那一行），转全静态 | `detection-and-anti-analysis.md` §Step 4、§Step 6 |
| F9 | 绕过模块越加越多，只有全套模块在场时目标才正常 | 三个数里两个为真：模块数、是否需要 keepalive、是否只在全栈下才正常 | "再补一个模块就好" | 转静态（同一文件的 Step 2B 阈值） | `detection-and-anti-analysis.md` §Step 2B |
| F10 | 补丁"没效果"，且没有任何错误 | 没有效 = 层的诊断错了 | "再试一个变体" | 回 `SKILL.md` §Start here 十三问重分类 | `SKILL.md` §Stop conditions |
| F11 | 每次签名请求都失败，但应用能起、UI 正常 | grep 命中签名派生密钥形态 | "是服务端改了" | `signature-derived-keys.md`（在被读处硬编码原证书值） | `pitfalls-3-patching-and-artifacts.md` P27 |
| F12 | 对照组（同管线、零补丁）也失败 | 失败归属是**管线/环境/设备**，不是补丁 | "补丁写错了" | 先修管线；`verification.md` §The control build rule | `pitfalls-2` P9 |
| F13 | 搜索"没找到"某字符串/方法/调用点 | 必须先在**已知存在**的输入上做阳性对照 | "这个数据不在包里" | 补阳性对照，再谈缺失 | `pitfalls-3` P25、`pitfalls-4` P33 |
| F14 | 设备上的行为与本地构建对不上 | 设备上的包 hash 不等于本地构建 hash | "我的补丁没生效" | `install_test.py` / `coldstart.py` 的"前台不是你"警告 | `pitfalls-3` P24、`pitfalls-2` P18 |
| F15 | 想放弃一条路线 | 放弃必须有单变量证据；两个变量一起改过的失败不算证据 | "这条路走不通" | 只用单变量重跑一次再写死 | `SKILL.md` §Non-negotiable constraints |
| F16 | 需要击穿服务端权威 | `server-api.md` 只判"谁拥有这个门" | "客户端补丁能解决" | 写成带边界的报告（`01-criteria.md` §4 第四形态） | `coverage-and-limits.md` §Not covered |

## 2. 能力缺口不是"再试一次"能填的（改走清单）

（来源：`references/coverage-and-limits.md` §Not covered、§Dependencies this skill does not ship）

| 缺口 | 本技能给到哪 | 现在该转到哪 |
|---|---|---|
| Unity / IL2CPP 逻辑恢复 | 只到运行时识别 | 无本域路线；在报告里写成"不覆盖"，不要硬套 `dart-aot.md` |
| React Native / Hermes、Cordova | 运行时识别 + "找字符串再找引用" | 同上；不要外推 IL2CPP/Flutter 的配方 |
| iOS / `.ipa` | 无 | 本域全部指令只对 Android 成立 |
| 服务端执行的授权 | `server-api.md` 判定归属 | 写成残余项，不要继续加补丁 |
| Dart AOT snapshot dump | 未随附 resolver；两个偏移空间不是常量差 | 明确写出你用的是哪个前端（aotopsy / blutter），两者对同一二进制报的 Dart 版本标签不同 |
| 开箱即用脱壳器 / 反检测军备竞赛 | 只路由问题 + 停手条件 | 按 §1 F5/F8/F9 转静态或写边界 |
| 内核模块 | `kernel-and-environment-hardening.md` 只画路线与版本门 | 不在本域；写边界 |
| 每台设备都能跑的 Stalker trace | 排除能让目标活着，但**不恢复事件投递** | 把零事件当成"要识别的边界"，不是"照着做的配方" |

## 3. 边界要写成一句可复核的话（模板）

（来源：`references/advanced-unpacking.md` §什么时候该停手并写边界，模板原样保留）

```
"在 <时间窗> 内用 <方法> 拿到 <N> 份唯一镜像，其中 <M> 份为抽取壳形态；
 方法体恢复未做，因为它需要 <具体机制>，本域由用户提供。"
```

这句话比"加固很强，脱壳失败"有用一百倍：它给出**可复核的量化前提**与**缺的那个机制**，
下一个人能据此决定是继续投入还是换形态。

**边界记录六行**（来源：`references/handoff-boundaries.md` §A boundary record, in six lines）：

```
observable:     <你真正看到的，连同它出现的层>
form:           <static JNI | dynamic registration | Java2C | loader | VMP | ordinary fault>
evidence:       <计数 / 密度 / 日志行 / trace，连同产生它的命令>
crossed to:     <拥有下一个问题的文件>
not determined: <这一侧无法判定的事，写成边界>
falsifier:      <什么观察会把它挪到另一侧>
```

## 4. 机检入口：这五条先跑，比继续推理便宜

（来源：`references/pitfalls.md` §哪些坑可以变成一条检查；命令参数以各脚本 `--help` 为准）

```bash
python Tool/skill/apkseep/scripts/doctor.py --capabilities --json    # 能力缺口（F8 的入口）
python Tool/skill/apkseep/scripts/dex_check_verifier.py out.apk      # 补丁是否合法（verifier 层）
python Tool/skill/apkseep/scripts/dex_classdiff.py a.dex b.dex       # F3/F4 类别漂移
python Tool/skill/apkseep/scripts/apk_diff.py in.apk out.apk --summary   # 只动了想要的 entry 吗
python Tool/skill/apkseep/scripts/scan_leaks.py --root .             # 交付前的泄漏面
```

## 5. 这一篇算「用对了」吗

- [ ] 我能在表里指出**当前现象**是哪一行，而不是凭印象继续试
- [ ] 我给"放弃某路线"配了单变量证据，而不是两个变量一起改的失败
- [ ] 我没有把"没有报错"当成"成功了"
- [ ] 我写过一句可复核的边界句，含时间窗、方法、数量、缺的机制
- [ ] 我把环境事实（工具跑不起来）单独记为一条，而不是混进"目标很硬"
- [ ] 我跑过 §4 里至少一条机检命令，且它的输出在案
