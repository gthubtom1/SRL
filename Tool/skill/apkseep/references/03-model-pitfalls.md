# 03 模型常见失误 —— 这一域里最贵的二十几种"看起来对"的做法

> 本篇是以下文件的归并索引：`references/pitfalls.md` §按代价排序、§三个反模式、§哪些坑可以变成一条检查、
> `references/pitfalls-1-packaging-and-dex.md`（P1–P8）、`references/pitfalls-2-environment-and-evidence.md`（P9–P22）、
> `references/pitfalls-3-patching-and-artifacts.md`（P23–P30）、`references/pitfalls-4-native-and-install.md`（P31–P38）、
> `references/pitfalls-5-verification-and-decoding.md`（P39–P42）、
> `references/handoff-boundaries.md` §The four ways a boundary gets crossed wrongly、§Six mis-crossings、
> `references/long-task-discipline.md` §Long-context decay: the same mistake, twice、
> `references/detection-and-anti-analysis.md` §Step 2B、
> `references/membership-and-limits.md` §The fake-VIP trap、
> `references/verification.md` §The claim ladder、
> `references/evidence-summary.md` §What a row does not tell you、
> `SKILL.md` §Stop conditions、§Non-negotiable constraints。
>
> **本篇不新增条目**：每条都能指回上列文件里已经付过代价的那一条；编号 `M**` 是本篇的索引号，
> 原始编号（`P**`）与来源文件写在每条末尾，检索时以 `P**` 为准。

## 怎么用这一篇

先按**现象**找到一条，再读它的「机制」和「判据」两行。**"这条我读过"不等于"这次在此情形下失效"** ——
条目是按机制归类的，命中时要对着自己当前的现象再确认一次条件（来源：`pitfalls.md` §三个反模式）。
目录里没有命中的条目时，正确动作是按 `SKILL.md` §Stop conditions 停下来分类，而不是继续试。

检索入口（来源：`pitfalls.md` §命令块 A，原样搬运；编号以 `P**` 为准，`M**` 只是本篇索引）：

```bash
# 1) 列出全部编号（连续性与总数一眼可见）
grep -h -o '^## P[0-9]\+\.' pitfalls-*.md | sort -t P -k2 -n | tr '\n' ' '

# 2) 按编号查一条（别人日志里只给了编号时）
grep -n '^## P21\.' pitfalls-*.md

# 3) 按现象关键词查（英文条目用英文关键词，别用中文猜）
grep -rn -i 'checksum\|resources.arsc\|INSTALL_FAILED\|META-INF\|move-result' pitfalls-*.md | head
```

期望输出形态：编号 1–42 **连续无空洞**；按编号查只命中一处；按现象查命中数不为 0。
三条里任一条对不上，别急着加新条目 —— 先按 `pitfalls.md` §命令块 B 证明它还没被写过。

## M01 删掉整个 `META-INF/` 当作"清理签名残留"
- 机制：重打包时把 `META-INF/` 整目录删掉会连带删掉 `services/` 等被运行时加载的条目，包还能装、启动即死。
- 判据：输出 APK 的 `META-INF/` 里除了签名文件是否还有 `services/`。
- 来源：`pitfalls-1-packaging-and-dex.md` P1；机检：`apk_diff.py` repack 前后对比。

## M02 把字符串改长了，还说"内容一样就行"
- 机制：`string_ids` 必须按 UTF-16 码点有序；改长会破坏顺序，整包被拒。**等长替换**是这条约束下的唯一安全形态。
- 判据：`string_ids` 是否仍有序、dex 是否仍通过 `dexutil.verify_dex_header`。
- 来源：`pitfalls-1` P2；机检：`dex_strpatch.py` 的排序守卫。

## M03 用全树 smali 往返做小改动
- 机制：R8 优化过的 dex 被整树重建后，表检查全过、运行时坏。方法级重建还会把文件撑大（实测 `debug_info` 924 B → 22.8 KB，dex 4.32 MB → 7.73 MB）。
- 判据：改动是否需要**新指令**。不需要就用等长改字节。
- 来源：`pitfalls-1` P3；`dex-patching.md` §Pick the least destructive technique。

## M04 对同一个 dex 改写两次
- 机制：ART 拒绝启动被二次改写的 dex —— 现象是"改对了却起不来"。
- 判据：一次构建只允许一次写；第二次改动从原始基线重做。
- 来源：`pitfalls-1` P4。

## M05 为了藏一个 UI 元素，把接口打成 404
- 机制：同屏其它功能依赖这个接口，一个 404 会把整屏带走（实测形态：永远停在启动页）。
- 判据：抑制点在**数据消费层或渲染层**；如果请求路径变了，那就是 bug。
- 来源：`pitfalls-1` P5；`SKILL.md` §Non-negotiable constraints。

## M06 补丁打在一个被广泛调用的 helper 上
- 机制：`Long.valueOf` 形状的 helper 有 30 个调用方，它不是广告专用 hook。
- 判据：动手前数调用方。
- 来源：`pitfalls-1` P6；机检：`find_refs.py`。

## M07 客户端伪造 VIP / 会员态
- 机制：伪造出来的权益在服务端没有对应资源，屏幕是空的 —— 比登出更糟的状态。
- 判据：先判"谁决定"（客户端可执行 vs 服务端权威）。服务端权威时，正确产出是报告 + 边界。
- 来源：`pitfalls-1` P7；`membership-and-limits.md` §The fake-VIP trap。

## M08 把静态反编译结果当成运行时行为
- 机制：反编译读到的是"代码写了什么"，不是"这次运行走了哪条路"。R8 之后连符号都会变形。
- 判据：结论里有没有一次**运行时**观察（hook 触发、日志、屏幕）。
- 来源：`pitfalls-2-environment-and-evidence.md` P10。

## M09 只看 `apksigner verify` 的输出
- 机制：签名校验通过只说明签名合法，不说明装得上、起得来、功能对。它对应的是 Rung 2，不是 Rung 4。
- 判据：报告里写的是哪一级 Rung。
- 来源：`pitfalls-2` P13；`verification.md` §The claim ladder。

## M10 把同尺寸的 dex dump 当成"另一份证据"
- 机制：同一块内存 dump 多次，文件名不同、内容相同；后续每一条推断都会被自己重复计数。
- 判据：`dex_dump_validate.py` 的 `dedupe` 段（唯一镜像数）。
- 来源：`pitfalls-2` P14；`advanced-unpacking.md` §常见误判 ②。

## M11 包管理器报成功，就当装上了
- 机制：安装成功描述的是**请求**，不是磁盘上的 app。之后每条观察都在描述上一版。
- 判据：设备上产物的 hash 等于本地构建的 hash。
- 来源：`pitfalls-2` P18；机检：`install_test.py` / `coldstart.py`。

## M12 用内部信号代替用户可见结果
- 机制："hook 触发了"是内部信号；用户要的是屏幕上的结果。两者可以同时为真与相反。
- 判据：结论是否以**用户可见**的现象为终点。
- 来源：`pitfalls-2` P19；`SKILL.md` §What "done" means。

## M13 把"我没抓到"当成"它不在"
- 机制：采样窗口、`logcat` 缓冲、清理时机都会制造这种假缺失。
- 判据：有没有一次阳性对照证明"这套采集能抓到已知存在的东西"。
- 来源：`pitfalls-2` P20；`pitfalls.md` §三个反模式。

## M14 一次改两个变量，然后归因
- 机制：复合失败不教任何东西，而且会被归到错误的原因上（本域最贵的一条：数小时）。
- 判据：这次失败前面是否只有**一个**变量变了。
- 来源：`pitfalls-2` P21；`SKILL.md` §R2；`long-task-discipline.md` §Single-variable discipline。

## M15 把"搜索没找到"当成"数据不在"
- 机制：搜索器可能提前退出（解码脱同步）、也可能搜错了空间（文件偏移 vs pool 偏移）。
- 判据：阳性对照 + 换一个独立读取器复算。
- 来源：`pitfalls-3` P25、`pitfalls-4` P33。

## M16 用"不返回"来封掉一条终止路径
- 机制：自旋桩让调用方**持锁**卡死，无关线程一起挂；症状（挂起、被杀、重启循环）与病因完全不像，且没有崩溃记录。
- 判据：用**返回**良性值抑制，优先成功值（`0`）；绝不改写 `pthread_exit` / `exit` / `abort`。
- 来源：`pitfalls-4-native-and-install.md` P31；`native-tamper-and-suicide.md` §The rule。

## M17 把蓄意崩溃读成普通 bug
- 机制：加固库很少调 `kill`，更常**制造一个 fault**（加载小常量当指针），让死亡看起来像普通缺陷。
- 判据：先枚举真正触发的是哪个机制（信号与 tombstone 能把它们分开）。
- 来源：`pitfalls-4` P34。

## M18 用节头解析一个被去节的 ELF
- 机制：加固库经常伪造/删除节头，用节头走一遍会得出"没有符号"。
- 判据：函数边界来自 `PT_GNU_EH_FRAME` / 程序头，不来自节头。
- 来源：`pitfalls-4` P36；`native-tamper-and-suicide.md` §Forged section headers。

## M19 改完字节就收工，没按序重算头部
- 机制：dex 头部有两个完整性字段，**先 signature 后 checksum**；顺序反了会得到 `Bad checksum` + 一个普通类 `ClassNotFoundException`。
- 判据：`dexutil.fix_dex_header` 的调用顺序；`dex_check_verifier.py` 是否通过。
- 来源：`pitfalls-4` P37；`byte-level-patching.md` §The dex header has two integrity fields。

## M20 装包报 `[-124]` 就去改 `resources.arsc` 的内容
- 机制：这条报错说的是 **STORED 且 4 字节对齐**，不是内容。
- 判据：`resources.arsc` 是否 STORED 且对齐。
- 来源：`pitfalls-4` P38；机检：`repack.py` 安装前检查。

## M21 截了图，却从日志或从补丁本身下结论
- 机制：没被看过的截图不构成证据；逐字节相同的连拍说明什么都不会变。
- 判据：截图是否**逐张看过**，且结论引用的是屏幕上看到的东西。
- 来源：`pitfalls-2` P20；`long-task-discipline.md` §Captures you never looked at are not evidence。

## M22 截到的"你的应用"其实是别的应用
- 机制：厂商安装器/商店页会占住前台，`am start` 之后前台不是目标包。
- 判据：前台 Activity 的包名是否等于目标包。
- 来源：`pitfalls-5-verification-and-decoding.md` P40；机检：`coldstart.py` 的"前台不是你"警告。

## M23 改出来的分支做了相反的事，而进程起得很干净
- 机制：分支取反后启动毫无异常，是"静态检查看不出、只有功能观察能看出"的那类错误。
- 判据：必须跑 Rung 4（直接观察功能），不是 Rung 3。
- 来源：`pitfalls-5` P41；`verification.md` §The claim ladder。

## M24 解码脱同步之后，继续读后面的每个偏移
- 机制：指令长度解错一次，之后所有偏移都错；错得越久越像"目标结构复杂"。
- 判据：解码器是否在已知合法输入上做过自检；偏移是否**算出来**的而不是猜出来的。
- 来源：`pitfalls-5` P42；`SKILL.md` §Tooling（"用脚本前先看有没有现成的"）。

## M25 用对岸的工具回答这一岸的问题
- 机制：为回答"这个类有没有方法体"去 dump 内存；为回答"这个库加载了没有"去反编译 `.so`。工具更重、答案更plausible —— 而 plausible 在这里比"没有答案"更糟。
- 判据：你用的工具是否就是这个问题所在层的工具。
- 来源：`handoff-boundaries.md` §① Using the other side's tool on this side's question。

## M26 把"接缝"当成"实现"
- 机制：`Java_*` 符号只说明函数存在，不说明它就是你要找的那个；R8 下符号还会随类名变形。
- 判据：有没有跨到实现那一侧去读。
- 来源：`handoff-boundaries.md` §② Reading the join as the implementation。

## M27 悄悄换了交付形态
- 机制：在 root 设备上跑通的 hook，被用"成品 APK"的语言写进报告 —— 这就是 R1 点名的那次漂移。
- 判据：每个检查点重读 G1 那一句，并写出形态。
- 来源：`handoff-boundaries.md` §③；`SKILL.md` §R1。

## M28 把"边界"当"判决"
- 机制："检查在 native 层，所以客户端不可改"是把边界越过后误读 —— native 代码仍是客户端代码。
- 判据：真正的判决要求**服务端**拥有那个值。
- 来源：`handoff-boundaries.md` §④；`server-api.md` §Prove who owns the gate。

## M29 长上下文衰减：把已经证过的事再证一遍
- 机制：同一个人第二次犯同一个错；而**重验证很便宜、重决策不便宜**。
- 判据：实验记录里有没有"已定（不要再推）/ 已推翻（不要再试）"两段。
- 来源：`long-task-discipline.md` §Long-context decay；`SKILL.md` §Long-task rule。

## M30 越加越多的绕过模块
- 机制：每加一个模块，目标多一个可以注意到的点，之后的结果更难归因。
- 判据：三个数里两个为真就转静态（模块数、是否需要 keepalive、是否只在全栈下才正常）。
- 来源：`detection-and-anti-analysis.md` §Step 2B。

## M31 把 `evidence-summary` 的"ok"读成"已验证"
- 机制：矩阵里每一行都带 `status` 与 `strength`；`ok` + `unverified` 是合法组合（脚本能跑，但没在真实加固目标上跑过）。
- 判据：读的是 `strength` 那一列，不是 `status`。
- 来源：`evidence-summary.md` §What a row does not tell you。

## 自查（五条，任一不成立就说明这一步没做对）

- [ ] 我能说出最近一次失败属于本篇哪一条，并引用了它的 `P**` 编号
- [ ] 我的结论里有 Rung 4 以上的观察，而不只是"能装、日志干净"
- [ ] 我数过调用方 / 做过阳性对照 / 留了对照组，而不是凭"应该没问题"
- [ ] 我没有把"我没抓到"写成"它不存在"
- [ ] 我的记录里有"已推翻，不要再试"这一段，且它是最新的
