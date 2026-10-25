# Dynamic analysis with Frida — 拆分目录（2 篇，内容无损）

> 本篇范围：原 502 行 Frida 文档的入口页；正文拆成 2 篇，保留全部探测模板与反插桩内容。
> 前后篇：本页是目录；从 [dynamic-frida-1-setup-and-probe.md](dynamic-frida-1-setup-and-probe.md) 开始。

原文件按 `##` 小节拆分，小节标题与内容未摘要化。

| 子篇 | 覆盖小节 | 行数 |
|---|---|---|
| [dynamic-frida-1-setup-and-probe.md](dynamic-frida-1-setup-and-probe.md) | 版本对齐、Frida 17+ 陷阱、hook 策略、四层探测模板 | 384 |
| [dynamic-frida-2-failures-and-anti-instrumentation.md](dynamic-frida-2-failures-and-anti-instrumentation.md) | hook 不触发排查、`Java.choose` 死实例、混淆代码读取、反插桩、证据捕获 | 126 |

---

## 本页怎么用：Frida 的第一步不是写 hook，是判"能不能 attach"

两个子篇各有各的地盘，但它们之间有一道**环境门**：这道门不过，后面所有 hook 讨论都是空转。

| 你要做的事 | 读哪篇 | 前一篇为什么不合适 |
|---|---|---|
| 对齐 `frida` / `frida-server` 版本、选 attach 还是 spawn、装四层探测 | 子篇 1 | 子篇 2 假设"已经有一份能跑的会话" |
| hook 明明 `HOOK-OK` 却零事件、`Java.choose` 命中死实例、名称被混淆 | 子篇 2 | 子篇 1 只到"探测装上"，不含"装上之后为什么没输出" |
| 进程一 attach 就死、`frida-server` 被 ROM 杀掉、设备自己重启 | 先读本页 §环境门，再进子篇 2 | 这两类症状经常被误记成"目标反调试"，而它们有一半是环境 |
| 只需要**调用**目标自己的函数（签名/token/加密） | `emulation-and-rpc.md` | 那是另一个交付形态；在本页继续加 hook 会走偏 |

**顺序是硬的**：环境门 → 会话能存活 → 事件能到达 → 命中能解释。跳过其中任何一层，你都会在
后面某处把"工具没工作"当成"目标没有这个行为"。

## 环境门：四个数，一次采完

Frida 失败的原因里，**版本/权限/端口/时钟**这四类占了大头，而它们都能在写第一行 JS 之前测出来。

```bash
# 1) 本域工具的总体能力（缺什么、装它要多久）——最先跑，最便宜
python scripts/doctor.py --json | head -40

# 2) 设备侧前置条件（root、ABI/翻译层、时钟偏移、残留 proxy/forward、已死的 device server）
python scripts/preflight.py

# 3) 版本必须两侧对齐：客户端与设备端
pip show frida 2>/dev/null | grep -i '^Version'          # 或: frida --version
adb shell "su -c '<server-binary> --version'"            # 设备侧二进制的版本
adb shell "su -c 'pidof <server-binary>'"                # 空 = 没在跑（这才是"连不上"的常见原因）

# 4) 端口转发是否还在（重连后经常要重建）
adb forward --list
```

期望输出（形态；具体值随机器变）：

```
# doctor.py --json（摘要）
{"capabilities": [{"name": "frida-attach", "state": "ok", ...},
                  {"name": "apksigner", "state": "BLOCKED", "missing": ["apksigner"], ...}]}

# preflight.py（摘要）
[ok]   device: 1 device online      [warn] clock skew: 41s
[ok]   root: su -c id → uid=0       [warn] leftover proxy: 127.0.0.1:8080
[ok]   abi: arm64-v8a (no translation)

16.5.9      <- client
16.5.9      <- server
12345       <- pidof 有输出
emulator-5554 tcp:27042 tcp:27042
```

**通过长什么样**：两侧版本字符串**相同**、`pidof` 有输出、`adb forward --list` 里有你用的那一条、
`preflight` 没有 `clock skew` 之外的 warn（有 skew 就先记下来，它会让"超时"这类结论失真）。
四项里有一项不过，就不要开始 hook —— 你会把它的后果记到目标头上。

## 命令块：把一次会话做成可复盘的记录

```bash
# 四层探测（网络层 + OkHttp + java.net + 被吞的异常消息），流式落盘，进程常驻
python scripts/run_probe.py --pkg <pkg> --script scripts/frida_probe.js --out probe-$(date +%s).log

# 只想先看环境自述 + 谁读了 /proc/self/maps（只观察，不改任何字节）
python scripts/anti_detect_probe.js    # 通过 run_probe.py 注入；见下
python scripts/run_probe.py --pkg <pkg> --script scripts/anti_detect_probe.js --out env.log

# spawn 下 Activity 栈起不来时：先在内存里写补丁，detach，再正常启动
python scripts/spawn_patch_detach.py --pkg <pkg>
```

**通过长什么样**：

| 观察 | 通过 | 不通过时的含义 |
|---|---|---|
| `probe-*.log` 首行 | 有时间戳、`pkg`、`pid`、客户端/设备端版本 | 没有版本行 ⇒ 这份日志以后无法证明是哪个组合跑出来的 |
| 四层探测 | 每层至少一行 `HOOK-OK` 或明确的 `HOOK-SKIP` 理由 | 整层消失 ⇒ 加载顺序/类加载器问题，不是"这层没有调用" |
| `env.log` | 有 `TracerPid`、有 frida 命名的映射列表、有首次检测到的时间点 | 只有空白 ⇒ 注入成功但脚本没跑，先查 `logcat` 的脚本错误 |
| `spawn_patch_detach.py` | 打印 `PATCHED` 之后才 detach，且 detach 后 UI 能起 | 打印顺序反了 ⇒ Activity 栈永远起不来，见子篇 1 §spawn keeps the Activity stack down |

## 三条纪律，比任何 hook 模板都重要

1. **一个变量。** 一次会话里只改一个东西（是否 spawn、是否 hook 某一层、是否改了 server 名）。
   两个变量同时改，得到的是"某个组合能用"，而不是"哪个因素起作用"。
2. **对照必须同环境。** 原版包在同设备、同网络、同 root 状态下跑一遍；否则你无法区分"目标检测到
   frida"和"这台机器本来就不让这个包活"。这是 `detection-and-anti-analysis.md` 的入口条件。
3. **零事件先归因，再定性。** 零事件的三种成因（脚本没跑 / 路径没走到 / 被检测后提前退出）看的东西
   完全不同：`logcat` 脚本错误 / 栈与断点 / 进程生命期曲线。把三者混成"没有这个行为"是本域最常见的假阴性。

## 会话台账（每次实验一行，别靠记忆）

| 字段 | 为什么必须记 |
|---|---|
| 客户端版本 / 设备端版本 | 版本偏斜会产生看起来像"目标崩了"的错误（P15） |
| 注入方式（spawn / attach by name / attach by pid） | 三种方式的行为不同，尤其对早期检测 |
| 包 hash + 安装时间 | 证明这次观察的是**这个**构建，不是上一次留下的 |
| 会话起止时间 / 进程 pid 变化 | pid 变了说明进程重启过，两次观察不是一个状态 |
| 事件计数（每层） | "有没有"和"有多少"是两件事；后者能证明窗口够长 |
| 结束时设备状态 | `frida-server` 还在不在、`adb forward` 还在不在，决定下一次能不能复现 |

## 四种"以为 hook 生效了"的形态

这四种都发生在**脚本没有报错**的前提下，所以它们不会打断你，只会让结论慢慢变错。

**① 钩到的是包装层，不是业务层。** OkHttp 的 `Interceptor` 链、SDK 自己的 `a.a.a()` 转发层、
Kotlin 协程的 `invokeSuspend`，都是"名字对、语义不对"的位置。判据：打印的栈里，业务类是否出现在
**你的 hook 之下**而不是之上。动作：往栈的下游再走一层，或者直接 hook 最靠近数据消费的那一个方法。

**② 方法命中但参数是 `null` / 默认值。** 常见于 hook 了接口/抽象方法的重载错位，或 hook 了
`Object` 参数版本而实际调用的是 `String` 版本。判据：参数类型与数量必须与实际调用一致；用
`Java.use(...).overloads` 逐个枚举，并打印 `overloads.length`。动作：显式指定 `overload(<types>)`。

**③ 事件来了但被自己的输出吞掉。** 高频 hook（每个请求、每次渲染）把日志刷满，真实事件被截断或
超时丢弃。判据：日志行数 vs 事件数是否一致；文件是否在某个大小处停止。动作：在脚本里做计数与采样
（前 N 条 + 每 M 条一条），并把上限写进脚本而不是事后 `head`。

**④ 命中的是上一次运行的进程。** pid 变了但脚本还连着旧的（或反过来）。判据：日志里的 pid 与
`pidof <pkg>` 当前值比对，且与"安装时间"一起看。动作：每次实验前重读 pid 与包 hash，把
"这次观察的是这个构建"当成一条要打印出来的事实。

## 什么时候不该用 Frida（换轴的判据）

| 情况 | 为什么不划算 | 换到 |
|---|---|---|
| 只需要读一个常量/一个字段/一段配置 | 一条静态命令的事，注入引入了整个环境变量 | `dex_strings.py`、`runtime-data.md` |
| 目标生命期 < 1 秒，且检测在 `JNI_OnLoad` 之前 | 注入窗口短于可观测窗口 | `dynamic-frida-2-...` §静态插桩，或静态读 |
| 检测通过裸 `svc` 读 `/proc/self/status` | libc 层 hook 结构上看不到 | `kernel-and-environment-hardening.md` |
| 需要的是"调用一次并拿到返回值" | hook 是在猜调用时机，RPC 是直接调用 | `emulation-and-rpc.md` |
| 应用是 Flutter/RN，UI 由运行时绘制 | Java 层 hook 零命中是**正常**的 | `framework-runtimes.md`、`dart-aot.md` |
| 目标在 attach 后必死，且你只需要它的初值 | 每次都在同一个点死，观测窗口不可用 | 静态读 + 一次干净启动留下的缓存（子篇 2 §self-recorded evidence） |

这张表存在的意义：**不要在"该换轴"的地方继续调 hook 参数**。零命中之后每多试一次，都在给
"Frida 在此情形下失效于这个目标"这个错误结论添砖。

## 一次会话的最小时间线

把会话写成时间线，比写"我 hook 了 X，没触发"有用得多。模板（数字来自你自己的日志）：

```
t+0.00s  spawn 发出                   pkg=<pkg> build=<sha256[:12]>
t+0.31s  script loaded                client=16.5.9 server=16.5.9
t+0.34s  HOOK-OK  network (4 layers)  classes resolved: 12/12
t+0.35s  resume
t+0.41s  first DNS: <host>            (来自 network 层)
t+0.52s  JAVA-HIT  <class>.<method>   stack: <3 frames>
t+0.90s  process exit                 no java stack, no tombstone
```

三个判据直接从这条线读出来：

- **`resume` 与第一条业务事件的时间差** = 你的观测窗口有多大。差 < 100 ms ⇒ 任何"没看到"都要打折。
- **`HOOK-OK` 的解析比例**（`12/12`）说明 hook 是否真的装到了类上，而不是"我以为装了"。
- **`process exit` 之前有没有 `JAVA-HIT`** 决定这次是"目标自己退"还是"我的 hook 惊动了它"。

## 与其它交付形态的切换判据

| 你的目标是 | Frida 是不是对的工具 | 换成 |
|---|---|---|
| 证明"这个类在这个时机被调用" | 是（一次性探测最合适） | — |
| 让功能长期可用、且要装到别的设备上 | **不是**（会话一结束就没了） | `repack-and-sign.md` 或 `lsposed-and-modules.md` |
| 拿到一个签名/token 的结果 | 不必要地重 | `emulation-and-rpc.md`（RPC 或仿真） |
| 判定"服务器还是客户端拥有这个门" | 部分（能看到请求与响应，但权威判定要`server-api.md`） | `server-api.md` |

**一句话**：Frida 是**观察与定位**的工具，不是**交付**的工具。把它当交付，最后你会得到一个
"在我机器上、开着会话、root 状态下能用"的结果 —— 那正是 R1 里最贵的 drift。

## 命令块：零事件时先采这三样，再谈反调试

```bash
# A) 脚本层面：注入有没有报错（很多"零事件"其实是脚本一半没加载）
adb logcat -d -s Frida:F frida:F AndroidRuntime:E | tail -40

# B) 进程层面：它现在还活着吗，活了多久，谁杀的
adb shell "su -c 'cat /proc/<pid>/stat'" | awk '{print "state="$3, "starttime="$22}'
adb shell "su -c 'dmesg | tail -20'"          # 被内核/低内存杀掉时会留痕

# C) 观测层面：事件到底有没有发生（用进程自己的日志，不用你的 hook 判断）
adb logcat -d --pid=<pid> | tail -80
```

**通过长什么样**（三项都拿到了，才算"零事件"是一个观察）：

- A：`logcat` 里**没有** `Error: ...` / `TypeError: not a function` / `Java bridge` 报错。
- B：`state` 是 `R`/`S`（活着），`starttime` 与你的注入时刻对得上；若进程已不在，记下 `dmesg` 的最后一行
  —— "被 OOM 杀" 与 "自己 exit" 是两种完全不同的结论。
- C：`--pid` 过滤的日志里有正常业务活动（说明进程确实在跑业务），而你的 hook 没有输出。

三项齐了，才有资格说"hook 装了、进程活着、业务在跑、但没有事件"—— 这时零事件才**指向 hook 位置或类加载器**，
而不是指向检测。缺任何一项，它指向的是你的环境。

## 归因表：零事件的三条分支

| 分支 | 第一条命令 | 判据 | 下一步 |
|---|---|---|---|
| 脚本没跑 / 跑了一半 | A（`logcat` 脚本错误） | 有异常或只有前几行 `HOOK-OK` | 修脚本；用最小脚本先验证桥接可用 |
| 路径没走到 | C（进程自身日志）+ 一次真实 UI 操作 | 业务日志里没有对应动作 | 先让 UI 真的触发（`environment.md` §driving the UI），再 hook |
| 被检测后提前退出 | B（`stat` / `dmesg`）+ 时间线 | 退出发生在 `resume` 后极短时间 | 走 `detection-and-anti-analysis.md`，并且**先跑原版对照** |

这张表的作用不是穷举，而是**避免"零事件 ⇒ 反调试"这条默认推断**。在真实样本上，三条分支的比例
远没有直觉那么偏向第三条 —— 而误判成第三条的代价最大，因为它会导向一整套反-反检测工程。

## 汇报模板（会话版，复制改数字即可）

```
claim:        <一句话：观察到了什么，在哪一层>
channel:      frida spawn/attach (client <v> / server <v>)  forward: <tcp:port>
target:       <pkg> build=<sha256[:12]>  pid=<pid> (pid changed: yes/no)
window:       resume -> first business event = <x> ms;  session <a>..<b>s
events:       network <n> / okhttp <n> / java.net <n> / throw <n>     (per layer)
hits:         <class>.<method> x<n>   first hit at t+<x> ms
control:      original build, same device/network -> <what happened>
not observed: <the layers that produced nothing, and the branch you assigned>
next:         <one action>
```

两条规矩：**`events` 必须按层给数**（"有事件"不是数），**`control` 不能写"未做"却当对照用**
—— 没做就写 `not done`，那句话会影响别人怎么读你的结论。

## 边界：本页不回答的问题

- **"这个检测是谁写的"** —— 本页只负责让会话活下来并产出事件；检测的定位顺序在
  `detection-and-anti-analysis.md` §Step 3。
- **"怎么绕过"** —— 绕过是反检测军备，不是本域交付；能绕过的边界与代价写在同一篇的 Step 2B。
- **"这个值改成什么才对"** —— 值来自静态读或一次干净的运行时读取（`runtime-data.md`），
  不来自 hook 里反复试。
- **"为什么它是崩溃的"** —— 原生死亡看 `native-tamper-and-suicide.md` 与 `scripts/native_crash.py`；
  本页只帮你把"崩溃"与"被观测"分开。
- **"能不能做成一个可交付的包"** —— 那是 G1 的四种形态问题（`SKILL.md` §Gates），
  Frida 只是其中一种临时形态。

## 这一篇算"用对了"吗

- [ ] 我先跑了 `doctor.py` + `preflight.py`，并把两侧版本对齐当成硬门而不是建议
- [ ] 我知道自己这次走的是哪条注入路径，且记录了包 hash 与 pid 变化
- [ ] 零事件时我先分了三种成因，而不是直接写"目标没有这个行为"
- [ ] 我留下了对照（原版包、同设备、同网络）或明确写了"未做对照"
- [ ] 我的日志里有版本/时间戳/pid，别人能凭它复现这次会话
