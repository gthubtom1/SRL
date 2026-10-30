# 01 判据表 —— apkseep 什么时候算「打下来了」

> 本篇是以下文件的归并索引：`SKILL.md` §Coverage（强度标签表）、§G1（交付形态四选一）、
> `references/recon.md` §2 Is it packed?、§3 Where does the app's own code live?、§5 Signature and tamper checks、
> `references/packers.md` §Reading the rejection signal、§Where integrity evidence actually comes from、
> `references/advanced-unpacking.md` §三个可数指标、§通过长什么样、
> `references/advanced-unpacking-1-shapes-and-active-invocation.md` §The four shapes a dump can be、
> `references/java2c-and-jni-sinking.md` §The five shapes、§The discriminating measurement is native density、
> `references/code-virtualization-and-custom-linkers.md` §Identification — three cheap tells、
> `references/verification.md` §The claim ladder、§The control build rule、
> `references/patch-audit.md` §1 Did it land? Compare *length*, not bytes、
> `references/repack-and-sign.md` §2a（`resources.arsc` STORED + 4 字节对齐）、
> `references/signature-derived-keys.md` §How to spot it (four greps, minutes)、
> `references/server-api.md` §Prove who owns the gate、
> `references/server-config-and-updates.md` §3 Patch the decision, not the data、
> `references/tls-and-cert.md`、`references/evidence-summary.md` §The capability matrix、
> `references/coverage-and-limits.md` §Strength labels、§Not covered。
>
> **本篇不新增方法论**：正文只摘取并重排上面这些文件的已有判据，每节标注来源文件。
> 遇到本篇没写到的现象，回 `SKILL.md` §Symptom index 按症状找文件，不要在这里外推。

## 0. 先固定证据坐标：标签、命令、输出三件都要在

（来源：`references/coverage-and-limits.md` §Strength labels；`SKILL.md` §Coverage 的强度表）

任何结论都必须带一个标签，标签决定它能不能支撑决策：

| 标签 | 含义 | 可以支撑决策吗 |
|---|---|---|
| `observed` | 跑过一条命令，且它的输出在案 | 可以 |
| `inferred` | 由观察推出，但中间那一步是推理 | 只能暂定 |
| `unverified` | 假设，或别人报告过、本仓没复现 | 只能当"待验证项" |

`observed` 的保留口径是严格的（`references/long-task-discipline.md`）：**"我想明白了"是 `inferred`，不是 `observed`**。
一个没有命令与输出的结论，写进报告时必须同时写清它是 `inferred` 还是 `unverified`，否则下一个人会把它当事实继承。

## 1. 判据表（场景 → 可机检判据 → 证据形态 → 误报风险）

（来源：逐行标注在「来源」列；数字与判据原文均取自该文件，未做改写）

| 场景 | 可机检判据 | 证据形态 | 误报风险 | 来源 |
|---|---|---|---|---|
| 这个包是否加固 | `AndroidManifest.xml` 的 `application android:name` 是第三方壳类（`com.stub.StubApp`、`com.secneo.*`、`com.tencent.StubShell`、`s.h.e.l.l.*`…）而不是应用自己的类 | manifest 原文 + 类名 + 长短 | **关键词命中 ≠ 加固**：普通应用里也可能出现 `StubApp`（实测上下文 `com.google.android.launcher/.StubApp`）；要落到"上下文 + 壳入口类 + so 名" | `recon.md` §2 |
| dex 是否只有壳类 | `classes.dex` 只有几十 KB、只装壳类；或 `assets/` 里有高熵大 blob（可能伪装成 JPEG：魔数合法但解不出图） | `unzip -l` 的 entry 与尺寸、熵 | "看起来像壳"不是判据；clean 形态也是结果，要显式记一行"no packer" | `recon.md` §2 |
| dump 是不是抽取壳骨架 | `dex_dump_validate.py` 的 `stub%` / `emptied%`：**双峰**，不是阈值（旧稿的"几十个百分点"判据已被实测推翻并删除） | `dex_dump_validate.py` 表格 + `dedupe` 段 + `verdict` 行 | "解析通过"≠"内容在"；`cksum=ok sig=ok class=4210` 与 `stub%` 是两件事 | `advanced-unpacking.md` §三个可数指标、§通过长什么样；`advanced-unpacking-1-...md` §The four shapes a dump can be |
| 类是不是 Java2C / JNI sinking | native 声明密度：真实 JNI 样本 **0.03–0.04%**，Java2C 形态 fixture **82.76%**（约 2000×），且 `.so` 里 `Java_*` 符号数与 dex 的 native 方法数按 ABI 1:1 | `java2c_probe.py --apk` 的 JSON（`java_symbols` 等计数） | 符号搜不到 ≠ 没有 native 代码：动态注册与 `-fvisibility=hidden` 会让搜索**静默失败**；判据是"导出 `JNI_OnLoad` 且零 `Java_*`" | `java2c-and-jni-sinking.md` §The discriminating measurement is native density；`coverage-and-limits.md` §Covered |
| 方法体是不是私码（VMP） | 方法体在、但反汇编器解出来是私有 opcode；**静态判据只能排除 VMP，不能判定 VMP** | `vmp_diff_harness` 的闭环结果 + 手写 opcode 表的对照 | 自写 opcode 表曾在**普通 dalvik** 上产出"VMP"结论且零结构错误 —— 这是这条判据存在的理由 | `evidence-summary.md` §The capability matrix（Dex-VMP declaration boundary） |
| 补丁是否真的落地 | 长度一致改字节：**全文件 diff 只有目标那几字节 + header 8..32**（实测 5,528 字节 dex 里改 2 字节） | `apk_diff.py --summary` / `dex_patch_bytes.py --report` | 只比对"我改了的那段"会漏掉意外改动；必须整文件比 | `patch-audit.md` §1；`evidence-summary.md` §The capability matrix |
| 结构是否完整 | `dex_classdiff`：类集合一致、`ACC_INTERFACE` 零漂移、未触碰的类逐字节相同 | `dex_classdiff` 结构化输出 | **`dex_classdiff` 通过是必要条件，不是充分条件**：它看不见 code-item 级损坏 | `verification.md` §The claim ladder（Rung 1）；`evidence-summary.md` |
| 装得上、起得来 | 装成功 + 进程存活 + `logcat` 无致命签名 | `install_test.py`、`coldstart.py` 输出 | 包管理器说成功 ≠ 装上了（P18）；必须 **hash 设备上的产物**再测 | `verification.md` Rung 3；`pitfalls-2-environment-and-evidence.md` P18 |
| 目标行为真的变了 | 直接观察那个功能本身（屏幕、端点、UI） | 截图/请求响应 + 时间戳 | "日志干净"不是证据；"我没看到广告"也不是计数 | `verification.md` Rung 4；`ad-removal.md` §Step 4 |
| 没有别的功能回退 | 相邻功能都跑一遍：图片、播放、列表、登录、设置 | 逐项操作记录 | 只看"改动的那一个功能"，回退会整轮不被发现 | `verification.md` Rung 5 |
| repack 后所有签名请求都失败 | grep `toCharsString()` / `signatures[0]` / `getPackageInfo(..., 64)`：签名值若进了 native HMAC/DES，就必须在被读处硬编码**原证书值** | `sig_probe.py --apk`（离线候选）+ `sig_probe.py --live <pkg>`（设备上真值） | "应用能启动、UI 正常"完全不能排除这一条 —— 它是最贵的静默失败 | `signature-derived-keys.md` §How to spot it |
| 这个门归客户端还是服务端 | 无 token / 伪造 token 两次请求的响应差异；资产 URL 是否按请求签发 | 请求/响应原文 + 状态码 | 把"服务端没给"误判成"客户端能改"= 白做一天；伪造 session 比登出更糟 | `server-api.md` §Prove who owns the gate；`membership-and-limits.md` §First question: who decides? |
| 服务器下发的 UI 配置有没有被改动到 | 两层取数（本地默认 → 远端覆盖）；改的是**决策**而不是数据 | 远端 config 原文 + 改前改后渲染 | 改数据会被下一次远端覆盖悄悄恢复（远程 re-enable） | `server-config-and-updates.md` §1、§3、§6 |
| 单个功能网络失败是不是我造成的 | 未改的原版在同一设备/同一网络先跑一遍 | 原版对照 + 特性域请求日志 | 一个 app 可以带两条独立信任链，"别的请求能通"证明不了任何事 | `tls-and-cert.md`；`SKILL.md` §Start here Q8 |
| 装包被拒 | `[-124]` → `resources.arsc` 必须 STORED **且** 4 字节对齐；裸数字码（如 `[-99]`）→ 设备侧安装拦截，走 root `pm install` | 安装输出原文 | 把设备侧拦截当成"我的包坏了"会白改一整轮 | `repack-and-sign.md` §2a、§vendor install interception；`pitfalls-4-native-and-install.md` P38、`pitfalls-5` P39 |

## 2. 「打下来了」是有等级的，报告里必须写等级

（来源：`references/verification.md` §The claim ladder，逐字保留）

| Rung | 可以声称 | 需要的证据 |
|---|---|---|
| 0 | "dex 被改过" | 目标方法的字节级 diff |
| 1 | "结构完整" | `dex_classdiff`：类相同、`ACC_INTERFACE` 零漂移、未改的类逐字节相同 |
| 2 | "能构建、能签名" | 签名校验通过 |
| 3 | "能装、能起" | 进程存活，`logcat` 无致命签名 |
| 4 | "目标行为变了" | 直接观察到那个功能变了 |
| 5 | "没有别的回退" | 相邻功能逐项验证 |
| 6 | "机制被证明" | 独立证据说明**为什么**（比如 SDK 域名从未被解析，因为 init 从没跑） |
| 7 | "分发的产物就是验过的那个" | 重新下载发布物，与本地被测构建比 hash |

口径：**任何交付最低 Rung 3；声称"问题解决了"要 Rung 4；交给用户前要 Rung 5；声称"这个子系统死了"要 Rung 6；
产物一旦离开本机就要 Rung 7。**

## 3. 四个可数指标：能算的就不许靠感觉

（来源：`references/advanced-unpacking.md` §三个可数指标；`java2c-and-jni-sinking.md` §Identification）

| # | 指标 | 从哪来 | 它决定什么 |
|---|---|---|---|
| 1 | `stub%` / `emptied%`（平凡方法体占比） | `dex_dump_validate.py` | 抽取壳 vs 完整镜像；它是**双峰**的，不是阈值 |
| 2 | 唯一镜像数（sha256 去重后） | 同一条命令的 `dedupe` 段 | 你手上有几个"版本"；重复 dump 会被当成多份证据 |
| 3 | `native` 方法数 ÷ `Java_*` 符号数 | `java2c_probe.py` | 这个目标到底有没有可 dump 的 dex |
| 4 | 生命期 / 内存 / 写出速率 | `adb shell` 采样（`advanced-unpacking.md` §花窗口之前的三个成本实验） | 一个 root 窗口值不值得开、能写出多少 |

```bash
# 指标 1/2：一次 dump 体检（结构 + 去重 + 平凡体占比 + 候选排序）
python Tool/skill/apkseep/scripts/dex_dump_validate.py ./dumps --json > dumps.json

# 指标 3：先把 Java2C 这条死路排除掉
python Tool/skill/apkseep/scripts/java2c_probe.py --apk ./target.apk --json > j2c.json

# 指标 3 的静态旁证：本地库的导出符号（按 ABI 分开数，不要混）
python Tool/skill/apkseep/scripts/elf_plt.py lib/arm64-v8a/libfoo.so --symbol JNI_OnLoad
```

通过的样子（`advanced-unpacking.md` §通过长什么样）：候选原镜像 `stub%` **个位数**、`dedupe` 的唯一镜像数
≤ 你预期的 dex 数、`--find 'Lcom/example/app/'` 命中数与字符串表里该前缀的类数**同数量级**。
任一条不成立，就不要把"脱壳完成"写进记录。

## 4. 结论只有四种形态，形态决定验证方式

（来源：`SKILL.md` §G1 的四形态表；验证要求来自 `verification.md`）

| 形态 | 什么时候是正确答案 | 验证方式（缺一不可） |
|---|---|---|
| 重建的可安装 APK | 行为在客户端；没有多点完整性校验；不是抽取壳 | Rung 2–5：签名、装、起、目标功能、相邻功能 |
| LSPosed / Xposed 模块 | 逻辑在客户端但应用抗 repack，或结果只需在受控 root 设备上可用 | 模块装载 + 作用域 + 目标功能；**装成功不是证据** |
| 本地 RPC / 仿真服务 | 你不需要改 app，只需要**调用**它（签名、token、加密） | 同一个输入两次调用结果一致 + 真实业务响应 |
| 带边界的分析报告 | 权威在服务端，或目标是真 VMP / 抽取壳且恢复成本高于收益 | 边界句 + 反例句（见 `02-failure-criteria.md` §3） |

## 5. 一条命令能判的，不许靠人记

（来源：`references/pitfalls.md` §哪些坑可以变成一条检查；命令参数以各脚本 `--help` 为准）

```bash
python Tool/skill/apkseep/scripts/doctor.py --capabilities --json   # G2：这台机器真能做什么
python Tool/skill/apkseep/scripts/dex_check_verifier.py app.apk      # 补丁是否"合法"（verifier 层）
python Tool/skill/apkseep/scripts/dex_classdiff.py a.dex b.dex       # 结构是否只动了想要的地方
python Tool/skill/apkseep/scripts/apk_diff.py before.apk after.apk --summary
```

## 6. 这张表有意不覆盖的东西

（来源：`references/coverage-and-limits.md` §Not covered、§Dependencies this skill does not ship）

- **自动恢复 Unity / IL2CPP 原始 C# 方法体**不在本表承诺内；`framework-runtimes.md` 负责识别运行时，类型/地址映射可按 `../subskills/il2cpp-dump/SKILL.md` 的条件式方法核验。新增方法不改变历史验证记录，不能硬套 Dart 路线。
- **React Native / Hermes 字节码、Cordova 内部**：只到运行时识别 + "找字符串再找谁引用它"。
- **iOS / `.ipa`**：本域所有设备/签名/打包指令都是 Android。
- **击穿服务端权威**：`server-api.md` 判定**谁拥有这个门**，不含如何绕过服务端执行的授权。
- **开箱即用的脱壳器、反检测军备竞赛、内核模块开发**：`advanced-unpacking.md` 只路由问题并给出停手条件；
  `kernel-and-environment-hardening.md` 只画路线与版本门。
- **Dart AOT 的 snapshot dump 是本技能未随附的依赖**：`dart_pool_strings.py` 报**文件**偏移，
  `pp.txt`/`dart_pprefs.py` 说**pool** 偏移，两个空间之间不是常量差（实测 4,241 个共有字符串里 4,237 个不同差值）。

## 7. 这一篇算「用对了」吗

- [ ] 我的每条结论都带 `observed` / `inferred` / `unverified` 标签，且 `observed` 有命令与输出
- [ ] 我判"是否加固"时看了上下文和壳入口类，而不是只数关键词
- [ ] 我判 dump 时给了 `stub%`、唯一镜像数、`--find` 命中数三个数字，而不是"看起来完整"
- [ ] 我排除过 Java2C（或明确写下"尚未排除"）
- [ ] 我报告里写了 Rung 等级；没到 Rung 4 就不说"问题解决了"
- [ ] 我一句话说清了交付形态（四形态之一），并在每个检查点重读它
- [ ] 我至少跑过一个 `scripts/` 里的机检脚本，而不是全靠人读
