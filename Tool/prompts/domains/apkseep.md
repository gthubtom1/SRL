# apkseep 任务卡（28 张）

> 本域的卡不是从外部技能名导入的：`Tool/config/taskcard-sources.json` 里**没有** `apkseep` 条目
> （该文件的 domains 只覆盖 web-pentest / pwn-crypto / firmware-iot / ad-cloud / protocol-plugin /
> plugin-targets / forensics-mobile / malware-analysis / supply-chain-security / reverse）。
> 所以这 28 张卡是**从本域自己的正文逐条搬运**的：每张卡的触发词/前置/步骤/判据/失败判据都能在
> `reference` 指到的那个文件里找到原句，没有新增方法论。
>
> 用法：按触发词选卡 → 照步骤跑 → 用判据/失败判据决定继续或改走
> （改走清单在 `Tool/skill/apkseep/references/02-failure-criteria.md`）→ 在 reference 里找完整命令。
> 所有卡只在自有或明确授权的样本/设备上执行；默认只读，写操作前先备份原件并留 hash。

### 01 判加固与 manifest 入口类（源：recon.md §2 Is it packed?）
- 触发词：这个 APK 加固了吗、StubApp、壳入口类、application android:name
- 前置：拿到 APK 原件并记录 sha256；工作目录用 ASCII 路径（aapt 在 GBK 环境打不开中文路径）
- 步骤：1) `aapt dump badging app.apk` 取包名/版本/launchable-activity；2) 读 manifest 的 `application android:name`，判断是应用自己的类还是第三方壳类；3) `unzip -l app.apk | sort -k1 -n | tail -20` 看最大 entry 是 assets/lib/dex 哪一类
- 判据：能说出入口类归属 + 最大 entry 的性质；"no packer" 也要显式记一行（application 是自己的类、单 plain classes.dex、无 lib/）
- 失败判据：只数关键词（`StubApp` 命中但上下文是 `com.google.android.launcher/.StubApp`）就判加固，或把 aapt 的 Illegal byte sequence 当成"没有 manifest"：先复制到 ASCII 路径重跑，再按 02 卡判壳类型
- reference：Tool/skill/apkseep/references/recon.md

### 02 dump 体检与抽壳识别（源：advanced-unpacking.md §三个可数指标）
- 触发词：脱壳、dump 出来的 dex、stub%、抽取壳、方法体是 return-void
- 前置：dump 目录已就位；先确认 `doctor.py --capabilities --json` 能用
- 步骤：1) `python Tool/skill/apkseep/scripts/dex_dump_validate.py ./dumps`；2) 读 `REJECTED` 行、`dedupe` 段、`stub%` / `emptied%`；3) `--find 'Lcom/example/app/'` 核覆盖面；4) 需要机读时加 `--json`
- 判据：候选原镜像 `stub%` 个位数、唯一镜像数 ≤ 预期 dex 数、`--find` 命中数与字符串表里该前缀的类数同数量级
- 失败判据：`stub%` 落在高那一峰 ⇒ 抽取壳形态，转主动调用循环或写边界；把"解析通过（cksum=ok sig=ok）"当成"内容在"是最贵的一次误判
- reference：Tool/skill/apkseep/references/advanced-unpacking.md

### 03 Java2C vs JNI sinking 判别（源：java2c-and-jni-sinking.md §The discriminating measurement is native density）
- 触发词：整类是 native 声明、Java_ 符号搜不到、java2c、jni sinking
- 前置：拿到 APK 与其中全部 `.so`；不同 ABI 要分开数
- 步骤：1) `python Tool/skill/apkseep/scripts/java2c_probe.py --apk ./target.apk --json > j2c.json` 取 native 密度与 java_symbols 计数；2) 用 `elf_plt.py --symbol JNI_OnLoad` 看导出；3) 对照 dex 里 native 方法数与 `.so` 的 `Java_*` 符号数是否 1:1
- 判据：真实 JNI 目标密度 0.03–0.04%，Java2C 形态 82.76%；判据形态是"导出 JNI_OnLoad 且零 Java_*"
- 失败判据：只有密度一个数字时结论只能是 inferred；密度到几十 % ⇒ 停，不要再开内存窗口（此时没有 dex 可 dump）
- reference：Tool/skill/apkseep/references/java2c-and-jni-sinking.md

### 04 Dex VMP 边界（源：advanced-unpacking-2-root-dump-and-vmp-boundary.md §The honest boundary）
- 触发词：私有 opcode、方法体解不出来、VMP、代码虚拟化
- 前置：已有可解析的 dex 镜像；已排除抽取壳
- 步骤：1) 用与目标无关的独立解码器复算"方法体解不出来"；2) 需要 opcode 映射时走 `vmp_diff_harness`；3) 交叉核对确认不是解码器自己的问题
- 判据：静态判据只能**排除** VMP，不能判定；判定需要闭环重导出的 opcode 映射且与独立读取器一致
- 失败判据：用手写 opcode 表在普通 dalvik 上得出"VMP"结论（已有先例，零结构错误）：改为写带边界的报告，不要继续加变体
- reference：Tool/skill/apkseep/references/advanced-unpacking-2-root-dump-and-vmp-boundary.md

### 05 等长字节补丁（源：byte-level-patching.md）
- 触发词：patch dex、等长改字节、const-string、分支取反
- 前置：已用 patch-audit 的基线；原件 hash 已记录
- 步骤：1) `python Tool/skill/apkseep/scripts/dex_find_insn.py` 定位指令偏移；2) 写 spec 后 `dex_patch_bytes.py --entry classes.dex --spec spec.json -o out.dex`；3) 按序重算 signature 然后 checksum
- 判据：全文件 diff 只含目标那几字节 + header 8..32；目标偏移解码结果确实变了
- 失败判据：改动需要新指令（等长写不下）⇒ 换 06 卡的方法级重写；偏移是猜的不是算出来的 ⇒ 回 02 卡重取基线
- reference：Tool/skill/apkseep/references/byte-level-patching.md

### 06 dexlib2 方法级重写（源：dex-patching.md §Technique 1）
- 触发词：改方法体、dexlib2、方法级重写、新指令
- 前置：已确认等长改字节表达不了这个改动
- 步骤：1) 只重写目标方法（`scripts/dexpatch/`）；2) 保持 dex 其余部分不动；3) 复核文件体积变化并记录
- 判据：`dex_classdiff` 类集合一致、未触碰的类逐字节相同
- 失败判据：用全树 smali 往返代替方法级重写（R8 优化过的 dex 只在运行时坏）：改回方法级，并记录体积影响
- reference：Tool/skill/apkseep/references/dex-patching.md

### 07 补丁审计五步（源：patch-audit.md §Command block）
- 触发词：审计补丁、补丁是否合法、verifier、类漂移
- 前置：有改前/改后两个产物
- 步骤：1) `dex_check_verifier.py out.apk`（能否加载）；2) `dex_classdiff.py a.dex b.dex`（类集合 + access flags）；3) 解码目标偏移；4) 头部按序重算；5) `apk_diff.py in.apk out.apk --summary`（声明外有没有东西动了）
- 判据：五步全过；任一步只"看起来对"不算
- 失败判据：`dex_classdiff` 通过就收工（它看不见 code-item 级损坏）：补跑 verifier 与整包 diff
- reference：Tool/skill/apkseep/references/patch-audit.md

### 08 重打包与签名顺序（源：repack-and-sign.md §The rules）
- 触发词：重打包、zipalign、apksigner、META-INF、resources.arsc
- 前置：原件已备份；签名材料就位；知道目标 minSdk（它决定签名方案）
- 步骤：1) 用 `repack.py --apk original.apk --out out.apk`；2) **先签名、再对齐**；3) `zipalign -c -v 4 out.apk` 复核；4) `apksigner verify --print-certs out.apk`
- 判据：`zipalign -c` 通过、签名校验通过、`resources.arsc` 是 STORED 且 4 字节对齐
- 失败判据：整目录删 `META-INF/`（会删掉 services/ 等运行时条目，启动即死）；顺序反了（先对齐后签名）会让对齐失效
- reference：Tool/skill/apkseep/references/repack-and-sign.md

### 09 分片 APK 与 App Bundle（源：split-apk.md §3 The decision: merge or resign）
- 触发词：split apk、aab、xapk、pm install-multiple、分片
- 前置：拿到 base + 全部 split_config.*；记录每个成员 sha256
- 步骤：1) `repack.py --apk base.apk --split-mode analyze` 判这组是什么；2) 先证明"合并合法"再谈合并；3) 需要单文件时走 `--split-mode resign`（一套 keystore 签全部成员）
- 判据：作为**集合**能装上；每个成员单独校验都过还不够
- 失败判据：合并被拒就当成签名错（可能是不该合并：成员自带 resources.arsc）：改走统一 resign
- reference：Tool/skill/apkseep/references/split-apk.md

### 10 安装与首次启动复验（源：verification.md §The claim ladder Rung 3）
- 触发词：装上没反应、am start 无输出、第一次启动、前台不是目标
- 前置：设备在线；`preflight.py` 无残留 proxy/forward 与时钟漂移
- 步骤：1) `install_test.py --apk out.apk`；2) 比对设备上产物 hash 与本地构建；3) `coldstart.py --pkg <pkg> --out ./cap` 抓前 20 秒；4) `snap.py --out ./cap --count 20`
- 判据：设备 hash == 本地构建 hash；前台 Activity 的包名 == 目标包；进程存活且 logcat 无致命签名
- 失败判据：包管理器报成功就当装上了（安装成功描述的是请求）：重装/清数据/处理厂商安装器占屏后重测
- reference：Tool/skill/apkseep/references/verification.md

### 11 广告移除的三层判据（源：ad-removal.md §Step 4）
- 触发词：去广告、弹窗、开屏、广告 SDK
- 前置：已在 01 卡判出"没有加固"或有解包后的可改产物
- 步骤：1) 枚举这个 app 里"广告"指哪几种形态；2) 找单一收敛点（不是逐个散点）；3) 选补丁层（SDK 调用/渲染/数据消费）；4) 数 SDK 自己的日志行数 n → 0
- 判据：三类独立证据——屏幕观察、SDK 日志计数为 0、相邻功能未回退
- 失败判据："我没看到广告"不是计数；补丁后广告还在 ⇒ 先查服务器下发配置与远程 re-enable，再谈再补
- reference：Tool/skill/apkseep/references/ad-removal.md

### 12 服务器下发 UI 配置（源：server-config-and-updates.md §3 Patch the decision, not the data）
- 触发词：远端配置、运营弹窗、tab 配置、远程 re-enable、热更新
- 前置：已抓到一次该配置的响应；知道本地默认值
- 步骤：1) 确认两层取数（本地默认 → 远端覆盖）；2) 定位"由谁决定要不要显示"；3) 改决策，不改数据
- 判据：改完在远端配置不变的前提下仍然不再出现；且下次拉取不会把它恢复
- 失败判据：只改本地数据（下一次远端覆盖悄悄恢复）：改决策点，并评估 re-enable 通道
- reference：Tool/skill/apkseep/references/server-config-and-updates.md

### 13 会员/付费墙归属判定（源：membership-and-limits.md §First question: who decides?）
- 触发词：会员、VIP、付费墙、解锁功能、授权的边界
- 前置：有可用账号（或明确无账号）；知道目标功能在哪个屏
- 步骤：1) 用无 token 与伪造 token 各请求一次；2) 看资产 URL 是否按请求签发；3) 判定客户端可执行 / 服务器下发数据 / 服务端权威
- 判据：三分类明确并可复核；服务端权威时正确产出是报告 + 边界，不是补丁
- 失败判据：伪造权益（屏幕是空的，比登出更糟）：停手，写归属结论
- reference：Tool/skill/apkseep/references/membership-and-limits.md

### 14 登录墙与绑定（源：account-gates.md §Step 1）
- 触发词：不用登录、跳过绑定、游客模式、账号墙
- 前置：知道"客户端门"与"账号域资源"的区别；绝不伪造 session
- 步骤：1) 先分类看到的是什么；2) 找收敛点并用 `find_refs.py` 数调用方；3) 改完判断哪些屏变可用、哪些因账号域仍为空
- 判据：报告里逐个功能写清"变可用 / 仍为空及原因"
- 失败判据：伪造 session 去满足一个门（产生比登出更糟的状态）：改为分类结论 + 边界
- reference：Tool/skill/apkseep/references/account-gates.md

### 15 签名派生密钥（源：signature-derived-keys.md §How to spot it）
- 触发词：重签后所有请求失败、signatures[0]、toCharsString、getPackageInfo
- 前置：**在第一次重打包之前**做；有设备上的原版可读真值
- 步骤：1) 四个 grep 枚举读点；2) `sig_probe.py --apk app.apk` 离线枚举候选；3) `sig_probe.py --live <pkg>` 读设备真值；4) 在被读处硬编码原证书值
- 判据：每个读点都拿到原证书值；重签后签名请求恢复
- 失败判据：应用能起、UI 正常就当没事（这是最贵的静默失败）：15 分钟 grep 先做，别等交付前才发现
- reference：Tool/skill/apkseep/references/signature-derived-keys.md

### 16 更新与强制升级（源：updates-and-forced-upgrade.md §step 6）
- 触发词：强制更新、must update、版本检查、自更新
- 前置：已确认存在版本检查/升级提示；补丁要随构建一起做，不当作后续
- 步骤：1) 把更新例程入口 no-op；2) 把版本比较强制到"无更新"这一侧；3) 再查热更新/远端配置通道
- 判据：在版本号不变的前提下不再弹升级、也不再被远程替换
- 失败判据：只处理弹窗不处理比较逻辑：补全两层；忽略远端配置会在下次拉取时被还原
- reference：Tool/skill/apkseep/references/updates-and-forced-upgrade.md

### 17 native 终止路径抑制（源：native-tamper-and-suicide.md §The rule）
- 触发词：启动即死、SIGSEGV 全寄存器 0、反调试自杀、蓄意崩溃
- 前置：先记录 time-to-death 作为基线；原件在同一设备上先跑一次
- 步骤：1) `native_crash.py crash.log --lib libfoo.so=<path>` 定位；2) 枚举**全部**实例（不只第一个）；3) 解析桩属于哪个符号；4) 用返回良性值抑制
- 判据：进程不再死在同一站点，且相邻功能没被拖死
- 失败判据：用"不返回"（自旋）封路径 ⇒ 调用方持锁卡死、症状像挂起/被杀：改成返回值，优先成功 0
- reference：Tool/skill/apkseep/references/native-tamper-and-suicide.md

### 18 自定义加载器与代码虚拟化（源：code-virtualization-and-custom-linkers.md §The deadlock that eats hours）
- 触发词：没壳但重签后启动即死、JNI_OnLoad 返回 JNI_ERR、签名杀手是诱饵
- 前置：已确认 manifest 无第三方壳类；有对照构建
- 步骤：1) 解析每个 `.so` 的 PT_DYNAMIC 看有没有 DT_NEEDED 引用它；2) 删掉它并读**准确**的报错，确定是哪个类/方法在执行；3) 把检查与实现分开；4) 验证
- 判据：能说出"检查在哪一层读到什么值"，并有一次重写字符串常量后的对照
- 失败判据：把 Java 层"签名校验通过"当成校验已绕过（那是诱饵）：继续往 native 侧读
- reference：Tool/skill/apkseep/references/code-virtualization-and-custom-linkers.md

### 19 native 层与调用点（源：native-and-so.md）
- 触发词：so 层、JNI 方法替换、DT_NEEDED、符号、ABI
- 前置：知道真正执行的是哪个 ABI（只有 live mapping 是 ground truth）
- 步骤：1) `lib_map.py --pkg <pkg>` 看实际映射；2) `elf_plt.py --symbol <name>` 找 PLT 桩；3) 需要调用点时不要靠符号（动态注册会静默失败）
- 判据：映射、符号、调用点三者能对上，且 ABI 没有混用
- 失败判据：`getprop`/primaryCpuAbi 当成"正在跑什么"：以 live mapping 为准
- reference：Tool/skill/apkseep/references/native-and-so.md

### 20 去混淆与 Stalker trace（源：native-dbi-and-deobfuscation.md §6 failure modes）
- 触发词：ollvm、状态机、Stalker、trace 零事件、去混淆
- 前置：已判出混淆形态；知道"排除"与"事件投递"是两件事
- 步骤：1) 先选要观察什么，再选工具；2) `stalker_trace.js` 记录；3) `stalker_report.py` 出直方图/首访顺序/调用边
- 判据：trace 能给出一条可复核的执行路径；零事件要写成边界，不是结论
- 失败判据：把"零事件"当成"目标没有这段代码"（排除能让目标活着，但不恢复事件投递）：改走静态或写边界
- reference：Tool/skill/apkseep/references/native-dbi-and-deobfuscation.md

### 21 Frida 会话与反插桩（源：dynamic-frida-1-setup-and-probe.md §Setup）
- 触发词：frida、hook 不触发、attach 即死、spawn
- 前置：两侧版本对齐；`doctor.py --capabilities --json` 与 `preflight.py` 已跑
- 步骤：1) 版本对齐门先过；2) 先 attach 已知会跑的方法做阳性探针；3) spawn 时若 Activity 栈起不来，先在内存写补丁再 detach；4) 记录三行：是否有事件、是否进程先死、是否环境不具备条件
- 判据：阳性探针能触发；"never fires" 与 "never ran" 被证据分开
- 失败判据：hook 不触发就断定有检测：先做环境自述（observer-only 探针不改任何字节），再按 Stage 定位
- reference：Tool/skill/apkseep/references/dynamic-frida-1-setup-and-probe.md

### 22 LSPosed 模块交付（源：lsposed-and-modules.md §Deploy, enable, and verify）
- 触发词：lsposed、xposed 模块、不想重打包、多点签名校验
- 前置：G1 判过"模块形态"是正确答案；有受控 root 设备
- 步骤：1) `lsposed_scaffold.py --package <pkg> --out <dir>`；2) 检查 `assets/xposed_init` 指向的入口类**真的在** dex 里；3) 部署/启用/作用域；4) 同时读 logcat 与 `/data/adb/lspd/log/modules_<ts>.log`
- 判据：日志 tag 在**两个**通道里任一出现；作用域正确；目标功能验证过
- 失败判据：只看 logcat 就判"模块没加载"（有 ROM 的 logd 是坏的）：读 LSPosed 文件日志；装成功不是证据
- reference：Tool/skill/apkseep/references/lsposed-and-modules.md

### 23 仿真与 RPC（源：emulation-and-rpc.md §When emulation or RPC is the right move）
- 触发词：只想调用它、unidbg、frida rpc、签名函数
- 前置：确认"不需要改 app，只需要调用它"
- 步骤：1) 先看清环境账单（按天预算，不是按小时）；2) unidbg 路线补齐缺失环境；3) 或走 Frida RPC 把活函数服务化
- 判据：同一输入两次调用结果一致，且响应里含真实业务字段
- 失败判据：把"能起 JVM"当成"能跑目标库"：缺的依赖要一个个补，且记录补了什么
- reference：Tool/skill/apkseep/references/emulation-and-rpc.md

### 24 运行期本地数据（源：runtime-data.md）
- 触发词：datastore、SharedPreferences、SQLite、改本地状态、离线验证
- 前置：先判"这是数据问题还是代码问题"
- 步骤：1) 定位 app 私有目录里的容器；2) datastore（protobuf）用 `datastore_inject.py` 回写；3) 回读验证；4) 评估 app 是否会重写你的编辑
- 判据：回读得到你写入的值，且一次冷启动后仍在
- 失败判据：手工改 protobuf 静默失败（缺字段/长度不对）：用脚本回写并回读
- reference：Tool/skill/apkseep/references/runtime-data.md

### 25 协议与 protobuf 面（源：protocol-reverse.md §1 Protobuf on the wire）
- 触发词：protobuf、grpc、quic、抓包解不出、pinning 在 so
- 前置：已拿到一份 body（不是"我抓到了流量"）
- 步骤：1) `protobuf_decode_raw.py --hex '<hex>'`；2) 读候选列表与 `tie:` 行；3) 需要 schema 时从 APK 里的生成代码反推
- 判据：长度定界字段能给出"字符串/嵌套消息/packed 数组"三选一并可解释 tie
- 失败判据：看到可读字符串就当成"解出来了"：把 tie 行与候选一起写进结论
- reference：Tool/skill/apkseep/references/protocol-reverse.md

### 26 服务器 API 归属（源：server-api.md §Prove who owns the gate）
- 触发词：服务端校验、接口重放、响应包络、谁决定的
- 前置：先按 app 自己的请求头重放，不用代理近似
- 步骤：1) 从 dex 里 harvest 路径与头；2) 用 app 的头重放一次、再去掉代理重放一次；3) 用"错但形状合法"的参数探验证面
- 判据：能说清这个门由客户端执行还是服务端执行，并有两次请求的差异作证据
- 失败判据：把"能打通接口"当成"能绕过授权"：本卡只判归属；击穿服务端的办法在该文件里被明确列为残余项
- reference：Tool/skill/apkseep/references/server-api.md

### 27 Flutter / Dart AOT 与跨平台运行时（源：dart-aot.md §1 Pin the Dart version）
- 触发词：flutter、dart、libapp.so、跨平台运行时、il2cpp
- 前置：snapshot dump 是本技能**未随附**的依赖；先确认你用的是哪个前端（aotopsy / blutter）
- 步骤：1) 固定 Dart 版本再选工具；2) 确认 `libapp.so` 真的被加载；3) 建自己的 pool 引用索引（`dart_pprefs.py`）；4) 定位与打补丁
- 判据：反汇编与独立反汇编器一致（已有实测：32/32、96/96）；调用者索引对称差为 0
- 失败判据：把对象池当成"本技能能自己解"的：写出你用的前端与原因（两家对同一二进制报的 Dart 版本标签不同）；il2cpp 逻辑恢复本域不覆盖
- reference：Tool/skill/apkseep/references/dart-aot.md

### 28 交付前脱敏与泄漏扫描（源：desensitization-and-leak-scans.md §The scanner）
- 触发词：脱敏、发布证据、泄漏扫描、README 引用真实工作
- 前置：待发布的证据/transcript/README 已成稿
- 步骤：1) `scan_leaks.py --root .`；2) `--show-exempt` 看错误的抑制；3) 对照 do-not-anonymize 清单决定保留什么
- 判据：每个命中项都看过并有处置（改文件 / 写豁免理由）；清单内的证据没被删
- 失败判据：命中数当成"要删的行数"：命中是"要看的行"，删掉 do-not-anonymize 的证据会毁掉可复核性
- reference：Tool/skill/apkseep/references/desensitization-and-leak-scans.md
