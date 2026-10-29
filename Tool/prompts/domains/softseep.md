# 逆向域任务卡（24 张）

> 源技能名严格取自 `Tool/config/taskcard-sources.json` 的 `domains.softseep` 列表。
> 每张卡六段：触发词 / 前置 / 步骤 / 判据 / 失败判据 / reference。
> 用法：先按触发词选卡，再读 reference；判据不成立就按失败判据换路。

### 01 Ghidra 样本函数图与入口定位（源：reverse-engineering-malware-with-ghidra）
- 触发词：Ghidra、函数图、入口定位、xref、反编译、sub_xxx
- 前置：样本 SHA256 已记录；Ghidra/headless 可用或已有反编译缓存；确认授权沙箱
- 步骤：1) `python Tool/skill/softseep/scripts/preflight-classify.py --help` → rc=0，期望：usage 含 `<path>` 与 `--self-test`；2) `python Tool/skill/softseep/scripts/preflight-classify.py Tool/samples/real/crackerjack/a.exe` → rc=0，期望：`"format": "pe"`、`"machine": "x86-64"`、`"has_clr": false`；3) `python Tool/skill/malware-analysis/scripts/mal-triage.py --file Tool/samples/real/crackerjack/a.exe --json` → rc=0，期望：`"type": "PE"`、section_anomalies 含 overlay
- 判据：入口到关键节点的调用路径可打印；每个命名函数能说出「字符串/常量/调用者」依据；关键函数有反编译片段
- 失败判据：只得到 `sub_xxx` 且无字符串/常量线索 → 转符号恢复/动态断点；分析 2 分钟无关键结论 → 转动态
- reference：Tool/skill/softseep/references/01-criteria.md

### 02 Rust 样本符号与 panic 路径定位（源：reverse-engineering-rust-malware）
- 触发词：Rust、rust_eh_personality、core::、panic、musl、静态链接
- 前置：确认二进制为 Rust（字符串/符号/异常人格）；记录架构与 strip 状态
- 步骤：1) `nm -C`/`strings` 找 `core::`/`alloc::`/panic 文案；2) 用调用图从 `main`/`runtime` 向下；3) 对关键函数做结构体/枚举布局还原
- 判据：能定位到业务入口与至少一个网络/文件/加密函数；panic 路径与业务路径可区分；函数名有依据
- 失败判据：符号全剥离且无特征字符串 → 转指纹/调用图；把 Rust unwind 当 C++ 异常 → 回到 07-disassembly-deep-read
- reference：Tool/skill/softseep/references/08-symbol-recovery.md

### 03 .NET 程序集与 dnSpy/ILSpy 静态解剖（源：reverse-engineering-dotnet-malware-with-dnspy）
- 触发词：.NET、CLR、dnSpy、ILSpy、BSJB、#Strings、托管
- 前置：`preflight-classify.py` 显示 `has_clr=true`；准备 dnSpy/ilspycmd；备份样本
- 步骤：1) 读 CLR 数据目录与元数据流；2) 反编译到 C#，找 `License/Verify/Activate`；3) 对混淆方法记录「方法体缺失/资源加密/动态 token」现象
- 判据：关键方法可读或明确标注为加密 stub；字符串/字段/调用链能指向授权或行为；版本/强名称记录
- 失败判据：只有 stub、方法体在资源里 → 转动态解壳/JIT Hook；不要硬读静态 IL
- reference：Tool/skill/softseep/references/01-criteria.md

### 04 勒索加密例程与密钥流还原（源：reverse-engineering-ransomware-encryption-routine）
- 触发词：勒索、加密例程、AES、ChaCha20、密钥流、文件遍历、RSA
- 前置：样本在隔离环境；准备文件系统快照/测试文件；只对副本运行
- 步骤：1) 定位文件遍历与加密调用；2) 识别算法原语/模式/IV/密钥来源；3) 用测试文件验证加密前后长度、头尾、重命名规则
- 判据：算法/模式/密钥派生可写成伪代码；测试文件加密结果可复算；密钥来源（本地/外发）明确
- 失败判据：只有算法常量没有密钥流 → 转动态断点/内存取证；无法复算 → 不写「已还原」
- reference：Tool/skill/softseep/references/01-criteria.md

### 05 Android 样本 Jadx 入口与 Native 桥（源：reverse-engineering-android-malware-with-jadx）
- 触发词：APK、Jadx、DEX、JNI、native、AndroidManifest、so
- 前置：APK 已授权；jadx/apktool 可用；记录 APK SHA256
- 步骤：1) jadx 反编译，读 Manifest/入口 Activity/Service；2) 找 `loadLibrary`/JNI 方法与反射调用；3) 对 `.so` 做架构/符号/字符串 triage，必要时转 Ghidra
- 判据：入口→关键逻辑→数据来源链可画；native 库与 Java 调用点对应；权限/广播/服务有证据
- 失败判据：DEX 被加固/动态加载 → 转 `apkseep`/动态脱壳；不要在本域硬解 Android 壳
- reference：Tool/skill/softseep/references/01-criteria.md

### 06 PE Studio 静态 triage 与可疑面清单（源：performing-static-malware-analysis-with-pe-studio）
- 触发词：PE Studio、triage、导入表、字符串、熵、签名、可疑面
- 前置：样本只读；准备哈希/节表/导入/字符串输出目录
- 步骤：1) `python Tool/skill/malware-analysis/scripts/mal-triage.py --file Tool/samples/real/crackerjack/a.exe --json` → rc=0，期望：`"type": "PE"`、`"section_anomalies"` 含 `overlay`；2) `python Tool/skill/pwn-crypto/scripts/pwn-check.py --file Tool/samples/real/crackerjack/a.exe --json` → rc=0，期望：`"protections"` 含 NX/PIE；3) `python Tool/skill/softseep/scripts/preflight-classify.py Tool/samples/real/crackerjack/a.exe` → rc=0，期望：`"sections"` 含 `.text`/`.rdata`
- 判据：每个可疑面至少一条可机检证据；高熵节/无签名/异常导入有记录；不把「可疑」写成「恶意」
- 失败判据：只有静态可疑面无法闭环 → 转动态/沙箱；不要用字符串直接定性质
- reference：Tool/skill/softseep/references/01-criteria.md

### 07 Go 二进制 gopclntab 与函数名恢复（源：analyzing-golang-malware-with-ghidra）
- 触发词：Go、gopclntab、runtime.main、moduledata、Ghidra、函数名
- 前置：确认 Go 构建；记录架构/版本/ strip 状态
- 步骤：1) `go tool nm`/`strings` 找运行时符号；2) 用 gopclntab 恢复函数表；3) 从 `main.main`/网络/文件调用向下画图
- 判据：函数名恢复有依据；入口到关键行为路径可打印；接口表/字符串不被误读为 C++ vtable
- 失败判据：符号全无且 gopclntab 被破坏 → 转调用图/常量；不要按 C++ 结构硬套
- reference：Tool/skill/softseep/references/08-symbol-recovery.md

### 08 Linux ELF 动态链接与入口分析（源：analyzing-linux-elf-malware）
- 触发词：ELF、readelf、PIE、DT_NEEDED、ptrace、LD_PRELOAD、Linux
- 前置：记录 ELF 哈希/架构/PIE/RELRO；准备隔离容器
- 步骤：1) `readelf -h/-S/-d` 读入口/段/依赖；2) 查 `ptrace`/`/proc`/`LD_PRELOAD` 行为；3) 动态跑测试样本，记录系统调用与网络
- 判据：入口在可执行段；依赖/符号/缓解策略明确；动态行为有 strace/日志
- 失败判据：静态无符号且动态被反调试 → 转外部观测/Frida；不要把 PE 节表经验套 ELF
- reference：Tool/skill/softseep/references/07-disassembly-deep-read.md

### 09 UPX/压缩壳脱壳与 OEP 判据（源：analyzing-packed-malware-with-upx-unpacker）
- 触发词：UPX、压缩壳、OEP、dump、IAT、脱壳
- 前置：备份样本；准备 x64dbg/Scylla/upx；确认壳类型
- 步骤：1) `python Tool/skill/malware-analysis/scripts/mal-unpack.py --file Tool/cases/malware-analysis03/input/packed-upx.exe --out-dir work/rev09 --json` → rc=0，期望：`"packers"` 含 UPX 且 dumps 含 carve-embedded-pe；2) `python Tool/skill/malware-analysis/scripts/mal-triage.py --file Tool/cases/malware-analysis03/input/packed-upx.exe --json` → rc=0，期望：节名 UPX0/UPX1 且 W+X；3) `python Tool/skill/malware-analysis/scripts/mal-unpack.py --self-test` → rc=0，期望：`"ok": true`
- 判据：内存出现原节名/明文导入；OEP 落在原 `.text`；IAT 可解析；dump 哈希记录
- 失败判据：能运行但节仍高熵/IAT 坏 → 继续找 OEP；VM 壳转运行期取功能
- reference：Tool/skill/softseep/references/09-patch-engineering.md

### 10 Bootkit/rootkit 启动链与持久化面（源：analyzing-bootkit-and-rootkit-samples）
- 触发词：bootkit、rootkit、MBR、UEFI、启动链、持久化、驱动
- 前置：隔离虚拟机/可回滚快照；准备磁盘/固件镜像；只在隔离快照内运行
- 步骤：1) 枚举启动项/服务/驱动/计划任务；2) 定位引导链写入点与内核模块；3) 记录持久化机制与清除路径
- 判据：持久化链每一跳有路径/键值/文件证据；启动顺序可解释；清除后复验
- 失败判据：只看到用户态持久化 → 结论止于用户态（bootkit 属硬件层，另立任务）；无法回滚 → 停止，生产环境按 `scope` 清单
- reference：Tool/skill/softseep/references/10-anti-debug.md

### 11 Linux 内核 rootkit 模块与 hook 面（源：analyzing-linux-kernel-rootkits）
- 触发词：Linux kernel、rootkit、LKM、syscall table、hook、/proc、隐藏模块
- 前置：隔离内核/虚拟机；准备内核符号/模块列表；只在内核 VM 内加载
- 步骤：1) 比对 `/proc/modules`/`lsmod`/sysfs 与磁盘模块；2) 查 syscall/文件操作/网络 hook；3) 记录隐藏对象与通信方式
- 判据：隐藏模块/被 hook 的函数有地址/字节证据；行为差异可复现；清理后可复验
- 失败判据：只看到用户态异常 → 不写内核 rootkit；无隔离环境 → 停手
- reference：Tool/skill/softseep/references/10-anti-debug.md

### 12 UEFI bootkit 持久化与固件面（源：analyzing-uefi-bootkit-persistence）
- 触发词：UEFI、bootkit、SPI、固件、DXE、NVRAM、Secure Boot
- 前置：固件镜像/可回滚设备；准备 chipsec/UEFITool；确认授权
- 步骤：1) 解析固件卷/驱动/变量；2) 定位 DXE 驱动或 NVRAM 持久化点；3) 记录启动链与校验绕过面
- 判据：固件组件/变量有偏移/哈希证据；启动链可解释；Secure Boot 状态明确
- 失败判据：只有 OS 层持久化 → 不写 UEFI bootkit；无回滚设备 → 停手
- reference：Tool/skill/softseep/references/08-symbol-recovery.md

### 13 内存转储中的凭据与密钥提取（源：extracting-credentials-from-memory-dump）
- 触发词：内存 dump、凭据、LSASS、密钥、minidump、字符串
- 前置：已授权样本/测试机；准备 dump 与符号；避免真实凭据外泄
- 步骤：1) 记录 dump 来源/哈希/进程；2) 扫 ASCII/UTF-16/结构体（`sockaddr_in`/blob）；3) 对命中做上下文校验，脱敏后入报告
- 判据：命中地址/结构/上下文可解释；凭据/密钥可复现但不外泄；转储 region 表完整
- 失败判据：只命中随机字符串 → 不写「提取到凭据」；真实凭据 → 立即脱敏/删除
- reference：Tool/skill/softseep/references/license-validation.md

### 14 无文件/内存加载样本的检测面（源：detecting-fileless-malware-techniques）
- 触发词：fileless、无文件、PowerShell、反射加载、内存模块、WMI
- 前置：隔离环境；准备 ETW/Procmon/Sysmon；记录基线
- 步骤：1) 建立基线进程/网络/模块；2) 抓内存模块/脚本块/父子进程异常；3) 提取可检测特征（命令行/模块路径/行为序列）
- 判据：异常有基线对照；检测规则可命中测试样本且不误报基线；证据可复现
- 失败判据：只有单次日志无基线 → 降级为疑似；规则误报高 → 收窄条件
- reference：Tool/skill/softseep/references/01-criteria.md

### 15 PowerShell 混淆解码与脚本还原（源：deobfuscating-powershell-obfuscated-malware）
- 触发词：PowerShell、混淆、Base64、IEX、字符串拼接、解码
- 前置：不执行未知脚本；准备隔离 PowerShell/文本工具；记录脚本哈希
- 步骤：1) 静态提取编码块/拼接/替换；2) 分层解码（Base64/gzip/XOR），每层记录输入输出；3) 还原到可读脚本并标注危险调用
- 判据：每层解码可复算；最终脚本可读；危险调用（下载/执行/持久化）有定位
- 失败判据：解码后仍是乱码 → 检查编码/压缩/XOR 键；不要执行原脚本
- reference：Tool/skill/softseep/references/03-model-pitfalls.md

### 16 二进制利用面与缓解策略核对（源：performing-binary-exploitation-analysis）
- 触发词：二进制利用、栈溢出、堆、ROP、DEP、ASLR、CFG
- 前置：已授权靶标；准备调试器/保护检查工具；记录二进制哈希
- 步骤：1) `python Tool/skill/pwn-crypto/scripts/pwn-check.py --file Tool/samples/real/crackerjack/a.exe --json` → rc=0，期望：`"NX": "Enabled"`、`"PIE": "Enabled (DYNAMIC_BASE/ASLR)"`；2) `python Tool/skill/pwn-crypto/scripts/pwn-check.py --self-test` → rc=0，期望：`"ok": true`；3) `python Tool/skill/pwn-crypto/scripts/pwn-repro.py --self-test` → rc=0，期望：`"ok": true`
- 判据：崩溃可复现；偏移/可控数据有调试器证据；缓解策略与利用可行性一致
- 失败判据：只崩溃不可控 → 不写可利用；缓解阻断 → 转信息泄露/其它路线
- reference：Tool/skill/softseep/references/07-disassembly-deep-read.md

### 17 MS17-010/EternalBlue 漏洞面核对（源：exploiting-ms17-010-eternalblue-vulnerability）
- 触发词：MS17-010、EternalBlue、SMB、445、漏洞面
- 前置：仅授权隔离靶场；扫描限于靶场；准备补丁/版本信息
- 步骤：1) 核对目标 SMB 版本/补丁；2) 在隔离靶场复现漏洞面；3) 记录利用前置与失败条件
- 判据：目标版本/补丁状态可机检；隔离靶场行为可复现；不影响真实网络
- 失败判据：目标已打补丁/不可达 → 停止，扫描范围不扩大；授权清单外 → 停并交回用户
- reference：Tool/skill/softseep/references/01-criteria.md

### 18 DEP/ASLR 等内存保护实现核对（源：implementing-memory-protection-with-dep-aslr）
- 触发词：DEP、ASLR、CFG、缓解策略、SetProcessMitigationPolicy、DllCharacteristics
- 前置：记录目标 PE 头/加载配置；准备 PowerShell/PInvoke 或调试器
- 步骤：1) 读 `DllCharacteristics`/加载配置；2) 运行时查进程缓解策略；3) 对照「声明 vs 实际」，列出缺口
- 判据：声明与实际一致/差异有证据；关键模块 ASLR/CFG 状态明确；不把「编译选项」当「运行时已启用」
- 失败判据：只读磁盘头不查运行时 → 结论降级；差异无法解释 → 记录未验证
- reference：Tool/skill/softseep/references/01-criteria.md

### 19 厚客户端鉴权链路与补丁点收敛（源：performing-thick-client-application-penetration-test）
- 触发词：厚客户端、鉴权链路、补丁点、license、状态字、代理 DLL
- 前置：目标版本/SHA256；备份；准备 x64dbg/Ghidra/Frida；确认授权
- 步骤：1) 画「输入→解密→校验→状态落地→消费者」；2) 找真正状态源与消费者；3) 做最小补丁并跑 A/B/C 对照
- 判据：状态字/返回值/UI 三重证据一致；补丁后功能闭环且稳定；可回滚
- 失败判据：只改 UI 或 license_type → 回状态源；补丁多次崩 → 按 02-failure-criteria 换路
- reference：Tool/skill/softseep/references/04-walkthrough-project-a.md

### 20 移动端证书固定绕过与流量观测（源：performing-mobile-app-certificate-pinning-bypass）
- 触发词：certificate pinning、证书固定、Frida、SSL、移动端、抓包
- 前置：已授权 App/测试机；准备 Frida/mitmproxy/自签 CA；记录 App 哈希
- 步骤：1) 识别 pinning 实现（OkHttp/TrustManager/native）；2) 选择 hook 点或改测试包；3) 抓包验证请求/响应
- 判据：绕过可复现；流量可解密；不破坏 App 其它功能；证据含请求/响应
- 失败判据：native pinning/双向认证 → 转 `apkseep`/`forensics-mobile`；不要在生产 App 上做
- reference：Tool/skill/softseep/references/license-validation.md

### 21 Windows 注册表取证与授权状态定位（源：analyzing-windows-registry-for-artifacts）
- 触发词：注册表、Registry、Run、CLSID、授权状态、取证
- 前置：已授权样本/测试机；准备注册表导出/对比工具；记录基线
- 步骤：1) 导出 before/after；2) diff 关键键（Run/CLSID/许可/时间戳）；3) 关联到进程/文件/网络行为
- 判据：键值变化可复现；与授权/持久化/试用期有因果关系；before/after 文件哈希记录
- 失败判据：只看到键变化无因果 → 降级为线索；不要改生产机注册表
- reference：Tool/skill/softseep/references/01-criteria.md

### 22 Prefetch/执行历史与样本落地核对（源：analyzing-prefetch-files-for-execution-history）
- 触发词：Prefetch、执行历史、取证、落地文件、时间线
- 前置：已授权取证镜像/测试机；准备 PECmd/解析脚本；记录时区
- 步骤：1) 解析 Prefetch 的执行次数/时间/加载模块；2) 与文件系统/注册表/事件日志对齐；3) 建时间线
- 判据：时间线多源一致；执行次数/路径有原始字段；时区/格式说明清楚
- 失败判据：只有单源时间 → 不写确定时间线；Prefetch 被清 → 转其它证据
- reference：Tool/skill/softseep/references/08-symbol-recovery.md

### 23 补丁响应流程与版本回归（源：building-patch-tuesday-response-process）
- 触发词：补丁响应、Patch Tuesday、版本回归、补丁清单、回滚
- 前置：目标版本/SHA256；补丁 manifest；测试用例/回滚脚本
- 步骤：1) `python Tool/skill/softseep/scripts/patch-verify.py --self-test` → rc=0，期望：`{"ok": true, "checks": 5}`；2) `python Tool/skill/softseep/scripts/reverse-accept.py --self-test` → rc=0，期望：`{"ok": true, "checks": 4}`；3) `python Tool/skill/softseep/scripts/patch-verify.py --help` → rc=0，期望：usage 含 `--manifest`/`--rollback`
- 判据：`patch-verify.py` 通过；关键功能回归通过；回滚后哈希/行为恢复
- 失败判据：补丁后崩溃/签名失败 → 按 02/09 换路；无回滚 → 不交付
- reference：Tool/skill/softseep/references/09-patch-engineering.md

### 24 补丁管理工作流与跨版本迁移（源：implementing-patch-management-workflow）
- 触发词：补丁管理、跨版本、AOB、manifest、版本化、迁移
- 前置：旧版/新版样本与哈希；旧补丁清单；AOB/拓扑工具
- 步骤：1) 记录两版指纹；2) AOB/拓扑跨距定位新偏移；3) 更新 manifest 并跑 `patch-verify`；4) 回归 UI/授权/稳定性
- 判据：新版本唯一命中；RVA/偏移差可解释；回归通过；manifest 版本化
- 失败判据：多命中/偏移不可解释 → 重新分析，不硬套；跨大版本 → 转 `04-version-migrate`
- reference：Tool/skill/softseep/references/09-patch-engineering.md
