# plugin-targets 任务卡（24 张）

> 源技能名取自 `Tool/config/taskcard-sources.json` 的 `plugin-targets`（24 条）。上游没有直系插件技能，以下均为同族最近邻，卡名统一标「（借）」。
> 每张卡固定六段；`reference` 指向本域真实存在的 reference。只对自有或明确授权的插件/宿主操作。

### 01 浏览器扩展安装面与历史痕迹取证（借）（源：analyzing-browser-forensics-with-hindsight）
- 触发词：Chrome 扩展、Edge 扩展、Extensions 目录、CRX、安装面、历史痕迹
- 前置：已取得扩展目录或 `.crx` 副本；只读；记录浏览器 profile 路径与版本
- 步骤：1) `file`/`xxd` 判容器并算 sha256；2) 用 `plugin-triage.py --json` 读 manifest/入口/权限；3) 对照 `Extensions/<id>/<ver>/` 与 `_metadata/verified_contents.json` 记录来源与版本
- 判据：容器/版本/来源/哈希四项齐全；`manifest_version`、`background`、`content_scripts` 能指到文件
- 失败判据：CRX 头两次截取失败 → 只报哈希与容器，转商店安装目录；不硬猜偏移
- reference：Tool/skill/plugin-targets/references/browser-extension.md

### 02 扩展权限面与浏览数据触达清点（借）（源：extracting-browser-history-artifacts）
- 触发词：扩展权限、cookies、history、tabs、storage、浏览数据、权限面
- 前置：已解包扩展；知道宿主版本；准备隔离 profile（不读真实账号数据）
- 步骤：1) `jq` 导出 `permissions/optional_permissions/host_permissions`；2) `plugin-repro.py` 生成权限→file/line 证据；3) 对 `cookies/history/tabs` 追 sink（fetch/native/storage）
- 判据：高危权限至少一条 `status=observed`；不能解释的单列 `unexplained-static`；无“权限=恶意”的越级结论
- 失败判据：权限全 `unexplained-static` → 扩大解包范围/查动态 API 拼接；仍无 → 标“权限面未闭环”
- reference：Tool/skill/plugin-targets/references/01-criteria.md

### 03 扩展隔离世界与宿主边界验证（借）（源：implementing-browser-isolation-for-zero-trust）
- 触发词：isolated world、MAIN world、content script、web_accessible_resources、postMessage、隔离
- 前置：已解包；能在隔离 profile 加载扩展；记录 baseline
- 步骤：1) 查 `content_scripts[].world/run_at/matches`；2) 找注入 `<script>`/`web_accessible_resources`/`postMessage` 桥；3) 分别在页面 DevTools 与扩展 DevTools 验证变量可见性
- 判据：能说清每段代码在哪个世界、`window` 是谁的、跨世界通信方式；消息有 `source/origin` 校验
- 失败判据：变量对不上且找不到桥 → 查 CSP/`world` 字段；不要改页面代码硬试
- reference：Tool/skill/plugin-targets/references/browser-extension.md

### 04 Electron 客户端 asar 入口与 IPC 面（借）（源：performing-thick-client-application-penetration-test）
- 触发词：Electron、asar、app.asar、preload、ipcMain、ipcRenderer、contextBridge
- 前置：已取得 `app.asar` 或 `resources/app/`；只读原包；记录 Electron/Node 版本
- 步骤：1) `plugin-triage.py --path app.asar --json` 列 main/preload/`.node`/`.jsc`；2) `plugin-repro.py` 解包并抽 IPC/危险调用；3) 画 renderer→preload→channel→main handler→sink
- 判据：`main`/`preload` 文件存在；至少一条 IPC 链有 file/line；`webPreferences` 安全开关可读
- 失败判据：asar 头解析两次失败 → 只报容器与哈希；IPC 只有一端 → 标 `inferred`
- reference：Tool/skill/plugin-targets/references/electron-and-asar.md

### 05 LSPosed/Xposed 模块入口与作用域核对（借）（源：conducting-mobile-app-penetration-test）
- 触发词：Xposed、LSPosed、模块 APK、hook 作用域、xposed_init
- 前置：只在自有/授权测试机；模块 APK 与目标包版本已知；不改真实账号
- 步骤：1) 读 `AndroidManifest.xml` 的 xposedmodule 与 `assets/xposed_init`；2) 找 `IXposedHookLoadPackage` 与目标包/类/方法；3) 核对 LSPosed 作用域是否包含目标包
- 判据：hook 目标类/方法→参数/返回值→可观察效果可画；作用域明确；模块可禁用回退
- 失败判据：目标被抽取壳/加固无法定位方法 → 标“目标未定”，交 `apkseep`/`forensics-mobile`，不在本域硬拆
- reference：Tool/skill/plugin-targets/references/01-criteria.md

### 06 扩展/asar 内混淆 JS 的入口还原（借）（源：deobfuscating-javascript-malware）
- 触发词：混淆 JS、bundle、source map、prettier、eval、字符串表
- 前置：已解包；有 Node/prettier；不执行包内代码
- 步骤：1) 先找 source map/chunk 名/字符串表；2) `prettier` 格式化后按入口下断；3) 用 `plugin-repro.py` 的 `minimal_unit` 定位文件/符号
- 判据：入口文件可读；至少一个消息/网络/存储调用能指到行号；混淆不冒充加密
- 失败判据：无 source map 且入口被 `.jsc`/加密覆盖 → 只给字符串面/边界，不硬读一行
- reference：Tool/skill/plugin-targets/references/electron-and-asar.md

### 07 扩展远端 URL 与更新源核对（借）（源：analyzing-malicious-url-with-urlscan）
- 触发词：远程 URL、update_url、collector、WebSocket、更新源、外联
- 前置：已解包；不联网请求目标；只做静态与离线域名核对
- 步骤：1) `plugin-triage.py` 导出 `remote_urls`；2) `plugin-repro.py` 的 `fetch/WebSocket` 证据对到参数来源；3) 查 `update_url`/`app-update.yml`/`latest.yml` 与签名策略
- 判据：URL/方法/字段/是否带 Cookie/token 可指认；更新链“谁能推送”明确
- 失败判据：只有 URL 字符串、无调用点 → 标 `inferred`；不要写“已外发”
- reference：Tool/skill/plugin-targets/references/browser-extension.md

### 08 扩展注入面与页面消息校验（借）（源：performing-web-application-vulnerability-triage）
- 触发词：content script 注入、onMessage、sender、externally_connectable、页面消息
- 前置：已解包；隔离 profile；记录 baseline 消息
- 步骤：1) 列 `content_scripts.matches`/`all_frames`/`run_at`；2) 查 `onMessage` 的 `sender.tab/url/origin` 校验；3) 查 `externally_connectable` 与 `postMessage` 的 origin 校验
- 判据：任意页面可驱动的条件齐备（注入范围+外部连接+无校验）才写“可被外部触发”
- 失败判据：缺任一条件 → 写“条件不足/未验证”；不把“有 sendMessage”当漏洞
- reference：Tool/skill/plugin-targets/references/browser-extension.md

### 09 Native host 通信面与证书边界（借）（源：performing-mobile-app-certificate-pinning-bypass）
- 触发词：nativeMessaging、connectNative、NativeMessagingHosts、allowed_origins、本机桥
- 前置：已取得扩展侧；系统 host manifest 可只读查看；不启动未知 host
- 步骤：1) 找 host 名常量与 `connectNative` 调用；2) 按平台查 host manifest 的 `path/allowed_origins`；3) 只读记录 host 二进制签名/版本，不执行
- 判据：扩展 ID ↔ allowed_origins ↔ host 可执行文件 ↔ 调用点四项能对上
- 失败判据：只有扩展侧、host manifest/二进制缺失 → 标“host 未取得”，停；协议交 protocol-plugin
- reference：Tool/skill/plugin-targets/references/04-walkthrough-chrome-extension.md

### 10 企业策略下的插件白名单与旁加载（借）（源：implementing-mobile-application-management）
- 触发词：企业策略、白名单、旁加载、ExtensionInstallForcelist、签名、受限工作区
- 前置：已知宿主与企业策略来源；只读注册表/策略文件；不改生产策略
- 步骤：1) 查浏览器/IDE 的企业策略与允许列表；2) 记录插件签名者/版本/加载来源；3) 对照 `capabilities.untrustedWorkspaces`/`idea-version`/`engines`
- 判据：安装来源、签名者、更新通道、卸载残留四项齐全；策略阻止加载时能指出是哪一层
- 失败判据：签名/白名单阻止加载两次 → 停，记录校验层；不提供绕过方法
- reference：Tool/skill/plugin-targets/references/ide-plugins.md

### 11 插件命令/工具注册面的权限审计（借）（源：auditing-mcp-servers-for-tool-poisoning）
- 触发词：命令注册、contributes.commands、Action、工具面、权限审计、扩展点
- 前置：已解包 VSIX/JetBrains；知道宿主版本；不执行插件
- 步骤：1) 列 `contributes.commands`/`plugin.xml <actions>`；2) 对到 `registerCommand`/`actionPerformed` 实现；3) 查命令参数是否进入文件/网络/进程 sink
- 判据：每个命令/扩展点有实现入口；参数校验与副作用明确；无“注册即执行”的误判
- 失败判据：命令注册存在但实现找不到 → 标“入口不一致”；不猜实现
- reference：Tool/skill/plugin-targets/references/ide-plugins.md

### 12 Xposed 模块动态观测边界（借）（源：performing-dynamic-analysis-of-android-app）
- 触发词：Xposed 动态、hook 日志、作用域、LSPosed、运行时观测
- 前置：自有/授权测试机；模块可禁用；不接真实账号；记录 baseline
- 步骤：1) 启用模块前记录目标行为；2) 只开一个模块/一个 hook，抓日志与调用栈；3) 禁用模块确认行为回退
- 判据：hook 命中日志 + 单变量行为差异 + 回退恢复三者齐全
- 失败判据：模块未加载/作用域不包含目标 → 停，先修环境；不在生产机反复试
- reference：Tool/skill/plugin-targets/references/02-failure-criteria.md

### 13 扩展/插件清单静态解析（借）（源：performing-android-app-static-analysis-with-mobsf）
- 触发词：静态解析、manifest、package.json、plugin.xml、清单、哈希
- 前置：已取得包副本；工具链可用（unzip/7z/Python）；只读
- 步骤：1) `file`/sha256/解包；2) `plugin-triage.py --json` 读清单/入口/权限；3) `plugin-repro.py --json` 落权限证据与最小单元
- 判据：清单字段可解析；入口 exists=true；高危权限有证据或明确未闭环
- 失败判据：解包两次失败/清单不可解析 → 只报容器与哈希；不把字符串当清单
- reference：Tool/skill/plugin-targets/references/01-criteria.md

### 14 Unity/Electron 运行时 hook 观测边界（借）（源：reverse-engineering-ios-app-with-frida）
- 触发词：运行时 hook、Unity、Electron、Frida、调试器、观测边界
- 前置：离线副本/测试环境；允许附加调试器；在线反作弊环境只做外部观测
- 步骤：1) 确认运行时（Mono/IL2CPP/Electron）与版本；2) 只对一个方法/channel 下断；3) 记录参数/返回值与 baseline 差异
- 判据：命中点可指认；单变量差异可重复；回退后基线恢复
- 失败判据：触发反作弊/EDR/崩溃 → 立即停，记录环境；不隐藏注入/不绕过
- reference：Tool/skill/plugin-targets/references/electron-and-asar.md

### 15 BepInEx/MelonLoader DLL 反编译入口（借）（源：reverse-engineering-dotnet-malware-with-dnspy）
- 触发词：BepInEx、MelonLoader、插件 DLL、ilspycmd、dnSpy、HarmonyPatch
- 前置：已定位 `BepInEx/plugins`/`MelonLoader/Mods`；离线副本；有 .NET 反编译工具或降级方案
- 步骤：1) 列插件 DLL 与日志；2) `ilspycmd` 反编译插件，找 `BaseUnityPlugin`/`MelonMod`/`HarmonyPatch`；3) 把 patch 目标对到游戏程序集/`dump.cs`
- 判据：插件类→初始化方法→patch 目标→字段/返回值→可观察效果可画
- 失败判据：插件未加载/目标方法找不到 → 标“未加载/目标未定”；不猜方法名
- reference：Tool/skill/plugin-targets/references/unity-and-mods.md

### 16 Electron 原生模块与驱动 ELF 接口面（借）（源：analyzing-linux-elf-malware）
- 触发词：.node、ELF、原生模块、导出表、驱动、接口面
- 前置：已解包 asar；`file`/`nm`/`objdump` 可用；只读
- 步骤：1) 列 `.node`/`.so`/`.sys` 与架构；2) 看导出/导入/字符串/依赖库；3) 对照 JS 调用点确认参数/返回/错误码
- 判据：JS↔原生边界（函数名/参数/返回）能对上；版本/架构匹配；驱动加载链明确
- 失败判据：只有二进制无 JS 调用点 → 标“接口未闭环”；深挖二进制交 softseep/unpack-loop
- reference：Tool/skill/plugin-targets/references/electron-and-asar.md

### 17 VSIX/扩展签名与更新链核验（借）（源：implementing-code-signing-for-artifacts）
- 触发词：签名、VSIX、扩展签名、更新链、发布者、update_url
- 前置：已取得包与安装来源；只读签名/更新配置；不修改生产签名
- 步骤：1) 记录签名者/发布者/版本；2) 查 `update_url`/市场/企业策略/`app-update.yml`；3) 改包实验只在副本，确认哪层校验会拒绝
- 判据：安装来源、签名者、更新通道、卸载残留四项齐全；改动触发哪层校验可说明
- 失败判据：签名/白名单阻止加载两次 → 停；不提供绕过签名/白名单的方法
- reference：Tool/skill/plugin-targets/references/ide-plugins.md

### 18 插件包静态扫描流水线（借）（源：implementing-devsecops-security-scanning）
- 触发词：静态扫描、流水线、插件包、批量、JSON、CI
- 前置：有插件包清单；Python 3.12；离线；输出目录可写
- 步骤：1) 对每个包跑 `plugin-triage.py --json`；2) 对重点包跑 `plugin-repro.py --json`；3) 汇总 `container/permissions.high/entrypoints/data_flow/blocked`
- 判据：每个包有哈希/容器/入口/权限结论；失败包有 `blocked_at`；结果可复算
- 失败判据：批量中单包失败不影响其他包；失败包只报容器与哈希，不阻塞流水线
- reference：Tool/skill/plugin-targets/references/01-criteria.md

### 19 扩展消息 API 的输入校验（借）（源：testing-api-security-with-owasp-top-10）
- 触发词：消息 API、onMessage、输入校验、schema、sender、注入
- 前置：已解包；能找到消息类型与 handler；隔离 profile
- 步骤：1) 列消息类型/字段/发送方；2) 查 handler 对类型/长度/路径/URL 的校验；3) 对可疑字段追 sink（eval/fetch/fs/native）
- 判据：至少一个可控字段→sink 的路径有代码证据；校验缺失点可指认
- 失败判据：只有消息类型、无字段流 → 标 `inferred`；不写“可注入”
- reference：Tool/skill/plugin-targets/references/browser-extension.md

### 20 浏览器扩展攻击面穿透测试（借）（源：performing-web-application-penetration-test）
- 触发词：扩展攻击面、权限组合、注入、外联、最小单元、穿透
- 前置：自有/授权扩展与隔离浏览器；记录 baseline；不碰真实账号
- 步骤：1) 按 `01-criteria.md` 过权限/入口/消息/存储；2) 选一个最小单元做单变量改动；3) 触发同一事件，对比消息/存储/网络
- 判据：入口+权限+数据流+最小单元四件齐全；改动有 baseline 与回退
- 失败判据：动态两次失败（签名/策略/版本）→ 转静态与更新链；不反复改包
- reference：Tool/skill/plugin-targets/references/04-walkthrough-chrome-extension.md

### 21 扩展内隐藏端点/更新源发现（借）（源：detecting-shadow-api-endpoints）
- 触发词：隐藏端点、shadow API、update_url、配置端点、扩展外联
- 前置：已解包；有静态 URL/字符串；不联网请求
- 步骤：1) 从 manifest/配置/JS 字符串提取 URL 与路径；2) 对照 `fetch/WebSocket` 调用点与参数；3) 查更新器/企业策略/市场端点
- 判据：端点有调用点或配置来源；是否带凭据/用户数据可指认；更新链归属明确
- 失败判据：只有字符串、无调用点 → 标“候选端点/未验证”；不写“已通信”
- reference：Tool/skill/plugin-targets/references/browser-extension.md

### 22 IPC/消息 schema 校验（借）（源：implementing-api-schema-validation-security）
- 触发词：IPC、schema、channel、参数校验、contextBridge、消息格式
- 前置：已解包 Electron/扩展；能列出 channel/消息类型；只读
- 步骤：1) 列 channel/消息类型与发送方；2) 查 handler 对类型/范围/路径/URL 的校验；3) 对未校验字段追 sink
- 判据：每个 channel 有发送方/接收方/参数/副作用；校验缺失点可指认
- 失败判据：只有一端 → 标 `inferred`；不写“可任意调用/RCE”
- reference：Tool/skill/plugin-targets/references/electron-and-asar.md

### 23 插件写入型后门与更新链排查（借）（源：hunting-for-webshell-activity）
- 触发词：写入型后门、更新链、持久化、插件目录、自更新、落盘
- 前置：已取得安装目录与更新配置；只读；不执行可疑更新
- 步骤：1) 查插件目录可写文件/自更新代码/`update_url`；2) 查启动项/服务/注册表持久化；3) 对照签名者与更新来源，列出“谁能推送”
- 判据：写入点→持久化→更新来源三段可指认；签名/白名单层明确
- 失败判据：只有可疑文件、无写入/加载链 → 标 `inferred`；不写“已植入”
- reference：Tool/skill/plugin-targets/references/desktop-plugins.md

### 24 容器内 Electron/插件目录取证（借）（源：analyzing-docker-container-forensics）
- 触发词：容器、Docker、Electron、插件目录、镜像、取证
- 前置：自有/授权容器镜像或运行实例；只读挂载；记录镜像 digest
- 步骤：1) 定位 `resources/app.asar`/扩展目录/插件目录；2) 算哈希并 `plugin-triage.py`/`plugin-repro.py` 解包；3) 记录镜像层/安装来源/更新配置
- 判据：包哈希、容器、入口、权限/插件清单可指认；镜像 digest 与路径可追溯
- 失败判据：容器内文件被裁剪/加密 → 只报镜像与哈希；不把容器层当插件逻辑
- reference：Tool/skill/plugin-targets/references/electron-and-asar.md
