# 01 判据表：插件 / 扩展 / Mod

> 范围：浏览器扩展（MV2/MV3）、VSIX/JetBrains、Electron/asar、Unity BepInEx/MelonLoader、输入法/驱动级插件。
> 路由：纯协议复刻由 `protocol-plugin`（R24）承担；APK 壳/重打包由 `apkseep` 承担；普通 PE 脱壳由 `unpack-loop` 承担；供应链 lockfile 审计由 `supply-chain-security` 承担。
> 本表判据尽量做成“可机检”：命令能跑、输出字段能对上、文件/行号能指认。看不到就写 `unverified`，不升格为结论。

## 1. 总表

| # | 场景 | 输入面 | 判据（可机检） | 证据形态 | 误报风险 |
|---|---|---|---|---|---|
| 1 | 浏览器扩展容器识别 | `.crx` / `.xpi` / 解压目录 | `plugin-triage.py --json` 的 `container` ∈ `{crx,xpi,zip,directory}`；CRX 能找到 `PK\x03\x04`；`manifest.json` 可解析 | JSON + `manifest.json` 原文 + 包哈希 | 扩展名伪装成 `.crx` 实为 zip；CRX3 头后有多个 PK 段，截错段 |
| 2 | MV3 入口闭环 | `manifest.json` | `background.service_worker` 或 `background.scripts` 指向的文件存在；`content_scripts[].js` 全部存在；`action/options_page/devtools_page` 存在或为空 | 入口清单（kind/path/exists）+ 行号 | 声明了入口但文件缺失；`type:module` 的动态 import 未列出 |
| 3 | MV3 service worker 生命周期 | `background.service_worker` | 代码中出现 `chrome.runtime.onInstalled/onStartup/onMessage/alarms` 至少一个唤醒源；持久状态写入 `chrome.storage`/IndexedDB 而非模块全局变量 | 事件注册点 + 存储键 | 把“SW 休眠导致没看到网络”误判为“没有网络”；把模块全局变量当持久状态 |
| 4 | 权限面逐条落地 | `permissions` / `host_permissions` | `plugin-repro.py` 的 `permissions[].status` 为 `observed`，且 `evidence[]` 有 file/line/snippet；`host_permissions` 与 `content_scripts.matches` 一致或更窄 | 权限→文件:行号→片段 | 权限由宿主/内置 API 隐式使用，静态搜不到；打包库里的同名 API 造成假命中 |
| 5 | 宽 host + 敏感 API | `<all_urls>` / `*://*/*` + cookies/webRequest | 同时命中 `broad_hosts` 与 `permission_surface.high`；且 `data_flow` 中存在 `cookies`→`fetch/WebSocket` 或 `connectNative` 的边 | 两条数据流边 + 代码片段 | 合法同步/翻译扩展也读页面；高权限本身不是恶意 |
| 6 | content script 隔离世界 | `content_scripts[].world` / 注入 `<script>` | `world` 为 `ISOLATED`（默认）还是 `MAIN`；是否用 `web_accessible_resources` + `<script src>` 进页面；`window`/`document` 变量能否跨世界访问 | manifest 字段 + 注入代码行 | 把 isolated world 的 `window` 当页面 `window`；把 `postMessage` 当同世界调用 |
| 7 | 消息面校验 | `runtime.onMessage` / `postMessage` | 每个 `onMessage` 有 `sender.tab.id` / `sender.url` / `origin` 校验之一；`externally_connectable.matches` 不是 `*://*/*` 或未声明 | 校验分支代码 + 发送方清单 | 内部扩展消息不校验也合理；只看到 `sendMessage` 不代表可被任意页面触发 |
| 8 | nativeMessaging 链 | `nativeMessaging` + `connectNative` | 代码有 host 名常量；系统 host manifest 的 `allowed_origins` 与扩展 ID 对应；host 二进制路径存在或明确缺失 | host 名 + manifest 路径 + 进程路径 | 只有扩展侧常量、没有 host 侧样本时不能证明可执行 |
| 9 | VSIX 激活闭环 | `.vsix` / `extension/package.json` | `main` 文件存在；`activationEvents` 与 `contributes.commands`/`languages`/`views` 至少一条对应；`engines.vscode` 与目标宿主版本相容 | package.json 摘要 + 入口行号 | `activationEvents:*` 但无实际命令；bundle 压缩导致入口可读但逻辑不可读 |
| 10 | VSIX 受限工作区 | `capabilities.untrustedWorkspaces` | `supported:false` 或 `restrictedConfigurations` 非空；代码在受限工作区仍执行文件/进程操作即为风险 | capabilities + 调用点 | 扩展只读工作区也可能合法；未在真实 VS Code 加载不能证明行为 |
| 11 | JetBrains 扩展点 | `.jar` / `META-INF/plugin.xml` | `plugin.xml` 可解析；`<actions>`/`<extensions>`/`<applicationService>` 的 class 能在 jar 中找到；`idea-version` 覆盖目标 IDE | plugin.xml + class 路径 + 反编译入口 | Kotlin lambda/协程导致类名漂移；`plugin.xml` 与实际实现版本不一致 |
| 12 | Electron 三层边界 | `app.asar` | `package.json.main` 存在；`BrowserWindow.webPreferences.preload` 指向文件；`contextIsolation`/`nodeIntegration`/`sandbox` 值可读到；`ipcMain`/`ipcRenderer` 通道成对出现 | package.json + 窗口创建代码 + IPC 清单 | asar 头解析错位导致读到伪 JSON；`main` 被 `.jsc` 覆盖 |
| 13 | Electron IPC 校验 | preload + main | 每个暴露的 channel 能指到 handler；handler 对路径/URL/命令参数有校验；`shell.openExternal` 限制 scheme | channel→handler→sink 三段 | 只看到 `contextBridge` 就断言“可 RCE”；实际参数被上游校验 |
| 14 | Unity 加载器/运行时 | 游戏目录 | 存在 `BepInEx`/`MelonLoader`/`doorstop_config.ini`；`GameAssembly.dll`+`global-metadata.dat` 判 IL2CPP；`Managed/Assembly-CSharp.dll` 判 Mono | 目录清单 + 日志 + 程序集哈希 | 只装加载器未装插件；IL2CPP 元数据版本与二进制不匹配 |
| 15 | Unity patch 闭环 | 插件 DLL + 游戏程序集 | 插件类继承 `BaseUnityPlugin`/`MelonMod`；`HarmonyPatch` 目标类型/方法在游戏程序集或 `dump.cs` 中存在；日志显示插件已加载 | DLL 字符串 + 反编译源码 + 日志行 | 目标方法被内联/重载；patch 注册成功但目标未调用 |
| 16 | 输入法/驱动加载链 | `.ime`/`.sys`/服务/注册表 | 能列出加载服务/驱动、签名者、设备/IOCTL 或命名管道；用户态调用方能指认 | `sc query`/`driverquery` + 签名 + 设备名 | 把“已安装”当“已加载”；把厂商签名当安全证明 |
| 17 | 签名与更新链 | 商店/更新器/策略 | 记录签名者、更新 URL、`allowed_origins`/白名单、旁加载方式；改动后是否会被覆盖/拒绝加载 | 签名信息 + 更新配置 + 加载来源 | 开发者模式旁加载被商店版覆盖；企业策略只允许签名包 |
| 18 | 最小可改单元 | 入口文件/类/方法 | `plugin-repro.py` 的 `minimal_unit.path` 存在；有 symbols 或行号；能说明改前/改后观察点与回退方式 | minimal_unit JSON + baseline 哈希 | 选到 bundle 头部或生成文件；改动点无法回退 |
| 19 | 外挂脚本/二进制插件（用户脚本、kubectl/IaC、Jupyter） | `*.user.js` 头、`kubectl-foo`、`.terraform/providers`、`jpserver_extensions` | `userscript.headers.grant[]`∩`userscript.api_calls[]` 非空且每条有 file/line；`cli_plugin.invoker` ∈ `{kubectl,terraform,jupyter}` 且 `iac.lock_hashes` 与 provider 二进制哈希一致；`jupyter.routes[].authenticated` 明确、`jupyter.extensions[].enabled=true` | 头字段 JSON + 二进制/锁哈希 + 路由表 | `@grant`/配置键声明≠调用；扩展 enabled 未重启即当已生效 |
| 20 | Office/Outlook Web Add-in | `manifest.xml` | `addin.permissions.element` 与 `addin.version_overrides.permissions` 均非空；`addin.function_file.url`/`addin.source_location.host` 可指认；`addin.app_domains[]` 与 task pane 实际跳转域一致；`addin.update_channel` ∈ `{sideload,appsource,central}` | 清单片段 + 承载页 URL + 加载来源 | 只读顶层 `<Permissions>` 漏 `VersionOverrides`；把 `AppDomains` 当网络出口白名单 |
| 21 | Electron ASAR 完整性/加载约束 | `app.asar` + fuse | `plugin-accept.py --json` 的 `asar_integrity_ok`/`load_from_asar_only`/`bypass_path` 三字段齐全；fuse 值与 asar 头哈希可复算；`bypass_path` ∈ `{none,unpacked,run-as-node,inspect,dir-fallback}` | fuse 输出 + asar 哈希 + 实际加载路径 | 旧版无 fuse；只看到 `app.asar` 就断言完整性开启 |
| 22 | V8 字节码（bytenode） | `.jsc` / `v8::internal::Script` | `v8_bytecode=true`；`v8_version_match` 记录 Electron/Node/V8 三元组；`decompile_ok` 有命令/rc；否则只能给字符串面 | `.jsc` 头 + 版本三元组 + 反汇编命令/rc | 版本不符硬解；把反汇编当源码 |
| 23 | Electron IPC 越权验收 | `ipcMain.handle` / preload / `webPreferences` | `ipc_sender_checked`/`openexternal_scheme`/`webpref_unsafe`/`preload_exposed` 四字段有 file/line 或 `unverified`；至少一条 channel→sink 有证据 | handler + preload + 窗口参数 + sink | 只看到 `contextBridge` 就断言 RCE；远端内容与本地页混判 |

## 2. 机检命令（最小集）

```bash
# 结构 + 权限面 + 可疑 API
python Tool/skill/protocol-plugin/subskills/plugin-targets/scripts/plugin-triage.py --path target.crx --json

# 解包 + 入口/权限证据 + 最小可改单元
python Tool/skill/protocol-plugin/subskills/plugin-targets/scripts/plugin-repro.py --path target.crx --out work/repro --json

# 浏览器扩展关键字段
jq '{manifest_version,permissions,host_permissions,background,content_scripts,
     web_accessible_resources,externally_connectable,update_url}' work/repro/manifest.json

# VSIX
jq '{main,activationEvents,contributes,capabilities,engines}' work/repro/extension/package.json

# asar
python Tool/skill/protocol-plugin/subskills/plugin-targets/scripts/plugin-triage.py --path app.asar --json

# 域验收：字段/哈希/real+recorded/refs + 权限代码证据
python Tool/skill/protocol-plugin/subskills/plugin-targets/scripts/plugin-accept.py --root . --json
```

## 3. 判据分级

| 级别 | 含义 | 允许写什么 |
|---|---|---|
| `observed` | 文件/行号/命令输出直接可见 | “代码在此处调用了 X” |
| `inferred` | 由清单/字符串/调用关系推断，未动态验证 | “很可能由 X 触发”，并列出缺环 |
| `unverified` | 只有声明或第三方描述 | “声明了 X，未验证” |
| `blocked` | 工具/签名/版本/权限导致无法继续 | 写 `blocked_at` 与已确认的容器结论 |

## 4. 完成判据（缺一不可）

- [ ] 包哈希、版本、来源、宿主版本齐全，原包只读。
- [ ] 清单入口/权限逐条映射到文件与行号，不能解释的单列。
- [ ] 至少一条“输入 → 插件 → 输出”的数据流有代码证据。
- [ ] 最小可改单元可指认，且有 baseline 与回退方式。
- [ ] 动态观测在隔离环境，未影响真实账号/生产数据。
- [ ] 结论按 observed/inferred/unverified 标注，缺环不冒充完成。

## 5. 失败判据与边界

- 两次换工具仍解不出可读清单/入口 → 只报容器与哈希，转 `strings`/安装目录，不硬猜偏移。
- 权限/入口能列出但无法对应代码路径 → 标“权限面未闭环”，不写“恶意”。
- 动态加载两次失败（签名/白名单/版本不匹配）→ 转静态与更新链，不反复改包。
- 插件内含协议但取不到明文/帧边界 → 交 `protocol-plugin`（R24）。
- 触发反作弊/企业策略/账号风控 → 立即停，记录环境，不换号绕过。
- 本文只做授权范围内的插件结构、入口、权限与数据流分析；签名/白名单/反作弊校验按 `02-failure-criteria.md` 记录为校验层。

## 附：上游技能卡索引（24 张）

> 上游 = `mukul975/Anthropic-Cybersecurity-Skills`（818 技能库）。本表只回答一件事：这条上游技能在本域**落到哪张卡、哪篇 reference、判据是什么**。

| 上游技能 | 本域任务卡 | 落点 reference | 一句话判据 |
|---|---|---|---|
| `analyzing-browser-forensics-with-hindsight` | 浏览器扩展安装面与历史痕迹取证（借）（源：analyzing-browser-forensics-with-hindsight） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/browser-extension.md` | 容器/版本/来源/哈希四项齐全；`manifest_version`、`background`、`content_scr… |
| `extracting-browser-history-artifacts` | 扩展权限面与浏览数据触达清点（借）（源：extracting-browser-history-artifacts） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/01-criteria.md` | 高危权限至少一条 `status=observed`；不能解释的单列 `unexplained-static`；无“权限… |
| `implementing-browser-isolation-for-zero-trust` | 扩展隔离世界与宿主边界验证（借）（源：implementing-browser-isolation-for-zero-trust） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/browser-extension.md` | 能说清每段代码在哪个世界、`window` 是谁的、跨世界通信方式；消息有 `source/origin` 校验 |
| `performing-thick-client-application-penetration-test` | Electron 客户端 asar 入口与 IPC 面（借）（源：performing-thick-client-application-penetration-test） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/electron-and-asar.md` | `main`/`preload` 文件存在；至少一条 IPC 链有 file/line；`webPreferences`… |
| `conducting-mobile-app-penetration-test` | LSPosed/Xposed 模块入口与作用域核对（借）（源：conducting-mobile-app-penetration-test） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/01-criteria.md` | hook 目标类/方法→参数/返回值→可观察效果可画；作用域明确；模块可禁用回退 |
| `deobfuscating-javascript-malware` | 扩展/asar 内混淆 JS 的入口还原（借）（源：deobfuscating-javascript-malware） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/electron-and-asar.md` | 入口文件可读；至少一个消息/网络/存储调用能指到行号；混淆不冒充加密 |
| `analyzing-malicious-url-with-urlscan` | 扩展远端 URL 与更新源核对（借）（源：analyzing-malicious-url-with-urlscan） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/browser-extension.md` | URL/方法/字段/是否带 Cookie/token 可指认；更新链“谁能推送”明确 |
| `performing-web-application-vulnerability-triage` | 扩展注入面与页面消息校验（借）（源：performing-web-application-vulnerability-triage） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/browser-extension.md` | 任意页面可驱动的条件齐备（注入范围+外部连接+无校验）才写“可被外部触发” |
| `performing-mobile-app-certificate-pinning-bypass` | Native host 通信面与证书边界（借）（源：performing-mobile-app-certificate-pinning-bypass） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/04-walkthrough-chrome-extension.md` | 扩展 ID ↔ allowed_origins ↔ host 可执行文件 ↔ 调用点四项能对上 |
| `implementing-mobile-application-management` | 企业策略下的插件白名单与旁加载（借）（源：implementing-mobile-application-management） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/ide-plugins.md` | 安装来源、签名者、更新通道、卸载残留四项齐全；策略阻止加载时能指出是哪一层 |
| `auditing-mcp-servers-for-tool-poisoning` | 插件命令/工具注册面的权限审计（借）（源：auditing-mcp-servers-for-tool-poisoning） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/ide-plugins.md` | 每个命令/扩展点有实现入口；参数校验与副作用明确；无“注册即执行”的误判 |
| `performing-dynamic-analysis-of-android-app` | Xposed 模块动态观测边界（借）（源：performing-dynamic-analysis-of-android-app） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/02-failure-criteria.md` | hook 命中日志 + 单变量行为差异 + 回退恢复三者齐全 |
| `performing-android-app-static-analysis-with-mobsf` | 扩展/插件清单静态解析（借）（源：performing-android-app-static-analysis-with-mobsf） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/01-criteria.md` | 清单字段可解析；入口 exists=true；高危权限有证据或明确未闭环 |
| `reverse-engineering-ios-app-with-frida` | Unity/Electron 运行时 hook 观测边界（借）（源：reverse-engineering-ios-app-with-frida） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/electron-and-asar.md` | 命中点可指认；单变量差异可重复；回退后基线恢复 |
| `reverse-engineering-dotnet-malware-with-dnspy` | BepInEx/MelonLoader DLL 反编译入口（借）（源：reverse-engineering-dotnet-malware-with-dnspy） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/unity-and-mods.md` | 插件类→初始化方法→patch 目标→字段/返回值→可观察效果可画 |
| `analyzing-linux-elf-malware` | Electron 原生模块与驱动 ELF 接口面（借）（源：analyzing-linux-elf-malware） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/electron-and-asar.md` | JS↔原生边界（函数名/参数/返回）能对上；版本/架构匹配；驱动加载链明确 |
| `implementing-code-signing-for-artifacts` | VSIX/扩展签名与更新链核验（借）（源：implementing-code-signing-for-artifacts） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/ide-plugins.md` | 安装来源、签名者、更新通道、卸载残留四项齐全；改动触发哪层校验可说明 |
| `implementing-devsecops-security-scanning` | 插件包静态扫描流水线（借）（源：implementing-devsecops-security-scanning） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/01-criteria.md` | 每个包有哈希/容器/入口/权限结论；失败包有 `blocked_at`；结果可复算 |
| `testing-api-security-with-owasp-top-10` | 扩展消息 API 的输入校验（借）（源：testing-api-security-with-owasp-top-10） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/browser-extension.md` | 至少一个可控字段→sink 的路径有代码证据；校验缺失点可指认 |
| `performing-web-application-penetration-test` | 浏览器扩展攻击面穿透测试（借）（源：performing-web-application-penetration-test） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/04-walkthrough-chrome-extension.md` | 入口+权限+数据流+最小单元四件齐全；改动有 baseline 与回退 |
| `detecting-shadow-api-endpoints` | 扩展内隐藏端点/更新源发现（借）（源：detecting-shadow-api-endpoints） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/browser-extension.md` | 端点有调用点或配置来源；是否带凭据/用户数据可指认；更新链归属明确 |
| `implementing-api-schema-validation-security` | IPC/消息 schema 校验（借）（源：implementing-api-schema-validation-security） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/electron-and-asar.md` | 每个 channel 有发送方/接收方/参数/副作用；校验缺失点可指认 |
| `hunting-for-webshell-activity` | 插件写入型后门与更新链排查（借）（源：hunting-for-webshell-activity） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/desktop-plugins.md` | 写入点→持久化→更新来源三段可指认；签名/白名单层明确 |
| `analyzing-docker-container-forensics` | 容器内 Electron/插件目录取证（借）（源：analyzing-docker-container-forensics） | `Tool/skill/protocol-plugin/subskills/plugin-targets/references/electron-and-asar.md` | 包哈希、容器、入口、权限/插件清单可指认；镜像 digest 与路径可追溯 |
