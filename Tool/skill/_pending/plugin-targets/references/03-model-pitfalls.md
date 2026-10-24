# 03 模型常见失误：插件 / 扩展 / Mod

> 范围：用 LLM/代理做插件逆向时的常见错误动作与纠正。每条都能在 `01-criteria.md` / `02-failure-criteria.md` 找到对应判据。
> 用法：只做包体哈希与容器识别的纯取证按 SKILL §1 执行；本页收模型判断失误。
> 读法：先看“错误动作”，对照自己是否正在这么做；再看“正确动作”的可机检落点。

### 1. 把“解包成功”当“分析完成”

- **错误动作**：`unzip` 成功、列出 `manifest.json`，就写“已完成插件分析”。
- **为什么错**：解包只证明容器可读；入口、权限映射、数据流、最小可改单元一个都还没有。
- **正确动作**：跑 `plugin-repro.py --json`，要求 `entrypoints` 有 exists=true 的入口、`permissions[].status=observed` 至少覆盖高危权限、`data_flow` 至少一条边、`minimal_unit.path` 可指认。

### 2. 看到 `manifest.json` 的权限就下“恶意”结论

- **错误动作**：`permissions` 里有 `cookies`/`nativeMessaging`/`debugger`，直接写“窃取 Cookie/可执行任意程序”。
- **为什么错**：权限是能力声明，不是使用证据；很多合法扩展（密码管理器、远程桌面、下载器）需要这些权限。
- **正确动作**：逐条跑 `plugin-repro.py` 的权限证据，只有 `status=observed` 且有 file/line 才写“调用了 X”；再追 sink（fetch/native host/文件），缺 sink 写 `inferred`。

### 3. 把 MV3 service worker 当持久后台页

- **错误动作**：在 SW 里下断，等了几分钟没有请求，就判断“扩展不发网络请求”。
- **为什么错**：MV3 SW 事件驱动，会被浏览器随时回收；模块全局变量也会丢。
- **正确动作**：先触发 `onInstalled/onStartup/onMessage/alarms`，在 `chrome://serviceworker-internals` 确认唤醒；持久状态去 `chrome.storage`/IndexedDB 找；记录“休眠导致未观测”而不是“无行为”。

### 4. 在 content script 里读页面变量

- **错误动作**：content script 里 `window.__INITIAL_STATE__` 读不到，就认为页面没有这个变量或代码被混淆。
- **为什么错**：content script 默认在 isolated world，`window` 是扩展的隔离上下文，不是页面 `window`。
- **正确动作**：查 `world:"MAIN"`、`web_accessible_resources` + 注入 `<script>`、或 `postMessage` 桥；用页面 DevTools 与扩展 DevTools 分别验证。

### 5. 把 `chrome.runtime.sendMessage` 当“任意页面可调用”

- **错误动作**：看到 content script 发消息、background 有 `onMessage`，就写“任意站点可驱动扩展”。
- **为什么错**：还需要 content script 被注入到该站点（`matches`）、`externally_connectable` 允许、以及 `sender` 校验缺失。
- **正确动作**：列出 `content_scripts.matches`、`externally_connectable.matches`、`onMessage` 的 `sender.tab/url/origin` 校验；三者齐备才写“可被外部页面触发”。

### 6. 把 CRX3 头当 zip 直接解

- **错误动作**：`unzip plugin.crx` 失败，就判断“包损坏/加密”。
- **为什么错**：CRX3 = `Cr24` + 版本 + 头长度 + 签名/公钥 + ZIP；zip 起点不在 0。
- **正确动作**：先 `xxd -l 64` 找 `PK\x03\x04`，按头部长度截取；失败两次按 `02-failure-criteria.md` 第 2 条转商店安装目录。

### 7. 把 asar 当加密容器，或把 `.jsc` 当 JS

- **错误动作**：`npx asar extract` 后看到 `.jsc`，用编辑器打开乱码，就写“代码加密不可分析”。
- **为什么错**：asar 只是打包格式，头是 JSON + 偏移；`.jsc` 是 V8 字节码，需要匹配 Node/Electron 版本，不是文本。
- **正确动作**：先解析 asar 头列出 `main/preload/.node/.jsc`；`.jsc` 记录版本与 `bytenode` 加载器，找 source map/原始 bundle；JS 层能解释的行为不要下沉到字节码。

### 8. 只看 `contextBridge` 就断言 RCE

- **错误动作**：preload 里 `contextBridge.exposeInMainWorld('api', { run: (x)=>ipcRenderer.invoke('run', x) })`，直接写“renderer 可执行任意命令”。
- **为什么错**：还要看 main 侧 handler 是否拼接命令、是否校验参数、是否只允许固定命令；也要看 renderer 是否能被远端内容控制。
- **正确动作**：画 `renderer → preload → channel → ipcMain handler → sink` 五段；逐段找校验与可控输入；缺一段写 `inferred`。

### 9. 把 VSIX 的 `activationEvents:*` 当“启动即执行一切”

- **错误动作**：看到 `*` 就写“扩展一启动就执行恶意逻辑”。
- **为什么错**：`*` 只表示激活时机宽；真正的行为在 `activate()` 和命令/语言服务里，且可能被 `engines.vscode`/受限工作区拦住。
- **正确动作**：`main` 入口 + `contributes.commands`/`languages` + `activate()` 内的文件/网络/进程调用三段对齐；记录 `capabilities.untrustedWorkspaces`。

### 10. 把 JetBrains 的 `plugin.xml` 当完整调用链

- **错误动作**：只读 `plugin.xml` 的 `<actions>` 就写“插件会读取项目所有文件并外发”。
- **为什么错**：`plugin.xml` 只是注册表；实现可能在 Kotlin 协程、Service、扩展点回调里，且类名会被 shade/重定位。
- **正确动作**：`plugin.xml` → class 在 jar 中存在 → 反编译顶层类 → 追文件/网络/凭据 API；找不到 class 时标“入口不一致”，不要猜。

### 11. 把 Unity 插件 DLL 当独立程序分析

- **错误动作**：只反编译 `BepInEx/plugins/Mod.dll`，不看游戏程序集，就写“Mod 修改了玩家血量”。
- **为什么错**：Harmony patch 的目标在游戏程序集/IL2CPP `dump.cs` 里；插件侧只有 patch 声明，必须两边对上。
- **正确动作**：先确认加载器/运行时/日志，再 `ilspycmd`/`Cpp2IL` 得到游戏侧符号，最后把 `HarmonyPatch(typeof(T), nameof(T.M))` 与目标方法、字段、返回值对齐。

### 12. 把 IL2CPP 的 `dump.cs` 当原始源码

- **错误动作**：在 `dump.cs` 里看到方法体/字段偏移，直接引用为“游戏原始实现”。
- **为什么错**：`dump.cs` 是结构恢复（类型/方法/字段/偏移），方法体多为占位；偏移需用 IDA/Ghidra 对 `GameAssembly.dll` 验证。
- **正确动作**：把 `dump.cs` 当符号表；关键方法回到二进制看调用约定与偏移；元数据版本不匹配时停（见失败判据第 18 条）。

### 13. 忽略签名/白名单/更新链，反复改包

- **错误动作**：改完 VSIX/asar/扩展后加载失败，继续改代码，认为是逻辑错。
- **为什么错**：宿主可能校验签名、完整性、企业白名单、`engines`/`idea-version`；改包不签名本来就不会加载。
- **正确动作**：先记录加载来源与校验层（商店/旁加载/企业策略/更新器）；两次失败就停，转静态与更新链，不反复改包。

### 14. 把“命中敏感 API”当“数据外发已确认”

- **错误动作**：`grep` 到 `fetch(`、`atob(`、`child_process`，就写“收集数据并外发”。
- **为什么错**：`fetch` 可能请求合法配置；`atob` 可能只是解码资源；`child_process` 可能调用固定工具。
- **正确动作**：追参数来源与 URL/命令常量；确认输入是否含用户数据；把“API 命中”与“数据流边”分开写。

### 15. 把动态观测跑在真实账号/生产宿主上

- **错误动作**：直接在日用浏览器/IDE/游戏账号加载未验证插件，观察行为。
- **为什么错**：插件可能读 Cookie/token、改文件、发远端；会污染证据并影响真实数据。
- **正确动作**：用隔离 profile/虚拟机/离线副本；先备份包与 baseline；动态只做只读观测，改动前导出存储与消息。

### 16. 报告里把 `inferred` 写成 `observed`

- **错误动作**：没有行号/动态证据，但结论写得很确定。
- **为什么错**：读者无法区分“看到”与“猜到”，后续复现会失败。
- **正确动作**：每条结论标 `observed/inferred/unverified/blocked`；`inferred` 必须写缺哪一环、下一步怎么补；失败写 `blocked_at` 与已确认结论。

### 17. 把协议问题留在插件层硬解

- **错误动作**：插件与远端用私有二进制协议，直接在插件代码里猜字段/分帧。
- **为什么错**：协议复刻需要抓包、分帧、状态机、重放；插件层只能给入口与载荷，硬猜会把错误字段写进结论。
- **正确动作**：插件层交出“入口 + 载荷位置 + 触发条件”，协议部分转 `protocol-plugin`（R24）。

### 18. 忽略宿主版本与插件版本的自洽

- **错误动作**：拿旧版 VSIX 在新 VS Code、旧 BepInEx 在新游戏、旧扩展在新 Chrome 上分析，直接把失败当插件问题。
- **为什么错**：`engines.vscode`、`idea-version`、BepInEx/IL2CPP 版本、MV2/MV3 差异都会改变加载与 API 行为。
- **正确动作**：记录宿主版本、插件版本、运行时版本；版本不匹配先换环境或只做静态；结论里写清适用版本。

### 19. 把“声明了权限”当“调用了 API”

- **错误动作**：用户脚本写了 `@grant GM_xmlhttpRequest`、加载项写了 `<Permissions>ReadWriteMailbox</Permissions>`、VSIX 写了 `capabilities`，就在报告里写“它会跨域外发/能改邮箱/能读工作区”。
- **为什么错**：`@grant`/`Permissions`/`capabilities` 是**声明面**（申请到的能力）；真实行为在调用点（`GM_xmlhttpRequest(...)`、Graph/EWS 请求、`workspace.fs` 调用）。声明与调用可以完全不相交，也可能被 `@connect` 白名单、`AppDomains`、受限工作区反过来限制。
- **正确动作**：分别产出 `declared`（清单/头字段）与 `observed`（file/line 调用点）两张表，取交集写结论；差集单列成 `declared_unused`/`observed_undeclared`。判据字段：`permissions[].status`、`userscript.api_calls[]`、`addin.permissions.element`。

## 失败判据与边界

- 如果你正在用“权限/入口/敏感 API 命中”直接下恶意结论 → 停，回到 `01-criteria.md` 的 observed/inferred 分级。
- 如果两次换工具仍无法把权限/入口落到代码路径 → 停，按 `02-failure-criteria.md` 标“未闭环”，不要补写猜测。
- 如果在真实账号/生产宿主上做动态观测 → 停，换隔离 profile/虚拟机/离线副本，并记录 baseline。
- 如果协议字段/分帧拿不到 → 交 `protocol-plugin`（R24），不在插件层硬解。
- 边界：本清单只覆盖授权范围内的插件结构、入口、权限与数据流；签名/白名单/反作弊校验记为校验层。
