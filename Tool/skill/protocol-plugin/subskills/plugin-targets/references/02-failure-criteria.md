# 02 失败判据：看到这些就停/降级

> 范围：本域所有包型。失败判据不是“能力不足”清单，而是**停止条件**：继续做只会把猜测写成结论。
> 入口：已拿到可读入口且能动态复现的样本，按 `01-criteria.md` 正常推进；本页只收失败判据。
> 每条给出“改走哪条”，避免在一个观测层反复撞墙。

## 1. 失败判据表

| # | 现象 | 判定 | 改走哪条 | 代价 |
|---|---|---|---|---|
| 1 | `plugin-triage.py` 对同一包连续两次 `blocked_at=container` | 容器/头部不可信，偏移猜错 | 只报包哈希 + `file`/`xxd` 前 64 字节；转解压目录或 `strings`，不再猜 asar/CRX 偏移 | 失去文件清单，只能给容器结论 |
| 2 | CRX 能找到 `Cr24` 但找不到 `PK\x03\x04`，或找到多个 PK 段 | 截取点不确定，解出的 zip 可能损坏 | 按 CRX 版本字段算头部长度；失败则用商店安装目录（`Extensions/<id>/<ver>/`） | 多花一次取证；旧版 CRX2 可能需要额外头解析 |
| 3 | `manifest.json` 能读，但引用的 `background`/`content_scripts` 文件全部缺失 | 包被裁剪/构建产物不完整，入口未闭环 | 标“入口声明存在、实现缺失”；改查 `web_accessible_resources`、内联 `<script>`、`importScripts` | 无法给数据流；只能给权限面 |
| 4 | 权限能列出，但 `plugin-repro.py` 全部 `unexplained-static` | 权限可能由宿主隐式使用、动态拼接 API 名、或代码在未包含的子包 | 标“权限面未闭环”；扩大解包范围；查 `chrome.*` 字符串拼接与 `eval`；不要写“恶意” | 可能漏掉真实调用；需要人工读打包库 |
| 5 | MV3 service worker 加载后立刻休眠，Network 面板空白 | SW 生命周期导致观测缺失，不是“没有网络” | 触发 `onInstalled/onMessage/alarms`；用 `chrome://serviceworker-internals` 或 DevTools 的 Service Workers 面板唤醒；改看 `chrome.storage` 写入 | 动态证据不足；需设计触发事件 |
| 6 | content script 里 `window.foo` 读不到页面变量 | isolated world 误判 | 查 `world:"MAIN"`、`web_accessible_resources` + 注入 `<script>`、`postMessage` 桥；不要改页面代码硬试 | 需要重做注入链；可能触碰 CSP |
| 7 | `onMessage` 存在但无法证明任意页面可触发 | 消息面校验/SW 唤醒/外部连接三者缺一 | 查 `externally_connectable`、`sender.url` 校验、`tabs.sendMessage` 发送方；标 `inferred` | 不能写“任意站点可利用” |
| 8 | `nativeMessaging` 只有扩展侧 host 名，系统目录没有 host manifest/二进制 | host 侧样本缺失，无法证明执行链 | 按平台查 `NativeMessagingHosts` 注册表/目录；没有就标“host 未取得”，停 | 只能给扩展侧调用点；无法验证 host 行为 |
| 9 | VSIX `main` 指向的文件不存在，或只有 `activationEvents:*` | 构建产物不完整/入口被 bundle 重写 | 查 `browser` 字段、`extension/` 实际文件、`contributes` 命令；标“入口未闭环” | 无法动态加载；只能看清单 |
| 10 | VSIX 在目标 VS Code 版本加载失败（`engines.vscode` 不匹配） | 宿主版本不兼容，不是代码错 | 换匹配版本或只看静态；不要改 `engines` 后宣称“已验证” | 需额外环境；旧版 API 可能不可用 |
| 11 | JetBrains `plugin.xml` 的 class 在 jar 中找不到 | 版本/构建不一致或类被 shade/重定位 | 用 `jar tf` 全量搜 class；查 `META-INF` 多版本；仍找不到就标“入口不一致” | 反编译输出不可信；需要重新取包 |
| 12 | 反编译 Kotlin 插件得到大量 `$lambda$`/协程状态机 | 入口可读但调用链被编译器改写 | 先从 `plugin.xml` 的 Action/Service 定位顶层类，再顺着 `invoke`/`suspend` 找；必要时动态下断 | 读代码时间显著增加 |
| 13 | asar 头部 JSON 能解析，但 `package.json` 读出来是乱码/空 | `data_offset` 对齐错，或文件被压缩/加密 | 用 `plugin-triage.py` 的 `data_offset` 与条目 `offset` 复核；`asar` 不是加密，若字节不可读则标“非标准 asar” | 可能读不到入口；需改用安装目录 |
| 14 | `main.js`/`preload.js` 全是 `.jsc` 字节码，且没有匹配的 Node/Electron 版本 | V8 字节码不可当 JS 读，版本不匹配无法反编译 | 记录 Electron/Node 版本与 `bytenode` 加载器；找 source map/原始 bundle；否则只做字符串与导出面 | 入口逻辑不可读；只能给边界 |
| 15 | 能列 IPC channel，但只有 renderer 或只有 main 一端 | 链路不完整，不能证明可利用 | 补齐另一端（asar 子包/动态加载文件）；标 `inferred`；不要写“可 RCE” | 需要完整包或动态观测 |
| 16 | Unity 插件日志没有 guid/版本，`BepInEx/plugins` 里的 DLL 未被加载 | 加载链失败，patch 是否生效未知 | 查 `LogOutput.log`/`Latest.log`、Doorstop 配置、依赖版本；修路径/版本两次仍失败就停 | 不能验证 patch；只能做静态 |
| 17 | Harmony patch 目标方法找不到，或方法被内联/重载签名不匹配 | patch 目标未定 | 用 `dump.cs`/程序集全量搜方法名与签名；查 `Transpiler` 目标；仍找不到标“目标未定” | 不能改代码；需要更多符号 |
| 18 | IL2CPP `global-metadata.dat` 与 `GameAssembly.dll` 版本不匹配 | 元数据与二进制不同版本，dump 输出不可信 | 换对应版本 Il2CppDumper/Cpp2IL；从同一次安装目录重新取两份文件 | 之前的结构恢复全部作废 |
| 19 | 改完插件后宿主拒绝加载（签名/白名单/完整性校验） | 校验层阻止，不是代码 bug | 停；记录校验层与加载来源；转静态与更新链分析；不反复改包 | 无法动态验证改动；需要官方签名/授权环境 |
| 20 | 插件更新后行为变化，但旧包已被覆盖 | 更新链覆盖了证据 | 先固定版本/备份包与哈希；查 `update_url`/商店版本/企业策略；用旧版本重跑 | 需要重新取证；旧版本可能已不可得 |
| 21 | 输入法/驱动已安装但 `sc query`/`driverquery` 看不到运行实例 | “安装”≠“加载”；可能按需启动或被策略禁用 | 查服务启动类型、事件日志、加载器；只读枚举，不加载未签名驱动 | 无法触发通信路径；只能给安装面 |
| 22 | 触发反作弊/EDR/企业策略告警 | 环境风险，继续会污染证据或影响账号 | 立即停；记录环境、时间、告警；换离线副本或纯静态；不换号绕过 | 动态证据缺失；可能需重新搭环境 |

## 2. 停止规则（硬）

1. **同一路径两次失败就换观测层**：静态→动态→安装目录→更新链，不在同一层反复试错。
2. **缺环不升格**：没有代码/动态证据的权限、入口、IPC、patch，只能写 `inferred`/`unverified`。
3. **签名/白名单/版本校验失败两次**：停，不再改包；记录“校验层阻止”。
4. **反作弊/EDR/账号风控**：立即停，不尝试绕过、不隐藏注入。
5. **协议字节拿不到明文/帧边界**：交 `protocol-plugin`（R24），不在插件层猜字段。

## 3. 降级路线

| 缺失能力 | 降级做法 | 结论强度 |
|---|---|---|
| 无 `npx asar` | `plugin-triage.py`/`plugin-repro.py` 解析 asar 头与偏移 | 结构可读；字节码/原生模块仍不可读 |
| 无 `ilspycmd`/`dnSpy` | `strings` + `monodis`/`r2 -A` 看类型/方法名 | 只能给入口与字符串面 |
| 无 `jadx`/CFR | `javap -c` + `jar tf` + `plugin.xml` | 只能给扩展点与粗粒度调用 |
| 无 DevTools/CDP | 静态消息面 + 存储键 + 日志 | 不能证明运行时触发 |
| 无 IL2CPP dump | 只读 `global-metadata.dat` 字符串与插件 DLL | patch 目标标 `unverified` |
| 无签名/授权环境 | 静态 + 更新链 + 官方文档 | 不写“已加载/已利用” |

## 4. 失败判据与边界

- 失败判据的产物也应留证：命令、rc、stderr、`blocked_at`、已确认的包哈希。
- 不要用“解包成功”“看到 manifest”“命中敏感 API”替代完成判据。
- 商店签名、企业白名单、反作弊或驱动签名强制：记录校验层后按本页降级。
- 涉及真实账号/生产宿主时，优先离线副本；动态观测必须在隔离环境并记录 baseline。

## 5. 失败记录模板

```text
target=<包路径> sha256=<64 hex> container=<crx|vsix|asar|zip|dir|unity>
commands=<triage/repro 命令与 rc>
blocked_at=<container|unpack|permission|entry|dynamic|signature|tool-missing>
confirmed=<已确认的入口/权限/文件>
missing=<缺的环：host/主进程/IL2CPP 元数据/动态观测/签名环境>
next=<换哪条观测层；如果停，写停的理由>
```
