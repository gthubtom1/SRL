---
name: plugin-targets
description: "'这个插件/扩展怎么逆/浏览器扩展或 IDE 插件 (.crx/.vsix/.asar) —— 插件/扩展/Mod：MV2/MV3、VSIX/JetBrains、Electron asar、BepInEx。"
license: MIT
compatibility: Windows/Linux/macOS；解包用 unzip/7z，asar 用 npx asar 或仓库脚本，.NET 用 ilspycmd/dnSpy，Unity 用 Il2CppDumper/Cpp2IL，Java 用 jadx/CFR；全部缺省时可用内置 `plugin-triage.py`/`plugin-repro.py` 做结构与证据初筛。
metadata:
  version: "2.0.0"
  category: plugin-targets
  routes: "R25"
  hard_gates: "入口可指认 / 权限或扩展点可解释 / 数据流可追 / 最小可改单元可验证"
  references: "references/01-criteria.md, references/02-failure-criteria.md, references/03-model-pitfalls.md, references/04-walkthrough-chrome-extension.md, references/browser-extension.md, references/ide-plugins.md, references/electron-and-asar.md, references/unity-and-mods.md, references/desktop-plugins.md"
---

# plugin-targets — 插件 / 扩展 / Mod（R25）

> 只回答一件事：**这个插件从哪进入宿主、拿到什么权限/扩展点、读了什么数据、把数据送到哪、最小可改单元是什么。**
> 不把“解包成功”当完成，也不把“看到 manifest/权限”当分析。只对自有或明确授权的插件/宿主操作。

## 1. 范围与路由（边界）

| 本域输入面 | 相邻域（由谁承担） |
|---|---|
| 浏览器扩展 `.crx`/`.xpi`/商店安装目录（MV2/MV3） | 普通网页 JS 签名/补环境 → `mcp-js-reverse-playbook` |
| VS Code/Cursor `.vsix`、JetBrains `.jar` | 纯协议/抓包/分帧/状态机/重放 → `protocol-plugin`（R24） |
| Electron `app.asar`/`resources/app`、preload、`.node`/`.jsc` | APK 壳/重打包/Xposed 模块深拆 → `apkseep` |
| Unity BepInEx/MelonLoader（Mono/IL2CPP）、Harmony patch | PE 壳/反调试/驱动二进制深挖 → `unpack-loop`/`softseep` |
| 输入法/驱动级插件、OBS/StreamDeck、native messaging host | 供应链 lockfile/构建完整性 → `supply-chain-security` |

**硬边界**：

- 插件里的私有协议不要在本技能内硬解：先交出“入口 + 载荷位置 + 触发条件”，再由 `protocol-plugin` 复刻。
- 遇到商店签名/企业白名单/驱动签名强制/反作弊校验：记录校验层与判据，按 `01-criteria.md` 收束；授权测试同时记录环境与回退。
- 原始包只读；解包/改动只在副本；动态观测只在隔离 profile/虚拟机/离线副本。

## 2. 前置检查（3 件）

1. **授权与来源**：记录包路径/URL、版本、商店 ID、安装时间、宿主版本；确认有权分析。
2. **证据目录**：`work/{unpack,repro,evidence}`；原包算 sha256，先备份。
3. **工具探测**：`unzip`/`7z`、`python`、`node`/`npx asar`、`ilspycmd`/`dnSpy`、`jadx`、`Il2CppDumper`/`Cpp2IL`；缺失走降级（§8），不要卡在安装工具。

```bash
sha256sum plugin.crx
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --path plugin.crx --json
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py --path plugin.crx --out work/repro --json
```

## 3. 判型表

| 形态 | 包体/识别 | 入口 | 终点判据 |
|---|---|---|---|
| 浏览器扩展 | `.crx`/`.xpi`/解压目录；`manifest.json` | `background.service_worker`/`content_scripts` | 权限面 + 消息流 + 关键逻辑 |
| VS Code 扩展 | `.vsix`（zip）；`extension/package.json` | `main`/`activationEvents` | 激活点 + 命令/贡献点 |
| JetBrains 插件 | `.jar`/`.zip`；`META-INF/plugin.xml` | action/extension/service | 扩展点 + 服务 |
| Electron | `app.asar`/`resources/app` | `package.json` → main/preload | 主进程/preload/原生模块 |
| Unity Mod | BepInEx/MelonLoader 目录 | `BepInEx/plugins/*.dll` 等 | 插件类 + Harmony patch 目标 |
| 输入法/驱动 | `.ime`/`.sys`/DLL/服务 | 注册表/服务/加载器 | 加载链 + 通信协议 |
| Native host | 系统 `NativeMessagingHosts/*.json` | host 可执行文件 | 扩展 ID ↔ allowed_origins ↔ 进程 |

## 4. 判据表（确认 / 疑似）

> 机检脚本：`plugin-triage.py`（结构/权限面）、`plugin-repro.py`（解包/权限证据/数据流/最小单元）。
> “确认”必须能指到 file/line 或动态证据；“疑似”只能写 `inferred`，并列出缺环。

| 类别 | 确认（observed） | 疑似（inferred/unverified） |
|---|---|---|
| 容器/入口 | `container` 明确；manifest/package/plugin.xml 可解析；入口文件 `exists=true` | 只有扩展名/魔数；入口声明但文件缺失 |
| 权限面 | `permissions[].status=observed` 且 evidence 有 file/line；宽 host 与代码一致 | 权限能列但无代码路径（`unexplained-static`） |
| MV3/隔离世界 | 有唤醒源 + 持久状态；能说清 ISOLATED/MAIN 与 `postMessage` 校验 | SW 休眠导致未观测；变量对不上 |
| 数据流 | 至少一条 `data_flow` 边有 file/line（sendMessage/fetch/connectNative/ipc） | 只有 API 命中、无参数来源；只有一端 |
| VSIX/JetBrains | 激活事件/扩展点→实现→关键 API 有行号；版本匹配 | 只有 `activationEvents:*`；class 找不到 |
| Electron | main/preload 存在；IPC 通道成对；`webPreferences` 可读 | 只有 `.jsc`/原生模块；IPC 只有一端 |
| Unity | 加载器/运行时/日志齐全；patch 目标在游戏程序集/`dump.cs` 存在 | 插件未加载；目标被内联/混淆 |
| 原生/驱动 | 加载链→入口→用户态调用方/设备可指认 | 仅安装未加载；只有注册项 |
| 最小单元 | `minimal_unit.path` 存在，有符号/行号、baseline、回退 | 选到 bundle 头部/生成文件；改动不可回退 |

## 5. 失败判据（看到即降级）

> 完整表见 `references/02-failure-criteria.md`（22 条）。这里只列“立即停/换层”的硬条件。

| 现象 | 判定 | 改走哪条 |
|---|---|---|
| 同一包两次 `blocked_at=container` | 容器/偏移不可信 | 只报哈希 + `file`/`xxd`；转安装目录/`strings` |
| manifest 入口文件全缺 | 包被裁剪/构建不完整 | 标“入口未闭环”；查 `web_accessible_resources`/内联脚本 |
| 权限全 `unexplained-static` | 权限未落地 | 扩大解包范围；查动态 API 拼接；仍无 → 标未闭环，不写“恶意” |
| MV3 SW 休眠、Network 空白 | 观测缺失 | 触发 `onInstalled/onMessage/alarms`；查 storage；不写“无网络” |
| native host 只有扩展侧 | host 样本缺失 | 查系统 `NativeMessagingHosts`；无 → 停 |
| VSIX `main` 缺失/仅 `*` | 入口未闭环 | 查 `browser`/contributes/实际文件 |
| asar 头解析两次失败 | 偏移错/非标准 asar | 只报容器与哈希；转 `strings`/安装目录 |
| 全 `.jsc` 且版本不匹配 | 字节码不可读 | 记录版本/加载器；找 source map；只做字符串面 |
| IPC 只有一端 | 链路不完整 | 补齐另一端；标 `inferred` |
| Unity 插件未加载/IL2CPP 版本不匹配 | 加载链/工具链失败 | 查日志/版本；两次失败即停 |
| 改包后拒绝加载 | 签名/白名单/完整性 | 停；记录校验层；转静态/更新链 |
| 触发反作弊/EDR/企业策略 | 环境风险 | 立即停；记录环境；换离线副本 |

**停止规则**：同一路径两次失败就换观测层；缺环不升格；签名/白名单/版本失败两次即停；反作弊/EDR 立即停；协议拿不到明文/帧边界交 R24。

## 6. 模型常见失误（≥8 条）

> 完整 18 条见 `references/03-model-pitfalls.md`。每条都是“错误动作 → 为什么错 → 正确动作”。

1. **把“解包成功”当“分析完成”**：解包只证明容器可读；正确动作是跑 `plugin-repro.py`，要求入口 exists、权限有 file/line、至少一条数据流、最小单元可指认。
2. **看到权限就下“恶意”结论**：权限是能力声明；正确动作是逐条找证据与 sink，缺 sink 写 `inferred`。
3. **把 MV3 SW 当持久后台页**：SW 会休眠、模块全局变量会丢；正确动作是触发唤醒源、查 `chrome.storage`/IndexedDB。
4. **在 content script 里读页面变量**：默认 ISOLATED world；正确动作是查 `world:"MAIN"`/注入桥/`postMessage`。
5. **把 `sendMessage` 当任意页面可调用**：还需注入范围 + `externally_connectable` + 无 `sender` 校验；三者齐备才写“可被外部触发”。
6. **把 CRX3 头当 zip 直接解**：`Cr24` + 版本/头长度 + ZIP；先找 `PK\x03\x04`，失败两次转商店目录。
7. **把 asar 当加密 / 把 `.jsc` 当 JS**：asar 是 JSON 头 + 偏移；`.jsc` 是 V8 字节码，需版本匹配。
8. **只看 `contextBridge` 就断言 RCE**：还要看 main handler 的参数校验与 sink；缺一段写 `inferred`。
9. **把 VSIX `activationEvents:*` 当“启动即执行一切”**：真正行为在 `activate()`/命令里，且可能被 `engines`/受限工作区拦住。
10. **把 `plugin.xml` 当完整调用链**：它只是注册表；class 可能被 shade/重定位，找不到就标“入口不一致”。
11. **把 Unity 插件 DLL 当独立程序**：patch 目标在游戏程序集/`dump.cs`；必须两边对上。
12. **把 IL2CPP `dump.cs` 当原始源码**：它是结构恢复；关键偏移回 `GameAssembly.dll` 验证，版本不匹配即停。
13. **忽略签名/白名单/更新链反复改包**：先记录校验层；两次失败即停。
14. **把“命中敏感 API”当“数据已外发”**：追参数来源与 URL/命令常量，区分 API 命中与数据流边。
15. **在真实账号/生产宿主上动态观测**：用隔离 profile/虚拟机/离线副本，先备份 baseline。
16. **报告把 `inferred` 写成 `observed`**：每条结论标级别；缺环写清楚。
17. **在插件层硬解私有协议**：交 `protocol-plugin`（R24），本域只交入口与载荷位置。
18. **忽略宿主/插件/运行时版本自洽**：记录版本；不匹配先换环境或只做静态。

## 7. 流程（每阶段有完成判据）

### 阶段 A：收货与判型

```bash
sha256sum target > SHA256SUMS
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --path target --json
```

完成判据：`container` 明确；清单可解析；入口清单存在；原包只读。

### 阶段 B：解包与入口

```bash
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py --path target --out work/repro --json
```

完成判据：`entrypoints` 至少一个 `exists=true`；后台/内容脚本/main/preload/插件 DLL 可指认；`unpacked` 路径可复跑。

### 阶段 C：权限/扩展点落地

```bash
jq '{permissions,optional_permissions,host_permissions,background,content_scripts,
     externally_connectable,update_url}' work/repro/unpack/manifest.json
```

完成判据：每个高危权限有 `status=observed` + file/line；不能解释的单列；VSIX/JetBrains 的激活事件/扩展点对到实现。

### 阶段 D：数据流与最小单元

完成判据：至少一条“输入 → 插件 → 输出”有代码证据；`minimal_unit.path/symbols` 可指认；有 baseline 与回退方式；协议部分单独标注交 R24。

### 阶段 E：动态/签名/更新（可选）

完成判据：隔离环境；只读优先；一次一个变量；两次加载失败即停；记录签名者/更新通道/受限工作区。

### 阶段 F：结论与复算

完成判据：结论按 `observed/inferred/unverified/blocked` 标注；命令/rc/哈希/产物齐全；案例产物 sha256 可复算。

## 8. 参考索引（逐篇）

| 文件 | 用途 |
|---|---|
| `references/01-criteria.md` | 判据总表：场景/输入面/机检判据/证据形态/误报风险 |
| `references/02-failure-criteria.md` | 失败判据 22 条：现象/判定/改走哪条/代价 |
| `references/03-model-pitfalls.md` | 模型常见失误 18 条：错误动作/为什么错/正确动作 |
| `references/04-walkthrough-chrome-extension.md` | 真实案例走查：本机 Chrome MV3 扩展（Quicker 1.2.4） |
| `references/browser-extension.md` | MV3 service worker、隔离世界、权限面、消息面 |
| `references/ide-plugins.md` | VSIX/JetBrains 激活点、扩展点、受限工作区、签名更新 |
| `references/electron-and-asar.md` | asar 结构、main/preload/renderer、IPC、原生模块/`.jsc` |
| `references/unity-and-mods.md` | BepInEx/MelonLoader、Mono/IL2CPP、Harmony patch、验证流程 |
| `references/desktop-plugins.md` | OBS/StreamDeck、输入法/驱动、native host、签名/持久化 |

## 9. 脚本用法

```bash
# 结构 + 权限面 + 可疑 API + 远程 URL（只读，不解包落盘）
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --path target.crx --json
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --path app.asar --json

# 解包 + 入口/权限证据 + 数据流 + 最小可改单元
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py --path target.vsix --out work/repro --json

# 离线自检（无外网/无真实目标）
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --self-test
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py --self-test

# 兼容入口（转发到 skill 脚本）
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --path target.crx
```

退出码：0 成功；2 结构化失败（`{"ok": false, "blocked_at": "...", "reason": "..."}`）。脚本不执行包内代码、不联网。

## 10. 任务卡入口

- `Tool/prompts/domains/plugin-targets.md`（24 张，源技能名取自 `Tool/config/taskcard-sources.json`，均为最近邻，卡名标「借」）。
- 推荐顺序：01/02/03（浏览器）→ 04/22（Electron）→ 15/14（Unity）→ 17/10（IDE/签名）→ 09/23（native/持久化）→ 20（综合）。

## 11. KB board 入口

- `Tool/mcp/Tool/reverselab/kb/plugin/README.md`（board 索引 + 10 分钟初筛 + 三条硬判据 + 失败判据 + 邻域边界）。
- 逐篇：`manifest-and-permissions.md`、`asar-and-mod-loaders.md`、`mv3-service-worker-isolation.md`、`asar-main-process.md`、`unity-il2cpp-bepinex.md`、`ide-plugin-vsix-jetbrains.md`、`plugin-failure-criteria.md`。

## 12. 交付检查清单

- [ ] 包哈希、版本、来源、宿主版本齐全，原包只读。
- [ ] manifest/package.json/plugin.xml 的权限与入口逐条解释。
- [ ] 页面/宿主 → 插件 → 远端/本地的数据流至少一条有 file/line。
- [ ] 最小可改单元已定位，有 baseline 与回退。
- [ ] 动态观测在隔离环境，未影响真实账号/生产数据。
- [ ] 结论标注 observed/inferred/unverified/blocked；缺环不冒充完成。
- [ ] 协议/分帧问题已明确交给 `protocol-plugin`（R24）。

> 失败判据、边界与降级详见 `references/02-failure-criteria.md` 与 `references/03-model-pitfalls.md`。
