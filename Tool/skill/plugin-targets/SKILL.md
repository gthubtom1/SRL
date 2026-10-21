---
name: plugin-targets
description: 【插件/扩展/Mod】浏览器扩展（Chrome/Edge/Firefox）、IDE 插件（VSIX/JetBrains）、Electron asar、Unity BepInEx/MelonLoader 与输入法/驱动级插件的逆向与取证。以“入口、关键逻辑、数据来源、最小可改单元”四件事齐全为判据，覆盖 manifest 权限面、content script 隔离世界、service worker、原生模块、插件签名与更新链，并给出缺工具时的降级路线。
license: MIT
compatibility: Windows/Linux/macOS；解压用 unzip/7z，asar 用 npx asar，.NET 用 ilspycmd/dnSpy，Unity 用 IL2CPP 工具链；全部缺省时可用 `seep_domain_audit(mode="plugin")` 做清单与风险初筛。
metadata:
  version: "1.1.0"
  category: plugin-targets
  routes: "R25"
  hard_gates: "入口可指认 / 权限可解释 / 数据流可追 / 最小可改单元可验证"
  references: "references/browser-extension.md, references/desktop-plugins.md, references/electron-and-asar.md, references/unity-and-mods.md"
---

# plugin-targets — 插件 / 扩展 / Mod（R25）

> 只回答一件事：**这个插件从哪进入宿主、读了什么数据、把数据送到哪、最小可改单元是什么。**
> 不把“解包成功”当完成，也不把“看到 manifest”当分析。仅对自有或明确授权的插件/宿主操作。

**分工（硬边界）**：插件 / 扩展 / Mod → **本技能（R25）**；协议 / 抓包 / 分帧 / 状态机 / 重放 → **`protocol-plugin`（R24）**。插件里的私有协议不要在本技能内硬解，先交出入口与载荷，再由 protocol-plugin 复刻。

## 0. 判型与边界

| 形态 | 包体 | 入口 | 终点判据 |
|---|---|---|---|
| 浏览器扩展 | `.crx`/`.xpi`/解压目录 | `manifest.json` → background/service_worker | 权限面 + 消息流 + 关键逻辑 |
| VS Code 扩展 | `.vsix`（zip） | `extension/package.json` → `main`/`activationEvents` | 激活点 + 命令/贡献点 |
| JetBrains 插件 | `.jar`/`.zip` | `META-INF/plugin.xml` → action/extension | 扩展点 + 服务 |
| Electron | `app.asar`/`resources/app` | `package.json` → main | 主进程/预加载/原生模块 |
| Unity Mod | BepInEx/MelonLoader | `BepInEx/plugins/*.dll` | 插件类 + Harmony patch 目标 |
| 输入法/驱动 | `.ime`/`.sys`/DLL | 注册表/服务/加载器 | 加载链 + 通信协议 |

**边界**：普通网页 JS 签名/补环境走 `mcp-js-reverse-playbook`；APK 走 `apkseep`；PE 壳/反调试走 `unpack-loop`；客户端授权旁路走 `01`–`05`。本技能只读取这些产物，不重复其方法。

**四条硬规则**：① 先备份/复制，原包只读；② 先静态后动态，动态只在隔离环境；③ 一次只改一个变量并留基线；④ 同一路径两次失败就换观测层。

## 1. 收货与清单（先留证据）

```bash
sha256sum plugin.crx > SHA256SUMS
mkdir -p work/{unpack,export,evidence}
unzip -q plugin.crx -d work/unpack        # crx 也是 zip；失败再用 7z
file work/unpack/* | head
find work/unpack -maxdepth 2 -type f | sort
```

- 记录来源 URL、版本、商店 ID、签名状态、安装时间、宿主版本。
- 浏览器扩展的商店 ID 与 `manifest.key` 可用于确认“同一个扩展”；升级后对比 key 是否变化。
- 判据：包体哈希、文件清单、manifest/package.json、入口文件四项齐全。

## 2. 浏览器扩展（Chrome/Edge/Firefox）

### 2.1 manifest 权限面

```bash
jq . work/unpack/manifest.json
jq '{mv: .manifest_version, perms: .permissions, host: .host_permissions,
     bg: .background, cs: .content_scripts, war: .web_accessible_resources}' \
   work/unpack/manifest.json
```

- 高危组合：`<all_urls>` + `webRequest`/`declarativeNetRequest` + `cookies`；`debugger`；`nativeMessaging`；`externally_connectable`；`content_scripts` 注入所有站点。
- MV3 的 `service_worker` 是事件驱动，可能被浏览器随时回收；持久状态在 `chrome.storage`/IndexedDB。
- `web_accessible_resources` 暴露给页面的文件是页面与扩展的桥；`matches` 越宽，攻击面越大。
- 判据：每个权限能对应到一条实际代码路径；不能解释的权限单独列出。

### 2.2 入口与数据流

```bash
# 找入口与消息面
grep -RInE "chrome\.(runtime|tabs|storage|cookies|webRequest|declarativeNetRequest|scripting)|browser\." work/unpack --include='*.js' | head -80
grep -RInE "sendMessage|onMessage|connectNative|externally_connectable|postMessage" work/unpack --include='*.js' | head -80
```

- 三条链必须画出来：**页面 → content script → background → 远端/本地**；**background → tabs/scripting → 页面**；**扩展 → native host → 本机进程**。
- `content_scripts` 默认在 isolated world；只有注入 `<script>` 或 `world:"MAIN"` 才进页面上下文，两者能力不同。
- 存储：`chrome.storage.local/sync`、`IndexedDB`、`localStorage`（content script 看到的是页面域）、Cookie。
- 判据：能指出消息类型、发送方/接收方、携带字段、落盘位置。

### 2.3 动态观测

```text
1. chrome://extensions → 开发者模式 → 加载已解压的扩展
2. 打开该扩展的 service worker → DevTools → Network/Sources/Console
3. 页面 DevTools → Application → Extension storage / IndexedDB
4. 需要看页面上下文时，在 content script 注入点下断，或 CDP 附加 target
```

- 只读优先：先记录消息与存储，再考虑改返回值；改动前导出 baseline。
- 判据：静态入口与运行时消息能对上，且能解释某条存储是何时由谁写入。

## 3. 桌面插件（VSIX / JetBrains / asar / Unity Mod）

### 3.1 VS Code `.vsix`

```bash
unzip -q ext.vsix -d work/unpack
jq '{name, version, main, activationEvents, contributes, capabilities}' work/unpack/extension/package.json
```

- `main` 是入口；`activationEvents` 决定何时加载（`onCommand`、`onLanguage`、`*` 最宽）。
- `contributes` 看命令、配置、语言服务、任务、调试器；`capabilities.untrustedWorkspaces` 看是否在受限工作区禁用。
- 判据：激活事件 → 命令/语言服务 → 关键文件读写/网络请求，链路完整。

### 3.2 JetBrains `.jar`

```bash
unzip -l plugin.jar | head -40
unzip -p plugin.jar META-INF/plugin.xml
# 反编译（授权）
jadx -d work/jadx plugin.jar   # 或 CFR/procyon
```

- `plugin.xml` 的 `<actions>`、`<extensions>`、`<applicationService>` 是入口；`idea-version` 决定兼容范围。
- 判据：扩展点 → Action/Service → 关键逻辑与数据源。

### 3.3 Electron `asar`

```bash
npx asar list app.asar | head -80
npx asar extract app.asar work/asar
jq '{name, version, main, dependencies, scripts}' work/asar/package.json
```

- `main` 是主进程；`preload` 是渲染进程与 Node 的桥；`contextIsolation:false`/`nodeIntegration:true` 会放大风险。
- `*.node` 原生模块要单独 `file`/`strings`；`bytenode` 的 `.jsc` 需 V8 字节码工具，不能当普通 JS。
- 判据：主进程/预加载/渲染三层边界清楚，能指出 IPC 通道与校验点。

### 3.4 Unity Mod（BepInEx/MelonLoader）

```bash
find . -iname 'BepInEx' -o -iname 'MelonLoader' -o -iname '*.dll' | head
ilspycmd Mod.dll -o work/mod-src
grep -RInE "Harmony(Patch|Prefix|Postfix)|MelonMod|OnUpdate|RegisterType" work/mod-src | head -40
```

- 先找插件入口（`BaseUnityPlugin.Load` / `MelonMod.OnInitializeMelon`），再找 patch 目标（原游戏方法）。
- 判据：插件类 → patch 目标 → 修改的字段/返回值 → 可观察效果。

## 4. 签名、更新与持久化

- 扩展/插件更新链：商店签名、`update_url`、企业策略、开发者模式旁加载；记录“谁可以推送更新”。
- Windows 驱动/输入法：签名者、加载服务、注册表启动项、与用户态进程的通信（IOCTL/命名管道/共享内存）。
- 判据：能说明“装一次后如何持续存在”，以及卸载是否彻底。

## 5. 工具与降级

| 能力 | 首选 | 降级 |
|---|---|---|
| 解包 | `unzip`/`7z` | Python `zipfile`、`bsdtar` |
| manifest/JSON | `jq` | Python `json`（注释用 json5） |
| asar | `npx asar` | 解析 asar header（JSON 长度+偏移） |
| .NET | `ilspycmd`/`dnSpy` | `monodis`、`r2 -A` |
| JS | DevTools/CDP | `js-reverse` 工具链、`prettier` 后手读 |
| 清单/风险初筛 | `seep_domain_audit(mode="plugin")` | 本文命令 + `seep_auto_triage` |

缺工具走 `seep_tool_discover` / `tool-run.ps1` / `seep_tool_install`；安装需确认。降级要标注“验证到什么程度”。

## 6. 坑

1. **crx 版本头**：Chrome 的 CRX3 头不是 zip 开头，先找 `PK\x03\x04` 再解。
2. **MV3 service worker 休眠**：看不到网络不等于没发；用 `chrome://serviceworker-internals` 或 DevTools 唤醒。
3. **isolated world 误判**：content script 里 `window` 不是页面 `window`；变量对不上先查 world。
4. **source map 缺失**：压缩代码先 `prettier` + `source-map` 还原，别硬读一行。
5. **asar 不是加密**：能列目录不代表能读 `.jsc`/原生模块；字节码要单独处理。
6. **插件版本与宿主不匹配**：VSIX `engines.vscode`、JetBrains `idea-version`、BepInEx 版本都会导致“加载失败”。
7. **签名/白名单**：企业宿主可能只加载签名插件；改完不签名 = 不加载，别误判为代码错。
8. **更新覆盖**：开发者模式旁加载会被商店版覆盖；记录加载来源与更新策略。
9. **隐私**：插件常读 Cookie/token；证据脱敏，不把凭据写进报告。

## 7. 验收与失败判据

**完成判据（缺一不可）**

- [ ] 包体哈希、版本、来源、宿主版本齐全，原包只读。
- [ ] manifest/package.json/plugin.xml 的权限与入口逐条解释。
- [ ] 页面/宿主 → 插件 → 远端/本地的数据流能画出来。
- [ ] 最小可改单元已定位，并有“改前/改后”的可观察差异。
- [ ] 动态观测在隔离环境，未影响真实账号与生产数据。
- [ ] 结论标注 observed/inferred/unverified；缺环不冒充完成。

**失败判据（何时停）**

- 包体无法解出可读清单/入口，且两次换工具仍失败 → 停，只报包体哈希与容器结论。
- 权限/入口能列出但无法对应到任何代码路径 → 标“权限面未闭环”，不写“恶意”。
- 动态加载两次失败（签名/白名单/版本不匹配）→ 停，转静态与更新链分析，不反复改包。
- 插件内含协议但无法取到明文/帧边界 → 交 protocol-plugin（R24），不在本技能猜字段。
- 触发反作弊/企业策略/账号风控 → 立即停，记录环境，不换号绕过。

> 细节：`references/browser-extension.md`、`references/desktop-plugins.md`、`references/electron-and-asar.md`、`references/unity-and-mods.md`。
