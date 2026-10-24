# 浏览器扩展：MV3 service worker 与隔离世界

> 范围：Chrome/Edge（MV2/MV3）、Firefox（MV2/MV3 差异）、`.crx`/`.xpi`/商店安装目录。
> 路由：普通网页 JS 逆向/补环境由 `mcp-js-reverse-playbook` 承担；纯协议复刻由 `protocol-plugin`（R24）承担；APK 壳由 `apkseep` 承担。
> 目标：把“权限声明”变成“代码路径”，把“页面 → content → background → native/远端”画成有行号的边。

## 1. 来源与容器

| 来源 | 路径 | 特点 |
|---|---|---|
| 商店安装 | `Extensions/<id>/<version>/` | 解压目录，最干净；`_metadata/verified_contents.json` 可校验文件 |
| `.crx` | `Cr24` + 版本/头长度 + 签名/公钥 + ZIP | 不能直接 `unzip`，先找 `PK\x03\x04` |
| `.xpi` | ZIP | Firefox；MV2 仍常见 |
| 企业策略 | `ExtensionInstallForcelist`/`ExtensionSettings` | 记录“谁强制安装/谁可更新” |
| 旁加载 | 开发者模式目录 | 记录路径与是否会被商店版覆盖 |

```bash
file target.crx
xxd -g1 -l 64 target.crx
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --path target.crx --json
sha256sum target.crx
```

- CRX3 头：`Cr24` + 4 字节版本 + 4 字节头长度 + 头（签名/公钥）+ ZIP；截取点用头部长度算，不要只找第一个 PK（旧格式可能有多个）。
- 解压失败两次按 `02-failure-criteria.md` 第 2 条转商店安装目录。
- `_metadata/verified_contents.json` 是文件级哈希树；可用于“安装后是否被改过”的取证，不是加载时校验的全部。

## 2. manifest 权限面

```bash
jq '{manifest_version,name,version,permissions,optional_permissions,host_permissions,
     background,content_scripts,web_accessible_resources,externally_connectable,
     action,options_page,devtools_page,side_panel,content_security_policy,update_url}' \
  unpack/manifest.json
```

| 字段 | 看什么 | 高危组合 |
|---|---|---|
| `permissions` | API 能力 | `nativeMessaging`、`debugger`、`cookies`、`webRequest`、`scripting`、`userScripts` |
| `host_permissions` | 站点范围 | `<all_urls>` + content script 全站注入 |
| `optional_permissions` | 运行时申请 | 静态阶段不能当已获得；要动态看 `permissions.request` |
| `background.service_worker` | MV3 事件页 | 会休眠；事件驱动 |
| `background.scripts` | MV2 持久页 | 常驻，状态在内存 |
| `content_scripts` | 注入范围/时机/世界 | `matches:<all_urls>`、`all_frames:true`、`run_at:document_start`、`world:MAIN` |
| `web_accessible_resources` | 暴露给页面的文件 | 宽 matches + 可被页面 `fetch`/`<script>` 加载 |
| `externally_connectable` | 哪些站点可直连 | `*://*/*` + 特权消息 |
| `nativeMessaging` | 调本机 host | host manifest 的 `allowed_origins` 过宽 |
| `content_security_policy` | 是否允许 `unsafe-eval`/远端脚本 | 与远端内容共存 |

**判据**：每个权限能对应到 `plugin-repro.py` 的 `permissions[].evidence[].file/line`；不能解释的单列 `unexplained-static`。

## 3. MV3 service worker 生命周期

MV3 的 background 是 service worker：

- 事件驱动：空闲约 30 秒被回收（浏览器策略会变）；模块全局变量不是持久状态。
- 唤醒源：`onInstalled`、`onStartup`、`onMessage`、`alarms`、`webNavigation`、`tabs` 事件、`declarativeNetRequest` 规则命中、`contextMenus` 点击等。
- 持久化：`chrome.storage.local/sync/session`、IndexedDB、Cache Storage；不要用 `localStorage`（SW 里不可用）。
- 定时任务：`chrome.alarms`（最小 30 秒级，实际受浏览器限制），不是 `setInterval`。
- 调试：`chrome://serviceworker-internals` 看状态/停止/启动；DevTools 的 Service Workers 面板可离线/唤醒。

```bash
# 找唤醒源与持久状态
grep -nE "onInstalled|onStartup|onMessage|alarms\.|storage\.(local|sync|session)|indexedDB" \
  unpack/background/*.js | head -60
```

**判据**：至少一个唤醒源 + 一处持久状态；否则“行为在 SW 重启后丢失”是设计问题，不是观测问题。

## 4. isolated world 与 MAIN world

| 世界 | 能看到 | 能改 | 进入方式 |
|---|---|---|---|
| ISOLATED（默认） | 扩展 API、自己的变量；页面 DOM 可见但 JS 全局隔离 | 页面 DOM，不能改页面 JS 全局 | `content_scripts` 默认 |
| MAIN | 页面 `window`/全局变量 | 页面 JS 全局 | `world:"MAIN"`（MV3）或注入 `<script>` |
| 扩展页/SW | 扩展 API、跨域（受权限） | 扩展存储/网络 | `background`/`options`/`popup` |

常见桥：

```js
// content script（ISOLATED）→ 页面（MAIN）
const s = document.createElement('script');
s.src = chrome.runtime.getURL('inject.js');       // 需要 web_accessible_resources
(document.head || document.documentElement).appendChild(s);
window.addEventListener('message', (e) => {
  if (e.source !== window) return;                 // 必须校验 source/origin
  chrome.runtime.sendMessage({ type: 'from-page', data: e.data });
});
```

**判据**：能说清某段代码在哪个世界运行、它读的 `window` 是谁的、跨世界通信用的是 `postMessage` 还是 `chrome.runtime`。看不到 `world` 字段时默认 ISOLATED。

## 5. 数据流三条链

### 5.1 页面 → 扩展

```text
page DOM/event
  → content script (ISOLATED)
  → chrome.runtime.sendMessage({type,payload})
  → service worker onMessage
  → storage / fetch / native host
```

检查 `sender.tab.id`、`sender.url`、`sender.origin` 是否校验；未校验 + content script 全站注入 = 任意页面可驱动。

### 5.2 扩展 → 页面

- `chrome.scripting.executeScript`（MV3）或 `tabs.executeScript`（MV2）。
- `world:"MAIN"` 才能改页面全局；ISOLATED 只能改 DOM。
- `web_accessible_resources` + `fetch(chrome.runtime.getURL('x'))` 是常见桥；检查资源是否含敏感配置/密钥。
- `declarativeNetRequest` 规则看 `rules/*.json` 的 `urlFilter`、`resourceTypes`、`action`（redirect/modifyHeaders）。

### 5.3 扩展 → 本机/远端

- `chrome.runtime.connectNative(host)` / `sendNativeMessage`；host 名对应系统 manifest。
- Windows：`HKCU/HKLM\Software\...\NativeMessagingHosts\<name>`；macOS/Linux：`~/Library/Application Support/.../NativeMessagingHosts/`、`~/.config/...`。
- 检查 host manifest 的 `path`、`allowed_origins`；host 进程是独立可执行文件，要单独分析（本域只交接口，不深入其协议）。
- 远端：`fetch`/`XMLHttpRequest`/`WebSocket`/`sendBeacon`；记录 URL、方法、字段、是否带 Cookie/token。

**判据**：至少一条链能从输入指到 sink；`plugin-repro.py` 的 `data_flow` 给出 kind/file/line。

## 6. 存储与凭据

| 位置 | 读法 | 注意 |
|---|---|---|
| `chrome.storage.local/sync/session` | DevTools → Application → Extension storage | 明文 token/配置；`sync` 会跨设备 |
| IndexedDB | DevTools → Application | 结构随版本变；可能存页面快照 |
| `localStorage` | 页面域 | content script 看到的是页面存储，不是扩展存储 |
| Cookie | `chrome.cookies` 权限 | 记录 domain/path/HttpOnly/SameSite；证据脱敏 |
| Cache Storage | DevTools | 可能含下载资源/远端脚本 |

**判据**：敏感数据能对应到写入 API、读取方、生命周期（SW 重启后是否还在）。

## 7. 动态观测（隔离环境）

```text
1. 新建隔离 profile（不要用日用浏览器）
2. chrome://extensions → 开发者模式 → Load unpacked
3. 扩展卡片 → service worker → Inspect
4. Sources 下断：onMessage / fetch / storage.set / connectNative
5. Application → Extension storage / IndexedDB
6. 页面 DevTools → Network，按 Initiator=extension 过滤
7. 记录 baseline：未注入/未改代码时的消息、存储、网络
```

- SW 休眠：先触发事件再观察；必要时用 `chrome://serviceworker-internals` 手动 start。
- 页面上下文：CDP `Target.getTargets` 找 `type=page`，或在注入点下断。
- 只读优先：先记录消息/存储/网络，再考虑改返回值；改动前导出 baseline。

**判据**：静态入口与运行时消息能对上；能解释某条存储是何时由谁写入。

## 8. 常见高风险模式（只写能力，不直接定性）

- 宽 host + 读表单/Cookie + 远端上报。
- `nativeMessaging` + 下载/执行二进制（host 侧）。
- `externally_connectable` 允许任意站点触发敏感动作。
- MV3 只允许打包内代码，但 `importScripts`/`eval`/`unsafe-eval` 仍可能出现（会被商店拒绝）。
- 供应链：内嵌第三方 SDK/统计脚本；对比商店版与旁加载版哈希、`_metadata` 哈希树。
- 更新链：`update_url`、企业策略、旁加载覆盖；记录“谁可以推送更新”。

## 9. 最小可改单元

优先级：

1. 单个 `onMessage` 分支/消息类型（加日志、改返回值、加校验）。
2. 单个 content script 注入点（`world`/`run_at`/`matches`）。
3. 单个 `chrome.scripting.executeScript` 调用。
4. 单个 `connectNative` 调用（只改扩展侧，host 侧另算）。

改动前：备份解压目录、记录 `manifest.json` 哈希、导出 storage baseline；改动后：重载扩展，触发同一事件，对比消息/存储/网络。一次只改一个变量。

**判据**：改动点文件/行号可指认，回退方式明确，行为差异可重复。

## 10. 用户脚本（Tampermonkey / Violentmonkey）

用户脚本没有 `.crx`：权限来自元数据头的 `@grant`，不是 `manifest.permissions`。

典型头：`// @match https://example.com/*` + `// @grant GM_xmlhttpRequest` + `// @connect api.example.net` + `// @require https://cdn.example.org/lib.js` + `// @updateURL https://example.org/demo.meta.js`，夹在一对 `// ==UserScript==` 之间。

| 头字段 | 作用 | 取证要点 |
|---|---|---|
| `@match`/`@include` | 注入范围 | `@match` 是 scheme+host+path；`@include` 通配/正则更宽，易越界 |
| `@grant` | 申请 GM_* 能力 | `none`＝页面/沙箱上下文且几乎无 GM_*；`unsafeWindow` 也要显式 grant |
| `@connect` | `GM_xmlhttpRequest` 目标域 | 未列入即被拦；`@connect *` 等于任意外联 |
| `@require` | 安装/更新时拉远端库 | 供应链面：内容不由脚本哈希固定 |
| `@updateURL` | 更新链 | 谁控制该 URL 谁就能推新代码；`@version` 比较决定是否拉取 |

**GM_* 权限面**：`GM_setValue/getValue/listValues`（跨站存储）、`GM_xmlhttpRequest`（绕 CORS）、`GM_cookie`、`GM_download`、`GM_openInTab`、`GM_notification`、`GM_addStyle`；逐条对到调用点才算“用到”。

**隔离世界**：TM 默认沙箱（MV3 走 `chrome.userScripts`，`world:ISOLATED`），`window` 是包装对象；`@grant unsafeWindow` 或 `world:MAIN` 才碰页面真 `window`。Violentmonkey 的 `@inject-into`（auto/page/content）决定上下文，`auto` + `@grant none` 常落到 page。

```bash
jq '{name,version,match,grant,connect,require,updateURL}' work/repro/userscript.headers.json   # 头字段
```

**判据**：`userscript.headers.grant[]`∩`userscript.api_calls[]` 非空且每条有 file/line；`userscript.update_url.host` 与 `connect[]`/`match[]` 域不同则单列；`@require` 的 URL 与哈希另存。

**失败判据**：只有 `@grant` 无调用点 → 写“权限声明未使用”，不写“读写 cookie”；`@require` 404/无哈希 → `unverified`；上下文与报告不符 → 回看 `@inject-into`/`world`；更新 URL 不可解析 → 只给 `@version` 与本地哈希。

## 11. 失败判据与边界

- 包体解不出可读清单/入口，两次换工具仍失败 → 停，只报哈希与容器（见 `02-failure-criteria.md` 第 1–3 条）。
- 权限能列但无法对应代码路径 → 标“权限面未闭环”，不写“恶意”。
- MV3 SW 休眠导致动态观测缺失 → 标“未观测”，不写“无网络”。
- isolated world 变量对不上 → 查 `world`/注入桥，不要改页面代码硬试。
- native host 缺失 → 只写扩展侧调用点，host 行为 `unverified`。
- 触发企业策略/EDR/账号风控 → 立即停，记录环境；签名/白名单按校验层归档。
- 插件内私有协议/分帧 → 交 `protocol-plugin`（R24）。

> 关联：`references/04-walkthrough-chrome-extension.md`（真实扩展走查）、`references/01-criteria.md`、`references/02-failure-criteria.md`。
