# 浏览器扩展逆向速查

> 配套 `plugin-targets/SKILL.md`。只在自有或明确授权的扩展/浏览器配置上操作。

## 1. 包体来源

| 来源 | 路径/方法 | 备注 |
|---|---|---|
| 商店安装 | 浏览器 profile 的 `Extensions/<id>/<version>/` | 解压目录，最干净 |
| `.crx` | `unzip`/7z；CRX3 先定位 `PK\x03\x04` | 头部含签名与公钥 |
| `.xpi` | zip | Firefox，`manifest.json` 可能是 MV2 |
| 企业策略 | 注册表/`policy.json` | 记录 `ExtensionInstallForcelist` |

```bash
# CRX → ZIP：找到第一个 PK 头再截取
python3 - <<'PY'
b=open('plugin.crx','rb').read()
i=b.find(b'PK\x03\x04')
open('plugin.zip','wb').write(b[i:])
PY
unzip -q plugin.zip -d ext/
sha256sum plugin.crx ext/manifest.json
```

## 2. manifest 逐项

```bash
jq . ext/manifest.json
```

- `manifest_version`：MV2 有持久 background page，MV3 是 service worker。
- `permissions`：API 权限；`host_permissions`：站点范围；`optional_permissions` 运行时申请。
- `content_scripts[].matches` / `exclude_matches` / `run_at` / `all_frames` / `world`。
- `background.service_worker` 或 `background.scripts`；`type: module` 影响加载方式。
- `action`/`browser_action`、`options_page`、`devtools_page`、`side_panel`。
- `web_accessible_resources`：暴露给页面的文件与匹配域。
- `externally_connectable`：哪些站点可直接 `sendMessage`。
- `nativeMessaging`：可调用本机 host；host 清单在系统目录。
- `content_security_policy`：是否允许 `unsafe-eval`/远端脚本。
- `key`：扩展公钥，升级后是否变化。

## 3. 入口定位

```bash
# 所有 JS 中出现的扩展 API
grep -RInE "chrome\.|browser\." ext --include='*.js' | sed 's/:.*chrome\./ -> chrome./' | head -100
# 消息与注入
grep -RInE "onMessage|sendMessage|connectNative|executeScript|insertCSS|scripting\.executeScript" ext --include='*.js'
# 动态加载/混淆
grep -RInE "eval\(|new Function|atob\(|WebAssembly|importScripts|fetch\(" ext --include='*.js'
```

优先级：`background` → `content_scripts` → `options`/`devtools` → 页面注入。

## 4. 三条数据流

### 4.1 页面 → 扩展

```text
page DOM/event
  → content script (isolated world)
  → chrome.runtime.sendMessage({type, payload})
  → service worker onMessage
  → storage / fetch / native host
```

- 检查 `sender.tab.id`/`sender.url` 是否校验；未校验 = 任意页面可驱动。
- `postMessage` 的 `origin`/`source` 校验是常见缺口。

### 4.2 扩展 → 页面

- `chrome.scripting.executeScript` 注入函数；`world:"MAIN"` 才能改页面变量。
- `web_accessible_resources` + `fetch(chrome.runtime.getURL(...))` 是常见桥。
- `declarativeNetRequest` 规则可改请求头/重定向；看 `rules/*.json` 的 `urlFilter` 与 `resourceTypes`。

### 4.3 扩展 → 本机

- `chrome.runtime.connectNative(host)`；host 名对应系统 manifest：
  - Windows：注册表 `HKCU/HKLM\Software\...\NativeMessagingHosts\<name>`
  - macOS/Linux：`~/Library/Application Support/.../NativeMessagingHosts/`、`~/.config/...`
- 检查 host 的 `path`、`allowed_origins` 是否过宽；host 进程是独立可执行文件，需单独分析。

## 5. 存储与凭据

| 位置 | 读法 | 注意 |
|---|---|---|
| `chrome.storage.local/sync` | DevTools Application → Extension storage | 可能有明文 token |
| IndexedDB | DevTools Application | 结构随版本变 |
| `localStorage` | 页面域，不是扩展域 | content script 看到的是页面存储 |
| Cookie | `chrome.cookies` 权限 | 记录 domain/path/HttpOnly/SameSite |
| Cache Storage | DevTools | 可能含下载资源 |

- 证据脱敏：只保留字段名、长度、前缀；不写完整 token。
- 判据：每条敏感数据能对应到写入 API 与读取方。

## 6. 动态观测

```text
1. chrome://extensions → 开发者模式 → Load unpacked
2. 扩展卡片 → service worker → Inspect
3. Sources → 下断在 onMessage / fetch / storage.set
4. Application → Extension storage / IndexedDB
5. 页面 DevTools → Network 过滤扩展发起的请求（Initiator 指向 extension）
```

- MV3 worker 会休眠：先触发一次事件，再在 `chrome://serviceworker-internals` 看状态。
- 需要页面上下文：CDP `Target.getTargets` 找 `type=page`，或在 content script 的注入点下断。
- 记录 baseline：未注入/未改代码时的消息、存储、网络。

## 7. 常见恶意/高风险模式

- 宽 `host_permissions` + 读取所有表单/Cookie + 远端上报。
- `nativeMessaging` + 下载并执行二进制。
- `externally_connectable` 允许任意站点触发敏感动作。
- 远程脚本：MV3 禁止远端代码，但可用 `importScripts`/`eval` 绕过（会被商店拒绝）。
- 供应链：扩展内嵌第三方 SDK、统计脚本、更新检查；对比商店版与旁加载版哈希。

## 8. 报告模板

```text
扩展：<name> <version> (<id>)
权限：<permission> → <代码位置> → <实际能力>
入口：<background> / <content script> / <native host>
数据流：<source> → <sink>（含字段与协议）
存储：<key> @ <storage>，写入者 <file:line>
最小可改单元：<file:line>，改前/改后差异：<...>
未验证：<...>
```
