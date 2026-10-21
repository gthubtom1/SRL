# Manifest 与权限面：CRX/MV3、VSIX、JetBrains

> 目标：把“权限/入口”逐条落到代码路径；看不到数据流就只是清单，不是结论。

## 1. 容器识别

```bash
file target.crx target.vsix plugin.jar
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path target.crx
unzip -l target.vsix | head -40
jar tf plugin.jar | head -40
```

- `.crx` = CRX3 头 + ZIP；先找 `PK\x03\x04` 再解。
- `.vsix` = ZIP；入口在 `extension/package.json`。
- `.jar` = ZIP；入口在 `META-INF/plugin.xml`。
- 记录 SHA256、版本、来源、宿主版本。

**判据**：容器/版本/哈希/入口清单四项齐全，原包只读。

## 2. 浏览器扩展 manifest

```bash
jq '{manifest_version,permissions,host_permissions,optional_permissions,
     background,content_scripts,web_accessible_resources,
     externally_connectable,commands,content_security_policy}' ext/manifest.json
```

| 字段 | 看什么 | 高危组合 |
|---|---|---|
| permissions | API 权限 | `<all_urls>` + webRequest + cookies |
| host_permissions | 站点范围 | 过宽 + content script 全站注入 |
| background | SW/持久页 | MV3 事件驱动、可能休眠 |
| content_scripts | matches/js/world/run_at | `world:"MAIN"` 进页面上下文 |
| web_accessible_resources | 暴露给页面的文件 | 宽 matches + 可被页面加载 |
| externally_connectable | 哪些站点可 sendMessage | 任意站点 + 特权消息 |
| nativeMessaging | 调用本机 host | host manifest 的 allowed_origins |
| CSP | unsafe-eval/远端脚本 | 与远端内容共存 |

**判据**：每个权限都能对应一条实际代码路径；不能解释的单列。

## 3. 扩展入口与数据流

```bash
grep -RInE "chrome\.(runtime|tabs|storage|cookies|webRequest|scripting)|browser\." ext --include='*.js' | head -80
grep -RInE "sendMessage|onMessage|connectNative|postMessage" ext --include='*.js' | head -80
```

三条链：

1. 页面 → content script → background → 远端/本地
2. background → tabs/scripting → 页面
3. 扩展 → native host → 本机进程

- content script 默认 isolated world；`world:"MAIN"` 或注入 `<script>` 才进页面。
- 存储：`chrome.storage.local/sync`、IndexedDB、localStorage（页面域）、Cookie。
- 动态观测：`chrome://extensions` 开发者模式 → 加载已解压 → SW DevTools。

**判据**：能指出消息类型、发送/接收方、字段、落盘位置。

## 4. VS Code `.vsix`

```bash
unzip -q ext.vsix -d vsix/
jq '{name,version,main,activationEvents,contributes,capabilities,engines}' vsix/extension/package.json
```

- `main` 入口；`activationEvents`：`onCommand`/`onLanguage`/`*`。
- `contributes`：commands、menus、keybindings、languages、debuggers、configuration。
- `capabilities.untrustedWorkspaces`：受限工作区是否禁用。
- Webview 只是 UI；数据来源在 extension host（文件、网络、secret storage）。

**判据**：激活事件 → 命令/语言服务 → 文件/网络读写，链路完整。

## 5. JetBrains `.jar`

```bash
unzip -p plugin.jar META-INF/plugin.xml
jadx -d out/ plugin.jar
```

- `<actions>`、`<extensions>`、`<applicationService>` 是入口；`idea-version` 定兼容。
- Java/Kotlin 用 jadx/CFR/Fernflower；配置/文案常在 `messages/*.properties`。
- 最小单元：单个 Action/Service 或扩展点注册。

**判据**：扩展点 → Action/Service → 关键逻辑与数据源。

## 6. 失败判据

- 权限/入口无法对应代码路径 → 标“未闭环”。
- MV3 SW 休眠导致动态缺失 → 主动唤醒，仍缺失则标 `unverified`。
- 签名/企业白名单阻止加载 → 记录校验层，不反复改包。
- 压缩 bundle 无 source map 且无法定位 → 先 prettier/字符串表，不硬读一行。
