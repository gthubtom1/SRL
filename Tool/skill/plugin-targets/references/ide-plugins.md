# IDE 插件：VSIX / JetBrains 与签名更新

> 范围：VS Code/Cursor `.vsix`、JetBrains `.jar`/`.zip`、Open VSX/市场安装目录、企业侧载插件。
> 路由：Electron/asar 主进程由 `electron-and-asar.md` 承担；浏览器扩展由 `browser-extension.md` 承担；纯协议复刻由 `protocol-plugin`（R24）承担。
> 目标：**激活/扩展点 → 命令/服务 → 文件/网络/进程 → 签名与更新链**，并给出可回退的最小可改单元。

## 1. 包体与安装来源

| 形态 | 识别 | 入口 |
|---|---|---|
| VSIX | ZIP；`extension/package.json`；可选 `extension.vsixmanifest`、`[Content_Types].xml` | `extension/package.json` 的 `main`/`browser` |
| JetBrains | ZIP/JAR；`META-INF/plugin.xml` | `<actions>`、`<extensions>`、`<applicationService>` |
| 已安装 VS Code 扩展 | `~/.vscode/extensions/<publisher>.<name>-<ver>/` | `package.json` + `extension.js` |
| JetBrains 已安装 | 配置目录 `plugins/<name>/lib/*.jar` | `META-INF/plugin.xml` |
| 企业侧载 | 策略/内部市场 | 记录签名者、允许列表、更新源 |

```bash
file ext.vsix
unzip -l ext.vsix | head -40
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path ext.vsix --json
python Tool/skill/plugin-targets/scripts/plugin-repro.py --path ext.vsix --out work/repro --json
sha256sum ext.vsix
```

- `.vsix` 是 ZIP；不要假设 `extension/package.json` 一定在根，先列目录。
- `.jar` 也是 ZIP；`META-INF/plugin.xml` 可能在多版本目录（`META-INF/xxx/plugin.xml`）。
- 已安装目录通常可直接读，且能拿到 `package.json` 的原始字段；比商店包更适合取证。

**判据**：容器/版本/来源/宿主版本四项齐全；入口清单能指到实际文件。

## 2. VSIX：激活事件与贡献点

```bash
jq '{name,version,publisher,main,browser,activationEvents,contributes,
     capabilities,engines,extensionDependencies,extensionKind}' \
  work/repro/unpack/extension/package.json
```

| 字段 | 含义 | 风险/用法 |
|---|---|---|
| `main` | Node 入口 JS | 从这里追 `activate()` |
| `browser` | Web 扩展入口 | 与 `main` 可能不同；Web 版能力受限 |
| `activationEvents` | 何时激活 | `*` 最宽；`onCommand`/`onLanguage` 最窄 |
| `contributes.commands` | 命令 ID | 与 `registerCommand` 对应 |
| `contributes.configuration` | 配置项 | 可能含端点/密钥/危险开关 |
| `contributes.languages`/`grammars` | 语言支持 | 语法文件可含注入/路径 |
| `capabilities.untrustedWorkspaces` | 受限工作区 | `supported:false` 表示禁用；`restrictedConfigurations` 列出受限项 |
| `capabilities.virtualWorkspaces` | 虚拟工作区 | 影响文件读写假设 |
| `extensionDependencies` | 依赖扩展 | 供应链面；依赖也可能被替换 |
| `engines.vscode` | 兼容版本 | 不匹配会静默不激活 |

```bash
grep -RInE "activate\(|registerCommand|workspace\.|window\.|secrets\.|globalState|env\.openExternal" \
  work/repro/unpack/extension --include='*.js' | head -80
grep -RInE "child_process|execFile|spawn|https?://|download|writeFile|workspace\.fs" \
  work/repro/unpack/extension --include='*.js' | head -80
```

检查点：

- 激活事件 → `registerCommand`/语言服务/视图 → 实际文件/网络/进程调用；缺一段写 `inferred`。
- `workspace.fs`/`vscode.workspace.findFiles` 的根目录与 glob 是否受工作区信任影响。
- `secrets`/`globalState`/`workspaceState` 的键与生命周期；是否存 token。
- `env.openExternal` 的 URL scheme；`child_process` 的命令与参数是否拼接用户输入。
- Webview 的 `enableScripts`/`localResourceRoots`/`postMessage`；是否加载远端内容。

**判据**：至少一条“激活事件 → 命令 → 文件/网络/进程”链有代码证据；受限工作区行为明确。

## 3. JetBrains：plugin.xml 与扩展点

```bash
unzip -l plugin.jar | head -40
unzip -p plugin.jar META-INF/plugin.xml
python Tool/skill/plugin-targets/scripts/plugin-repro.py --path plugin.jar --out work/repro --json
```

`plugin.xml` 关键节点：

- `<id>`/`<version>`/`<idea-version since-build until-build>`：身份与兼容范围。
- `<depends>`：平台/其他插件依赖；可选依赖与版本范围。
- `<actions>`：菜单/快捷键入口，`class` 指向实现；`<add-to-group>` 决定出现位置。
- `<extensions defaultExtensionNs="com.intellij">`：扩展点注册（ inspections、intentions、toolWindow、fileType 等）。
- `<applicationService>`/`<projectService>`：服务入口；`serviceImplementation` 指向类。
- `<listener>`/`<applicationListener>`：启动/项目打开时触发。
- `<resource-bundle>`/`messages/*.properties`：文案与配置键，可能暴露内部端点。

```bash
# 反编译（先确认授权）
jadx -d work/jadx plugin.jar
# 或 CFR
java -jar cfr.jar plugin.jar --outputdir work/cfr
```

- 先按 `plugin.xml` 的 class 在 jar 中找对应文件；找不到就是“入口不一致”，不要猜。
- Kotlin 协程/lambda 会生成 `$lambda$`/状态机；从顶层 Action/Service 进入，再顺 `invoke`/`suspend`。
- 检查文件/网络/凭据/执行：`VirtualFile`、`FileDocumentManager`、`HttpClient`、`CredentialStore`、`GeneralCommandLine`、`ProcessBuilder`。
- 扩展点回调可能在没有用户操作时触发（启动、索引、保存）；记录触发条件。

**判据**：扩展点/ Action / Service → 实现类 → 关键 API，至少一条链完整。

## 4. 签名、信任与更新链

| 形态 | 签名/信任 | 更新 |
|---|---|---|
| VSIX（市场） | 市场签名/发布者校验 | 市场自动更新；`extensionKind` 影响运行位置 |
| VSIX（侧载） | 可能无签名；企业策略可限制 | 手动/内部市场；记录来源 |
| JetBrains | 市场签名/插件仓库 | `updateUrl`/市场；IDE 版本约束 |
| 企业环境 | 允许列表/策略/私有市场 | 策略覆盖；谁能推送更新 |

- 记录“谁可以推送更新”和“更新是否校验签名”；这是持久化与供应链的关键。
- 受限工作区：`capabilities.untrustedWorkspaces.supported=false` 时，插件在受限工作区应禁用；若代码仍执行文件/进程操作，要单独标风险。
- 旁加载/开发者模式可能被商店版或策略覆盖；记录加载来源与版本。
- 改包后不签名可能不加载；两次失败按 `02-failure-criteria.md` 第 19 条停。

**判据**：安装来源、签名者、更新通道、卸载残留四项齐全；受限工作区行为可解释。

## 5. 最小可改单元

优先级：

1. 单个命令 handler（`registerCommand` 回调 / Action `actionPerformed`）。
2. 单个配置项（VS Code `contributes.configuration` / JetBrains `Configurable`）。
3. 单个语言服务/扩展点回调（补日志、改返回值）。
4. 单个网络/进程调用点（先加校验/日志，不直接改业务）。

改动前：备份扩展目录/jar、记录 `package.json`/`plugin.xml` 哈希、导出配置 baseline；改动后：重载 IDE/扩展，触发同一命令，对比日志/文件/网络。一次只改一个变量。

**判据**：改动点文件/类/函数可指认，回退方式明确，行为差异可重复。

## 6. IaC / CLI 插件与 Jupyter 扩展

- `kubectl` 插件：`PATH` 里的 `kubectl-foo` 被 `kubectl foo` 直接 exec，无沙箱，继承用户 `kubeconfig`（集群管理员上下文时即集群权限）；`kubectl plugin list` 会列出候选并给出同名/不可执行警告；krew 是分发链。
- `terraform` provider：独立二进制 + gRPC。`TF_PLUGIN_MAGIC_COOKIE` 握手，首行形如 `1|5|tcp|127.0.0.1:PORT|grpc`；二进制在 `.terraform/providers/<registry>/<ns>/<type>/<ver>/<os_arch>/`；`.terraform.lock.hcl` 的 `h1:`/`zh:` 哈希是完整性判据。
- Jupyter：`jupyter server extension list` / `jupyter nbextension list`；server extension 在 `jupyter_server_config.json` 的 `ServerApp.jpserver_extensions`（旧键 `nbserver_extensions`）中启用，入口 `_jupyter_server_extension_points()` → `_load_jupyter_server_extension(serverapp)`，用 `web_app.add_handlers` 注册静态/API 路由。
- 静态路由要查三处：有无 `@tornado.web.authenticated`、路径是否经 `url_path_join(base_url, ...)`、`static_url_prefix` 指向哪个目录。未加 `authenticated` 的路由在无 token 配置下即可被读。
- 三者共同点：插件与宿主同权限，沙箱责任在插件侧；供应链在索引/仓库（krew、registry、pip/npm）。

```bash
kubectl plugin list 2>&1 | head -20
find .terraform/providers -maxdepth 6 -name 'terraform-provider-*' | head
jupyter server extension list 2>&1 | grep -E 'enabled|OK'
grep -RInE 'jpserver_extensions|nbserver_extensions|add_handlers|url_path_join' ~/.jupyter 2>/dev/null | head
```

**判据**：`cli_plugin.path` 存在且 `cli_plugin.invoker` ∈ `{kubectl,terraform,jupyter}`；`iac.provider.socket`/`iac.lock_hashes` 可读；`jupyter.extensions[].enabled=true` 且 `jupyter.routes[].authenticated` 明确；`jupyter.static_route.prefix` 可指认。

**失败判据**：只见 `kubectl-foo` 文件、不知谁调用 → `inferred`；provider 握手行抓不到（`TF_LOG=TRACE` 也无）→ 只给二进制哈希与 lock；Jupyter 扩展 `enabled` 但服务未重启 → 写“配置已写、未生效”；路由 302 到 login → 记“需认证”，不写“未授权可读”。

## 7. 失败判据与边界

- `main` 指向的文件不存在，或只有 `activationEvents:*` 而无可观测入口 → 标“入口未闭环”，不写“启动即执行”。
- `engines.vscode`/`idea-version` 不匹配导致加载失败 → 换环境或只做静态，不改版本字段后宣称“已验证”。
- `plugin.xml` 的 class 在 jar 中找不到 → 标“入口不一致”，全量搜 class/多版本 `META-INF`。
- Kotlin/JS bundle 反编译不可读，且无 source map → 只给入口/字符串面，不把 `$lambda$` 当业务逻辑。
- 签名/白名单/受限工作区阻止加载 → 停，记录校验层（企业策略/市场签名）。
- 插件内私有协议 → 交 `protocol-plugin`（R24）。

> 关联：`references/01-criteria.md` 第 9–11 条、`references/02-failure-criteria.md` 第 9–12/19 条、`references/desktop-plugins.md`（原生桌面插件）。
