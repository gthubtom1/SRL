# VSIX / JetBrains 插件：激活点、扩展点与签名

## 入口信号

- `.vsix` 是 ZIP，含 `extension/package.json`；已安装目录在 `~/.vscode/extensions/`。
- `.jar` 含 `META-INF/plugin.xml`；JetBrains 插件目录在 IDE 配置的 `plugins/`。
- `package.json` 的 `activationEvents`/`contributes`；`plugin.xml` 的 `actions`/`extensions`。
- 侧载/企业策略/市场签名信息。

## 可复制命令

```bash
# VSIX
unzip -l ext.vsix | head -40
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --path ext.vsix --json
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py --path ext.vsix --out work/repro --json
jq '{main,activationEvents,contributes,capabilities,engines,extensionDependencies}' \
  work/repro/unpack/extension/package.json

# JetBrains
unzip -p plugin.jar META-INF/plugin.xml
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py --path plugin.jar --out work/repro --json
jadx -d work/jadx plugin.jar    # 或 CFR
```

## VSIX 字段速查

| 字段 | 看什么 | 风险 |
|---|---|---|
| `main`/`browser` | 入口 | 文件不存在 = 入口未闭环 |
| `activationEvents` | `*` 最宽、`onCommand` 最窄 | 宽激活 + 启动逻辑 |
| `contributes.commands` | 命令 ID | 与 `registerCommand` 对应 |
| `contributes.configuration` | 配置项 | 端点/密钥/危险开关 |
| `capabilities.untrustedWorkspaces` | 受限工作区 | `supported:false` 应禁用 |
| `engines.vscode` | 兼容版本 | 不匹配静默不激活 |
| `extensionDependencies` | 依赖 | 供应链面 |

## JetBrains 节点速查

| 节点 | 含义 |
|---|---|
| `<id>/<version>/<idea-version>` | 身份与兼容范围 |
| `<depends>` | 平台/插件依赖、版本范围 |
| `<actions>` | 菜单/快捷键入口，`class` 指实现 |
| `<extensions>` | 扩展点注册（inspection/intention/toolWindow…） |
| `<applicationService>/<projectService>` | 服务入口 |
| `<listener>/<applicationListener>` | 启动/项目打开触发 |

## 确认判据

- VSIX：激活事件 → 命令/语言服务 → 文件/网络/进程，至少一条链有 file/line。
- JetBrains：`plugin.xml` 的 class 在 jar 中存在 → 扩展点/Action/Service → 关键 API。
- 签名/更新链：安装来源、签名者、更新通道、受限工作区四项齐全。
- 最小可改单元：单个命令/配置/回调可指认，有回退。

## 失败判据

- `main` 不存在或只有 `activationEvents:*` → 标“入口未闭环”。
- `engines.vscode`/`idea-version` 不匹配 → 换环境或只做静态。
- `plugin.xml` class 找不到 → 标“入口不一致”，全量搜 class/多版本 `META-INF`。
- bundle 无 source map 且反编译不可读 → 只给入口/字符串面。
- 签名/白名单/受限工作区阻止加载 → 停，记录校验层。

## 边界

- 不在真实工作区执行未验证插件；用隔离 IDE/测试项目。
- 不提供绕过市场签名/企业白名单的方法。
- 插件内协议交 `protocol-plugin`（R24）。

> 关联：`Tool/skill/_pending/plugin-targets/references/ide-plugins.md`、`Tool/cases/plugin05/case.json`。
