# 桌面插件逆向速查（VSIX / JetBrains / asar / Unity Mod）

> 配套 `plugin-targets/SKILL.md`。宿主与插件均需授权；改动只在副本。

## 1. VS Code / Cursor 扩展（`.vsix`）

```bash
unzip -q ext.vsix -d vsix/
find vsix -maxdepth 3 -type f | sort | head -60
jq . vsix/extension/package.json
```

关键字段：

| 字段 | 含义 | 风险/用法 |
|---|---|---|
| `main` | 入口 JS | 从这里追 |
| `browser` | Web 扩展入口 | 与 `main` 可能不同 |
| `activationEvents` | 何时激活 | `*` 最宽；`onCommand` 最窄 |
| `contributes.commands` | 命令 ID | 与 `registerCommand` 对应 |
| `contributes.configuration` | 配置项 | 可能含密钥/端点 |
| `capabilities.untrustedWorkspaces` | 受限工作区 | `supported:false` 表示禁用 |
| `extensionDependencies` | 依赖扩展 | 供应链面 |
| `engines.vscode` | 兼容版本 | 版本不匹配会静默不激活 |

```bash
# 入口与命令
grep -RInE "activate\(|registerCommand|workspace\.|window\.|secrets\.|globalState" vsix/extension --include='*.js' | head -80
# 网络与进程
grep -RInE "https?://|child_process|exec\(|spawn\(|download" vsix/extension --include='*.js' | head -80
```

- 扩展宿主是 Node/Electron；`require('child_process')`、`workspace.fs`、`env.openExternal` 是高价值点。
- 判据：激活事件 → 命令 → 文件/网络/进程，链路完整。

## 2. JetBrains 插件（`.jar`）

```bash
unzip -l plugin.jar | head -40
unzip -p plugin.jar META-INF/plugin.xml
unzip -p plugin.jar META-INF/pluginIcon.svg >/dev/null 2>&1
```

`plugin.xml`：

- `<id>`/`<version>`/`<idea-version since-build until-build>`：兼容范围。
- `<depends>`：平台/其他插件依赖。
- `<actions>`：菜单/快捷键入口，`class` 指向实现。
- `<extensions defaultExtensionNs="com.intellij">`：扩展点注册。
- `<applicationService>`/`<projectService>`：服务入口。

```bash
# 反编译（先确认授权）
jadx -d out plugin.jar
# 或 CFR
java -jar cfr.jar plugin.jar --outputdir out
```

- 判据：扩展点 → Action/Service → 关键逻辑（文件、网络、凭据、执行）。

## 3. Electron `asar`

```bash
npx asar list app.asar | head -100
npx asar extract app.asar app/
jq '{name,version,main,dependencies,scripts}' app/package.json
find app -name '*.node' -o -name '*.jsc' | head
```

- `main`：主进程入口；`preload`：预加载脚本；`renderer`：页面。
- `contextIsolation:false` 或 `nodeIntegration:true` 会让页面直接拿 Node 能力，风险最高。
- `ipcMain.handle`/`ipcRenderer.invoke`：列出通道与参数校验。
- `*.node`：`file`/`strings`/`nm`，必要时 IDA/Ghidra。
- `.jsc`（bytenode）：V8 字节码，不能当 JS 读；用对应 Node 版本加载/调试或找源 map。
- 判据：三层边界 + IPC 通道 + 原生模块清单。

```bash
grep -RInE "ipcMain\.(handle|on)|ipcRenderer\.(invoke|send)|shell\.openExternal|child_process" app --include='*.js' | head -80
```

## 4. Unity Mod（BepInEx / MelonLoader）

```bash
find . -maxdepth 3 -iname 'BepInEx' -o -iname 'MelonLoader' -o -iname 'winhttp.dll' | head
find BepInEx/plugins -name '*.dll' | head
ilspycmd BepInEx/plugins/Mod.dll -o mod-src
```

入口：

- BepInEx：`BaseUnityPlugin` 子类，`Awake()`/`Start()`/`Update()`；`[BepInPlugin]` 元数据。
- MelonLoader：`MelonMod` 子类，`OnInitializeMelon()`/`OnUpdate()`；`[assembly: MelonInfo]`。
- Harmony：`Harmony.Patch`/`[HarmonyPatch]`，`Prefix`/`Postfix`/`Transpiler`；目标是原游戏方法。

```bash
grep -RInE "HarmonyPatch|Harmony\.Patch|Prefix|Postfix|Transpiler|BaseUnityPlugin|MelonMod" mod-src | head -80
```

- 判据：插件入口 → patch 目标 → 修改的字段/返回值 → 可观察效果。
- 反作弊在线环境只读，不注入/不改内存；离线副本分析。

## 5. 输入法 / 驱动级插件

- 输入法：`*.ime`/`*.dll` 加载链、注册表 `Keyboard Layout`、与 `ctfmon`/`TextInputHost` 的关系。
- 驱动：`.sys` 的签名者、加载服务、`IoCreateDevice`/IOCTL、与用户态命名管道/共享内存。
- 先 `fltmc`/`sc query`/`driverquery` 列加载项；只读枚举，不加载未签名驱动。
- 判据：加载链 → 通信协议 → 可触发的用户态路径。

## 6. 签名与更新

| 形态 | 签名 | 更新 |
|---|---|---|
| VSIX | 商店签名/发布者 | `extensionKind`、自动更新 |
| JetBrains | 插件市场签名 | `updateUrl` |
| Electron | 安装包签名/公证 | `electron-updater`/自定义 |
| Unity Mod | 通常无签名 | 加载器/管理器覆盖 |
| 驱动 | EV/WHQL | Windows Update/厂商服务 |

- 记录“谁可以推送更新”和“更新是否校验签名”；这是持久化与供应链的关键。
- 判据：安装来源、签名者、更新通道、卸载残留四项齐全。

## 7. 工具降级

| 能力 | 首选 | 降级 |
|---|---|---|
| zip/VSIX | `unzip` | Python `zipfile`、7z |
| asar | `npx asar` | 解析 header（JSON 长度 + 偏移表） |
| .NET | `ilspycmd`/`dnSpy` | `monodis`、`r2 -A` |
| Java | `jadx`/CFR | `javap -c`、`procyon` |
| JS | DevTools | `prettier` + `source-map`、`js-reverse` |
| 清单初筛 | `seep_domain_audit(mode="plugin")` | 本文 grep + `seep_auto_triage` |

缺工具时用 `seep_tool_discover`、`tool-run.ps1`、`seep_tool_install`；安装需确认。

## 8. 报告检查

- [ ] 宿主版本与插件版本/兼容范围。
- [ ] 入口文件与激活/加载条件。
- [ ] 清单权限/扩展点逐条映射到代码。
- [ ] 数据流（读什么、发到哪、存哪里）。
- [ ] 最小可改单元与改前/改后差异。
- [ ] 签名/更新链与卸载残留。
