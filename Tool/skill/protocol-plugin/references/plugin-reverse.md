# 插件 / 扩展 / Mod 逆向参考（历史交叉引用）

> **归属已调整**：R25 插件/扩展/Mod 的正式技能与判据见 `plugin-targets/SKILL.md`；本文仅作为 protocol-plugin 旧版交叉资料保留，不再作为 R25 入口。
> 判据：**入口 + 关键逻辑 + 数据来源 + 最小可改单元**。
> 先读清单与注册点，再反编译；不要从打包产物头部硬改。总流程与边界见 `../SKILL.md`。

## 0. 包型判读与通用步骤

| 形态 | 容器 | 入口清单 | 运行时 | 最小单元 |
|---|---|---|---|---|
| Chrome/Edge MV3 | `.crx` = CRX3 头 + ZIP | `manifest.json` | 扩展进程 / SW / content script | 消息处理、注入点 |
| VS Code | `.vsix` = ZIP | `extension/package.json` | Extension Host (Node) | command / activation |
| JetBrains | `.jar` / `.zip` | `META-INF/plugin.xml` | JVM / IDE 平台 | Action / extension |
| Electron | `app.asar` | `package.json` | main / preload / renderer | IPC / 原生模块 |
| 游戏 Mod | BepInEx/MelonLoader | `plugins/*.dll`、`Mods/*.dll` | Unity Mono / Il2Cpp | Harmony patch |

通用步骤：`file` 判型 → 列表（`unzip -l` / `jar tf` / `npx asar list`）→ 读入口清单 → 找注册点 → 反编译关键文件 → 在日志/调试器里验证加载 → 定最小单元。

## 1. Chrome / Edge MV3（`.crx`）

### 1.1 解包

```bash
unzip extension.crx -d ext/          # 多数 CRX3 可直接解
# 若 unzip 失败：跳过 Cr24 头（magic 4B + version 4B + header_len 4B）
python - <<'PY'
import struct, zipfile, io
b = open("extension.crx","rb").read()
assert b[:4] == b"Cr24"
ver, hlen = struct.unpack("<II", b[4:12])
zipfile.ZipFile(io.BytesIO(b[12+hlen:])).extractall("ext")
PY
```

### 1.2 清单检查

| 字段 | 看什么 |
|---|---|
| `manifest_version` | 2 还是 3；MV2 的 background page 与 MV3 SW 不同 |
| `permissions` / `host_permissions` | 能访问哪些 API/域名 |
| `background.service_worker` / `background.scripts` | 后台入口文件 |
| `content_scripts` | `matches`、`js`、`run_at`、`world`（MAIN/ISOLATED） |
| `web_accessible_resources` | 页面可加载的资源 |
| `externally_connectable` | 哪些站点可发消息 |
| `nativeMessaging` | 是否有本地宿主通道 |
| `content_security_policy` | 是否限制 eval/远程脚本 |

### 1.3 定位关键逻辑

- 从 `chrome.runtime.onMessage` / `sendMessage` 找消息协议与 handler。
- 从 `chrome.webRequest`、`declarativeNetRequest`、`chrome.storage`、`fetch`/`XMLHttpRequest` 找数据流。
- content script 在隔离世界，页面变量不可见；主世界逻辑看 `world: "MAIN"` 或动态注入的 `<script>`。
- Service Worker 无 DOM，可能被事件唤醒；在 `chrome://extensions` 打开开发者模式 → “检查视图 service worker”。
- 加载已解包扩展做动态验证；注意商店签名/策略校验，改包仅用于授权测试环境。
- **native messaging**：扩展只是通道；读宿主 manifest 的 `allowed_origins`、`path`、`type`，再分析宿主程序。宿主可能是 Python/Node/原生二进制。

### 1.4 数据来源与最小单元

数据来源优先级：`chrome.storage` → 扩展内置 JSON/规则 → 远程 API → native host 返回值。
最小可改单元：一个 `onMessage` handler、一个 content script 注入函数、或 native host 的一个命令分支。先改返回值验证链路，再动算法。

## 2. VS Code 扩展（`.vsix`）

```bash
unzip extension.vsix -d vsix/
# 结构通常为 extension/package.json、extension/extension.js、extension/node_modules/
```

- 入口：`package.json` 的 `main`（常为 `./extension.js`）；激活：`activationEvents`（`onCommand`、`onLanguage`、`*` 等）。
- 功能注册：`contributes.commands` / `menus` / `keybindings` / `configuration`；从 command id 搜 `registerCommand`。
- `extension.js` 常被 esbuild/webpack 打包/压缩；先搜 command id、URL、错误文案，再回到源模块边界。
- Extension Host 是 Node 环境：文件、网络、`child_process`、`vscode.env`、SecretStorage 都可能承载关键逻辑。
- Webview 只是 UI；消息走 `postMessage`，真正数据在扩展侧。最小单元通常是一个 command handler 或其 service。

## 3. JetBrains 插件（`.jar`）

```bash
jar tf plugin.jar | head -100
unzip plugin.jar -d plugin/
# 读 META-INF/plugin.xml：actions / extensions / applicationService / depends / lib
```

- 反编译：jadx 可直接读 jar；也可用 CFR / Fernflower / IDE 自带 decompiler。`javap -c -p` 用于快速看字节码。
- 入口：`<actions>` 的 `actionPerformed`、`<extensions>` 的实现类、启动/项目监听器。
- Java/Kotlin 混合时注意 `@JvmStatic`、协程、lambda 与混淆名；先按字符串/UI 文案反查类。
- 资源：`messages/*.properties`、`resources/`、`lib/` 内的依赖 jar；协议地址、许可证文案常在这里。
- 最小单元：单个 Action/Service 类或扩展点注册；改动后通过 IDE 的 “Install Plugin from Disk” 验证。

## 4. Electron（`asar`）

```bash
npx asar list app.asar
npx asar extract app.asar app/
npx asar extract-file app.asar package.json
```

- 入口看 `package.json` 的 `main`（main 进程）；`preload` 是隔离边界；renderer 是前端 bundle。
- 安全/能力面：`contextIsolation`、`nodeIntegration`、`sandbox`、`ipcMain`/`ipcRenderer` channel、`shell.openExternal`。
- `.node` 是原生模块：JS 只暴露调用契约，导出函数用 `dumpbin /exports`、`nm -D` 或 IDA/Ghidra 看。
- 打包器可能校验 asar 完整性/签名：先确认校验发生在启动、加载、更新还是服务端；不要盲目重打包。
- 动态验证：`--inspect`/`--inspect-brk` 调 main，DevTools 调 renderer；先看 IPC 消息再改逻辑。
- 最小单元：main 的 IPC handler、preload 暴露面、renderer 的单一 bundle 模块。

## 5. 游戏 Mod（BepInEx / MelonLoader）

### 5.1 BepInEx

- 目录：`winhttp.dll`（doorstop）、`BepInEx/core`、`BepInEx/plugins`、`BepInEx/config`。
- 日志：`BepInEx/LogOutput.log`；先确认插件被 chainloader 加载、目标程序集已解析。
- 插件是托管 DLL（.NET）；用 dnSpy/ILSpy 打开，找 `BaseUnityPlugin`、`Awake`、`Update`、Harmony patch 类。

### 5.2 MelonLoader 与 Unity

- 目录：`MelonLoader/`、`Mods/`、`UserData/`；日志 `MelonLoader/Latest.log`。
- 先判 **Mono 还是 Il2Cpp**：
  - Mono：`GameName_Data/Managed/Assembly-CSharp.dll` 可直接用 dnSpy/ILSpy。
  - Il2Cpp：`GameAssembly.dll` + `global-metadata.dat`；先 `Il2CppDumper` 产出 `dump.cs`/`il2cpp.h`，再用 IDA 对照。
- 从入口场景、按钮事件、`Update`、配置读取反推到业务方法；用日志/断点确认调用时机。

### 5.3 Harmony patch

```csharp
[HarmonyPatch(typeof(TargetClass), nameof(TargetClass.TargetMethod))]
static class Patch {
    static void Prefix(ref int value) { /* 改参数，或 return false 跳过原方法 */ }
    static void Postfix(ref int __result) { /* 改返回值 */ }
    // Transpiler 改 IL；只在 Prefix/Postfix 不够时使用
}
```

- `Prefix` 改参数/跳过原逻辑，`Postfix` 改返回值，`Transpiler` 改 IL。
- 最小单元 = 一个目标方法 + 一个 patch 类；保留原方法可回退。
- 先验证“方法被调用”（日志/计数器），再改行为；注意反作弊/完整性校验与联机同步。

## 6. 证据与最小可改单元

每个目标至少产出：

| 项 | 内容 |
|---|---|
| 入口 | 文件、清单字段/注册点、运行时加载路径、日志证据 |
| 关键逻辑 | 函数/类/模块、输入输出、副作用、调用链 |
| 数据来源 | 配置、网络、存储、原生库、游戏对象，至少追一层 |
| 最小单元 | 文件/类/方法级改动点、依赖、回退方式 |
| 验证 | 重载/重启后行为变化符合预期，原功能未被无关破坏 |

## 7. 常见坑

| 坑 | 处理 |
|---|---|
| CRX 签名/商店策略 | 先确认校验层；改包只在授权测试环境，必要时用“加载已解包”而非替换商店版 |
| MV3 SW 休眠 | 事件唤醒导致断点丢失；用 `chrome://serviceworker-internals` 或日志确认生命周期 |
| VSIX 市场校验/依赖 | `node_modules` 可能未打包；先看 `extension/` 实际内容与 `main` 是否存在 |
| JetBrains 类加载 | 依赖 `lib/` 版本冲突会导致类找不到；先看 `idea.log` 与 `plugin.xml` 的 `depends` |
| asar 完整性/签名 | 校验可能在 main 启动前；先定位校验函数，再决定改 asar 还是改加载器 |
| `.node` ABI | Electron/Node 版本不匹配会加载失败；不要只看 JS 报错 |
| Unity Il2Cpp | 不能直接用 dnSpy 看 `GameAssembly.dll`；先 Il2CppDumper 恢复符号 |
| Harmony 未生效 | 目标方法被内联/泛型/重载；确认签名、命名空间与 patch 日志 |
| 反作弊/联机 | 客户端 patch 可能被判违规；优先离线/私服/授权环境验证 |

## 8. 边界与交接

- 网页/前端 JS 的签名、补环境、浏览器调试 → `mcp-js-reverse-playbook`。
- 客户端授权/许可证/门禁/版本迁移 → `01-gate-bypass` ~ `05-backend-rebuild`。
- 壳/反调试/内存 dump → `unpack-loop`；原生算法与反编译 → `ida-reverse` / `reverse-engineering`。
- 本技能只做“定位入口/逻辑/来源 + 最小可改单元”，不重复上述技能的方法体系。
