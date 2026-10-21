# asar 与 Mod 加载器：Electron / BepInEx / MelonLoader

> 目标：**主进程/preload/renderer** 或 **加载器/插件类/patch 目标** 的边界清楚，能指到最小可改单元。

## 1. Electron asar 结构

```bash
file app.asar
xxd -g1 -l 64 app.asar
npx asar list app.asar | head -80
npx asar extract app.asar app/
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path app.asar --json
```

- 头 4 字节 `04 00 00 00`；后接 header 长度与 JSON 树。
- `files` 是树，叶子有 `size/offset/unpacked/link`。
- 无 `npx asar` 时用脚本解析头并递归列目录；不解包也能看结构。

**判据**：入口、preload、`.node`/`.jsc`、`app.asar.unpacked` 全部列出。

## 2. 三层边界

```bash
jq '{name,version,main,scripts,dependencies}' app/package.json
grep -RInE "ipcMain\.(handle|on)|ipcRenderer\.(invoke|send)|contextBridge" app/ --include='*.js'
grep -RInE "nodeIntegration|contextIsolation|sandbox|webSecurity" app/ --include='*.js'
```

| 层 | 关键点 | 风险 |
|---|---|---|
| main | `app.whenReady`、`BrowserWindow`、`ipcMain` | 参数校验、路径拼接、命令执行 |
| preload | `contextBridge`、暴露的函数 | 暴露整个 ipcRenderer = 放大攻击面 |
| renderer | bundle、webview、远端加载 | `nodeIntegration:true` + 远端内容 |

- `shell.openExternal` 限制 `https/http`；`file://`/自定义 scheme 要单独看。
- `webSecurity:false`、宽松 CSP、`allowRunningInsecureContent` 与远端内容叠加时优先审。
- `.node` 用 `file`/`strings`/IDA；`.jsc` 是 V8 字节码，需匹配 Electron 版本。

**判据**：能指出一个 channel 的发送方、接收方、参数、副作用与校验缺失点。

## 3. 完整性/更新链

- 校验发生在启动、加载还是更新？看 `app-update.yml`、`latest.yml`、`electron-updater`、平台签名。
- `app.asar.unpacked` 的原生模块通常不参与 asar 完整性，但可能受代码签名/路径校验。
- 改包仅授权测试；不签名可能不加载，别误判代码错。

**判据**：说明“改哪个文件触发哪层校验”及失败表现。

## 4. BepInEx / MelonLoader

```bash
find . -maxdepth 4 \( -iname 'BepInEx' -o -iname 'MelonLoader' \
  -o -iname 'doorstop_config.ini' -o -iname 'LogOutput.log' -o -iname 'Latest.log' \) -print
find BepInEx/plugins MelonLoader/Mods -maxdepth 2 -type f | sort
```

- BepInEx：`winhttp.dll`/doorstop、`BepInEx/core`、`plugins/*.dll`、`LogOutput.log`。
- MelonLoader：`MelonLoader/`、`Mods/`、`UserData/`、`Latest.log`。
- 先确认插件真的加载：日志有 guid/版本/Chainloader 输出。
- 运行时：Mono（`Assembly-CSharp.dll`）vs IL2CPP（`GameAssembly.dll` + `global-metadata.dat`）。

**判据**：加载器、注入方式、插件目录、日志、运行时五项齐全。

## 5. Harmony patch

```bash
ilspycmd Mod.dll -o mod-src/
grep -RInE "Harmony(Patch|Prefix|Postfix|Transpiler)|BepInPlugin|MelonMod" mod-src/ | head -60
Il2CppDumper GameAssembly.dll global-metadata.dat out/
```

- 从 `[HarmonyPatch(typeof(Target), nameof(Target.Method))]` 反推目标。
- 优先 `Prefix`（改参数/跳过）或 `Postfix`（改返回值）；`Transpiler` 改 IL，风险最高。
- IL2CPP 的 `dump.cs` 是结构恢复；字段偏移再用 IDA/Ghidra 对二进制验证。

**判据**：插件类 → patch 目标 → 修改字段/返回值 → 可观察效果。

## 6. 失败判据

- asar 头解析失败两次 → 停，只报容器/哈希，转 strings/安装目录。
- main/preload 全被字节码/加密覆盖且无版本匹配工具 → 标“入口未读”。
- 插件日志未加载，两次修正路径/版本仍失败 → 停，报加载链。
- 目标方法找不到/被内联/混淆 → 标“patch 目标未定”，不猜方法名。
- 在线反作弊触发 → 立即停，只做外部观测或离线副本。
