# Electron 与 asar 逆向

> 配套 `plugin-targets/SKILL.md` 的 §3.3。目标：**主进程 / preload / renderer 三层边界清楚，定位 IPC、原生模块与校验点**。
> 只对自有或明确授权的安装包操作；`asar` 不是加密，能列目录不等于能读字节码/原生模块。

## 1. 先判形态

| 形态 | 识别 | 入口 |
|---|---|---|
| `app.asar` | 文件头 4 字节为 `04 00 00 00`，后接 JSON 头 | `package.json` 的 `main` |
| `resources/app/` | 解包后的目录 | 同上 |
| `app.asar.unpacked/` | 与 asar 同级 | `.node`、原生依赖 |
| 安装包 | NSIS/Squirrel/MSI/dmg | `resources/`、`app-*`、`Update.exe` |
| bytenode | `*.jsc` + `bytenode` 依赖 | V8 字节码，不是普通 JS |

```bash
file app.asar
xxd -g1 -l 64 app.asar
npx asar list app.asar | head -80
npx asar extract app.asar work/asar
sha256sum app.asar work/asar/package.json
```

无 `npx asar` 时用标准库解析：前 8 字节含 header 长度，向后找 `{` 并 `json.loads` 头部；`files` 是树，叶子含 `size/offset/unpacked`。仓库脚本：

```bash
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path app.asar
```

**判据**：能列出入口、preload、所有 `.node`/`.jsc`、`app.asar.unpacked` 内容，并记录 asar 头部哈希与解包路径。

## 2. package.json 与三层边界

```bash
jq '{name,version,main,scripts,dependencies,devDependencies,
     build,electronVersion}' work/asar/package.json
```

- `main`：主进程入口，通常 `dist/main.js`/`main.js`；从这里追 `app.whenReady()`、`BrowserWindow`、`ipcMain`。
- `preload`：在 `BrowserWindow` 的 `webPreferences.preload` 指定；它是 renderer 与 Node 的桥。
- `contextIsolation`/`nodeIntegration`/`sandbox`/`webSecurity`：决定 renderer 能否直接拿 Node/跨域。
- `loadURL`/`loadFile`：看加载本地文件还是远端；`setWindowOpenHandler`、`will-navigate` 是导航边界。
- `dependencies` 里的 `electron-updater`、`electron-store`、`keytar`、`node-pty` 是更新/存储/凭据/命令执行的高价值点。

**判据**：每个 `webPreferences` 安全开关都能对应到实际窗口创建代码；能说明 renderer 是否能触达 Node。

## 3. IPC 与数据流

```bash
grep -RInE "ipcMain\.(handle|on)|ipcRenderer\.(invoke|send|sendSync)|contextBridge\.exposeInMainWorld" work/asar --include='*.js' | head -100
grep -RInE "shell\.openExternal|child_process|execFile|spawn|fs\.(read|write)|net\.|https?\.request" work/asar --include='*.js' | head -100
```

三条链必须画出来：

1. **renderer → preload → IPC channel → main handler → 文件/网络/命令**
2. **main → webContents.send → preload 回调 → renderer 状态/存储**
3. **main → 原生模块/更新器 → 本机文件/远端**

检查点：

- channel 名是否可被任意页面调用；`contextBridge` 暴露的是函数还是整个 `ipcRenderer`（后者等于放大攻击面）。
- handler 是否校验参数（路径穿越、命令拼接、URL scheme、权限）。
- `shell.openExternal` 是否限制 `https/http`；`file://`/自定义 scheme 可能触发本地执行。
- `webSecurity:false`、`allowRunningInsecureContent`、宽松 CSP 是否与远端内容共存。

**判据**：能指出一个具体 channel 的发送方、接收方、参数、副作用与校验缺失点。

## 4. asar 完整性 / 签名 / 更新链

- 先确认校验发生在**启动、加载、更新**哪一层：`app.asar` 哈希、`electron-updater` 签名、平台代码签名、企业白名单。
- `app.asar.unpacked` 里的原生模块通常不参与 asar 完整性；但可能受代码签名/路径校验。
- 更新源看 `app-update.yml`、`latest.yml`、`update_url`、`publish` 配置；记录“谁能推送更新”。
- 改包仅用于授权测试；改完不签名 = 可能不加载，别误判为代码错。

**判据**：能说明“改动哪个文件会触发哪层校验”，以及校验失败的可观察表现。

## 5. 原生模块 / 字节码

```bash
find work/asar -name '*.node' -o -name '*.jsc' -o -path '*app.asar.unpacked*' | sort
file work/asar/**/*.node 2>/dev/null
strings -n 8 work/asar/native.node | head -80
```

- `.node`：`dumpbin /exports`、`nm -D`、IDA/Ghidra 看导出与调用契约；JS 层只能看参数/返回值。
- `.jsc`：V8 字节码，需匹配 Electron/Node 版本；不要当源码读。记录版本与加载器（`bytenode`）。
- `.wasm`：看导入/导出表与字符串；必要时 wasm2wat。
- 加密/混淆 bundle：先找 source map、`webpack` chunk 名、字符串表；不要从压缩头部硬改。

**判据**：JS 与原生模块的边界（函数名、参数、返回、错误码）能对上，且版本匹配。

## 6. 最小可改单元

优先级从高到低：

1. **单个 IPC handler**：参数校验/权限判断/路径拼接处；改动小、可回退、效果可观察。
2. **preload 暴露面**：把“暴露整个 ipcRenderer”收窄为白名单函数（防御视角），或定位被暴露的特权调用。
3. **单个 renderer 模块**：业务逻辑/协议/存储键；需处理 bundle 压缩与 source map。
4. **原生模块**：只有当 JS 层无法解释行为时才下沉；改动风险最高。

改动前导出 baseline（文件哈希、行为录屏/日志），改动后重载并对比；一次只改一个变量。

**判据**：改动点能指到文件/函数/channel，回退方式明确，行为差异可重复。

## 7. 失败判据与边界

- asar 头部解析失败两次（版本/自定义容器）→ 停，只报容器与哈希，转 `strings`/安装目录，不硬猜偏移。
- 能列文件但 `main`/`preload` 均被字节码/加密覆盖，且无版本匹配工具 → 标“入口未读”，不把字符串当逻辑。
- IPC 链路只能看到一端（renderer 或 main 缺失）→ 标 `inferred`，不写“可任意调用”。
- 触发代码签名/更新器/反作弊校验 → 停，记录校验层，不反复改包。
- 不提供绕过商店签名、企业白名单或更新签名的方法；授权测试也要记录环境与回退。

> 关联：`references/desktop-plugins.md`（VSIX/JetBrains）、`references/unity-and-mods.md`（Unity Mod）。
