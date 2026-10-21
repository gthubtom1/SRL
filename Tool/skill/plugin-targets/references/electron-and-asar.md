# Electron / asar：主进程、preload 与原生模块

> 适用：`app.asar`/`resources/app/`、Electron 安装包、`app.asar.unpacked`、bytenode `.jsc`。
> 不适用：纯浏览器扩展（→ `browser-extension.md`）、Unity Mod（→ `unity-and-mods.md`）、纯协议复刻（→ `protocol-plugin` R24）。
> 目标：把 **主进程 / preload / renderer** 三层边界、IPC 通道、原生模块契约说清楚；asar 不是加密，能列目录不等于能读字节码。

## 1. 形态与容器

| 形态 | 识别 | 入口 |
|---|---|---|
| `app.asar` | 头 4 字节 `04 00 00 00`，后接 header 长度 + JSON 树 | `package.json` 的 `main` |
| `resources/app/` | 已解包目录 | 同上 |
| `app.asar.unpacked/` | 与 asar 同级的 `<name>.asar.unpacked/` | `.node`、原生依赖 |
| 安装包 | NSIS/Squirrel/MSI/dmg | `resources/`、`app-*`、`Update.exe` |
| bytenode | `*.jsc` + `bytenode` 依赖 | V8 字节码，不是普通 JS |

```bash
file app.asar
xxd -g1 -l 64 app.asar
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path app.asar --json
python Tool/skill/plugin-targets/scripts/plugin-repro.py --path app.asar --out work/repro --json
sha256sum app.asar
```

- asar 头：`uint32 4` + `uint32 header_size` + `uint32 json_len` + JSON；JSON 从偏移 12 开始，`data_offset` 再按 4 字节对齐。
- 条目 `files` 是树；叶子含 `size`/`offset`（字符串，需转 int）/`unpacked`/`link`。
- 无 `npx asar` 时用仓库脚本解析头与偏移；解包失败两次按 `02-failure-criteria.md` 第 13 条处理。

**判据**：能列出 `main`、`preload`、所有 `.node`/`.jsc`、`app.asar.unpacked` 条目，并记录 asar 头哈希/大小。

## 2. package.json 与三层边界

```bash
jq '{name,version,main,scripts,dependencies,devDependencies,build,electronVersion}' work/repro/unpack/package.json
```

- `main`：主进程入口；从这里追 `app.whenReady()`、`BrowserWindow`、`ipcMain`、`app.on('web-contents-created')`。
- `preload`：`BrowserWindow.webPreferences.preload` 指定；renderer 与 Node 的桥。
- `contextIsolation`/`nodeIntegration`/`sandbox`/`webSecurity`：决定 renderer 能否直接拿 Node/跨域。
- `loadURL`/`loadFile`：本地还是远端；`setWindowOpenHandler`、`will-navigate`、`will-attach-webview` 是导航边界。
- `dependencies`：`electron-updater`、`electron-store`、`keytar`、`node-pty`、`sqlite3` 是更新/存储/凭据/命令执行/数据的高价值点。

```bash
grep -RInE "webPreferences|contextIsolation|nodeIntegration|sandbox|webSecurity|preload" \
  work/repro/unpack --include='*.js' | head -60
```

**判据**：每个 `webPreferences` 安全开关都能对应到实际窗口创建代码；能说明 renderer 是否能触达 Node/文件/网络。

## 3. 主进程：窗口、导航与权限

主进程是 Electron 的“特权层”，常见入口与风险：

| 入口 | 作用 | 风险点 |
|---|---|---|
| `app.whenReady()` | 启动窗口/服务 | 启动即注册全局 handler |
| `BrowserWindow` | 创建窗口 | `preload`、`nodeIntegration`、`sandbox`、`webSecurity` |
| `webContents.setWindowOpenHandler` | 新窗口策略 | 返回 `allow` 且未校验 URL |
| `will-navigate` / `will-redirect` | 导航拦截 | 未限制远端/自定义 scheme |
| `session.setPermissionRequestHandler` | 摄像头/麦克风/通知 | 全部 allow |
| `protocol.register*` | 自定义 scheme | `file://` 映射到任意路径 |
| `webContents.executeJavaScript` | 主进程注入 | 拼接用户输入 |
| `shell.openExternal` | 打开外部程序/URL | `file://`/自定义 scheme 可触发本地执行 |
| `autoUpdater`/`electron-updater` | 更新 | 更新源/签名校验 |

**判据**：能指出一个具体窗口的创建参数、导航策略、权限 handler，以及它们是否与远端内容共存。

## 4. IPC 与数据流

```bash
grep -RInE "ipcMain\.(handle|on|once)|ipcRenderer\.(invoke|send|sendSync|on)|contextBridge\.exposeInMainWorld" \
  work/repro/unpack --include='*.js' | head -100
grep -RInE "shell\.openExternal|child_process|execFile|spawn|fs\.(read|write|readdir)|net\.|https?\.request" \
  work/repro/unpack --include='*.js' | head -100
```

三条链：

1. **renderer → preload → channel → main handler → 文件/网络/命令**
2. **main → `webContents.send` → preload 回调 → renderer 状态/存储**
3. **main → 原生模块/更新器 → 本机文件/远端**

检查点：

- channel 名是否可被任意页面调用；`contextBridge` 暴露的是白名单函数还是整个 `ipcRenderer`（后者等于放大攻击面）。
- handler 是否校验参数：路径穿越、命令拼接、URL scheme、权限、大小/类型。
- `shell.openExternal` 是否只允许 `https/http`；`file://`/`ms-*`/自定义 scheme 要单独确认。
- `webSecurity:false`、`allowRunningInsecureContent`、宽松 CSP 是否与远端内容共存。
- preload 是否把 `ipcRenderer` 原样暴露（`exposeInMainWorld('ipc', ipcRenderer)`）——这是常见的高危写法。

**判据**：能指出一个具体 channel 的发送方、接收方、参数、副作用与校验缺失点；缺一端写 `inferred`。

## 5. 原生模块与字节码

```bash
find work/repro/unpack -name '*.node' -o -name '*.jsc' -o -name '*.wasm' | sort
file work/repro/unpack/**/*.node 2>/dev/null
strings -n 8 work/repro/unpack/native.node | head -80
```

- `.node`：`dumpbin /exports`、`nm -D`、IDA/Ghidra 看导出与调用契约；JS 层只能看参数/返回值/错误码。
- `.jsc`：V8 字节码，需匹配 Electron/Node 版本；不要当源码读。记录版本、`bytenode` 加载器、是否有 source map。
- `.wasm`：看导入/导出表与字符串；必要时 wasm2wat。
- 加密/混淆 bundle：先找 source map、webpack chunk 名、字符串表；不要从压缩头部硬改。

**判据**：JS 与原生模块的边界（函数名、参数、返回、错误码）能对上，且版本匹配。

## 6. asar 完整性、签名与更新链

- 确认校验发生在**启动、加载、更新**哪一层：asar 哈希、`electron-updater` 签名、平台代码签名、企业白名单。
- `app.asar.unpacked` 的原生模块通常不参与 asar 完整性，但可能受代码签名/路径校验。
- 更新源看 `app-update.yml`、`latest.yml`、`update_url`、`publish` 配置；记录“谁能推送更新”。
- 改包仅用于授权测试；改完不签名 = 可能不加载，别误判为代码错。

**判据**：能说明“改动哪个文件会触发哪层校验”，以及校验失败的可观察表现。

## 7. 最小可改单元

优先级从高到低：

1. **单个 IPC handler**：参数校验/权限判断/路径拼接处；改动小、可回退、效果可观察。
2. **preload 暴露面**：把“暴露整个 ipcRenderer”收窄为白名单函数（防御视角），或定位被暴露的特权调用。
3. **单个 renderer 模块**：业务逻辑/协议/存储键；需处理 bundle 压缩与 source map。
4. **原生模块**：只有 JS 层无法解释行为时才下沉；改动风险最高。

改动前导出 baseline（文件哈希、窗口/日志/网络），改动后重载并对比；一次只改一个变量。

**判据**：改动点能指到文件/函数/channel，回退方式明确，行为差异可重复。

## 8. 失败判据与边界

- asar 头解析失败两次（版本/自定义容器）→ 停，只报容器与哈希，转 `strings`/安装目录，不硬猜偏移。
- 能列文件但 `main`/`preload` 均被字节码/加密覆盖，且无版本匹配工具 → 标“入口未读”，不把字符串当逻辑。
- IPC 链路只能看到一端（renderer 或 main 缺失）→ 标 `inferred`，不写“可任意调用”。
- 触发代码签名/更新器/反作弊校验 → 停，记录校验层，不反复改包。
- 不提供绕过商店签名、企业白名单或更新签名的方法；授权测试也要记录环境与回退。
- 远端协议/帧格式交 `protocol-plugin`（R24）。

## 9. ASAR integrity 绕过：fuse 组合与旁路验收

Electron 的 asar 完整性由 fuse 决定，不是 asar 自己声明。`embeddedAsarIntegrityValidation` 开启后，主进程核对 `resources/app.asar` 头哈希/内嵌 `ElectronAsarIntegrity` 记录；`onlyLoadAppFromAsar` 进一步禁止 `resources/app/` 目录回退。

```bash
npx @electron/fuses read --app ./App.exe                 # 读 fuse 线；rc=0 才有结论
strings -a ./App.exe | grep -iE 'asar|integrity' | head
xxd -g1 -l 64 resources/app.asar
sha256sum resources/app.asar
ls -la resources/app resources/app.asar.unpacked 2>/dev/null
```

- 先记三元：`asar_integrity_ok`（头哈希与 fuse/内嵌记录一致）、`load_from_asar_only`（是否只允许 asar、目录回退是否被封）、`bypass_path`（`none|unpacked|run-as-node|inspect|dir-fallback`）。
- 修改 `resources/app.asar` 或 `app.asar.unpacked` 后，先观察是否被完整性校验拒绝；`.unpacked` 通常不在 asar 头哈希内，但仍可能被代码签名/路径校验覆盖。
- `ELECTRON_RUN_AS_NODE=1 ./App.exe -e "..."` 绕过 app 主进程，`--inspect` 在已启动的主进程上附加调试；两条路都受 `runAsNode`/调试开关与授权环境约束。
- 只在自有/授权副本上验证旁路；记录环境变量、fuse 值、实际加载路径与拒绝日志，不把“能列文件”当成“能改逻辑”。
- 出处：Electron GHSA-vmqv-hx8q-j7mg（2025-09 修复）；2026 年仍可能有旧版未升级。

**判据**：三个字段齐全，且能指到 fuse 值、asar 头哈希与实际加载文件。
**失败判据**：完整性校验阻止加载两次 → 停，记校验层与哈希；fuse 读不到 → 只报版本/字符串并标 `blocked_at=integrity`；不绕过签名/白名单。

## 10. V8 字节码（bytenode .jsc）

`.jsc` 是 V8 字节码/代码缓存，不是 JS；先用头与加载器确认，再谈反编译。

```bash
find work/repro -name '*.jsc' -printf '%p %s\n'
xxd -g1 -l 64 main.jsc
grep -RInE 'bytenode|\.jsc|runBytecode|compileFile' work/repro/unpack --include='*.js'
node -p "process.versions.v8 + ' / ' + process.versions.electron"
strings -n 8 main.jsc | grep -E 'v8::internal::Script|bytenode|V8 version' | head
```

- 头：`v8::internal::Script`/`bytenode` 标识、`V8 version` 或 code-cache 魔数；不同 V8 版本头布局不同，先对齐 Electron/Node/V8 三元组。
- `v8_bytecode`：确认 `.jsc` 且不是普通 JS/source map；记录加载器（`bytenode`/`vm.Script`/自定义）与入口文件名。
- `v8_version_match`：用样本自带 Electron 或同版本 Node 的 V8；版本不符先报不匹配，不硬喂给当前 Node。
- `decompile_ok`：仅在版本对齐、有反汇编器/改版 V8 的授权环境里尝试；输出是反汇编/伪代码，不等于原始 JS；保留 rc、工具版本与失败点。
- 路线：定位字节码版本 → 同版本 V8 反汇编器/改版 V8 → 导出指令流与常量池 → 对照 `Script` 头/函数表；跨大版本通常不可行。
- 出处：rce.moe 2025-01、SE 30434（V8 字节码版本与反汇编边界）。

**判据**：`v8_bytecode`、`v8_version_match`、`decompile_ok` 可按命令复算；至少给出入口/函数/常量之一。
**失败判据**：版本不匹配或反汇编两次失败 → 标 `decompile_ok=false`，只给字符串/导出面/加载器；不改 V8 版本硬解、不把反汇编当源码。

## 11. Electron IPC 越权验收

IPC 验收看“谁能调用 → 参数是否校验 → 落到哪个 sink”，不看 channel 名字是否可疑。

```bash
python Tool/skill/plugin-targets/scripts/plugin-repro.py --path app.asar --out work/repro --json
python Tool/skill/plugin-targets/scripts/plugin-accept.py --root . --case Tool/cases/plugin04 --json
grep -RInE 'ipcMain\.(handle|on)|ipcRenderer\.(invoke|send)|contextBridge|openExternal' work/repro/unpack --include='*.js'
grep -RInE 'nodeIntegration|contextIsolation|sandbox|webPreferences|preload' work/repro/unpack --include='*.js'
```

- `ipc_sender_checked`：handler 是否校验 `event.senderFrame.url`/`sender.id`/窗口来源/权限；只校验参数不校验发送方不算。
- `openexternal_scheme`：`shell.openExternal` 的 URL 是否白名单到 `https/http`；`file:`、`ms-*`、自定义 scheme 单列。
- `webpref_unsafe`：`nodeIntegration:true`、`contextIsolation:false`、`sandbox:false`、`webSecurity:false` 与远端内容共存时记风险；单机本地页可降级。
- `preload_exposed`：`contextBridge.exposeInMainWorld('x', ipcRenderer)` 原样暴露 vs 白名单函数；只暴露函数名不够，要看参数是否直达 sink。

**判据**：四个字段各有 file/line 或明确 `unverified`；至少一条 channel 能画到 sink。
**失败判据**：只有 preload 或只有 main 一端 → 标 `inferred`；无法证明 sender 可被外部页面触达 → 不写“越权/RCE”；签名/白名单阻止动态验证 → 转静态。

> 关联：`references/04-walkthrough-chrome-extension.md` 的通用取证流程、`references/02-failure-criteria.md` 第 13–15 条。
