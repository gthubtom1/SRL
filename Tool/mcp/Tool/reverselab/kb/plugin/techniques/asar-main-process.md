# asar 与 Electron 主进程：入口、IPC、原生模块

## 入口信号

- 文件头 4 字节 `04 00 00 00`；`package.json` 有 `main`/`build.preload`。
- 目录里有 `app.asar.unpacked/`、`*.node`、`*.jsc`。
- 安装包 `resources/app.asar` 或 `resources/app/`。
- 进程列表出现 Electron 应用；崩溃日志/更新器配置可辅助确认版本。

## 可复制命令

```bash
file app.asar
xxd -g1 -l 64 app.asar
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path app.asar --json
python Tool/skill/plugin-targets/scripts/plugin-repro.py --path app.asar --out work/repro --json

jq '{name,version,main,build,scripts,dependencies,devDependencies}' work/repro/unpack/package.json
grep -RInE "ipcMain\.(handle|on)|ipcRenderer\.(invoke|send)|contextBridge|shell\.openExternal|child_process" \
  work/repro/unpack --include='*.js' | head -100
find work/repro/unpack -name '*.node' -o -name '*.jsc' -o -name '*.wasm' | sort
```

## asar 头速查

| 偏移 | 内容 |
|---|---|
| 0 | `04 00 00 00` |
| 4 | header size（little-endian uint32） |
| 8 | JSON 长度（部分实现） |
| 12 | header JSON（`{"files":{...}}`） |
| data_offset | 头后按 4 字节对齐 |

叶子字段：`size`、`offset`（字符串）、`unpacked`、`link`。`offset` 相对 `data_offset`；转 int 再 seek。

## 三层边界

| 层 | 文件 | 关键点 |
|---|---|---|
| main | `main.js`/`dist/main.js` | `app.whenReady`、`BrowserWindow`、`ipcMain`、导航/权限 handler |
| preload | `preload.js` | `contextBridge.exposeInMainWorld`；暴露函数还是整个 `ipcRenderer` |
| renderer | `renderer.js`/bundle | 页面/WebView；`contextIsolation`/`nodeIntegration`/`sandbox` |

## 确认判据

- `main`、`preload`、`package.json` 三个文件都存在且能指认。
- 至少一条 `renderer → preload → channel → ipcMain handler → sink` 链路有 file/line。
- `webPreferences` 的安全开关值与窗口创建代码一致。
- `.node`/`.jsc`/`app.asar.unpacked` 清单完整，版本信息记录。

## 失败判据

- asar 头解析失败两次 → 只报容器与哈希，转 `strings`/安装目录，不猜偏移。
- `main`/`preload` 全被 `.jsc`/加密覆盖且无匹配版本 → 标“入口未读”。
- IPC 只有一端 → 标 `inferred`，不写“可任意调用”。
- 签名/更新器阻止加载 → 停，记录校验层，不反复改包。

## 边界

- asar 不是加密；能列目录不代表能读字节码/原生模块。
- 原生模块只做接口/导出面分析，深入二进制逆向交 `softseep`/`unpack-loop`。
- 远端协议交 `protocol-plugin`（R24）。
- 不提供绕过代码签名/更新签名/企业白名单的方法。

> 关联：`Tool/skill/plugin-targets/references/electron-and-asar.md`、`Tool/cases/plugin04/case.json`。
