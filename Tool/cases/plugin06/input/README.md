# plugin06 输入：本机已安装的 Chrome 扩展（Tampermonkey 5.5.1）

| 项 | 值 |
|---|---|
| 目标类型 | Chrome/Edge MV3 浏览器扩展（userscript 管理器） |
| 产品/版本 | Tampermonkey **5.5.1**（manifest_version 3，minimum_chrome_version 120） |
| 扩展 ID | `dhdgffkkebhmkfjojejmpbldmpobfkfo` |
| 原始安装目录 | `<CHROME_EXT>` = `~/AppData/Local/Google/Chrome/User Data/Default/Extensions/dhdgffkkebhmkfjojejmpbldmpobfkfo/5.5.1_0`（本机已安装，装于 2026-10-09） |
| 入口文件 | `manifest.json`（`background.service_worker=background.js`、`action.default_popup=action.html`、`options_page=options.html`） |
| 包体 | `real-extension.zip`（482455 字节，13 个文件，字节级复制，未改动内容） |

## 只读说明

- 原始目录只按**只读引用**使用：`real-extension.zip` 是把源文件字节级复制后打包的副本，源目录本身未被写入、未被移动、未被改权限。
- 本案例不做任何签名/校验绕过：`_metadata/verified_contents.json` 原样保留（仅用于记录商店安装的树哈希存在），未复算逐文件树哈希。
- 未在浏览器里加载该扩展，未调用任何远端接口，未连 native host。

## 为什么只截取 13/86 个文件

源目录 5.6 MB / 86 个文件，其中 `vendor/eslint`、`images/`、`style.css`、`editor.css`、30+ 语言包与入口/权限判定无关。截取范围 = manifest + service worker/offscreen/页面桥脚本 + 3 个 HTML 入口 + en 语言包 + 签名树元数据；每个文件的来源路径、字节数与 sha256 见 `../artifacts/provenance.json`。

## 复跑

```bash
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --path Tool/cases/plugin06/input/real-extension.zip --json
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py --path Tool/cases/plugin06/input/real-extension.zip --out Tool/cases/plugin06/artifacts/repro --json
python Tool/skill/_pending/plugin-targets/scripts/plugin-accept.py --root . --case Tool/cases/plugin06 --json
```
