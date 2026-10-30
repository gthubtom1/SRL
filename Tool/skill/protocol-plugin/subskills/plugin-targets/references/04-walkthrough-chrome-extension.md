# 04 真实案例走查：本机 Chrome MV3 扩展（Quicker 1.2.4）

本页保留历史样本、输出和当时 `_pending` 路径，不代表当前安装身份。现在复验从 `Tool/skill/protocol-plugin/subskills/plugin-targets/SKILL.md` 进入，脚本位于其 `scripts/`；复验记录另绑当前目标哈希与 run，不能用旧案例输出代替。

> 范围：想照着复跑“真实安装扩展 → 结构/权限/入口/数据流/最小单元”的完整链路。
> 结论边界：本走查只做静态子集分析（未加载浏览器、未连接 native host）；“恶意/已外发”的定性需动态证据。
> 样本来源：本机 Chrome 用户扩展目录（`~/AppData/Local/Google/Chrome/User Data/Default/Extensions/klggb…/1.2.4_0`），截取 6 个入口/权限相关文件，内容未修改。仓库内输入为 `Tool/cases/plugin03/input/real-extension.zip`。

## 1. 目标与假设

- 扩展：Quicker 1.2.4（MV3），native host 名 `com.getquicker.chromeagent`。
- 已知面：`nativeMessaging`、`debugger`、`scripting`、`userScripts`、`<all_urls>`。
- 要回答：
  1. 包是什么、入口在哪；
  2. 每个高危权限能否落到代码路径；
  3. 页面 → content → background → native/远端 的边是否存在；
  4. 最小可改单元在哪；
  5. 哪些结论只能算 `inferred`/`unverified`。

## 2. 命令与原始输出

### 2.1 结构 + 权限面（plugin-triage.py）

```bash
cd /d/Seep-Reverse-Lab
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py \
  --path Tool/cases/plugin03/input/real-extension.zip --json
```

关键输出（节选，已去掉长数组）：

```json
{
  "container": "zip",
  "sha256": "874f1b86b184b3304031df3f3b93c4cd850af2ff4c9f03451601d15d6e9ffc9b",
  "size": 96095,
  "file_count": 6,
  "top_level": ["_locales", "background", "content", "manifest.json", "popup"],
  "permission_surface": {
    "high": ["nativeMessaging", "debugger", "scripting", "userScripts"],
    "broad_hosts": ["<all_urls>"],
    "host_permissions": [{"pattern": "<all_urls>", "risk": "critical"}]
  },
  "entrypoints": {"manifest": "manifest.json", "package": null, "plugin_xml": null},
  "suspicious_apis": {
    "nativeMessaging": {"count": 2, "files": ["manifest.json", "background/background.js"]},
    "debugger": {"count": 27, "files": ["background/background.js"]},
    "chrome_cookies": {"count": 5, "files": ["background/background.js"]},
    "network_request": {"count": 4, "files": ["background/background.js"]}
  }
}
```

判读：

- `container=zip` + `manifest.json` → 浏览器扩展；扩展名/来源不影响结构判断。
- `permission_surface.high` 里 4 项高危；`<all_urls>` 是宽 host。
- `suspicious_apis` 只是“命中”，不是“已外发”；下一步必须做权限证据。

### 2.2 解包 + 权限证据 + 最小单元（plugin-repro.py）

```bash
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py \
  --path Tool/cases/plugin03/input/real-extension.zip \
  --out Tool/cases/plugin03/artifacts/repro --json
```

人类可读输出（节选）：

```text
== plugin repro ==
container : zip  files=6 extracted=6
unpacked  : .../Tool/cases/plugin03/artifacts/repro/unpack
permissions:
  - nativeMessaging   risk=critical status=observed evidence=2
  - debugger          risk=critical status=observed evidence=1
  - scripting         risk=high     status=observed evidence=1
  - userScripts       risk=high     status=observed evidence=2
  - sidePanel         risk=low      status=unexplained-static evidence=0
data_flow : runtime.sendMessage, runtime.onMessage, connectNative, fetch, storage, cookies, scripting.executeScript, postMessage
minimal   : {"path": "background/background.js", "lines": 147, "flow_hits": 14, ...}
```

关键 JSON 片段（节选）：

```json
{
  "permissions": [
    {"name": "nativeMessaging", "risk": "critical", "status": "observed",
     "evidence": [{"file": "background/background.js", "line": 146,
                   "snippet": "chrome.runtime.connectNative(...)"}]},
    {"name": "sidePanel", "risk": "low", "status": "unexplained-static", "evidence": []}
  ],
  "data_flow": [
    {"kind": "runtime.sendMessage", "hits": [{"file": "content/content.js", "line": 48}]},
    {"kind": "connectNative", "hits": [{"file": "background/background.js", "line": 146}]},
    {"kind": "cookies", "hits": [{"file": "background/background.js", "line": 48}]}
  ],
  "minimal_unit": {"path": "background/background.js", "lines": 147, "flow_hits": 14}
}
```

判读：

- 12/13 个声明权限能找到代码证据；`sidePanel` 在截取子集中没有对应文件，标 `unexplained-static`，不是“恶意”，而是“这个子集无法闭环”。
- 数据流能指到文件/行号：content → background（`sendMessage`/`onMessage`）、background → native（`connectNative`）、background → 网络（`fetch`）、background → 存储/Cookie。
- 最小可改单元是 `background/background.js`（147 行 bundle，14 处数据流命中）；但这是压缩 bundle，改动前应找 source map 或只做断点观测。

### 2.3 manifest 关键字段

```bash
jq '{manifest_version,version,permissions,optional_permissions,host_permissions,
     background,content_scripts,web_accessible_resources,externally_connectable,update_url}' \
  Tool/cases/plugin03/artifacts/repro/unpack/manifest.json
```

关键值（节选）：

```json
{
  "manifest_version": 3,
  "version": "1.2.4",
  "permissions": ["nativeMessaging", "tabs", "debugger", "contextMenus", "storage",
                  "tts", "scripting", "userScripts", "activeTab", "downloads",
                  "tabGroups", "webNavigation", "sidePanel"],
  "optional_permissions": ["bookmarks", "browsingData", "history", "cookies",
                           "sessions", "pageCapture"],
  "host_permissions": ["<all_urls>"],
  "background": {"service_worker": "background/background.js"},
  "content_scripts": [{"all_frames": true, "js": ["content/content.js"], "matches": ["<all_urls>"]}],
  "externally_connectable": null,
  "update_url": "https://clients2.google.com/service/update2/crx"
}
```

判读：

- `content_scripts.matches=<all_urls>` + `all_frames=true`：每个 frame 都可能注入；消息面必须看 `sender` 校验。
- `externally_connectable=null`：未声明外部站点直连；比“任意站点可 sendMessage”弱一档。
- `optional_permissions` 含 `cookies/history/bookmarks/pageCapture`：运行时才申请，静态阶段不能当已获得。
- `update_url` 指向 Chrome 商店更新端点：更新链由商店签名控制。

## 3. 数据流图（只写有证据的边）

```text
page DOM / frame
  └─ content/content.js（ISOLATED, all_frames）
       └─ chrome.runtime.sendMessage
            └─ background/background.js  onMessage
                 ├─ chrome.runtime.connectNative("com.getquicker.chromeagent")
                 ├─ chrome.debugger.*（27 处命中）
                 ├─ chrome.cookies.*（5 处命中）
                 ├─ chrome.storage.*
                 └─ fetch / XMLHttpRequest
```

未证明的边（写 `inferred`/`unverified`）：

- native host 二进制是否存在、`allowed_origins` 是否只允许该扩展 ID；
- 远端请求的实际域名/证书/响应；
- `debugger` 权限是否用于用户主动操作，还是后台自动附加；
- 页面数据是否真的进入上述 sink（需要动态消息与参数追踪）。

## 4. 结论

| 结论 | 级别 | 依据 |
|---|---|---|
| 包为 MV3 浏览器扩展，6 个文件，入口 `background/background.js` + `content/content.js` | observed | triage/repro JSON + manifest |
| 4 个高危权限 + 宽 host；12/13 权限有代码证据 | observed | `permissions[].status=observed` + evidence file/line |
| 存在 content→background→native/网络的代码路径 | observed | `data_flow` 四条边 + 行号 |
| 最小可改单元为 `background/background.js` | observed | `minimal_unit.path/lines/flow_hits` |
| native host 可被执行 / 数据已外发 | unverified | 缺 host 二进制、缺动态网络/消息 |
| `sidePanel` 权限用途 | blocked | 截取子集缺对应文件；不是恶意结论 |

## 5. 边界与失败判据

- 本走查只做静态、只读；未在浏览器加载扩展，未连接 `com.getquicker.chromeagent`，未访问任何远端。
- 高权限 ≠ 恶意：Quicker 是自动化工具，`debugger`/`nativeMessaging` 可能是产品功能；报告只写“能力与代码路径”，不写“窃取”。
- 压缩 bundle 的行号来自解包后的文件；如果没有 source map，行号只能用于定位，不等于源码行号。
- 若你复跑时 `permissions[].status` 大量 `unexplained-static`：先扩大解包范围/确认子集，再按 `02-failure-criteria.md` 第 4 条降级，不要补写“恶意”。
- 若要在真实浏览器动态验证：用隔离 profile，先记录 baseline，再触发 `onMessage`/`connectNative`；不要把真实账号 Cookie 写进证据。
- 协议/帧格式问题交 `protocol-plugin`（R24）；本案例不猜 native host 协议字段。

## 6. 复跑清单

```bash
# 1) 结构/权限面
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --path Tool/cases/plugin03/input/real-extension.zip --json
# 2) 解包/证据/最小单元
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py --path Tool/cases/plugin03/input/real-extension.zip --out /tmp/repro03 --json
# 3) 对照 manifest
jq '{permissions,optional_permissions,host_permissions,background,content_scripts,externally_connectable}' /tmp/repro03/unpack/manifest.json
# 4) 离线自检（确认工具本身可用）
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --self-test
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py --self-test
```
