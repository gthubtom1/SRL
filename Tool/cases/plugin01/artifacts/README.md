# plugin01 产物说明

- 输入：`input/ext.zip`（sha256 `1103cad9d78f2438555e0ea80ff74d384a29c22a9060782eba2b37473eb682dc`，1194 B），内含 `manifest.json`、`background.js`、`content.js`。
- 运行：`python ../../../Tool/scripts/plugin-triage.py --path input/ext.zip --json`，rc=0。
- 结果（完整 stdout 见 `run.json`）：识别为 `ZIP 浏览器扩展包`，MV3 / `Lab Session Helper` 1.2.0，3 个文件；权限 `storage,scripting,cookies`，host_permissions `https://*.example.invalid/*`；命中 `chrome_cookies`、`network_request`；远程 URL `https://api.example.invalid/session` 与 host 匹配式。结论：入口已定位，未命中高风险 API。
- 数据流（静态阅读）：content.js → `chrome.runtime.sendMessage` → background.js → `chrome.cookies.getAll` → `fetch(API)`。
- 边界：仅静态初筛，未把扩展加载进浏览器、未观察 service worker 回收/唤醒、未取得商店或旁加载真实样本；`cookies`/`scripting` 的实际滥用需动态与代码路径证据。
