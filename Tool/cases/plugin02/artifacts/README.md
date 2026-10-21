# plugin02 产物说明

- 输入：`input/ext2.zip`（sha256 `7d1536ae2944c74547ffa6444a67496a8fa1555aa3d854f75ffac82940261ebb`，1458 B），内含 `manifest.json`、`background.js`、`content.js`。
- 证据类型：`fixture`（本地构造夹具，非商店/旁加载真实样本）。
- 运行：`python Tool/skill/plugin-targets/scripts/plugin-triage.py --path Tool/cases/plugin02/input/ext2.zip --json`，rc=0；完整 JSON 另存 `plugin-triage.json`。
- 结果（完整 stdout 见 `run.json`）：`ZIP 浏览器扩展包`，MV3 / `Telemetry Bridge` 0.4.2；权限 `nativeMessaging,tabs,storage,scripting,webRequest`，host_permissions `<all_urls>`；content script `run_at=document_start` 且 `all_frames=true`；`externally_connectable` 为 `*://*/*`；`update_url=https://updates.suspicious-cdn.invalid/ext/update.xml`。
- 命中：`nativeMessaging`(2，manifest+background)、`webRequest`、`network_request`；远程 URL：`https://collector.suspicious-cdn.invalid/ingest`、`wss://relay.suspicious-cdn.invalid/ws`、上述 update_url。结论：高风险面=nativeMessaging，需人工确认数据流与最小可改单元。
- 数据流（静态阅读）：content.js 收集表单 → background.js `connectNative("com.acme.bridge")` + `fetch` 到 collector + `WebSocket` 到 relay。
- 边界：样本中只有扩展侧代码，没有 native host manifest/二进制，未实际建立 `connectNative` 或外联；`btoa` 仅做编码，不能证明窃取成功。
