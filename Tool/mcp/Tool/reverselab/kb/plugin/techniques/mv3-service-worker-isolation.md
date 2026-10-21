# MV3 service worker 与隔离世界

## 入口信号

- `manifest_version: 3` 且 `background.service_worker` 指向单个 JS 文件。
- content script 里读不到页面 `window` 变量；或注入 `<script>`/`world:"MAIN"`。
- 动态调试时 Network 面板空白，但扩展确实工作。
- `chrome.storage`/IndexedDB 中有状态，SW 重启后仍在。

## 可复制命令

```bash
# 结构 + 权限面
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path extension.zip --json

# 解包 + 权限证据 + 数据流 + 最小单元
python Tool/skill/plugin-targets/scripts/plugin-repro.py --path extension.zip --out work/repro --json

jq '{manifest_version,permissions,host_permissions,background,content_scripts,
     web_accessible_resources,externally_connectable}' work/repro/unpack/manifest.json

grep -nE "onInstalled|onStartup|onMessage|alarms\.|storage\.(local|sync|session)|indexedDB" \
  work/repro/unpack --include='*.js' | head -60
```

## SW 生命周期检查表

| 问题 | 机检点 | 结论 |
|---|---|---|
| 有唤醒源吗 | `onInstalled/onStartup/onMessage/alarms` 至少一个 | 无 → 行为可能永远不触发 |
| 状态持久吗 | `chrome.storage`/IndexedDB 写入 | 只写模块全局变量 → SW 重启丢失 |
| 定时任务 | `chrome.alarms` vs `setInterval` | `setInterval` 在 SW 中不可靠 |
| 休眠后网络缺失 | `chrome://serviceworker-internals` 状态 | 先唤醒再判断，不写“无网络” |
| 消息面 | `onMessage` + `sender.tab/url/origin` 校验 | 无校验 + 全站注入 = 外部可驱动 |

## 隔离世界检查表

| 现象 | 原因 | 正确做法 |
|---|---|---|
| content script 读不到页面变量 | ISOLATED world | 查 `world:"MAIN"`/注入 `<script>`/`postMessage` 桥 |
| `postMessage` 收到陌生来源 | 未校验 `source`/`origin` | 加 `e.source===window` 与 origin 白名单 |
| 页面能加载扩展资源 | `web_accessible_resources` 宽 matches | 收窄资源与 matches；检查资源是否含敏感数据 |
| 改了页面变量但扩展看不到 | 两个世界各自一份 | 用桥传递，不能直接共享变量 |

## 确认判据

- 至少一个唤醒源 + 一处持久状态，能解释 SW 重启后的行为。
- 每条消息能指到 `onMessage` 分支、发送方、字段；`sender` 校验情况明确。
- 每个 content script 能说出 world、`run_at`、`matches`、`all_frames`。
- `plugin-repro.py` 的 `permissions[].status=observed` 覆盖高危权限；不能解释的单列。

## 失败判据

- SW 一直休眠，触发事件后仍无网络/消息 → 标“未观测”，不写“无行为”。
- `world`/注入桥找不到，变量对不上 → 先查 `web_accessible_resources` 与 CSP，不要改页面代码硬试。
- 权限全 `unexplained-static` → 扩大解包范围或查动态拼接 API；仍无 → 标“权限面未闭环”。
- 触发企业策略/EDR/账号风控 → 立即停，记录环境。

## 边界

- 只做授权扩展/隔离 profile 的静态与只读动态；不读真实账号 Cookie 写报告。
- MV3 远端代码被商店禁止，但 `eval`/`importScripts`/`unsafe-eval` 仍可能出现；只写代码事实，不写“已绕过商店”。
- 协议/帧格式交 `protocol-plugin`（R24）。

> 关联：`Tool/skill/plugin-targets/references/browser-extension.md`、`references/04-walkthrough-chrome-extension.md`。
