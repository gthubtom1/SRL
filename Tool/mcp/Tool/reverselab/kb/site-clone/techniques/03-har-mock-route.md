---
id: "site-clone/03-har-mock-route"
title: "HAR 回放与 page.route：让离线副本加载录制数据"
title_en: "HAR Replay and page.route for Offline Recorded Data"
summary: >
  crawl 录制 GET JSON/API，rebuild 生成 HAR 与 Playwright page.route 脚本；
  未命中请求 abort，避免离线副本联网。HAR 只回放读快照，写操作仍标 backend-required。
board: "site-clone"
category: "03-har"
signals: ["XHR", "fetch", "_next/data", "HAR", "page.route", "offline loading", "CORS"]
mcp_tools: ["site-crawl.py", "site-rebuild.py", "site-diff.py"]
keywords: ["HAR", "page.route", "mock", "回放", "API", "OpenAPI"]
difficulty: "intermediate"
tags: ["har", "playwright", "mock", "route", "api"]
language: "zh-CN"
last_updated: "2026-10-22"
related_articles: ["site-clone/02-dom-snapshot-freeze", "site-clone/06-failure-criteria"]
---
# HAR 回放与 page.route：让离线副本加载录制数据

## 入口信号

- 本地副本一直 loading，控制台看到 `_next/data/...json` 或 `/api/...` 404。
- 页面有跨域 API（如 `api.example.com`），本地同源服务器无法提供。
- 需要把录制会话导出成 API/OpenAPI 形状（tabapi 等 2026 社区工具）。
- 有人把 HAR 命中当成“后端已复刻”。

## 官方能力（来源）

- Playwright Mock APIs：https://playwright.dev/docs/mock
- `page.route`：https://playwright.dev/docs/api/class-page#page-route
- `route.fulfill`：https://playwright.dev/docs/api/class-route#route-fulfill
- HAR 1.2：http://www.softwareishard.com/blog/har-12-spec/

## 录制（crawl）

`site-crawl.py` 只记录 GET，条件：

- `content-type` 含 `json`；
- URL 含 `/api/` 或 `/_next/data/`；
- `resource_type` 为 `xhr`/`fetch`。

输出：

```text
crawl/api/001-user_name.json
crawl/site-graph.json.api[]  # url/method/status/content_type/body_file/sha256/bytes
```

跨域 API 也可录，但只作为只读快照；写接口不录/不伪造。

## 重建（rebuild）

```bash
python Tool/skill/_pending/site-clone/scripts/site-rebuild.py \
  --crawl work/crawl --out work/rebuild --rps 2
```

生成：

- `rebuild/har.json`：HAR 1.2，含 request/response/content；
- `rebuild/mock/playwright-route.js`：可直接 require 的 route handler；
- 同源 `_next/data` 落到 `site/_next/data/...`，本地服务器直接 200。

使用：

```js
const mock = require('./rebuild/mock/playwright-route.js');
await mock(page);          // 必须在 page.goto 之前
await page.goto('http://127.0.0.1:8787/');
```

handler 行为：

1. 本地 `127.0.0.1/localhost` → `route.continue()`；
2. HAR 精确 URL 命中 → `route.fulfill({status, headers, body})`；
3. 忽略 query 的 path 命中 → fulfill（应对随机 query）；
4. 未命中 → `route.abort()`，绝不联网。

## 确认判据

- `har_entries` 等于录制的 GET API 数；
- 本地 `http_404=0`，页面不再卡 loading；
- 未命中请求被 abort（可在 `local_requests` 中看到）；
- `local-mock` 页面在 diff 中 DOM/像素达标；
- 写操作/登录仍出现在 `backend_required[]`。

## 失败判据

| 现象 | 判定 | 改走哪条 |
| :-- | :-- | :-- |
| 未命中 `continue()` | 离线副本联网 | 改 `abort()` 或补 HAR |
| 只 mock 同源，不 mock 跨域 | 页面卡 loading | 跨域 API 也录/加白名单 |
| HAR 含 Cookie/Token | 凭据泄露 | 脱敏后重生成 |
| 200 但 body 是错误页 | 软 404 | 用 DOM/文本相似度抓 |
| 把 HAR 当写操作 | 结论越界 | 标 `backend_required`，降 PARTIAL |

## 边界

- HAR 是时间点快照；后端部署/数据变化后可能失效。
- HAR 不产生事务/鉴权/幂等/错误分支。
- 登录态、写操作、实时计算 → `backend_required`；HAR 只用于读。
