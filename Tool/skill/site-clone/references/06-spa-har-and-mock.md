# SPA 复刻：Playwright `page.route` + HAR 回放

> SPA/Next.js 的难点不是“下载 HTML”，而是**渲染后 DOM**与**运行时 API**。
> 本页给出可复制的 HAR mock 流程：crawl 录制 → rebuild 落地 → `page.route` 回放 → diff 验收。

## 1. 官方能力（来源）

- Playwright Mock APIs：https://playwright.dev/docs/mock
- `page.route` API：https://playwright.dev/docs/api/class-page#page-route
- `route.fulfill`：https://playwright.dev/docs/api/class-route#route-fulfill
- HAR 1.2 规范：http://www.softwareishard.com/blog/har-12-spec/
- Chrome DevTools 导出 HAR：https://developer.chrome.com/docs/devtools/network/reference/#save-as-har

关键点：

1. `page.route('**/*', handler)` 能拦截页面发起的请求；
2. `route.fulfill({status, headers, body})` 返回录制响应；
3. 没命中的请求应 `route.abort()`，避免离线副本偷偷联网；
4. HAR 只保存请求/响应，不保存后端状态/事务。

## 2. crawl：录制什么

`site-crawl.py` 对每个页面监听 `response`，满足任一条件即记录：

- `content-type` 含 `json`；
- URL 路径含 `/api/` 或 `/_next/data/`；
- `resource_type` ∈ `xhr`/`fetch`；
- 方法必须是 **GET**（非 GET 直接 abort，记入 `skipped_non_get`）。

保存到：

```text
artifacts/crawl/api/001-user_name.json
artifacts/crawl/api/002-country.json
```

`site-graph.json.api[]` 每条：

```json
{
  "url": "https://block.youtest.me/_next/data/<buildId>/user/name.json",
  "method": "GET",
  "status": 200,
  "content_type": "application/json",
  "body_file": "api/001-user_name.json",
  "sha256": "<64 hex>",
  "bytes": 1234
}
```

跨域 API（如 `api.youtest.me/info/country`）同样记录，但标 `backend_required` 的“只读快照”原因。

## 3. rebuild：落地与 HAR

```bash
python Tool/skill/site-clone/scripts/site-rebuild.py \
  --crawl Tool/cases/site-clone01/artifacts/crawl \
  --out Tool/cases/site-clone01/artifacts/rebuild
```

- 同源 `_next/data/...json` 写到 `site/_next/data/...json`，本地服务器直接 200；
- 跨域 API 写到 `mock/api/<host>/...`，由 HAR 回放；
- `har.json` 每条含 request/response/content；
- `mock/playwright-route.js` 是可直接 require 的示例：

```js
const HAR = require('../har.json');
module.exports = async function mock(page) {
  await page.route('**/*', async (route) => {
    const url = route.request().url();
    const hit = HAR.log.entries.find(e => e.request.url === url)
             || HAR.log.entries.find(e => e.request.url.split('?')[0] === url.split('?')[0]);
    if (!hit) {
      const u = new URL(url);
      if (u.hostname === '127.0.0.1' || u.hostname === 'localhost') return route.continue();
      return route.abort();
    }
    const c = hit.response.content;
    const body = c.encoding === 'base64'
      ? Buffer.from(c.text, 'base64') : Buffer.from(c.text || '', 'utf8');
    return route.fulfill({
      status: hit.response.status,
      headers: Object.fromEntries(hit.response.headers.map(h => [h.name, h.value])),
      body
    });
  });
};
```

验收时 `site-rebuild.py` 自己起 `http.server`，并用同一套 HAR 逻辑跑本地截图/交互，保证离线。

## 4. 两种重建模式

| 模式 | 命令 | 适用 | 风险 |
| :-- | :-- | :-- | :-- |
| 冻结 DOM（默认） | `site-rebuild.py --crawl ... --out ...` | 静态 1:1、像素/DOM 最稳 | 交互靠原生 DOM，JS 交互丢失 |
| 保留 JS | `--keep-js` | 需要客户端路由/菜单/表单 | hydration 需要 `_next/data`，DOM/像素易漂 |

冻结模式做三件事：

1. 删除 `<script>`（保留 `link rel=stylesheet`）；
2. 对 `img[style*=opacity:0]` 恢复可见（避免入场动画元素永久隐藏）；
3. 在 `<head>` 插 HTML 注释标记（不增加 DOM 节点）。

保留 JS 模式必须确认：

- 同源 `_next/data` 已落地；
- 跨域 API 有 HAR；
- `page.route` 先于 `goto` 注册；
- 本地 `http.server` 的 MIME 正确（`.js`/`.css`/`.json`/`.woff2`/`.svg`）。

## 5. Next.js 特例

- `_buildManifest.js` 的 `sortedPages` 是路由宇宙的权威来源；
- `__NEXT_DATA__.buildId` 决定 `_next/data/<buildId>/...` 路径；
- 客户端跳转可能不改变 `page.url()` 的 path（取决于 router），crawl 必须记录 `final_url`；
- 静态导出站点仍然可能有客户端重定向（缺数据 → `/?error=...`），这类页面要标 `backend-required`。

## 6. HAR 的边界（必须写进报告）

HAR 能做的：

- 回放 GET JSON/HTML/JS/CSS；
- 让离线副本在没有后端时仍能渲染同一状态；
- 给 diff 提供“资源集合”证据。

HAR 不能做的：

- 产生新的写操作（POST/PUT/PATCH/DELETE）；
- 证明鉴权/权限/幂等/错误分支；
- 替代数据库/队列/实时计算；
- 保证未来仍然有效（录制是时间点快照）。

因此：

- `local-mock` 页面可以 PASS；
- 写操作/登录/实时状态必须 `backend-required`，结论 PARTIAL；
- 报告写清“HAR 录制时间窗 + 只读”。

## 7. 失败判据

- HAR 未命中却 `route.continue()` → 离线副本联网，证据污染。
- `route.fulfill` 返回 200 但 body 是错误页 → 软 404，DOM/文本会暴露。
- 只 mock `_next/data` 不 mock 跨域 API → 页面卡在 loading。
- 保留 JS 但本地 404 → hydration 失败，DOM/像素双漂移。
- 把 HAR 回放写成“后端已复刻” → 结论越界，必须降级。
