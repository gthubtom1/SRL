---
id: "site-clone/04-route-coverage-next"
title: "路由覆盖：从 _buildManifest 到 missing_rate"
title_en: "Route Coverage: from _buildManifest to missing_rate"
summary: >
  Next.js 静态导出的页面表在 _buildManifest.js 的 sortedPages；首页可能没有任何 <a>。
  本页给出 route_universe 构造、missing_rate 计算与漏页反例。
board: "site-clone"
category: "04-routes"
signals: ["missing route", "buildManifest", "sortedPages", "sitemap", "Next.js", "client redirect"]
mcp_tools: ["site-crawl.py", "site-diff.py"]
keywords: ["路由覆盖", "missing_rate", "buildManifest", "sortedPages", "sitemap", "Next.js"]
difficulty: "intermediate"
tags: ["routes", "nextjs", "coverage", "buildmanifest", "sitemap"]
language: "zh-CN"
last_updated: "2026-10-22"
related_articles: ["site-clone/02-dom-snapshot-freeze", "site-clone/05-pixel-dom-diff"]
---
# 路由覆盖：从 _buildManifest 到 missing_rate

## 入口信号

- 首页没有 `<a href>`，只有 button/客户端跳转。
- Next.js 页面，`__NEXT_DATA__.nextExport=true`。
- 站点有 `_next/static/<buildId>/_buildManifest.js`。
- 只抓了 1 页，覆盖率却写 100%。

## route_universe 的三个来源

1. **HTML 链接**：`a[href]`、`area[href]`（同源，排除资源扩展名）；
2. **buildManifest**：`_buildManifest.js` 的 `sortedPages`（排除 `/_app`、`/_error`）；
3. **sitemap**：`/sitemap.xml` 的 `<loc>`（同源）。

```bash
curl -sS https://target/_next/static/<buildId>/_buildManifest.js | head -30
curl -sS https://target/sitemap.xml | head -20
```

`__NEXT_DATA__` 里的 `buildId` 用来拼 `_buildManifest` 与 `_next/data/<buildId>/...` 路径。

## 计算

```text
expected = |route_universe|
crawled  = |routes[].route|
missing  = expected - crawled
missing_rate = missing / max(expected, 1)
pass = missing_rate <= 0.02
```

`site-crawl.py` 会在抓取前先读 seed HTML，解析 buildId，把 `sortedPages` 加进队列；
所以 block.youtest.me 的 11 个业务页 + 首页 = 12，`missing_rate=0.0`。

## 客户端重定向

静态导出站点仍可能有客户端重定向：

- 缺用户数据 → `/?error=player_or_user_data_missing_completed_page`；
- 缺 quiz → `/?error=...`。

处理：

1. 记录 `final_url`，不要只看请求 path；
2. 页面标 `backend-required`；
3. 不要把重定向后的错误页算成“业务页已复刻”。

## 确认判据

- `route_universe` 至少包含链接 + buildManifest + sitemap 三来源；
- `missing_routes[]` 为空，或每条都有解释（动态路由/需登录/已删除）；
- 每个 route 有 HTML + 截图 + 状态码；
- `missing_rate` 与 `diff.json.route_coverage` 一致。

## 失败判据

| 现象 | 判定 | 改走哪条 |
| :-- | :-- | :-- |
| 只抓首页 | 覆盖率假 | 解析 buildManifest/sitemap |
| 把 `/_app`、`/_error` 当业务页 | 分母错误 | 排除框架页 |
| 客户端重定向后仍算原 route | 数据边界错误 | 记录 final_url + backend-required |
| 动态路由无 sitemap | 无法构造宇宙 | 写“已知路由覆盖率”，不写全站 100% |
| missing_rate 与 diff 不一致 | 证据不一致 | 重跑 crawl/diff |

## 边界

- buildManifest 只覆盖构建时页面；新部署/参数化路由可能不在其中。
- 登录后路由通常不在静态导出表里，不能算“漏抓”，要标后台边界。
- 路由覆盖是“同源 URL 集合”指标，不衡量页面内容正确性；后者看 DOM/像素/资源。
