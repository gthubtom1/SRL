# 抓取输入记录 — block.youtest.me

## 目标与授权

| 项 | 值 |
|---|---|
| 目标 | `https://block.youtest.me`（"Don't Block Me" 测验站） |
| 站点形态 | Next.js 静态导出（`nextExport: true`，buildId `MF0PX5Om9anXYG9uRYEC-`）+ Cloudflare（`server: cloudflare`，`cf-cache-status: DYNAMIC`） |
| 授权 | 用户明确声明已获授权；仅做只读抓取与离线复刻演练 |
| 约束 | 只 GET/HEAD、同源、≤2 rps、≤150 页；不登录、不提交表单、不做漏洞测试 |
| 抓取窗口（UTC） | 2026-10-21T23:37Z（robots/首访）～ 2026-10-22T00:09Z（最后一页）；diff 生成于 2026-10-22T00:14Z |
| 执行环境 | Windows / Python 3.12.0 / Playwright 1.62.0（sync）/ Chromium 153.0.8010.12（`chromium-1243`） |

## 抓取参数

| 参数 | 值 |
|---|---|
| 视口 | 1280 × 800，`device_scale_factor=1` |
| 限速 | 全局 0.5 s/请求（2 rps），路由拦截器与 `context.request` 共用同一令牌桶 |
| 页面预算 | 上限 150，实际 12（buildManifest 推断出的全部页面路由） |
| 方法白名单 | 仅 `GET`（未使用 HEAD，也未发 POST） |
| 来源白名单 | `https://block.youtest.me`；跨域/非 GET 一律 `route.abort()` 并记录 |
| 路由发现 | `/_next/static/<buildId>/_buildManifest.js` 的 `sortedPages` + 页面内 `<a href>` 实测 |
| 稳定性处理 | 等 `LoadingScreen` 消失 → DOM 节点/文本/URL 连续 2 s 不变 → 注入禁动画 CSS → 截图 |
| 确定性处理 | 固定种子 `Math.random`（LCG, seed=42）+ `requestAnimationFrame` 时间戳固定为 1200 ms |
| 数据落盘 | HTML 原文、截图、DOM 摘要、同源资源、`_next/data/*.json`、XHR/fetch 清单与回放体 |

## robots / ToS 观察（只读记录，不构成法律意见）

- `GET /robots.txt` → `200`，1248 字节。内容为 **content-signal 声明**（search / ai-input / ai-train 三类用途说明），
  **未观察到 `User-agent` / `Disallow` / `Allow` / `Sitemap` 规则行**。
- `GET /sitemap.xml` → `404`（返回的是站点 404 页面）。
- 响应头未观察到 `X-Robots-Tag`；有 HSTS、`x-content-type-options: nosniff`、`referrer-policy: strict-origin-when-cross-origin`。
- `_buildManifest.js` 中没有独立的服务条款/隐私政策路由；`/contact` 是联系/支持表单页，本次只读取页面，未提交。
- 站内页面底部与分享素材引用了母品牌域 `https://youtest.me/static/assets/promo/*`（跨域图片）；按同源约束未抓取。

## 边界声明

- 未创建测验、未加入测验、未填写任何表单、未登录、未发送 POST。
- 未对目标做任何漏洞探测（无 fuzz、无目录爆破、无注入尝试）；路径仅来自构建清单与页面链接。
- 离线副本只包含公开静态资源与公开 `_next/data` JSON；回放体见 `artifacts/site/_replay/bodies/`，无个人数据。
- 复刻用途为兼容性/取证演练；页面素材版权归原站所有，未再分发到案例目录之外。
