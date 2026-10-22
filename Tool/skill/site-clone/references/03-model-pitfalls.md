# site-clone 模型常见失误（14 条）

> 每条固定：**错误动作 → 为什么错 → 正确动作**。
> 这些不是“注意事项”，而是验收时会直接扣分的机器判据来源。

## 1. 把 wget/HTTrack 当万能

- 错误动作：`wget --mirror` 抓完就写“1:1 复刻完成”。
- 为什么错：wget/HTTrack 只保存服务器直接返回的 HTML/资源，不执行 JS；SPA 渲染后的 DOM、登录后页面、XHR 数据都拿不到。
- 正确动作：静态资源可复用 wget/HTTrack；页面必须用 `site-crawl.py`（Playwright）渲染后抓 `page.content()` + 截图 + API。见 `05-static-mirror-limits.md`。

## 2. 只抓首页链接，不看 buildManifest

- 错误动作：只把 `<a href>` 放进队列，路由覆盖写 100%。
- 为什么错：Next.js 静态导出把页面表放在 `_buildManifest.js` 的 `sortedPages`；首页可能没有任何 `<a>`。
- 正确动作：`site-crawl.py` 解析 `_buildManifest.js` + `sitemap.xml`，把 `sortedPages` 加入 `route_universe`。

## 3. 不固定 viewport/DPR

- 错误动作：原站截图 1440×900，本地截图 1280×720，直接算像素差。
- 为什么错：尺寸不同只能 resize，比例/字体/换行全变，差异不可解释。
- 正确动作：固定 `viewport=1280x720`、`dpr=1`，两边用同一 Playwright/Chromium 版本。

## 4. 截图不禁用动画

- 错误动作：轮播/浮动装饰/加载动画还在跑，截图差 5% 就判失败或判通过。
- 为什么错：动画帧随时间变化，同一页面两次截图都不同。
- 正确动作：`page.screenshot(..., animations="disabled")`；动画 WebP 用 `masked_ratio` 单列，同时报告 `raw_ratio`。

## 5. 删除 JS 后不修 inline `opacity:0`

- 错误动作：冻结 DOM 后 logo/插画消失，仍写“像素一致”。
- 为什么错：入场动画由 JS 改 inline `opacity/transform`；删 JS 后元素永久隐藏。
- 正确动作：`site-rebuild.py` 冻结 DOM 时对 `img[style*=opacity:0]` 恢复可见状态；截图复核。

## 6. 保留 JS 却不提供 `_next/data`

- 错误动作：`--keep-js` 重建后直接 diff。
- 为什么错：Next.js hydration 会请求 `_next/data/...json`，本地 404 或重渲染，DOM/像素双漂移。
- 正确动作：crawl 录制 `_next/data`/API，rebuild 落到 `site/_next/data/...` 并生成 HAR；或默认冻结 DOM。

## 7. 把跨域 API 当同源资产

- 错误动作：把 `https://api.youtest.me/info/country` 下载成 `site/api/...`。
- 为什么错：跨域 API 不是静态资产；本地路径/Origin/Cookie 语义都不同，写操作更不能伪造。
- 正确动作：crawl 用 `--allow-host api.youtest.me` 只记录 GET 响应；rebuild 生成 HAR + `page.route` mock；写接口标 `backend-required`。

## 8. 把 HAR 回放当真实后端

- 错误动作：HAR 命中就写“答题/登录/下单已复刻”。
- 为什么错：HAR 只是录制响应的重放；没有真实状态变更、鉴权、幂等、错误分支。
- 正确动作：HAR 只用于读快照/`local-mock`；提交/计分/登录/支付 → `backend_required[]`，结论 PARTIAL。

## 9. 只看状态码 200

- 错误动作：本地 `status=200` 就判资源完整、页面正确。
- 为什么错：Cloudflare challenge、软 404、错误重定向、SPA 空壳都可能 200。
- 正确动作：同时看标题/正文/DOM/资源 hash；软 404 用文本相似度抓。

## 10. 用页面源码代替渲染后 DOM

- 错误动作：直接 `curl` HTML 当 DOM 快照。
- 为什么错：SPA 源码只有壳，真实 DOM 是 JS 渲染后的结果。
- 正确动作：Playwright `page.goto` + wait + `page.content()`；记录等待时间与最终 URL。

## 11. 用文本相似度替代结构

- 错误动作：文本一样就判 DOM 一致。
- 为什么错：结构塌了/节点少了，文本仍可能一样；交互也会坏。
- 正确动作：节点数比、层级比、标签序列、文本相似度四项都算，取最小值 ≥0.98。

## 12. 忽略字体/图片 404

- 错误动作：DOM/文本通过就写 PASS。
- 为什么错：字体缺失导致换行/宽度变化，图片 404 导致视觉崩，但 DOM 文本可能不变。
- 正确动作：资源判据单列 `http_404`、`external_links`；CSS `url()`、`srcset`、woff2 都要检查。

## 13. 交互只用位置 selector

- 错误动作：`div:nth-child(3) > button` 点击语言菜单。
- 为什么错：DOM 一漂移就点错；动画未完成还会 timeout。
- 正确动作：用 `aria-label`/`role`/可见性过滤；交互脚本记录 expected/actual，少于 5 条通过就降 PARTIAL。

## 14. 把 `backend-required` 写成“已复刻”

- 错误动作：静态快照 + HAR 回放，结论写“完整 1:1，包括登录/答题/榜单”。
- 为什么错：后端逻辑没有复制；这是结论越界，不是技术瑕疵。
- 正确动作：逐页标 `backend-required`，给接口清单与缺口，结论 PARTIAL；要真复刻就转后端重建域。
