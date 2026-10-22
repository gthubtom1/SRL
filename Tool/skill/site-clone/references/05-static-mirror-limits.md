# 静态镜像的边界：wget / HTTrack 能做什么、不能做什么

> 2026 的工具对比文章反复给同一结论：**wget/HTTrack 只能镜像静态站**；
> SPA 渲染、登录态、后端逻辑、实时数据拿不到。本页把这个结论落到可机检的判据上。

## 1. 能力对照

| 能力 | wget `--mirror` | HTTrack | Playwright crawl（本域） |
| :-- | :-- | :-- | :-- |
| 递归下载 HTML/资源 | 是 | 是 | 是（同源、限速、只 GET） |
| 保持目录/链接改写 | 部分 | 是 | 是（本地路由 + 资产路径） |
| 执行 JS / 渲染 SPA | 否 | 否 | 是（`page.content()`） |
| 抓 XHR/fetch JSON | 否 | 否 | 是（录制到 `api/`） |
| 登录后页面 | 否（除非手工带 Cookie） | 否 | 默认按 scope 清单执行；需单独授权 |
| 截图/DOM/交互证据 | 否 | 否 | 是（截图 + DOM + interactions） |
| HAR mock | 否 | 否 | 是（`har.json` + `page.route`） |
| 后端写操作 | 否 | 否 | 不复制，标 `backend-required` |

来源：

- GNU Wget Manual（递归/镜像/限速参数）：https://www.gnu.org/software/wget/manual/wget.html
- HTTrack 官方文档：https://www.httrack.com/html/index.html
- 2026 工具对比文章（wget/HTTrack vs 浏览器抓取）：结论为“静态可镜像，SPA/登录/后端不可”，本页按该结论设计判据；文章链接以团队资料库为准，引用时写清“2026 工具对比”。

## 2. 为什么静态镜像会“看起来成功，实际失败”

### 2.1 SPA 只有壳

`wget` 保存的是服务器返回的 HTML。Next.js/React/Vue 的首页往往只有：

```html
<div id="root"></div>
<script src="/assets/index.js"></script>
```

真实 DOM 要等 JS 执行后才出现。静态镜像的 DOM 节点数、文本、截图都不等于线上页面。

### 2.2 登录态不是静态资源

登录后页面通常依赖：

- `Set-Cookie` 会话；
- `Authorization: Bearer`；
- `localStorage/sessionStorage`；
- CSRF token；
- 服务端按用户返回的 JSON。

wget/HTTrack 不会登录，也不会保存这些状态。即使手工带 Cookie 抓一次，也只是“某个时刻的登录快照”，不是可复刻的登录系统。

### 2.3 后端逻辑不可复制

答题提交、计分、下单、发帖、支付都属于写操作：

- 静态镜像没有数据库/事务/鉴权；
- HAR 只能重放录制响应，不能产生新的状态；
- 伪造“提交成功”会把取证变成造假。

正确做法：把这些页面/接口标 `backend-required`，给后端接口清单，不在前端副本里假装成功。

### 2.4 第三方资源与广告

wget/HTTrack 可能把广告/统计脚本一起抓下来，造成：

- 外链未阻断（资源判据失败）；
- 广告 iframe 改变布局（像素假差异）；
- 跟踪脚本在离线副本里继续请求外网（隐私/合规问题）。

本域默认：非白名单 host 一律 abort，改写到 `/__external__/blocked.*`。

## 3. 何时可以只用静态镜像

满足以下全部条件时，wget/HTTrack 可作为**资产参考**，但仍需本域脚本补证据：

1. 页面是服务器直出 HTML，无 JS 渲染依赖；
2. 无登录、无 XHR/fetch、无写操作；
3. 资源同源或已明确白名单；
4. 只需要离线阅读，不需要交互/截图/DOM 判据。

即使满足，也要跑：

```bash
python Tool/skill/site-clone/scripts/site-crawl.py --url <origin> --out <dir> --rps 2
python Tool/skill/site-clone/scripts/site-rebuild.py --crawl <dir> --out <rebuild>
python Tool/skill/site-clone/scripts/site-diff.py --crawl <dir> --rebuild <rebuild>
```

否则无法回答“路由覆盖多少、像素差多少、DOM 是否一致、有没有 404/外链”。

## 4. 2026 工具生态的正确分工

| 阶段 | 首选 | 原因 |
| :-- | :-- | :-- |
| 发现 URL | Playwright + `_buildManifest.js` / sitemap | 静态镜像看不到客户端路由 |
| 抓 DOM/截图 | Playwright | 需要渲染后 DOM 与固定 viewport |
| 抓 API | Playwright `response.body()` + HAR | 需要请求/响应体，且只 GET |
| 抓静态资产 | wget/HTTrack 或本域 `site-rebuild.py` | 资产可复用；但要限速与白名单 |
| 离线回放 | `page.route` + HAR | 只读 mock；写操作仍需真实后端 |
| 保留动画 | clone-space-mcp（2026 社区工具） | 静态镜像会丢动画/交互状态 |
| 导出站点/表单/API map | playwright-archaeologist（2026 社区工具） | 仍需人工核对业务语义 |
| 录制会话→API/OpenAPI | tabapi（2026 社区工具） | 只覆盖录制到的请求 |

社区工具（webEmbedding、playwright-archaeologist、clone-space-mcp、tabapi）来自 2026 工具清单，未见稳定官方规范；引用时标注“2026 社区工具”，不要写成厂商承诺。

## 5. 失败判据

- 只跑 wget/HTTrack 就写“1:1 完成” → 证据不合格。
- 静态镜像 DOM 节点数明显少于线上 → 需要 Playwright 渲染。
- 登录后页面没有单独授权/单独标注 → 数据边界错误。
- 离线副本仍在请求外网广告/统计 → 资源判据失败。
- 把 HAR 回放当写操作 → 结论越界，必须 `backend-required`。

## 6. 一句话

> wget/HTTrack 是“资产搬运工”，不是“站点复刻器”；
> 1:1 的判据在 DOM/截图/资源/交互/数据边界，不在“文件下载完了”。
