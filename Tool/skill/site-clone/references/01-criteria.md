# site-clone 判据表（六条，可机检）

> 目标：同一份 crawl/rebuild/diff 产物，换机器重跑，`site-accept.py` 给出同一个 `status`。
> 所有数值字段都在脚本源码里出现；门禁可直接复算，不靠人工“看起来一样”。

## 1. 总表

| 场景 | 输入面 | 判据（可机检） | 证据形态 | 误报风险 |
| :-- | :-- | :-- | :-- | :-- |
| 路由覆盖 | 种子 HTML 链接、`_buildManifest.js` 的 `sortedPages`、`sitemap.xml` | `missing_rate = missing / expected ≤ 0.02`；`missing_routes[]` 必须为空或可解释 | `site-graph.json.coverage` + `route_universe[]` | 中：只抓首页链接会漏 Next.js 页面；动态路由无 sitemap 时无法构造宇宙 |
| 像素一致（静态） | 同 viewport/DPR 的原站截图与本地截图 | 差异像素占比 `ratio ≤ 0.01`；同时保留 `raw_ratio` | `crawl/screenshots/*.png` + `rebuild/screenshots/*.png` + `diff.json` | 高：动画帧、字体回退、滚动位置、广告位都会造成假差异 |
| 像素一致（SPA） | 同 viewport/DPR；JS 渲染后截图 | `ratio ≤ 0.03`；动画 WebP 区域可用 `masked_ratio` 单列，但必须报告 `raw_ratio` | 同上 + `pixel.pages[].masked_boxes` | 高：hydration 时序、`_next/data` 缺失、动画 WebP 帧不同 |
| DOM 一致 | 抓取时 `page.content()` 与本地加载后 DOM | 节点数比、层级比、文本相似度、标签序列相似度均 ≥ 0.98 | `crawl/pages/*.html` + `rebuild/local/*.html` | 中：script/style 注入、随机 token、广告 iframe 会污染；需先归一化 |
| 资源完整 | 页面 `src/href/srcset`、CSS `url()`、JS 动态请求 | `http_404 = 0`；`external_links = 0`（白名单外） | `rebuild.json.resources` + `local_requests[]` | 中：软 404、CDN 403、`data:` URI 被误算外链 |
| 交互一致 | crawl 记录的 6–11 条脚本（title/body/样式/DOM/链接/语言菜单/输入） | `interactions_passed ≥ 5`；每条都有 expected/actual | `site-graph.json.interactions` + `rebuild.json.interactions` | 高：selector 漂移、动画未完成、登录态缺失导致“不可用”而非“不一致” |
| 数据边界 | 每页 `data_boundary` + `backend_required[]` | 每页 ∈ `recorded-snapshot` / `local-mock` / `backend-required`；状态页/跨域 API 必须在 `backend_required[]` | `site-graph.json` + `rebuild.json` + `accept.json` | 高：把错误重定向页当正常页、把 HAR 回放当后端 |
| 证据可复算 | case 目录 | `artifacts[].sha256` 复算一致；`lessons[0]` 含命令与 `rc=`；`repro.status=recorded` | `case.json` + 全部 artifacts | 低：手写数字/伪造截图会在这里暴露 |
| 授权与速率 | `input/scope.txt`、抓取日志 | 目标在 scope；只 GET；主动请求 ≤ 2 rps；非 GET 被 abort 计数 | scope + `site-graph.json.skipped_non_get` | 中：浏览器页面自身 POST 不等于爬虫越界，但必须记录并阻断 |

## 2. 判定公式与落点

### 2.1 路由覆盖

```text
expected  = |route_universe|        # 链接 + buildManifest.sortedPages + sitemap
crawled   = |routes[].route|
missing   = expected - crawled
missing_rate = missing / max(expected, 1)
pass      = missing_rate <= 0.02
```

- 脚本：`site-crawl.py` 的 `coverage`；`site-diff.py` 的 `route_coverage`。
- 反例：只把 `a[href]` 当宇宙，Next.js 站点会漏 `_buildManifest.js` 里的页面。
- 反例：把 `/404`、`/500` 当业务页；应在报告里单列“错误页”，不要混入覆盖率。

### 2.2 像素

```text
diff = |orig_rgb - local_rgb|.max(axis=2)
ratio = count(diff > 8) / total_pixels
threshold = 0.01 (static) | 0.03 (spa)
pass = max(ratio over pages) <= threshold
```

- 固定：`viewport=1280x720`、`dpr=1`、`animations="disabled"`、同一浏览器版本。
- 动画 WebP：`site-crawl.py` 记录 `images[]` 边界框；`site-diff.py` 对 `n_frames>1` 的图片区域计算 `masked_ratio`，但必须同时保留 `raw_ratio`。
- 报告写法：`raw=0.0282, masked=0.0040, threshold=0.03`；不要只写 masked。

### 2.3 DOM

```text
node_ratio  = min(nodes_a, nodes_b) / max(nodes_a, nodes_b)
depth_ratio = min(depth_a, depth_b) / max(depth_a, depth_b)
text_sim    = SequenceMatcher(text_a, text_b).ratio()
tag_sim     = SequenceMatcher(tags_a, tags_b).ratio()
pass = min(node_ratio, depth_ratio, text_sim, tag_sim) >= 0.98
```

- 归一化：删除 `script/style/noscript/template` 及其文本；压缩空白；保留可见 DOM。
- 不归一化随机 token/时间戳会拉低文本相似度；应把它们替换为 `<token>` 再比。
- 只看节点数不看文本：空壳页也能 0.99；三项必须同时达标。

### 2.4 资源

```text
http_404       = count(local_requests[].status == 404)
external_links = count(html/css href/src 指向白名单外 http(s))
assets_failed  = count(assets_failed[])   # 信息项，不单独判 fail
pass = http_404 == 0 and external_links == 0
```

- 白名单：只允许 `api.youtest.me` 这类明确授权的 API host；广告/统计域名默认阻断。
- 外链 `<a>` 可保留 `data-original-href`，但 `href` 必须改为 `#`，否则资源判据失败。
- 软 404：状态 200 但正文是错误页；用 DOM/文本相似度抓出来，不能只看状态码。

### 2.5 交互

crawl 在种子页记录 6–11 条脚本：

| kind | expected | 本地重放判据 |
| :-- | :-- | :-- |
| `title` | 页面标题 | 完全一致或文本相似度 ≥ 0.98 |
| `body_text_head` | 正文前 160 字 | 前缀一致或相似度 ≥ 0.98 |
| `stylesheet_count` | 可见 stylesheet 数 | 本地 ≥ 原站 |
| `dom_nodes` | 渲染后节点数 | 比值 ≥ 0.95（交互容差；主 DOM 判据仍 0.98） |
| `heading_text` | 首个 h1/h2 文本 | 完全一致或相似度 ≥ 0.98 |
| `link_count` | 同源/外链 anchor 数 | 完全一致 |
| `paragraph_count` / `image_count` | 结构计数 | 完全一致 |
| `document_lang` | html lang | 完全一致 |
| `language_menu` | 点击语言按钮后可见选项数 | opened/options 一致 |
| `text_input` | 文本输入框可填 | filled=true 且值一致 |

`interactions_passed ≥ 5` 才算过；少于 5 条说明副本不可交互或脚本选择器失效。

### 2.6 数据边界

| 标签 | 判定条件 | 例子 |
| :-- | :-- | :-- |
| `recorded-snapshot` | 页面无 XHR/fetch 依赖，DOM/资源完整 | example.com；静态文档页 |
| `local-mock` | 页面加载时请求 JSON/API，且响应已录制并可由 HAR 回放 | Next.js `_next/data`、公开配置 API |
| `backend-required` | 线上 302 到 `?error=...`、需要登录/会话/写操作/实时计算 | 答题、计分、榜单、分享、下单 |

`backend_required[]` 每条至少包含：`route` 或 `api`、`reason`；能写清“缺哪个后端能力”更好。
`site-accept.py` 的 `status`：六项全过 = PASS；核心四项过但交互/边界不过 = PARTIAL；核心项失败 = BLOCKED。

## 3. 证据形态（case 目录）

```text
input/scope.txt
artifacts/crawl/site-graph.json
artifacts/crawl/pages/*.html
artifacts/crawl/screenshots/*.png
artifacts/rebuild/rebuild.json
artifacts/rebuild/har.json
artifacts/rebuild/mock/playwright-route.js
artifacts/rebuild/local/*.html
artifacts/rebuild/screenshots/*.png
artifacts/diff.json
artifacts/accept.json
```

每个 artifacts 都在 `case.json.artifacts[]` 里写 `sha256`；`site-accept.py --case` 会复算。

## 4. 误报风险清单

- **动画**：轮播/浮动装饰/入场动画会让同一页面两次截图不同；固定 `animations="disabled"`，动画 WebP 单列 masked。
- **字体**：系统字体缺失导致文本宽度变化；保留 woff2 并报告 fallback。
- **广告/统计**：第三方脚本被阻断后布局变化；外链白名单要显式写，默认阻断并计数。
- **Cloudflare**：challenge 页可能 200；必须看标题/正文/资源，不能只看状态码。
- **软 404**：错误页 200；DOM 文本相似度会暴露。
- **hydration**：JS 保留时 `_next/data` 缺失会重渲染；默认冻结 DOM，`--keep-js` 需重新 diff。
- **动态路由**：无 sitemap/buildManifest 时无法构造宇宙；只能写“已知路由覆盖率”，不能写“全站 100%”。
- **登录态**：公开页抓到不等于登录后页面；Cookie/session 不入库，登录后页面标 backend-required。

## 5. 报告模板（一段话）

```text
目标 <origin>，viewport 1280x720@1x，<N> 路由，missing_rate=<x>；
像素 raw=<x>/masked=<x>（阈值 <t>），DOM min=<x>，404=<n>，外链=<n>，
交互 <p>/<t>；status=<PASS|PARTIAL|BLOCKED>；
backend_required：<route/API + 原因>。
```
