---
name: site-clone
description: "【网站 1:1 复刻】授权+同源白名单+≤2 rps 下用 Playwright 抓路由/资产/API 与 DOM 快照做离线副本，按 6 条机检判据给 PASS/PARTIAL/BLOCKED。"
---

# 网站 1:1 复刻（site-clone）

> 唯一交付标准：**换一台干净机器，按 `crawl → rebuild → diff → accept` 重跑，同一组数值可复算**。
> “看起来一样”不算；只有**路由覆盖、截图、DOM、资源、交互、数据边界**六项都有数值才算完成。
> 判据表：`references/01-criteria.md`；失败判据：`references/02-failure-criteria.md`；
> 模型失误：`references/03-model-pitfalls.md`；真实走查：`references/04-walkthrough-block-youtest.md`。
> 矩阵：`Tool/config/site-clone-matrix.json`；KB：`Tool/mcp/Tool/reverselab/kb/site-clone/README.md`。

## 1. 适用 / 范围与路由（边界）

适用：

- 已获书面授权，对同一 origin 的公开页面、静态资源、可录制 API 做只读复刻。
- 需要把线上站点变成可离线打开、可截图比对、可证据留存的副本。
- 需要判断“哪些页面能 1:1、哪些必须 HAR mock、哪些必须真实后端”。
- 竞品/历史版本取证、UI 回归、迁移前基线、培训演示环境。

范围与路由（先停手或转交）：

- 没有授权、scope 不清、目标不属于甲方：**不发第一个请求**。
- 需要账号密码、Cookie、Token 才能看的页面：默认按 scope 清单执行登录态；确需登录必须单独授权并记录会话边界。
- 需要复刻后端写操作（下单、答题提交、计分、发帖、支付）：本技能只标注 `backend-required`，不伪造成功。
- 绕过 Cloudflare/WAF/验证码、撞库、批量注册、压测：拒绝。
- 纯漏洞验证 → `web-pentest`；客户端/APK/固件 → 对应域；协议逆向 → `protocol-plugin`。

## 2. 六条判据（全部可机检）

> 完整表（场景 / 输入面 / 判据 / 证据形态 / 误报风险）见 `references/01-criteria.md`。

| # | 判据 | 机检字段 | 通过阈值 |
| :- | :-- | :-- | :-- |
| 1 | 路由覆盖 | `missing_rate` | 同源 URL 集合缺失率 ≤ 0.02 |
| 2 | 像素一致 | `ratio` / `raw_ratio` / `masked_ratio` | 同视口/DPR：静态 ≤ 0.01，SPA ≤ 0.03 |
| 3 | DOM 一致 | 节点数、层级、文本相似度 | 三者均 ≥ 0.98 |
| 4 | 资源完整 | `http_404` / `external_links` | 0 个 404；白名单外 0 个外链 |
| 5 | 交互一致 | `interactions_passed` | ≥ 5 条关键交互可在离线副本重放 |
| 6 | 数据边界 | `backend_required` / 逐页标签 | 每页 ∈ recorded-snapshot / local-mock / backend-required |

三条工程约束（与判据同等重要）：

- **只 GET**：抓取与重建阶段必须 POST/PUT/DELETE/PATCH；浏览器页面自身发出的非 GET 请求在 crawl 中直接 abort 并计数。
- **≤2 rps**：页面导航和资产下载统一限速；浏览器子资源由页面自然加载，但爬虫主动请求必须限速。
- **确定性**：`site-graph.json` / `rebuild.json` / `diff.json` 不写 `generated_at`；排序固定；截图使用固定 viewport/DPR 与 `animations="disabled"`。

## 3. 数据边界三态（必须先标注，再谈 1:1）

| 标签 | 含义 | 证据 | 能否 1:1 |
| :-- | :-- | :-- | :-- |
| `recorded-snapshot` | 页面是抓取时的静态 DOM/资源快照 | HTML + 截图 + 资产 hash | 是（只读） |
| `local-mock` | 页面依赖的 JSON/API 已录制，用 HAR + `page.route` 回放 | HAR entry + mock 脚本 | 条件式（只读） |
| `backend-required` | 页面依赖登录态/写操作/实时计算，录制无法替代 | 线上 302 `?error=...`、跨域 API、写接口 | 否，必须标 PARTIAL/BLOCKED |

规则：

1. 一页一标签，写在 `site-graph.json.data_boundary` 与 `rebuild.json.data_boundary`。
2. 任何 `backend-required` 页面都必须进入 `backend_required[]`，写清 route/API 与原因。
3. `backend-required` 不是失败免责声明：它必须让验收结论停在 PARTIAL，而不是硬写 PASS。
4. 登录态单独标注：能拿到公开页 ≠ 能复刻登录后页面；Cookie/session 不写入仓库。

## 4. 工作流（四步，每步有完成判据）

### 步骤 0：授权与 scope

```bash
mkdir -p Tool/cases/site-clone01/input
printf '%s\n' 'target=https://block.youtest.me/' 'authorization=written scope' > Tool/cases/site-clone01/input/scope.txt
```

完成判据：scope 文件包含 target、授权人/工单、允许 host、速率、禁止动作；Cloudflare/WAF 目标写明可能拦截。

### 步骤 1：抓取（site-crawl.py）

```bash
python Tool/skill/site-clone/scripts/site-crawl.py \
  --url https://block.youtest.me/ \
  --out Tool/cases/site-clone01/artifacts/crawl \
  --max-pages 20 --max-depth 3 --rps 2 --allow-host api.youtest.me
```

- 同源 GET；非 GET abort；离源请求 abort 并记入 `external[]`。
- 路由宇宙来自：种子 HTML 链接 + `_buildManifest.js` 的 `sortedPages` + `sitemap.xml`。
- 每页输出 `pages/<slug>.html`、`screenshots/<slug>.png`、`images[]` 边界框。
- 输出 `site-graph.json`：`routes[]` / `assets[]` / `api[]` / `external[]` / `coverage` / `interactions[]` / `data_boundary`。

完成判据：`missing_rate ≤ 0.02`；每页有 HTML + 截图；API 响应体已存 `api/`；`backend_required` 非空（如果目标有状态页）。

### 步骤 2：重建（site-rebuild.py）

```bash
python Tool/skill/site-clone/scripts/site-rebuild.py \
  --crawl Tool/cases/site-clone01/artifacts/crawl \
  --out Tool/cases/site-clone01/artifacts/rebuild --rps 20
```

- 下载同源资产到 `site/`，保留原路径；离源资源改写到 `/__external__/blocked.*` 或数据 URI。
- 默认 **冻结 DOM**：删除 app script，保留抓取时的渲染后 DOM/CSS；这是静态 1:1 的确定性模式。
- `--keep-js` 保留脚本，用于 SPA/HAR 模式；通常 DOM/像素会漂移，必须重新 diff。
- 生成 `har.json` + `mock/playwright-route.js`，供 `page.route` 回放录制 API/`_next/data`。
- 本地 `http.server` 预览：`--serve --port 8787`；`--serve-seconds 5` 可自停。
- 输出 `rebuild.json`：pages/assets/HAR/local_requests/interactions/data_boundary。

完成判据：`http_404=0`、`external_links=0`、HAR 条数等于录制的 API 数、本地截图与 DOM 已生成。

### 步骤 3：三路差分（site-diff.py）

```bash
python Tool/skill/site-clone/scripts/site-diff.py \
  --crawl Tool/cases/site-clone01/artifacts/crawl \
  --rebuild Tool/cases/site-clone01/artifacts/rebuild \
  --out Tool/cases/site-clone01/artifacts/diff.json
```

- 像素：Pillow + numpy；`ratio` 为差异像素占比；动画 WebP 区域单独 `masked_ratio`，同时保留 `raw_ratio`。
- DOM：去掉 script/style/noscript 后比较节点数、层级、标签序列、文本相似度。
- 请求集合：原站资源/API 路径 vs 本地请求/状态；统计 404 与外链。
- 交互：把 crawl 记录的脚本在本地副本重放，逐条给 pass。
- 输出 `criteria` 六项 + `summary.status`（PASS/PARTIAL）。

完成判据：六项都有布尔与数值；失败项能定位到 route；`backend_required` 透传。

### 步骤 4：验收（site-accept.py）

```bash
python Tool/skill/site-clone/scripts/site-accept.py --case Tool/cases/site-clone01
python Tool/skill/site-clone/scripts/site-accept.py --root .
python Tool/skill/site-clone/scripts/site-accept.py --self-test
```

- `PASS`：六项全过。
- `PARTIAL`：核心四项（路由/像素/DOM/资源）过，但交互 <5 或数据边界未标全。
- `BLOCKED`：路由/像素/DOM/资源任一失败，或缺失 diff/重建产物。
- 输出 `backend_required[]`；案例证据 hash/refs/repro 同时校验。

## 5. 失败判据（看到即降级）

> 完整 14 行表见 `references/02-failure-criteria.md`；KB 版见 `techniques/06-failure-criteria.md`。

- 只跑了 `wget --mirror`/HTTrack 就宣称 1:1：静态镜像拿不到 SPA 渲染结果、登录态、后端逻辑。
- 路由覆盖只看首页链接：不解析 `_buildManifest.js`/sitemap，漏页却被算成 100%。
- 截图对比未固定 viewport/DPR/动画：像素差随窗口和动画帧漂移。
- 只比截图不比 DOM：截图相同但节点/文本/交互已坏。
- 只比 DOM 不比资源：DOM 对，但 CSS/字体/图片 404，页面实际不可用。
- 只 GET 页面却让浏览器 POST 登录/提交：越界，且会把写操作带进证据。
- 把 HAR 回放当真实后端：HAR 只能重放录制响应，不能证明写操作/实时计算。
- 把 Cloudflare 拦截页当站点首页：状态 200 也可能是 challenge，必须看标题/正文/资源。
- 交互只点一个按钮就写“交互一致”：少于 5 条关键交互不足以支撑。
- 证据缺命令/rc/hash：无法复算，直接作废。
- 目标返回 429/5xx 还继续：立即退避；继续跑会变成可用性事故。
- 未授权、越出白名单、抓取个人数据：停止并报告。

## 6. 模型常见失误（≥10 条）

> 14 条完整版见 `references/03-model-pitfalls.md`。

1. 把“静态镜像工具”当万能 → wget/HTTrack 只保存服务器返回的 HTML/资源；SPA 的 DOM、登录后页面、XHR 数据拿不到。
2. 只抓首页 → Next.js 静态导出的页面表在 `_buildManifest.js`，不解析就漏 10 个路由。
3. 不固定 viewport/DPR → 同一页在 1280×720 与 1440×900 下像素差异不可比。
4. 截图不禁用动画 → 动画帧/轮播/浮动装饰造成假差异；用 `animations="disabled"` 并在报告里注明。
5. 把 JS 删除后不修 inline `opacity:0` → 入场动画元素永久隐藏，截图缺 logo/插画。
6. 保留 JS 却由相邻能力承担 `_next/data` → hydration 报错或页面重渲染，DOM/像素双漂移。
7. 把跨域 API 当同源资产 → `api.youtest.me` 这类请求必须进 HAR/mock，不能下载成静态文件。
8. 把 HAR 回放当写接口 → 只能返回录制响应；提交/计分/登录仍应标 `backend-required`。
9. 只看状态码 200 → Cloudflare challenge、软 404、错误重定向都可能 200。
10. 用页面源码代替渲染后 DOM → SPA 源码只有壳；必须 `page.content()` 后再比对。
11. 用文本相似度替代节点/层级 → 文本一样但结构塌了；三项都要算。
12. 忽略字体/图片 404 → DOM 和文本都对，视觉仍崩；资源集合必须单列。
13. 交互脚本复用不稳定 selector → 位置/文本选择器会漂；用 aria-label、role、可见性过滤。
14. 把 `backend-required` 写成“已复刻” → 验收必须 PARTIAL，不能拿静态快照冒充后端。

## 7. 2026 工具生态（能力与缺口，写报告必须标注来源）

| 工具/项目 | 2026 能力 | 缺口 | 来源 |
| :-- | :-- | :-- | :-- |
| wget `--mirror` | 静态 HTML/资源递归下载、限速、robots | 不执行 JS；SPA 渲染、登录态、XHR 数据拿不到 | GNU Wget Manual, https://www.gnu.org/software/wget/manual/wget.html |
| HTTrack | 整站静态镜像、链接改写、断点续传 | 同上；依赖服务器直出 HTML | HTTrack docs, https://www.httrack.com/html/index.html |
| Playwright `page.route` | 拦截/fulfill 请求，HAR 回放，离线 mock | 不是后端；写操作/实时状态仍需真实服务 | Playwright Mock APIs, https://playwright.dev/docs/mock ；page.route, https://playwright.dev/docs/api/class-page#page-route |
| Chrome DevTools HAR | 录制请求/响应，导出 `.har` | 只含录制窗口；登录态/Cookie 需另行授权 | Chrome DevTools Network reference, https://developer.chrome.com/docs/devtools/network/reference/#save-as-har |
| webEmbedding | 用 Playwright 抓 DOM/样式/资产/网络，优先复用、必要时重建 | 社区工具，无稳定官方规范；复杂动画仍需人工 | 2026 社区工具清单（名称/能力由用户提供；未见官方规范） |
| playwright-archaeologist | 导出站点地图、表单、API map | 同上；语义/业务规则仍需人工 | 2026 社区工具清单（名称/能力由用户提供） |
| clone-space-mcp | 离线保留动画/交互快照 | 同上；后端状态不可复制 | 2026 社区工具清单（名称/能力由用户提供） |
| tabapi | 录制会话 → API/OpenAPI 描述 | 同上；只覆盖录制到的请求 | 2026 社区工具清单（名称/能力由用户提供） |

结论（2026 现状）：

- **静态站**：wget/HTTrack 可接近 1:1，但仍要补截图/DOM/资源/交互四类证据。
- **SPA/Next.js**：必须用 Playwright 渲染后抓 DOM，并把 `_next/data`/API 录成 HAR，用 `page.route` 回放。
- **登录态/后端逻辑**：工具只能录制，不能复制；正确做法是标 `backend-required`，给真实后端接口清单，不伪造成功。

## 8. 案例与 KB

- `Tool/cases/site-clone01`：真实 `block.youtest.me`（Next.js + Cloudflare），12 路由、141 资产、7 API，PASS（静态冻结），9 条 backend-required。
- `Tool/cases/site-clone02`：真实 `example.com`（静态单页），1 路由，像素 0.0、DOM 1.0，PASS。
- `Tool/cases/site-clone03`：本地两页 HTML/CSS/SVG 夹具，3 路由，PASS，可离线复跑。
- KB：`Tool/mcp/Tool/reverselab/kb/site-clone/README.md`，7 篇 technique + 失败判据。

## 9. 交付清单（缺一不算完成）

- [ ] `input/scope.txt`：目标、授权、白名单、速率、禁止动作。
- [ ] `artifacts/crawl/site-graph.json`：routes/assets/api/external/coverage/interactions/data_boundary。
- [ ] `artifacts/rebuild/rebuild.json` + `har.json` + `mock/playwright-route.js`。
- [ ] `artifacts/diff.json`：六项布尔 + 数值 + 失败 route。
- [ ] `artifacts/accept.json`：PASS/PARTIAL/BLOCKED + `backend_required[]`。
- [ ] 命令、rc、sha256、viewport/DPR、抓取时间窗写进 `case.json.lessons`。
- [ ] 报告明确写：哪些页面是 `recorded-snapshot`、哪些 `local-mock`、哪些 `backend-required`。
- [ ] 不包含 Cookie/Token/个人数据；不包含未授权目标的原始内容。

## 10. 相关引用

- `references/01-criteria.md` — 六条判据 + 场景/输入面/证据/误报。
- `references/02-failure-criteria.md` — 14 行失败判据与降级路线。
- `references/03-model-pitfalls.md` — 14 条模型失误。
- `references/04-walkthrough-block-youtest.md` — 真实抓取/重建/diff 走查。
- `references/05-static-mirror-limits.md` — wget/HTTrack 边界与 2026 对比。
- `references/06-spa-har-and-mock.md` — Playwright route/HAR 回放。
- `references/07-auth-and-backend-boundary.md` — 登录态与后端不可复制。
- `references/08-tool-ecosystem-2026.md` — 2026 工具能力矩阵与出处。
- `Tool/config/site-clone-matrix.json` — 14 条类目判据。
- `Tool/mcp/Tool/reverselab/kb/site-clone/README.md` — KB 索引。
