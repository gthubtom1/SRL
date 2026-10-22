# site-clone-drill01 — block.youtest.me 1:1 复刻演练（crawl / rebuild / diff）

真实目标只读抓取 + 离线重建 + 像素/DOM/网络三方对比。
**只 GET、同源、≤2 rps、12 页、不登录、不提交**。抓取细节见 [input/README.md](input/README.md)。

## 1. 结论

| 维度 | 结果 |
|---|---|
| 路由 | buildManifest 推断 12 条（`/`、`/404`、`/contact`、`/find`、`/player/*` 3 条、`/user/*` 6 条） |
| 同源资源 | 166 个（js 71 / svg 38 / mp3 12 / webp 11 / json 10 / css 9 / woff2 6 / png 4 / lottie 2 / ico+webmanifest+jpg 3） |
| XHR/fetch | 13 次观测，其中 12 次是数据接口（`_next/data/<build>/<route>.json`）；跨域 `api.youtest.me/info/country` 1 次被策略拦截 |
| 像素差异 | 原始 **1.10%**；剔除动画 WebP 包围盒后 **0.00%**（全部 12 页均为 0） |
| DOM 相似度 | **0.9765**（节点 0.30 / 文本 3-gram 0.35 / 标签序列 0.35 加权） |
| 离线外联残留 | 28 次尝试、3 个主机，**unexpected = 0**（见 §5 白名单） |
| 数据边界 | recorded-snapshot 5 页；backend-required 7 页；local-mock 0 页 |

逐页：

| 路由 | 原始像素差 | 静态像素差* | DOM | 动画遮罩占比 |
|---|---|---|---|---|
| `/` | 1.50% | 0.00% | 99.5% | 4.2% |
| `/404` | 2.54% | 0.00% | 98.7% | 8.4% |
| `/contact` | 0.00% | 0.00% | 99.4% | 0.0% |
| `/find` | 1.58% | 0.00% | 95.3% | 4.2% |
| `/player/completed` | 1.58% | 0.00% | 95.3% | 4.2% |
| `/player/name` | 1.58% | 0.00% | 99.5% | 4.2% |
| `/player/playing` | 1.58% | 0.00% | 95.5% | 4.2% |
| `/user/creating` | 0.01% | 0.00% | 92.9% | 1.9% |
| `/user/name` | 0.05% | 0.00% | 97.1% | 1.9% |
| `/user/scoreboard` | 1.26% | 0.00% | 99.5% | 4.2% |
| `/user/share` | 1.58% | 0.00% | 99.5% | 4.2% |
| `/user/scoreboard/answers` | 0.00% | 0.00% | 99.4% | 0.0% |

\* 静态像素差 = 排除动画 WebP（`ANIM` 块）包围盒后，在剩余像素上的差异占比。
全站汇总：原始 1.10%，静态 **0.0000%**，DOM **0.9765**。

## 2. 流水线

```
scripts/crawl.py       -> artifacts/crawl/{html,shots,dom,assets,data,network.json,har.json,routes.json}
scripts/rebuild.py     -> artifacts/site/ + artifacts/site/_replay/{mocks.json,bodies/} + rebuild-report.json
scripts/replay_diff.py -> artifacts/offline/{shots,dom,network.json} + artifacts/diff.json
scripts/manifest.py    -> artifacts/MANIFEST.sha256（412 个文件）
```

### crawl

- 路由来自 `_buildManifest.js` 的 `sortedPages`，并用页面内 `<a href>` 复核；构建清单里的 per-route chunk 与
  `_next/data/<build>/<route>.json` 全部补抓，避免离线时 404。
- `page.route` 统一裁决：同源 GET 放行并经过 0.5 s 令牌桶；跨域或非 GET 直接 `abort()` 并写入
  `blocked_by_policy`（60 次：adsense 12 / cloudflare RUM 32 / 母品牌 promo 15 / `api.youtest.me` 1）。
- 响应体按 URL 保存；文档存 `html/`，数据存 `data/`，其余存 `assets/`；`har.json` 记录最小 HAR 字段。
- 截图前：等 `LoadingScreen` 消失 → DOM 连续 2 s 无变化 → 禁动画 CSS → 固定 `Math.random` 与 rAF 时间戳。

### rebuild

- 路由 → `<route>/index.html`；资源按 URL path 落盘；`https://block.youtest.me/` → `/`。
- 剔除 24 个第三方脚本标签（Cloudflare beacon / AdSense / funding-choices），它们是跨域广告/追踪，抓取阶段本就已拦截。
- 录制到的 `_next/data` 响应写入 `_replay/mocks.json`（3 个唯一体，按 path 与 path?query 双键），供回放。
- 报告 dangling 本地引用 = **0**（排除 JS 字符串前缀碎片）。

### replay / diff

- 内置 `ThreadingHTTPServer` 服务 `artifacts/site/`；Playwright `page.route` 对同源 `xhr/fetch` 与
  `_next/data/*` 用 `fulfill()` 回放录制响应（本次 12 次命中），其余本地请求走文件；外联一律 abort 并记录。
- **像素**：1280×800、DPR=1 截图。任一 RGB 通道 `|Δ| > 12` 记为差异像素；`diff_ratio` 为全图占比。
  `diff_ratio_static` 先遮罩动画 WebP（逐帧不可比）再算，分母为未遮罩像素。
- **DOM**：`nodes = 1 - |a-b|/max(a,b)`；`text` = `innerText` 归一化后字符 3-gram Dice；
  `struct` = 前序标签序列 `difflib.SequenceMatcher.ratio`；`score = 0.30*nodes + 0.35*text + 0.35*struct`。
- 逐页数据边界判定：最终 URL 与路由不一致（路由守卫重定向）→ `backend-required`；否则 `recorded-snapshot`。

## 3. 数据边界（逐页）

| 路由 | 边界 | 依据 |
|---|---|---|
| `/`、`/404`、`/contact`、`/user/scoreboard/answers`、`/user/name` | `recorded-snapshot` | 静态导出 HTML + 录制的 `_next/data`，离线完整渲染 |
| `/find`、`/player/completed`、`/player/name`、`/player/playing`、`/user/creating`、`/user/scoreboard`、`/user/share` | `backend-required` | 无 user/player 会话时被路由守卫重定向（如 `?error=user_data_missing_scoreboard`），真实内容必须后端 |
| `local-mock` | 0 页 | 未构造任何假数据；回放体全部来自录制 |

必须后端的能力（`backend_required_features`）：创建测验、玩家加入/答题、成绩榜与逐题答案、分享落地页、
`api.youtest.me/info/country` 国家查询。

## 4. 1:1 到哪一层、缺哪一层

- **已到**：公开静态 UI 的 1:1 —— 12 条路由的 HTML/CSS/JS/字体/图片/音频/Lottie 全部本地化，
  静态像素差 0.00%，DOM 0.9765；同源 `_next/data` 可离线回放，客户端路由、语言选择器、表单壳、404 均可用。
- **缺**：所有**写入/会话态**链路 —— 创建测验（POST）、玩家加入与答题、成绩榜、分享页、账号；
  这些页面在无后端时只会重定向或停留在空壳，已按 `backend-required` 标注。
- **缺**：跨域 `api.youtest.me/info/country`（国家/旗帜来源）与母品牌 `youtest.me/static/assets/promo/*` 图片
  —— 受"同源"约束未抓取；离线时请求被拦截，页面回退默认旗帜/占位图。
- **结论**：这是"静态前端 1:1 + 数据边界明确的离线快照"，不是可独立运行的完整站点。

## 5. 离线外联残留（diff.json → network）

`verdict = whitelist-only`，`unexpected = []`。28 次外联尝试全部被 `abort()`：

| 主机 | 次数 | 分类 | 原因 |
|---|---|---|---|
| `api.youtest.me` | 1 | backend-required-api | `/info/country` 跨域数据接口，同源范围外 |
| `pagead2.googlesyndication.com` | 12 | policy-excluded-third-party | AdSense 脚本，抓取阶段已拦截 |
| `youtest.me` | 15 | policy-excluded-cross-origin-brand-asset | 母品牌 promo 图片，违反同源约束 |

## 6. 复现

```bash
cd Tool/cases/site-clone-drill01
python scripts/crawl.py          # rc=0，12/12 页，约 6 分钟（2 rps）
python scripts/rebuild.py        # rc=0，assets=166，dangling=0
python scripts/replay_diff.py    # rc=0，生成 artifacts/diff.json
python scripts/manifest.py       # rc=0，412 个文件 sha256
python -m http.server 8765 --directory artifacts/site   # 手动查看离线副本
```

## 7. 已知卡点 / 风险

- **动画 WebP**：`characters.webp`、`bubu.webp`、`name-input-bubu-mascot.webp` 等 6 个文件是 APNG 式动画 WebP，
  逐帧不可比；原始像素差主要来自它们。已按包围盒遮罩并单列 `diff_ratio_static`，未用"选一帧"掩盖差异。
- **时间敏感**：抓取与回放均固定随机数与 rAF 时间戳；若目标改版（buildId 变化），需整条流水线重跑。
- **广告/追踪**：离线副本主动剔除 24 个第三方脚本标签，因此"带广告"的原始视觉不在复刻范围内。
- **动态内容**：页面若依赖真实会话（成绩、分享码），离线只能复现其空态/重定向态，不能复现真实数据。
- 未做移动端视口、暗色模式、多语言全量截图；仅 1280×800 / 英文 / 默认主题。
