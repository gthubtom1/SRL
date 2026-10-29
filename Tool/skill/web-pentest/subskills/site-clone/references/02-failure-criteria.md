# site-clone 失败判据表（看到即降级）

> 结论只能落在三种状态：`PASS` / `PARTIAL` / `BLOCKED`。
> 出现本表任一现象，**必须**把结论写成“1:1 完成”；先按“改走哪条”降级或补证。

## 1. 失败判据表（14 行）

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| 只跑了 `wget --mirror` / HTTrack，就写“整站 1:1” | 证据不合格 | 改用 `site-crawl.py` 渲染后抓 DOM/截图/API；静态镜像只作资产参考 | 0.5–2 小时/站 |
| 只抓首页，路由覆盖率却写 100% | 路由判据失败 | 解析 `_buildManifest.js` 的 `sortedPages` + `sitemap.xml`，重建 `route_universe` | 20–60 分钟 |
| `missing_rate > 0.02` | BLOCKED（核心项） | 补抓缺失 route；若缺失是动态路由，写“已知路由覆盖率”并降 PARTIAL | 取决于页数 |
| 截图 viewport/DPR 不一致 | 像素判据无效 | 固定 1280×720@1x，重抓/重截；报告写清设备参数 | 10–30 分钟 |
| 未禁用动画，像素差 5%+ | 假差异 | `animations="disabled"`；动画 WebP 用 `masked_ratio` 单列并保留 `raw_ratio` | 10–20 分钟 |
| 只比截图，不比 DOM | DOM 判据缺失 | 补 `site-diff.py` 的节点/层级/文本三项；截图相同不代表结构对 | 10 分钟 |
| 只比 DOM，不比资源 | 资源判据缺失 | 查 `http_404`、`external_links`、CSS `url()`、字体/图片 | 10–20 分钟 |
| 本地 404 > 0 | 资源判据失败 | 补下载资产；检查 query string、`srcset`、CSS 相对路径 | 20–60 分钟 |
| 白名单外还有 http(s) 外链 | 资源判据失败 | 改写为 `/__external__/blocked.*` 或 `data:`；`<a>` 用 `data-original-href` | 10 分钟 |
| 交互通过 < 5 条 | 交互判据失败 → PARTIAL | 增加稳定 selector（aria-label/role）；补 title/body/input/link 等 5 条以上 | 30–60 分钟 |
| `backend_required` 为空，但页面线上 302 到 `?error=...` | 数据边界判据失败 | 逐页标注；把状态页/跨域 API 写入 `backend_required[]` | 20 分钟 |
| 把 HAR 回放当真实写操作 | 结论越界 → BLOCKED | HAR 只证明读取快照；提交/计分/登录必须标 `backend-required` | 需真实后端 |
| 登录后页面被写成 `recorded-snapshot` | 数据边界错误 | 登录态单独授权、单独抓取；否则标 `backend-required` | 0.5–1 天（授权） |
| 目标 429/5xx 仍继续抓 | 违规 | 立即退避/停止；记录阈值；重跑时降到 1 rps 或换窗口 | 可能封 IP |
| 证据缺命令/rc/sha256 | 证据不合格 | 回填 `case.json.lessons` 与 artifacts hash；无法回填则作废 | 可能全损 |

## 2. 降级路线（按优先级）

```text
发现失败现象
→ 先判断是“抓取缺失”还是“能力不可复制”
→ 抓取缺失：补 route/资产/交互，重跑 diff
→ 能力不可复制（登录/写操作/实时计算）：标 backend-required，结论降 PARTIAL
→ 核心四项（路由/像素/DOM/资源）任一失败：结论 BLOCKED
→ 只有交互/边界失败：结论 PARTIAL，不写 PASS
```

## 3. 状态判定（与 `site-accept.py` 一致）

| 条件 | 状态 | 报告写法 |
| :-- | :-- | :-- |
| 六项全过 | `PASS` | “静态副本 1:1；backend_required 见清单” |
| 路由/像素/DOM/资源全过；交互 <5 或边界未标全 | `PARTIAL` | “视觉/结构达标，交互或数据边界未闭环” |
| 路由/像素/DOM/资源任一失败 | `BLOCKED` | “不满足 1:1；失败项与 route 见 diff.json” |
| 缺 crawl/rebuild/diff 产物 | `BLOCKED` | “证据链不完整” |

## 4. 常见“假通过”

- **空壳页**：DOM 节点数很少但文本相似度 1.0；必须同时看节点数/层级。
- **软 404**：状态 200、标题是错误页；看正文与 DOM，不看状态码。
- **Cloudflare challenge**：200 + “Just a moment...”；看标题/资源，必要时换授权窗口。
- **动画蒙版过大**：`masked_ratio` 很高但 `raw_ratio` 也高；必须报告 raw，不能只报 masked。
- **HAR 全命中**：请求都 fulfill，但写操作仍没发生；数据边界必须写 `backend-required`。
- **本地预览缓存**：浏览器缓存导致 0 404；用新 context/禁用缓存重跑。

## 5. 负结果也有价值

失败时至少留下：

1. 失败项与数值（`diff.json` 路径）。
2. 失败 route/API 列表（`backend_required[]`）。
3. 停止理由（授权/速率/Cloudflare/后端缺失）。
4. 下一步（补授权、补资产、换 HAR、改走 web-pentest/后端复刻）。

这样下一个人不用重复烧同样的时间，也不会把 `PARTIAL` 误读成 `PASS`。
