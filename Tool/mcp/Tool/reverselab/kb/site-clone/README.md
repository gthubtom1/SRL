# Site Clone 知识库 — 网站 1:1 复刻

> Board：`site-clone`。配套技能：`Tool/skill/site-clone/SKILL.md`。
> 本库只收“可复现、有判据、有边界”的复刻方法；静态镜像、HAR 回放、DOM 冻结、像素/DOM 差分、后端边界各一篇。
> 维护口径：一篇一招，50–200 行；入口信号 → 可复制命令 → 确认判据 → 失败判据 → 边界。

## 入口（按问题选篇）

| 你现在的处境 | 先读 | 产物 |
| :-- | :-- | :-- |
| 只跑了 wget/HTTrack，想知道够不够 | [01-static-mirror-boundary.md](techniques/01-static-mirror-boundary.md) | 静态/SPA 能力对照 |
| SPA 渲染后 DOM 与线上不一致 | [02-dom-snapshot-freeze.md](techniques/02-dom-snapshot-freeze.md) | 冻结 DOM + 截图 |
| 页面有 XHR/`_next/data`，离线打不开 | [03-har-mock-route.md](techniques/03-har-mock-route.md) | HAR + `page.route` |
| 不确定有没有漏页 | [04-route-coverage-next.md](techniques/04-route-coverage-next.md) | `route_universe` + `missing_rate` |
| 截图/DOM 差异怎么算 | [05-pixel-dom-diff.md](techniques/05-pixel-dom-diff.md) | `diff.json` 六项 |
| 结论被质疑/想降级 | [06-failure-criteria.md](techniques/06-failure-criteria.md) | 失败判据表 + 状态 |
| 登录后页面/写操作怎么办 | [07-auth-backend-boundary.md](techniques/07-auth-backend-boundary.md) | `backend_required[]` |

## 分析链

```text
授权/scope/2 rps
→ Playwright 抓路由宇宙（链接 + _buildManifest.sortedPages + sitemap）
→ 渲染后 DOM + 截图 + GET API 响应
→ 资产落地/外链阻断/链接改写
→ HAR + page.route 回放（如有 API）
→ 像素/DOM/资源/交互/数据边界六项 diff
→ site-accept 给 PASS/PARTIAL/BLOCKED + backend_required
```

## 三条硬判据

1. **可复算**：换机器按 `crawl → rebuild → diff → accept` 重跑，数值一致。
2. **有边界**：每页标 `recorded-snapshot` / `local-mock` / `backend-required`。
3. **不越界**：只 GET、≤2 rps、外链阻断、登录态/写操作不伪造。

补充两条工程判据：

4. **固定参数**：viewport 1280×720、DPR 1、同一 Playwright/Chromium、`animations=disabled`。
5. **证据完整**：命令、rc、sha256、时间窗、失败 route 全部落盘。

## 2026 工具结论（来源）

- wget/HTTrack 只能镜像静态；SPA/登录/后端逻辑拿不到（2026 工具对比；GNU Wget Manual，https://www.gnu.org/software/wget/manual/wget.html ；HTTrack，https://www.httrack.com/html/index.html）。
- Playwright `page.route` + HAR 可做接口 mock（Playwright Mock APIs，https://playwright.dev/docs/mock）。
- webEmbedding（Playwright 抓 DOM/样式/资产/网络，优先复用、必要时重建）、playwright-archaeologist（导出站点/表单/API map）、clone-space-mcp（离线保留动画）、tabapi（录制会话→API/OpenAPI）为 2026 社区工具清单，未见稳定官方规范；引用时标注“2026 社区工具”。

## 失败判据（看到即降级）

- 只跑静态镜像就写 1:1。
- 只抓首页、不解析 buildManifest。
- 截图不固定 viewport/DPR/动画。
- 只比截图不比 DOM，或只比 DOM 不比资源。
- 本地 404/白名单外外链仍写 PASS。
- 交互 <5 条仍写“交互一致”。
- 把 HAR 回放当写操作、把登录后页面标 snapshot。
- 证据缺命令/rc/hash，或触发 429/5xx 仍继续。

详细表与降级路线见 [06-failure-criteria.md](techniques/06-failure-criteria.md) 与
`Tool/skill/site-clone/references/02-failure-criteria.md`。

## 技能参考（深水区）

- [01-criteria.md](../../../../../../Tool/skill/site-clone/references/01-criteria.md) — 六条判据与数值阈值。
- [02-failure-criteria.md](../../../../../../Tool/skill/site-clone/references/02-failure-criteria.md) — 14 行失败判据。
- [03-model-pitfalls.md](../../../../../../Tool/skill/site-clone/references/03-model-pitfalls.md) — 14 条模型失误。
- [04-walkthrough-block-youtest.md](../../../../../../Tool/skill/site-clone/references/04-walkthrough-block-youtest.md) — 真实 Next.js 站点走查。
- [05-static-mirror-limits.md](../../../../../../Tool/skill/site-clone/references/05-static-mirror-limits.md) — wget/HTTrack 边界。
- [06-spa-har-and-mock.md](../../../../../../Tool/skill/site-clone/references/06-spa-har-and-mock.md) — HAR 回放。
- [07-auth-and-backend-boundary.md](../../../../../../Tool/skill/site-clone/references/07-auth-and-backend-boundary.md) — 登录/后端边界。
- [08-tool-ecosystem-2026.md](../../../../../../Tool/skill/site-clone/references/08-tool-ecosystem-2026.md) — 2026 工具矩阵。

## 案例

- `Tool/cases/site-clone01` — 真实 block.youtest.me，静态冻结 PASS，9 条 backend_required。
- `Tool/cases/site-clone02` — 真实 example.com，单页 PASS。
- `Tool/cases/site-clone03` — 本地两页夹具，离线全链路 PASS。
