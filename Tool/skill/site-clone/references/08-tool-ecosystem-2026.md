# 2026 工具生态：抓取、复刻、回放、验收

> 本页只回答一个问题：**2026 年这些工具各自能拿到什么，拿不到什么。**
> 引用规则：官方文档给链接；社区工具标注“2026 社区工具清单（名称/能力由用户提供）”，不写成厂商承诺。

## 1. 能力矩阵

| 工具 | 抓 HTML | 执行 JS | 抓 DOM | 截图 | 抓 XHR/API | HAR 回放 | 登录态 | 后端逻辑 | 来源 |
| :-- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-- |
| wget `--mirror` | 是 | 否 | 否 | 否 | 否 | 否 | 否 | 否 | https://www.gnu.org/software/wget/manual/wget.html |
| HTTrack | 是 | 否 | 否 | 否 | 否 | 否 | 否 | 否 | https://www.httrack.com/html/index.html |
| Playwright crawl | 是 | 是 | 是 | 是 | 是 | 是（`page.route`） | 需授权 | 否 | https://playwright.dev/docs/mock |
| Chrome DevTools HAR | 是 | 是 | 否 | 否 | 是 | 导出 | 录制窗口 | 否 | https://developer.chrome.com/docs/devtools/network/reference/#save-as-har |
| webEmbedding | 是 | 是 | 是 | 是 | 是 | 可接 | 需授权 | 否 | 2026 社区工具清单 |
| playwright-archaeologist | 是 | 是 | 是 | 可选 | 是 | 可接 | 需授权 | 否 | 2026 社区工具清单 |
| clone-space-mcp | 是 | 是 | 是 | 是 | 是 | 可接 | 需授权 | 否 | 2026 社区工具清单 |
| tabapi | 可选 | 是 | 否 | 否 | 是 | 可接 | 录制会话 | 否 | 2026 社区工具清单 |
| 本域 site-* 脚本 | 是 | 是 | 是 | 是 | 是 | 是 | 默认不碰 | 标边界 | 本仓库 |

读法：

- **wget/HTTrack 只能镜像静态站**；SPA/登录/后端逻辑拿不到（2026 工具对比结论）。
- **Playwright 是抓取底座**：渲染、截图、DOM、网络、`page.route` 都在同一套 API。
- **webEmbedding**：用 Playwright 抓 DOM/样式/资产/网络，优先复用、必要时重建；适合把页面拆成“可复用组件 + 需重建部分”。
- **playwright-archaeologist**：导出站点/表单/API map；适合先画地图，再决定抓什么。
- **clone-space-mcp**：离线保留动画；静态镜像会丢动画/交互状态，它是补充。
- **tabapi**：录制会话 → API/OpenAPI；适合把 XHR 变成接口清单，但仍只覆盖录制到的请求。
- **HAR**：通用交换格式，Chrome/Playwright 都能导出；只保存请求/响应，不保存后端状态。

## 2. 选型决策树

```text
目标页面是服务器直出、无 JS、无登录？
├─ 是 → wget/HTTrack 可做资产镜像；仍用 site-crawl 补截图/DOM/路由判据
└─ 否 → Playwright 渲染
   ├─ 页面有 XHR/fetch？
   │  ├─ 是 → 录 HAR → rebuild 生成 page.route mock → 标 local-mock
   │  └─ 否 → 冻结 DOM → recorded-snapshot
   ├─ 需要登录？
   │  ├─ 有授权 → 单独 profile/context，只读；登录后页面最多 local-mock
   │  └─ 无授权 → 标 backend-required，停止
   └─ 有写操作/实时计算？
      └─ 是 → backend-required；HAR 不能替代
```

## 3. 2026 工具对比的三个结论

1. **静态镜像不是复刻**：wget/HTTrack 只保存服务器返回的字节；DOM/截图/交互/API 需要浏览器。
2. **HAR 是读快照，不是后端**：Playwright `page.route` 能回放 GET 响应，不能产生写操作/事务。
3. **社区工具解决“保留”而非“复制”**：webEmbedding/clone-space-mcp 保留 DOM/动画；tabapi 保留 API 形状；登录态/后端逻辑仍不可复制。

## 4. 工具→判据映射

| 判据 | 主要工具 | 产物 |
| :-- | :-- | :-- |
| 路由覆盖 | Playwright + `_buildManifest.js` | `site-graph.json.route_universe` |
| 像素一致 | Playwright 截图 + Pillow/numpy | `diff.json.pixel` |
| DOM 一致 | Playwright `page.content()` + HTMLParser | `diff.json.dom` |
| 资源完整 | Playwright response + 本地 http.server | `diff.json.resources` |
| 交互一致 | Playwright locator/fill/click | `interactions[]` |
| 数据边界 | 人工判定 + HAR/302 证据 | `backend_required[]` |
| HAR 回放 | Playwright `page.route` | `har.json` + `mock/playwright-route.js` |
| 动画保留 | clone-space-mcp（可选） | 动画快照/说明 |

## 5. 版本与复现

- 记录 Playwright 版本、Chromium 版本、viewport/DPR、OS；
- 记录抓取时间窗（UTC）；
- 记录 wget/HTTrack 版本（如果用了）；
- 记录 HAR 生成方式与脱敏规则；
- 记录社区工具版本/commit（如果有）；
- 报告写“在 X 版本、Y 时间窗可复现”，不写“永久有效”。

## 6. 失败判据

- 用 2026 工具名当结论，没有命令/rc/产物 → 证据不合格。
- 引用社区工具却不标“社区/未见官方规范” → 来源不实。
- 把 wget/HTTrack 产物直接当 DOM/截图证据 → 判据不成立。
- 把 HAR 回放当写操作 → 结论越界。
- 不记录版本/时间窗 → 不可复现。

## 7. 一句话

> 2026 年的正确组合是：**Playwright 抓、HAR 回放、静态镜像搬资产、社区工具保留动画/地图**；
> 后端与登录态不在这条工具链的能力范围内，必须显式标边界。

## 8. 任务卡源名（`Tool/config/taskcard-sources.json`，site-clone 跨域借用）

本域 24 张任务卡的源技能名（借自 web-pentest / plugin-targets），用于对题性核对：

- performing-web-application-penetration-test
- testing-api-security-with-owasp-top-10
- detecting-shadow-api-endpoints
- performing-subdomain-enumeration-with-subfinder
- performing-web-application-firewall-bypass
- analyzing-browser-forensics-with-hindsight
- implementing-browser-isolation-for-zero-trust
- performing-web-application-vulnerability-triage
- implementing-api-schema-validation-security
- extracting-browser-history-artifacts
- performing-web-application-vulnerability-triage
- detecting-shadow-api-endpoints
