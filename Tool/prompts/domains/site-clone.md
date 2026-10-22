# site-clone 任务卡（24 张）

> 入口：`Tool/skill/site-clone/SKILL.md`。每张卡固定六段，`reference` 指向本域 reference。
> 统一前置：书面授权 + 同源白名单 + ≤2 rps + 只 GET；任何越界立即停。
> 统一失败口径：见 `Tool/skill/site-clone/references/02-failure-criteria.md`，不把 PARTIAL 写成 PASS。
> 源名来自 `Tool/config/taskcard-sources.json`；site-clone 为第 11 域，卡源跨域借用并标注「借」。

### 01 wget 静态镜像边界（源：performing-web-application-penetration-test（借 web-pentest））
- 触发词：`wget`、`--mirror`、静态镜像、整站下载、SPA 壳
- 前置：已授权；目标可能是服务器直出 HTML；明确禁止写操作；先看首页源码
- 步骤：1) `curl -sS https://target/ | head -40` 判断是否只有 root 壳；2) `wget --mirror --page-requisites --convert-links --wait=0.5 --limit-rate=200k https://target/`；3) 用 `site-crawl.py --url https://target/ --out work/crawl --rps 2` 补渲染 DOM/截图
- 判据：静态站且无 JS/登录/API 才可用 wget 作资产参考；仍需 `missing_rate`、像素、DOM、404/外链四项数值
- 失败判据：只跑 wget 就写 1:1；SPA 只抓到壳；登录后页面缺失
- reference：Tool/skill/site-clone/references/05-static-mirror-limits.md

### 02 HTTrack 资产镜像（源：performing-web-application-penetration-test（借 web-pentest））
- 触发词：`HTTrack`、httrack、镜像、离线资产、链接改写
- 前置：已授权；目标允许递归 GET；设置限速与深度；不抓第三方广告
- 步骤：1) `httrack https://static.example/ -O work/httrack`；2) 检查下载目录是否只有静态资源；3) `python Tool/skill/site-clone/scripts/site-rebuild.py --crawl work/crawl --out work/rebuild --rps 2` 重建同源资产
- 判据：HTTrack 只作资产参考；页面 DOM/截图/路由必须由 Playwright crawl 产出
- 失败判据：把 HTTrack 目录当完整副本；外链广告一起抓下来；无截图/DOM 数值
- reference：Tool/skill/site-clone/references/05-static-mirror-limits.md

### 03 Playwright 渲染抓取（源：performing-web-application-penetration-test（借 web-pentest））
- 触发词：`Playwright`、渲染、page.content、截图、同源抓取
- 前置：已授权；Chromium/Playwright 可用；固定 viewport 1280x720、DPR 1；只 GET
- 步骤：1) `python Tool/skill/site-clone/scripts/site-crawl.py --self-test` → rc=0；2) `python Tool/skill/site-clone/scripts/site-crawl.py --url https://target/ --out work/crawl --max-pages 20 --rps 2`；3) 检查 `site-graph.json` 的 routes/assets/api/coverage
- 判据：每页有渲染后 HTML + 截图；非 GET 被 abort；离源请求进 external；missing_rate ≤0.02
- 失败判据：用 curl 源码代替渲染 DOM；等待不足抓到 loading；越源抓广告
- reference：Tool/skill/site-clone/references/04-walkthrough-block-youtest.md

### 04 Next 静态导出路由（源：testing-api-security-with-owasp-top-10（借 web-pentest））
- 触发词：`Next.js`、nextExport、`__NEXT_DATA__`、静态导出、buildId
- 前置：目标为 Next.js；已授权；只读；允许读取 `_next/static` 清单
- 步骤：1) 检查 `__NEXT_DATA__.nextExport`；2) 取 `buildId`；3) 用 `site-crawl.py` 自动解析 `_buildManifest.js` 并把 sortedPages 入队
- 判据：sortedPages 中业务页全部进入 route_universe；`/_app`、`/_error` 排除；missing_rate ≤0.02
- 失败判据：只抓首页；把框架页当业务页；buildId 过期未重取
- reference：Tool/skill/site-clone/references/04-walkthrough-block-youtest.md

### 05 buildManifest 路由宇宙（源：detecting-shadow-api-endpoints（借 plugin-targets））
- 触发词：`buildManifest`、sortedPages、路由宇宙、漏页、route
- 前置：目标 Next.js；已授权；已保存 seed HTML；只 GET
- 步骤：1) `curl -sS https://target/_next/static/<buildId>/_buildManifest.js`；2) 提取 sortedPages；3) `python Tool/skill/site-clone/scripts/site-crawl.py --url https://target/ --out work/crawl --rps 2`；4) 对比 `route_universe` 与 `routes`
- 判据：`missing_routes[]` 为空或逐条解释；`missing_rate` 与 diff 一致
- 失败判据：只看 `<a href>`；动态路由无 sitemap 却写 100%；客户端重定向页算原 route
- reference：Tool/skill/site-clone/references/01-criteria.md

### 06 sitemap 补漏（源：performing-subdomain-enumeration-with-subfinder（借 web-pentest））
- 触发词：`sitemap`、sitemap.xml、URL 集合、补漏、route
- 前置：已授权；目标可能有 sitemap；只 GET；遵守 robots 的速率/路径
- 步骤：1) `curl -sS https://target/sitemap.xml`；2) 提取同源 `<loc>`；3) 与 buildManifest/链接取并集；4) 重跑 crawl 与 diff
- 判据：route_universe 至少包含链接 + buildManifest + sitemap 三来源（有则加）
- 失败判据：把 sitemap 当唯一来源；跨域 loc 混入；sitemap 404 仍写全站覆盖
- reference：Tool/skill/site-clone/references/01-criteria.md

### 07 Cloudflare challenge 识别（源：performing-web-application-firewall-bypass（借 web-pentest））
- 触发词：`Cloudflare`、challenge、CF-RAY、200 假页、拦截
- 前置：已授权；不绕过 challenge；目标可能 200 返回拦截页；只 GET
- 步骤：1) `curl -sS -D - -o /dev/null https://target/ | sed -n '1,12p'`；2) 看标题/正文是否 “Just a moment”；3) 用 `site-crawl.py` 抓取并检查 title/body/资源
- 判据：状态码 + 标题/正文/资源一起看；challenge 页不能当业务首页
- 失败判据：200 即认为成功；拦截页被算 recorded-snapshot；429 继续重试
- reference：Tool/skill/site-clone/references/04-walkthrough-block-youtest.md

### 08 SPA 冻结 DOM（源：analyzing-browser-forensics-with-hindsight（借 plugin-targets））
- 触发词：`SPA`、冻结、freeze、DOM 快照、hydration
- 前置：已授权；页面需要 JS 渲染；已保存 `page.content()`；只 GET
- 步骤：1) `python Tool/skill/site-clone/scripts/site-rebuild.py --crawl work/crawl --out work/rebuild --rps 2`；2) 检查 `site/index.html` 无 `<script>`；3) `python Tool/skill/site-clone/scripts/site-diff.py --crawl work/crawl --rebuild work/rebuild`
- 判据：DOM 节点/层级/文本/标签相似度 ≥0.98；本地 404=0
- 失败判据：保留 JS 但 `_next/data` 404；冻结后交互全失；只比文本
- reference：Tool/skill/site-clone/references/06-spa-har-and-mock.md

### 09 animation opacity 修复（源：implementing-browser-isolation-for-zero-trust（借 plugin-targets））
- 触发词：`animation`、`opacity`、入场动画、logo 消失、截图
- 前置：冻结 DOM 后 logo/插画消失；已定位 inline style；固定 viewport/DPR
- 步骤：1) 搜索 `style="opacity: 0"`；2) 用 `site-rebuild.py` 的 freeze_dom 恢复 img 可见；3) 重截并看 `diff.json.pixel`
- 判据：冻结后图片可见；像素 raw ≤ 阈值；动画 WebP 单列 masked_ratio
- 失败判据：删 JS 后元素永久隐藏；只报 masked；不固定动画
- reference：Tool/skill/site-clone/references/01-criteria.md

### 10 pixel diff 复核（源：performing-web-application-vulnerability-triage（借 plugin-targets））
- 触发词：`pixel`、`diff`、截图差异、ratio、像素
- 前置：原站/本地截图同 viewport/DPR；`animations=disabled`；已生成 rebuild
- 步骤：1) `python Tool/skill/site-clone/scripts/site-diff.py --crawl work/crawl --rebuild work/rebuild --out work/diff.json`；2) 读 `criteria.pixel.pages[]`；3) 对失败 route 重截
- 判据：静态 ratio ≤0.01；SPA ratio ≤0.03；同时报告 raw_ratio
- 失败判据：尺寸不一致直接 resize；只报 masked；动画未固定
- reference：Tool/skill/site-clone/references/01-criteria.md

### 11 masked_ratio 动画（源：analyzing-browser-forensics-with-hindsight（借 plugin-targets））
- 触发词：`masked_ratio`、动画 WebP、`raw_ratio`、像素、mask
- 前置：页面含动画 WebP；crawl 已记录 images[] 边界；diff 已启用 mask
- 步骤：1) 检查 `pixel.pages[].masked_boxes`；2) 对比 raw_ratio 与 masked_ratio；3) 报告同时写两个数
- 判据：mask 区域可解释（动画帧）；raw_ratio 仍在阈值内；不掩盖整页差异
- 失败判据：只报 masked；mask 区域过大；把动画差异当静态差异
- reference：Tool/skill/site-clone/references/01-criteria.md

### 12 DOM 节点层级（源：analyzing-browser-forensics-with-hindsight（借 plugin-targets））
- 触发词：`DOM`、节点、层级、文本相似度、结构
- 前置：已保存渲染后 DOM；本地已加载；归一化 script/style
- 步骤：1) 跑 `site-diff.py`；2) 看 `criteria.dom.pages[]` 的 node_ratio/depth_ratio/text_similarity；3) 对失败页查广告/iframe/随机 token
- 判据：四项相似度均 ≥0.98；失败页能定位
- 失败判据：只看文本；用源码代替渲染 DOM；随机 token 未归一化
- reference：Tool/skill/site-clone/references/01-criteria.md

### 13 CSS 字体资产（源：performing-web-application-penetration-test（借 web-pentest））
- 触发词：`CSS`、`font`、woff2、字体、资源
- 前置：目标有自定义字体；已抓同源资产；本地预览可访问
- 步骤：1) 检查 `rebuild.json.assets` 是否含 woff2；2) 检查 CSS `url()` 是否本地化；3) 重跑 diff 看文本/像素
- 判据：http_404=0；字体 MIME 正确；文本宽度/换行与线上一致
- 失败判据：字体 404 但 DOM 文本相同就写 PASS；CSS url() 未改写
- reference：Tool/skill/site-clone/references/05-static-mirror-limits.md

### 14 srcset 响应图（源：performing-web-application-vulnerability-triage（借 plugin-targets））
- 触发词：`srcset`、响应式图片、图片 404、资源
- 前置：页面使用 srcset/picture；已抓同源图片；固定 DPR
- 步骤：1) 检查 `site-rebuild.py` 是否改写 srcset 每个 URL；2) `local_requests` 查 404；3) 对照截图看图片清晰度
- 判据：srcset 每个候选都本地化；http_404=0；无外链图片
- 失败判据：只改写 src 漏 srcset；图片 404 未计；外链图片未阻断
- reference：Tool/skill/site-clone/references/01-criteria.md

### 15 404 资源清零（源：detecting-shadow-api-endpoints（借 plugin-targets））
- 触发词：`404`、资源、http_404、外链、blocked
- 前置：本地预览已起；rebuild 已生成；允许阻断外链
- 步骤：1) 读 `rebuild.json.resources`；2) 对 404 查 `local_requests`；3) 补资产或改写 `/__external__/blocked.*`；4) 重跑 diff
- 判据：http_404=0；白名单外 external_links=0；软 404 用 DOM 文本抓
- 失败判据：只看状态码；把 403 算 200；外链未改写
- reference：Tool/skill/site-clone/references/01-criteria.md

### 16 HAR 生成（源：detecting-shadow-api-endpoints（借 plugin-targets））
- 触发词：`HAR`、har.json、API 录制、recorded-snapshot
- 前置：页面有 GET XHR/fetch/_next/data；已授权录制；只读
- 步骤：1) 用 `site-crawl.py` 录制 `api/`；2) `site-rebuild.py` 生成 `har.json`；3) 检查 `har_entries` 与 api 数一致
- 判据：HAR 条数等于录制 GET API；跨域 API 也入 HAR；Cookie/Token 脱敏
- 失败判据：只录同源；HAR 含凭据；把 POST 录成 HAR 并回放
- reference：Tool/skill/site-clone/references/06-spa-har-and-mock.md

### 17 page.route 回放（源：testing-api-security-with-owasp-top-10（借 web-pentest））
- 触发词：`page.route`、`mock`、回放、fulfill、route
- 前置：已有 har.json；Playwright 可用；本地 http.server 可起
- 步骤：1) 在 `page.goto` 前 require `mock/playwright-route.js`；2) 未命中请求 abort；3) 检查本地 `http_404=0` 且页面不卡 loading
- 判据：HAR 命中 fulfill；未命中 abort；`local-mock` 页面 DOM/像素达标
- 失败判据：未命中 continue 导致联网；只 mock 同源；把 HAR 当写操作
- reference：Tool/skill/site-clone/references/06-spa-har-and-mock.md

### 18 backend_required 标注（源：implementing-api-schema-validation-security（借 plugin-targets））
- 触发词：`backend`、`backend_required`、数据边界、写操作、状态页
- 前置：已看到 302 `?error=...` 或写接口；已授权只读；不伪造成功
- 步骤：1) 在 `site-graph.json.data_boundary` 逐页标注；2) 把 route/API + reason 写入 `backend_required[]`；3) `site-accept.py --case` 检查透传
- 判据：每页三态齐全；状态页/跨域 API/写接口都在 backend_required；结论不写完整 1:1
- 失败判据：把错误页当正常页；HAR 回放当后端；登录后页面标 snapshot
- reference：Tool/skill/site-clone/references/07-auth-and-backend-boundary.md

### 19 login 登录态边界（源：analyzing-browser-forensics-with-hindsight（借 plugin-targets））
- 触发词：`login`、登录态、session、授权、只读
- 前置：登录墙；无书面授权则不抓；有授权也只读、单独 profile
- 步骤：1) 确认账号/角色/路径/时间窗；2) 只 GET；3) 登录后页面标 local-mock 或 backend_required；4) 不入库 Cookie/Token
- 判据：登录后页面不标 recorded-snapshot；凭据不入库；写操作不执行
- 失败判据：无授权抓登录后页面；用测试账号写操作；HAR 含 Cookie
- reference：Tool/skill/site-clone/references/07-auth-and-backend-boundary.md

### 20 cookie 会话脱敏（源：extracting-browser-history-artifacts（借 plugin-targets））
- 触发词：`cookie`、`token`、凭据、脱敏、session
- 前置：已录制 HAR/响应；需要保留证据但去凭据
- 步骤：1) 扫描 HAR 的 Cookie/Authorization；2) 删除或替换为 `<redacted>`；3) 重算 artifact sha256；4) 跑 accept 复核
- 判据：仓库无 Cookie/Token/个人信息；HAR 仍能回放公开 GET；hash 一致
- 失败判据：Cookie 入库；只改文档不改 HAR；hash 未重算
- reference：Tool/skill/site-clone/references/07-auth-and-backend-boundary.md

### 21 OAuth/SAML 不复刻（源：implementing-browser-isolation-for-zero-trust（借 plugin-targets））
- 触发词：`OAuth`、`SAML`、SSO、回调、IdP
- 前置：目标使用第三方登录；已授权范围只含公开页；不伪造回调
- 步骤：1) 识别 OAuth/OIDC/SAML 跳转；2) 把回调/登录后页面标 backend_required；3) 在报告写“依赖 IdP，不复刻”
- 判据：OAuth/SAML 回调不进离线副本；不伪造 state/nonce；结论 PARTIAL
- 失败判据：静态化回调页宣称可登录；伪造 token；绕过 MFA
- reference：Tool/skill/site-clone/references/07-auth-and-backend-boundary.md

### 22 self-test 夹具（源：performing-web-application-penetration-test（借 web-pentest））
- 触发词：`self-test`、夹具、离线、回归、fixture
- 前置：无需外网；Playwright 可用；临时目录可写
- 步骤：1) `python Tool/skill/site-clone/scripts/site-crawl.py --self-test`；2) `site-rebuild.py --self-test`；3) `site-diff.py --self-test`；4) `site-accept.py --self-test`
- 判据：四条均 rc=0 且输出 `"ok": true`；fixture 不依赖真实目标
- 失败判据：self-test 需要外网；rc≠0；只跑一条就写全绿
- reference：Tool/skill/site-clone/references/04-walkthrough-block-youtest.md

### 23 sha256 证据（源：performing-web-application-vulnerability-triage（借 plugin-targets））
- 触发词：`sha256`、证据、artifact、复算、case.json
- 前置：case 目录已有 crawl/rebuild/diff；准备提交
- 步骤：1) 生成 artifacts；2) 计算 sha256 写入 case.json；3) `site-accept.py --case` 复算；4) JSON 不写 generated_at
- 判据：artifacts 存在且 hash 一致；lessons 含命令/rc；repro.status=recorded
- 失败判据：幻影 artifact；hash 不符；JSON 带生成时间导致复跑漂移
- reference：Tool/skill/site-clone/references/01-criteria.md

### 24 clone-space-mcp 动画与 tabapi 接口（源：detecting-shadow-api-endpoints（借 plugin-targets））
- 触发词：`clone-space-mcp`、`tabapi`、animation、OpenAPI、API map
- 前置：已授权；目标含动画/复杂 XHR；只读；社区工具版本/commit 可记录
- 步骤：1) 用 `clone-space-mcp` 保留动画快照（可选）；2) 用 `tabapi` 把录制会话导出 API/OpenAPI 形状；3) 与 `site-crawl.py` 的 api[] 对照；4) 写清只覆盖录制到的请求
- 判据：动画/接口清单作为补充证据；最终结论仍由六条判据给出；来源标“2026 社区工具”
- 失败判据：把社区工具输出当后端复刻；不标来源/版本；接口清单与 HAR 不一致
- reference：Tool/skill/site-clone/references/08-tool-ecosystem-2026.md
