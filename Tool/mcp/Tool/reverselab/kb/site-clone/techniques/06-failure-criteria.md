---
id: "site-clone/06-failure-criteria"
title: "Site Clone 失败判据：看到即降级"
title_en: "Site Clone Failure Criteria: Downgrade on Sight"
summary: >
  汇总 1:1 复刻的假通过：静态镜像冒充全站、只抓首页、动画未固定、只比截图、
  资源 404、交互不足、HAR 当后端、登录态误标。每条给判定、改走哪条与代价。
board: "site-clone"
category: "06-failure"
signals: ["static mirror only", "missing route", "pixel drift", "404", "less than 5 interactions", "backend required"]
mcp_tools: ["site-accept.py", "site-diff.py", "site-crawl.py"]
keywords: ["失败判据", "降级", "PARTIAL", "BLOCKED", "误报", "证据"]
difficulty: "beginner"
tags: ["failure", "criteria", "downgrade", "false-positive"]
language: "zh-CN"
last_updated: "2026-10-22"
related_articles: ["site-clone/01-static-mirror-boundary", "site-clone/07-auth-backend-boundary"]
---
# Site Clone 失败判据：看到即降级

## 入口信号

出现任一情况，说明已进入失败判据区：

- 结论只能引用“wget 下载完了”“截图看着一样”。
- 没有 `missing_rate`、`ratio`、DOM 相似度、404/外链数值。
- 交互脚本少于 5 条，或没有 expected/actual。
- 页面线上 302 到 `?error=...`，却被标 `recorded-snapshot`。
- 目标 429/5xx 还在继续抓。

## 失败判据表

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| 只跑 wget/HTTrack 写 1:1 | 证据不合格 | Playwright 渲染 + 四脚本 | 0.5–2h |
| 只抓首页 | 路由假覆盖 | 解析 buildManifest/sitemap | 20–60m |
| missing_rate > 0.02 | BLOCKED | 补抓/解释缺失 route | 视页数 |
| viewport/DPR 不一致 | 像素不可比 | 固定 1280×720@1x 重截 | 10–30m |
| 动画未禁用 | 假差异 | animations=disabled + mask 单列 | 10–20m |
| 只比截图 | DOM 判据缺失 | 补节点/层级/文本/标签 | 10m |
| 只比 DOM | 资源判据缺失 | 查 404/外链/CSS url() | 10–20m |
| 本地 404 >0 | 资源失败 | 补资产/改路径/查 query | 20–60m |
| 白名单外外链 | 资源失败 | 改写 blocked/data URI | 10m |
| 交互 <5 | PARTIAL | 补稳定 selector | 30–60m |
| backend_required 为空但线上报错 | 边界失败 | 逐页标注 + 接口清单 | 20m |
| HAR 当写操作 | 结论越界 | 降 PARTIAL/转后端 | 需后端 |
| 登录后页面标 snapshot | 边界错误 | 单独授权或标 backend | 0.5–1d |
| 缺命令/rc/hash | 证据不合格 | 回填 case.json 与 hash | 可能全损 |

## 状态判定

| 条件 | 状态 |
| :-- | :-- |
| 六项全过 | PASS |
| 核心四项（路由/像素/DOM/资源）过，交互/边界不过 | PARTIAL |
| 核心四项任一失败 | BLOCKED |
| 缺 crawl/rebuild/diff | BLOCKED |

## 可复制命令

```bash
python Tool/skill/site-clone/scripts/site-accept.py --case Tool/cases/site-clone01
python -c "import json;d=json.load(open('Tool/cases/site-clone01/artifacts/diff.json'));print(d['summary'])"
```

## 确认判据（反向）

只有同时满足才允许写 PASS：

1. 六项都有布尔与数值；
2. 数值能被脚本复算；
3. `backend_required` 已列清，且没有把写操作写成已复刻；
4. 证据含命令、rc、sha256、viewport/DPR、时间窗。

## 边界

- 失败判据不是免责声明；写了“未验证”也不能把 PARTIAL 写成 PASS。
- 负结果要记录停止理由与下一步，避免重复烧时间。
- 目标/Cloudflare/后端变化后旧结论可能失效，需要重跑。
