---
id: "site-clone/02-dom-snapshot-freeze"
title: "渲染后 DOM 快照与冻结：SPA 1:1 的确定性基线"
title_en: "Rendered DOM Snapshot and Freeze for Deterministic SPA Clones"
summary: >
  SPA 的源码 HTML 只是壳；必须用 Playwright 渲染后抓 page.content()，再决定冻结 DOM
  （默认）或保留 JS（HAR 模式）。本页给出等待、截图、inline opacity 修复与验证。
board: "site-clone"
category: "02-dom"
signals: ["SPA shell", "hydration", "page.content", "opacity:0", "animation", "DOM diff"]
mcp_tools: ["site-crawl.py", "site-rebuild.py", "site-diff.py"]
keywords: ["DOM", "快照", "冻结", "hydration", "animation", "opacity"]
difficulty: "intermediate"
tags: ["dom", "playwright", "freeze", "hydration", "screenshot"]
language: "zh-CN"
last_updated: "2026-10-22"
related_articles: ["site-clone/03-har-mock-route", "site-clone/05-pixel-dom-diff"]
---
# 渲染后 DOM 快照与冻结：SPA 1:1 的确定性基线

## 入口信号

- `curl` 拿到的是 `<div id="root"></div>` 或 Next.js 的 `__NEXT_DATA__` 壳。
- 页面加载后先显示 loading，再出现内容；等待时间不够会抓到半成品。
- 截图里 logo/插画消失，但 HTML 里明明有 `<img>`。
- 本地副本和线上 DOM 节点数差很多，或 hydration 报错。

## 可复制命令

```bash
# 1) 渲染后抓 DOM/截图/API（只 GET，2 rps）
python Tool/skill/_pending/site-clone/scripts/site-crawl.py \
  --url https://target/ --out work/crawl --max-pages 20 --max-depth 3 --rps 2

# 2) 默认冻结 DOM：删 script，保留渲染结果与 CSS
python Tool/skill/_pending/site-clone/scripts/site-rebuild.py \
  --crawl work/crawl --out work/rebuild --rps 2

# 3) 需要客户端交互时保留 JS（必须补 _next/data/HAR）
python Tool/skill/_pending/site-clone/scripts/site-rebuild.py \
  --crawl work/crawl --out work/rebuild --rps 2 --keep-js
```

## 等待与截图

- `page.goto(..., wait_until="load")` 后至少等 2.5–3.5 秒；Next.js 站点在 1 秒内可能只渲染 loading。
- 记录最终 URL、标题、`page.content()`、`page.inner_text("body")`。
- 截图固定：`viewport=1280x720`、`device_scale_factor=1`、`animations="disabled"`。
- 同一页面在 hydration 前后 DOM 不同；crawl 必须等稳定后再保存。

## 冻结 DOM 做三件事

1. 删除所有 `<script>`（保留 `link rel=stylesheet`）；
2. 对 `img[style*=opacity:0]` 恢复 `opacity:1`，并把 `translate3d(...)/scale(...)` 归位（入场动画元素否则永久隐藏）；
3. 在 `<head>` 插入 `<!-- site-clone-mode:frozen-dom -->` 注释（不增加 DOM 节点）。

```python
# 等价逻辑（site-rebuild.py freeze_dom）
text = re.sub(r"<script\b[^>]*>.*?</script>", "", text, flags=re.I | re.S)
text = re.sub(r"<img\b[^>]*>", unhide_img, text, flags=re.I)
```

## 确认判据

- `rebuild/local/*.html` 与 `crawl/pages/*.html` 的节点/层级/文本相似度 ≥ 0.98。
- 截图差异：静态 ≤ 1%，SPA ≤ 3%；动画 WebP 区域单列 `masked_ratio` 并报告 `raw_ratio`。
- 本地 404=0，白名单外外链=0。
- 冻结模式下交互仍能跑 ≥5 条（title/body/样式/DOM/链接/输入等原生交互）。

## 失败判据

| 现象 | 判定 | 改走哪条 |
| :-- | :-- | :-- |
| 等待 1 秒就保存 | 半成品 DOM | 等 2.5–3.5 秒并检查标题/正文 |
| 删 JS 后 logo 消失 | 冻结不完整 | 修 inline `opacity:0` |
| 保留 JS 但本地 404 | hydration 失败 | 落 `_next/data`/HAR 或改冻结 |
| 节点数差 >2% | DOM 判据失败 | 检查广告/iframe/随机内容 |
| 只比文本 | 结构塌陷 | 节点/层级/标签/文本四项一起算 |

## 边界

- 冻结 DOM 是“只读快照”，不是可交互应用；JS 菜单/客户端路由会失效。
- 保留 JS 能恢复交互，但需要 `_next/data`/API mock，且 DOM/像素更容易漂移。
- 登录后页面不在本页覆盖范围；见 `07-auth-backend-boundary.md`。
