---
id: "site-clone/05-pixel-dom-diff"
title: "像素与 DOM 差分：把“看起来一样”变成数值"
title_en: "Pixel and DOM Diff: Turning 'Looks the Same' into Numbers"
summary: >
  用 Pillow/numpy 算差异像素占比，用 HTMLParser/SequenceMatcher 算节点/层级/文本/标签相似度；
  固定 viewport/DPR/动画，动画 WebP 区域单列 masked_ratio，但必须报告 raw_ratio。
board: "site-clone"
category: "05-diff"
signals: ["pixel diff", "DOM diff", "screenshot", "animations", "raw_ratio", "masked_ratio"]
mcp_tools: ["site-diff.py", "site-accept.py"]
keywords: ["像素", "DOM", "差分", "Pillow", "numpy", "相似度"]
difficulty: "intermediate"
tags: ["pixel", "dom", "diff", "pillow", "similarity"]
language: "zh-CN"
last_updated: "2026-10-22"
related_articles: ["site-clone/02-dom-snapshot-freeze", "site-clone/06-failure-criteria"]
---
# 像素与 DOM 差分：把“看起来一样”变成数值

## 入口信号

- 人工截图“看着一样”，但客户问差多少。
- 两版页面文本相同，结构/交互却坏了。
- 动画/字体/广告导致截图差异不可解释。
- 需要一条能复算的 PASS/PARTIAL 判定。

## 像素

```text
diff  = |orig_rgb - local_rgb|.max(axis=2)
ratio = count(diff > 8) / total_pixels
static: ratio <= 0.01
spa   : ratio <= 0.03
```

固定参数：

- viewport 1280×720，DPR 1；
- 同一 Playwright/Chromium 版本；
- `page.screenshot(..., animations="disabled")`；
- 同一滚动位置（默认顶部）。

动画 WebP：

- crawl 记录 `images[]`（src/x/y/w/h）；
- diff 对 `n_frames>1` 的图片区域算 `masked_ratio`；
- 同时输出 `raw_ratio`、`masked_boxes`、`masked_ratio`；
- 报告不能只写 masked。

```bash
python Tool/skill/site-clone/scripts/site-diff.py \
  --crawl work/crawl --rebuild work/rebuild --out work/diff.json
python -c "import json;d=json.load(open('work/diff.json'));print(d['criteria']['pixel'])"
```

## DOM

```text
node_ratio  = min(nodes)/max(nodes)
depth_ratio = min(depth)/max(depth)
text_sim    = SequenceMatcher(text_a, text_b).ratio()
tag_sim     = SequenceMatcher(tags_a, tags_b).ratio()
pass = min(...) >= 0.98
```

归一化：

- 删除 `script/style/noscript/template` 及文本；
- 压缩空白；
- 随机 token/时间戳替换为 `<token>`（如需要）；
- 保留可见 DOM 结构。

## 资源与请求集合

```text
http_404       = count(local_requests[].status == 404)
external_links = count(href/src 指向白名单外 http(s))
```

- 外链 `<a>` 改写为 `#` + `data-original-href`；
- 资源外链改写 `/__external__/blocked.*`；
- 软 404 用 DOM/文本相似度抓，不只看状态码。

## 交互

- crawl 记录 6–11 条脚本；
- rebuild 在本地副本重放；
- `interactions_passed >= 5`；
- 每条 expected/actual 落盘；selector 用 aria-label/role/可见性。

## 确认判据

- 六项都有布尔与数值；
- `diff.json.summary.status` 与 `site-accept.py` 一致；
- 失败项能定位到 route；
- `backend_required` 透传到 `accept.json`。

## 失败判据

| 现象 | 判定 | 改走哪条 |
| :-- | :-- | :-- |
| resize 后比像素 | 假差异 | 固定 viewport/DPR 重截 |
| 只报 masked_ratio | 掩盖动画差异 | 同时报 raw |
| 只比文本 | 结构塌陷 | 节点/层级/标签/文本四项 |
| 本地 404 未算 | 资源判据假 | 统计 local_requests |
| 交互 <5 仍 PASS | 交互判据假 | 降 PARTIAL |

## 边界

- 像素对字体/动画/广告敏感；必须记录环境与 mask。
- DOM 结构相似不等于功能一致；交互脚本补足。
- 差分只证明“副本与原站差异”，不证明“后端已复刻”。
