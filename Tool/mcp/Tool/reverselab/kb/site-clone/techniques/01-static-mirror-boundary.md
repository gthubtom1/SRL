---
id: "site-clone/01-static-mirror-boundary"
title: "静态镜像边界：wget/HTTrack 能拿到什么"
title_en: "Static Mirror Boundary: What wget/HTTrack Actually Capture"
summary: >
  wget/HTTrack 只保存服务器直出的 HTML/资源，不执行 JS；SPA 渲染、登录态、
  XHR/API、后端写操作都拿不到。本页给出能力对照、判定与改走路线。
board: "site-clone"
category: "01-static"
signals: ["wget --mirror", "HTTrack", "static site", "SPA shell", "login wall", "backend logic"]
mcp_tools: ["site-crawl.py", "site-rebuild.py", "site-diff.py"]
keywords: ["wget", "HTTrack", "静态镜像", "SPA", "登录态", "后端边界"]
difficulty: "beginner"
tags: ["static-mirror", "wget", "httrack", "spa", "boundary"]
language: "zh-CN"
last_updated: "2026-10-22"
related_articles: ["site-clone/02-dom-snapshot-freeze", "site-clone/06-failure-criteria"]
---
# 静态镜像边界：wget/HTTrack 能拿到什么

## 入口信号

- 有人拿 `wget --mirror` / HTTrack 的目录说“整站已 1:1”。
- 目标首页源码只有 `<div id="root"></div>` + 一个大 JS。
- 页面需要登录、验证码、邀请，或者线上会 302 到 `/?error=...`。
- 页面数据来自 `/api/`、`/_next/data/`、GraphQL、WebSocket。

## 能力对照

| 能力 | wget | HTTrack | Playwright crawl |
| :-- | :-: | :-: | :-: |
| 递归下载 HTML/资源 | 是 | 是 | 是 |
| 链接改写/目录保持 | 部分 | 是 | 是 |
| 执行 JS / 渲染 DOM | 否 | 否 | 是 |
| 抓 XHR/fetch JSON | 否 | 否 | 是 |
| 截图/交互证据 | 否 | 否 | 是 |
| 登录后页面 | 否 | 否 | 需单独授权 |
| 后端写操作 | 否 | 否 | 不复制，标边界 |

来源：

- GNU Wget Manual：https://www.gnu.org/software/wget/manual/wget.html
- HTTrack：https://www.httrack.com/html/index.html
- 2026 工具对比：静态可镜像，SPA/登录/后端不可（引用时写“2026 工具对比”）。

## 可复制命令（只作资产参考）

```bash
# 静态站：限速 + 只抓页面所需资源
wget --mirror --page-requisites --convert-links --wait=0.5 --limit-rate=200k \
  https://static.example/

# 同一目标仍要补渲染证据
python Tool/skill/site-clone/scripts/site-crawl.py \
  --url https://static.example/ --out work/crawl --max-pages 20 --rps 2
python Tool/skill/site-clone/scripts/site-rebuild.py --crawl work/crawl --out work/rebuild --rps 2
python Tool/skill/site-clone/scripts/site-diff.py --crawl work/crawl --rebuild work/rebuild
```

## 确认判据

静态镜像可作为资产参考，仅当：

1. 页面服务器直出 HTML，无 JS 渲染依赖；
2. 无登录、无 XHR/fetch、无写操作；
3. 资源同源或已明确白名单；
4. 仍然补了 `missing_rate`、截图、DOM、404/外链四项数值。

否则只能算“下载了文件”，不能算复刻。

## 失败判据

| 现象 | 判定 | 改走哪条 |
| :-- | :-- | :-- |
| 首页只有 SPA 壳 | 静态镜像无效 | Playwright `page.content()` |
| 登录后页面缺失 | 数据边界错误 | 单独授权/标 `backend-required` |
| XHR 数据没抓到 | 页面不完整 | 录 HAR / `page.route` |
| 外链广告还在请求 | 资源判据失败 | 阻断并改写 `/__external__/blocked.*` |
| 无截图/DOM/路由数值 | 证据不合格 | 补 site-* 四脚本 |

## 边界

- wget/HTTrack 是资产搬运工，不是站点复刻器。
- 静态站可以接近 1:1；SPA/登录/后端逻辑必须换工具或标边界。
- 任何“1:1”结论都要回到六条判据，而不是“文件下载完成”。
