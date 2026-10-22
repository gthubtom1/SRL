---
id: "site-clone/07-auth-backend-boundary"
title: "登录态与后端边界：能录不能复制"
title_en: "Auth and Backend Boundary: Recordable, Not Reproducible"
summary: >
  Cookie/Token/localStorage 只是时间点状态，服务端 session/写操作/实时计算不可复制。
  本页给出四层会话、判定表、合规红线与 backend_required 写法。
board: "site-clone"
category: "07-auth"
signals: ["login wall", "Cookie", "JWT", "OAuth", "write operation", "backend required"]
mcp_tools: ["site-crawl.py", "site-accept.py"]
keywords: ["登录态", "Cookie", "Token", "OAuth", "SAML", "后端边界"]
difficulty: "intermediate"
tags: ["auth", "cookie", "session", "backend-required", "compliance"]
language: "zh-CN"
last_updated: "2026-10-22"
related_articles: ["site-clone/03-har-mock-route", "site-clone/06-failure-criteria"]
---
# 登录态与后端边界：能录不能复制

## 入口信号

- 页面跳登录/要求 MFA/邀请。
- 线上访问受保护路由 302 到 `/?error=...`。
- 接口是 POST/PUT/PATCH/DELETE，或返回实时榜单/推荐。
- HAR 里出现 `Cookie`/`Authorization` 头。

## 四层会话

| 层 | 载体 | 可录 | 可复制 | 说明 |
| :-- | :-- | :-: | :-: | :-- |
| Cookie | Set-Cookie/Cookie | 需授权 | 否 | 过期/HttpOnly/SameSite |
| Token | Authorization/JWT | 需授权 | 否 | 不入库 |
| 浏览器存储 | localStorage/sessionStorage/IndexedDB | 快照 | 否 | 时间点状态 |
| 服务端会话 | session id/DB | 否 | 否 | 需真实后端 |

## 判定表

| 特征 | 标签 | 结论 |
| :-- | :-- | :-- |
| 公开静态页 | recorded-snapshot | 可 PASS |
| 公开 GET JSON | local-mock | 可 PASS |
| 登录后 GET（已授权只读） | local-mock | 可 PASS（只读） |
| 登录/登出 | backend-required | 不复制 |
| 创建/提交/支付/删除 | backend-required | 不复制 |
| 实时榜单/推荐 | backend-required | 不复制 |
| OAuth/OIDC/SAML 回调 | backend-required | 不复制 |
| WebSocket/SSE | backend-required | 可录片段，不可复刻 |

## 合规红线

- 登录态抓取必须单独授权：账号/角色/路径/时间窗/数据保留。
- 仓库禁止：Cookie、Token、密码、身份证、手机号、真实订单/聊天。
- 禁止用测试账号做写操作（改密码、邀请、导出、删除）。
- 禁止伪造 OAuth 回调/绕过 MFA。
- 上传前做 secret 扫描。

## backend_required 写法

```json
[
  {"route": "/user/scoreboard", "reason": "需要用户成绩；线上 302 到 /?error=..."},
  {"api": "https://api.example.com/info/country", "reason": "跨域 API；仅录制快照可回放，实时地理逻辑不复刻"},
  {"route": "/quiz/submit", "reason": "写操作；HAR 不能产生事务"}
]
```

## 可复制命令

```bash
python Tool/skill/site-clone/scripts/site-accept.py --case Tool/cases/site-clone01
python -c "import json;d=json.load(open('work/rebuild/rebuild.json'));print(d['data_boundary']);print(d['backend_required'])"
```

## 确认判据

- 每页都有三态标签；
- 状态页/跨域 API/写接口都在 `backend_required[]`；
- HAR 已脱敏；
- 结论没有把登录/写操作写成已复刻。

## 失败判据

| 现象 | 判定 | 改走哪条 |
| :-- | :-- | :-- |
| 登录后页面标 snapshot | 边界错误 | 标 backend-required |
| HAR 含 Cookie/Token | 凭据泄露 | 脱敏重生成 |
| 用测试账号写操作 | 违规 | 停止并报告 |
| 伪造 OAuth 回调 | 误导/不安全 | 删除，标不复制 |
| 写接口 HAR 回放 200 | 结论越界 | 降 PARTIAL，转后端 |

## 边界

- “能看”不等于“能复制”；登录态只是快照。
- 后端写操作/实时计算/鉴权必须真实后端；本域只负责标注与取证。
- 需要真正后端复刻时，转到后端重建域，不在前端副本里假装。
