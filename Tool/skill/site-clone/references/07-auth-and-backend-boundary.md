# 登录态与后端边界：哪些能录制，哪些不能复制

> 1:1 复刻的边界，八成卡在登录态与后端写操作。
> 本页给判定表：什么能进离线副本，什么必须标 `backend-required`，什么直接拒绝。

## 1. 会话状态的四层

| 层 | 载体 | 能否录制 | 能否复制 | 备注 |
| :-- | :-- | :-- | :-- | :-- |
| Cookie | `Set-Cookie` / `Cookie` | 可录制（需授权） | 否 | 过期、HttpOnly、SameSite 都会变 |
| Token | `Authorization: Bearer` / JWT | 可录制（需授权） | 否 | 不能把 token 写进仓库 |
| 浏览器存储 | `localStorage` / `sessionStorage` / IndexedDB | 可导出快照 | 否 | 只是某个时刻的状态 |
| 服务端会话 | session id / 数据库 | 不可 | 否 | 需要真实后端 |

结论：**能拿到公开页 ≠ 能复刻登录系统**。登录后页面最多做“只读快照”，不能做“可登录副本”。

## 2. 授权与合规

登录态抓取必须单独授权，至少写清：

- 允许使用的测试账号/角色；
- 允许访问的页面/接口前缀；
- 是否允许读取个人数据（默认不允许）；
- 数据保留期限与销毁方式；
- 禁止：修改密码、邀请成员、导出客户数据、绕过 MFA。

仓库里禁止出现：

- Cookie / Token / 密码 / 身份证 / 手机号；
- 真实用户头像/聊天记录/订单；
- `.env`、私钥、数据库连接串。

## 3. 数据边界判定表

| 页面/接口特征 | 标签 | 证据 | 结论 |
| :-- | :-- | :-- | :-- |
| 公开静态页，无 XHR | `recorded-snapshot` | HTML + 截图 + 资产 hash | 可 PASS |
| 公开页 + GET JSON（配置/国家/汇率） | `local-mock` | HAR entry + mock | 可 PASS（只读） |
| 登录后列表/详情（GET） | `local-mock` 或 `backend-required` | 若已授权录制且只读 → local-mock；否则 backend-required | 视授权 |
| 登录/登出 | `backend-required` | 需要服务端会话 | 不复制 |
| 创建/提交/支付/删除 | `backend-required` | 写操作 | 不复制，禁止伪造 |
| 实时计算/排行榜/推荐 | `backend-required` | 依赖数据库/实时状态 | 不复制 |
| 第三方 OAuth/OIDC/SAML 回调 | `backend-required` | 依赖 IdP | 不复制 |
| WebSocket/SSE 实时流 | `backend-required` | 依赖服务端推送 | 可录制片段，不能复刻 |

## 4. 处理流程

```text
看到登录墙
→ 先问：是否有书面授权使用测试账号？
→ 否：只复刻公开页；登录后页面标 backend-required，停止。
→ 是：单独建 profile/context，记录账号角色、时间窗、允许路径。
→ 抓取：只 GET；不点“保存/提交/删除”；不导出个人数据。
→ 产物：登录后页面只留 DOM/截图/hash；Cookie/Token 不入库。
→ 验收：登录相关页面一律 backend-required 或 local-mock（只读），结论不写“完整 1:1”。
```

## 5. 常见误区

- **把 Cookie 写进 HAR**：HAR 会包含 `Cookie`/`Authorization` 头；入库前必须脱敏。
- **把 JWT 当静态字符串**：JWT 有过期/签名/刷新；复制 token 不等于复制登录。
- **把 localStorage 快照当会话**：服务端 session 可能已失效；刷新就掉线。
- **把 CORS 当可绕过**：本地副本跨域请求会被浏览器拦截；用 HAR mock 或同源反向代理，且只读。
- **把 iframe 登录页嵌进副本**：第三方页面不受控，可能泄露凭据；默认阻断。
- **把 OAuth 回调本地化**：state/nonce/PKCE 都依赖 IdP；本地伪造会失败且不安全。

## 6. 安全边界

- 不在离线副本里保留任何真实凭据；
- 不把 `Set-Cookie` 回放给浏览器（HAR 只回放 body/headers 的白名单字段）；
- 不复制 `ServiceWorker` 缓存中的鉴权响应；
- 不把 `IndexedDB` 中的个人数据打包进案例；
- 不上传案例到公共仓库前做 secret 扫描。

## 7. 失败判据

- 登录后页面被标 `recorded-snapshot` → 数据边界错误。
- 报告写“已复刻登录”但没有真实后端 → 结论越界。
- HAR/案例含 Cookie/Token/个人信息 → 直接作废并清理。
- 用测试账号做了写操作 → 违规，停止并报告。
- 把 OAuth/SSO 回调页静态化后宣称可登录 → 误导。

## 8. 一句话

> 登录态可以“看”，不可以“复制”；后端可以“录”，不可以“假装”。
> 该标 `backend-required` 的地方，越早标越省时间。
