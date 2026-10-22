---
name: signin-automation
description: "账号任务自动化的六个原语：会话池（多账号隔离）、定时通知（cron/幂等/重试上限）、验证码三分支、滑块缺口、旋转角度、TLS 指纹。附带 OPSEC 参数与可机检判据（会话有效性 / 指纹一致 / 节奏不触发风控 / TLS 与 HTTP2 头序一致）。供 playbook（qinglong-signin / multi-account-runner / captcha-handling / app-daily-task）组合调用。"
---

# signin-automation（账号任务自动化的六个原语）

> 本目录只提供**脚本原语 + 判据**；任务编排见 `Tool/playbooks/qinglong-signin.md`、
> `Tool/playbooks/multi-account-runner.md`、`Tool/playbooks/captcha-handling.md`。
> 执行范围由用户提供的 `scope` 决定：目标、账号、速率、通知渠道都是输入。
>
> 判据与 OPSEC 细节：`Tool/skill/signin-automation/references/01-fingerprint-and-pacing.md`。
> 脚本：`Tool/skill/signin-automation/scripts/*.py` + `Tool/scripts/captcha-gap.py`、`Tool/scripts/captcha-angle.py`。

本域的唯一交付标准：**同一账号、同一指纹、同一节奏下，任务结果可重复；换号换机仍按判据成立**。
“登录上了”不算，回填 200 的登录页也不算；只有**会话证据 + 指纹一致 + 节奏未触发风控**三者齐才算一条可用链路。

## 1. 范围与路由（边界）

### 1.1 本域输入面

- 已有账号清单（cookie / token / device_id），要按账号隔离地跑签到、积分、每日任务。
- 目标有 Cloudflare / Akamai / DataDome / 极验一类风控，需要把“浏览器像不像人”拆成可测的量。
- 需要定时执行（cron）、结果通知（telegram / 钉钉 / 企微）且**同一任务同一天只生效一次**。
- 出现图形码、滑块、旋转、短信码，需要按分支处置而不是硬试。
- 纯 HTTP 侧被 403，需要判断是 TLS 指纹（JA3/JA4）还是 HTTP/2 头序（伪头顺序、SETTINGS）不一致。

### 1.2 相邻域与路由

- 只做单次登录抓包、签名还原 → `web-pentest` / `mcp-js-reverse-playbook`。
- 客户端卡密/本地校验绕过 → `01-gate-bypass`；APK/小程序侧签名与重放 → `apkseep`。
- 账号批量执行的整体编排（案例、预算、env 台账、交付）→ `multi-account-runner` 配方。
- 验证码三分支的完整证据链（OCR 落盘、人工队列、票据一次性）→ `captcha-handling` 配方。
- 目标侧风控判定与封号申诉走运营流程；本域只产出“可复现的执行计划 + 判据结论”。

### 1.3 三条硬边界

1. 凭据只以占位或掩码出现（`session-pool.py` 只打印 `ab***yz(len=N)`），明文不进日志与提交。
2. 所有原语默认 **offline**：`session-pool` / `schedule-notify` / `captcha-branch` / `tls-fingerprint`
   的 `self_check.network_requests` 恒为 0，真正发请求由调用方按 scope 执行。
3. 速率与并发是输入：先按 §6 的参数表落一份 `opsec.json`，再由 runner 读取；不在脚本里写死。

## 2. 前置检查（三件，齐备再开工）

### 2.1 账号基线与隔离面

```bash
python Tool/skill/signin-automation/scripts/session-pool.py \
  --accounts work/<case>/accounts.json --concurrency 1 --rate 12 \
  --json-out work/<case>/pool.json
```

- 每个账号一行：`status ∈ {ok,expired,blocked}`、`invalidate`、`next_action`。
- **隔离面**：一个账号 = 一个浏览器 profile（独立 user-data-dir）+ 一个出口 IP + 一份 device_id。
  两个账号共用 profile 或共用出口，等于把两个号绑在同一设备指纹上。
- 完成判据：`pool.json.pool.ok >= 1`，`rotation_order` 非空，`invalidated` 里的号不再重试。

### 2.2 节奏与预算

```bash
python Tool/skill/signin-automation/scripts/schedule-notify.py --validate-cron "30 8 * * *"
python Tool/skill/signin-automation/scripts/schedule-notify.py --task daily-signin \
  --accounts acc-1,acc-2 --cron "30 8 * * *" --channel telegram --retries 2 \
  --json-out work/<case>/plan.json
```

- 全池每分钟请求数、单账号并发、抖动分布三件必须写进计划，不是跑起来再说。
- 完成判据：`plan.json.idempotency_key` 存在；`retries <= 3`；cron 五段合法且带时区说明。

### 2.3 指纹基线（只读回显）

```bash
# 只读公开回显端点：只发 GET、不带凭据、目标站不在请求路径上
curl -sS --max-time 20 https://tls.peet.ws/api/all -o work/<case>/fp-client.json
curl -sS --max-time 20 https://httpbin.org/headers -o work/<case>/h2-headers.json
```

- 记录：UA、`sec-ch-ua*`、Accept-Encoding、时区、语言、屏幕、`hardwareConcurrency`、
  JA3/JA4、HTTP/2 伪头顺序。
- 完成判据：`fp-client.json` 里 JA4 与所选 `impersonate` 档位同族；同一 profile 连测两次 JA3/JA4 不变。

## 3. 判据表（五条，全部可机检）

> 机检入口：`python Tool/skill/signin-automation/scripts/opsec-check.py --session work/<case>/session.json`
> 输出 `verdicts.*.pass` 五项；`ok=false` 时 `blocked_at` 指出卡在哪一条。
> 字段级细节与自测方法见 `Tool/skill/signin-automation/references/01-fingerprint-and-pacing.md`。

| # | 判据 | 可机检字段（opsec-check.py） | 通过条件 | 常见误判 |
| :-- | :-- | :-- | :-- | :-- |
| 1 | 会话有效性 | `verdicts.session_valid` | 存在 `cookie_reuse=true` 且 `status=200` 且 `has_user_marker=true` 的请求 | 200 的登录页 / 空 JSON 壳 / SPA 兜底页都算“200” |
| 2 | 指纹一致 | `verdicts.fp_stable` | 同一会话内 UA、时区、语言、字体集、WebGL、屏幕、`hardwareConcurrency`、WebRTC 各只有 1 个取值 | 只比 UA 不看 `fonts_hash`；换代理导致 WebRTC 出口 IP 变了 |
| 3 | 节奏不触发风控 | `verdicts.pacing_ok` | 滑动窗口（默认 5 次）内 `max_window_rps <= limits.max_rps`，窗口内 `429=0`、滑块挑战 `=0` | 只看总平均 rps，看不到突发窗口；把 429 当“网络抖动”重试 |
| 4 | TLS 指纹匹配 | `verdicts.tls_match` | 会话内 JA3 与 JA4 各自唯一；给了 `claimed.ja4_prefix` 时前缀命中 | 用 Chrome UA 配 curl 默认 TLS；代理侧做了 TLS 终止 |
| 5 | HTTP/2 头序一致 | `verdicts.h2_order_match` | 会话内 `h2_pseudo_order` 唯一，且等于 `claimed.h2_pseudo_order` 或声明浏览器族的标准顺序 | 手拼 header 以为能改顺序；H1.1 目标也去比 H2 顺序 |

退出码约定（与仓库其它原语一致）：

- `rc=0`：五条全过，可直接进下一步。
- `rc=3`：五条全过但有 **at-risk 警告**（如间隔变异系数 < 0.05，像固定 sleep）。
- `rc=2`：至少一条未过，`blocked_at + next_action` 给出改走哪条。

## 4. 失败判据表（看到即降级，别用更多请求去“凑”）

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| 连续窗口内出现 429 | 节奏触发（`blocked_at=rate-limit`） | `max_rps` 砍半 + 改串行 + 间隔换对数正态；仍 429 换出口/改时段 | 当日进度损失；换出口要重登，device_id 可能被判新设备 |
| 出现滑块/点选/旋转挑战 | 行为或指纹被识别 | 先跑 `captcha-branch.py` 定分支：图形→`ocr`、滑块→`interactive`、无感 200→`manual` | 每条 1–5 分钟；滑块轨迹被训练过的站仍会二次挑战 |
| 账号被标记 blocked / 登录直接 403 风控页 | 该号已进黑名单 | 停该号，冷却（默认 1800s）后换 device_id 重登；连续两次 blocked 转人工 | 该号当日作废；重新养号成本最高 |
| 登录成功但立刻掉线（下一个请求 401/302 回登录页） | 会话无效：cookie 未绑定成功或被服务端即时失效 | 回抓登录链，检查是否漏了设备校验/二次校验接口；补 `device_id` 再试 | 每次 3–10 分钟；可能是强绑定，需放弃 HTTP 侧改浏览器侧 |
| 设备指纹不匹配（UA 与 JA4 不同族、时区与出口 IP 不符） | 指纹面自相矛盾 | 固定一个 profile（浏览器族 + 时区 + 语言 + 出口），只改一个变量重测 | 每轮 2–5 分钟；跨时区代理需要重新对齐 locale/时区 |
| 同一会话出现多种 JA3/JA4 | 有多条客户端/代理在混用 | 关掉代理侧 TLS 终止，`impersonate` 档位写死 | 需要改代理链路；短时无法收敛时降级为“网络层不确定” |
| 伪头顺序与声称浏览器不符 | 客户端库不匹配 UA | 换 `tls-fingerprint.py --client` 档位；别手拼 header | 一次抓包复测；库版本可能不支持目标档位 |
| 验证码分支判不出（信号冲突） | 特征不足 | 记 `trace_id` + 响应特征，转 `manual` 一次人工核验 | 人工 5–20 分钟；批量任务会阻塞在该号 |
| 滑块 `confidence < 0.35` / 旋转 `confidence < 0.35` | 求解不可信 | 换图重取；或转人工 | 每次 30 秒；连续 3 次失败说明该验证码被加了噪 |
| 通知发送失败 | 渠道问题，不影响任务结果 | 保留本地 `result.json`，换渠道重发；幂等键不变 | 分钟级；重复发送由幂等键挡住 |

## 5. 六个原语

### 5.1 会话池（多账号隔离）

```bash
python Tool/skill/signin-automation/scripts/session-pool.py \
  --accounts work/<case>/accounts.json --concurrency 2 --rate 20 \
  --now 2026-10-20T09:00:00Z --json-out work/<case>/pool.json
```

- 三态：`ok` / `expired`（无凭据或 `expires_at` 已过）/ `blocked`（人工标记）。
- 隔离要求：**每号独立 profile 目录 + 独立出口**；`effective_concurrency` 会被裁到 ok 账号数。
- `rotation_order` 即轮转顺序；`quarantine` 里的号不再入队，避免空转重试。
- 判据：`pool.ok=true`，`accounts[].credential_masks` 不含明文。

### 5.2 定时通知（cron + 幂等 + 重试上限）

```bash
python Tool/skill/signin-automation/scripts/schedule-notify.py \
  --task daily-signin --accounts acc-1,acc-2 --cron "30 8 * * *" \
  --channel wecom --retries 2 --start-date 2026-10-20 \
  --json-out work/<case>/plan.json
```

- 幂等键 = `sha1(date|account|task)[:16]`：同一天、同账号、同任务只产生一次副作用。
- 重试上限 0–5（默认 2），超过即转人工；退避序列写在计划里。
- 通知载荷三种渠道模板：telegram / dingtalk / wecom（只生成 URL 与 body 骨架，不发请求）。
- 判据：重复执行时 `idempotency_key` 相同且 `duplicate_submits=0`。

### 5.3 验证码分支（图形 / 滑块 / 短信）

```bash
python Tool/skill/signin-automation/scripts/captcha-branch.py \
  --response work/<case>/resp.json --attempts 1 --json-out work/<case>/captcha.json
```

| 分支 | 触发特征 | 下一步 | 判据 |
| :-- | :-- | :-- | :-- |
| `ocr` | 图片/字符类挑战（`image_base64` 存在） | 本地 OCR（`Tool/scripts/temp_ocr.ps1`）后一次性回填 | `ocr.json.confidence`；低置信度直接转 `manual` |
| `interactive` | 滑块/行为/token（`slider_token`、`challenge_type`） | 走滑块/旋转原语拿参数，再提交票据 | `gap.json` / `angle.json` 的 `confidence` 过线 |
| `manual` | 无感 200 但无挑战特征，或连续失败 | 截图 + 挑战原文进人工队列，一次核验 | 人工回填人/时间/结果 |

短信类按 `manual` 处理：验证码只对人类可见，脚本侧只保留“请求已发出”的证据。

### 5.4 滑块缺口（`Tool/scripts/captcha-gap.py`）

```bash
python Tool/scripts/captcha-gap.py --bg work/<case>/bg.png --slice work/<case>/slice.png \
  --json --out work/<case>/gap.json
```

- 方法：Sobel 边缘 + NCC 模板匹配，纯 `numpy`+`Pillow`，本地离线。
- 阈值：`confidence >= 0.55` 直接提交；`0.35–0.55` 用 ±2px 试探；`< 0.35` 换图或转人工（rc=3）。
- 判据：`gap.json` 含 `x` 与 `confidence`；坐标与背景图宽度同量纲（不做 DPR 换算会偏一半）。

### 5.5 旋转角度（`Tool/scripts/captcha-angle.py`）

```bash
python Tool/scripts/captcha-angle.py --image work/<case>/rotate.png \
  --json --out work/<case>/angle.json
```

- 方法：粗搜 5° → 细搜 0.5°，评分用反向旋转后的对称性。
- 阈值：`confidence >= 0.6` 直接提交；`0.35–0.6` 在 ±1.5° 内试 2–3 次；`< 0.35` 换图/人工。
- 90° 对称图只能定到等价类：此时 `ambiguous=true`、`confidence <= 0.35`，**只看 `angle_mod90`**；
  要唯一角必须有箭头/文字等方向线索。

### 5.6 TLS 指纹（curl_cffi / uTLS 的 profile 名与判据）

```bash
python Tool/skill/signin-automation/scripts/tls-fingerprint.py \
  --url https://target.example/api/login --client chrome \
  --ja4 t13d1516h2_8daaf6152771_02713d6af862 \
  --json-out work/<case>/tls-plan.json
```

| 声称浏览器 | `--client` | curl_cffi `impersonate` | 典型 JA4 前缀 | HTTP/2 伪头顺序 |
| :-- | :-- | :-- | :-- | :-- |
| Chrome / Edge 桌面 | `chrome` / `edge` | `chrome124`（回退 `chrome120`、`chrome110`） | `t13d1516h2` / `t13d1517h2` / `t13d1715h2` | `:method :authority :scheme :path` |
| Firefox 桌面 | `firefox` | `firefox133` 起（同族） | `t13d1715h2` 一类 | `:method :path :authority :scheme` |
| Safari iOS | `safari` | `safari18_0` 一类 | 含 3DES/重复签名算法 | `:method :scheme :authority :path` |
| Android App | — | `okhttp4` 一类 | 无 GREASE、无 ECH | `:method :path :authority :scheme` |

- 判据：`tls-plan.json.plan.impersonate` 与 UA 同族；`header_order` 不被业务头污染（先固定档位，再叠业务头）。
- Go 侧同族档位（uTLS）：`HelloChrome_Auto` / `HelloFirefox_Auto` / `HelloSafari_Auto` / `HelloIOS_Auto` /
  `HelloAndroid_11_OkHttp`；选型规则与 curl_cffi 一致——UA 写哪个族就用哪个 `Hello*`，混用等于自报“UA 伪造”。
- 执行侧复算：`tshark -i <iface> -f 'tcp port 443' -Y 'tls.handshake.type==1' -T fields -e tls.handshake.ja3`，
  或读只读回显端点 `tls.peet.ws/api/all` 的 `tls.ja3/ja4`；两次抓包必须同值。
- HTTP/2 侧：`SETTINGS_INITIAL_WINDOW_SIZE`（Chrome 6291456 / Firefox 131072）、
  `MAX_CONCURRENT_STREAMS`（Chrome 1000 / Firefox 125）、`MAX_HEADER_LIST_SIZE` 262144 必须与声称浏览器一致。
- 判据落地：`opsec-check.py` 的 `verdicts.tls_match` 与 `verdicts.h2_order_match` 同时为 true。

## 6. OPSEC 参数表（写进 `opsec.json`，由 runner 读）

| 维度 | 参数 | 建议值 | 判据 / 为什么 |
| :-- | :-- | :-- | :-- |
| 请求间隔 | 分布形状 | 对数正态（`mu=ln(中位间隔)`, `sigma=0.35`） | 固定 sleep 的间隔变异系数≈0，`opsec-check` 会报 at-risk |
| 请求间隔 | 中位间隔 | 单账号 3–8s；全池 ≤ 20–60 次/分钟 | 与 `max_window_rps` 一致，突发窗口才是风控看到的量 |
| 请求间隔 | 停顿 | 每 8–15 次插一次 20–60s 长停顿 | 人不会连续 40 分钟匀速点 |
| 并发 | 单账号并发 | 1（串行） | 同号并发在服务端等于“多设备同时在线” |
| 并发 | 全池并发 | ≤ ok 账号数，且 ≤ 2–4 | `session-pool` 的 `effective_concurrency` 就是这条 |
| 代理池 | 粘性 | 一号一出口，会话内不变 | 会话中途换 IP = 设备指纹与出口不符 |
| 代理池 | 轮换触发 | 429 连续 2 次 / 出口 RTT > 3s / 该号 blocked | 每次轮换都要重登，代价记在失败判据表 |
| 浏览器启动 | 自动化特征 | `--disable-blink-features=AutomationControlled`，并确认 `navigator.webdriver === false` | 只加旗标不改 JS 也能被查；启动后要回显一次 |
| 浏览器启动 | 指纹 seed | 每号固定 `--fingerprint=<seed>`（同号复访用同 seed） | 换 seed = 新设备，会触发“新设备验证” |
| 浏览器启动 | 字体 | 装目标平台字体（emoji / CJK / Windows 字体），`fonts_hash` 落盘 | 缺字体导致 Canvas 哈希与声称系统不符 |
| 对齐 | 时区 | IANA 时区 = 出口 IP 所在时区 | 时区与 IP 不符是 Akamai/Cloudflare 的高权重信号 |
| 对齐 | 语言 | `Accept-Language` 与 `navigator.language(s)` 一致（如 `zh-CN,zh;q=0.9`） | 只改 header 不改 `navigator.languages` 会自相矛盾 |
| 对齐 | 分辨率 | `screen` 与 `window.innerWidth/Height` 同族（如 1920×1080 配 1920×937 可视区） | 无头默认 800×600 是最常见的穿帮点 |
| 对齐 | WebRTC | 泄漏 IP = 出口 IP（`--fingerprint-webrtc-ip=auto`） | 真实内网 IP 泄漏等于直接暴露代理 |

## 7. 模型常见失误（8 条）

1. 把 `status=200` 当登录成功 → 回填的是登录页/SPA 壳；必须同时有 `has_user_marker`。
2. 只比 UA 就说“指纹一致” → JA4、`fonts_hash`、WebRTC 出口、屏幕尺寸任一漂移都算不一致。
3. 用固定 `time.sleep(2)` 当“人味” → 间隔方差≈0 是最好抓的机器特征；改对数正态 + 长停顿。
4. 用总平均 rps 判断限速 → 风控看的是突发窗口；必须按滑动窗口算 `max_window_rps`。
5. 看到 429 就立刻重试 → 等于把“被限速”升级成“被封号”；先退避再换出口。
6. 同一 profile 目录跑两个账号 → 服务端看到同一设备两个身份，直接关联封禁。
7. 手拼 `sec-ch-ua` / 自定义头序以为能改 H2 指纹 → 伪头顺序由库决定；换档位而不是拼字符串。
8. 滑块/旋转低置信度也提交 → 一次错答会把该号拉进“可疑”池；`< 0.35` 一律换图或转人工。

## 8. 脚本与参考索引

| 文件 | 作用 | 自测 / 判据 |
| :-- | :-- | :-- |
| `Tool/skill/signin-automation/scripts/session-pool.py` | 多账号凭据池：状态、并发/限速、失效标记、轮转 | `--self-test` rc=0（9 项） |
| `Tool/skill/signin-automation/scripts/schedule-notify.py` | cron 校验、幂等键、重试上限、三渠道通知载荷 | `--self-test` rc=0（12 项） |
| `Tool/skill/signin-automation/scripts/captcha-branch.py` | 响应特征 → `ocr` / `interactive` / `manual` + `next_action` | `--self-test` rc=0（10 项） |
| `Tool/scripts/captcha-gap.py` | 滑块缺口定位：Sobel + NCC → `x` / `confidence` | `--self-test` rc=0；`<0.35` 时 rc=3 |
| `Tool/scripts/captcha-angle.py` | 旋转角度：粗搜 + 细搜 → `angle` / `angle_mod90` / `ambiguous` | `--self-test` rc=0；`<0.35` 或对称图 rc=3 |
| `Tool/skill/signin-automation/scripts/tls-fingerprint.py` | JA3/JA4 + 档位 + 头序 + H2 开关 → 请求计划 | `--self-test` rc=0（12 项） |
| `Tool/skill/signin-automation/scripts/opsec-check.py` | 会话日志 → 五条判据（会话/指纹/节奏/TLS/H2） | `--self-test` rc=0（12 项）；未过 rc=2 |
| `Tool/skill/signin-automation/references/01-fingerprint-and-pacing.md` | 指纹面清单、TLS/H2 指纹、检测方视角与“怎么自测” | 本文档；每条附只读回显端点用法 |

## 9. 验收（跑完再交付）

```bash
python Tool/skill/signin-automation/scripts/opsec-check.py --session work/<case>/session.json \
  --out work/<case>/opsec.json          # rc=0 或 3 才算过；rc=2 按 next_action 改走
python Tool/scripts/captcha-gap.py --help >/dev/null && echo ok-gap
python Tool/scripts/captcha-angle.py --help >/dev/null && echo ok-angle
python Tool/scripts/preflight.py --fast
```

- 交付物：`accounts.example.json`、`pool.json`、`plan.json`、`captcha.json`、`gap.json` / `angle.json`
  （按需）、`tls-plan.json`、`session.json`、`opsec.json`、`report.md`（池 / 节奏 / 验证码 / 指纹四段）。
- 报告只写 `verdicts.*.pass` 为 true 的结论；未过的写进“失败判据”段落并附 `next_action`。
