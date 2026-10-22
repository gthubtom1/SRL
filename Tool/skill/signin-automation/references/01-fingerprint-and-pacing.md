# 01 · 浏览器指纹面与请求节奏（signin-automation）

> 范围：账号任务自动化的“像不像同一台真人设备”这一层——浏览器指纹面、TLS/HTTP2 网络指纹、
> 检测方会看什么、以及每一项**怎么自测**。
> 路由：单次登录抓包/签名还原走 `web-pentest`；APK/小程序侧签名走 `apkseep`；
> 本页只回答“这条链路的指纹面是否自洽、节奏是否会触发风控”。
> 机检入口：`Tool/skill/signin-automation/scripts/opsec-check.py`（五条判据）；
> 档位生成：`Tool/skill/signin-automation/scripts/tls-fingerprint.py`（不发请求，只出计划）。

本页的所有自测都只用**公开只读回显端点**（GET、无凭据、无登录），不向目标站点发额外请求。
回显端点的作用是“把浏览器/客户端自己看到的证据落盘”，不是攻击面。

## 1. 浏览器指纹面清单（同一会话内必须恒定）

| 面 | 观测源（浏览器侧） | 一致条件 | 自测方法（只读） |
| :-- | :-- | :-- | :-- |
| User-Agent | `navigator.userAgent` + 请求头 `User-Agent` | 两处字节完全相同，且与声称的浏览器大版本一致 | 打开 `https://httpbin.org/headers` 看回显的 `User-Agent`，与 `navigator.userAgent` 逐字符比对 |
| Client Hints | `navigator.userAgentData.brands` / `getHighEntropyValues()` | `sec-ch-ua`、`sec-ch-ua-platform`、`sec-ch-ua-mobile` 与 UA 同族同版本；`full-version-list` 大版本一致 | `https://tls.peet.ws/api/all` 的 `http1.headers` 里有实际发出的 `sec-ch-ua*`；再在控制台跑 `await navigator.userAgentData.getHighEntropyValues(["platformVersion","fullVersionList"])` 对照 |
| Canvas | `toDataURL()` 的稳定哈希 | 同一 profile 多次、多标签页哈希一致；与声称平台的字体渲染一致 | 页面里 `document.createElement('canvas').toDataURL().length` + 自己算 sha256；`https://browserleaks.com/canvas` 直接给 hash 与“是否唯一” |
| WebGL | `UNMASKED_VENDOR_WEBGL` / `UNMASKED_RENDERER_WEBGL`、`getSupportedExtensions()` | vendor/renderer 与声称 GPU 档位一致；扩展列表长度合理（不是空数组） | 控制台读 `gl.getParameter(gl.UNMASKED_RENDERER_WEBGL)`（需 `WEBGL_debug_renderer_info`）；`https://browserleaks.com/webgl` 有完整回显 |
| 字体 | `document.fonts.check()` 的枚举结果集 | 字体集哈希恒定；与声称 OS 的默认字体集同族（如 Windows 有 Segoe UI，Linux 通常没有） | 逐个 `document.fonts.check("12px 'Segoe UI'")` 收集布尔向量再哈希；`https://abrahamjuliot.github.io/creepjs/` 给字体指纹与“异常”提示 |
| 时区 | `Intl.DateTimeFormat().resolvedOptions().timeZone` + `getTimezoneOffset()` | IANA 时区与出口 IP 的 geo 一致；偏移随夏令时正确变化 | `https://tls.peet.ws/api/all` 不回时区，用控制台读两个值；出口 IP 归属用 `https://ipinfo.io/json` 一类只读端点核对 |
| 语言 | `navigator.language` / `navigator.languages` | 与请求头 `Accept-Language` 同族同顺序（如 `zh-CN,zh;q=0.9` ↔ `["zh-CN","zh"]`） | 控制台读 `navigator.languages`，与 `https://httpbin.org/headers` 回显的 `Accept-Language` 比对 |
| 屏幕 | `screen.width/height`、`screen.availWidth/availHeight`、`devicePixelRatio` | `avail*` ≤ `*`；DPR 与分辨率组合是真实存在过的机型；可视区小于屏高（有工具栏） | 控制台读三个对象后做一致性断言；`https://browserleaks.com/screen` 有回显 |
| 硬件并发数 | `navigator.hardwareConcurrency` | 取值在 {2,4,6,8,12,16,20,24} 内且与本机/声称机型匹配 | 控制台读；`https://deviceandbrowserinfo.com` 会把它列进指纹面并与 UA 做合理性判断 |
| 内存 | `navigator.deviceMemory` | 与并发数同档位（8 核配 8GB 而不是 64GB） | 同上，控制台读 `navigator.deviceMemory` |
| WebRTC | ICE candidate 里的 IP、`RTCPeerConnection` 可用性 | 泄漏 IP 必须等于出口 IP；不给内网真实地址 | `https://browserleaks.com/webrtc` 直接列出 candidate；或页面里建一个 `RTCPeerConnection({iceServers:[]})` 收集 `onicecandidate` |
| 插件/媒体设备 | `navigator.plugins.length`、`enumerateDevices()` | 无头默认 0 插件、0 音频设备，是高频穿帮点 | `https://browserleaks.com/javascript` 与 `https://abrahamjuliot.github.io/creepjs/` 都列这项 |

**落盘格式**：每个请求一行，字段名与 `opsec-check.py` 的 `FP_FIELDS` 对齐
（`ua` / `ch_platform` / `timezone` / `locale` / `fonts_hash` / `webgl_vendor` / `webgl_renderer` /
`screen` / `hardware_concurrency` / `device_memory` / `webrtc_ip`）。判据只看“同一会话里是不是只有 1 个取值”。

## 2. TLS 指纹（JA3 / JA4）

### 2.1 两个哈希各看什么

- **JA3**：`TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats` 用 `-` 连接后取 MD5。
  粒度粗，但能一眼分出“这是 curl 默认栈”还是“这是浏览器栈”。
- **JA4**：明文结构 `t13d1516h2_<cipher hash>_<extension hash>`，第一段自带
  `协议版本 + SNI(d/ i) + cipher 数量 + extension 数量 + ALPN 首项`。比 JA3 更能区分同族不同版本。

判据不是“JA3 好看”，而是**会话内唯一 + 与声称浏览器同族 + 换机复算同值**。

### 2.2 档位与常见族

| 声称浏览器 | curl_cffi `impersonate` | JA4 前缀（示例） | 容易踩的点 |
| :-- | :-- | :-- | :-- |
| Chrome 124–142 桌面 | `chrome124`（回退 `chrome120` / `chrome110`） | `t13d1516h2` / `t13d1517h2` / `t13d1715h2` | 手改 cipher 列表会把 GREASE 顺序打乱，直接变成另一个指纹 |
| Firefox 桌面 | `firefox133` 起同族档位 | `t13d1715h2` 一类 | Firefox 把 `:path` 放在 `:authority` 前，和 Chrome 不同族 |
| Safari iOS | `safari18_0` 一类 | 含 3DES/重复签名算法 | 桌面 TLS 配 iOS UA 会被直接判“UA 伪造” |
| Android App（OkHttp） | `okhttp4` 一类 | 无 GREASE、无 ECH、扩展少 | OkHttp 3 只到 TLS1.2，现代站点可能直接拒 |

### 2.3 怎么自测

```bash
# ① 客户端侧：一次 GET 换回 TLS/HTTP2/头序全部回显（只读、无凭据）
curl -sS --max-time 20 https://tls.peet.ws/api/all -o work/<case>/fp-client.json
# 关键字段：tls.ja3, tls.ja4, http2.akamai_fingerprint(=伪头顺序+SETTINGS 摘要), http1.headers

# ② 线路侧：抓一次 ClientHello 自己算 JA3（需要本机有 tshark）
tshark -i <iface> -f 'tcp port 443' -Y 'tls.handshake.type==1' \
  -T fields -e tls.handshake.ja3 -e tls.handshake.ja4 -c 1

# ③ 计划侧：拿期望值反查档位（不发请求）
python Tool/skill/signin-automation/scripts/tls-fingerprint.py \
  --url https://target.example/ --client chrome \
  --ja4 t13d1516h2_8daaf6152771_02713d6af862 --json-out work/<case>/tls-plan.json
```

判定：①②两处的 JA3/JA4 必须同值；③的 `plan.impersonate` 必须与 ① 的实际栈同族。
三处任一不一致 → 说明“计划用的档位”和“实际跑起来的客户端”不是同一个东西（常见于代理侧 TLS 终止）。

## 3. HTTP/2 头序（伪头顺序 + SETTINGS）

| 浏览器 | 伪头顺序 | `SETTINGS_INITIAL_WINDOW_SIZE` | `MAX_CONCURRENT_STREAMS` | `MAX_HEADER_LIST_SIZE` |
| :-- | :-- | --: | --: | --: |
| Chrome / Edge | `:method :authority :scheme :path` | 6,291,456 | 1000 | 262,144 |
| Firefox | `:method :path :authority :scheme` | 131,072 | 125 | 65,536 |
| Safari iOS | `:method :scheme :authority :path` | 2,097,152 | 100 | —（不下发） |
| OkHttp 4 | `:method :path :authority :scheme` | 16,777,216 | 1000 | — |

- 伪头顺序**由 HTTP/2 库决定**，改不了：`h2` 库按 `:method/:path/:authority/:scheme` 出，curl_cffi 的
  `impersonate` 档位才按浏览器重排。所以“换档位”是唯一可控动作，“手拼 header”无效。
- 业务头（`Authorization`、`token`、`device_id`）要**在档位固定之后再叠**，避免污染头序。
- 判据：会话内 `h2_pseudo_order` 唯一，且等于 `claimed.h2_pseudo_order` 或声明浏览器族的标准顺序
  （`opsec-check.py` 的 `verdicts.h2_order_match`）。
- 自测：`https://tls.peet.ws/api/all` 的 `http2.akamai_fingerprint`/`sent_frames` 会给出这一帧的伪头顺序与
  SETTINGS 参数；`https://nghttp2.org/httpbin/headers` 用来确认实际到达服务端的 header 集合（不含顺序）。

## 4. 检测方视角：Cloudflare / Akamai 常看什么

下面每一条都写成**可量化的阈值**，便于自测与写进判据表；阈值是经验区间，不保证对每个站点都成立，
但只要有一条严重越界，就说明“这条链路不像人”。

| 信号 | 检测方怎么算 | “像人”的经验阈值 | 自测方法 |
| :-- | :-- | :-- | :-- |
| TLS/H2 与 UA 同族性 | JA3/JA4/伪头顺序 vs `User-Agent` 大版本 | 三处同族；“Chrome UA + curl 栈”是最常见的不一致 | 抓一次 ClientHello（§2.3 ②）+ `tls.peet.ws/api/all` 对照 |
| IP 与 UA/时区一致性 | 出口 IP 的 ASN/geo vs UA 里的平台与时区 | ASN 为住宅/移动网络；时区偏移与 geo 一致；机房 ASN 直接降权 | `https://ipinfo.io/json` 只读核对 ASN/时区；`https://tls.peet.ws/api/all` 看 `tls.tls_version_negotiated` 是否被降级 |
| 请求间隔分布 | 相邻请求间隔的**方差**与分布形状 | 变异系数 ≥ 0.3（对数正态）；固定间隔≈0 是最强机器特征 | 把日志时间戳丢给 `opsec-check.py`，看 `pacing_ok.gap_cv`；`< 0.05` 会给出 at-risk |
| 突发窗口 | 任意 N 次请求的瞬时速率 | 滑动窗口峰值 ≤ 人手动速率的 2–4 倍；出现 429 说明已越线 | 同一脚本的 `pacing_ok.max_window_rps`；调 `limits.max_rps` 复算 |
| 鼠标轨迹 | 采样点的曲率、步长、是否存在直线瞬移 | 有 Bézier 曲率与 15% 左右过冲；瞬移（同一点连点/零位移点击）是机器特征 | 录一次会话看 `mousemove` 的坐标序列：相邻点距离应非恒定、方向应渐变 |
| 键盘节奏 | 相邻 `keydown` 间隔、是否有停顿/错字回改 | 每字符 70±40ms，10% 概率长停顿，偶发错字回退 | 页面里挂 `keydown` 监听打印 `performance.now()` 差值，看是否恒定 |
| 页面停留 | 首次导航→首个交互、表单填写的停留时长 | 关键字段间有 0.8–1.5s 的“阅读”停顿，整页停留 ≥ 数秒 | 用 Performance 面板录一段，看事件时间轴是否“一路匀速” |
| 交互前是否有前置导航 | 是否直接 POST 提交接口 | 正常会话有 `GET /` → 静态资源 → `POST /login` 的序列 | 抓包看 Referer/`sec-fetch-site`：直接打接口通常 `sec-fetch-site: none` 且无 Referer |
| 滚动与可见性 | `scroll` 事件、`IntersectionObserver`、`visibilitychange` | 有渐进滚动与短暂失焦，不是“永远前台可见” | 手动与脚本各跑一次，比对 `document.visibilityState` 序列与 `scrollY` 轨迹 |
| 指纹唯一性分数 | CreepJS 一类库的“同一浏览器多标签页是否给出同一指纹” | `getBoundingClientRect` 的 noisiness 稳定、无 `headless` 特征 | 同一 profile 连开两个标签页跑 `https://abrahamjuliot.github.io/creepjs/`，两次 trust score 与 hash 应一致 |

**读法**：一条 429 或一次滑块不说明“指纹错”，它只说明“某个信号越界”。按顺序排查——
节奏（间隔方差、突发窗口）→ 出口（IP 与会话是否粘性）→ 浏览器指纹面（§1）→ 网络指纹（§2/§3）。
每轮只改一个变量，否则无法归因。

## 5. 一份可直接抄的自测清单

```text
[ ] session-fp-1   https://tls.peet.ws/api/all      → 保存 ja3/ja4/akamai_fingerprint/http1.headers
[ ] session-fp-2   控制台读 UA / userAgentData / languages / timezone / screen / hardwareConcurrency / deviceMemory
[ ] session-fp-3   https://browserleaks.com/webrtc   → 记录 candidate IP，确认等于出口 IP
[ ] session-fp-4   同一 profile 连开两标签页重跑 1–3 → 两次结果必须一致
[ ] session-net-1  tshark 抓 ClientHello → JA3/JA4 与 session-fp-1 同值
[ ] session-net-2  http2.akamai_fingerprint 的伪头顺序与声称浏览器族一致
[ ] session-pace-1 日志时间戳 → opsec-check.py 的 gap_cv ≥ 0.3、max_window_rps ≤ 上限
[ ] session-pace-2 连续两天同账号同任务 → 幂等键一致、重复副作用 0
[ ] session-capt-1 出现挑战时先跑 captcha-branch.py 定分支，再决定 ocr/interactive/manual
[ ] session-capt-2 滑块/旋转的 confidence 与阈值（0.55 / 0.6）比对后再提交
```

把这十条的结果写进 `work/<case>/session.json`（字段对齐 `opsec-check.py`），再跑一次：

```bash
python Tool/skill/signin-automation/scripts/opsec-check.py \
  --session work/<case>/session.json --out work/<case>/opsec.json
```

`rc=0` 表示五条判据全过；`rc=3` 表示有 at-risk 警告（通常是节奏太规整）；
`rc=2` 时按输出的 `blocked_at` 与 `next_action` 改走，**不要加请求量去试**。

## 6. 与失败判据的对应

| 本页发现的偏差 | 落到 SKILL.md 的哪条失败判据 | 改走 |
| :-- | :-- | :-- |
| `gap_cv < 0.05` 或 `max_window_rps` 超限 | 节奏触发（429 前兆） | 间隔改对数正态 + 长停顿；`max_rps` 砍半 |
| `fp_stable=false`（UA/字体/WebRTC 漂移） | 设备指纹不匹配 | 固定 profile seed + 粘性出口，只改一个变量重测 |
| `tls_match=false`（JA4 前缀不符/多值） | 指纹与 UA 不同族 | 换 `--client` 档位；关掉代理侧 TLS 终止 |
| `h2_order_match=false` | 伪头顺序不符 | 换与 UA 同族的库档位，业务头后叠 |
| `session_valid=false`（200 但无用户标识） | 登录后立刻掉线/假成功 | 回抓登录链，补设备校验/二次校验 |
| 挑战类型判不出、或 confidence 低于阈值 | 验证码分支不可信 | 换图重取；超 3 次转人工，别硬猜 |
