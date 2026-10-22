# API 面测绘：HAR / pcap(json) / JS 三源交叉

> 产物只有一个：`api-surface.json`。没有它就不写后端——写完再补测绘，等于按想象实现。

## 1. 为什么必须三源交叉

| 源 | 能回答 | 答不了 |
|---|---|---|
| HAR | 客户端**实际**发出的 method / path / query / body / 状态码 / 响应体 | 只在运行时出现的分支（未点到的按钮）、定时任务 |
| pcap(json) | 非浏览器客户端（APK/桌面端）的真实字节、TLS 之外的裸协议 | JS 里的字符串常量、路由拼接逻辑 |
| JS 文本 | 路由常量、截断、别名、host 常量、未触发分支 | 真实头、真实参数、真实错误码 |

单源必错：只信 HAR 会漏掉"用户没点到的接口"；只信 JS 会把 `const PREFIX="/v1/chat"` 拼出来的运行时路径当规范路径。

## 2. 输入形态

### HAR

- 浏览器 DevTools / Playwright `context.new_har()` / mitmproxy 导出均可。
- 只要 `log.entries[]`；`request.url`、`request.method`、`request.queryString`、`request.postData.text`、`response.status`、`response.content.text` 六个字段决定成败。
- `content.encoding == "base64"` 会被解码；空 `text` 视为**无样本**（不是空响应样本）。
- 入库前脱敏：`Cookie` / `Authorization` / `Set-Cookie` / 手机号 / 邮箱一律替换成占位符；HAR 是证据，不是凭据仓库。

### pcap(json)

- 纯标准库不解析二进制 pcap。脚本检测 magic（`d4c3b2a1` / `a1b2c3d4` / `4d3cb2a1`）后直接 `blocked_at=pcap-binary`。
- 合法输入是 JSON 流表，三种顶层形态都认：
  ```json
  {"flows": [{"method":"POST","url":"https://h/api/x","body":{...},"response":{"status":200,"body":{...}}}]}
  ```
  或 `{"requests":[...]}`，或裸列表。
- 每条至少给 `url`（或 `host`+`path`）；`response.body` 是对象/数组时进入样本。

### JS 文本

- 目录递归只收 `.js/.mjs/.cjs/.ts/.jsx/.tsx/.map`，单文件 8 MiB 上限。
- 抽取四类字面量：`https?://…`、引号包住的 `/…` 路由、`host/baseUrl/apiHost` 常量、`method:"POST"` 或 `axios.post` 邻近方法。
- 路由前缀默认表：`/api /v1 /v2 /v3 /info /auth /login /token /session /user /player /find /dl /script /heartbeat /ping /poll /version /upload /admin /quiz /scoreboard /share /data`。可用 `--js-path-prefixes` 覆盖（逗号分隔）。
- 纯主机 URL（`https://h`）不算端点，避免把 base 常量当成 `GET /`。

## 3. 端点唯一键与参数面

- 唯一键 = `method + host + path`；`scheme` 只用于 `id` 展示。
- `id` 形如 `POST https://api.example.test/v1/chat/completions`，排序按 `(method, host, path)`，输出可复算。
- query 参数面：`{"名字": {"observed": [...], "required": bool, "source": ["har"|"pcap"|"js"]}}`；`observed` 去重排序，**保留观测值**（`trace=1` 这种也要留）。
- body 参数面：顶层字段 + 一层嵌套（`a.b`），记录 `types` 与来源。GET 带 body 会加 note，按实际实现，不改形态。
- `required` 目前按"抓包里每次都出现"判定；`--strict` 的服务端校验用它，误报时以抓包为准改标记。

## 4. 截断与别名（最容易漏的失败）

> 真实故障：客户端把 URL 定长截断成 `/v1/chat/c`、`/vid/`，服务端只注册 `/v1/chat/completions`，
> 请求落到鉴权分支 → 401「登录已过期」→ 脚本死循环。

规则：

1. 同一 host 下，A 是 B 的**严格前缀**、A 不以 `/` 结尾、B 还有后续字符 → A 记 `truncated=true`，`aliases` 收 B。
2. 截断端点**单独成条**，不并进规范路径；mock 里两条都注册。
3. host 形态不同（同 path、`block.youtest.me` vs `api.youtest.me`）也算别名，登记在 `notes`/`evidence`，
   由实施者决定是否两条都开。
4. 大小写、尾斜杠、`//`、`;jsessionid` 归一后再比较，但**保留原始 `raw`** 作为证据。

## 5. 角色（role）判定

`switch-verify.py` 靠 role 选四类探针，规则写死在脚本里，顺序敏感：

| 顺序 | role | 命中正则（节选） |
|---|---|---|
| 1 | login | `login|signin|auth|token|session|join|/player$|/user$` |
| 2 | heartbeat | `heartbeat|keepalive|/ping|/poll|/version|/alive|/uptime|/info/` |
| 3 | submit | 剩余 POST/PUT/PATCH/DELETE |
| 4 | list | 剩余 GET |
| 5 | other | HEAD/OPTIONS |

误判处理：在 api-surface.json 里改 `role` 字段后重跑（脚本按端点重算，改完记得写回），
或在 switch-verify 里换探针。不要为了凑四类去抓无关请求。

## 6. 命令与产物

```bash
# 三源一起喂
python Tool/skill/05-backend-rebuild/scripts/api-surface.py \
  --har work/capture/har.json \
  --pcap work/capture/flows.json \
  --js  work/site/assets \
  --out work/api/api-surface.json

# 只看某一台主机，且样本落盘到指定目录
python Tool/skill/05-backend-rebuild/scripts/api-surface.py \
  --har work/capture/har.json --hosts api.example.test \
  --samples-dir work/api/samples --out work/api/api-surface.json

python Tool/skill/05-backend-rebuild/scripts/api-surface.py --self-test
python Tool/skill/05-backend-rebuild/scripts/api-surface.py --help
```

产物：

- `api-surface.json`：`schema/sources/stats/endpoints/roles/orphans/rules` 七块。
- `samples/`：每个观测响应一个 JSON，文件名 `<id 摘要>-<sha 前 10 位>.json`，内容截到 `--max-sample-bytes`（默认 64 KiB）。
- `stats.by_role` 必须四类齐全（T2/T3）；缺类说明抓包没覆盖或 role 规则要调。

## 7. 验收判据

| # | 判据 | 机检字段 | 通过线 |
|---|---|---|---|
| 1 | 端点有证据 | 每个 endpoint 的 `evidence` 非空 | 100% |
| 2 | 参数面带观测值 | `query`/`body_fields` 至少一项有 `observed` 或 `types` | 主流程端点 100% |
| 3 | 截断/别名登记 | `stats.truncated` 与抓包/JS 对照 | 差 0 条 |
| 4 | 四类齐全 | `roles` 含 login/list/submit/heartbeat | 4/4 |
| 5 | 样本可复算 | `samples[].sha256` 重算一致 | 100% |
| 6 | 静态交叉验证 | 同一 path 在 HAR 与 JS 都能找到（或写明只有单源证据） | 主流程端点 |

## 8. 失败判据（先查这些，再怀疑实现）

- `orphans` 非空：HAR 脱敏成空 / host 白名单过滤过严 / JS 前缀表太窄。
- `stats.with_samples < 主流程端点`：HAR 抓的是 metadata（`Content-Length: 0`）或响应体被导出工具丢掉。
- 端点数量远大于预期：JS 抽到了 static chunk 里的资源路径，收窄 `--js-path-prefixes`。
- 全部 `role=other`：method 丢了（HAR 正常不会有），检查 pcap 流表的 `method` 字段。
- `truncated=0` 但你怀疑有截断：用 JS 的原始引号字符串再跑一遍，`--js-path-prefixes` 加上 `/` 开头的自定义前缀。
