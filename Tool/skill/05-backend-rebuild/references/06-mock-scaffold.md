# mock 脚手架：录制回放 + 明确标注的骨架

> 目标不是"看起来像后端"，而是**让客户端走到下一步，同时不撒谎**。
> 每个响应都带 `source`：`recorded` 是录制的，`scaffold-stub` 是推断的骨架。

## 1. 生成物

`backend-scaffold.py --api api-surface.json --schema schema.json --out work/backend` 产出：

| 文件 | 内容 | 是否可改 |
|---|---|---|
| `server.py` | 单文件 `http.server`，路由/快照/骨架全部内嵌 | 可读，重生成会覆盖 |
| `routes.json` | 路由表（path/pattern/method/role/snapshot/origin） | 只读，用于核对 |
| `snapshots/*.json` | 从 api-surface 样本复制来的录制体 | 只读证据 |
| `schema.json` | schema 副本（表/主键/枚举） | 只读 |
| `hosts.fragment` | `127.0.0.1 <host>` 行 | 可人工合并 |
| `proxy.pac` | 最小 PAC 模板（默认端口 8787） | 改端口后重新生成 |
| `README.md` | 起服务/三路语义/切换说明 | 可改 |

零第三方依赖：只用 `argparse/json/os/re/time/urllib/http.server`。Python ≥ 3.8 可跑。

## 2. 路由匹配

- 每条端点生成一个正则：`/a/{id}`、`/a/:id`、`/a/<id>` 的变量段 → `[^/]+`，其余字符 `re.escape`，末尾允许一个 `/`。
- 同一端点的 `aliases`（截断形态）各自成一条路由，`truncated=true`，指向同一快照。
- 匹配优先级：按 `paths` 排序后取第一个命中；同 path 不同 method 分开注册。
- 方法不匹配但路径命中 → 405，附 `allowed` 列表；路径不命中 → 404。

## 3. 响应决策树

```text
/__health 或 /__routes            → 元信息（含 routes/recorded/stub/hosts/tables）
有 __delay 且钩子开               → sleep(≤10s)，继续
有 __status 且钩子开              → 直接回该码 + {"error": __error}
方法/路径命中？
  ├─ 否 → 405（路径命中） / 404 not_implemented（路径不命中）
  └─ 是
      ├─ --strict 且缺必需 query/body 字段 → 400 validation_failed
      ├─ 有快照 → 录制状态码 + 快照字节（source=recorded）
      └─ 无快照 → 200 + 骨架（source=scaffold-stub，含 endpoint/table/fields/items=[]）
```

骨架长这样（不会伪造业务值）：

```json
{"ok": true, "source": "scaffold-stub", "snapshot": "missing",
 "endpoint": "POST https://block.youtest.me/api/player",
 "reason": "无录制快照：形状按 api-surface/schema 推断，不是业务数据",
 "table": "player_name", "fields": ["pageProps", "__N_SSG"], "result": null}
```

## 4. 测试钩子

| 钩子 | 用法 | 用途 |
|---|---|---|
| `__delay=<秒>` | 任意路径加 query | 造超时（客户端 1 s 超时即触发） |
| `__status=<码>` | 任意路径加 query | 造错误码（401/409/502） |
| `__error=<code>` | 配合 `__status` | 错误信封内容 |

钩子只应在本地/CI 开：部署时加 `--no-test-hooks`，或在网关层剥掉这三个参数。
`switch-verify.py` 的三路回归依赖它们；服务端不带钩子时，超时路径会自动退回黑洞 socket。

## 5. 命令

```bash
# 生成（不启动）
python Tool/skill/05-backend-rebuild/scripts/backend-scaffold.py \
  --api work/api/api-surface.json --schema work/api/schema.json --out work/backend

# 生成 + 前台启动
python Tool/skill/05-backend-rebuild/scripts/backend-scaffold.py \
  --api work/api/api-surface.json --schema work/api/schema.json --out work/backend \
  --serve --port 8787

# 直接跑生成的 server
python work/backend/server.py --host 127.0.0.1 --port 8787 --strict

# 自检（生成 + 起停 + 200/404/405/401 四种断言）
python Tool/skill/05-backend-rebuild/scripts/backend-scaffold.py --self-test
```

`--serve` 会先打印一行 `{"ok":true,"base":"http://127.0.0.1:<port>","routes":N}`，再阻塞服务；
脚本化调用时读这一行拿真实端口。

## 6. 演练实测（site-clone-drill01）

| 指标 | 值 |
|---|---|
| backend_required 清单 | 9 条（7 页面能力 + 2 跨域 API） |
| API 面端点 | 15（9 能力 + 6 条录制 `_next/data`） |
| mock 路由 | 15 |
| 录制回放 | 6（`_next/data/<build>/<route>.json`，真实体） |
| 派生骨架 | 9（能力端点无录制响应体） |
| 四类×三路回归 | 12/12 通过 |

结论：录制覆盖到的页面数据走回放；业务写入/会话没有录制体，明确回骨架。
这条边界写进报告，避免把"骨架 200"说成"接口已实现"。

## 7. 从 mock 到忠实后端

| 阶段 | 做法 | 判据 |
|---|---|---|
| M2 骨架 | 全部回骨架 + 录制回放 | 客户端能走到下一步，不崩 |
| M3 契约 | 按 schema 落库，实现读接口 | 列表/详情的字段集合与录制一致 |
| M3+ 写入 | 提交/登录落库，幂等与错误码到位 | `switch-verify` 四类×三路全绿 + 幂等用例 |
| M4 忠实 | 签名重算、心跳语义、下发物版本 | 关停表现与原厂一致；干净机器可部署 |

替换点：`server.py` 的"骨架分支"换成真实处理函数；快照保留作为回归基线（不是运行时依赖）。

## 8. 安全与边界

- 服务只绑 `127.0.0.1`（默认），对外暴露要显式 `--host` 并加访问控制。
- `snapshots/` 里可能含脱敏前的业务字段：入库前跑一遍脱敏检查（邮箱/手机/token）。
- 测试钩子、`/__routes`、`/__health` 在生产形态由网关屏蔽。
- 录制体只用于本地回放，不作为"线上数据"分发。

## 9. 失败判据

| 症状 | 根因 | 修法 |
|---|---|---|
| 客户端一直 404 | 注册的是规范路径，客户端发的是截断形态 | 看 `routes.json` 的 `truncated`，补别名 |
| 一直 401 | 404 被错误地实现成 401 | 按 §3 决策树分开 |
| 骨架被当成真实数据 | 报告没写 `source` | 所有响应带 `source`，报告单列骨架数 |
| 超时路径测不出 | 服务端没钩子 | 用 `--no-test-hooks` 时改黑洞探针（switch-verify 自动） |
| 端口冲突 | 固定 8787 被占 | `--port 0` 让系统分配，读启动行 |
| 换机器跑不起来 | PAC/hosts 写死了本机端口/路径 | 重新生成，端口走参数 |
