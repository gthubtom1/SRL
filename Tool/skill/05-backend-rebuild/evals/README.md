# 阶段五真实演练：site-clone-drill01

> 目的：证明四脚本能在**真实案例产物**上串起来，而不是只在 self-test 的合成数据上通过。
> 产物只写仓库根 `work/`（gitignore），案例目录只读。

## 1. 输入：9 条 `backend_required`

案例 `Tool/cases/site-clone-drill01/artifacts/diff.json` 给出 7 条 `boundary=backend-required` 路由，
`backend_required_features` / `network.blocked_hosts` 点名 2 个跨域 API，合计 9 条：

| # | 案例证据 | 复刻能力端点 | role |
|---|---|---|---|
| 1 | `/find` | `GET /api/quiz/lookup?code=` | list |
| 2 | `/player/name` | `POST /api/player`（加入=建会话） | login |
| 3 | `/player/playing` | `GET /api/player/quiz?quiz_id=` | list |
| 4 | `/player/completed` | `POST /api/player/answer` | submit |
| 5 | `/user/creating` | `POST /api/quiz`（同源形态） | submit |
| 6 | `/user/scoreboard` | `GET /api/scoreboard?quiz_id=` | list |
| 7 | `/user/share` | `GET /api/share?code=` | list |
| 8 | `api.youtest.me/info/country` | `GET /info/country` | heartbeat |
| 9 | 创建测验写入（跨域 `POST api.youtest.me`） | `POST /api/quiz`（跨域形态，与 #5 同 path 不同 host） | submit |

另外把 6 条**录制页面数据** `_next/data/<build>/<route>.json` 一并放进 HAR，
它们有真实响应体，用于验证"录制快照逐字节回放"（与 9 条能力端点分开记账）。

## 2. 命令

```bash
# 全流程（约 5~10 秒）
python Tool/skill/05-backend-rebuild/evals/run-drill.py

# 指定案例/产物目录（产物必须在 <repo>/work/ 下）
python Tool/skill/05-backend-rebuild/evals/run-drill.py \
  --case Tool/cases/site-clone-drill01 --work work/backend-rebuild-drill01

# 保留上次产物做对比（默认清空重建）
python Tool/skill/05-backend-rebuild/evals/run-drill.py --keep
```

退出码：0 = 全流程通过；2 = `{ok:false,blocked_at,reason}`，`blocked_at` 指明卡在哪个阶段。

## 3. 产物

```
work/backend-rebuild-drill01/
├── har.backend-required.json   # 15 条 HAR entry（9 能力 + 6 录制数据）
├── items.json                  # 9 条清单 + 证据 + 录制数据索引
├── recorded/                   # 6 份录制体副本（schema 输入）
├── api/
│   ├── api-surface.json        # 15 端点，样本 6
│   ├── api-surface-js.json     # JS 静态交叉验证（/info/country 等）
│   ├── schema.json / schema.sql
│   └── switched.json           # 四类 × 三路
├── backend/                    # server.py / routes.json / snapshots/ / hosts.fragment / proxy.pac
├── report.json
└── REPORT.md
```

## 4. 期望结果（可复算）

| 指标 | 值 |
|---|---|
| 清单条数 | 9（7 capability + 2 api） |
| 角色 | login 1 / list 4 / submit 3 / heartbeat 1 |
| API 面端点 | 15（GET 11 / POST 4），有样本 6 |
| schema 表 | 6；主键 `[]`（录制体只有 shell 字段） |
| mock | 15 路由：录制 6 / 骨架 9 |
| switch-verify | `verdict=pass`，`counts={cases:12, pass:12, fail:0}` |

删除 `work/backend-rebuild-drill01` 后重跑，除 `base` 端口与 `ms` 耗时外结果一致。

## 5. 边界与诚实声明

- **9 条清单 → 9 个能力端点** 是"实现形态"，不是原厂路径；证据列在 `items.json.evidence`。
- #5 与 #9 是同 path 不同 host 的两种形态，故意都注册（host 别名是真实故障源之一）。
- 9 条能力端点**没有录制响应体**，mock 返回 `source=scaffold-stub`；录制的 6 条页面数据才回放真实体。
- 页面数据体只有 `pageProps.title` 一类 shell 字段 → schema 主键不可判是**正确结果**，不是脚本缺陷。
- 本案到 **L3**：结构通、四类×三路全绿、可复跑；M4 还缺真实会话样本、签名字段复算、下发物版本与停服 UI 表现。

## 6. 换一个案例怎么用

1. 把案例的 `data_boundary` 里 `backend-required` 条目数、`backend_required_features` 读出来；
2. 在 `run-drill.py` 的 `CAPS`/`EXTRA_APIS` 里写"页面 → 能力端点"映射（保持 9 条口径就改断言）；
3. 有录制响应体的端点直接进 HAR `response.content.text`；
4. 跑 `run-drill.py`，失败时按 `blocked_at` 定位（`har` / `api-surface` / `schema-infer` / `backend-scaffold` / `switch-verify`）。
