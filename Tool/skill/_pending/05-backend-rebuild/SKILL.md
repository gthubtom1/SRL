---
name: 05-backend-rebuild
description: "'客户端依赖服务端/把后端也复刻出来 (.exe) —— 阶段⑤：后端复刻（业务 API / 服务端能力 / 远程下发容器）。"
metadata:
  stage: "5/6"
  trigger: "T2/T3"
  prev: "01-gate-bypass"
---

> **适用范围**：本技能是主域按需调用的方法，不是每项任务的必经阶段。沿用 router 的当前项目/版本/run；只做用户目标需要的部分。阶段编号/prev/next 是相关方法索引，不授权扩大任务。静态分析不强制改包、旁路、换品牌、接授权或重建后端。专门成品路径的硬闸仍按原判据验收，不以删步骤冒称成品完成。

# 05 · 后端复刻（客户端 + 服务端都自洽）

> **成功标准（M4）**：客户端指向**我们自己的后端**，登录/卡密/心跳/业务/下发全部走通；
> 关掉我们的后端时，客户端表现与"原厂停服"一致（不是崩、不是死循环）。

> **通用性声明**：文中端点、路径、错误码都是示例；判据看"形状"，实际以目标为准。

本技能自带 4 个零依赖脚本 + 1 个真实演练，全部可 `--self-test`：

| 层 | 文件 | 作用 |
|---|---|---|
| 判据 | [01 API 面](references/01-api-surface.md) | HAR/pcap/JS 三源、截断/别名、role 规则 |
| 判据 | [02 数据模型](references/02-data-model.md) | 字段聚类、主键/枚举/时间、DDL 草案 |
| 判据 | [03 存储](references/03-storage.md) | 落库、事务/幂等、迁移、干净机器部署 |
| 判据 | [04 会话与鉴权](references/04-session-auth.md) | 签名重算、key 归属、401/404 分离、心跳 |
| 判据 | [05 业务规则](references/05-business-rules.md) | 状态机、不变量、幂等、边界值 |
| 判据 | [06 mock 脚手架](references/06-mock-scaffold.md) | 生成物、回放/骨架、测试钩子、局限 |
| 判据 | [07 切换与回归](references/07-switch-and-regression.md) | hosts/PAC/patch、四类×三路、停服 |
| 判据 | [08 失败判据](references/08-failure-criteria.md) | blocked/fail/rework、L1/L2/L3 口径 |
| 脚本 | `scripts/api-surface.py` | HAR / pcap(json) / JS → `api-surface.json` |
| 脚本 | `scripts/schema-infer.py` | 响应样本 → `schema.json` + `CREATE TABLE` 草案 |
| 脚本 | `scripts/backend-scaffold.py` | api-surface + schema → 可跑本地 mock（录制回放 + 明确骨架） |
| 脚本 | `scripts/switch-verify.py` | 切本地后端 → 四类 × 正常/超时/错误码 → `switched.json` |
| 演练 | `evals/run-drill.py` | site-clone-drill01 的 9 条 `backend_required` 端到端 |

---

## 0. 触发条件（先做 §3bis 三问，三问齐备再进入）

| 问 | 命中含义 |
|---|---|
| Q1 除授权外还有业务端点吗？ | 有 → 至少 T2 |
| Q2 这些能力在客户端里实现了吗？ | 找不到实现/密钥 → T2/T3 |
| Q3 有下发物吗（脚本/插件/配置/容器）？ | 有，且业务在其中 → T3 |

| 档 | 要做的事 | 上限 |
|---|---|---|
| T1 | **移交阶段③**：只接自家授权 | M3 |
| T2 | 精简后端：3–5 个端点 + 切换验证 | **M3** |
| T3 | 完整流水线（本技能 + 下发物） | **M4** |

**纪律**：T1 却做后端 = 多此一举；Q1–Q3 命中却按 T1 交付 = 交空壳。两种都算返工。

---

## 1. 三层 API 面（不要混成一层）

| 层 | 长什么样 | 复刻要点 |
|---|---|---|
| **L1 宿主↔服务端** | 卡密（RSA 握手 + AES + 签名）、心跳、版本轮询 | 能抓包 + 能重算签名 → 忠实复刻 |
| **L2 脚本/插件↔服务端** | 脚本侧卡密链、业务接口、脚本容器下发（`/dl/xxx.iec`） | 业务在容器里；容器打包与版本也要复刻 |
| **L3 外部上游** | 第三方解析/AI/数据源 | **不复刻**，做转发/代理 + 自带 key；记录延迟与失败画像 |

**Key 归属必须写进报告**：Key 在服务端时，"复刻"= 重实现 + 换自家 key，不是"破解出别人的 key"。

---

## 2. 四脚本流水线（命令 + 判据）

> 旧七步被压成四步：①API 面 ②数据模型 ③mock 脚手架 ④切换回归。
> 签名/下发包不再单独列脚本，作为 L2→M4 的人工步骤（判据见 `references/04-session-auth.md`、
> `references/05-business-rules.md`）。

### ① API 面测绘

```bash
python Tool/skill/_pending/05-backend-rebuild/scripts/api-surface.py \
  --har work/capture/har.json --pcap work/capture/flows.json --js work/site/assets \
  --out work/api/api-surface.json
```

- 产物：`api-surface.json` + `samples/`（每个观测响应一份，sha256 可复算）。
- 判据：每个端点有证据（har/pcap/js）；`roles` 含 login/list/submit/heartbeat；
  截断/别名单独成条（`truncated=true`）；参数面带观测值。
- 失败：`blocked_at=extract`（没抽到端点）先查脱敏/白名单/JS 前缀表。

### ② 数据模型

```bash
python Tool/skill/_pending/05-backend-rebuild/scripts/schema-infer.py \
  --samples work/api/samples --out work/api/schema.json --ddl work/api/schema.sql
```

- 产物：`schema.json`（字段/主键/枚举/时间格式）+ `schema.sql`。
- 判据：主键只在样本唯一且非空时成立（`rows<2` 直接空）；枚举/时间格式与样本一致；
  DDL 可在空库执行；同输入两次输出一致。
- 失败：`blocked_at=infer`（样本不是 JSON/没有对象）先补真实响应样本。

### ③ mock 脚手架

```bash
python Tool/skill/_pending/05-backend-rebuild/scripts/backend-scaffold.py \
  --api work/api/api-surface.json --schema work/api/schema.json --out work/backend
python work/backend/server.py --host 127.0.0.1 --port 8787
```

- 产物：`server.py`（http.server 单文件）、`routes.json`、`snapshots/`、`hosts.fragment`、`proxy.pac`。
- 语义：有录制快照 → 原样回放（`source=recorded`）；没有 → 200 + 骨架（`source=scaffold-stub`）；
  未注册 → 404 `not_implemented`；方法不对 → 405；`--strict` 缺参数 → 400。
- 判据：`routes.json` 覆盖 api-surface 全部端点（含别名）；`source` 字段可查；骨架数写进报告。
- 失败：客户端仍 404 → 补截断别名；客户端 401 循环 → 401/404 没分开。

### ④ 切换验证 + 回归

```bash
python Tool/skill/_pending/05-backend-rebuild/scripts/switch-verify.py \
  --api work/api/api-surface.json --server work/backend/server.py --port 0 \
  --timeout 1.2 --mode proxy --out work/api/switched.json
```

- 产物：`switched.json`（四类 × 正常/超时/错误码；`applied=false`，只产出 hosts 片段）。
- 判据：`verdict=pass`，`counts.pass=counts.cases`（默认 12）；timeout 必须是客户端超时；
  error_code 必须是 4xx + JSON `error`；normal 与录制状态码一致。
- 失败：`blocked_at=roles`（缺类，补抓包/改 role）或 `blocked_at=regression`（看 `classes.*`）。

### 真实演练（L3 判据）

```bash
python Tool/skill/_pending/05-backend-rebuild/evals/run-drill.py
```

用 `Tool/cases/site-clone-drill01` 的 9 条 `backend_required` 作为输入，生成 mock 并跑
switch-verify；产物只写 `work/backend-rebuild-drill01/`（gitignore），rc=0 即 L3。

---

## 3. 路由形态（最容易被忽略的一类失败）

真实故障：脚本里的 URL 被**定长截断**成 `/v1/chat/c`、`/vid/`，服务端只注册了
`/v1/chat/completions`、`/api/vid/parse` → 请求落到鉴权分支 → 401「登录已过期」→ 脚本死循环。

**必须记录客户端实际发出的路径形态**（截断/别名/大小写/query/host 形态），不许按"规范路径"实现：

1. 抓包里**每一个** path 都有实现或明确的 404/405 语义；
2. 别名与截断单独登记（`/v1/chat/c` ≠ `/v1/chat/completions`）；
3. 鉴权失败与 404 要能区分，否则调试时会被误导成"未登录"。

---

## 4. L1 / L2 / L3 交付口径

| 口径 | 含义 | 必要产物 | 通过线 |
|---|---|---|---|
| **L1 证据级** | 知道有哪些接口、长什么样 | `api-surface.json` + `schema.json`/`schema.sql` | 端点有证据；四类角色齐全；schema 不猜主键 |
| **L2 契约级** | 客户端能切到本地后端并跑完三路 | L1 + `work/backend/` + `switched.json` | 12/12 通过；录制/骨架边界写明；切换可回滚 |
| **L3 演练级** | 真实案例端到端可复跑 | L2 + `evals/run-drill.py` rc=0 + `report.json` | 9/9 覆盖；删 `work/` 重跑结果一致 |
| **M4** | 忠实后端（脚本之外） | L3 + 签名重算/心跳语义/下发物版本/停服一致/干净机器部署 | 见 §7 |

一句话：L1 = 看见了；L2 = 切得动；L3 = 别人能复跑；M4 = 原厂停服也像。
档位（T2/T3）与交付深度（L1/L2/L3）不互相替代。

---

## 5. 复刻后端 8 项 checklist

1. 端点全覆盖（抓包 + 静态交叉验证），含截断/别名/host 形态；
2. 签名/加密可重算（用客户端算法重算一个被接受的请求）；
3. 心跳与超时语义（频率、错误计数、超限行为）；
4. 下发物打包与版本（容器格式、版本号、轮询）；
5. 设备与账号绑定（单设备在线、顶号）若原厂有；
6. 数据落库 + 管理页面（至少能看设备/卡密）；
7. **上游同步策略**（继续拉原厂脚本 或 完全自建，二选一并写风险）；
8. 干净机器可部署（无本机残留依赖，部署脚本可跑）。

---

## 6. 演练实测（site-clone-drill01）

| 项 | 值 |
|---|---|
| 输入 | 9 条 `backend_required`（7 页面能力 + 2 跨域 API） |
| API 面 | 15 端点（9 能力 + 6 条录制 `_next/data`），角色 4/4 |
| schema | 6 表；主键不可判（录制体只有 `pageProps.title` shell 字段）→ 正确结果 |
| mock | 15 路由：录制回放 6 / 派生骨架 9 |
| 回归 | 四类 × 三路 = 12/12 |
| 产物 | `work/backend-rebuild-drill01/{api,backend,recorded}/`、`report.json`、`REPORT.md` |

边界：骨架 200 ≠ 接口已实现；本案到 L3（结构通、可复跑），M4 还缺真实会话/签名字段/下发物。

---

## 7. 验收（M4 四条）

1. 客户端指向自有后端 → 登录/卡密/心跳/业务/下发全通；
2. **关掉自有后端** → 客户端表现与"原厂停服"一致（不是崩）；
3. `api-surface.json` 里每个端点都有我们的实现或明确的"不需要"；
4. 后端能在干净机器上按说明起起来。

门禁（先开档位，才能交 M4，否则 `deliver` 按上限拒）：

```bash
python Tool/scripts/case_state.py verdict --case <C> --value 可赢 --tier T3 --note "业务在后端：/v1/chat/c、/dl/script.iec"
python Tool/scripts/case_state.py gate   --case <C>          # 必须 0
python Tool/scripts/case_state.py deliver --case <C> --level M4 --evidence "<端到端日志/录屏路径>"
```

本技能自检（改完必跑）：

```bash
for s in api-surface schema-infer backend-scaffold switch-verify; do
  python Tool/skill/_pending/05-backend-rebuild/scripts/$s.py --self-test || exit 2
done
python Tool/skill/_pending/05-backend-rebuild/evals/run-drill.py
python Tool/scripts/preflight.py --fast
```

---

## 8. 返工项

- ❌ T1 目标去做后端（多此一举）
- ❌ 只复刻客户端就宣布完成（空壳）
- ❌ 没有 `api-surface.json` 就动手写后端
- ❌ 按"规范路径"实现，不记录客户端的截断/别名/host 形态
- ❌ 把骨架响应说成"接口已实现"
- ❌ 用 401 掩盖 404（调试会被带偏）
- ❌ 关掉后端客户端直接崩，却宣布 M4
- ❌ 把"复刻后端"说成"破解出别人的 key"（Key 在服务端时是重实现 + 换 key）
- ❌ 报告缺边界声明（覆盖 N/N、录制/骨架数、回归 12 条、未覆盖项）
