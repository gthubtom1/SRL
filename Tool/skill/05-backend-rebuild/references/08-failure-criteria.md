# 失败判据与交付口径：什么时候可以说"做完了"

> 阶段五最常见的返工不是"代码写错"，而是**口径写大了**：
> 骨架 200 说成接口实现、录制回放说成后端复刻、页面能开说成 M4。
> 本页把"卡住 / 失败 / 可交付"三级说清楚，并给出可机检的判据。

## 1. 三个失败层级

| 层级 | 含义 | 脚本表现 | 处理 |
|---|---|---|---|
| `blocked` | 输入/前置不成立，继续做没有意义 | `{ok:false,blocked_at,reason}` + rc=2 | 补输入（抓包/样本/授权）后重跑，不改判据 |
| `fail` | 跑了但判据不过（回归红、主键不可判、端点缺证据） | rc=2 或 `verdict=fail` | 修实现/样本，重跑同一命令 |
| `rework` | 产物自洽但口径不对（把 L1 说成 L3、把骨架说成录制） | 报告审阅发现 | 降级口径 + 补证据，不改数字 |

`blocked_at` 的常见值（与脚本一致）：`args`、`input`、`analyze`、`extract`、`pcap-binary`、
`samples`、`infer`、`scaffold`、`roles`、`verify`、`regression`、`case`、`har`、`api-surface`、
`schema-infer`、`backend-scaffold`、`switch-verify`、`self-test`。

## 2. L1 / L2 / L3 交付口径

| 口径 | 含义 | 必要产物 | 能说的话 | 不能说的话 |
|---|---|---|---|---|
| **L1 证据级** | 知道有哪些接口、长什么样 | `api-surface.json`（端点+方法+参数+样本）、`schema.json`+`schema.sql` 草案 | "API 面已测绘，N 个端点，四类角色齐全" | "后端已复刻" |
| **L2 契约级** | 客户端能切到本地后端并跑完四类×三路 | L1 + `work/backend/`（mock，录制回放 + 骨架）+ `switched.json`（12/12） | "可切换，主流程与错误/超时路径有定义行为" | "业务规则已实现"、"登录态 1:1" |
| **L3 演练级** | 真实案例端到端可跑、可复算 | L2 + `evals/run-drill.py` rc=0 + `report.json` + 录制/骨架边界写明 | "9/9 backend_required 覆盖，四类×三路全绿，命令可复现" | "M4 / 关停一致 / 下发物已复刻" |
| **M4** | 忠实后端（脚本之外） | L3 + 签名重算被接受 + 心跳语义 + 下发物版本 + 停服一致 + 干净机器部署 | "客户端指向自有后端，全链路自洽" | — |

一句话记忆：

- L1 = **看见了**；L2 = **切得动**；L3 = **别人能复跑**；M4 = **原厂停服也像**。
- 档位（T2/T3）由阶段零裁定；L1/L2/L3 是**交付深度**，两者不互相替代。

## 3. 机检判据（本技能四脚本）

```bash
# 1) 四个脚本自检（各自 rc=0）
python Tool/skill/05-backend-rebuild/scripts/api-surface.py   --self-test
python Tool/skill/05-backend-rebuild/scripts/schema-infer.py  --self-test
python Tool/skill/05-backend-rebuild/scripts/backend-scaffold.py --self-test
python Tool/skill/05-backend-rebuild/scripts/switch-verify.py --self-test

# 2) 真实演练（rc=0，产物只写 work/）
python Tool/skill/05-backend-rebuild/evals/run-drill.py

# 3) 仓库门禁（悬空引用 0）
python Tool/scripts/preflight.py --fast
```

| # | 判据 | 通过线 |
|---|---|---|
| 1 | 脚本可自检 | 4/4 `--self-test` rc=0 |
| 2 | 端点有证据 | `api-surface.json` 每个端点 `evidence` 非空 |
| 3 | 四类角色 | `roles` 含 login/list/submit/heartbeat |
| 4 | 样本可复算 | `samples[].sha256` 重算一致；空 body 不算样本 |
| 5 | schema 不猜 | `rows<2` 的表 `primary_key=[]`；JSON 列不当主键 |
| 6 | mock 不撒谎 | 每个响应带 `source`；骨架数写进报告 |
| 7 | 回归全绿 | `switched.json` `verdict=pass`，`counts.pass=counts.cases` |
| 8 | 切换不污染 | `applied=false`；系统 hosts 未被修改 |
| 9 | 演练可复算 | 删 `work/` 重跑，除端口/耗时外一致 |
| 10 | 门禁 | `preflight --fast` 33/33 且悬空引用 0 |

## 4. 症状 → 根因 → 动作

| 症状 | 根因 | 动作 |
|---|---|---|
| 客户端 401 循环 | 截断路径未注册，落到鉴权分支 | 查 `routes.json.truncated`，补别名；401/404 分开 |
| 客户端 404 但抓包有请求 | mock 只注册了规范路径 | 同上；api-surface 的 `aliases` 必须进 mock |
| `switch-verify` `blocked_at=roles` | 某类端点缺失/role 判错 | 补抓包或改 role 规则，别减类 |
| `normal` 预期 2xx 实际 4xx | 录制样本本身是错误响应 | 拿有效会话重录；或改判据前先改样本 |
| `timeout` 未超时 | 服务端无钩子或客户端超时太长 | 黑洞探针 / 调小 `--timeout` |
| `error_code` 返回 200 | 服务端忽略 `__status` | 开钩子；生产形态用网关注入 |
| schema 主键全空 | 样本只有 1 行或全是 JSON | 正常；补 2+ 条真实响应后重跑 |
| schema 枚举为空 | 样本值全相同/高基数 | 正常；用真实流量复核，别手工塞 |
| 报告说"后端完成"但 mock 全是骨架 | 口径写大 | 降到 L2 并单列骨架数；补真实实现再升 L3/M4 |
| 换机器演练失败 | 绝对路径/端口/案例目录依赖 | 只读案例、产物写 `work/`、端口 0 |

## 5. 报告必须包含的边界声明

任何阶段五交付报告，至少写清四行：

1. **覆盖面**：`backend_required` 清单 N 条，覆盖 N/N；
2. **数据真实性**：录制回放 X 条 / 派生骨架 Y 条（骨架不是业务数据）；
3. **回归范围**：四类 × 三路 = 12 条，通过数；
4. **未覆盖项**：签名重算 / 心跳真实语义 / 下发物版本 / 停服 UI 表现，各自状态。

缺任意一行，按 `rework` 处理（不是 fail，但交付不成立）。

## 6. 返工清单（本技能专属）

- ❌ T1 目标去做后端（多此一举）；Q1–Q3 命中却按 T1 交（空壳）。
- ❌ 没有 `api-surface.json` 就写后端。
- ❌ 只注册规范路径，不登记截断/别名。
- ❌ 把骨架响应说成"接口已实现"。
- ❌ 用 401 掩盖 404。
- ❌ 关掉后端客户端崩溃/死循环，却宣布 M4。
- ❌ 把"重实现 + 换自家 key"说成"破解出别人的 key"。
- ❌ 报告没有 §5 的四行边界声明。

## 7. 门禁与档位（与仓库一致）

```bash
# 阶段零末尾定档（T2→M3 上限，T3→M4 上限）
python Tool/scripts/case_state.py verdict --case <C> --value 可赢 --tier T3 --note "业务在后端"
python Tool/scripts/case_state.py gate    --case <C>
python Tool/scripts/case_state.py deliver --case <C> --level M4 --evidence "<端到端日志/录屏>"
```

门禁不绿时，先补证据再谈档位；`deliver` 会按上限拒绝超档声明。
L3 演练通过 ≠ M4：M4 还需要签名字段复算、心跳语义、下发物版本、停服一致、干净机器部署五项。
