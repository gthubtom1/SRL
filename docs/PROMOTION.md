# 能力 / 配方 / 域：什么时候从「一次」变成「一层」

> 这份文件只回答一件事：**这次的产物该落在哪一层？**
> 生成：`python Tool/scripts/forge.py <playbook|capability|domain> <name>`；命令门禁：`playbook-check.py --json`；层门禁：`capability-gate.py` / `domain-gate.py --domain <name>`。

## 1. 三次规则

| 第几次遇到 | 落点 | 形态 | 判据 |
| :-- | :-- | :-- | :-- |
| 第 1 次 | `Tool/cases/<case>/` | 案例：命令 + rc + JSON 字段 + 证据 | 证据可复算，结论能被别人重跑 |
| 第 2 次 | `Tool/playbooks/<name>.md` | 配方：触发词 + 步骤命令序列 + 判据 + 失败换路 | 步骤里每条命令脚本存在、`--help` rc=0 |
| 第 3 次 | `Tool/capabilities/<name>.json` + 脚本 | 能力：输入/输出/脚本/refs/compose | `capability-gate` 绿，脚本 `--self-test` rc=0 |
| 收敛后 | 已有域 | 域只收「已第 3 次且被多次 compose」的能力 | `domain-gate --domain <name>` 绿 |

**域不主动建**：新域只能被动收敛——先有案例、配方、能力，且跨案例证据稳定，才讨论域。

## 2. 判定表（本次该放哪层）

| 事实 | 结论 |
| :-- | :-- |
| 只有一次观测，无证据 | 留在案例，暂不晋升 |
| 同类输入面出现第 2 次，命令序列稳定 | 升配方（playbook） |
| 同一判定被 2 个以上配方复用 | 升能力（capability） |
| 能力已 `usable`，且被 3 个以上配方 compose | 考虑收敛进域 |
| 只有脚本能跑，判据写不出 | 不晋升，回案例补判据 |
| 判据稳定但输入面仍会变 | 停在配方，等第 3 次再升能力 |
| 跨域串味（目标属于别的域） | 转交对应域，不新建 |

## 3. 晋升检查清单

通用：

- [ ] 有可复跑的输入样本或 fixture，且目标哈希已记录。
- [ ] 判据是数值/布尔/哈希，不依赖「看起来一致」。
- [ ] 失败判据写明 `blocked_at` 与换路，不只是一句「失败」。
- [ ] 证据路径相对仓库根，sha256 可复算。
- [ ] 命令里的脚本路径真实存在，无占位残留。

升配方（第 2 次）：

- [ ] `forge.py playbook <name>` 生成后已按真实命令改写步骤。
- [ ] `playbook-check.py --json` 中该配方 `bad` 为空。
- [ ] 触发词能命中真实意图，且不与既有配方重复。
- [ ] `Tool/playbooks/README.md` 索引已加一行。

升能力（第 3 次）：

- [ ] `forge.py capability <name>` 已把 `maturity` 从 `probe` 改为 `usable`。
- [ ] `capability-gate.py --json` 绿，`scripts`/`refs` 无幻影。
- [ ] 脚本 `--help` 与 `--self-test` 均 rc=0，失败走结构化 rc=2。
- [ ] `compose` 只指向已注册 id，矩阵行已补。

收敛进域（被动）：

- [ ] 已满足三次规则，且不是「先建域再找内容」。
- [ ] `domain-gate.py --domain <name> --json` 无 FAIL。
- [ ] `references/` 必备四篇齐全，KB 有 failure-criteria 篇。
- [ ] 案例 3–5 个（≥1 个 real），任务卡 20–30 张。
- [ ] 部署哈希一致：`~/.pi/agent/skills` 与仓库逐域一致。
