# AUDIT-REQUEST —— 第三方审查委托书（**只读，只出报告**）

> **一句话**：你是**只读审查员**，不是施工队。你的交付物是**一份报告**，不是修改后的仓库。
> 任何对仓库的写入都属于违约，会让项目方无法判断"是我原来的问题，还是你改出来的问题"。
> 需要改动时，你在报告里写「改哪个文件、第几行、改成什么、为什么、改后收益、怎么验证」，由项目方自己决定是否实施。

版本基线：`v1.26.1`｜生成时间：2026-10-22
配套文件：`docs/FORK-BRIEF.md`（项目身份与契约）、`docs/AUDIT-REPORT-TEMPLATE.md`（报告骨架）

---

## 1. 身份与边界

| 项 | 规定 |
| :-- | :-- |
| 你的角色 | 独立第三方审查员（只读） |
| 你的交付物 | 一份 Markdown 报告（按 `docs/AUDIT-REPORT-TEMPLATE.md` 填写） |
| 你的权限 | 读文件、跑第 3 节列出的**只读验证命令** |
| 你的权限边界 | 写文件、删文件、装依赖、改配置、改仓库状态 —— 全部**不许** |
| 交付地点 | 报告写到仓库**之外**（例如你的输出目录），或只作为对话产出；不要写进仓库 |

**为什么要这么严**：这个仓库的门禁是自洽的（44 项体检 + 110 项域深度 + 双平台 verify）。一旦有人边审边改，门禁全绿就失去意义——没人能分清"原本就是绿的"还是"被改绿的"。

---

## 2. 开工前先做环境声明（报告里必须写）

1. 操作系统与版本、`python --version`、`powershell` 是否可用、`pwsh` 是否可用。
2. 是否在**仓库副本**上工作（推荐 `git clone <repo> <tmpdir>`，在副本上审；但**同样不许在副本里提交**）。
3. MCP 服务是否能拉起（`python Tool/scripts/mcp-doctor.py --quick` 的输出）。
4. 若某项因环境原因跑不了，**写明"未验证"**，不要用推测填空。

---

## 3. 可以跑的只读命令（白名单）

```bash
# 门禁类（只读，不改仓库）
python Tool/scripts/preflight.py
python Tool/scripts/preflight.py --fast
python Tool/scripts/domain-gate.py --all
python Tool/scripts/domain-gate.py --domain <域>
python Tool/scripts/domain-gate.py --links
python Tool/scripts/mcp-param-contract.py
python Tool/scripts/skill-route-probe.py
python Tool/scripts/capability-gate.py --json
python Tool/scripts/playbook-check.py
python Tool/scripts/kb_acceptance.py
python Tool/scripts/check-budget.py
python Tool/scripts/verify-routing-coherence.py
python Tool/scripts/smoke-e2e.py
python Tool/scripts/mcp-doctor.py --quick
python Tool/scripts/mcp-doctor.py --session

# 各脚本自测（只读，本地离线）
python <任意脚本> --help
python <任意脚本> --self-test

# 双平台体检
powershell -File setup/verify.ps1 -Detailed
bash setup/verify.sh

# 只读 git 查询
git log --oneline -20
git status
git diff --stat <a>..<b>
git show <commit>:<path>
```

**注意**：`smoke-e2e.py` 与 `mcp-doctor.py --fix` 会拉起 MCP 子进程；`smoke-e2e` 允许（它只在 `work/` 写临时产物），`--fix` 不要跑（它会启动外部程序）。

---

## 4. 不许做的动作（做了即违约）

1. 任何写入：`edit` / `write` / `patch` / 重定向写文件 / `sed -i` / 生成文件。
2. 任何 git 状态变更：`add` / `commit` / `checkout` / `reset` / `stash` / `clean` / `push` / `merge` / `rebase` / `worktree add`。
3. 安装或升级依赖：`pip install`、`npm i`、`winget`、`go install`。
4. 运行安装/部署/卸载脚本：`setup/install*.ps1`、`setup/update.ps1`、`setup/uninstall.ps1`、`Tool/scripts/tool-run.ps1`、`Tool/scripts/mcp-doctor.py --fix`。
5. 改动 `~/.pi/agent/`（提示词、技能部署目录、mcp.json、settings）。
6. 删除或移动仓库内任何文件、目录。
7. 访问外部网络目标（本仓的 web/pentest 相关脚本用于授权目标；审查阶段只跑离线/回环）。

若你判断"必须改才能验证"，那就**不验证**，在报告里标 `unverifiable-by-readonly` 并写清需要什么条件。

---

## 5. 读什么（顺序不能乱）

1. `docs/FORK-BRIEF.md` —— 身份、契约、文档地图、明确不做、已知债务、常见误解。
2. `docs/RELEASE-1.26.1.md` —— 最近一轮交付台账（做了什么 / 证据 / 剩余）。
3. `docs/DOMAIN-SPEC-v2.md` —— 域契约（九件套）。
4. `docs/UPSTREAM.md` —— 与上游差异、吸收纪律。
5. `docs/DEFERRALS.md` —— 延迟项 + 明确不做。
6. `ROADMAP.md` —— 现在能做什么。
7. 需要细节时再看具体 `Tool/skill/<域>/SKILL.md` 与 `references/`。

**不要**把以下当作现状（`docs/FORK-BRIEF.md` §6 有完整说明）：`docs/AUDIT.md`、`docs/audit/*.md`、
`docs/history/OPTIMIZATION-2.0.md`、`work/plans/*`、`work/` 下任何产物、`.pi/`。
**不要**审查：`Tool/upstream/`、`Tool/mcp/Tool/safe/`（内置工具链二进制）、`破甲卡生成/`（项目方另一个侧项目）。

---

## 6. 报告必须回答的问题（缺一项就算不合格）

1. **总体判定**：这个项目现在能否交付使用？给出 1–10 分与一句话理由。
2. **门禁可信度**：44/110/65/12 这些数字是不是真的？你自己跑出来是多少？与文档是否一致？
3. **与上游的差异是否成立**：文档声称的增量（第 2 类）哪些能验证、哪些是纸面？
4. **需求覆盖度**：项目方的 6 条设计目标（`docs/FORK-BRIEF.md` §3）逐条打分 + 证据。
5. **缺陷清单**：按严重度分级，每条必须有**复现命令 + 原始输出**。
6. **改进清单**：每条写「改什么 / 为什么 / 改后能改良什么 / 风险 / 怎么验证 / 工作量」。
7. **文档一致性**：还有哪些文档在说旧数字/旧结论？逐条列「文件:行 + 现状 vs 实际」。
8. **清理建议**：有没有该删的陈旧文件、重复内容、死代码、未使用资产？**只给建议，不要动手**。
9. **不确定项**：你无法验证的，单独列，写清需要什么条件才能验证。
10. **结论**：如果只能改 3 处，你改哪 3 处？为什么是这 3 处？

---

## 7. 报告格式硬要求

- 语言：中文；术语首次出现给英文原文。
- 每条发现用**固定字段**（见模板）：`ID / 标题 / 严重度 / 类别 / 证据（命令+输出）/ 影响 / 为什么该改 / 改后收益 / 建议方案（文件:行 + 片段）/ 风险 / 验证判据 / 工作量 / 是否已验证`。
- **证据优先**：没有复现输出的条目，一律放到「§不确定项」，不许混进缺陷清单。
- 严重度定义：
  - **P0**：会让用户拿到错误结论，或让门禁失去意义（假绿、证据造假、判据不可机检）。
  - **P1**：能力缺失导致某类任务做不了，或换机/换模型即失效。
  - **P2**：一致性问题（文档数字、路径、命名），不致错但会误导。
  - **P3**：体验/效率（提示词冗长、输出可读性、体积）。
- 禁止的表述：「建议整体重构」「建议引入框架 X」这类无判据建议；要么给出可验证的最小改动，要么不写。
- 每条改进必须能给出一条**验收命令**（跑完看到什么算改好了）。

---

## 8. 交付前自检（你自己过一遍）

- [ ] 报告里每个数字都能对上一条命令输出
- [ ] 没有一条修改被我实际执行（`git status` 在我工作前后都应是干净的）
- [ ] 缺陷与"不确定"分成两节
- [ ] 至少覆盖：门禁真实性与 11 个域中的 3 个域抽样
- [ ] 给出了"只改 3 处"的排序及理由
- [ ] 明确写了"未验证"的部分及原因
