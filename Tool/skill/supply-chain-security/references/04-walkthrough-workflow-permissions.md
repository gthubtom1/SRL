# 04 walkthrough · 真实 workflow 权限面审计（本仓库 upstream-sync.yml）

> 范围：需要判断一条 GitHub Actions 流水线“权限是否过大、触发器是否危险、action 是否能被重写”时。
> 前置：仓库读权限；本走查覆盖 GitHub Actions（GitLab/Jenkins 走对应流水线卷）；运行时 secrets 实际值只记录引用。
> 对象：`Seep-Reverse-Lab/.github/workflows/upstream-sync.yml`（仓库内真实文件，非夹具）。
> 脚本：`Tool/skill/supply-chain-security/scripts/ci-perm-audit.py`、`Tool/skill/supply-chain-security/scripts/sc-check.py`。

## 1. 目标与对象钉住

要回答三个问题：

1. 这条 workflow 的 token 权限面有多大？
2. 触发器是否会让不可信输入进入有权限的 job？
3. 第三方 action 是否可被移动到别的 commit？

先钉对象（所有命令在仓库根执行）：

```bash
git rev-parse HEAD
sha256sum .github/workflows/upstream-sync.yml
```

真实输出：

```text
57a3bd1ecf5d9945fe14f1a5c7c5c9db58cf1fc6
fe7894d5f9e134f7cf6deaacc3caabeb5aeb92edb6fb0412825166a1b321aed3  .github/workflows/upstream-sync.yml
```

结论：对象是 commit `57a3bd1` 下的 workflow，文件哈希 `fe7894d5…`。后续所有 JSON 都对应这两个值，换 commit 需重跑。

## 2. 权限与触发器扫描

```bash
python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py \
  --path .github/workflows \
  --out Tool/cases/supply-chain03/artifacts/ci.json
echo $?
```

真实输出（节选，来自 `artifacts/ci.json`）：

```json
{
  "target": {"path": ".github/workflows", "workflows_total": 1},
  "workflows": [{
    "name": "upstream-sync.yml",
    "triggers": [{"name": "schedule", "line": 4},
                 {"name": "workflow_dispatch", "line": 7}],
    "permissions": {"contents": "write", "pull-requests": "write"},
    "token_default": "write:contents,pull-requests",
    "action_pins": [
      {"action": "actions/checkout@v4", "line": 29, "pinned": false, "ref": "v4"},
      {"action": "actions/setup-python@v5", "line": 34, "pinned": false, "ref": "v5"}
    ],
    "secrets_refs": [{"name": "GITHUB_TOKEN", "line": 49}],
    "jobs": ["check-and-sync"]
  }],
  "summary": {"findings_total": 2, "by_severity": {"medium": 2}, "high_or_critical": 0}
}
```

rc=0（无 high）。注意 `ok: true` 只表示“扫描完成”，不表示“无风险”。

## 3. 用第二个脚本交叉核对

```bash
python Tool/skill/supply-chain-security/scripts/sc-check.py \
  --path .github/workflows \
  --out Tool/cases/supply-chain03/artifacts/sc.json
echo $?
```

真实输出（节选）：

```json
{
  "target": {"path": ".github/workflows", "files_scanned": 1, "truncated": false},
  "summary": {"risks": {"critical": 0, "high": 0, "medium": 2, "low": 0, "info": 0},
              "risks_total": 2, "high_or_critical": 0,
              "ecosystems": []},
  "risks": [
    {"level": "medium", "category": "ci-action-pin",
     "file": ".github/workflows/upstream-sync.yml", "line": 29,
     "evidence": "uses: actions/checkout@v4"},
    {"level": "medium", "category": "ci-action-pin",
     "file": ".github/workflows/upstream-sync.yml", "line": 34,
     "evidence": "uses: actions/setup-python@v5"}
  ]
}
```

两个脚本对同一文件给出相同结论：2 条 action pin 风险，无权限/触发器高危。交叉核对的价值是防止单一规则的缩进解析偏差。

## 4. 人工核对（脚本不覆盖的部分）

打开 workflow 原文，逐项核对组合：

| 检查项 | 实际值 | 判定 |
| :-- | :-- | :-- |
| 触发器 | `schedule`（每周一）+ `workflow_dispatch`（人工，choice 输入） | 无 `pull_request_target`/`workflow_run`，不可信输入面小 |
| 顶层 permissions | `contents: write`、`pull-requests: write` | 权限偏大，但只服务“建分支 + 开 PR” |
| job 级 permissions | 未声明 | 继承顶层写权限 |
| checkout ref | 未指定 `ref:`，默认当前分支 | 不 checkout PR head |
| secrets | `secrets.GITHUB_TOKEN` 通过 `env: GH_TOKEN` 传入 | 是仓库 token，不是长期 PAT |
| action pin | `actions/checkout@v4`、`actions/setup-python@v5` | tag 可移动，medium |
| 输入插值 | `INPUT_TARGET` 经 `env` 传入 shell，且有白名单分支 | 未直接 `${{ inputs.target }}` 进 `run` |

关键判断：**写权限 + 不可信触发器** 才构成高危链。本文件触发器只来自 schedule 与人工 dispatch，且 `target` 输入走 `choice` 白名单，因此不写“可被 PR 提权”，只写“action tag 可移动 + 权限面偏大”。

## 5. 结论与最小修复

确认项（有文件行号与复算 JSON）：

- `actions/checkout@v4` 与 `actions/setup-python@v5` 使用可移动 tag（L29/L34），供应链上可被重写。
- 顶层 `permissions` 给了 `contents: write` + `pull-requests: write`，job 级未收窄。

未确认项（写了边界，不冒充结论）：

- 未验证 GitHub 仓库默认 token 设置与环境保护规则；未验证 secrets 在 fork PR 下是否可见（本文件没有 PR 触发器）。
- 未做 reusable workflow / 动态生成权限分析。

最小修复：

```yaml
permissions:
  contents: read
jobs:
  check-and-sync:
    permissions:
      contents: write
      pull-requests: write
    steps:
      - uses: actions/checkout@<40-hex-sha>
      - uses: actions/setup-python@<40-hex-sha>
```

即：顶层只读，写权限下移到真正需要建分支/开 PR 的 job；action 固定 40 位 commit SHA，更新走 Dependabot。

## 6. 边界与失败判据

- 本走查只证明“静态配置面”的结论；没有运行 workflow，也没有读取 GitHub API 的实际权限。
- 如果 `ci-perm-audit.py` 输出 `workflows_total=0`，先检查 `--path` 是否指向 `.github/workflows`，不要写“无 workflow”。
- 如果文件含 YAML 锚点/merge key 或 reusable workflow，缩进扫描可能漏权限，必须人工补看。
- 如果只有 tag 未 pin、但触发器与权限都受控，按 `02-failure-criteria.md` 降为加固项，不写“已被利用”。
- 复跑前先核对 `artifacts/target.json` 的 `workflow_sha256`；不一致说明对象已变，旧结论作废。

## 7. 权限面审计的 12 项可迁移清单

| # | 检查项 | 通过 | 不通过时 |
| :-: | --- | --- | --- |
| 1 | 触发器枚举 | 每个 `on:` 都能解释 | 有未知 `workflow_run` |
| 2 | 顶层 permissions | 显式且最小 | 缺省/`write-all` |
| 3 | job 级 permissions | 写权限只给必要 job | 所有 job 继承写 |
| 4 | checkout ref | 不可信触发不 checkout PR head | `ref: ${{ github.event.pull_request.head.sha }}` |
| 5 | secrets 作用域 | 只在需要的 step/job | 全 job 环境变量 |
| 6 | 第三方 action pin | 40 位 SHA 或 `sha256:` | `@v4`/`@main` |
| 7 | 本地 action | `./` 可接受 | 被当第三方误报 |
| 8 | 表达式注入 | 不可信字段经 `env:` | 直接进 `run:` |
| 9 | 自托管 runner | 只跑受保护分支 | fork PR 可跑 |
| 10 | reusable workflow | 源文件/权限已展开 | 只看调用行 |
| 11 | 环境/审批 | 生产 job 有 environment | 无审批直接发布 |
| 12 | token 类型 | 优先 `GITHUB_TOKEN`/OIDC | 长期 PAT 入库 |

**判据**：12 项逐项填 `pass/fail/na`；`fail` 必须有行号与组合解释。

## 8. 从 workflow 到利用链：三要素矩阵

| 触发器 | 权限 | 输入面 | 判定 |
| --- | --- | --- | --- |
| `pull_request_target` | `contents: write` | checkout PR head + 执行 PR 代码 | 高危：可改仓库/窃密 |
| `pull_request_target` | `contents: read` | 不 checkout PR head | 低：记录为设计 |
| `workflow_run` | `contents: write` | 处理不可信 artifact | 高危：下游提权 |
| `workflow_run` | `contents: read` | 只读上游可信分支 | 低 |
| `issue_comment` | `contents: write` | 评论内容进 `run:` | 高危：表达式注入 |
| `schedule` | `contents: write` | 无外部输入 | 中：权限过大但利用面小 |
| `workflow_dispatch` | `contents: write` | `choice` 白名单 | 中：权限过大，可加固 |

**规则**：三列同时成立才是“可利用链”；缺一列只能写“加固项/设计如此”。

### 8.1 一条链的写法（示例）

```text
触发器：pull_request_target（L4）
权限：contents: write（L12，job 级未收窄）
输入面：checkout ref=head.sha（L21）+ run: make test（L30）
结论：不可信 PR 代码在写 token 下执行 → 可修改仓库内容
缺口：未验证分支保护是否阻断 push；未验证 secrets 是否可用
```

## 9. 命令与“通过长什么样”（本走查复验）

```bash
WF=.github/workflows/upstream-sync.yml

# 1) 对象
sha256sum "$WF"
git rev-parse HEAD

# 2) 权限/触发器/pin
python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py \
  --path .github/workflows --out /tmp/ci.json
jq '.workflows[] | {name, permissions, triggers, action_pins, secrets_refs}' /tmp/ci.json

# 3) 人工核对组合
grep -nE 'on:|permissions:|uses:|ref:|secrets\.|\$\{\{' "$WF" | head -40

# 4) 交叉扫描
python Tool/skill/supply-chain-security/scripts/sc-check.py \
  --path .github/workflows --out /tmp/sc.json
jq '.summary.risks' /tmp/sc.json
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| 对象 | workflow 哈希 + commit 可复算 | 只有文件名 |
| 权限 | 顶层/job 级都能读出 | 解析为空 |
| 触发器 | 全部枚举且可解释 | 漏 `workflow_run` |
| pin | 全部 40 hex 或标 medium | 把 medium 当 high |
| 组合 | 三要素矩阵能对上 | 只凭关键字写“可利用” |

## 10. reusable workflow：脚本不覆盖的部分

`ci-perm-audit.py` 只能看到调用行，权限可能藏在上游文件里。手工展开顺序：

1. `uses: org/repo/.github/workflows/x.yml@ref` → 取 `org/repo` 对应 ref 的文件。
2. 看上游 `permissions:` 与 `secrets: inherit`。
3. 看上游是否 `checkout` 调用方代码/是否使用 `inputs` 拼 shell。
4. 把上游权限合并到调用 job，再套三要素矩阵。

**判据**：报告里每个 reusable workflow 都有“上游文件 + ref + 权限”三行；缺一行就写“未展开”。

## 11. 一句话总结

- 权限大不大，看“写权限能不能被不可信输入触达”；
- action 危不危险，看“能不能被移动到别的 commit + 有没有写权限”；
- 触发器危不危险，看“checkout 了什么 + secrets 可见吗”。

三句都答不上来，就只写配置事实，不写风险结论。

补充：仓库/组织的默认 token 权限会改变 `permissions:` 缺省值；报告里要写“当前仓库设置”，
不能把“我本地看到的”当成 GitHub 的全局默认。

## 这一篇算"用对了"吗

- [ ] 我先钉住 commit + workflow 哈希，再谈权限
- [ ] 我把顶层与 job 级 permissions 合并看，没有只看一处
- [ ] 我用“触发器 × 权限 × 输入面”矩阵判断，而不是关键字命中
- [ ] 我能区分“设计如此/加固项/可利用链”三档
- [ ] 我的修复是最小改动（顶层只读 + 写权限下移 + pin SHA）
- [ ] 复跑前我会核对 workflow 哈希，对象变了就作废旧结论
