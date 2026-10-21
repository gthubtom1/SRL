---
id: "supply-chain/04-ci-permission-audit"
title: "GitHub Actions 权限面：触发、token、checkout 与 action pin"
title_en: "GitHub Actions Permission Surface: Triggers, Tokens, Checkout, and Action Pins"
summary: >
  用行号级扫描把 workflow 的触发者、permissions、checkout ref、secrets 与 action
  引用分开列，按“不可信输入 × 权限 × 执行面”组合判风险，而不是关键字命中即报洞。
board: "supply-chain"
category: "04-ci-permission-audit"
signals: ["pull_request_target", "workflow_run", "permissions:", "write-all", "secrets.", "uses:", "self-hosted", "ref:"]
mcp_tools: ["ci-perm-audit.py", "sc-check.py", "actionlint"]
keywords: ["GitHub Actions", "CI 权限", "pull_request_target", "action pin", "secrets"]
difficulty: "intermediate"
tags: ["ci-cd", "github-actions", "permissions", "supply-chain"]
language: "zh-CN"
last_updated: "2026-10-21"
related_articles: ["supply-chain/01-dependency-confusion", "supply-chain/06-reachability-failure-criteria"]
---
# GitHub Actions 权限面：触发、token、checkout 与 action pin

## 入口信号

- `pull_request_target` + `actions/checkout` + `ref: github.event.pull_request.head.*`
- `workflow_run` 下游直接执行上游产物，且继承写权限。
- 顶层 `permissions: write-all` 或 job 级未收窄。
- `uses: owner/action@v4`（可移动 tag）或 `docker://image:tag`。
- `run:` 里直接插值 `${{ github.event.* }}`/`${{ inputs.* }}`。

## 可复制命令

```bash
python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py \
  --path .github/workflows --out ci.json

# 交叉核对（另一套规则）
python Tool/scripts/sc-check.py --path .github/workflows --out sc.json

# 只看命中行
grep -RInE "pull_request_target|workflow_run|write-all|secrets\.|uses:" .github/workflows
```

## 判据（确认）

1. 每个 workflow 有显式 `permissions`，且默认 `contents: read`。
2. 写权限只出现在受保护分支/发布 job；PR job 只读。
3. 不可信触发不 checkout PR head；必须 checkout 时无 secrets、无写 token、有人工审批。
4. 第三方 action 固定 40 位 commit SHA；docker action 固定 `@sha256:`。
5. 不可信事件字段经 `env:` 传值并加引号，不直接进 `run:`。
6. 每条 finding 有 `workflow`/`line`/`evidence`，能打开原文核对。

## 组合判定（不要单看一条）

| 触发器 | 权限 | checkout | 判定 |
| :-- | :-- | :-- | :-- |
| `pull_request_target` | write | PR head | 高危：不可信代码拿写 token |
| `pull_request_target` | read | 基分支 | 中：仍需看 secrets 与脚本注入 |
| `workflow_run` | write | 上游产物 | 中高：上游可被投毒 |
| `schedule`/`workflow_dispatch` | write | 基分支 | 权限偏大（加固项），不写“可被 PR 提权” |
| `push` | read | 基分支 | 低：常规构建 |

## 失败判据

- 只命中 `pull_request_target` 关键字，没有 checkout/secrets/权限组合 → 疑似。
- action 未 pin，但 token 只读且无 secrets → 加固项。
- `ci-perm-audit.py` 报 `workflows_total=0`：先检查 `--path`，不要写“无 workflow”。
- YAML 锚点/merge key/reusable workflow 未展开：扫描覆盖不足，人工补看。
- 只有 tag 没有 digest：对象不可钉住，签名/来源结论无效。

## 边界

- 只读审计，不改生产流水线、不触发发布。
- 不验证 secrets 实际值，只记录名称/作用域/行号。
- 不把 GitHub 默认权限当已知；仓库设置需另行确认。
- 真实走查见 `Tool/skill/supply-chain-security/references/04-walkthrough-workflow-permissions.md`。
