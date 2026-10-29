---
name: ci-cd-security
description: "GitHub Actions/GitLab CI 的触发、代码来源、权限与制品信任链审计；区分静态候选、实际可达和修复任务。"
metadata:
  version: "2.1.0"
  target_runtimes: "GitHub Actions / GitLab CI；解析器支持范围单列"
---

# CI/CD 触发与信任链

输入为固定 commit 加未提交差异、工作流及本地/reusable include、runner 环境和期望发布策略。默认审计产出发现、反证、未知与修复建议；只有用户授权修复时才改目标文件。不得为验收触发发布、改生产流水线或获取真实 Secret/OIDC/runner Token。

复用 [CI 与制品深度方法](../../references/cicd-and-artifacts.md)、[权限走查](../../references/04-walkthrough-workflow-permissions.md)、[安装脚本](../../references/05-lockfile-and-install-scripts.md)。已有脚本从源码根调用：

```bash
python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --path .github/workflows --out work/ci.json
```

该脚本是面向 GitHub Actions 的缩进扫描器，不是完整 YAML/表达式求值器，也不验证实际组织设置、第三方 action 源码或 GitLab 规则。缺 include/远端工作流/平台配置时列未覆盖，不把零 finding 当安全证明。

## GitHub Actions

按“事件 → 攻击者可控输入 → 所检出代码/ref → 表达式插值/shell → job 权限/secret/OIDC → 产物消费”追链。`pull_request_target` 本身不证明可利用，关键在是否执行不可信 PR head 或消费被污染 artifact/cache，并且高权限确实可达。审核环境、fork 规则、permissions 继承与 reusable workflow 的边界分别核实。

把输入作为环境变量传递可避免表达式直接成为 shell 源码，但必须正确引用；变量后来进 eval、bash -c、未引用展开或命令选项仍可能不安全：

```yaml
env:
  ISSUE_TITLE: ${{ github.event.issue.title }}
run: printf '%s\n' "$ISSUE_TITLE"
```

此例只演示 shell 安全消费，输出内容本身还需满足数据边界。若存在秘密或不适合公开的用户数据，不原样写日志。

Action 完整 commit pin 可降低可变 tag 漂移，不能证明该 commit 的代码安全；核来源仓库、具体 SHA、transitive action、运行时下载及更新流程。permissions 取实际任务最小值，发布 job 的写权限要有明确触发/环境限制；不机械把所有 job 改为只读。

## GitLab CI 分支

读取主 `.gitlab-ci.yml` 与 include 的实际项目/ref/模板，记录本地未能解析的远端项。核 workflow:rules、job rules、MR/merged-results/push/tag/schedule 等触发来源与变量、protected branch/tag/environment、runner tag/隔离、artifact/cache 及下游 pipeline 的信任链。配置语义以实际 GitLab 版本/项目设置为准，不能只按单文件猜规则展开。

Protected/masked 变量不等于所有运行都可安全访问；需核当前 fork/MR 规则、分支保护与 job 执行代码。`CI_JOB_TOKEN` 的作用域/allowlist、OIDC id_tokens 的 audience、镜像/依赖 digest 均需独立证据。凭据由用户控制，仅取得变量名、授权设置和合成 canary 结果，不导出环境或完整日志。

## 正反例与验收

正例：在隔离合成 workflow 中，不可信标题直插 shell 的候选可用无害标记验证，改为正确引用的 env 后按数据输出、无额外命令；同时基线功能正常。反例：`pull_request_target` 只处理 PR 元信息、未运行不可信代码且无高权 sink，不能仅凭关键词判定已被利用。固定 SHA 但 action 内另下载未校验脚本也不能称不可变构建。

每条发现给文件/行、触发前提、可控源、权限、sink、影响和未核项；审计无需全部修改，修复任务须前后对照。无 CI 运行证据时标静态候选/配置确认，不冒充真实 pipeline 见证。制品分析请 sbom-audit、可疑脚本请 softseep/malware-analysis，结果返回同一 project/version/run。同形失败两次回触发与来源判断。
