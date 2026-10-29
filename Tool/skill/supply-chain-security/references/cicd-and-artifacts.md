# CI/CD 与制品完整性速查

> 配套 `supply-chain-security/SKILL.md`。只读审计；不改生产流水线，不推送包。
>
> **范围**：审计 GitHub Actions/GitLab CI/Jenkins 的触发、权限、secrets、action pin，以及制品签名/来源。
> 范围：本文覆盖只读流水线审计；生产流水线修改、签名伪造、仓库/镜像清单按 `scope` 执行；应用层漏洞见 `web-pentest`。

## 1. GitHub Actions 审计

```bash
find .github/workflows -type f | sort
grep -RInE "^(on:|permissions:|jobs:)|pull_request_target|workflow_run|secrets\.|write-all" .github/workflows
grep -RInE "uses:\s*[^#]+@(main|master|v[0-9]+)$" .github/workflows
```

| 模式 | 攻击面 | 检查 |
|---|---|---|
| `pull_request_target` | fork PR 代码 + secrets | 是否 checkout PR head；是否执行 PR 代码 |
| `workflow_run` | 下游有高权限 | 是否处理不可信 artifact |
| `issue_comment`/`issues` | 评论触发 | 是否把评论内容拼进 shell |
| `permissions: write-all` | token 过大 | 是否只需 `contents: read` |
| `actions/checkout` tag | tag 可移动 | 是否 pin 到 commit SHA |
| 自托管 runner | 持久化/横向 | 是否跑 fork PR |
| `run: echo ${{ github.event.* }}` | 表达式注入 | 是否进入 shell |

最小修复：

```yaml
permissions:
  contents: read
# 第三方 action 用 commit SHA
uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
```

- 判据：每个 workflow 的触发者、权限、secret、第三方 action pin 四项能解释。

## 2. GitLab CI

```bash
grep -RInE "include:|script:|only:|except:|rules:|variables:|secrets" .gitlab-ci.yml .gitlab 2>/dev/null
```

- `include` 远端模板要 pin commit/版本；`only/except` 与 protected branch 是否一致。
- `protected` variables 只在受保护分支/tag 可用；runner tag 是否隔离。
- `script` 中的变量插值：不可信输入不要直接拼 shell。

## 3. Jenkins

```groovy
// 风险示例：不可信参数进入 shell
sh "curl ${params.URL} | bash"

// 更安全：参数白名单 + 不执行远端脚本
sh 'curl --fail --output artifact.bin "$ARTIFACT_URL"'
```

- 共享库要 pin 版本；`withCredentials` 只在必要步骤绑定；agent 标签隔离。
- 判据：不可信输入不进入 shell/表达式；凭据只在受保护分支可用。

## 4. 制品签名与来源

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
cosign verify <image> \
  --certificate-identity-regexp 'https://github.com/<org>/<repo>/.github/workflows/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation <image> --type slsaprovenance
cosign verify-blob --signature artifact.sig --certificate artifact.pem artifact
```

检查：

- 签名者身份是否与仓库/流水线匹配；OIDC issuer 是否正确。
- Rekor 透明日志条目是否存在；证书是否过期。
- SLSA provenance 的 `materials`/`buildType` 是否对应源码与构建步骤。
- 判据：能回答“谁在什么流水线、用什么源码、构建了哪个 digest”。

## 5. 制品与发布

```bash
sha256sum dist/* | tee dist/SHA256SUMS
gpg --verify dist/SHA256SUMS.sig dist/SHA256SUMS
```

- 发布页的校验和、签名、SBOM 是否同源；下载域名是否 HTTPS/HSTS。
- 更新器是否校验签名/哈希；是否允许降级/回滚到旧版。
- 判据：下载→校验→安装三步都能验证来源。

## 6. 容器构建

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
docker history --no-trunc <image> | head -40
trivy image --scanners vuln,secret <image>
syft <image> -o table | head -40
```

- 基础镜像固定 digest；多阶段构建不把构建工具/凭据留在最终层。
- `.dockerignore` 是否排除 `.env`/`.git`/密钥；运行用户非 root。
- 判据：digest、层来源、运行用户、敏感文件四项齐全。

## 7. 供应链事件响应

```text
1. 确认范围：哪些版本/镜像/流水线受影响
2. 冻结：停止发布，保留构建日志与制品
3. 取证：commit、workflow run、artifact digest、签名记录
4. 轮换：CI token、registry 凭据、签名密钥
5. 修复：pin 依赖、撤包、重新构建、重新签名
6. 验证：干净环境重建，diff 产物
```

- 不上传恶意包到公共 registry 做“测试”；在隔离 registry 复现。
- 判据：影响范围、根因、修复、验证四段齐全。

## 8. 报告模板

```text
流水线：<repo>/.github/workflows/<file>
触发：<event>；权限：<permissions>
不可信输入：<source> → <sink>
第三方 action：<name@ref>（是否 pin SHA）
Secret：<name/scope>（不写值）
制品：<digest>；签名：<identity/issuer>；provenance：<有/无>
结论：<可利用/不符合基线/不可达>
修复：<最小改动> + <验证命令>
```

## 9. K8s 清单 / IaC 扫描

```bash
kubesec scan deploy.yaml                         # 输出 score 与每项 reason
trivy config --format json --output iac.json .   # Dockerfile/K8s/Terraform
checkov -d . --framework kubernetes,terraform --output json > checkov.json
terraform providers lock -platform=linux_amd64   # 生成/校验 .terraform.lock.hcl 的 zh: 哈希
terraform init -backend=false                    # 只读初始化（远端 state 保持原样）
```

- 先钉对象：`git rev-parse HEAD`、清单文件 sha256；多环境 overlay 要写明实际部署的是哪一份。
- `kubesec scan` 的 `score<0` 只是信号；逐条把 `reason` 对到字段：
  `securityContext.privileged=true`、`hostPath` 挂载、`hostNetwork=true`/`hostPID=true`、
  `runAsUser: 0`、`allowPrivilegeEscalation` 未禁用、capabilities 含 `SYS_ADMIN`。
- `trivy config`/`checkov` 的命中必须有 `file:line` 或资源名 + 字段路径（如
  `Deployment/spec/template/spec/containers[0].securityContext.privileged`）。
- Terraform：`.terraform.lock.hcl` 里每个 provider 有版本与 `zh:` 哈希；provider/module 来源固定 registry/commit；
  不把 `terraform plan` 的远端 state 当只读证据。

**判据**：命中项能对应到“可被工作负载利用的具体字段”，且该字段在**实际部署的清单**里存在；
`kubesec_score<0` 或 `iac_field` ∈ {`privileged`, `hostPath`, `hostNetwork`, `runAsUser:0`}，
并能说明利用后果（逃逸/挂载宿主机/提权），写 `iac_confirmed=true`。
**失败判据**：只有 info 级或“建议加 runAsNonRoot”；只有镜像 CVE 没有清单字段；命中的是未部署的样例/模板；
score 为负但 reason 全是 `INFO`。这些情况写 `iac_confirmed=false`，不要升 high。

## 10. 敏感信息风险检查（位置/数据流与合成证据）

不以读取真实 token/私钥并脱敏作为审查步骤。扫描器可把匹配秘密原文写到 JSON/stdout；使用前核实际安全输出和网络验证选项，只在合成夹具或用户已脱敏材料上运行。不默认在线验证、下载敏感日志或回显命中行。
对实际工程按文件位置、secret 引用名称、权限配置与输入到 sink 的数据流判断风险；必要时用合成 canary 验证。只有高熵/名字/旧示例不能证明泄露或凭据有效；缺当前安全观测写 unknown。实际秘密若由用户确认暴露，由用户在宿主完成撤销/轮换，Agent 不索取值。

## 11. 失败判据（看到即降级）

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| 只命中 `pull_request_target` 关键字 | 未证明利用链 | 核对 checkout ref、job permissions、secrets 作用域 | 低：只读核对 |
| action 未 pin 但 token 只读、无 secrets | 加固项，不是漏洞 | 记录 pin 建议，交 Dependabot/PR | 低：改 CI 配置 |
| 只有 tag 没有 digest | 对象不可钉住 | 取 RepoDigests/crane digest 后重跑来源验证 | 中：需要 registry 访问 |
| `cosign verify` rc=0 但未核对 identity/issuer | 只证明“有签名” | 补 certificate identity/issuer 与 Rekor 条目 | 低：一次重跑 |
| reusable workflow/动态权限未展开 | 扫描覆盖不足 | 展开 reusable workflow 源文件，人工补看 | 中：需要上游仓库读权限 |
| 自托管 runner 但只跑受保护分支 | 风险下降 | 核对分支保护与审批；不写“可横向” | 低：读仓库设置 |
| 构建成功/能启动 | 不等于可信构建 | 走 digest+签名+attestation subject 对照 | 中：需要 provenance 数据 |

## 12. CI 敏感权限面（配置/审计与合成 canary）

按当前 commit/run/job 身份核对，不从真实环境提取、试用或散列凭据；不注册 rogue runner、不污染共享 cache。只读不意味着可读实际秘密。

| 面 | 可用证据 | 不足以确认 |
|---|---|---|
| env/secret 引用 | 不可信触发→job权限→secret名称引用→可达sink；受控无真实secret的测试step用合成canary | 名称、掩码或高熵串不能证明真实凭据可用 |
| runner/job 权限 | runner分配规则、受保护分支、job权限与审计元信息；隔离测试runner复现 | token存在不等于能领到高权job；不领取真实job补证 |
| OIDC | trust policy 的issuer/aud/sub/ref条件，与合成claims及测试租户授权决策对照 | 仅通配符/role ARN不证明真实角色已被获取；不取生产id_token |
| 构建日志/制品 | 已脱敏日志或合成日志中canary的数据流与可见范围 | 不下载可能含真实秘密的原日志再脱敏，不把示例当泄露 |
| cache | 独立测试key的低权写入→高权恢复→实际使用，记录marker哈希与清理 | key可猜或恢复命中不能单独证明执行 |
| registry | 非敏感主机/权限配置、测试命名空间与合成账户的访问决策 | config/helper名称不能证明凭据有效，不读取真实auth值 |

每条成立结论含对象/commit/run/job、实际命令或配置位置、安全原始输出及结论链。配置风险与实测可达分别裁定；未知不能升级成confirmed，也不强求一条风险才能完成。跨域细节见 `references/04-walkthrough-workflow-permissions.md` 与 `Tool/skill/_pending/ad-cloud/references/cloud-native.md`；它们的方法受同一当前材料边界约束。

## 13. 边界

- 只读审计；不改生产 workflow、不推送、不触发发布。
- 不把 YAML 缩进扫描当完整解析；锚点/merge key/reusable workflow 必须人工补看。
- 不验证 secrets 的实际值，只记录名称、作用域与引用行。
- 制品来源结论必须绑定 digest；应用层漏洞 → `web-pentest`，容器逃逸 → `ad-cloud`。

## 14. GitHub Actions 权限审计的 12 条判据

| # | 判据 | 通过 | 失败时 |
| :-: | --- | --- | --- |
| 1 | 触发器可枚举 | 每个 `on:` 有来源 | 未知 `workflow_run` |
| 2 | 顶层最小权限 | 默认 `contents: read` | 缺省/`write-all` |
| 3 | job 级收窄 | 写权限只给发布 job | 全部继承 |
| 4 | checkout 目标 | 不可信触发不取 PR head | `ref: head.sha` |
| 5 | secrets 作用域 | 只绑必要 step | 全 job env |
| 6 | action pin | 40 hex 或 `sha256:` | 可移动 tag |
| 7 | 表达式 | 不可信字段经 `env:` | 直接进 `run:` |
| 8 | 自托管 | 只跑受保护分支 | fork PR 可跑 |
| 9 | 环境审批 | 生产 job 有 environment | 无审批发布 |
| 10 | reusable workflow | 已展开源文件 | 只看调用行 |
| 11 | 凭据类型 | `GITHUB_TOKEN`/OIDC | 长期 PAT |
| 12 | 日志/缓存 | 不落 secret、key 不可猜 | 明文/可预测 key |

**判据**：12 条逐项 `pass/fail/na`；`fail` 必须带行号 + “触发器×权限×输入面”组合解释。

## 15. 命令与“通过长什么样”（CI 权限复验）

```bash
# 1) 结构扫描
python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py \
  --path .github/workflows --out /tmp/ci.json
jq '.workflows[] | {name, triggers, permissions, action_pins, secrets_refs}' /tmp/ci.json

# 2) 人工核对关键组合
grep -nE 'on:|pull_request_target|workflow_run|permissions:|ref:|secrets\.|\$\{\{' \
  .github/workflows/*.yml | head -60

# 3) 交叉
python Tool/skill/supply-chain-security/scripts/sc-check.py \
  --path .github/workflows --out /tmp/sc.json
jq '.summary.risks' /tmp/sc.json
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| 触发器 | 全部枚举且可解释 | 漏 `workflow_run` |
| 权限 | 顶层+job 级都可读 | 空/解析失败 |
| pin | 第三方全 40 hex | 可移动 tag |
| 组合 | 三要素矩阵能对上 | 关键字当结论 |
| 修复 | 顶层只读+下移+pin | “加个审批”泛泛而谈 |

## 这一篇算"用对了"吗

- [ ] 我按“触发器→checkout→permissions→secrets→pin”的顺序看，而不是只 grep
- [ ] 我能区分“设计如此/加固项/可利用链”三档
- [ ] 我的权限结论同时覆盖顶层与 job 级
- [ ] 我没有把 action tag 未 pin 直接写成“已被投毒”
- [ ] 我知道 `permissions: {}` 不等于 job 级无写权限
- [ ] 我的修复是最小改动，并给了验证命令
