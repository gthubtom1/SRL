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

## 10. secrets 扫描与真伪验证

```bash
gitleaks detect --source . --no-git --report-format json --report-path gitleaks.json
trufflehog filesystem . --json --no-update > trufflehog.jsonl
detect-secrets scan --all-files > detect-secrets.json
```

- 先按规则看前缀与长度：AWS `AKIA`/`ASIA` + 20 位、GitHub `ghp_`/`github_pat_`、Slack `xox[baprs]-`、
  Stripe `sk_live_`、私钥 `-----BEGIN ... PRIVATE KEY-----`；前缀不对的“高熵串”先降级。
- 校验和/结构：JWT 三段可解码、信用卡 Luhn、AWS key 的 base32 结构；能离线复算的先复算。
- 真伪验证只在授权范围内做**只读**调用（如 `aws sts get-caller-identity`、`GET /user`）；
  不写数据、不改权限。不能从仓库推导时，字段写 `secret_rotated=unverified`，不要猜“已轮换/未轮换”。
- 命中后先查历史与派生：`git log -S<fingerprint>`、镜像层、CI 日志；确认是否仍在用。
- 报告只留指纹：`sha256(secret)[:12]`，不贴完整值；真实密钥走撤销/轮换流程。

**判据**：`secret_prefix_ok=true` + `secret_length_ok=true` +（可离线时）`secret_checksum_ok=true`，
且 `secret_rotated` ∈ {`true`,`false`,`unverified`}；真实凭据有轮换/撤销记录（`rotation_ref`），才写 `secret_status=confirmed`。
**失败判据**：只有“熵高”；示例 token/文档占位符；前缀或长度不符；无法验证却写 `confirmed`；
把 `unverified` 写成“已失效”。出现任一情况只写 `secret_status=suspected`。

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

## 12. CI 凭据提取面（env dump / runner token / OIDC / 日志 / 缓存 / registry）

> 素材：归档 `offensive-cicd-secrets`（MITRE T1552 Unsecured Credentials）。此处只吸收**判据**：
> 凭据暴露到哪一步才算“可提取”、哪一步只能算“配置缺失”，以及什么样的一次结果才算证据。
> 不写编码外带技巧、不写日志掩码绕过；凭据只留指纹。
>
> 前提：要么有一次**授权内**的构建执行（自有仓库/授权测试分支跑受控 step），要么只有构建日志、
> cache/artifact、registry 的只读权限。**没有构建执行权时只有后三行（日志/缓存/registry）可判。**

| 提取面 | 前置条件 | 可机检判据（字段/输出） | 失败判据 | 代价 |
| :-- | :-- | :-- | :-- | :-- |
| 环境变量注入面 | 受控 step 能跑 `env`；secrets 以 env 注入到 job/step；已拿到 secrets **名单**（API 只给名字，不给值） | 运行时变量名与 `ci.json` 的 `secrets_refs[]`（及仓库/组织级 secrets 名单）交集非空；值在日志里呈 `***` 掩码；再用该值做**一次只读**校验（如 registry `GET /v2/` 鉴权读、云 `sts get-caller-identity`）rc=0 | 只有掩码命中、无独立校验；命中的是平台自动注入变量（`GITHUB_*`/`CI_*`）；值为 `changeme`/长度 <8 的占位符 | 中：每次执行都进 CI 审计与日志；把 secret 值落盘/外传违反凭据红线 |
| runner / job token 复用 | 自托管 runner 或可被 claim 的 job 队列；拿到注册 token 或 job token | 用注册 token 请求 job 队列（GitLab `POST /api/v4/jobs/request`、GitHub register 端点）返回 2xx **且领到的 job 有 secrets/写权限**；证据含 job id 与该 job 的 secrets 名单 | `401/403`（token 已轮换）；领到 job 但 job 无 secrets、只读；只证明 token 有效（注册 token ≠ job token 权限） | 高：注册 rogue runner 触发 `runner_registered` 审计；必须注销并回读已消失 |
| OIDC 联邦滥用 | 云端 trust policy 的 `sub` 通配（`repo:org/*`、`repo:org/*:*`）或只校验 `aud`；能在我方授权仓库/分支请求 id_token | `ACTIONS_ID_TOKEN_REQUEST_URL` 取到 id_token，`cut -d. -f2 \| base64 -d` 得 `sub`/`ref`/`repository` 与 trust 条件不匹配仍 `assume-role-with-web-identity` rc=0，且 `get-caller-identity` 的 Arn 是目标 role | `AccessDenied`/`InvalidIdentityToken`（说明 policy 校验到 `sub`/`ref`）；claims 与实际一致（正常行为）；只有 role ARN 可猜、无 token | 高：每次 assume 在 CloudTrail 留 `AssumeRoleWithWebIdentity`；测试仓库必须在授权清单内 |
| 构建日志泄漏 | 能只读构建日志（Actions run logs / GitLab job trace / Jenkins consoleText） | 日志命中 `secret_prefix_ok`（前缀+长度+结构）的凭据串，且能对应到 secrets 名单或环境变量名；`git log -S<fingerprint>` 或锁文件/部署配置证明仍在用 | 只有高熵串/示例 token/文档占位符；已被掩码成 `***`；只出现在已轮换的旧 run；`secret_prefix_ok=false` | 中：下载日志会把敏感内容落到工作机，先定脱敏与存放位置 |
| 缓存投毒 | 工作流用 `actions/cache`/GitLab `cache:`，cache key 由不可信输入决定（PR 可影响的 `hashFiles`/分支名），下游 job 以更高权限恢复同一 key | 低权 job 写入 marker 文件 → 高权 job 恢复到同一路径且 `sha256` 一致（`cache.hit=true` 且 marker 真实存在），marker 在高权 job 中可被读取/执行 | cache miss/跨分支 key 不共享；marker 存在但高权 job 不使用该路径；只有 key 可猜未验证写入 | 高：需要两次真实 run，计入 CI 账单与审计；污染公共/共享 cache 属越界 |
| registry / 制品凭据 | 构建环境有 `~/.docker/config.json`、`docker-credential-*` 或 `IMAGE_PUSH_TOKEN` 类变量 | `config.json` 的 `auths[]`/`credHelpers[]` 里有 registry 主机 + 一条对**授权 registry** 的只读 `GET /v2/_catalog`（或 `HEAD /v2/<repo>/manifests/<tag>`）返回 200 | 只有 `credHelpers` 名而无凭据；`401 unauthorized`；token 只对 public repo 有效 | 中：registry 拉取会产生审计日志；不得列举他人命名空间 |

**什么算证据（四件，缺一降级为“配置缺失”）**

1. 对象：run id / pipeline id / job id + commit SHA + 触发者；
2. 命令与 rc：受控 step 的命令行、退出码、执行时间；
3. 原始输出片段：变量名 + `***` 掩码形态，或日志行号 + `sha256(secret)[:12]` 指纹；
4. 一次独立只读校验：对**授权**资源做单次 `GET`/`get-caller-identity`/`HEAD` 并 rc=0；
   没有这一步，只能写“变量存在”，不能写“凭据可用”。

```bash
# 1) 名单侧（只读，API 不给值）
curl -sS -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/$REPO/actions/secrets" | jq -r '.secrets[].name'
# 2) 受控 step 内（授权分支）只取名字与掩码形态，不落值
env | grep -iE '^(AWS_|AZURE_|GCP_|GITHUB_|GITLAB_|DOCKER_|NPM_|VAULT_)' | cut -d= -f1 | sort
# 3) OIDC claims 与实际上下文是否一致（不解出可用 token）
curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sts.amazonaws.com" \
  | jq -r .value | cut -d. -f2 | base64 -d 2>/dev/null | jq '{sub,ref,repository,aud}'
# 4) 日志侧：先按前缀过滤，命中后只留指纹
grep -rhoE '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|glpat-[A-Za-z0-9_-]{20})' logs_*/ | \
  while read -r s; do printf '%s %s\n' "$(printf %s "$s" | sha256sum | cut -c1-12)" "${s:0:4}"; done | sort -u
```

**失败判据速查**：只有 `***` 掩码没有独立校验 → 变量存在；只有高熵串 → 未验证；
只有 token 有效但无 job/secrets → 权限面未展开；只有 cache key 可猜 → 未验证写入；
只有 registry 主机名 → 未验证可用。以上任一情况在本域一律写 `candidate`，不进影响面。

**边界**：不注册 rogue runner、不污染共享 cache、不把 secret 值写进证据目录；
OIDC 测试只在授权仓库内做；日志/registry 侧只读。跨域细节：`references/04-walkthrough-workflow-permissions.md`
（权限面走查）、`Tool/skill/_pending/ad-cloud/references/cloud-native.md`（拿到云凭据之后的 IAM 判据）。

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
