# CI/CD 与制品完整性速查

> 配套 `supply-chain-security/SKILL.md`。只读审计；不改生产流水线，不推送包。
>
> **适用**：审计 GitHub Actions/GitLab CI/Jenkins 的触发、权限、secrets、action pin，以及制品签名/来源。
> **不适用**：需要修改生产流水线、伪造签名、或对未授权仓库/镜像操作；应用层漏洞不在此文。

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
terraform init -backend=false                    # 只读初始化，不碰远端 state
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

## 12. 边界

- 只读审计；不改生产 workflow、不推送、不触发发布。
- 不把 YAML 缩进扫描当完整解析；锚点/merge key/reusable workflow 必须人工补看。
- 不验证 secrets 的实际值，只记录名称、作用域与引用行。
- 制品来源结论必须绑定 digest；应用层漏洞 → `web-pentest`，容器逃逸 → `ad-cloud`。
