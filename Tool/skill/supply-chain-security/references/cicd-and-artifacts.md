# CI/CD 与制品完整性速查

> 配套 `supply-chain-security/SKILL.md`。只读审计；不改生产流水线，不推送包。

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
