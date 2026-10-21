# image-and-provenance · 镜像 digest 与来源证明

> 配套 `supply-chain-security/SKILL.md`。只操作自有/授权镜像仓库；不推送、不覆盖 tag、不伪造签名。
> 底线：**tag 是名字，digest 才是内容；能构建不等于可信构建**。报告里的镜像必须写 `repo@sha256:...`。
>
> **适用**：已有镜像/制品 digest 或可读取签名/attestation，需要判断来源与构建链是否可信。
> **不适用**：未授权拉取私有镜像、推送/覆盖 tag、伪造签名，或要求跑不可信镜像做动态分析。

## 0. 钉住对象

```bash
# 本地镜像：拿到 RepoDigests / Id / 配置
docker image inspect <image> --format '{{.Id}} {{.RepoDigests}} {{.Created}}'
docker image inspect <image> --format '{{json .Config}}' | head -c 1000

# 远程 registry（有 crane/skopeo 时）
crane digest <registry>/<repo>:<tag>
skopeo inspect docker://<registry>/<repo>:<tag> --format '{{.Digest}}'

# 没有工具时：至少记录 tag、拉取时间、镜像 ID、RepoDigests
docker pull <image>@sha256:<digest>
```

**判据**：同一个 digest 能对应到明确的仓库、构建时间、基础镜像与源码 commit。
**失败判据**：报告只写 `latest`/`v1.2.3`；本地 `Id` 与 `RepoDigests` 对不上；digest 来自截图而非命令输出。

## 1. SBOM 与镜像内容

```bash
syft <image> -o cyclonedx-json=evidence/<case>/image.cdx.json
syft <image>@sha256:<digest> -o spdx-json=evidence/<case>/image.spdx.json
trivy image --scanners vuln,secret <image>@sha256:<digest> -f json -o evidence/<case>/image.trivy.json

# 层与历史：找构建工具、凭据、临时文件
docker history --no-trunc <image>@sha256:<digest>
docker save <image>@sha256:<digest> -o image.tar
tar -tf image.tar | head
```

记录：SBOM 工具+版本、生成时间、镜像 digest、OS 包与语言包数量、基础镜像 digest。

**判据**：SBOM 的 `metadata.component` / `subject` 指向目标 digest；任一组件能追到锁文件或 OS 包版本。
**失败判据**：SBOM 对着 tag 生成、生成后 digest 变了；SBOM 里没有基础镜像；只贴漏洞数量不贴组件。

## 2. 签名验证（cosign）

### 2.1 keyless / OIDC

```bash
cosign verify <image>@sha256:<digest> \
  --certificate-identity-regexp '^https://github\.com/<org>/<repo>/\.github/workflows/<wf>@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify-attestation <image>@sha256:<digest> \
  --type slsaprovenance \
  --certificate-identity-regexp '^https://github\.com/<org>/<repo>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### 2.2 key-based / 企业签名

```bash
cosign verify --key cosign.pub <image>@sha256:<digest>
cosign verify-blob --signature artifact.sig --certificate artifact.pem artifact
gpg --verify artifact.sig artifact
minisign -Vm artifact -p pubkey.pub
```

记录：签名者身份、OIDC issuer、证书 SAN、Rekor 条目、签名时间、是否 keyless。

**判据**：签名验证通过，且身份/issuer 与预期发布流水线完全匹配；attestation 的 subject digest 与目标一致。
**失败判据**：只看到 `cosign verify` 退出码 0 但没核对 identity；自签证书被当成官方；attestation 对的是另一个 tag/digest。

## 3. SLSA / 来源证明

```bash
cosign verify-attestation <image>@sha256:<digest> --type slsaprovenance \
  | jq -r '.payload' | base64 -d | jq '.predicate'
cosign download attestation <image>@sha256:<digest> | jq .
```

重点字段：

- `subject[].digest.sha256` 是否等于目标镜像 digest。
- `builder.id` 是否是可信任的托管构建器（如 GitHub Actions、Google Cloud Build）。
- `buildType`、`invocation.configSource.uri` 是否指向受保护分支/固定 commit。
- `materials` 是否包含源码 commit 与基础镜像 digest。
- `metadata.buildStartedOn/FinishedOn` 与发布记录是否吻合。

**判据**：subject digest 一致 + builder 可信 + 源码 commit 可追 + 构建参数无未审计注入。
**失败判据**：attestation 是手工生成的“声明”；builder 是本地机器；materials 缺少源码或基础镜像；只凭 SLSA level 数字。

## 4. 构建链一致性（从源码到 digest）

```bash
# 源码侧
git rev-parse HEAD
git status --porcelain
git verify-commit HEAD 2>/dev/null || true

# 构建侧（只读导出 workflow）
find .github/workflows -type f -maxdepth 1 -print
grep -nE 'permissions:|uses:|pull_request_target|workflow_run|secrets\.' .github/workflows/*.yml

# 制品侧
sha256sum artifact.tar.gz
cosign verify-blob --signature artifact.sig --certificate artifact.pem artifact.tar.gz
```

**判据**：源码 commit → CI run → 镜像 digest → SBOM → 签名/attestation 五者能串成一条链。
**失败判据**：中间任一环靠“应该就是”；用本地 `docker build` 的产物冒充 CI 产物；commit 与构建参数不可追。

## 4.1 供应商台账（vendor.json）

> 目的：把“镜像里有什么”接到“谁维护、何时 EOL、出了事找谁”。台账不是 SBOM 的替代品。

```json
{
  "schema": "vendor-ledger/v1",
  "components": [{"name": "openssl", "version": "3.0.13", "license": "Apache-2.0", "maintenance": "active", "eol": "2026-09-07", "contact": "security@vendor.example", "sbom_ref": "pkg:generic/openssl@3.0.13?arch=amd64"}]
}
```

- 字段固定：组件名/版本/许可证/维护状态（active/security-only/eol）/EOL 日期/联系人/SBOM 引用。
- 台账条目来自 SBOM 的 purl 或锁文件，不能手写一个“大概版本”。

**判据**：每个生产依赖都有台账条目（`vendor_entry=true`），且 `vendor_sbom_ref` 能在 SBOM 中找到同名同版本组件（`vendor_sbom_match=true`）；EOL 缺失时只能写 `vendor_eol=unknown`。
**失败判据**：只有顶层依赖有台账；版本与 SBOM 对不上；EOL 为空却写“仍在维护”；无联系人。缺项写 `vendor_status=incomplete`。

## 5. 运行面与最小权限

```bash
docker image inspect <image>@sha256:<digest> --format '{{.Config.User}}'
docker run --rm <image>@sha256:<digest> id
syft <image>@sha256:<digest> -o table | grep -Ei 'curl|wget|gcc|make|npm|pip'
```

- 是否 `USER root`；是否带构建工具/包管理器；是否含 `.git`、`.env`、SSH key。
- 是否多阶段构建把 secret 留在层里；`.dockerignore` 是否漏掉敏感文件。
- 运行时是否只读根文件系统、是否 drop capabilities（部署侧证据）。

**判据**：镜像 digest、层来源、运行时用户、敏感文件四项齐全。
**失败判据**：只看 Dockerfile 不看实际层；把 `USER` 指令当成运行时一定生效。

## 6. 常见坑

- **tag 可移动**：同一 tag 隔天指向不同 digest；证据必须写 digest。
- **多架构 manifest**：`docker inspect` 的 digest 可能是 manifest list，不是平台镜像 digest；记录 `--platform`。
- **镜像 ID ≠ RepoDigest**：本地构建的 `Id` 没有 registry 来源。
- **签名身份不核对**：`cosign verify` 通过只说明“有人签了”，不说明“对的人签了”。
- **attestation 与镜像脱节**：subject digest 不一致时，attestation 再漂亮也无效。
- **SBOM 过期**：digest 变了必须重生成。
- **密钥进层**：`ARG`/`ENV`/`COPY .env` 都可能留在 history 或层里。
- **CI 缓存投毒**：缓存 key 可被 PR 影响时，构建产物不可信。

## 7. 失败判据（必须撤稿 / 降级）

- 没有 digest，只有 tag/截图/`latest`。
- 签名验证通过但未核对 identity/issuer；或使用自签证书冒充官方。
- attestation subject 与目标 digest 不一致。
- SBOM 与镜像 digest 对不上，或生成时间晚于发布且无说明。
- 把“能构建”“能拉取”“有签名”三者之一当成“可信来源”。
- 未授权推送/覆盖 tag、未授权拉取私有镜像、修改生产 registry。
- 只扫漏洞不核对来源，直接把 CVE 数量当供应链结论。

## 8. 边界

- 不做镜像投毒、不覆盖 tag、不伪造签名/attestation。
- 不执行不可信镜像；动态分析只在隔离环境，且需单独授权。
- 不给出合规认证结论（SLSA 等级、ISO/SOC2）；只列证据与差距。
- 应用层漏洞 → `web-pentest`；容器逃逸/云原生 → `ad-cloud`；本文件只覆盖制品来源与构建链。
