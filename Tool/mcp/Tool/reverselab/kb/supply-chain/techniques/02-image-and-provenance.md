---
id: "supply-chain/02-image-and-provenance"
title: "镜像 digest、签名与 SLSA 来源证明"
title_en: "Image Digest, Signature, and SLSA Provenance"
summary: >
  把镜像从 tag 钉到 repo@sha256:digest，验证 cosign 签名身份与 OIDC issuer，核对 attestation 的 subject digest/builder/materials，再用 SBOM 与构建链把源码 commit 串到制品。
summary_en: >
  Pin an image from tag to repo@sha256:digest, verify cosign signature identity and OIDC issuer, check attestation subject digest/builder/materials, then connect source commit to artifact via SBOM and build chain.
board: "supply-chain"
category: "02-image-provenance"
signals: ["RepoDigests", "sha256:", "cosign", "slsaprovenance", "Rekor", "builder.id", "SBOM"]
mcp_tools: ["cosign", "syft", "docker", "crane"]
keywords: ["镜像", "digest", "cosign", "签名", "SLSA", "attestation", "SBOM", "来源"]
difficulty: "advanced"
tags: ["oci", "cosign", "slsa", "sbom", "digest", "provenance"]
language: "zh-CN"
last_updated: "2026-10-21"
related_articles: ["supply-chain/01-dependency-confusion"]
---
# 镜像 digest、签名与 SLSA 来源证明

## 场景
需要回答“这个镜像是不是由预期流水线、用预期源码构建的”。tag、构建成功、漏洞扫描通过都不能单独回答。

## 输入信号
- 部署清单写 `image: app:latest` 或只有 tag。
- registry 返回 `Docker-Content-Digest`。
- 镜像带 cosign 签名/attestation，但没人核对 identity。
- SBOM 对着 tag 生成，发布时间晚于镜像。
- CI 中有 `pull_request_target`、未 pin 的 action、过宽 permissions。

## 步骤 1：tag → digest
```bash
IMAGE=registry.example.com/app:1.4.2
DIGEST=$(crane digest "$IMAGE" 2>/dev/null || true)
echo "digest=$DIGEST"
docker image inspect "$IMAGE" --format '{{.Id}} {{.RepoDigests}}'
docker pull "registry.example.com/app@sha256:<digest>"
```

记录：`repo@sha256:<digest>`、平台（manifest list 需 `--platform`）、拉取时间、镜像 ID。
判据：报告中的对象是 digest，不是 tag；本地 ID 与 RepoDigest 能对应。

## 步骤 2：SBOM 对 digest
```bash
syft "registry.example.com/app@sha256:<digest>" -o cyclonedx-json=image.cdx.json
trivy image --scanners vuln,secret "registry.example.com/app@sha256:<digest>" -f json -o image.trivy.json
docker history --no-trunc "registry.example.com/app@sha256:<digest>"
```

判据：SBOM 的 subject/component 指向目标 digest；基础镜像也有 digest；组件能追到锁文件或 OS 包。
失败判据：SBOM 对 tag 生成、生成后 digest 变了、只贴漏洞数量。

## 步骤 3：cosign 签名（keyless）
```bash
cosign verify "registry.example.com/app@sha256:<digest>" \
  --certificate-identity-regexp '^https://github\.com/<org>/<repo>/\.github/workflows/<wf>@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

cosign verify-attestation "registry.example.com/app@sha256:<digest>" \
  --type slsaprovenance \
  --certificate-identity-regexp '^https://github\.com/<org>/<repo>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

记录：签名者身份、OIDC issuer、证书 SAN、Rekor 条目、签名时间。
判据：验证通过 + identity/issuer 与预期流水线完全匹配 + subject digest 一致。
失败判据：只看退出码 0、自签证书冒充官方、attestation 对的是另一个 digest。

## 步骤 4：SLSA attestation 字段
```bash
cosign download attestation "registry.example.com/app@sha256:<digest>" \
  | jq -r '.payload' | base64 -d | jq '.predicate' > provenance.json
jq '{subject: .subject, builder: .predicate.builder.id,
     buildType: .predicate.buildType,
     source: .predicate.invocation.configSource.uri,
     materials: .predicate.materials}' provenance.json
```
重点核对：

- `subject[].digest.sha256` == 目标 digest。
- `builder.id` 是可信托管构建器，不是本地机器。
- `configSource.uri` 指向受保护分支/固定 commit。
- `materials` 含源码 commit 与基础镜像 digest。
- 构建时间与发布记录吻合。

## 步骤 5：构建链一致性
```bash
git rev-parse HEAD
git status --porcelain
find .github/workflows -maxdepth 1 -type f -print
grep -nE 'permissions:|uses:|pull_request_target|workflow_run|secrets\.' .github/workflows/*.yml
```

判据：源码 commit → CI run → 镜像 digest → SBOM → 签名/attestation 五者能串成一条链。
失败判据：任一环靠“应该就是”；本地 `docker build` 冒充 CI 产物；commit/构建参数不可追。

## 运行面
```bash
docker image inspect "registry.example.com/app@sha256:<digest>" --format '{{.Config.User}}'
syft "registry.example.com/app@sha256:<digest>" -o table | grep -Ei 'curl|wget|gcc|make|npm|pip'
```

- 是否 root；是否带构建工具/包管理器；是否含 `.git`/`.env`/SSH key。
- 多阶段构建是否把 secret 留在层里；`.dockerignore` 是否漏敏感文件。

## 失败判据
- 没有 digest，只有 tag/截图/`latest`。
- 签名通过但未核对 identity/issuer。
- attestation subject 与目标 digest 不一致。
- SBOM 与 digest 对不上，或生成时间晚于发布且无说明。
- 把“能构建/能拉取/有签名”之一当成“可信来源”。
- 未授权推送/覆盖 tag、拉取私有镜像、修改 registry。

## 边界
- 不做镜像投毒、不覆盖 tag、不伪造签名/attestation。
- 不执行不可信镜像；动态分析只在隔离环境且需单独授权。
- 不给合规认证结论（SLSA 等级/ISO/SOC2）；只列证据与差距。
