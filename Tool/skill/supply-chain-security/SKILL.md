---
name: supply-chain-security
description: 【供应链 / 依赖 / CI-CD】对源码仓库、锁文件、容器镜像与构建流水线做可复现的供应链审计：SBOM、SCA、漏洞可达性、依赖混淆/投毒、锁文件完整性、GitHub Actions/GitLab CI 权限、制品签名与来源证明。以“可达漏洞有 PoC 或投毒链有证据”为判据，拒绝只贴扫描器告警。
license: MIT
compatibility: Linux/macOS/WSL2；syft、grype、osv-scanner、trivy、cosign、semgrep 可选；纯标准库脚本可做清单与风险信号。Windows 经 tool-run.ps1 启动。
metadata:
  version: "1.0.0"
  category: supply-chain-security
  hard_gates: "范围与版本钉住 / SBOM 可复现 / 可达性验证 / 签名与权限有证据"
---

# supply-chain-security — 供应链 / 依赖 / CI-CD

> 只回答一件事：**这个制品由什么组成、哪个依赖/构建步骤能被利用、证据是否足以让维护者修复。**
> SCA 告警 ≠ 漏洞；构建成功 ≠ 可信构建。仅对自有或明确授权的仓库/镜像/流水线操作。

## 0. 范围与基线

先钉住四件事，缺一不扫：

1. **对象**：仓库 commit、镜像 digest（不是 tag）、锁文件、CI 配置、制品哈希。
2. **环境**：语言/包管理器/构建命令/基础镜像/运行时版本。
3. **授权**：仓库、镜像仓库、CI 账号归属；不改生产流水线，不推送恶意包。
4. **判据**：本次要回答的问题是“能否被利用”还是“是否符合基线”；两者产出不同。

```bash
git rev-parse HEAD
sha256sum package-lock.json requirements.txt go.sum Cargo.lock 2>/dev/null
docker image inspect <image> --format '{{.Id}} {{.RepoDigests}}'
```

## 1. SBOM（先有清单，再谈漏洞）

```bash
syft dir:. -o spdx-json=sbom.spdx.json
syft <image> -o cyclonedx-json=sbom.cdx.json
# 或 cdxgen
cdxgen -o bom.json .
```

- 记录工具/版本/格式/生成时间；SBOM 必须能对应到 commit 或 image digest。
- 直接依赖与传递依赖分开；标出未知许可证、停止维护、无来源的包。
- 判据：任一组件能从 SBOM 追到锁文件条目与安装路径。

## 2. SCA 与可达性

```bash
osv-scanner scan -r . --format json > osv.json
grype sbom:sbom.cdx.json -o json > grype.json
trivy fs --scanners vuln,secret,misconfig . -f json -o trivy.json
```

| 告警 | 必查 | 结论 |
|---|---|---|
| 直接依赖命中 CVE | 版本是否在受影响范围、调用路径 | 可达/不可达 |
| 传递依赖命中 | 是否实际打包/加载 | 运行时是否存在 |
| 容器 OS 包 | 基础镜像是否包含、是否可触发 | 利用条件 |
| 密钥扫描 | 是否真实、是否已轮换 | 凭据事件 |

- **可达性**：从入口到危险函数画出调用链；动态用测试/请求验证。仅版本匹配不算确认。
- 判据：高危项有“可达/不可达”结论与证据；不可达也要写原因。

## 3. 依赖投毒与完整性

### 3.1 依赖混淆 / 抢注

```bash
# 检查私有 scope 是否在公共 registry 可解析
npm view @corp/pkg name version 2>/dev/null
pip index versions <internal-pkg> 2>/dev/null
```

- 私有包名未注册/未锁定 registry → 攻击者可抢注同名包。
- 检查 `.npmrc`/`pip.conf`/`nuget.config` 的 registry 与 scope 映射。
- 判据：每个私有 scope 有 registry 锁定；公共同名包不存在或版本受控。

### 3.2 安装脚本与二进制

```bash
jq '.scripts' package.json
grep -RInE "preinstall|postinstall|install" package.json packages/*/package.json 2>/dev/null
grep -RInE "curl|wget|Invoke-WebRequest|base64|eval|child_process" package.json scripts 2>/dev/null
```

- `postinstall` 下载二进制、`node-gyp` 编译、`prepare` 执行脚本都是执行面。
- 锁文件必须含 integrity；`resolved` 指向可信 registry；禁止 `git+http`/`file:` 不明来源。
- 判据：安装期执行的每条命令有来源与必要性；无法解释的下载脚本单独列为风险。

### 3.3 制品签名与来源

```bash
cosign verify <image> --certificate-identity <id> --certificate-oidc-issuer <issuer>
cosign verify-attestation <image> --type slsaprovenance
cosign verify-blob --signature artifact.sig --certificate artifact.pem artifact
```

- 记录签名者身份、OIDC issuer、rekor 条目、SLSA 等级；自签/无签名要标注。
- 判据：能说明“谁在什么流水线、用什么源码、构建了哪个 digest”。

## 4. CI/CD 流水线

### 4.1 GitHub Actions

```bash
find .github/workflows -name '*.yml' -o -name '*.yaml'
grep -RInE "pull_request_target|workflow_run|permissions:|secrets\.|github\.event\.(issue|comment|pull_request)" .github/workflows
```

| 模式 | 风险 |
|---|---|
| `pull_request_target` + checkout PR 代码 | 不可信代码拿到 secrets |
| `workflow_run` 下游执行上游产物 | 权限提升/供应链 |
| `permissions: write-all` | token 过大 |
| `actions/checkout` 未 pin SHA | tag 可被移动 |
| `run: echo ${{ github.event.* }}` | 表达式注入 |
| 自托管 runner 跑 PR | 持久化/横向 |

- 判据：每个 workflow 的触发者、权限、secret、第三方 action pin 都能解释。
- 修复：最小 `permissions`、pin commit SHA、隔离不可信代码、OIDC 替代长期密钥。

### 4.2 GitLab / Jenkins / 通用

- `include` 远端模板、`only/except` 分支保护、protected variables、runner tag。
- Jenkinsfile 的 `sh` 插值、共享库、凭据绑定、agent 标签。
- 判据：不可信输入不能进入 shell/表达式；凭据只在受保护分支可用。

## 5. 容器与构建环境

```bash
trivy image --scanners vuln,secret <image>
docker history --no-trunc <image>
syft <image> -o table
```

- 基础镜像是否固定 digest；是否以 root 运行；是否包含构建工具/凭据。
- 多阶段构建是否把 secrets 留在层里；`.dockerignore` 是否漏掉 `.env`。
- 判据：镜像 digest、层来源、运行时用户、敏感文件四项齐全。

## 6. 工具与降级

| 能力 | 首选 | 降级 |
|---|---|---|
| SBOM | `syft`/`cdxgen` | 手工解析锁文件 + 语言清单 |
| SCA | `osv-scanner`/`grype` | `trivy`、registry advisory 手工比对 |
| 签名 | `cosign` | `gpg`/`minisign` + 发布页校验 |
| CI 审计 | 本文 grep + 平台 API | 只读导出 workflow 后人工审 |
| 清单/风险 | `seep_domain_audit(mode="deps")` | `seep_auto_triage` + 锁文件解析 |

缺工具走 `seep_tool_discover` / `tool-run.ps1` / `seep_tool_install`；安装需确认。

## 7. 坑

1. **tag 当 digest**：镜像 tag 可移动；证据必须写 digest。
2. **SCA 全量当漏洞**：大多数告警不可达；必须给调用链或运行时证据。
3. **锁文件被忽略**：没有 integrity 的锁文件等于没有锁。
4. **私有 scope 未锁 registry**：依赖混淆的入口。
5. **`pull_request_target`**：最容易被利用的 CI 模式；先看触发与 checkout。
6. **第三方 action 未 pin SHA**：tag 可被重写。
7. **构建缓存/层泄漏**：secret 可能留在镜像历史。
8. **SBOM 过期**：commit/digest 变了要重生成。
9. **只扫不修**：报告必须给最小修复（升级/替换/权限/隔离）。

## 8. 判据（可交付结论）

- [ ] 对象钉到 commit/digest，工具与版本可复现。
- [ ] SBOM 覆盖直接+传递依赖，能追到锁文件。
- [ ] 高危告警有可达性结论与证据；不可达有原因。
- [ ] 依赖/CI/镜像至少一条真实风险链，且能给最小修复。
- [ ] 签名/来源/权限有证据，未把“能构建”当“可信构建”。
- [ ] 未推送恶意包、未改生产流水线、未外泄凭据。

## 9. 失败判据（必须撤稿 / 降级）

- 只有 SCA 告警/版本匹配，没有可达调用链或运行时证据。
- 只有 tag 没有 digest；或 SBOM 对不上 commit/digest。
- 锁文件缺失/integrity 缺失，却仍宣称“可复现构建”。
- CI 风险只凭关键字命中，未核对触发条件、checkout 内容与 secrets 作用域。
- 依赖混淆只看到私有 scope 名，未验证 registry 的实际解析结果。
- 镜像签名/来源未验证，或用“能构建”代替“可信构建”。
- 扫描越权到无关仓库/镜像，或改动了生产流水线、推送了测试包。

## 10. 边界（不做什么）

- 不代替甲方做投毒/利用：不推送恶意包、不改生产 CI、不拉取未授权镜像。
- 不做 CVE 武器化；只做版本、可达性、补丁差异与影响面判断。
- 不给出法务/许可证合规结论；只列依赖、许可证标识与证据。
- Web 漏洞验证 → `web-pentest`；APK/固件逆向 → `apkseep` / `firmware-iot`；本技能只消费它们给出的制品与清单。

> 细节：`references/sbom-sca.md`、`references/cicd-and-artifacts.md`、`references/dependency-confusion.md`、`references/image-and-provenance.md`。
> 离线基线：`python scripts/sc-check.py --path <repo>`，输出 JSON；有 high/critical 时退出码 1。
