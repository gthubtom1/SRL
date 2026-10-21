# 01-criteria · 供应链判据表（可机检版）

> 适用：已授权的源码仓库、锁文件、容器镜像、构建流水线审计；目标是把“扫描器说有问题”收敛成“可复核的利用链或明确的不可达”。
> 不适用：未授权仓库/镜像、要求投毒或发布测试包、纯许可证法务结论、CVE 武器化。
> 配套：`Tool/skill/supply-chain-security/SKILL.md`、`Tool/scripts/sc-check.py`、`scripts/sbom-reach.py`、`scripts/ci-perm-audit.py`、`Tool/config/supply-chain-security-matrix.json`。
> 表中的“可机检”指能落成 JSON 字段、哈希或计数，由脚本复算；不是“看起来像”。

## 0. 三档结论只有一种写法

| 档位 | 含义 | 允许写进报告的位置 |
| :-- | :-- | :-- |
| 确认（confirmed） | 判据全部成立，证据可逐字节复算 | 标题、影响面、修复项 |
| 疑似（suspected） | 有信号，但缺一条硬判据 | 正文线索，禁止进标题 |
| 未确认（unconfirmed） | 判据不成立或不可复现 | 工作记录 / 失败判据 |

任何一条“确认”必须同时给出 **对象标识（commit/digest/锁文件 hash）、检测命令与 rc、原始输出、复算脚本结论** 四类证据。
缺任何一类，降为“疑似”，并按 `02-failure-criteria.md` 登记原因。

## 1. 主判据表

| 场景 | 输入面 | 判据（可机检） | 证据形态 | 误报风险 |
| :-- | :-- | :-- | :-- | :-- |
| 对象钉住 | `git rev-parse HEAD`、`docker image inspect`、锁文件 | commit 为 40 位 hex；镜像有 `RepoDigests` 或 `Id`；锁文件 sha256 已记录；工作区 `git status --porcelain` 为空 | `target.json`（commit/digest/锁文件 sha256/工作区状态） | 中：CI 在临时工作区构建，本地无 .git；镜像 tag 与 digest 不同步 |
| 锁文件存在且同源 | `package-lock.json`、`yarn.lock`、`pnpm-lock.yaml`、`requirements.txt`、`poetry.lock`、`go.sum`、`Cargo.lock`、`Gemfile.lock` | 每个应用生态至少一个锁文件；锁文件里的直接依赖集合与 manifest 声明集合一致（多/少都算漂移）；CI 使用冻结安装 | `sc-check.py` 的 `inventory.locks` + `summary.ecosystems` + CI 命令 grep | 中：库项目可不提交 Cargo.lock；monorepo 根锁覆盖子包；workspace 协议 |
| 锁文件完整性 | 锁文件的 `integrity`/`checksum`/`resolved` 字段 | npm 每个 `node_modules/*` 条目有 `integrity` 且 `resolved` 指向受控 registry；`resolved` 不含 `git+http:`/`file:` 不明来源 | `sc-check.py` 的 `category=lock-integrity/registry-integrity` 风险条目（file/line/evidence） | 中：旧锁格式无 integrity；私有 registry 使用自建域名但受控；`file:` 用于 monorepo 本地包 |
| 宽版本范围 | `package.json`、`requirements.txt`、`pyproject.toml`、`go.mod` | 生产依赖无 `*`/`latest`；`^`/`~`/`>=` 可接受但必须配锁文件；URL/git 依赖固定 commit | `sc-check.py` 的 `category=version-range`，每条含依赖名与原范围 | 中：`^`/`~` 是 npm 常规语义；`workspace:` 是 monorepo 本地协议；devDependencies 弹性更大 |
| SBOM 覆盖 | `syft`/`cdxgen` 输出、`pip freeze`、`npm ls --json` | SBOM 的 `metadata.component` 或 subject 指向同一 commit/digest；组件数 ≥ 锁文件条目数；每个直接依赖能在 SBOM 中找到 | `sbom.json` + `sbom-reach.py` 的 `components_total` / `missing_from_sbom[]` | 中：SBOM 格式合法但内容过期；语言包与 OS 包边界不清；可选依赖未安装 |
| SCA 可达性 | OSV/GHSA 命中、调用链、运行时加载 | 高危项必须给出“入口 → 传递 → sink”的调用链，或运行时加载证据；不可达项写明原因（未打包/死代码/仅测试/已 backport） | `osv.json` 命中项 + `reach.json`（`entry`/`import_chain[]`/`verdict`） + 代码行号 | 高：传递依赖未打包、死代码、仅测试依赖、backport 已修复、版本范围误匹配 |
| 依赖混淆（npm） | `@scope/pkg`、`.npmrc`、锁文件 `resolved` | 每个私有 scope 有 `@scope:registry=`；锁文件 `resolved` 域与 `.npmrc` 一致；公共同名包不可解析或版本受控 | `.npmrc` 原文 + 锁文件条目 +（授权联网时）`npm view` 输出 | 高：公开 scope 被误判为私有；企业私有包也托管在公共 registry；镜像代理同时代理公私源 |
| 依赖混淆（Python/NuGet） | `internal-*` 包名、`pip.conf`/`PIP_INDEX_URL`、`nuget.config` | 内部包只从受控 index 解析；无 `--extra-index-url` 回退；NuGet 有 `packageSourceMapping` 且私有前缀只映射私有 feed | `pip.conf`/`nuget.config` 原文 + `sbom-reach.py` 的 `registry` 字段 + 安装命令 | 高：包名含 internal 但确实是公开库；镜像站同时代理公共与私有；mapping 存在但顺序错误 |
| 安装脚本执行面 | `package.json scripts`、`binding.gyp`、`setup.py`、`postinstall` | 每条安装期命令能解释来源与必要性；下载二进制的 URL 有 hash 校验；无 `curl|sh`、无 base64+eval、无明文 token | `sc-check.py` 的 `category=install-scripts` + manifest 原文行 | 中：esbuild/sharp 等原生包正常下载预编译二进制；`prepare` 用于本地开发 |
| CI 权限面 | `.github/workflows/*.yml` 的 `permissions:` | 顶层或 job 级有显式 `permissions`；默认 `contents: read`；只有发布 job 给 `contents/packages: write`；无 `write-all` | `ci-perm-audit.py` 的 `workflows[].permissions` / `findings[].rule=permissions-*` | 中：仓库默认权限可能已是只读；job 级 permissions 覆盖顶层；`write-all` 在隔离的发布仓库可接受 |
| CI 危险触发器 | `on: pull_request_target`、`workflow_run`、`issue_comment`、`self-hosted` | 不可信触发不接触 secrets/写 token；`pull_request_target` 不 checkout PR head；`workflow_run` 校验上游产物来源；自托管只跑受保护分支 | `ci-perm-audit.py` 的 `triggers[]` + `checkout_refs[]` + `secrets_refs[]` + 命中行号 | 高：`pull_request_target` + 环境保护 + 只读 job 可能是安全设计；`workflow_run` 只读上游可信分支 |
| 第三方 action 固定 | `uses: owner/action@ref`、`docker://image` | 第三方 action 固定 40 位 commit SHA；docker action 固定 `@sha256:`；本地 `./` action 除外；更新走 Dependabot/PR | `ci-perm-audit.py` 的 `action_pins[]`（action/ref/pinned/line） | 中：官方 action 的 major tag 是常见做法，但仍是可移动引用；pin 后仍需看权限 |
| 表达式注入 | `run:`/`script:` 中的 `${{ github.event.* }}`、`github.head_ref`、`inputs.*` | 不可信事件字段不直接进入 shell；通过 `env:` 传值并加引号/白名单；`if:` 中使用不算注入 | `ci-perm-audit.py` 的 `findings[].rule=expression-injection` + 原始行 | 中：表达式只用于 `if`/`with` 且未进入 shell 时不可注入；值本身受控 |
| 镜像 digest | `FROM image:tag`、compose `image:` | 基础镜像与部署镜像固定 `repo@sha256:`；tag 只作可读别名；`docker image inspect` 的 digest 与 FROM 一致 | Dockerfile/compose 原文 + `docker image inspect` 输出 + `sc-check.py` 的 `image-tag` | 中：多阶段 `FROM <stage>` 是本地别名；`scratch` 无 digest；内部镜像仓库按 digest 解析 |
| 签名与来源 | `cosign verify`、attestation、Rekor | 签名通过 + certificate identity/issuer 与预期流水线匹配 + 签名对象 digest 与部署 digest 一致；attestation 的 subject digest 一致 | `cosign` 原始输出 + `certificate-identity`/`issuer` + `rekor` 条目 + attestation JSON | 高：只看 verify 退出码 0 未核对身份；attestation 可手工生成；SLSA 等级数字不等于本次构建可信 |
| 运行环境暴露 | Dockerfile `USER`、`ARG`/`ENV`、`.dockerignore`、`docker history` | 最终阶段非 root；构建期密钥不在层里；`.dockerignore` 排除 `.env`/`.git`；无 `curl|sh` | `docker history --no-trunc` + Dockerfile 行 + `sc-check.py` 的 `dockerfile-secrets/container-user` | 中：构建阶段需要 root；`ARG` 未写入最终层；基础镜像自带非 root 用户 |
| 密钥泄漏 | 仓库文本、CI 环境变量、镜像层 | 命中高熵串后必须验证真伪（前缀/长度/校验和/是否已轮换）；真实密钥走撤销流程，报告只留指纹 | `gitleaks`/`trivy` 原始命中 + 指纹 sha256 前 12 位 + 轮换记录 | 高：测试密钥、示例 token、文档占位符；熵高但无权限 |
| K8s 清单 / IaC | `kubesec scan`、`trivy config`、`checkov`、`.terraform.lock.hcl` | `kubesec_score<0` 且 reason 含 `privileged`/`hostPath`/`hostNetwork`/`runAsUser:0`；或 `trivy config`/`checkov` 命中带 `file:line` 的同一字段；`iac_confirmed=true` | `iac.json`/`checkov.json`（资源名、字段路径、行号）+ 实际部署清单 sha256 | 高：只有 INFO 级；命中的是未部署模板；把镜像 CVE 混入清单结论 |
| secrets 真伪 | `gitleaks detect --no-git`、`trufflehog filesystem`、镜像层 | `secret_prefix_ok=true` 且 `secret_length_ok=true`；可离线复算时 `secret_checksum_ok=true`；`secret_rotated` ∈ {`true`,`false`,`unverified`}，不可推导时必须 `unverified` | `gitleaks.json`/`trufflehog.jsonl` + `secret_fingerprint_sha256_12` + `rotation_ref` | 高：熵高但是占位符/测试密钥；把未验证写成已轮换或已失效 |
| 供应商台账 | `vendor.json`、SBOM、锁文件 | 每个生产依赖有台账条目（`vendor_entry=true`），且 `vendor_sbom_ref` 能在 SBOM 找到同名同版本组件（`vendor_sbom_match=true`）；`vendor_eol` 为日期或 `unknown`；`vendor_contact` 非空 | `vendor.json` + SBOM 组件 + `vendor_diff[]` | 中：只有顶层依赖有台账；许可证与 SBOM 不一致；内部组件无联系人 |
| 安装钩子网络面（2026 蠕虫） | `package.json scripts.preinstall/postinstall` | `postinstall_net=true`：钩子命令含 `curl`/`wget`/`node -e`/`bun`/`child_process`/`net.`/`http`；与 `bun_payload` 或 `ci_token_scan` 同时命中才升确认，单独命中只算疑似 | `sc-check.py` 的 `rule_hits[].rule=SC-101 postinstall-network`（`file`/`line`/`evidence` 原命令） | 中：esbuild/sharp 等原生包会合法下载预编译二进制；`prepare` 用于本地开发；内网镜像地址也命中 `http` |
| 远程/动态依赖（RDD） | 依赖值、锁文件 `resolved` | `rdd_ref=true`：依赖值匹配 `^(file:\|link:\|https?://\|git\+)`；或版本为 `*`/空且锁文件 `resolved` 指向远程 tarball；`file:`/`link:` 本身只算疑似 | `sc-check.py` 的 `rule_hits[].rule=SC-102 rdd-ref` + 锁文件 `resolved` 原文 + 依赖名 | 高：monorepo 的 `file:`/`link:` 是常规做法；受控内网 tarball 镜像；`workspace:` 协议不在本规则范围 |
| action 可移动 tag | workflow `uses: owner/repo@ref` | `action_tag_mutable=true`：`@vN`/`@vN.N.N` 等可移动引用且非 40 位 commit SHA；叠加写权限与不可信触发才升级 | `sc-check.py` 的 `rule_hits[].rule=SC-103 action-tag-mutable`（`file`/`line`/`uses` 原文） | 中：官方 action 的 major tag 是常见做法；pin 后仍需看 job 权限与 `secrets` 作用域 |

数据行数：23 行（门禁要求 ≥8）。新增场景只许追加，不许删掉“误报风险”列。

## 2. 判据的机检落点

| 判据 | 落点字段 | 复算脚本 | 通过条件 |
| :-- | :-- | :-- | :-- |
| 对象标识 | `target.commit` / `target.digest` / `locks[].sha256` | `sc-check.py` | 至少一个不可变标识；与 `git rev-parse HEAD` 或 `RepoDigests` 相等 |
| 锁文件覆盖 | `inventory.locks[]` / `summary.ecosystems[]` | `sc-check.py` | 每个 manifest 生态有锁文件，或降级说明原因 |
| CI 权限 | `workflows[].permissions` / `findings[].severity` | `ci-perm-audit.py` | 每个 workflow 有显式最小权限；高危规则有命中行号 |
| action 固定 | `action_pins[].pinned` | `ci-perm-audit.py` | 第三方 action 全为 40 位 SHA 或 `sha256:` |
| 组件可达 | `reachable[]` / `unreachable[]` | `sbom-reach.py` | 每个组件有 `entry`/`import` 命中或明确“未在源码出现” |
| SBOM 缺口 | `missing_from_sbom[]` | `sbom-reach.py` | 锁文件条目集合 ⊆ SBOM 组件集合 |
| 案例证据 | `artifacts[].sha256` | 门禁 + `sc-accept.py` | 逐字节一致（容忍 LF/CRLF 漂移但必须告警）；`refs` 无幻影；`recorded_real≥1` |
| 2026 蠕虫规则 | `rule_hits[].rule` / `severity` / `file` / `line` / `evidence` | `sc-check.py` | `SC-101/102/103` 在内置 fixture 上全部命中，且 `--self-test` rc=0 |

## 3. 证据形态的最低要求

```text
evidence/<case>/
  scope.md              # 授权人/工单/窗口/对象/禁止动作
  cmd.log               # 真实命令 + 时间 + rc
  target.json           # commit/digest/锁文件 sha256
  sc.json               # sc-check.py 原始输出
  ci.json               # ci-perm-audit.py 原始输出（若审 CI）
  sbom.json             # SBOM 或锁文件解析结果
  reach.json            # sbom-reach.py 输出（入口/导入/结论）
  conclusion.md         # 影响面 + 未验证边界 + 最小修复
```

- 主证据是可重放的命令与原始 JSON；截图只作补充。
- 哈希、digest、token 只留指纹或完整值（公开 digest 可留全量），避免泄漏凭据。
- 结论必须写清“没验证什么”（例如未联网查 registry、未跑运行时、未做 CVE 查询）。

## 4. 确认/疑似分界（最容易吵的五处）

1. **版本命中 CVE**：版本在受影响范围只证明“可能受影响”；没有调用链或运行时加载 → 疑似。
2. **私有 scope 未映射 registry**：只证明配置缺失；没有公共同名包解析结果 → 疑似。
3. **`pull_request_target`**：只证明触发器危险；没有 checkout PR head / secrets / 写权限组合 → 疑似。
4. **action 未 pin**：只证明可移动；没有仓库写权限或 secrets 暴露 → 疑似。
5. **镜像 tag**：只证明不可复现；没有 digest 对照或签名验证 → 疑似。

## 5. 失败判据（本文件相关）

出现以下任一情况，本表判据不成立，按 `02-failure-criteria.md` 换面：

- 只有扫描器告警/版本匹配，没有可达调用链或运行时证据。
- 只有 tag 没有 digest，或 SBOM 对不上 commit/digest。
- 锁文件缺 integrity 却宣称“可复现构建”。
- CI 风险只凭关键字命中，未核对触发条件、checkout 内容与 secrets 作用域。
- 依赖混淆只看到私有 scope 名，未验证 registry 的实际解析结果。
- 签名/来源未验证，或用“能构建”代替“可信构建”。

## 6. 边界

- 不推送恶意包、不抢注包名、不改生产流水线、不拉取未授权镜像。
- 不做 CVE 武器化；只做版本、可达性、补丁差异与影响面判断。
- 不替法务下许可证结论；只列组件、许可证标识与证据。
- Web/API 漏洞 → `web-pentest`；APK/固件逆向 → `apkseep`/`firmware-iot`；本域只消费制品与清单。

## 附：上游技能卡索引（24 张）

> 上游 = `mukul975/Anthropic-Cybersecurity-Skills`（818 技能库）。本表只回答一件事：这条上游技能在本域**落到哪张卡、哪篇 reference、判据是什么**。

| 上游技能 | 本域任务卡 | 落点 reference | 一句话判据 |
|---|---|---|---|
| `analyzing-sbom-for-supply-chain-vulnerabilities` | SBOM 漏洞面盘点（源：analyzing-sbom-for-supply-chain-vulnerabilities） | `Tool/skill/supply-chain-security/references/06-reachability-and-sbom-drift.md` | 组件能追到锁文件条目；`missing_from_sbom` 为空或差异逐条解释；工具/版本可复现 |
| `generating-and-analyzing-sboms` | SBOM 生成与漂移复算（源：generating-and-analyzing-sboms） | `Tool/skill/supply-chain-security/references/06-reachability-and-sbom-drift.md` | 两份 SBOM 组件数一致；purl/版本能对应锁文件；subject 与对象一致 |
| `performing-sca-dependency-scanning-with-snyk` | SCA 告警去重与分级（源：performing-sca-dependency-scanning-with-snyk） | `Tool/skill/supply-chain-security/references/01-criteria.md` | 每个高危项有版本范围、依赖路径、修复版本；不可达写明原因 |
| `detecting-dependency-confusion` | 依赖混淆三方对账（源：detecting-dependency-confusion） | `Tool/skill/supply-chain-security/references/dependency-confusion.md` | scope 有显式 registry；resolved 与映射一致；公共同名包不可解析或版本受控 |
| `detecting-typosquatting-packages-in-npm-pypi` | npm/PyPI 仿冒包名字对照（源：detecting-typosquatting-packages-in-npm-pypi） | `Tool/skill/supply-chain-security/references/dependency-confusion.md` | 相似度 ≥0.75 + 来源异常/未引用/脚本可疑，三者至少两项 |
| `detecting-typosquatting-packages` | 仿冒包来源与仓库指纹（源：detecting-typosquatting-packages） | `Tool/skill/supply-chain-security/references/05-lockfile-and-install-scripts.md` | 来源与官方不一致 + 仓库缺失/新建账号，才算来源异常证据 |
| `detecting-malicious-npm-packages` | 恶意 npm 包安装脚本（源：detecting-malicious-npm-packages） | `Tool/skill/supply-chain-security/references/05-lockfile-and-install-scripts.md` | 脚本含下载并执行或读取 CI 凭据 + 有实际网络目标；有原文与行号 |
| `detecting-supply-chain-attacks-in-ci-cd` | CI 供应链攻击面排查（源：detecting-supply-chain-attacks-in-ci-cd） | `Tool/skill/supply-chain-security/references/cicd-and-artifacts.md` | 不可信输入 × 写权限 × 执行面三者同时成立才写高危链 |
| `hunting-for-supply-chain-compromise` | 供应链失陷狩猎（源：hunting-for-supply-chain-compromise） | `Tool/skill/supply-chain-security/references/02-failure-criteria.md` | 至少两条独立证据（产物差异 + 行为/来源），且时间线吻合 |
| `performing-supply-chain-attack-simulation` | 供应链攻击演练的边界（源：performing-supply-chain-attack-simulation） | `Tool/skill/supply-chain-security/references/01-criteria.md` | 演练全程不触达公共 registry/生产流水线；有隔离证明与回滚 |
| `analyzing-supply-chain-malware-artifacts` | 供应链恶意制品分析（源：analyzing-supply-chain-malware-artifacts） | `Tool/skill/supply-chain-security/references/05-lockfile-and-install-scripts.md` | 恶意行为有原文/字节证据，且与正常版本差异可解释 |
| `verifying-build-provenance-with-slsa-sigstore` | SLSA/Sigstore 来源验证（源：verifying-build-provenance-with-slsa-sigstore） | `Tool/skill/supply-chain-security/references/image-and-provenance.md` | subject 一致 + builder 可信 + 源码 commit 可追；三项齐全 |
| `implementing-supply-chain-security-with-in-toto` | in-toto 供应链元数据（源：implementing-supply-chain-security-with-in-toto） | `Tool/skill/supply-chain-security/references/image-and-provenance.md` | 每个 step 的 materials/products hash 闭合，签名者符合预期 |
| `implementing-image-provenance-verification-with-cosign` | cosign 镜像来源验证（源：implementing-image-provenance-verification-with-cosign） | `Tool/skill/supply-chain-security/references/image-and-provenance.md` | identity/issuer 匹配 + digest 一致 + Rekor 有记录 |
| `implementing-sigstore-for-software-signing` | Sigstore 软件签名落地（源：implementing-sigstore-for-software-signing） | `Tool/skill/supply-chain-security/references/image-and-provenance.md` | 签名可被第三方按 identity/issuer 验证；制品 hash 与发布记录一致 |
| `implementing-secrets-scanning-in-ci-cd` | CI secrets 扫描与轮换（源：implementing-secrets-scanning-in-ci-cd） | `Tool/skill/supply-chain-security/references/cicd-and-artifacts.md` | 真实密钥有验证与轮换记录；报告只留指纹 |
| `implementing-devsecops-security-scanning` | DevSecOps 扫描编排（源：implementing-devsecops-security-scanning） | `Tool/skill/supply-chain-security/references/01-criteria.md` | 门禁可复算、误报有豁免记录、扫描对象钉住 commit/digest |
| `integrating-sast-into-github-actions-pipeline` | GitHub Actions 接入 SAST（源：integrating-sast-into-github-actions-pipeline） | `Tool/skill/supply-chain-security/references/04-walkthrough-workflow-permissions.md` | job 只读、action pin SHA、告警能定位到文件行 |
| `building-devsecops-pipeline-with-gitlab-ci` | GitLab CI DevSecOps 流水线（源：building-devsecops-pipeline-with-gitlab-ci） | `Tool/skill/supply-chain-security/references/cicd-and-artifacts.md` | 远端 include 固定版本；凭据只在受保护分支；不可信输入不进 shell |
| `scanning-container-images-with-grype` | grype 镜像扫描（源：scanning-container-images-with-grype） | `Tool/skill/supply-chain-security/references/02-failure-criteria.md` | 结果绑定 digest；高危项有包路径与修复版本；OS 包与语言包分开 |
| `performing-container-security-scanning-with-trivy` | trivy 容器与配置扫描（源：performing-container-security-scanning-with-trivy） | `Tool/skill/supply-chain-security/references/02-failure-criteria.md` | 每类 finding 有对象与行/层；secret 经过真伪验证 |
| `scanning-kubernetes-manifests-with-kubesec` | K8s 清单供应链基线（源：scanning-kubernetes-manifests-with-kubesec） | `Tool/skill/supply-chain-security/references/01-criteria.md` | 镜像固定 digest；高危字段有实际部署证据 |
| `managing-third-party-vendor-risk` | 第三方供应商风险台账（源：managing-third-party-vendor-risk） | `Tool/skill/supply-chain-security/references/02-failure-criteria.md` | 每个供应商标明对象标识、证据来源、未验证项 |
| `auditing-terraform-infrastructure-for-security` | Terraform 基础设施供应链审计（源：auditing-terraform-infrastructure-for-security） | `Tool/skill/supply-chain-security/references/01-criteria.md` | provider/module 固定版本或 commit；lock 文件存在；无明文凭据 |
