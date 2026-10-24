# supply-chain-security 任务卡（24 张）

> 入口：`Tool/skill/supply-chain-security/SKILL.md`。每张卡固定六段，`reference` 指向本域 reference。
> 统一前置：对象钉到 commit/digest/锁文件 sha256 + 只读 + 不联网（需联网另开授权）+ 不推送/不抢注/不改生产流水线。
> 统一失败口径：见 `Tool/skill/supply-chain-security/references/02-failure-criteria.md`，不把疑似写成确认。

### 01 SBOM 漏洞面盘点（源：analyzing-sbom-for-supply-chain-vulnerabilities）
- 触发词：`sbom`、CycloneDX、SPDX、组件清单、漏洞面
- 前置：已有 commit/digest；SBOM 或锁文件可读；记录生成工具与版本
- 步骤：1) `python Tool/skill/supply-chain-security/scripts/sbom-reach.py --sbom Tool/cases/supply-chain04/input/bom.json --source Tool/cases/supply-chain04/input/src --out work/reach01.json` → rc=0，期望：`"components_total": 4`、reachable 含 `left-pad`；2) `python Tool/skill/supply-chain-security/scripts/sbom-reach.py --lock Tool/cases/supply-chain04/input/package-lock.json --source Tool/cases/supply-chain04/input/src --out work/reach01-lock.json` → rc=0，期望：`"components_total": 2`、inputs.lock=true；3) `python Tool/skill/supply-chain-security/scripts/sbom-reach.py --self-test` → rc=0，期望：`"ok": true`
- 判据：组件能追到锁文件条目；`missing_from_sbom` 为空或差异逐条解释；工具/版本可复现
- 失败判据：SBOM 对不上 commit/digest、组件数差 >20% 且无解释；只能写“清单未验证”
- reference：Tool/skill/supply-chain-security/references/06-reachability-and-sbom-drift.md

### 02 SBOM 生成与漂移复算（源：generating-and-analyzing-sboms）
- 触发词：`syft`、`cdxgen`、SBOM 过期、组件漂移
- 前置：固定源码 commit 或镜像 digest；构建环境干净；工具版本记录
- 步骤：1) 生成 CycloneDX 与 SPDX 各一份 2) 记录工具版本、时间、对象标识 3) 与锁文件/freeze 对账，按 purl 对齐
- 判据：两份 SBOM 组件数一致；purl/版本能对应锁文件；subject 与对象一致
- 失败判据：格式合法但内容过期、语言包与 OS 包边界不清；降级为锁文件清单
- reference：Tool/skill/supply-chain-security/references/06-reachability-and-sbom-drift.md

### 03 SCA 告警去重与分级（源：performing-sca-dependency-scanning-with-snyk）
- 触发词：`snyk`、`osv-scanner`、`grype`、CVE 去重、优先级
- 前置：SCA 原始 JSON；组件版本与锁文件一致；已知工具版本
- 步骤：1) 按 `package+version+CVE` 去重 2) 标直接/传递、运行时/测试 3) 给每项打“可达/不可达/未知”
- 判据：每个高危项有版本范围、依赖路径、修复版本；不可达写明原因
- 失败判据：只有告警计数、多工具重复未去重、无修复版本；只能写“扫描器命中”
- reference：Tool/skill/supply-chain-security/references/01-criteria.md

### 04 依赖混淆三方对账（源：detecting-dependency-confusion）
- 触发词：依赖混淆、dependency confusion、私有 scope、registry 回退
- 前置：manifest、`.npmrc`/`pip.conf`/`nuget.config`、锁文件三方可读
- 步骤：1) 列私有 scope/内部包名 2) 核对 registry/index 映射 3) 核对锁文件 resolved host 与 integrity
- 判据：scope 有显式 registry；resolved 与映射一致；公共同名包不可解析或版本受控
- 失败判据：只看到 scope 名、未验证解析结果；只能写“配置缺失/未锁定”
- reference：Tool/skill/supply-chain-security/references/dependency-confusion.md

### 05 npm/PyPI 仿冒包名字对照（源：detecting-typosquatting-packages-in-npm-pypi）
- 触发词：typosquat、仿冒包、同形字、名字相似
- 前置：依赖清单；团队白名单/已知官方包列表；不联网
- 步骤：1) 对依赖名做编辑距离/相似度对照 2) 标出相似但不在白名单的包 3) 查锁文件来源与源码引用
- 判据：相似度 ≥0.75 + 来源异常/未引用/脚本可疑，三者至少两项
- 失败判据：只凭名字像；可能只是缩写或内部包，必须写“疑似仿冒”
- reference：Tool/skill/supply-chain-security/references/dependency-confusion.md

### 06 仿冒包来源与仓库指纹（源：detecting-typosquatting-packages）
- 触发词：包来源、仓库缺失、个人 registry、维护者指纹
- 前置：锁文件 resolved；包元数据（离线可读部分）；授权联网时才查 registry
- 步骤：1) 提取 resolved host/路径 2) 对照官方 registry 与包主页 3) 记录维护者/发布时间/仓库是否存在
- 判据：来源与官方不一致 + 仓库缺失/新建账号，才算来源异常证据
- 失败判据：未授权联网、只有包名或下载量；只能写“来源未验证”
- reference：Tool/skill/supply-chain-security/references/05-lockfile-and-install-scripts.md

### 07 恶意 npm 包安装脚本（源：detecting-malicious-npm-packages）
- 触发词：`postinstall`、`preinstall`、`curl|sh`、base64、`child_process`
- 前置：已取得包 tarball 或本地安装目录；隔离环境；不执行脚本
- 步骤：1) 读 `package.json scripts` 与入口文件 2) 找下载/解码/执行/读 env 的行为 3) 记录 URL、命令、外联域名
- 判据：脚本含下载并执行或读取 CI 凭据 + 有实际网络目标；有原文与行号
- 失败判据：官方 CDN 下载且有 hash 的原生包；不能写“投毒”
- reference：Tool/skill/supply-chain-security/references/05-lockfile-and-install-scripts.md

### 08 CI 供应链攻击面排查（源：detecting-supply-chain-attacks-in-ci-cd）
- 触发词：CI 投毒、`pull_request_target`、`workflow_run`、secrets、runner
- 前置：workflow 只读导出；仓库权限/分支保护已知；不改流水线
- 步骤：1) `python Tool/skill/supply-chain-security/scripts/sc-check.py --path Tool/ --max-files 1000 --out work/sc08.json` → rc=0，期望：`"files_scanned": 1000`、`"truncated": true`、`"risks_total": 7`；2) `python Tool/skill/supply-chain-security/scripts/sc-check.py --path Tool/cases/supply-chain03/input --out work/sc08-case.json` → rc=0，期望：`"files_scanned": 1`、`"risks_total": 0`；3) `python Tool/skill/supply-chain-security/scripts/sc-check.py --self-test` → rc=0，期望：`{"ok": true, "checks": 17}`
- 判据：不可信输入 × 写权限 × 执行面三者同时成立才写高危链
- 失败判据：只命中关键字、未看组合；只能写“疑似”
- reference：Tool/skill/supply-chain-security/references/cicd-and-artifacts.md

### 09 供应链失陷狩猎（源：hunting-for-supply-chain-compromise）
- 触发词：供应链失陷、异常外联、构建产物漂移、后门
- 前置：有基线（历史 SBOM/构建 hash/网络基线）；授权调查范围
- 步骤：1) 对比构建产物 hash 与 SBOM 差异 2) 查新增依赖/维护者变更 3) 查构建期外联与凭据读取
- 判据：至少两条独立证据（产物差异 + 行为/来源），且时间线吻合
- 失败判据：只有单条异常或无法排除正常发布；写“线索”不写“失陷”
- reference：Tool/skill/supply-chain-security/references/02-failure-criteria.md

### 10 供应链攻击演练的边界（源：performing-supply-chain-attack-simulation）
- 触发词：攻击演练、红队、投毒模拟、授权范围
- 前置：书面授权 + 隔离环境 + 动作白名单（真实 registry/生产 CI 另立授权）
- 步骤：1) 在本地 mock registry/CI 复现解析与安装 2) 记录攻击链与检测点 3) 只输出防御建议与检测规则
- 判据：演练全程不触达公共 registry/生产流水线；有隔离证明与回滚
- 失败判据：需要发布测试包、改生产 CI、抢注名字；立即停止并改走桌面演练
- reference：Tool/skill/supply-chain-security/references/01-criteria.md

### 11 供应链恶意制品分析（源：analyzing-supply-chain-malware-artifacts）
- 触发词：恶意包、tarball、安装脚本、外联、凭据
- 前置：样本已隔离；不执行；有 hash 与来源
- 步骤：1) 静态列文件/脚本/二进制 2) 提取 URL、域名、env 读取 3) 与正常版本做 diff
- 判据：恶意行为有原文/字节证据，且与正常版本差异可解释
- 失败判据：只有高熵/混淆、无行为证据；转 `malware-analysis` 做动态
- reference：Tool/skill/supply-chain-security/references/05-lockfile-and-install-scripts.md

### 12 SLSA/Sigstore 来源验证（源：verifying-build-provenance-with-slsa-sigstore）
- 触发词：SLSA、provenance、sigstore、attestation、builder
- 前置：有 attestation 与目标 digest；知道预期 builder/源码仓库
- 步骤：1) 校验 attestation 签名 2) 核对 subject digest 与部署 digest 3) 核对 builder id、materials、configSource
- 判据：subject 一致 + builder 可信 + 源码 commit 可追；三项齐全
- 失败判据：attestation 可手工生成、SLSA 等级数字当结论；写“未验证来源”
- reference：Tool/skill/supply-chain-security/references/image-and-provenance.md

### 13 in-toto 供应链元数据（源：implementing-supply-chain-security-with-in-toto）
- 触发词：in-toto、layout、link、step、supply chain metadata
- 前置：已知构建步骤与签名者；有 layout/link 文件
- 步骤：1) 核对 layout 的 step 与制品 2) 校验 link 签名与材料 hash 3) 对照最终产物 digest
- 判据：每个 step 的 materials/products hash 闭合，签名者符合预期
- 失败判据：layout 过期、step 缺失、签名者不明；只写“元数据不完整”
- reference：Tool/skill/supply-chain-security/references/image-and-provenance.md

### 14 cosign 镜像来源验证（源：implementing-image-provenance-verification-with-cosign）
- 触发词：`cosign`、keyless、OIDC issuer、Rekor、镜像签名
- 前置：镜像 digest；预期 workflow identity 与 issuer；可访问 Rekor（或离线 bundle）
- 步骤：1) `cosign verify` 带 identity/issuer 2) 核对签名对象 digest 3) 查 Rekor 条目与证书链
- 判据：identity/issuer 匹配 + digest 一致 + Rekor 有记录
- 失败判据：只看 rc=0、自签证书、digest 不一致；只写“存在签名”
- reference：Tool/skill/supply-chain-security/references/image-and-provenance.md

### 15 Sigstore 软件签名落地（源：implementing-sigstore-for-software-signing）
- 触发词：sigstore、cosign sign、keyless、制品签名、发布流程
- 前置：发布流水线可改（测试环境）；OIDC 可用；有制品 hash
- 步骤：1) 在测试流水线生成签名 2) 记录 identity/issuer/证书 3) 用 verify 与发布页校验闭环
- 判据：签名可被第三方按 identity/issuer 验证；制品 hash 与发布记录一致
- 失败判据：私钥落盘无保护、签名对象与发布对象不一致；不得上线
- reference：Tool/skill/supply-chain-security/references/image-and-provenance.md

### 16 CI secrets 扫描与轮换（源：implementing-secrets-scanning-in-ci-cd）
- 触发词：secret scanning、gitleaks、token 泄漏、轮换
- 前置：仓库只读；扫描规则允许；不把明文写进报告
- 步骤：1) `python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --self-test` → rc=0，期望：`{"ok": true, "checks": 11}`；2) `python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --path .github/workflows --out work/ci16.json` → rc=0，期望：`"workflows_total": 2`、findings 含 `action-unpinned`；3) `python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --help` → rc=0，期望：示例含 `--path .github/workflows`
- 判据：真实密钥有验证与轮换记录；报告只留指纹
- 失败判据：示例/占位符当泄漏、明文外传；降级为“未验证”
- reference：Tool/skill/supply-chain-security/references/cicd-and-artifacts.md

### 17 DevSecOps 扫描编排（源：implementing-devsecops-security-scanning）
- 触发词：DevSecOps、SAST/SCA/secret、扫描门禁、误报
- 前置：明确门禁阈值与阻断策略；工具版本固定；有基线
- 步骤：1) 分阶段接入 SAST/SCA/secret/镜像 2) 设阻断阈值与豁免流程 3) 记录每次扫描对象与结果
- 判据：门禁可复算、误报有豁免记录、扫描对象钉住 commit/digest
- 失败判据：只堆工具无阈值、扫描对象漂移；不得宣称“已覆盖”
- reference：Tool/skill/supply-chain-security/references/01-criteria.md

### 18 GitHub Actions 接入 SAST（源：integrating-sast-into-github-actions-pipeline）
- 触发词：SAST、GitHub Actions、code scanning、SARIF、权限
- 前置：workflow 在测试分支；token 最小权限；工具版本固定
- 步骤：1) 加只读 job 跑 SAST 2) 上传 SARIF 3) 核对告警与代码行，设阻断阈值
- 判据：job 只读、action pin SHA、告警能定位到文件行
- 失败判据：给写权限跑不可信 PR、只传报告不设阈值；降级为观察
- reference：Tool/skill/supply-chain-security/references/04-walkthrough-workflow-permissions.md

### 19 GitLab CI DevSecOps 流水线（源：building-devsecops-pipeline-with-gitlab-ci）
- 触发词：GitLab CI、include、protected variable、runner、SAST
- 前置：只读导出 `.gitlab-ci.yml`；runner 标签与分支保护已知
- 步骤：1) 核对 include 来源与版本 2) 核对 protected variables 与 runner 3) 核对脚本插值与制品签名
- 判据：远端 include 固定版本；凭据只在受保护分支；不可信输入不进 shell
- 失败判据：远端 include 可被替换、runner 跑任意 PR；写“配置风险”
- reference：Tool/skill/supply-chain-security/references/cicd-and-artifacts.md

### 20 grype 镜像扫描（源：scanning-container-images-with-grype）
- 触发词：`grype`、镜像扫描、SBOM 输入、CVE、基础镜像
- 前置：镜像 digest；grype 版本；授权拉取
- 步骤：1) `python Tool/skill/supply-chain-security/scripts/sc-check.py --path Tool/cases/supply-chain04/input --out work/sc20.json` → rc=0，期望：`"files_scanned": 7`、`"risks_total": 0`；2) `python Tool/skill/supply-chain-security/scripts/sc-check.py --path Tool/cases/supply-chain03/input --out work/sc20-case.json` → rc=0，期望：`"files_scanned": 1`、`"ok": true`；3) `python Tool/skill/supply-chain-security/scripts/sc-check.py --self-test` → rc=0，期望：`"checks": 17`
- 判据：结果绑定 digest；高危项有包路径与修复版本；OS 包与语言包分开
- 失败判据：扫 tag 不扫 digest、未去重、把 OS 包 CVE 当应用漏洞
- reference：Tool/skill/supply-chain-security/references/02-failure-criteria.md

### 21 trivy 容器与配置扫描（源：performing-container-security-scanning-with-trivy）
- 触发词：`trivy`、vuln/secret/misconfig、镜像层、配置
- 前置：镜像 digest；扫描器版本；只读
- 步骤：1) 跑 vuln+secret+misconfig 2) 分离镜像层/应用依赖/配置 3) 核对 secret 命中真伪
- 判据：每类 finding 有对象与行/层；secret 经过真伪验证
- 失败判据：把 misconfig 当漏洞、secret 未验证；降级为加固项
- reference：Tool/skill/supply-chain-security/references/02-failure-criteria.md

### 22 K8s 清单供应链基线（源：scanning-kubernetes-manifests-with-kubesec）
- 触发词：`kubesec`、K8s manifest、镜像 tag、runAsRoot、hostPath
- 前置：manifest 只读；集群/命名空间归属明确
- 步骤：1) 扫镜像 tag/digest 与安全上下文 2) 标 hostPath/privileged/root 3) 对照部署实际 digest
- 判据：镜像固定 digest；高危字段有实际部署证据
- 失败判据：只有静态 score、未对照实际部署；写“配置建议”
- reference：Tool/skill/supply-chain-security/references/01-criteria.md

### 23 第三方供应商风险台账（源：managing-third-party-vendor-risk）
- 触发词：供应商、第三方、SBOM 索取、漏洞通知、SLA
- 前置：供应商清单与合同范围；可核对的制品/版本
- 步骤：1) 收制品 SBOM 与签名/digest 2) 核对漏洞通知与修复时限 3) 建台账：对象/证据/责任人/到期
- 判据：每个供应商标明对象标识、证据来源、未验证项
- 失败判据：只有问卷无制品证据、把“已回复”当“已修复”
- reference：Tool/skill/supply-chain-security/references/02-failure-criteria.md

### 24 Terraform 基础设施供应链审计（源：auditing-terraform-infrastructure-for-security）
- 触发词：Terraform、provider、module、lock file、`.terraform.lock.hcl`
- 前置：IaC 只读；provider/module 来源已知；不 apply
- 步骤：1) `python Tool/skill/supply-chain-security/scripts/sc-accept.py --root . --json` → rc=0，期望：`"ok": true`、`"cases": 4`、`"real": 3`；2) `python Tool/skill/supply-chain-security/scripts/sc-check.py --path Tool/cases/supply-chain03/input --out work/sc24.json` → rc=0，期望：`"ok": true` 且 tool.guarantees 含 `no network`；3) `python Tool/skill/supply-chain-security/scripts/sc-check.py --self-test` → rc=0，期望：`"mode": "builtin-fixture"`
- 判据：provider/module 固定版本或 commit；lock 文件存在；无明文凭据
- 失败判据：module 指向 branch/latest、lock 缺失；只写“不可复现”
- reference：Tool/skill/supply-chain-security/references/01-criteria.md
