---
name: supply-chain-security
description: "审计这个仓库/依赖有没有问题/锁文件完整性/GitHub Actions 权限/供应链投毒/依赖混淆/SBOM 与制品签名。要求对象可钉住、可达有证据、修复可执行。 (package-lock.json/requirements.txt/Gemfile.lock/.github/workflows)"
license: MIT
compatibility: Linux/macOS/WSL2；syft、grype、osv-scanner、trivy、cosign、semgrep 可选；纯标准库脚本可做清单/锁文件/CI/可达性。Windows 经 tool-run.ps1 启动。
metadata:
  version: "2.0.0"
  category: supply-chain-security
  hard_gates: "对象钉住 / 清单可复现 / 可达有调用链 / 权限与来源有证据"
---

# supply-chain-security — 供应链 / 依赖 / CI-CD

> 只回答一件事：**这个制品由什么组成、哪个依赖/构建步骤能被利用、证据是否足以让维护者修复。**
> SCA 告警 ≠ 漏洞；构建成功 ≠ 可信构建；tag ≠ digest。仅对自有或明确授权的仓库/镜像/流水线操作。

## 阶段契约（与 softseep 一致，**先判再做**）
> **域契约**（判型→裁定+M1–M4→按上限执行→停手问）：见 `Tool/skill/seep-router/SKILL.md`（唯一口径：判型→选域→上限 M1–M4→必问三件）。本文件不复制。
  **停下来给 A/B/C 卡**，写明：几步、我在监控什么、我保证不动什么、我拿到什么。
- 空目录/首次开工由 **Agent 自己** `case_state.py init`，不要求用户敲命令。

## 1. 范围与路由（边界）

**本域输入面**

- 源码仓库的依赖清单、锁文件、registry 映射、安装脚本执行面。
- SBOM 生成/核对，SCA 告警的可达性收敛。
- GitHub Actions / GitLab CI / Jenkins 的触发、权限、secrets、action pin。
- 容器镜像 digest、签名、attestation、SLSA 来源证明。
- 依赖混淆、仿冒包、恶意安装脚本的识别与隔离。

**相邻域与路由**

- 仓库/镜像/流水线清单由 `scope` 声明；投毒、抢注、发布测试包、改生产 CI 按单独授权单执行。
- CVE 武器化、漏洞利用开发；只做版本/可达性/补丁差异/影响面。
- 应用层漏洞 → `web-pentest`；APK/固件逆向 → `apkseep`/`firmware-iot`；
  容器逃逸/云原生 → `ad-cloud`；恶意样本动态分析 → `malware-analysis`。
- 许可证/法务合规结论；本技能只列组件、声明与证据。

## 配方（照这个跑）

输入面命中下面某行时，先照该配方的命令序列跑，再回来对判据；配方正文只在 playbooks 一处，本文件只指路。

- 仓库依赖 / SBOM / CI 权限 / 制品签名审计 → `Tool/playbooks/supply-chain-audit.md`
- OSINT 资产测绘里的代码与凭据泄露面 → `Tool/playbooks/osint-recon.md`

## 上限怎么说（对客户）

- **只能看懂结构**：`只给了组件清单与版本命中（SBOM/扫描告警），哪个真能被调用过、我没验`
- **能改到能用**：`每个风险项都能指到调用路径或运行时加载（代码行 + 运行时依赖树），修复前后能对照`
- **能完全自己接管**：`每个产物都能自证：digest + 签名身份/issuer + 来源证明 subject 一致，CI 最小权限与不可信触发都有证据，别人重跑得同一结果`
- **卡点通常是**：`拿不到私有仓库/CI 凭据，或只有 tag 没有 digest——可达性只能停在「版本范围命中」`

> 依据：本文件 §3 判据表（SCA 可达/CI 凭据面/制品来源）+ §4 失败判据（零 finding 不写「无风险」）

## 2. 前置检查（三件）

1. **对象**：`git rev-parse HEAD`、镜像 `RepoDigests`/`crane digest`、锁文件 sha256；工作区是否干净。
2. **授权**：仓库/镜像/CI 账号归属；只读优先；联网查 registry 需单独授权。
3. **判据**：本次回答“能否被利用”还是“是否符合基线”；两者证据形态不同。

```bash
git rev-parse HEAD
git status --porcelain
sha256sum package-lock.json requirements.txt go.sum Cargo.lock 2>/dev/null
docker image inspect <image> --format '{{.Id}} {{.RepoDigests}}'
```

对象钉不住（无 commit/digest/锁文件 hash）时，只能写“未钉住”，不得写扫描结论。

## 3. 判据表（确认 / 疑似）

| 类别 | 确认（可机检） | 疑似（缺一条） | 证据形态 |
| :-- | :-- | :-- | :-- |
| 锁文件 | 锁文件与 manifest 同源；条目有 integrity；resolved 指向受控源；CI 冻结安装 | 有锁文件但缺 integrity / CI 用 `npm install` | 锁文件 sha256 + 条目 + CI 命令 |
| SBOM | subject 对 commit/digest；组件能追到锁文件；直接+传递覆盖 | SBOM 存在但过期/组件差 >20% | SBOM + `missing_from_sbom[]` |
| SCA 可达 | 入口→传递→sink 调用链，或运行时加载；不可达有原因 | 只有版本范围命中 | `reach.json` + 代码行 + 运行时依赖树 |
| 依赖混淆 | scope 有 registry 映射；resolved 与映射一致；公共同名不可解析 | 只看到私有 scope/内部包名 | `.npmrc`/`pip.conf`/`nuget.config` + 锁文件 |
| 安装脚本 | 每条安装期命令有来源/必要性；下载有 hash | 有 `postinstall` 未读内容 | manifest 原文 + URL + hash |
| CI 权限 | 显式最小 permissions；写权限只在发布 job | 顶层 `write-all` 但触发器受控 | `ci.json` 的 permissions + 行号 |
| CI 触发 | 不可信触发不接触 secrets/写 token；不 checkout PR head | 只命中 `pull_request_target` 关键字 | triggers/checkout_refs/secrets_refs |
| CI 凭据面 | 变量名与 secrets 名单交集 + 一次独立只读校验 rc=0（或 runner/OIDC/cache 任一提取面判据成立） | 只有 `***` 掩码/只有高熵串/token 有效但无 job | `ci.json` + run id + 变量名 + 指纹 + 校验 rc |
| 制品来源 | digest 一致 + 签名 identity/issuer 匹配 + attestation subject 一致 | 只有签名 rc=0 或只有 tag | cosign 输出 + Rekor + attestation |

完整表（24 行，含误报风险）：`references/01-criteria.md`。

## 4. 失败判据（看到即降级）

- 只有 SCA 告警/版本匹配，没有可达调用链或运行时证据。
- 只有 tag 没有 digest；SBOM 对不上 commit/digest。
- 锁文件缺 integrity 却宣称“可复现构建”。
- 只凭 `pull_request_target` 关键字命中，未核对 checkout 内容、job 权限与 secrets 作用域。
- 只看到 secrets 变量名/`***` 掩码，或只有 runner/OIDC token “有效”，就写“凭据可用”（缺一次独立只读校验）。
- 只看到私有 scope 名，未验证 registry 的实际解析结果。
- 签名/来源未验证，或用“能构建”代替“可信构建”。
- 扫描 `truncated=true`、`degraded[]` 非空、`missing_tools` 含 SCA/签名工具，却写“无风险”。
- 零 finding 被写成“不存在漏洞”。

完整表（24 行，含改走哪条/代价）：`references/02-failure-criteria.md`。

## 5. 模型常见失误（≥8 条）

1. **把 SCA 告警写成“存在高危漏洞”**：版本命中≠可利用；先查 import/调用链/运行时，缺证据写疑似。
2. **把 tag 当对象标识**：tag 可移动；报告必须写 `repo@sha256:<digest>`。
3. **把 `pull_request_target` 关键字当“已被利用”**：看 checkout ref + job permissions + secrets 组合。
4. **把私有 scope 名当“可被抢注”**：三方对账 registry 映射 + resolved + integrity，缺解析结果只写配置缺失。
5. **锁文件存在就宣称可复现**：还要 integrity、受控源、冻结安装、与 manifest 同源。
6. **把“能构建/能跑”当“可信构建”**：要签名身份、issuer、subject digest、Rekor。
7. **只看 `cosign verify` rc=0**：不核对 identity/issuer，等于只证明“有签名”。
8. **把 Python 发行名当 import 名**：`PyYAML`→`yaml`、`beautifulsoup4`→`bs4`；搜不到不等于不可达。
9. **只扫源码不看 CI/构建脚本**：供应链攻击常发生在构建期，CI/Dockerfile/安装脚本同等级。
10. **把 `write-all` 当必然可利用**：权限+触发器+输入面三者一起看。
11. **把许可证扫描当法务结论**：只列组件与声明，冲突交法务。
12. **把“未联网”当“已验证不可抢注”**：没查≠不存在，保留未验证项。
13. **用绝对路径/本机环境写复现**：路径相对仓库根，脚本先探测外部工具并降级。
14. **把零命中写成“无漏洞”**：写“当前规则集未命中”，附 `degraded[]` 与未覆盖输入面。

完整 15 条（错误动作→为什么错→正确动作）：`references/03-model-pitfalls.md`。

## 6. 流程（每阶段有完成判据）

### 阶段 A：钉对象

```bash
git rev-parse HEAD && git status --porcelain
sha256sum package-lock.json requirements.txt go.sum Cargo.lock 2>/dev/null
docker image inspect <image> --format '{{.RepoDigests}}'
```

完成判据：至少一个不可变标识（commit/digest/锁文件 hash）写入证据。

### 阶段 B：清单与 SBOM

```bash
python Tool/skill/supply-chain-security/scripts/sbom-reach.py \
  --sbom bom.json --lock package-lock.json --freeze freeze.txt --source . --out reach.json
```

完成判据：`components_total>0`；有 SBOM 时 `missing_from_sbom` 为空或逐条解释。

### 阶段 C：锁文件与 registry

```bash
python Tool/skill/supply-chain-security/scripts/sc-check.py --path . --out sc.json
jq '{inventory: .inventory.locks, risks: [.risks[] | select(.category|test("lock|registry|version"))]}' sc.json
```

完成判据：锁文件同源、integrity 覆盖、resolved 与 registry 映射一致。

### 阶段 D：可达性

```bash
jq '{entries, reachable: [.reachable[] | {name, entry_hit, hits}], missing_from_sbom}' reach.json
```

完成判据：每个高危组件有 `hits[]` 或明确“未观察到调用”；动态导入/entry points 已排查。

### 阶段 E：CI 权限与触发器

```bash
python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py \
  --path .github/workflows --out ci.json
jq '{summary, findings: [.findings[] | {rule, severity, line}]}' ci.json
```

完成判据：每个 workflow 有显式最小 permissions；不可信触发无 secrets/写 token；action pin SHA。

### 阶段 F：镜像/制品来源

```bash
cosign verify <image> --certificate-identity <id> --certificate-oidc-issuer <issuer>
cosign verify-attestation <image> --type slsaprovenance
```

完成判据：identity/issuer 匹配、签名 digest 一致、attestation subject 一致；否则写“未验证来源”。

### 阶段 G：结论与修复

- 每条结论：对象 + 命令 + rc + 原始 JSON + 文件/行号。
- 每条修复：具体值（版本/SHA/digest/permissions 文本）+ 验证命令。
- 未验证项单列，不藏在脚注。

## 7. 参考索引（逐篇）

| 文件 | 用途 |
| :-- | :-- |
| `references/01-criteria.md` | 24 行判据表：场景/输入面/可机检判据/证据形态/误报风险；§7 四面对账 |
| `references/02-failure-criteria.md` | 24 行失败判据：现象/判定/改走哪条/代价；§5 `blocked_at`、§7 lessons |
| `references/03-model-pitfalls.md` | 25 条模型常见失误：错误动作→为什么错→正确动作；§纠偏命令 |
| `references/04-walkthrough-workflow-permissions.md` | 真实 workflow 权限审计走查（命令+原始输出+边界）；§7 12 项、§8 三要素矩阵 |
| `references/05-lockfile-and-install-scripts.md` | 锁文件完整性、安装脚本执行面、registry 交叉点；§8 六生态、§9 投毒判据 |
| `references/06-reachability-and-sbom-drift.md` | SBOM 漂移、Python 发行名别名、从可达走到可利用；§8 四段式、§9 对账口径 |
| `references/sbom-sca.md` | SBOM/SCA/可达性速查与证据模板；§11 三个集合、§12 闭环 |
| `references/cicd-and-artifacts.md` | GitHub Actions/GitLab/Jenkins、签名与发布、报告模板；§12 CI 凭据提取面（env dump / runner token / OIDC 联邦 / 日志 / 缓存投毒 / registry 六面判据）；§14 12 条权限判据 |
| `references/dependency-confusion.md` | npm/pip/NuGet/Maven 依赖混淆与修复清单；§9 三方对账、§10 行为判据 |
| `references/image-and-provenance.md` | 镜像 digest、cosign、SLSA、构建链一致性；§9 验收矩阵 |

## 8. 脚本用法

| 脚本 | 用途 | 示例 |
| :-- | :-- | :-- |
| `Tool/skill/supply-chain-security/scripts/sc-check.py` | 离线盘点锁文件/宽版本/CI 权限/action pin/镜像 tag/依赖混淆 | `python Tool/skill/supply-chain-security/scripts/sc-check.py --path . --out sc.json` |
| `scripts/sbom-reach.py` | SBOM/锁文件/freeze → 源码 import/require 可达性 | `python Tool/skill/supply-chain-security/scripts/sbom-reach.py --lock package-lock.json --source . --out reach.json` |
| `scripts/ci-perm-audit.py` | workflow 权限面/危险触发器/action pin（行号级） | `python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --path .github/workflows --out ci.json` |

全部脚本：`--help` rc=0；`--self-test` 离线 rc=0 并输出含 `"ok"` 的 JSON；失败输出
`{"ok": false, "blocked_at": "...", "reason": "..."}` 且 rc=2；不硬编码本机路径。

## 9. 任务卡入口

- `Tool/prompts/domains/supply-chain-security.md`（24 张，六段格式，源名取自
  `Tool/config/taskcard-sources.json` 的 `supply-chain-security`）。
- 按对象选卡：SBOM → 01/02；SCA → 03；混淆 → 04；仿冒/恶意包 → 05/06/07/11；
  CI → 08/16/17/18/19；镜像/来源 → 12/13/14/15/20/21；K8s/IaC/供应商 → 22/23/24。

## 10. KB board 入口

- `Tool/mcp/Tool/reverselab/kb/supply-chain/README.md`
- 技术条目：`01-dependency-confusion`、`02-image-and-provenance`、`03-sbom-and-reachability`、
  `04-ci-permission-audit`、`05-lockfile-integrity`、`06-reachability-failure-criteria`、
  `07-typosquat-and-malicious-packages`。
- 矩阵：`Tool/config/supply-chain-security-matrix.json`（19 条，含 match/criteria/fail/pitfalls 口径）。

## 11. 硬判据（交付前自检）

- [ ] 对象钉到 commit/digest/锁文件 sha256，工具与版本可复现。
- [ ] SBOM 覆盖直接+传递依赖，能追到锁文件；差异有解释。
- [ ] 高危告警有可达性结论与证据；不可达有原因。
- [ ] 依赖/CI/镜像至少一条真实风险链，且给最小修复。
- [ ] 签名/来源/权限有证据，未把“能构建”当“可信构建”。
- [ ] 未推送恶意包、未改生产流水线、未外泄凭据、未越权扫描。

> 边界：不投毒、不抢注、不 CVE 武器化、不代法务下结论；只做自有/授权对象的证据链。

## 子技能（按需读，不常驻）

本域相关子技能放在 `Tool/skill/_pending/`（不占常驻上下文，需要时再读）：

- `_pending/doc-hygiene/SKILL.md` —— 审计报告与文档治理
