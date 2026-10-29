---
name: sbom-audit
description: "SBOM/锁文件/制品身份对账、SCA 匹配与代码可达性分层；记录生态覆盖、漏洞库版本和未覆盖项。"
metadata:
  version: "2.1.0"
  target_runtimes: "CycloneDX / SPDX / npm / Python / Maven / Go / Cargo 等"
---

# SBOM 与依赖风险

输入为固定源码快照/锁文件、制品 digest/平台与已有 SBOM；目标是清单、版本告警、调用可达或投毒研判中的哪一种先说明。复用 [SBOM/SCA](../../references/sbom-sca.md)、[漂移与可达性](../../references/06-reachability-and-sbom-drift.md)、[源解析](../../references/dependency-confusion.md)、[镜像来源](../../references/image-and-provenance.md)。

## 清单事实源与边界

| 生态 | 优先事实源 | 限制 |
|---|---|---|
| npm/pnpm/yarn | 精确锁文件、registry 映射和制品 integrity | npm audit 不生成完整 SBOM，不能用它直接审 pnpm 锁；peer/optional/platform 条件另核 |
| Python | 已固定 requirements、poetry/Pipfile/uv 锁、发行包元数据 | requirements 未必固定；发行名与 import 名不同；pip-audit 的解析/安装行为按版本核实 |
| Maven/Gradle | 解析后的依赖图、BOM/约束、锁与制品信息 | pom/build 文件可能动态求值；构建命令会加载插件/脚本，不能称纯静态 |
| Go | go.mod/go.sum 与 resolved module graph | go.sum 是校验集合，不等于实际全依赖；go list 可能联网/更新缓存 |
| Cargo | Cargo.lock、features/target 与实际依赖图 | cargo audit 是告警匹配，不证明代码被编入或可达 |

不为盘点运行未知安装脚本或包管理器构建。需要实际解析/下载时先核工具行为、现有范围与隔离条件；优先已有锁与安全制品。私有 registry 凭据、URL 中 Token、配置 Secret 不进入 Agent。

## 现有工具与外部 CLI

```bash
python Tool/skill/supply-chain-security/scripts/sbom-reach.py --sbom work/sbom.json --lock work/package-lock.json --source work/source --out work/reach.json
```

该脚本支持有限 CycloneDX/SPDX JSON、npm 锁与 freeze，并用静态 import/require 启发式分析；不是所有生态的完整依赖求解器，更不是可利用性证明。动态加载、反射、插件、生成代码和打包裁剪需独立核实。

当前安装支持时，可按 Syft/Grype 的实际帮助使用：

```bash
syft scan dir:work/source -o cyclonedx-json=work/sbom.json
grype sbom:work/sbom.json -o json > work/grype.json
```

先核版本、cataloger、平台/arch、扫描排除和漏洞数据库身份/更新时间；Syft 旧版本入口可能不同，不自动安装或默认联网更新。生成 SBOM 不证明版本身份准确，Grype 零告警只覆盖所用数据库/匹配规则与已识别组件。

## 身份、风险与覆盖分开

组件记录生态、名称、精确版本或未知、purl/CPE（可得时）、直接/传递、来源与依赖关系。SBOM 的 subject 必须对应实际 commit/工作树指纹或 image digest/platform。不同生态提供的 hash 可能是 SHA512、go.sum h1、包归档 digest、文件 digest 或没有；不能要求每个组件都有 SHA256。注明算法与对象层级，不伪造缺失哈希。

漏洞命中核受影响版本、发行版 backport、配置、调用路径和利用条件；静态 import 命中只说明可能触达，不证明到达漏洞 sink。清单漂移解释生成时点、target/features、dev/build/runtime 与已安装制品差异。

私有包同名或拼写相似是线索；依赖混淆需实际 registry 优先级、scope 配置与 resolved 来源支持；安装脚本需追具体命令、下载来源、校验与触发链。CVE 匹配、投毒、来源不可信与可利用性是不同结论。禁止为验证抢注/发布包、运行可疑 postinstall 或采集真实凭据。

## 正反例与交付

正例：SBOM 对应同一 digest，直接/传递组件可追到锁或制品，某告警有真实版本/调用条件支持，修复后相关版本与调用对照成立。反例：旧 SBOM 对新制品、缺私有依赖、漏洞库过期、扫描零结果，均不能写“不存在风险”。缺 hash 但有可追的合法版本身份不应一律判任务失败。

交付 subject、工具/数据库版本、组件/依赖覆盖、版本告警/可达/投毒各自证据、未覆盖生态和恢复条件。审计无需修改所有依赖；修复任务另验功能与制品身份。CI 来源请 ci-cd-security、二进制/脚本行为请 softseep/malware-analysis，结果归同一 project/version/run。同形失败两次回身份与工具支持判断。
