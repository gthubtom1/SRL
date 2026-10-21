# supply-chain-security 报告模板

> 复制到 `evidence/<case>/report.md`。truncated 结果只能写“未覆盖”，不能写“无风险”。

## 1 目标与授权
- 目标：<仓库/镜像/SBOM/CI / commit 或 digest / 版本>
- 授权：<只读扫描 / 是否允许 registry 查询 / 时间窗>
- 范围外：<生产构建 / 发布 / 写入依赖 / 真实 secrets>
- 环境：<扫描器版本 / 锁文件 / 包管理器 / 网络>

## 2 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/sc.json | <sha256> | `python Tool/scripts/sc-check.py --path <repo> --out ...` | 0 | 清单/CI/风险 |
| E02 | artifacts/reach.json | <sha256> | `python Tool/skill/supply-chain-security/scripts/sbom-reach.py --sbom ... --source ...` | 0 | 组件触达 |
| E03 | artifacts/ci.json | <sha256> | `python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --path .github/workflows` | 0 | 权限/pin |

## 3 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| SBOM/锁定 | 组件、版本、resolved/integrity 可对账 | <实测> | E02 | <结论> |
| 触达 | import/require 命中入口，非仅清单列出 | <实测> | E02 | <结论> |
| dependency confusion | registry 映射 + 锁文件 resolved/integrity 三者一致 | <实测> | E02 | <结论> |
| CI 权限 | permissions 最小化，无多余 write | <实测> | E03 | <结论> |
| Action pin | 第三方 action 固定 40 位 commit SHA | <实测> | E03 | <结论> |
| Secrets | 无明文/无长寿命 token，扫描有基线 | <实测> | E01/E03 | <结论> |

## 4 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| `truncated=true` 被写成全量无风险 | <yes/no> | E01 | 改写“未覆盖”，提高上限分片重跑 |
| 只有 SBOM 清单，无 import 触达 | <yes/no> | E02 | 不写可利用，补源码/入口 |
| 只有 CVE 版本匹配，无锁文件对账 | <yes/no> | E02 | 标 candidate |
| action 用 tag/branch | <yes/no> | E03 | 记 medium，建议固定 SHA |
| secrets 只在日志出现，未验证有效 | <yes/no> | E01 | 不写泄露，先轮换/验证范围 |
| registry 未授权/网络失败 | <yes/no> | E02 | 标环境限制，改离线锁文件 |

## 5 影响与边界
- 影响：<可触达组件 / 可写 CI / 可发布制品 / 可读 secrets>
- 边界：<只读静态 / 未实际构建 / 未查询 registry>
- 误报风险：<devDependency、可选依赖、合法自动化 token>
- 未覆盖：<未扫描目录、未解析的镜像层、未验证的签名>

## 6 修复建议（厂商视角）
1. 锁定 lockfile 与 registry，启用 integrity/resolved 校验；私有 scope 配置 scoped registry。
2. CI 显式 `permissions:` 最小化，第三方 action 固定 40 位 commit SHA，禁用 pull_request_target 滥用。
3. secrets 使用 OIDC/短时凭据，启用 secret scanning 与轮换；构建产物做 SLSA/Sigstore  provenance。
4. 持续生成 SBOM、CVE 扫描与触达分析，对 truncated 扫描分片补全。

## 7 复跑命令
```bash
python Tool/scripts/sc-check.py --path evidence/<case>/artifacts/repo --max-files 1000 --out evidence/<case>/artifacts/sc.json
python Tool/skill/supply-chain-security/scripts/sbom-reach.py --sbom evidence/<case>/artifacts/bom.json --source evidence/<case>/artifacts/src --out evidence/<case>/artifacts/reach.json
python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --path .github/workflows --out evidence/<case>/artifacts/ci.json
```
