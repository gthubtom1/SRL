# supply-chain-security 报告模板

> **客户视角五段（必须全在，缺一不算交付）**：下面五个是**真标题**——`python Tool/scripts/case_state.py report --check --file <本文件>`
> 按标题文字精确匹配「结论 / 已确认 / 仍未知 / 下一步 / 复查」，缺一段即 `[FAIL]`；每段标题下至少 2 行正文，
> 「结论」不超过 3 行，「已确认」里至少要有一个 `E-` / `C-` / `F-` 编号。「下一步 / 复查」别改名，改了检查器就找不到。

> 复制到 `work/<case>/report.md`。truncated 结果只能写“未覆盖”，不能写“无风险”。

## 1 结论（≤3 行：能不能用 / 到哪一步 / 卡在哪）
- 到哪一步：<只能看懂结构 | 能改到能用 | 能完全自己接管 | 现在做不了>
- 卡在哪：<卡点一句话 + 证据编号；没有卡点写「无」>
- 能不能用：<只按已有证据说一句；没跑过就写「未验证」>

## 2 已确认（每条：客户能听懂的一句话 + 证据 ID + 强度：强 / 中 / 弱）
- <客户能听懂的那句话>（`E-001`；强：同输入同输出可复现，命令与输出都能贴）—— 原始记录 `artifacts/<tool>-<时间>.json`
- <客户能听懂的那句话>（`E-002`；强：两路独立验证一致，不只是重复跑）—— 原始记录 `artifacts/<tool>-<时间>.json`
- 只有一次观测、没有可复跑命令的线索不进本段，写进第 3 段。

## 3 仍未知（每条：未知什么 + 为什么未知 + 缺什么才能知道）
- <未知什么>｜为什么未知：<环境限制 / 证据缺口 / 授权没给>｜还缺：<补什么才能知道>
- <未知什么>｜为什么未知：<同上>｜还缺：<同上>

## 4 下一步（省事路线 / 彻底路线 / 不建议做的事，各一条）
- 省事路线：<最小动作 + 拿到什么 + 大概要花多少功夫（区间 + 判断依据）>
- 彻底路线：<要补的证据或要动的位点 + 代价与工期>
- 不建议做：<哪条路会白费或越界，为什么>

## 5 怎么复查（复查单路径 + 关键重放命令 + 期望看到什么）
- 复查单：`python Tool/scripts/case_state.py recheck --case work/<case>` → 生成 `work/<case>/recheck.md`（目标哈希 / 环境 / 重放命令）
- 重放：<本域脚本命令；Windows 的 cmd 与 PowerShell 都能直接粘贴，见文末复跑命令>
- 期望：<关键字段或输出片段>；对不上先查「已知会变」（在线服务 / 证书 / IP / 时钟）

## 6 目标与授权
- 目标：<仓库/镜像/SBOM/CI / commit 或 digest / 版本>
- 授权：<只读扫描 / 是否允许 registry 查询 / 时间窗>
- 范围外：<生产构建 / 发布 / 写入依赖 / 真实 secrets>
- 环境：<扫描器版本 / 锁文件 / 包管理器 / 网络>

## 7 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/sc.json | <sha256> | `python Tool/skill/supply-chain-security/scripts/sc-check.py --path <repo> --out ...` | 0 | 清单/CI/风险 |
| E02 | artifacts/reach.json | <sha256> | `python Tool/skill/supply-chain-security/scripts/sbom-reach.py --sbom ... --source ...` | 0 | 组件触达 |
| E03 | artifacts/ci.json | <sha256> | `python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --path .github/workflows` | 0 | 权限/pin |

## 8 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| SBOM/锁定 | 组件、版本、resolved/integrity 可对账 | <实测> | E02 | <结论> |
| 触达 | import/require 命中入口，非仅清单列出 | <实测> | E02 | <结论> |
| dependency confusion | registry 映射 + 锁文件 resolved/integrity 三者一致 | <实测> | E02 | <结论> |
| CI 权限 | permissions 最小化，无多余 write | <实测> | E03 | <结论> |
| Action pin | 第三方 action 固定 40 位 commit SHA | <实测> | E03 | <结论> |
| Secrets | 无明文/无长寿命 token，扫描有基线 | <实测> | E01/E03 | <结论> |

## 9 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| `truncated=true` 被写成全量无风险 | <yes/no> | E01 | 改写“未覆盖”，提高上限分片重跑 |
| 只有 SBOM 清单，无 import 触达 | <yes/no> | E02 | 不写可利用，补源码/入口 |
| 只有 CVE 版本匹配，无锁文件对账 | <yes/no> | E02 | 标 candidate |
| action 用 tag/branch | <yes/no> | E03 | 记 medium，建议固定 SHA |
| secrets 只在日志出现，未验证有效 | <yes/no> | E01 | 不写泄露，先轮换/验证范围 |
| registry 未授权/网络失败 | <yes/no> | E02 | 标环境限制，改离线锁文件 |

## 10 影响与边界
- 影响：<可触达组件 / 可写 CI / 可发布制品 / 可读 secrets>
- 边界：<只读静态 / 未实际构建 / 未查询 registry>
- 误报风险：<devDependency、可选依赖、合法自动化 token>
- 未覆盖：<未扫描目录、未解析的镜像层、未验证的签名>

## 11 修复建议（厂商视角）
1. 锁定 lockfile 与 registry，启用 integrity/resolved 校验；私有 scope 配置 scoped registry。
2. CI 显式 `permissions:` 最小化，第三方 action 固定 40 位 commit SHA，禁用 pull_request_target 滥用。
3. secrets 使用 OIDC/短时凭据，启用 secret scanning 与轮换；构建产物做 SLSA/Sigstore  provenance。
4. 持续生成 SBOM、CVE 扫描与触达分析，对 truncated 扫描分片补全。

## 12 复跑命令
```bash
python Tool/skill/supply-chain-security/scripts/sc-check.py --path work/<case>/artifacts/repo --max-files 1000 --out work/<case>/artifacts/sc.json
python Tool/skill/supply-chain-security/scripts/sbom-reach.py --sbom work/<case>/artifacts/bom.json --source work/<case>/artifacts/src --out work/<case>/artifacts/reach.json
python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --path .github/workflows --out work/<case>/artifacts/ci.json
```
