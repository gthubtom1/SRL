# Supply Chain 知识库 — 供应链 / 依赖 / CI-CD

> Board：`supply-chain`。配套技能：`Tool/skill/supply-chain-security/SKILL.md`。
> 只收“对象可钉住、判据可复核、修复可执行”的供应链方法；SCA 告警与 tag 名称不进结论。
> 适用：授权仓库/镜像/流水线的只读审计。不适用：投毒/抢注、未授权 registry 探测、CVE 武器化。

## 入口

| 场景 | 先读 |
| :-- | :-- |
| 私有 scope / 内部包名 / registry 回退 | [依赖混淆与抢注](techniques/01-dependency-confusion.md) |
| 镜像 tag → digest、签名、attestation | [镜像 digest 与来源证明](techniques/02-image-and-provenance.md) |
| 有 SBOM/锁文件，问“组件进了源码吗” | [SBOM 与可达性](techniques/03-sbom-and-reachability.md) |
| workflow 权限、触发器、action pin | [GitHub Actions 权限面](techniques/04-ci-permission-audit.md) |
| integrity / resolved / 冻结安装 | [锁文件完整性](techniques/05-lockfile-integrity.md) |
| 结果不成立、要降级换面 | [供应链失败判据](techniques/06-reachability-failure-criteria.md) |
| 仿冒包、恶意安装脚本、外联 | [抢注/仿冒与恶意包](techniques/07-typosquat-and-malicious-packages.md) |
| Bun 载荷、运行期动态依赖（RDD） | [2026 ChainDrop / SANDWORM_MODE 战例](techniques/2026-chaindrop-sandworm.md) |

技能参考（逐篇）：`references/01-criteria.md`、`references/02-failure-criteria.md`、
`references/03-model-pitfalls.md`、`references/04-walkthrough-workflow-permissions.md`、
`references/05-lockfile-and-install-scripts.md`、`references/06-reachability-and-sbom-drift.md`、
`references/sbom-sca.md`、`references/cicd-and-artifacts.md`、
`references/dependency-confusion.md`、`references/image-and-provenance.md`。

## 分析链

```text
对象（commit/digest/锁文件 sha256）
→ 清单与 SBOM（锁文件/freeze/组件集合）
→ 锁文件完整性 + registry 映射
→ 源码入口可达性（import/require）
→ SCA 告警 + 版本范围 + 补丁 diff
→ CI 触发/权限/checkout/secrets/action pin
→ 镜像 tag→digest、签名、attestation
→ 最小修复 + 证据索引
```

## 三条硬判据

1. **对象可钉住**：commit、镜像 digest、锁文件 hash 至少有一个不可变标识，且报告写具体值。
2. **风险可复核**：依赖混淆看 registry 解析 + 锁文件 resolved/integrity；CVE 看调用链/运行时；
   CI 看触发 + checkout + 权限 + secrets 组合。
3. **修复可执行**：锁文件、registry 映射、最小 permissions、pin SHA、digest、签名验证，给到具体值。

## 失败判据（看到即降级）

- 只有 SCA 告警/版本匹配，没有调用链或运行时证据。
- 只有 tag 没有 digest；SBOM 对不上 commit/digest。
- 锁文件缺 integrity 却宣称“可复现构建”。
- 只凭 `pull_request_target` 关键字命中，未看 checkout 内容与 secrets 作用域。
- 只看私有 scope 名，未验证 registry 实际解析。
- 未验证签名身份/issuer，或用“能构建”代替“可信构建”。
- 扫描 `truncated=true`/`degraded[]` 非空，却写“无风险”。

完整表见 [失败判据](techniques/06-reachability-failure-criteria.md)。

## 工具与命令

```bash
# 离线清单/锁/CI/依赖混淆盘点（有 high/critical 时 rc=1）
python Tool/scripts/sc-check.py --path . --out sc.json

# 锁文件/freeze/SBOM → 源码可达性
python Tool/skill/supply-chain-security/scripts/sbom-reach.py \
  --sbom bom.json --lock package-lock.json --freeze freeze.txt --source . --out reach.json

# workflow 权限/触发器/action pin（有 high 时 rc=1）
python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py \
  --path .github/workflows --out ci.json

# 矩阵：按类目核对判据/误报
python - <<'PY'
import json
m = json.load(open('Tool/config/supply-chain-security-matrix.json', encoding='utf-8'))
for r in m['rows'][:8]:
    print(r['category'], '|', r['criteria'], '|', r['fail'], '|', r['false_positive_risk'])
PY
```

## 与相邻 board 的边界

- Web/API 漏洞：`web-pentest`；容器逃逸/云原生：`ad-cloud`。
- Android/iOS 客户端：`apk-reverse`；固件：`firmware-iot`；恶意样本：`malware-analysis`。
- 本 board 只回答：制品由什么组成、哪个依赖/构建步骤能被利用、证据是否足以修复。

每篇 technique 都必须包含：入口信号、可复制命令、确认判据、失败判据、边界。缺一项视为未完成。
