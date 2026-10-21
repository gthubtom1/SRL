# Supply Chain 知识库 — 供应链 / 依赖 / CI-CD

> Board：`supply-chain`。配套技能：`Tool/skill/supply-chain-security/SKILL.md`。
> 只收“对象可钉住、判据可复核、修复可执行”的供应链方法；SCA 告警与 tag 名称不进结论。

## 入口

- [依赖混淆与抢注](techniques/01-dependency-confusion.md)
- [镜像 digest 与来源证明](techniques/02-image-and-provenance.md)
- 技能参考：`references/sbom-sca.md`、`references/cicd-and-artifacts.md`、`references/dependency-confusion.md`、`references/image-and-provenance.md`
- 离线基线：`python Tool/skill/supply-chain-security/scripts/sc-check.py --path <repo>`
- 矩阵：`Tool/config/supply-chain-security-matrix.json`

## 分析链

```text
对象（commit/digest/锁文件）
→ 清单与 SBOM
→ 锁文件/integrity/registry 映射
→ SCA 告警 + 可达性
→ CI 触发/权限/action pin/secrets
→ 镜像 tag→digest、签名、attestation
→ 最小修复 + 证据索引
```

## 三条硬判据

1. **对象可钉住**：commit、镜像 digest、锁文件 hash 至少有一个不可变标识。
2. **风险可复核**：依赖混淆看 registry 解析结果；CVE 看可达性；CI 看触发+checkout+权限。
3. **修复可执行**：锁文件、registry 映射、最小 permissions、pin SHA、digest、签名验证，给到具体值。

## 失败判据（看到即降级）

- 只有 SCA 告警/版本匹配，没有调用链或运行时证据。
- 只有 tag 没有 digest；SBOM 对不上 commit/digest。
- 锁文件缺 integrity 却宣称“可复现构建”。
- 只凭 `pull_request_target` 关键字命中，未看 checkout 内容与 secrets 作用域。
- 只看私有 scope 名，未验证 registry 实际解析。
- 未验证签名身份/issuer，或用“能构建”代替“可信构建”。

## 与相邻 board 的边界

- Web/API 漏洞：`web-pentest`。
- 容器逃逸/云原生：`ad-cloud`。
- Android/iOS 客户端：`apk-reverse`。
- 本 board 只回答：制品由什么组成、哪个依赖/构建步骤可被利用、证据是否足以修复。

## 使用方式

```bash
# 离线盘点；有 high/critical 时退出码 1
python Tool/skill/supply-chain-security/scripts/sc-check.py --path . --out evidence/<case>/sc-check.json

# 按矩阵核对判据与误报风险
python - <<'PY'
import json
m=json.load(open('Tool/config/supply-chain-security-matrix.json'))
for r in m['rows'][:6]:
    print(r['category'], '|', r['criteria'], '|', r['false_positive_risk'])
PY
```

每篇技术文档都必须包含：入口信号、可复制命令、确认判据、失败判据、边界。缺一项视为未完成。
