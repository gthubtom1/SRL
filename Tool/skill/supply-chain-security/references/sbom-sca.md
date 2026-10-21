# SBOM / SCA / 可达性速查

> 配套 `supply-chain-security/SKILL.md`。只在授权仓库/镜像上扫描。
>
> **适用**：已有 commit/digest 或锁文件，需要生成/核对 SBOM、把 SCA 告警收敛为可达/不可达结论。
> **不适用**：没有对象标识、未授权联网、要求 CVE 武器化或投毒验证；运行时利用属于 `pwn-crypto`/`web-pentest`。

## 1. 锁定对象

```bash
git rev-parse HEAD | tee evidence/commit.txt
git status --porcelain | tee evidence/worktree.txt
sha256sum package-lock.json pnpm-lock.yaml yarn.lock requirements.txt poetry.lock \
          Pipfile.lock go.sum Cargo.lock pom.xml 2>/dev/null | tee evidence/locks.sha256
docker image inspect <image> --format '{{.Id}} {{.RepoDigests}}' | tee evidence/image.txt
```

- 报告写 commit + digest，不写 `latest`/tag。
- 工作区必须干净；本地未提交改动会使 SBOM 不可复现。

## 2. SBOM 生成

```bash
syft dir:. -o spdx-json=evidence/sbom.spdx.json
syft dir:. -o cyclonedx-json=evidence/sbom.cdx.json
syft <image> -o table | head -40
cdxgen -o evidence/bom.json .
```

检查：

```bash
jq '.packages | length' evidence/sbom.spdx.json
jq '.components | length' evidence/sbom.cdx.json
jq -r '.packages[] | [.name,.versionInfo,.licenseConcluded] | @tsv' evidence/sbom.spdx.json | head
```

- 直接依赖：锁文件/清单里有明确声明；传递依赖：由解析器带入。
- 许可证：`NOASSERTION`/空值单独列；GPL/AGPL 与分发方式冲突要提示。
- 判据：任一组件可从 SBOM 追到锁文件条目与安装路径。

## 3. SCA

```bash
osv-scanner scan -r . --format json > evidence/osv.json
grype sbom:evidence/sbom.cdx.json -o json > evidence/grype.json
trivy fs --scanners vuln,secret,misconfig . -f json -o evidence/trivy.json
```

归一化（示例）：

```bash
jq -r '.results[]?.packages[]? | [.package.name,.package.version,.vulnerabilities[0].id] | @tsv' evidence/osv.json | head
```

- 同一 CVE 在多工具重复：按 `package+version+CVE` 去重。
- 优先级：直接依赖 + 运行时可达 + 有公开 PoC > 传递依赖 + 不可达。
- 判据：每个高危项有“版本范围/调用链/运行时证据/修复版本”。

## 4. 可达性

```text
1. 入口：HTTP handler / CLI / 消息消费者 / 定时任务
2. 调用链：入口 → 业务函数 → 依赖 API（grep/IDE call hierarchy/CodeQL）
3. 运行时：请求/单测触发，断点或日志确认进入依赖
4. 版本：受影响范围包含当前版本；修复版本可用
5. 结论：reachable / not-reachable / unknown（附原因）
```

- Java：`mvn dependency:tree -Dincludes=<group:artifact>`；`jdeps`/Call Graph。
- Node：`npm ls <pkg>`；检查 `require`/`import` 静态路径与动态拼接收敛。
- Python：`pip show`、`pipdeptree`；注意可选依赖/插件加载。
- Go：`go mod graph`、`go list -deps`；vendor 目录是否实际使用。

## 5. 依赖混淆 / 抢注

```bash
npm config get registry
npm view @corp/private-pkg name version 2>&1
pip config list
pip index versions corp-private-pkg 2>&1
```

- 私有 scope 必须在配置中绑定私有 registry；公共同名包存在 = 抢注风险。
- 检查 `.npmrc` 的 `@corp:registry`、`pip.conf` 的 `index-url`/`extra-index-url`。
- 判据：每个内部包名有 registry 锁定，且公共 registry 无同名可解析包。

## 6. 锁文件完整性

```bash
grep -n '"integrity"' package-lock.json | head
grep -nE 'resolved.*(git\+http|file:|http://)' package-lock.json pnpm-lock.yaml yarn.lock
grep -nE '^\s*[a-zA-Z0-9_.-]+==[^=]' requirements.txt | head
```

- `integrity` 缺失、`resolved` 指向 http/未知主机、版本用 `*`/`latest` = 不可复现。
- 判据：安装可离线复现，哈希与锁文件一致。

## 7. 修复建议

| 风险 | 最小修复 |
|---|---|
| 直接依赖 CVE | 升级到修复版本；不能升则隔离/关闭入口 |
| 传递依赖 CVE | 上游升级/override/resolutions；评估替换 |
| 依赖混淆 | scope 绑私有 registry；保留名占位 |
| 锁文件缺失 | 提交锁文件；CI 用 `npm ci`/`pip install -r` |
| 安装脚本 | 移除不必要脚本；沙箱构建；审计下载源 |
| 许可证 | 替换/隔离/法务确认 |

## 8. 证据模板

```text
对象：<repo>@<commit> / <image>@sha256:<digest>
SBOM：<tool> <version> <path> <sha256>
SCA：<tool> <version> <path>；高危 N 条
可达：<CVE> <package@version> <入口→依赖> <reachable/not/unknown>
投毒：<scope/registry/同名包> <证据>
修复：<版本/配置/隔离> <验证命令>
未验证：<...>
```

## 9. 失败判据（看到即降级）

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| 只有 SCA 告警/版本匹配 | 未证明可达 | 用 `sbom-reach.py` 查源码 import，再查运行时依赖树 | 低：一次源码扫描 |
| SBOM 对不上 commit/digest | 清单不可信 | 重新生成并绑定对象；或改用锁文件解析 | 中：需要构建记录 |
| 组件数与锁文件差 >20% | SBOM 漂移/环境不全 | 记录差异，按 purl 对齐；必要时重生成 | 低：一次重生成 |
| 传递依赖命中但未打包 | 不可达（未进入产物） | 查构建产物/镜像层；写“未打包”原因 | 低：一次产物核对 |
| 仅测试/devDependency 命中 | 不进生产 | 核对依赖分组与 CI 安装参数 | 低：读 manifest |
| 可达但参数不可控 | 调用≠利用 | 写“可达、未见可控入口”，转人工代码审计 | 中：需要业务上下文 |

## 10. 边界

- 不把“未观察到调用”写成“不可达”，不把“可达”写成“可利用”。
- 不编造 CVE 编号或 PoC；没有 OSV/GHSA 数据时只做版本与调用面。
- SBOM 不覆盖 OS 包/内核/固件内嵌库；那些走 `firmware-iot`/`forensics-mobile`。
- 外部工具缺失时输出 `degraded`，并在报告里保留“未验证”项。
