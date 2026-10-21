# 2026 战例：ChainDrop / SANDWORM_MODE 的 Bun 载荷与运行期依赖

> 战例 KB-SC-2026-08 · 收录 2026-10-20 · 单篇 ≤200 行 · 只写对象钉住与判据，不复述 SBOM 方法。

## 来源与日期

- ChainDrop（2026-08 公开分析）：npm 生态内以“安装期投放 + 运行期拉取”组合传播的投放链，
  载荷在安装脚本阶段落地，后续由运行时动态解析。
- SANDWORM_MODE（2026-02 公开分析）：伪装开发者工具的恶意包，使用 Bun 运行时执行混淆载荷，
  以绕开只 hook Node `child_process`/`require` 的监控。
- 关联公开面：npm `postinstall`/`prepare` 生命周期、`bun` 可执行文件检测、远程动态依赖（RDD）
  在 install/runtime 阶段解析到 lockfile 之外的 URL。
- 本页为公开报告蒸馏，未附本机样本；包名/版本以报告原文为准，不在此复述 IOC 清单。

## 场景

入口信号：

- 锁文件里出现来源可疑的新包，或 `resolved` 指向非官方 registry/短命域名。
- `package.json` 的 `scripts` 含 `postinstall`/`prepare`/`preinstall`，且脚本里出现 `bun`、`curl`、
  `node -e`、base64 大块、或 `child_process` 动态拼接。
- CI 日志里出现 `bun install`/`bun run`，但仓库本身不是 Bun 项目。
- 依赖树里某包的 `dependencies` 在安装后才变化（运行期解析，RDD）。

先分清三种落点，判据不同：

| 落点 | 触发时机 | 关键证据 |
| :-- | :-- | :-- |
| install 脚本 | `npm i` / `bun install` | 生命周期脚本 + 子进程 + 外联 |
| 运行期动态依赖（RDD） | 首次 `require`/`import` | `rdd_ref` 指向 lockfile 外 URL |
| Bun 二进制载荷 | `bun run` 或下载的 `bun` | ELF/PE 头 + V8/JSC 之外的 JS 运行时特征 |

## 命令

```bash
# 0) 钉住对象：lockfile + tarball 哈希（不看 tag、不看版本号）
git rev-parse HEAD
sha256sum package-lock.json pnpm-lock.yaml yarn.lock 2>/dev/null
npm view <pkg>@<ver> dist.tarball dist.integrity --json
npm pack <pkg>@<ver> --pack-destination /tmp/pkgs && sha256sum /tmp/pkgs/*.tgz

# 1) 生命周期脚本面
python Tool/scripts/sc-check.py --path . --out sc.json
jq -r '.packages[]? | select(.scripts) | [.name,.version,(.scripts|keys|join(","))] | @tsv' \
  node_modules/.package-lock.json 2>/dev/null | head -20
grep -RInE '"(pre|post)?install"|"prepare"' package.json node_modules/*/package.json | head -30

# 2) 脚本内容里找 Bun / 下载 / 解码
grep -RInE '\bbun\b|bunx|curl |wget |base64 -d|child_process|spawn\(' \
  node_modules/*/package.json node_modules/*/*.js 2>/dev/null | head -30

# 3) 运行期依赖（RDD）：解析是否越出 lockfile
python Tool/skill/supply-chain-security/scripts/sbom-reach.py \
  --lock package-lock.json --source . --out reach.json
jq -r '.rdd[]? | [.name,.version,.resolved,.in_lockfile] | @tsv' reach.json 2>/dev/null

# 4) 沙箱内跑安装脚本（断网/只记录，不执行外联）
#    容器内：strace -f -e trace=execve,connect -o trace.log npm ci --ignore-scripts=false
grep -E 'execve|connect' trace.log | head -40
```

## 判据表

| 字段 | 取值 | 成立阈值 | 证据 |
| :-- | :-- | :-- | :-- |
| `bun_payload` | `none` / `bun-runtime` / `bun-downloaded` | `bun-runtime` 需在脚本或进程树里出现 `bun` 执行；`bun-downloaded` 还需落地文件哈希 | `trace.log` + `sha256` |
| `install_hook` | `postinstall`/`prepare`/`preinstall` + 文件:行 | 脚本内容可读，且与网络/子进程有直接调用关系 | 脚本原文 |
| `rdd_ref` | 形如 `npm:<pkg>@<ver>#<resolved-url>` | `in_lockfile=false` 且 URL 不在 registry 白名单；同一 `rdd_ref` 在两次安装中可复现 | `reach.json` |
| `tarball_integrity` | `sha512-...` vs 实算 | 与 registry 元数据一致；不一致即为篡改或镜像替换 | `npm pack` 哈希 |
| `egress` | 目标域名/IP + 端口 | 至少 1 条外联在断网沙箱里被记录，且非 telemetry 白名单 | `trace.log` |
| `persistence` | 落地路径/计划任务/启动项 | 有具体路径与写入时间；仅“内存执行”不写持久化 | 文件系统 diff |
| `detection_gap` | `node-hook-only` / `none` | 若监控只 hook Node 而载荷走 Bun，必须显式标注 | 监控配置 + 进程树 |

判定 `confirmed` 需同时满足：`tarball_integrity` 一致（证明分析的就是发布件）、`install_hook` 可指认、
`egress` 或 `bun_payload` 至少一条有运行时证据。三者缺一，只能写 `candidate`。

## 失败判据

- 只有包名相似/作者同名，没有 tarball 哈希与脚本证据 → 判否（仿冒判定见 07 篇）。
- `resolved` 指向 registry，但 `integrity` 缺失 → 不能证明“被替换”，只能写“完整性不可核”。
- 沙箱里 `npm ci` 未执行脚本（`--ignore-scripts`），却声称“已复现投放” → 判否，重跑并说明开关。
- 外联目标是通用 CDN/telemetry，且无后续载荷 → 降级为“可疑外联”，不写 C2。
- `bun` 只出现在 README/关键词里，进程树无 `bun` → `bun_payload=none`。
- RDD 解析依赖私有 registry 凭据 → 记录 `blocked`，不猜 URL。
- 触发厂商风控/账号锁定、或需要生产 CI 凭据 → 立即停，改用离线副本。
- 分析过程中执行了未脱敏的恶意脚本并产生真实外联 → 证据污染 + 越界，作废。

> 边界：只做授权仓库/镜像的只读审计与断网沙箱复现；不投毒、不抢注、不探测第三方 registry；
> Bun 载荷的逆向只在副本上做，不运行未脱壳样本连网。

## 与 reference 的关系

- 锁文件与安装脚本：[05-lockfile-and-install-scripts.md](../../../../../../../Tool/skill/supply-chain-security/references/05-lockfile-and-install-scripts.md)。
- 可达性与 SBOM 漂移：[06-reachability-and-sbom-drift.md](../../../../../../../Tool/skill/supply-chain-security/references/06-reachability-and-sbom-drift.md)。
- 失败判据：[02-failure-criteria.md](../../../../../../../Tool/skill/supply-chain-security/references/02-failure-criteria.md)。
- 同 board 邻近篇：[07-typosquat-and-malicious-packages.md](07-typosquat-and-malicious-packages.md)（仿冒判定）、
  [05-lockfile-integrity.md](05-lockfile-integrity.md)（integrity/resolved 口径）、
  [06-reachability-failure-criteria.md](06-reachability-failure-criteria.md)（降级路线）。
