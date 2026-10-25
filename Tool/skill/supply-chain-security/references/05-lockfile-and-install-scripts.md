# 05 · 锁文件完整性与安装脚本执行面

> 范围：npm/Python/Go/Rust/Ruby/PHP/.NET 仓库要判断“下一次安装会装到什么、安装期会执行什么”。
> 路由：只读消费已构建镜像由 `image-and-provenance.md` 承担；运行时动态加载由 `06-reachability-and-sbom-drift.md` 承担。
> 目标：把“有锁文件”推进到“锁文件与清单同源、条目有 integrity、resolved 受控、安装脚本可解释”。

## 1. 锁文件不是布尔值

一个锁文件只有同时满足下面四项，才算“可复现依赖”：

| 项 | 检查 | 失败后果 |
| :-- | :-- | :-- |
| 同源 | 锁文件与 manifest 在同一目录/同一 workspace；直接依赖集合一致 | 安装结果与声明不符，评审看的是旧清单 |
| 完整性 | 每个条目有 `integrity`/`checksum`/`h1:` | 包内容可被中间人替换而不报错 |
| 来源 | `resolved` 指向受控 registry；无不明 `git+http`/`file:` | 依赖混淆/抢注的入口 |
| 冻结安装 | CI 用 `npm ci`/`--frozen-lockfile`/`-mod=readonly`/`--locked` | 锁文件被忽略，每次解析最新版 |

`sc-check.py` 会把 `inventory.locks[]`、`category=lockfile/lock-integrity/registry-integrity` 写进 JSON；
`sbom-reach.py --lock` 则把锁文件条目转成组件清单，供与 SBOM 对账。

## 2. 各生态最小检查命令

```bash
# npm
npm ci --ignore-scripts --dry-run 2>&1 | tail -20
npm ls --all --json > /tmp/npm-ls.json
jq -r '.packages | to_entries[] | select(.value.integrity|not) | .key' package-lock.json | head

# Python
pip install --dry-run --require-hashes -r requirements.txt 2>&1 | tail -20
pip freeze > /tmp/freeze.txt
grep -nE '^(--extra-index-url|--index-url|--trusted-host)' requirements.txt

# Go / Rust
go mod verify
go list -m all | head
cargo tree --locked | head
cargo metadata --locked --format-version 1 > /tmp/cargo.json

# Ruby / PHP / .NET
bundle check
composer validate --strict
dotnet list package --include-transitive
```

判据：命令 rc=0 只代表“当前机器能解析”，不代表来源可信；必须再看 `resolved`/`integrity`/registry 配置。

## 3. 安装脚本执行面

npm 的 `preinstall`/`install`/`postinstall`/`prepare`，Python 的 `setup.py`，Ruby 的扩展编译，都是**安装即执行**。

```bash
jq -r '.scripts // {} | to_entries[] | "\(.key): \(.value)"' package.json
grep -RInE '"(pre|post)?install"|"prepare"' package.json packages/*/package.json 2>/dev/null
grep -RInE 'curl|wget|Invoke-WebRequest|base64|eval|child_process|execSync' \
  package.json scripts 2>/dev/null | head -30
```

分级口径：

| 形态 | 判定 | 处理 |
| :-- | :-- | :-- |
| `node-gyp rebuild`、`prebuild-install` 下载官方预编译包 | 常见原生包行为 | 核对 URL 域名、版本固定、是否有 hash |
| `curl … \| sh`、`powershell -enc`、base64+eval | 高风险执行面 | 阻断安装，要求改包或 vendor 化 |
| `postinstall` 里读 `process.env` 并发网络请求 | 可能外带 CI 凭据 | 单独列凭据事件，查环境变量作用域 |
| `prepare` 只在本地 git 安装时跑 | 开发辅助 | 生产安装加 `--ignore-scripts` 时确认无副作用 |

`--ignore-scripts` 是缓解不是根治：有些包缺了安装脚本就无法运行，必须先证明业务不需要。

## 4. registry 与依赖混淆的交叉点

```bash
npm config get registry
npm config get @corp:registry
pip config list
cat .npmrc 2>/dev/null
cat nuget.config 2>/dev/null
```

判据：

- 私有 scope 有 `@scope:registry=`，且锁文件 `resolved` 的 host 与它一致。
- Python 内部包只出现在私有 index，`requirements.txt` 无 `--extra-index-url` 回退。
- NuGet 有 `packageSourceMapping`，私有前缀只映射私有 feed，公共源不能兜底。
- 锁文件里同一包出现两个来源（公私各一）→ 直接列高风险，人工核对解析顺序。

失败判据：只看到 scope 名或 `internal-` 前缀，就写“可被抢注”。没有 registry 解析结果时，只能写“配置缺失/未锁定”。

## 5. 证据形态

```text
work/<case>/
  locks.sha256          # 所有锁文件的 sha256
  manifest-diff.txt     # manifest 直接依赖 vs 锁文件条目
  integrity-missing.txt # 缺 integrity 的条目
  scripts.txt           # 安装脚本原文
  registry.txt          # npm/pip/nuget 配置
  sc.json               # sc-check.py 输出
  sbom-reach.json       # 锁文件 → 组件 → 源码可达
```

每条风险必须带文件与行号；锁文件条目带包名+版本+resolved host。不要只贴“有 9 个 medium”。

## 6. 失败判据

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| 锁文件存在但 `integrity` 缺失过半 | 完整性链断裂 | 重新生成锁文件；CI 改冻结安装；核对 registry | 中：需改仓库与 CI |
| manifest 与锁文件直接依赖集合不一致 | 锁文件过期/不同源 | 以 manifest 为准重生成；检查 monorepo 根锁覆盖 | 低：一次重装 |
| `resolved` host 与 `.npmrc` registry 不一致 | 来源漂移，可能混淆 | 锁定 registry 后重生成；核对 CI 环境变量 | 中：需要私有源凭据 |
| 安装脚本下载二进制但无 hash | 执行面不可验证 | 要求固定版本+校验和，或 vendor 化 | 中：可能改依赖 |
| `--ignore-scripts` 后业务起不来 | 脚本是功能依赖 | 逐条审脚本内容；不能审就换包 | 高：可能替换核心依赖 |
| 私有 scope 未映射但无法联网验证 | 配置缺失，未验证解析 | 只写“未锁定”，联网验证另开授权 | 低：结论降级 |

## 7. 边界

- 不在生产机直接跑 `npm install` 验证；用 `--dry-run`、隔离容器或只读解析。
- 不发布测试包、不抢注包名、不改他人 registry。
- 锁文件解析不等于 CVE 扫描；可达性见 `06-reachability-and-sbom-drift.md`。
- 许可证结论不在此文；只记录组件来源与声明。

## 8. 六生态锁文件字段对照（字段级判据）

| 生态 | 锁文件 | 完整性字段 | 来源字段 | 冻结安装 |
| --- | --- | --- | --- | --- |
| npm | `package-lock.json` | `integrity`（sha512） | `resolved` | `npm ci` |
| yarn | `yarn.lock` | `integrity`/`checksum` | `resolved` | `--frozen-lockfile` |
| pnpm | `pnpm-lock.yaml` | `integrity` | `resolution.tarball` | `--frozen-lockfile` |
| pip | `requirements.txt`/`poetry.lock` | `--hash=sha256:` | `--index-url` | `--require-hashes` |
| Go | `go.sum` | `h1:` | module path | `-mod=readonly` |
| Cargo | `Cargo.lock` | `checksum` | `registry+https://` | `--locked` |
| Ruby | `Gemfile.lock` | `CHECKSUMS` | `remote:` | `--deployment` |
| NuGet | `packages.lock.json` | `contentHash` | `packageSourceMapping` | `--locked-mode` |

**通用判据**：每个条目至少有一个不可变校验（hash/checksum/contentHash）；来源 host 与配置一致；CI 用冻结命令。
缺一项就写“可复现性缺口”，不能写“依赖可复现”。

### 8.1 monorepo 的额外坑

- 根锁文件可能覆盖子包，但子包自己也有 manifest；先确认实际安装的是哪一份。
- `workspace:`/`file:`/`link:` 是本地协议，不算远程来源漂移；但必须确认发布时被打包成什么。
- 多个 lockfile 共存（npm + pnpm + yarn）→ 先确认 CI 用哪个，其余标“未使用/历史遗留”。

## 9. 安装脚本投毒的识别判据

> 安装脚本是“供应链攻击最短路径”：不需要业务代码 import，只要装包就执行。

### 9.1 行为面（看它做什么，不只看关键字）

| 行为 | 可疑信号 | 判据 |
| --- | --- | --- |
| 下载并执行 | `curl \| sh`、`wget -O- \| bash`、`iwr \| iex` | 原文 + URL + 行号 |
| 编码执行 | `base64 -d \| sh`、`eval(Buffer.from(...))` | 解码后是否仍是命令 |
| 读凭据 | `~/.npmrc`、`process.env.GITHUB_TOKEN`、`~/.aws` | 读取路径 + 后续网络 |
| 外带 | `fetch`/`https.request`/`net.` 到外部 host | host + 数据来源 |
| 持久化 | 写 `.github/workflows`、`.mcp.json`、shell rc | 写入路径 + 内容 |
| 自复制 | 改自身包/发版 | token + registry 操作 |

### 9.2 静态扫描命令

```bash
# 1) 列出所有安装钩子
jq -r '.scripts // {} | to_entries[] | select(.key|test("pre|post|prepare")) | "\(.key): \(.value)"' package.json

# 2) 钩子里的危险动作
grep -RInE 'curl|wget|Invoke-WebRequest|base64|eval|child_process|execSync|https?\.request|fetch\(' \
  package.json scripts 2>/dev/null | head -40

# 3) 读凭据/写配置
grep -RInE '\.npmrc|\.aws|GITHUB_TOKEN|ACTIONS_RUNTIME_TOKEN|\.mcp\.json|\.cursor' \
  package.json scripts 2>/dev/null | head -20

# 4) 包内高熵单行（bun 载荷常见）
find node_modules -name '*.js' -size +20k 2>/dev/null | while read -r f; do
  awk 'length($0)>20000{print FILENAME, length($0)}' "$f"
done | head
```

### 9.3 分级与处置

| 级别 | 判据 | 处置 |
| --- | --- | --- |
| 高 | 下载+执行，或读凭据+外带，有原文/行号 | 阻断安装；隔离包；轮换凭据 |
| 中 | 下载二进制但无 hash，或读环境变量但无外带 | 要求固定版本+hash；沙箱构建 |
| 低 | 原生编译/`prepare`，源可信 | 记录，`--ignore-scripts` 评估 |
| 误报 | 帮助文本/示例/注释 | 排除并写原因 |

## 10. 命令与“通过长什么样”（锁文件复验）

```bash
# 1) 锁文件与 manifest 同源
jq -r '.packages[""].dependencies // {} | keys[]' package-lock.json 2>/dev/null | sort > /tmp/lock-deps
jq -r '.dependencies // {} | keys[]' package.json 2>/dev/null | sort > /tmp/man-deps
diff /tmp/lock-deps /tmp/man-deps | head

# 2) integrity 缺失
jq -r '.packages | to_entries[] | select(.value.integrity|not) | .key' package-lock.json | head

# 3) 来源 host
jq -r '.packages | to_entries[] | select(.value.resolved) | .value.resolved' package-lock.json \
  | sed -E 's#https?://([^/]+)/.*#\1#' | sort | uniq -c

# 4) 冻结安装是否被 CI 使用
grep -RInE 'npm (ci|install)|--frozen-lockfile|--require-hashes|-mod=readonly|--locked' .github/workflows 2>/dev/null
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| 同源 | diff 为空 | 有缺失/多余 |
| 完整性 | 缺失条目为 0 | 过半缺失 |
| 来源 | host 只有受控 registry | 公网 tarball 混入 |
| 冻结 | CI 用 `ci/frozen/locked` | 用 `install` |
| 脚本 | 每条能解释必要性 | `curl\|sh` 未处理 |

## 11. yarn/pnpm 的“构建白名单”

| 包管理器 | 字段 | 含义 | 判据 |
| --- | --- | --- | --- |
| yarn 2+/4 | `dependenciesMeta.*.built` | 只允许列出的包跑构建脚本 | 未列出的包不应有 `postinstall` 行为 |
| pnpm | `onlyBuiltDependencies`/`pnpm.onlyBuiltDependencies` | 同上 | 白名单外无构建 |
| npm | 无等价白名单 | `--ignore-scripts` 全禁 | 需评估业务是否依赖 |

**检查**：`grep -RInE 'onlyBuiltDependencies|built:|dependenciesMeta' package.json pnpm-workspace.yaml .yarnrc.yml`。
**判据**：白名单外若有下载/执行行为，按“未受控执行面”处理；白名单内也要看 URL/hash。

### 11.1 锁文件里的“生命周期脚本”证据

- npm 锁文件不存脚本原文，只存包元数据；脚本要看 `node_modules/<pkg>/package.json` 或 tarball。
- pnpm/yarn 可能在 lock 里存 `hasBin`/`requiresBuild`；`requiresBuild=true` 就是“安装期会跑”。
- CI 日志里出现 `node-gyp`/`prebuild-install`/`bun` 是行为线索，不是结论；要回到包原文。

## 12. 一条底线

锁文件的价值不在“存在”，而在“下一次安装会装到同一字节”。
只要 `integrity`、受控来源、冻结安装三者缺一，就只能写“依赖可解析”，不能写“可复现”。
另外，`lockfileVersion` 1/2/3 的字段布局不同；跨版本比较前先确认字段名，避免把“没有该字段”误判成“缺 integrity”。

## 13. 最后一条检查

把锁文件、`.npmrc`、CI 安装命令三样并排放在一起；如果三者对不上，先修配置，再谈依赖安全。

## 这一篇算"用对了"吗

- [ ] 我核对了锁文件与 manifest 的直接依赖集合，不只看文件存在
- [ ] 我确认了每个条目有 integrity/checksum，且来源 host 受控
- [ ] 我确认 CI 使用冻结安装，而不是 `npm install`/无 hash 安装
- [ ] 我逐个读了安装钩子，能区分“原生编译”与“下载执行”
- [ ] 我没把 `--ignore-scripts` 当根治，评估了业务是否依赖脚本
- [ ] monorepo/多锁文件场景我写清了实际生效的是哪一份
