# 05 · 锁文件完整性与安装脚本执行面

> 适用：npm/Python/Go/Rust/Ruby/PHP/.NET 仓库要判断“下一次安装会装到什么、安装期会执行什么”。
> 不适用：只读消费已构建镜像（那属于 `image-and-provenance.md`）；也不覆盖运行时动态加载。
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
evidence/<case>/
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
