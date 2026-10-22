# dependency-confusion · 依赖混淆与抢注

> 配套 `supply-chain-security/SKILL.md`。只审计自有/授权仓库；**不发布、不抢占、不向公共 registry 上传任何测试包**。
> 一句话原理：包管理器按“名字”解析，而不是按“来源”解析；私有包名一旦在公共 registry 可被同名注册，构建就可能装到攻击者的包。
>
> **范围**：仓库含私有 scope/内部包名，需要判断“下一次安装会不会解析到公共同名包”。
> 范围：registry 探测、抢注/发布验证按 `scope` 清单执行；内部命名空间枚举限于授权范围。

## 0. 先画依赖来源图

对每个生态记录三件事：

1. 清单里的包名（包括 scope/namespace）。
2. 解析器实际使用的 registry / index / feed（`.npmrc`、`pip.conf`、`nuget.config`、`composer.json`、`GOPRIVATE`）。
3. 锁文件里每个包的 `resolved` 与 `integrity`。

```bash
# 只读盘点，不安装
find . -maxdepth 3 \( -name package.json -o -name .npmrc -o -name requirements.txt \
  -o -name pyproject.toml -o -name pip.conf -o -name nuget.config \
  -o -name composer.json -o -name go.mod \) -not -path '*/node_modules/*'
python Tool/scripts/sc-check.py --path . --out sc.json
```

**判据**：每个私有包名都能追到“私有 registry + 锁文件条目 + integrity”；三者缺一，就是候选风险。

## 1. npm / yarn / pnpm

### 1.1 风险形态

- 私有 scope（如 `@corp/*`）没有 `@corp:registry=` 映射，默认落到 `registry.npmjs.org`。
- `.npmrc` 写了公共 registry，或多个 registry 顺序不确定。
- 锁文件缺失/integrity 缺失，安装时重新解析。
- 依赖声明使用 `^`/`*`/`latest`，同名包可随时替换内容。

```bash
# 看本仓库实际配置（只读）
cat .npmrc 2>/dev/null
npm config get registry
npm config get @corp:registry

# 锁文件里私有 scope 解析到了哪里（只读）
python - <<'PY'
import json
d=json.load(open('package-lock.json'))
for k,v in (d.get('packages') or {}).items():
    if k.startswith('node_modules/@corp/'):
        print(k, v.get('resolved'), 'integrity=' + str(bool(v.get('integrity'))))
PY
```

**确认条件**：私有 scope 在锁文件中的 `resolved` 指向公共 registry（或没有 `resolved`/`integrity`），且 `.npmrc` 没有该 scope 的私有 registry 映射。
**失败判据**：scope 本来就是公开包；公司使用公共 registry 的私有 scope（付费私有包）；有完整锁文件且 `resolved` 指向内部镜像。

### 1.2 只读探测（需授权联网）

```bash
# 仅确认“同名公共包是否存在”，不要下载、不要发布
npm view @corp/pkg name version dist-tags 2>/dev/null
curl -sS -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/@corp%2fpkg
```

**判据**：公共 registry 返回 200 且该包不属于本公司 → 抢注面存在；再结合 `.npmrc` 判断是否会被解析到。
**失败判据**：返回 404（名字未被注册，仍是“未来可被抢注”，要按“未锁定 registry”处理）；或网络被代理挡住。

## 2. Python / pip

### 2.1 风险形态

- `requirements.txt` 里出现 `corp-*`/`internal-*` 等内部名，但没有 `--index-url`/`--extra-index-url`。
- `pip.conf` 未固定 `index-url`，或同时配置公共 PyPI 在前。
- 包名未固定版本、没有 hash，安装时从公共源解析。
- `pyproject.toml` 只写范围，没有锁文件。

```bash
python -m pip config list
cat /etc/pip.conf ~/.config/pip/pip.conf ~/.pip/pip.conf 2>/dev/null
grep -RInE '^(corp|internal|company|private)[-_]' requirements*.txt pyproject.toml 2>/dev/null
```

**确认条件**：内部风格包名 + 无私有 index 配置 + 无锁/hash，三者同时成立；再用 `pip download --no-deps -d /tmp/x <pkg>` 在隔离环境确认解析来源（需授权）。
**失败判据**：包名只是普通开源名（如 `internal` 是某公开库）；有 `--index-url` 指向内部源；有完整 hash 锁。

### 2.2 pip 的“依赖混淆”变体

- 同名包在 PyPI 与私有源都存在，pip 按 index 顺序取第一个。
- `--extra-index-url` 同时列公共与私有源时，pip 会合并候选，可能选版本号更高的公共包。
- 修复：只用一个受控 index，或使用 `--index-url` + `--no-index` 的离线 wheel 仓。

## 3. NuGet / Maven / Composer / Go

| 生态 | 风险点 | 只读检查 |
|---|---|---|
| NuGet | `nuget.config` 同时有 nuget.org 与私有 feed；包名 `Company.*` | `dotnet nuget list source`；检查 `packageSources` 与 `packageSourceMapping` |
| Maven | 私有 groupId 未在 `settings.xml` 镜像/仓库锁定；`SNAPSHOT` 可被覆盖 | `mvn help:effective-settings`；检查 `repositories` 顺序 |
| Composer | `composer.json` 的 `repositories` 含 packagist + 私有源；`minimum-stability: dev` | `composer config -l`；检查 `composer.lock` 的 `dist.url` |
| Go | 私有模块路径未设 `GOPRIVATE`/`GONOSUMDB`，走公共 proxy | `go env GOPRIVATE GONOSUMDB GOPROXY`；检查 `go.sum` |

**判据**：私有命名空间有显式 source mapping；锁文件记录来源与校验和；公共源不能回退解析私有名。

## 4. 攻击面排序（写报告用）

1. **可直接利用**：私有 scope 无 registry 映射 + 公共同名包已存在 + 锁文件缺失 → 下一次安装即可执行攻击者代码。
2. **条件利用**：有锁文件但 integrity 缺失；或 CI 使用 `npm install` 而非 `npm ci`。
3. **潜在**：私有名尚未被注册；攻击者可等待/抢注。
4. **仅基线问题**：宽版本范围、无锁文件，但 registry 已锁定且包名公开。

## 5. 修复清单（最小可执行）

- npm：`@corp:registry=https://npm.corp.example/`；提交锁文件；CI 用 `npm ci`；开启 `npm audit signatures`（如可用）。
- pip：`index-url=https://pypi.corp.example/simple`；禁用 `extra-index-url` 公共源；使用 `--require-hashes`。
- NuGet：`packageSourceMapping` 把 `Company.*` 只映射到私有 feed。
- Maven：`settings.xml` 镜像 `*` 到内部 Nexus/Artifactory；SNAPSHOT 只留开发仓，生产走 release 版本。
- Go：`GOPRIVATE=corp.example.com/*`；`GONOSUMDB` 同步；`GOPROXY` 指向内部 proxy。
- 通用：锁文件 + integrity/hash + CI 冻结安装 + 依赖更新走 PR 审核。

## 6. 失败判据（必须撤稿 / 降级）

- 只看到私有风格包名，没有检查 registry 配置与实际解析结果。
- 只看到公共同名包存在，没有证明构建会解析到它。
- 把“未注册”写成“已被抢注”；把“宽版本”写成“已投毒”。
- 用公共 registry 的搜索结果替代锁文件/CI 证据。
- 为了验证而发布测试包、抢占名字、修改生产 registry。
- 扫描/探测越出授权仓库或 registry 账户。

## 7. 边界

- 抢注/发布/上传只在授权私有 registry 内、按 `scope` 清单执行。
- 不查询与授权范围无关的私有包名；不枚举公司内部 namespace。
- 依赖混淆只是供应链风险的一类；CVE 可达性、CI 权限、镜像签名分别见同目录其他文档。
- 离线基线由 `scripts/sc-check.py` 覆盖；联网确认必须单独获得授权并记录时间、源、响应码。

## 8. 2026 npm 蠕虫检测（ChainDrop / Mini Shai-Hulud / SANDWORM_MODE）

> 出处：MSRC + Unit42 2026-08-04（ChainDrop / Mini Shai-Hulud）、Socket 2026-02-20（SANDWORM_MODE）、Elastic 2026-08-06（Bun 载荷与落地分析）。
> 判据全部离线静态；不安装、不执行 `postinstall`、不联网验证。

### 8.1 ChainDrop / Mini Shai-Hulud（2026-08，400+ 包）

- 规模：维护者 token 被盗后批量发版，一次污染 400+ npm 包，含 `keyv`、`cacheable-request` 及其传递依赖。
- 载荷：Bun 打包的混淆 JS，靠 `preinstall`/`postinstall` 钩子自动执行，不需要业务代码 import。
- 行为：扫描 `~/.npmrc`、进程环境、GitHub token 与云凭据（AWS/GCP/Azure），再用 GitHub Actions 外带与自复制——向受害者仓库或自身写 workflow、用窃取 token 继续发版。
- 落地痕迹：`bun run` 进程、临时目录里的高熵 `.js`、CI 日志里异常的 `bun install`/`bun run`。
- 只读证据：manifest 钩子行、包内高熵 JS 的路径与熵值、CI 日志片段。

### 8.2 SANDWORM_MODE（2026-02，19 包）

- 规模：19 个仿冒包，蹭 `claude`/`mcp`/`openai` 生态工具名（typosquat）。
- 手法一：劫持 CI workflow——改写 `.github/workflows/*.yml`，插入读取 token 的步骤并把 CI 凭据带走。
- 手法二：投毒 AI 工具链配置——写入 `.mcp.json`、`.cursor/mcp.json`、agent 配置文件，让 MCP server/agent 在开发者本机执行命令。
- 目标：CI token 与本地 AI 助手上下文，横向到私有仓库与云账号。

### 8.3 检测判据（可机检字段）

| 字段 | 判据 | 落点 |
| :-- | :-- | :-- |
| `postinstall_net` | `scripts.preinstall/postinstall` 含 `curl`/`wget`/`node -e`/`bun`/`child_process`/`net.`/`http` | manifest 行号 + 原命令 |
| `bun_payload` | 安装期命令调 `bun`/`bunx`，或包内出现单行高熵（≥4.5 bit/char）且 >20KB 的 JS | 文件 + 行号 + 熵值 |
| `rdd_ref` | 依赖值匹配 `^(file:\|link:\|https?://\|git\+)`，或版本 `*` 且锁文件 `resolved` 是远程 tarball | 依赖名 + 版本串 + `resolved` |
| `ci_token_scan` | 安装脚本/包源码读取 `GITHUB_TOKEN`、`ACTIONS_RUNTIME_TOKEN`、`~/.npmrc`、`~/.aws` | 文件 + 行号 |
| `ai_toolchain_hit` | 仓库或包内出现 `.mcp.json`、`.cursor/mcp.json`、agent 配置且被安装脚本写入 | 文件 + 写入行 |
| `action_tag_mutable` | workflow `uses: owner/repo@vN` 不是 40 位 commit SHA | workflow + 行号 |

**升级为确认**：`postinstall_net` 与 `bun_payload` 或 `ci_token_scan` 同时命中，且能指出可外带的凭据路径与出网目标。
**失败/降级**：只有宽版本或 `*`（未证明远程 tarball）；只有 tag 未 pin（无写权限/secrets 路径）；只有 AI 配置存在但无写入行为。

### 8.4 只读排查顺序

```bash
python Tool/scripts/sc-check.py --path . --out sc.json   # SC-101/102/103
grep -RInE '"(pre|post)install"' --include=package.json . | grep -v node_modules
grep -n '"resolved": *"https\?://' package-lock.json | head
git log --oneline -5 -- package.json package-lock.json    # 版本突变更像蠕虫发版
```

- 先看 `rule_hits`，再核对锁文件 `resolved`/`integrity`，最后才人工打开高熵 JS；`bun_payload` 需要熵值与体积两个数一起报。
- 发现真实凭据 → 只留指纹（sha256 前 12 位）并按轮换流程处理，报告里不写全量 token。
- 边界：不运行安装脚本、不向 registry 上传任何内容；本域只做只读取证与最小修复建议（pin 版本、`npm ci --ignore-scripts`、私有 registry 代理）。
