# 03-model-pitfalls · 供应链场景的模型常见失误

> 范围：用 LLM/助手辅助 SBOM、SCA、锁文件、依赖混淆、CI/CD、镜像签名分析时，对照检查输出里有没有“像结论的猜测”。
> 入口：纯工具语法/版本问题按工具安装页处理；本页只收模型判断失误。
> 每条格式：**错误动作 → 为什么错 → 正确动作**。看到自己在做左列，立即停并改右列。

### 1. 把 SCA 告警直接写成“存在高危漏洞”

**错误动作**：`osv-scanner`/`grype` 命中 `CVE-xxxx high`，报告标题写“项目存在高危漏洞，可 RCE”。

**为什么错**：SCA 只做版本范围匹配；传递依赖可能没打包、函数可能没被调用、测试依赖不进生产、发行版可能已 backport 修复。版本命中只是“可能受影响”。

**正确动作**：用 `sbom-reach.py` 从入口找 import/require 链，再查运行时依赖树与补丁 diff；有调用链或运行时加载才写 `confirmed`，否则写 `suspected` 并注明缺哪条证据。

### 2. 把镜像 tag 当对象标识

**错误动作**：报告写“审计了 `app:latest`”，`FROM node:20` 直接当基线，结论里不出现 digest。

**为什么错**：tag 可移动，同一 tag 今天和明天可能是不同镜像；没有 digest，SBOM、签名、attestation 都无法对应到具体制品。

**正确动作**：取 `RepoDigests` 或 `crane digest`，写 `repo@sha256:<64hex>`；基础镜像同样固定 digest；tag 只作可读别名。

### 3. 把 `pull_request_target` 关键字命中当成“已被利用”

**错误动作**：`grep pull_request_target` 命中就写“攻击者可窃取 secrets”，不看 checkout 和 permissions。

**为什么错**：`pull_request_target` 只在基仓库上下文运行；如果 workflow 不 checkout PR head、job 只有 `contents: read`、不引用 secrets，利用链不成立。

**正确动作**：按“触发器 → checkout ref → job permissions → secrets 作用域 → action pin”逐项核对；`ci-perm-audit.py` 会把 `checkout_refs`、`secrets_refs`、`permissions` 分字段列出，组合不成立就写“设计如此/误报”。

### 4. 把私有 scope 名当成“可被抢注”

**错误动作**：看到 `@corp/auth`、`internal-billing`，直接写“存在依赖混淆，可投毒”。

**为什么错**：私有 scope 是否可抢注取决于 registry 映射与锁文件 `resolved`；企业包可能本来就托管在公共 registry 的私有组织下，公共同名包可能已注册且受控。

**正确动作**：三方对账：manifest 的 scope/包名、`.npmrc`/`pip.conf`/`nuget.config` 的 registry 映射、锁文件的 `resolved`+`integrity`。缺 registry 实际解析结果时只写“配置缺失”，不写“可抢注”。

### 5. 锁文件存在就宣称“可复现构建”

**错误动作**：仓库有 `package-lock.json`，报告写“依赖可复现，构建可信”。

**为什么错**：锁文件可能缺 `integrity`、`resolved` 指向公共源、CI 用 `npm install` 而不是 `npm ci`、锁文件与 manifest 不同源；任何一条都破坏可复现性。

**正确动作**：核对锁文件条目完整性、registry 来源、CI 冻结安装命令、manifest/锁文件集合一致；四项齐全才写“可复现”，否则列缺口。

### 6. 把“能构建/能跑”当成“可信构建”

**错误动作**：CI 绿了、镜像能启动，就写“供应链可信、制品未被篡改”。

**为什么错**：构建成功只证明流水线跑通；没有签名验证、attestation subject 对照、builder 身份核对，无法证明制品来自该源码与该流水线。

**正确动作**：`cosign verify` 必须带 `--certificate-identity` 与 `--certificate-oidc-issuer`；attestation 的 subject digest 与部署 digest 对照；再看 Rekor 条目。缺一项就写“未验证来源”。

### 7. 只看签名退出码 0，不看签名者是谁

**错误动作**：`cosign verify` 返回 0，报告写“镜像已签名，可信”。

**为什么错**：任何人都能签任何镜像；不核对 identity/issuer，等于只证明“存在一个签名”。自签证书、fork 流水线、个人账号都能产生有效签名。

**正确动作**：固定预期 identity（workflow 路径/仓库）与 OIDC issuer；核对签名对象 digest；不匹配即降级为“签名存在但身份不符”。

### 8. 把 `npm install` 的输出当依赖清单

**错误动作**：用 `npm install` 后 `node_modules` 的目录名当 SBOM，或把 `npm ls` 的输出直接当全量传递依赖。

**为什么错**：`npm ls` 默认只显示已安装树，peer/optional 依赖可能缺失；`node_modules` 可能含 hoist/重复版本；锁文件才是解析结果的权威记录。

**正确动作**：以锁文件为权威，`npm ls --json --all` 只作交叉验证；组件集合与锁文件条目做差集，差异写进 `missing_from_sbom[]`。

### 9. 把 Python 包名当 import 名

**错误动作**：`pip freeze` 里有 `PyYAML==6.0`，就在源码里搜 `PyYAML`，搜不到便写“不可达”。

**为什么错**：发行名与 import 名经常不同（`PyYAML`→`yaml`、`beautifulsoup4`→`bs4`、`Pillow`→`PIL`）；大小写、连字符、下划线也不一致。

**正确动作**：维护发行名→import 名映射（脚本内置常见映射），再按 `import x`/`from x` 检索；仍搜不到时检查动态导入、entry points、插件加载，最后写“未观察到调用”而非“不可达”。

### 10. 只扫源码，不扫 CI 与构建脚本

**错误动作**：依赖清单干净就写“供应链无风险”，完全不看 `.github/workflows`、`Dockerfile`、`setup/*.ps1`。

**为什么错**：供应链攻击最常发生在构建期：不可信 PR 拿到写 token、action tag 被重写、`curl|sh` 下载二进制、secret 进入镜像层。源码干净不代表构建链干净。

**正确动作**：把 CI 权限/触发器、action pin、Dockerfile 的 FROM/USER/ARG、安装脚本下载面列为同等级输入面；用 `ci-perm-audit.py` 与 `sc-check.py` 分别覆盖。

### 11. 把 `write-all` 当成必然可利用

**错误动作**：看到 `permissions: write-all` 就写“可被提权改仓库”。

**为什么错**：权限大是加固问题，但利用还需要不可信输入进入同一 job、或有恶意 action/脚本；如果 workflow 只由 `workflow_dispatch` 触发且只跑可信分支，风险等级应下调。

**正确动作**：权限 + 触发器 + 输入面三者一起看；`write-all` 至少列 medium 加固项，只有不可信输入能到达该 job 时才升 high。

### 12. 把许可证扫描结果当法务结论

**错误动作**：`syft` 输出 `GPL-3.0`，报告写“项目违反许可证，必须开源”。

**为什么错**：许可证有双许可、例外条款、动态链接/分发方式差异；SBOM 的 `licenseConcluded` 可能是工具猜测；`NOASSERTION` 只是未知，不是冲突。

**正确动作**：只列组件、声明许可证、来源与分发方式；把“是否冲突”交给法务；未知许可证单列证据缺口。

### 13. 把“未联网”当成“已验证不可抢注”

**错误动作**：离线扫描后写“公共同名包不存在，无依赖混淆风险”。

**为什么错**：没联网就没有 registry 解析结果；“没查”不等于“不存在”。把未验证写成否定结论，是供应链报告里最常见的假阴性。

**正确动作**：离线只写“未验证公共解析”；联网验证需单独授权，命令与响应原文入证据；授权不足就保留为开放问题。

### 14. 用绝对路径/本机环境写复现步骤

**错误动作**：报告里写 `D:\Users\xxx\repo`、`/home/alice/...`，或依赖本机已装的 `syft`。

**为什么错**：换台机器就无法复现；泄露本机路径；外部工具缺失时步骤直接断掉。

**正确动作**：路径相对仓库根或用 `--root`/`--path` 传入；脚本先探测外部工具，缺失走降级分支并输出 `blocked_at: "tool-missing"`；复现步骤写清前置与替代路径。

### 15. 把扫描器零命中写成“无漏洞”

**错误动作**：`sc-check.py` 返回 0 条 high/critical，报告写“供应链安全，无风险”。

**为什么错**：零命中只代表当前规则集未覆盖；脚本明确标注 `degraded`/`missing_tools` 时，CVE、签名、registry 解析都没查。把“未发现”写成“不存在”是过度承诺。

**正确动作**：写“本次规则集未命中”，并列已覆盖/未覆盖输入面；把 `degraded[]` 原样带进报告；下一步列出需要外部工具或授权才能补的证据。

### 16. 把 `${{ }}` 当普通字符串（表达式注入）

**错误动作**：看到 `run: echo '${{ github.event.issue.title }}'` 里有单引号，就判断“已引号包裹，不会注入”。

**为什么错**：GitHub Actions 在交给 shell **之前**就展开 `${{ }}`；单引号只对展开后的字符串生效，攻击者可用 `'` 或 `$(...)` 逃逸。`if:`/`with:` 里不进入 shell 才相对安全。

**正确动作**：把不可信字段先落到 `env:`（如 `TITLE: ${{ github.event.issue.title }}`），脚本里用 `"$TITLE"` 引用并加白名单/长度校验；报告写清“表达式是否进入 shell”，并给出 `expression-injection` 的原始行号。

### 17. 把 `npm audit` 的 fix 建议当“安全升级”

**错误动作**：`npm audit fix` 后构建过了，报告写“漏洞已修复”。

**为什么错**：升级可能改变 API/行为、引入新的传递依赖，或只是把版本推到 advisory 范围外但未真正打补丁；构建过不等于业务不受影响。

**正确动作**：看锁文件 diff + 依赖树变化 + 测试结果；能定位到具体 advisory/commit 才写“已修复”，否则写“已升级，行为未验证”。

### 18. 把 `resolved` 有 URL 当“来源可信”

**错误动作**：锁文件每个条目都有 `resolved`，就写“依赖来源可追”。

**为什么错**：`resolved` 可能指向公网 tarball、`git+http`、未受控镜像；有 URL 只说明“能下载”，不说明“来源受控”。

**正确动作**：对 `resolved` 的 host 与 `.npmrc`/`pip.conf` 的 registry 做集合比对；缺 `integrity` 的条目单独列出。

### 19. 把 SBOM 的组件数当“覆盖完整”

**错误动作**：`components_total=800` 就写“SBOM 已覆盖全部依赖”。

**为什么错**：数量大可能包含 OS 包/重复组件，同时漏掉私有包/optional/peer；数量与覆盖是两件事。

**正确动作**：做“锁定集合 ⊆ 清单集合”的对账；`missing_from_sbom` 为空或逐条解释；按 purl 去重。

### 20. 把 `ghcr.io` 的 public 包当“官方”

**错误动作**：镜像在 `ghcr.io/<org>/...` 且 public，就写“官方镜像，可信”。

**为什么错**：任何账号都能建 org/仓库；public 只说明可拉取，不说明发布者身份。

**正确动作**：看 digest + 签名 identity/issuer + 仓库 owner 的发布记录；三者对齐才能写“官方”。

### 21. 把 `permissions: {}` 当“绝对安全”

**错误动作**：顶层 `permissions: {}`，就写“token 无权限”。

**为什么错**：job 级可以重新授予 `contents: write`；reusable workflow 也可能带入权限。

**正确动作**：顶层 + job 级合并看；再对触发器/checkout/secrets 三面；`write` 能被不可信输入触达才是高危。

### 22. 把依赖的 `postinstall` 当“普通构建步骤”

**错误动作**：`postinstall: node-gyp rebuild` 一律当正常，不核对下载源。

**为什么错**：原生包确实需要编译，但也可能在编译前下载预编译二进制/脚本并执行；`node-gyp` 本身也会拉取 headers。

**正确动作**：看脚本原文 + 下载 URL/域名 + hash 校验 + 是否读环境变量；正常则写“可接受”，异常则列执行面。

### 23. 把 `GOPRIVATE` 设置当“依赖混淆已解决”

**错误动作**：`go env GOPRIVATE=corp.example.com/*` 就写“私有模块不会走公共 proxy”。

**为什么错**：`GOPRIVATE` 只影响 proxy/sumdb 行为；如果模块路径本身可被公开解析，或 `GOFLAGS`/CI 环境覆盖，仍有风险。

**正确动作**：核对 `GOPROXY`/`GONOSUMDB`/`GONOSUMCHECK` + CI 环境变量 + `go.sum` 来源；四者一致才算锁定。

### 24. 把签名时间当“构建时间”

**错误动作**：`cosign` 输出签名时间，就写“镜像今天构建”。

**为什么错**：签名可以在构建后任意时间做；构建时间在 attestation 的 `metadata.buildStartedOn/FinishedOn` 或 CI run 记录里。

**正确动作**：构建时间看 provenance/CI；签名时间只证明“何时签”；两者都写，不混用。

### 25. 把 `latest` 的 digest 当“稳定基线”

**错误动作**：记录了 `latest` 当前 digest，就写“基线已固定”。

**为什么错**：digest 固定的是“这一刻的内容”；`latest` 明天会指向新 digest，基线的“可复现”只对旧 digest 成立。

**正确动作**：写 `repo@sha256:...`，并把 tag→digest 的映射与时间入档；比较时只用 digest。

## 25 条速查（提交前扫一眼）

| # | 一句话 | 正确动作 |
| :-: | --- | --- |
| 1 | SCA 告警 ≠ 漏洞 | 可达/运行时 |
| 2 | tag ≠ 对象 | digest |
| 3 | 触发器命中 ≠ 利用 | checkout/permissions/secrets |
| 4 | scope 名 ≠ 可抢注 | registry 解析 |
| 5 | 有锁文件 ≠ 可复现 | integrity/registry/冻结安装 |
| 6 | 能构建 ≠ 可信 | 签名 + provenance |
| 7 | 签名 rc=0 ≠ 身份对 | identity/issuer |
| 8 | `npm ls` ≠ 全量清单 | 锁文件为权威 |
| 9 | 发行名 ≠ import 名 | 映射表 |
| 10 | 只扫源码会漏 CI | workflow/Dockerfile |
| 11 | `write-all` ≠ 可利用 | 输入面组合 |
| 12 | 许可证 ≠ 法务结论 | 只列证据 |
| 13 | 未联网 ≠ 不存在 | 标未验证 |
| 14 | 绝对路径不可复现 | 相对/`--root` |
| 15 | 零命中 ≠ 无风险 | 列覆盖/缺口 |
| 16 | `${{ }}` 在 shell 前展开 | `env:` + 引用 |
| 17 | `audit fix` ≠ 已修复 | diff + 测试 |
| 18 | `resolved` ≠ 受控源 | host 对账 |
| 19 | 组件数 ≠ 覆盖 | 集合对账 |
| 20 | public ≠ 官方 | digest + 身份 |
| 21 | 顶层空 ≠ 无权限 | 合并 job 级 |
| 22 | `postinstall` 要读原文 | URL/哈希/环境变量 |
| 23 | `GOPRIVATE` ≠ 全锁 | 四变量 + CI |
| 24 | 签名时间 ≠ 构建时间 | provenance |
| 25 | `latest` digest ≠ 稳定基线 | 记录映射 |

## 纠偏命令：把“像结论”压成字段

```bash
# 1) 锁文件来源与完整性
jq -r '.packages | to_entries[] | select(.value.resolved) | [.key,.value.resolved,(.value.integrity!=null)] | @tsv' \
  package-lock.json 2>/dev/null | head -20

# 2) SBOM 与锁定集合对账
python Tool/skill/supply-chain-security/scripts/sbom-reach.py \
  --sbom bom.cdx.json --lock package-lock.json --source src --out reach.json
jq '{components: .components_total, missing: (.missing_from_sbom|length)}' reach.json

# 3) CI 权限面（顶层+job）
python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py --path .github/workflows --out ci.json
jq '.workflows[] | {name, permissions, triggers, action_pins}' ci.json

# 4) 签名身份
cosign verify "$IMAGE"@"$DIGEST" \
  --certificate-identity-regexp '^https://github\.com/<org>/<repo>/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com 2>&1 | head
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| resolved | host 与受控 registry 一致 + integrity | 公网 tarball/无 integrity |
| SBOM | `missing` 为 0 或逐条解释 | 大段缺失 |
| CI | permissions 与 triggers 均可读 | `workflows_total=0` |
| 签名 | identity/issuer 匹配 + digest 一致 | rc=0 但未对身份 |
| 结论 | 每条能指回上面一条命令 | 只有“经验上” |

## 这一篇算"用对了"吗

- [ ] 我没有把扫描器告警/关键字命中直接写成可利用
- [ ] 我的对象标识是 commit/digest/锁文件哈希，不是 tag/分支名
- [ ] 我对“来源/签名/可达”都核对了身份或调用链，不只看 rc=0
- [ ] 我把未联网/缺工具的面写成了未验证，没有写成“不存在”
- [ ] 我的修复建议有 diff/测试/回滚，不是“升级到最新”
- [ ] 我删掉了所有“应该/可能/大概”而没有证据的句子
