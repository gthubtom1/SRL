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
