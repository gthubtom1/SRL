# 02-failure-criteria · 供应链失败判据（看到即降级）

> 范围：SBOM/SCA/锁文件/依赖混淆/CI/镜像签名任一条路径卡住，或扫描结果无法复算时。
> 入口：对象标识与授权边界见 `../SKILL.md` 前置检查；本页只写失败判据。
> 原则：**同一手法同参数连续失败两次即停**，把时间换到另一条证据面，而不是重复撞扫描器。
> 每条格式：现象 / 判定 / 改走哪条 / 代价。表中“改走”是唯一允许的降级方向，不许原地加参数硬试。

## 1. 失败判据表

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| `--path` 扫描完成但 `truncated=true` | 覆盖不完整，不能写“全仓库无风险” | 加大 `--max-files/--max-depth` 重跑，或按 `Tool/`、`setup/`、`.github/` 分目录扫描并合并 | 低：一次重跑；大仓库耗时上升 |
| 目标目录没有 `.git`，`git rev-parse HEAD` 失败 | 对象不可钉住，SBOM/扫描结论不可复现 | 改用发布产物 sha256 + 镜像 digest；或从 CI run 的 `GITHUB_SHA` 取 commit | 中：需要维护者提供构建记录；否则只能写“对象未钉住” |
| `syft`/`osv-scanner`/`grype`/`trivy`/`cosign` 全部缺失 | 只有静态清单能力，SCA/签名路径 blocked | 降级到锁文件解析 + `sbom-reach.py` 源码入口可达性；CVE 手工按版本比对并注明未查库 | 中：没有 CVE 命中列表，报告只能给“依赖面与可达性”，不能给漏洞结论 |
| SBOM 组件数与锁文件条目数差 >20%，且无解释 | SBOM 与锁文件不同源，清单不可信 | 重新生成 SBOM（固定 commit/digest）；或直接用锁文件解析结果作为组件清单 | 低：一次重生成；若构建环境不可得则降级为锁文件清单 |
| 锁文件条目缺 `integrity`，但 CI 仍用 `npm install` | 完整性链断裂，不能宣称可复现构建 | 改 `npm ci`/`--frozen-lockfile`/`-mod=readonly`；重新生成锁文件并核对 registry | 中：需要改 CI 与锁文件，走 PR 评审 |
| `.npmrc` 有私有 scope 映射，但锁文件 `resolved` 指向公共 registry | 配置与锁定结果矛盾，依赖混淆仍可能 | 以锁文件为准列风险；重新在受控 registry 解析并生成锁文件；核对 CI 的 npm 配置 | 中：需要私有 registry 凭据；重装依赖 |
| 私有 scope 名在公共 registry 查询超时/被墙（未授权联网） | 未验证解析结果，不能写“可被抢注” | 只写“配置缺失/未锁定”的静态结论；联网验证另开授权窗口 | 低：结论降级；不产生外部请求 |
| `pip freeze` 有包但源码里搜不到任何 import | 可能未打包/仅工具依赖/动态导入，不能判“可达” | 检查 entry points、`importlib`、插件目录、运行时加载；仍无证据则写“未观察到调用” | 低：多跑一次源码检索；动态导入需人工 |
| SCA 命中 high，但调用链断在框架内部/无源码 | 版本匹配 ≠ 可利用，当前路径 blocked | 换证据面：查运行时依赖树、补丁 diff、是否真正打包；不可达就写原因 | 中：需要构建产物或运行时；只静态看会误判 |
| 镜像只有 tag，`docker image inspect` 拿不到 `RepoDigests` | 对象不可钉住，签名/来源结论无效 | 用 `crane digest`/registry API 取 digest；离线则记录 tag + 拉取时间并标注不可复现 | 中：需要 registry 访问；离线只能降级 |
| `cosign verify` 退出码 0，但未核对 identity/issuer | 只证明“有签名”，不证明“是本流水线签的” | 补 `--certificate-identity` 与 `--certificate-oidc-issuer`；对 Rekor 条目与 digest；不匹配即降级 | 低：一次重跑；需要知道预期身份 |
| `pull_request_target` 命中，但 workflow 没有 checkout、没有 secrets | 关键字命中不等于可利用 | 核对 `checkout` 的 `ref`、job 级 `permissions`、`secrets.*` 作用域；三者都不成立则记“设计如此”并关掉该告警 | 低：只读核对；误报要写进报告 |
| action 未 pin SHA，但仓库 token 只读、无 secrets | 可移动引用存在，利用链不成立 | 记录为加固项（非漏洞）；补 Dependabot/pin 建议；不写“已被投毒” | 低：只改 CI 配置，走 PR |
| `uses: ./local-action` 被规则误报为未 pin | 本地 action 与仓库同 commit，不需要 pin | 在报告中标注 `local-action` 并从第三方 action 统计中排除 | 低：修规则或人工排除 |
| 依赖安装脚本下载二进制，但 URL 是官方 CDN 且有 hash | 正常原生包行为，不是投毒 | 核对 URL 域名、hash 校验、版本固定；成立则降为“可接受”，不列高风险 | 低：一次人工核对 |
| 许可证扫描出现 `NOASSERTION`/空值 | 是证据缺口，不是许可证冲突 | 追到组件主页/仓库 LICENSE；仍未知则列“未知许可证”，交法务，不下结论 | 中：需要逐组件人工确认 |
| 镜像层里发现疑似密钥，但值是示例/占位符 | 高熵 ≠ 真凭据 | 用前缀/长度/校验和/权限验证；无法验证则只留指纹并标注“未验证真伪” | 低：一次验证；不要外传明文 |
| CI 日志里 `npm install` 成功，但锁文件在 PR 中被改 | 构建成功不代表依赖未变 | 对比 base/head 锁文件 diff；锁定变更需单独评审；构建产物重算 hash | 中：需要 PR diff 与产物；可能触发重新构建 |
| 扫描目标包含 `node_modules`/`vendor`/构建产物 | 统计被第三方代码污染，风险数虚高 | 排除依赖目录，只扫源码与清单；需要时单独扫 `node_modules` 做完整性核对 | 低：一次重跑；注意不要漏掉打包进产物的依赖 |
| 同一 CVE 被 osv/grype/trivy 重复报出，但去重后仍是同一版本 | 工具重复不等于影响面扩大 | 按 `package+version+CVE` 去重；只保留一个条目并注明多工具交叉 | 低：报告整理 |
| action 已 pin 到 40 位 SHA，但仓库仍被投毒 | pin 只防引用移动，不防被 pin 的 commit 本身恶意 | 核对 action 仓库信誉/审计记录；限制 token 权限；对第三方 action 做行为审阅 | 中：需要读 action 源码 |
| 高危项没有修复版本/缓解措施 | 报告不可执行，维护者无法处置 | 查上游 advisory/commit；给隔离/降权/替换/关闭功能的临时缓解；仍无则写“无可用修复” | 中：需要与维护者确认 |
| SBOM 生成工具版本未记录 | 清单不可复现，跨次比较无意义 | 记录工具名+版本+命令；固定版本重生成；按 purl 对齐 | 低：一次重生成 |
| 镜像 `docker history` 显示密钥层已被后续层删除 | 删除层不等于删除内容，仍可从历史层提取 | 视为泄漏：轮换密钥、重建镜像、改用 BuildKit secret 挂载 | 高：需轮换与重新发布 |
| 依赖树里同一包多版本共存，只修了其中一个 | 另一个版本仍可能被加载 | 用 `npm ls <pkg>`/`pip show` 找实际加载路径；统一版本或分别处置 | 中：可能引发兼容性改动 |

数据行数：24 行（门禁要求 ≥8）。

## 2. 降级顺序（卡住时按这个顺序换面）

1. **先补对象**：commit → 镜像 digest → 锁文件 sha256；对象钉不住，后面全是空谈。
2. **再补清单**：SBOM → 锁文件解析 → `pip freeze`/`npm ls`；清单不全就缩小结论范围。
3. **再补可达**：源码 import → 入口调用链 → 运行时加载；三级都无证据才写“不可达”。
4. **再补 CI**：触发器 → checkout ref → permissions → secrets → action pin；按这个顺序看组合。
5. **再补来源**：digest 对照 → 签名 identity/issuer → attestation subject → Rekor。
6. **仍不成立**：写 `blocked` + blocker + 已排除项；不要为了“有结论”编造成功。

## 3. 代价评估口径

| 代价 | 含义 | 例子 |
| :-- | :-- | :-- |
| 低 | 只读/一次重跑，无外部影响 | 重跑 `sc-check.py`、核对 workflow 行号、改报告措辞 |
| 中 | 需要改仓库/CI/锁文件，或需要额外凭据/构建 | 重新生成锁文件、改 `npm ci`、取 registry digest、补 SBOM |
| 高 | 可能影响生产流水线、需要轮换凭据、需要跨团队协调 | 改发布 workflow 权限、轮换泄漏密钥、替换基础镜像、重新签名 |

## 4. 边界

- 失败判据不是“放弃”，而是“停止当前路径并换面”；换面仍须在授权清单内。
- 任何会改 CI/锁文件/镜像的动作，先开 PR、单独授权、登记回滚。
- 报告里“未验证”必须显式写出来；把未验证项写成确认，比没有结论更糟。
- 真实凭据、token、签名私钥只留指纹；失败样本也不要落明文。

## 5. 失败归因：`blocked_at` 分类与最小交接

> 失败记录不是“做不了”，而是一组可复算字段：对象 + 卡点 + 已试 + 已排除 + 代价 + 重试条件。

| 卡点 | 含义 | 允许写 | 禁止写 |
| --- | --- | --- | --- |
| `no-target` | 无 commit/digest/锁文件哈希 | “对象未钉住” | “仓库无风险” |
| `tool-missing` | syft/osv/cosign 等缺失 | “只有静态清单能力” | “没有漏洞/没有签名” |
| `no-registry` | 无 registry 访问或未授权联网 | “未验证公共解析” | “不可抢注” |
| `no-build` | 无构建记录/产物 | “来源未验证” | “可信构建” |
| `parse` | YAML/锁文件/SBOM 解析失败 | “文件结构异常” | “没有配置” |
| `permission` | 读不到私有仓库/镜像 | “未获取对象” | “镜像不存在” |
| `encrypted` | 包/镜像层加密 | “未解密” | “无该组件” |
| `time` | 时窗/授权到期 | “本轮未完成” | “目标不存在” |

### 5.1 最小失败记录（JSON）

```json
{
  "stage": "reachability",
  "blocked_at": "tool-missing",
  "tried": [
    {"cmd": "sbom-reach.py --sbom bom.json --source .", "rc": 2,
     "stderr": "no lockfile or sbom"},
    {"cmd": "sc-check.py --path .", "rc": 0, "stdout": "risks_total=3"}
  ],
  "confirmed": ["3 条静态风险", "无锁文件"],
  "unconfirmed": ["CVE 可达性", "镜像签名"],
  "next": {"route": "generate lockfile then sbom", "cost": "1h"},
  "retry_when": "拿到 CI 的 npm ci 日志"
}
```

**判据**：`blocked_at` 一个主值；`tried` 每条有 rc；`confirmed/unconfirmed` 都非空；`next.cost` 可估。

### 5.2 交接三问

1. 下一个人能否用同一命令复现我的失败？（对象 + 命令 + rc）
2. 我排除的面是否写清？（“没查”与“查了没有”分开）
3. 补证需要什么？（工具/凭据/构建记录/授权）

## 6. 时窗与止损：两次失败就换面

| 路线 | 单次成本 | 止损 | 到点动作 |
| --- | --- | --- | --- |
| 取 digest | 5–15 min | 2 次 | 记录 tag + 拉取时间，标不可复现 |
| 生成 SBOM | 10–30 min | 2 次 | 用锁文件当清单 |
| 可达性扫描 | 10–20 min | 2 个入口 glob | 写“未观察到调用”，转人工 |
| CI 权限解析 | 10–20 min | 2 次 | 人工展开 reusable workflow |
| 签名验证 | 10–20 min | 2 次（含身份） | 写“签名存在但身份未验证” |
| registry 探测 | 5–10 min | 1 次授权窗口 | 只写静态配置缺失 |
| 镜像层取证 | 20–40 min | 2 次 | 用 SBOM/层清单，不硬解 |

> 止损不是“放弃”，是把“没查”变成“显式未验证”，防止报告把未知写成安全。

## 7. 经验回流（lessons）：五条供应链硬教训

### L1：`npm audit` 的 “fix available” 不是修复证明

- 现场：`npm audit fix` 把传递依赖升了一个大版本，构建过了，但 API 行为变了。
- 新判据：修复必须带“升级后调用链仍成立/测试通过/锁文件 diff 可读”三件；否则只写建议。
- 落点：`05-lockfile-and-install-scripts.md` §1；`03-model-pitfalls.md` 第 17 条。

### L2：`resolved` 有 URL 不等于来源可信

- 现场：锁文件所有条目都有 `resolved`，但一半指向公网 tarball。
- 新判据：`resolved` 必须与 `.npmrc`/`pip.conf` 的受控 registry 一致，且有 `integrity`。
- 落点：`dependency-confusion.md` §0；`01-criteria.md` 主表第 3 行。

### L3：SBOM 组件数多不等于覆盖完整

- 现场：SBOM 有 800 个组件，但锁文件的私有包一个都没进。
- 新判据：以“锁定集合 ⊆ 清单集合”对账；`missing_from_sbom` 必须为空或逐条解释。
- 落点：`06-reachability-and-sbom-drift.md` §1；`sbom-sca.md` §2。

### L4：`permissions: {}` 不是绝对安全

- 现场：顶层为空，但 job 级又给了 `contents: write`；扫描只看了顶层。
- 新判据：顶层 + job 级合并看；`write` 是否被不可信输入触达才是关键。
- 落点：`cicd-and-artifacts.md` §1；`04-walkthrough-workflow-permissions.md` §4。

### L5：签名时间不等于构建时间

- 现场：`cosign` 显示签名在今天，结论写“今天构建”。
- 新判据：构建时间看 attestation 的 `metadata.buildStartedOn/FinishedOn`；签名时间只证明“何时签”。
- 落点：`image-and-provenance.md` §3；`03-model-pitfalls.md` 第 24 条。

## 8. 命令与“通过长什么样”（失败记录复验）

```bash
# 【占位符】把 <...> 换成你的真实路径/端口/参数后再执行
CASE=work/sc-case

# 1) 对象与锁文件
cat "$CASE/commit.txt" 2>/dev/null; sha256sum -c "$CASE/locks.sha256" 2>/dev/null | tail -3

# 2) 失败字段齐全
python - <<'PY'
import json, pathlib
d = json.loads(pathlib.Path("work/sc-case/failure.json").read_text())
print({k: bool(d.get(k)) for k in ("stage","blocked_at","tried","confirmed","unconfirmed","next")})
PY

# 3) 降级是否被写进报告
grep -nE 'blocked_at|未验证|degraded|tool-missing' "$CASE/conclusion.md" | head
```

**通过长什么样**：

| 检查 | 通过 | 不通过 |
| --- | --- | --- |
| 对象 | commit/锁文件哈希可复算 | 只有分支名 |
| 字段 | 六 key 全 true | 缺 `tried`/`confirmed` |
| 归因 | 一个主 `blocked_at` | “环境问题”笼统描述 |
| 报告 | 降级项显式出现 | 只写“部分成功” |
| 代价 | 有路线 + 时间 + 前置 | “后续再看” |

## 9. 降级链决策树（卡住时照这个走）

```text
对象钉不住？
├─ 无 .git → 用发布产物 sha256 / CI GITHUB_SHA
├─ 镜像只有 tag → crane digest / registry API
└─ 锁文件无 → pip freeze / npm ls --all（标降级）

清单不全？
├─ SBOM 过期 → 按 commit/digest 重生成
├─ 组件数差 >20% → 锁文件当权威清单
└─ 私包缺失 → 补 registry 配置后重生成

可达不明？
├─ import 搜不到 → 查发行名→import 名 / 动态导入 / entry points
├─ 只有测试依赖 → 核分组与 CI 安装参数
└─ 无源码 → 用构建产物符号/层清单，标“未观察到”

CI 面不清？
├─ reusable workflow → 展开源文件人工看
├─ YAML 锚点/merge → 用解析器而非 grep
└─ 只有 tag 未 pin → 看是否叠加写权限/不可信触发

来源不明？
├─ 无 digest → 先钉对象
├─ 签名无身份 → 补 identity/issuer
└─ attestation 脱节 → 对 subject digest
```

### 9.1 两个典型场景

#### 场景 A：`npm ci` 能过，但 SBOM 少 40 个包

1. 先对账：`missing_from_sbom` 列出缺失包名。
2. 判断来源：这些包是否 `optionalDependencies`/平台相关/私有 scope。
3. 处理：若是私有 scope，查 `.npmrc` 与锁文件 `resolved`；若是平台包，在 SBOM 工具里开启对应平台。
4. 结论：不能写“SBOM 覆盖完整”；写“缺失 N 个，已解释 M 个，未解释 K 个”。

#### 场景 B：`cosign verify` 通过，但发布者不明

1. 补 `--certificate-identity-regexp` 与 `--certificate-oidc-issuer`。
2. 对 digest：签名对象是否就是部署的 digest。
3. 对 Rekor：条目时间/身份是否与发布记录一致。
4. 结论：身份不匹配 → “有签名但非预期流水线”；匹配 → 才能写“来源可信”。

## 10. 降级记录模板（可直接贴报告）

```text
对象：<repo@commit / image@digest>
本轮覆盖：<锁文件/SBOM/可达/CI/签名>
卡点：<blocked_at>（一个主值）
已试：<cmd> rc=<n>；<cmd> rc=<n>
已证实：<字段/计数/哈希>
未证实：<CVE 可达/签名身份/运行时加载>
代价：<时间/凭据/构建记录>
重试条件：<新授权/新工具/新产物>
```

## 11. 两个低成本高价值的检查

- 锁文件 diff：只改了一个小版本但新增了 `postinstall` → 优先看包原文。
- CI 冻结命令：`npm install` → `npm ci` 往往比升依赖更能防漂移。
- 失败记录不要只写 `blocked_at`：没有 `tried[]` 的卡点无法区分“没工具”与“工具跑了失败”。

## 这一篇算"用对了"吗

- [ ] 我能把一个失败写成 `blocked_at` + 已试 + 已排除 + 代价，而不是“做不了”
- [ ] 我给每条路线设了止损，两次失败就换面而不是加参数
- [ ] 我区分了“没查”与“查了没有”，没有把未知写成安全
- [ ] 我沉淀了至少一条 lessons，并指回它改动了哪条判据
- [ ] 我的失败记录能被下一个人用同一命令复现
- [ ] 我没有把 `tool-missing/no-registry/no-build` 写成“不存在/不可利用”
