# FORK-DELTA — 本仓与原版（上游）的差分台账

> **给谁看**：未来接手的 AI / 维护者。**只看这一份，不必把 4800 个文件重读一遍。**
> **原版**：`angusdevgo/Seep-Reverse-Lab`（git remote 名 `upstream`）
> **本仓**：`gthubtom1/Seep-Reverse-Lab`（`origin`）
> **术语（避免"上游"三种用法打架）**
> `upstream-origin` = `angusdevgo/Seep-Reverse-Lab`（本仓的分叉来源，能力对照基准）；
> `upstream-src` = `LING71671/open-reverselab`（`setup/upstream-rules.json` 的同步源，落 `Tool/upstream/*`）；
> `vendored` = 被复制进本仓的第三方内容（如 `Tool/mcp/Tool/reverselab/`），**不自动同步**，改动登记在其 `PROVENANCE.md`。

> **口径**：本文件是"我们改了什么"的**唯一账本**；每条都必须能回答：改了什么 / 为什么 / 在哪 / 怎么撤。

---

## 〇、三条使用规则（先读）

1. **要判断"上游的新东西值不值得并入"** → 用 §四 的五问评估表，不要凭感觉。
2. **要改我们的东西** → 先看 §三 台账里是否已有对应条目；有就改那条，别新增第二份实现（违反反臃肿原则）。
3. **§六 是自动生成的**：跑 `python Tool/scripts/fork-delta.py` 刷新，**不要手改**。

---

## 一、一句话结论

- 相对上游：**0 个文件删除 / 3 个重命名**（`ida-reverse→ida-assistant` 等；重命名保留转发，不算删除）。
- 规模差：MCP 工具 **23 → 40**（其中 3 处为**函数体内插入**，见 §3.7，带 `SEEP-EXT` 标记）；技能 **9 → 23**（含 00–05 六个阶段技能）；体检 **55 → 65**（两平台一致）；测试套件 **1 → 6**。
- 上游有 **3 个静默缺陷**（正则碾碎、哈希截断、同名技能覆盖）我们也继承了，**已修**。

---

## 二、怎么读差分（三类）

| 类型 | 含义 | 处理原则 |
|---|---|---|
| **A 新增**（只有我们有的文件） | 我们的增量能力 | 上游永远不会冲突；但要防臃肿（见 `BASELINE-FREEZE.md` §七） |
| **M 修改**（两边都有但内容不同） | 我们对上游的改进 | **合并上游时必须逐条看**，这是唯一会冲突的地方 |
| **D 删除**（上游有我们没有） | 不应该出现 | 出现即视为回归，必须补回或写明理由 |

---

## 三、能力差分台账（人工维护，按类别）

### 3.1 MCP 工具（23 → 40，+17）

| 工具 | 类别 | 解决什么 | 实现位置 | 回滚方式 |
|---|---|---|---|---|
| `seep_ensure_tool` | 工具自愈 | 四级探测 + 安装计划 | `seep_mcp_server.py`（扩展区） | 删函数块 |
| `seep_decompile_auto` | 引擎降级 | IDA→Ghidra→REA→r2 | 同上 | 删函数块 |
| `seep_pe_resources` | 资源层 | 资源载荷枚举/剥离 | 同上 + `pefile` | 删函数块 |
| `seep_mem_strings` | 内存层 | 活体只读字符串 | 同上 + ctypes | 删函数块 |
| `seep_pcap_extract` | 协议层 | pcap 端点/HTTP/载荷 | 同上 + tshark | 删函数块 |
| `seep_packer_detect` | 判壳 | 壳/反调试/反 VM + 手册路由 | 同上 | 删函数块 |
| `seep_http_replay` | 协议层 | 构造/重放 + TLS 指纹 + Cookie 会话 | 同上 + curl_cffi/requests | 删函数块 |
| `seep_web_recon` | 侦察 | Web 指纹/安全头/入口 | 同上 | 删函数块 |
| `seep_tool_discover` / `_control_plan` / `_research` / `_register_mcp` / `_install` / `_state` | 工具发现 | 六层探测 + 能力表 + 降级链 + 半自动安装 | `tool_autodiscover.py` + `Tool/config/*.json` | 删薄封装 + 保留插件 |
| `seep_create_skill` | 扩展性 | 新技能脚手架 | 同上 + `Tool/scripts/new-skill.py` | 删函数块 |
| `seep_case_search` | 案例库 | 按域/保护/深度检索案例（index 缓存 + 实时扫描） | 同上（`SEEP-EXT: case-lib`） | 删函数块 |
| `seep_case_read` | 案例库 | 读 case.json + facts.jsonl + README | 同上（`SEEP-EXT: case-lib`） | 删函数块 |

> **合并上游注意**：上游若也新增工具，**名字冲突优先上游语义**，但要先比对签名——同名不同义会造成静默错误。

### 3.2 技能（9 → 23）

| 技能 | 类型 | 说明 | 回滚 |
|---|---|---|---|
| `version-migration` | 新增（我们） | 跨版本追版 + AOB 特征迁移 | 删目录 + 删路由 R14 |
| `unpack-loop` | 新增（我们） | 脱壳闭环（判据驱动 / 三路线 / 两次熔断） | 删目录 + 删路由 R9 |
| `ida-assistant` | **改名**（原 `safe-skills/ida-reverse`） | 避免与顶层 `ida-reverse` 同名覆盖 | 改回原名会重新触发覆盖缺陷 |

### 3.3 声明式配置（0 → 5）

| 文件 | 作用 | 谁在读 |
|---|---|---|
| `Tool/config/tool-capabilities.json` | 15 个工具的 mcp/headless/gui/cli 能力与控制命令 | `seep_tool_research` / `plan_control` |
| `Tool/config/tool-install.json` | 22 项多途径安装（winget / 绿色直下 / pip / npm / go） | `seep_tool_install` |
| `Tool/config/engine-tiers.json` | 反编译引擎降级链 | `seep_decompile_auto` |
| `Tool/config/tool-runtimes.json` | 工具通道阶梯（MCP > CLI > GUI）+ 就绪判据 | `Tool/scripts/tool-run.ps1` |
| `Tool/config/mcp-servers.json` | MCP 装配（含占位符替换与 headers 策略） | `setup/install-pi.ps1` |

### 3.4 工程/安装链改进（M 类，合并上游时重点看）

| 上游缺陷 | 我们的改法 | 位置 |
|---|---|---|
| Linux `mcp.json` 用 sed 生成 → 反斜杠路径 + 未替换占位符 + 覆写用户条目 | 新增跨平台增量合并器（只增不删/写前备份/备份轮转） | `setup/merge_agent_config.py` + `install.sh` |
| 安装脚本 unzip 返回 1 时中断 | 显式兜住 | `setup/install.sh` |
| 卸载无差别删 `extensions/*.ts` | 改为随包白名单 | `setup/uninstall.*` |
| 路由表 44 条全部指向不存在的技能 | 重写为本包真实 15 条 + 自洽断言 | `Tool/scripts/routing.json` + `verify-routing-coherence.py` |
| `master-route.ps1` 配置路径错 → exit 2 | 修路径 + 三种技能落位解析 | `Tool/scripts/master-route.ps1` |
| 体检只查"文件在不在" | 换功能性断言（路径可解析 / 含关键规约 / 实跑测试） | `setup/verify.*` |
| 工具根写死 `D:\Tools` | **动态跨盘 + 用户级安装目标** | `tool_autodiscover.candidate_roots()` |
| 无预算/无熔断/模型爱 `-h` 硬试 | 提示词硬约束 + 动态操作预算 | `Tool/prompts/{SYSTEM,AGENTS}.md` |

### 3.5 安全/证据类修复（P0，务必保留）

| 缺陷 | 后果 | 修法 |
|---|---|---|
| `security-audit-interceptor.ts` 正则字符类未转义 | 任意文本被逐字符碾成垃圾（Gemini 链路必炸） | `\[ \]` 转义 + 标记判定 |
| `seep_auto_triage` 只读前 50MB 算哈希 | >50MB 样本返回**错误证据** | 流式整文件哈希 |
| `safe-skills/ida-reverse` 同名覆盖 | 顶层 `ida-reverse` 丢 13337 唤醒规约 | 改名 `ida-assistant` + 安装器冲突守卫 + 体检断言 |
| `SYSTEM.md` 双重语义（v1.9.3 修） | pi 内核把它当“替换默认提示词”、扩展又挂成 section → **整份规则在提示词里出现两次**（≈9.9k 字符/请求），且 pi 自带默认提示词被顶掉 | 改名 `SEEP.md`（内核对它透明，只有扩展读）+ 删自愈分支 + `before_agent_start` 强制 `sync(…, true)` 消除 800ms 节流空装配 |
| `SEEP.md §3` 与 `AGENTS.md §三` 逐字重复（v1.9.3 修） | 触发词清单在提示词里出现 3 次，两份还会各自漂移 | §3 改为指针，只留 `AGENTS.md §三` 单一事实源 |
| `seep_kb_search` 整串子串匹配（v1.10.1 修） | 多词中文查询（"完整性校验 反作弊"）必然归零，库里有 545 行内容也捞不出来 | 纯插入式增强：切词 + ASCII 词边界 + IDF + 覆盖率 + 标题/路径加成 + snippet 命中居中（`seep_mcp_server.py` 净删除仍为 0 行） |
| vendored `retry-level` 扩展（v1.10.6） | pi 默认只重试 3 次，`502/429` 抖动会让长任务整回合失败 | vendored `retry-level.ts`，安装链随包复制；安装器在 settings.json **缺失时**写入 `retry.maxRetries=10`（不覆盖用户档位）。回滚：删该文件 + settings 里的 retry 键 |
| vendored `pi-cmd-guard` 扩展（v1.10.2） | agent 会发出无 timeout 的 `find /` 类命令，命令不返回 → 会话卡死在 toolUse，物理上无法自愈 | 把 `cmd-guard.ts` + `cmd-guard.rules.json` 放进 `Tool/prompts/extensions/`，安装链随包复制；**规则按本仓场景改为 `blockGui:false`**（IDA GUI 是正当手段）。回滚：删这两个文件 + `uninstall` 会一并清理 |
| `kb/field_journal__template.md` 加"归因/边界/反证"三字段（v1.10.1） | 无边界与反证的失败记录会把一次具体情况升格成永恒规律 | **本地分叉**：该目录是 open-reverselab 的 vendored 副本，重新 vendor 时须重放此改动（只改模板，未塞内容） |

### 3.6 提示词分层与人格卡兼容（v1.10.0）

| 问题 | 后果 | 修法 |
|---|---|---|
| `SEEP.md` 同时承担"规则/话术/工具清单/SOP" | 换技能、换人格卡都要改提示词，且必然漂移 | 瘦身成**装配契约**（≤2.5k 字符）：只留五层裁决 + 指针；易变内容迁至 `MANUAL/PROMPT-LAYERS.md` 存档 |
| 人格卡靠 `INJECTED_PREFIXES` 枚举卡名保护 | 换第三方卡 → 卡文本被敏感词表改写污染 | 改为**结构判定** `looksLikePersonaCard()`（标签/角色声明+长度），`guard-prefixes.json` 同步 |
| 边界只靠 prompt 层约定 | 人格卡声明"无需验证授权"即可压过 | 双层锚：`sections["seep-boundary"]`（装配末尾）+ `appendBoundaryTail()`（provider payload 兜底，实测 `input[0].content` 可写） |
| G-Auth 在 5 处表述互相矛盾 | 同一句输入在不同路径下行为不一致 | 统一到 `AGENTS.md §六`（默认已授权、用户明说无授权才停），其余 4 处插入裁决声明；记录在 `MANUAL/PROMPT-LAYERS.md §四` |

---

### 3.7 阶段技能 + 案闸 + 追版（2026-10 新增，逐条可回滚）

| 项 | 位置 | 解决什么 | 怎么撤 |
|---|---|---|---|
| 阶段零 分析 | `Tool/skill/00-analysis/SKILL.md` | 结论先于证据（20 秒下结论的血案） | 删目录 + 去掉 routing R15 |
| 阶段一 旁路 | `Tool/skill/01-gate-bypass/SKILL.md` | 交付纪律：M1–M4 分级 | 删目录 + R11/R2 指回旧技能 |
| 阶段二 UI | `Tool/skill/02-ui-rebrand/SKILL.md` | 品牌替换与回归 | 删目录 + R12 |
| 阶段三 授权 | `Tool/skill/03-license-hookup/SKILL.md` | 接自有授权平台 | 删目录 + R13 |
| 阶段四 追版 | `Tool/skill/04-version-migrate/SKILL.md` + `Tool/scripts/migrate.py` + `Tool/docs/MIGRATION.md` | 新版不用重来 | 删三者 + R14 |
| 阶段五 后端复刻 | `Tool/skill/05-backend-rebuild/SKILL.md` | 客户端+后端全栈（仅 T2/T3 触发） | 删目录 + R16 |
| 案子闸 | `Tool/scripts/case_state.py` | 事实账 / 深度门 / 裁定 / `gate` / `deliver` | 删脚本 + 恢复 00/01 的文字规则 |
| MCP 只增不删闸 | `Tool/scripts/mcp-guard.py` + `Tool/mcp/.baseline/tools.json` | 把"净删除 0 行"从承诺变成可执行 | 删两者 + preflight 对应项 |
| MCP 验连 | `Tool/scripts/mcp-doctor.py` | 连不上必须报（不许静默） | 删脚本（verify 仍有基础断言） |
| 单一入口 | `ROADMAP.md`（根目录；`优化方案*.md` 已移出到 `work/plans/`） | 现状 + 下一步 | 删文件 + AGENTS 指针回退 |

**M 类·函数体内插入（仅 3 处，均有标记）**：`seep_mcp_server.py` 的 `kb_local`、`kb-multitoken`（两处）、
`_hash_file` 流式哈希。这三处**不是末尾纯追加**；`mcp-guard.py` 校验工具名不减少、`SEEP-EXT` 标记成对。

---

## 四、上游更新了怎么办（同步 SOP）

```bash
# 0. 一次性：确认 upstream remote
git remote -v | grep upstream || git remote add upstream https://github.com/angusdevgo/Seep-Reverse-Lab.git

# 1. 拉上游（不合并）
git fetch upstream

# 2. 只看差异（先看清单，不看内容）
git log --oneline HEAD..upstream/main          # 上游比我们多的提交
git diff --name-status upstream/main..HEAD     # 双向差异（A/M/D）

# 3. 重点看 M 类（两边都改过的文件）—— 这是唯一会冲突的地方
git diff upstream/main..HEAD -- <某个 M 文件>

# 4. 对每条上游变更过一遍「五问」（见下），决定：并入 / 不并入 / 只学思路

# 5. 并入后必跑五道闸（见 §五）
```

### 上游变更评估表（值不值得并入：五问）

| # | 问题 | 判"并入" | 判"不进" |
|---|---|---|---|
| 1 | 它解决的是**我们的空白**，还是**上游自己的坑**？ | 空白 → 并入 | 上游坑 → 我们已修过，**只学思路** |
| 2 | 它会不会**改动我们的 M 类文件**？ | 不会 → 低风险并入 | 会 → 先看 §3.4/§3.5 是否已处理 |
| 3 | 它的实现是否**与我们已有能力重复**？（反臃肿三不） | 不重复 → 并入 | 重复 → **只吸收参数/清单，不搬代码** |
| 4 | 它是否引入**新目录层 / 新配置体系 / 新状态文件**？ | 否 → 并入 | 是 → **拒绝**（违反反臃肿） |
| 5 | 删掉它，我们哪条链路会断？ | 会断 → 值得并入 | 不断 → 优先级最低 |

### 冲突高发区（已知 5 个，合并前先看）

1. `Tool/mcp/seep_mcp_server.py` —— 我们对它是**末尾纯追加**；上游若改中间函数，`git` 会冲突，**保留上游改动 + 我们的追加块**。
2. `Tool/prompts/extensions/*.ts` —— 上游改过 `load-system-prompt.ts`，我们是重写版；**以我们的为准**，只吸收上游新发现的边界条件。
3. `setup/install.sh` / `install-pi.ps1` —— 上游的 sed 生成已废弃；**不要回滚成上游写法**。
4. `Tool/scripts/routing.json` —— 上游是 44 条空头路由；**不要并回**。
5. `Tool/skill/softseep/SKILL.md` —— 上游会改调度表；合并时保留我们的行（`unpack-loop` / `version-migration` / 修正后的路径）。

---

## 五、并入后的验收（五道闸，缺一不可）

```bash
python Tool/mcp/test_seep_mcp.py                        # 9/9
python Tool/mcp/test_ext_assets.py                      # 73 passed
python Tool/scripts/verify-routing-coherence.py         # 路由自洽
python -m pytest Tool/scripts/compliance-relay/tests -q # 84/84
powershell -File setup/verify.ps1 -Detailed             # 65 项（./setup/verify.sh 同为 65 项）
python Tool/scripts/check-budget.py                     # 反臃肿预算
python Tool/scripts/smoke-e2e.py                        # 端到端链路（真实样本 12 项，约 13s）
```

---

## 六、自动生成：文件级差分清单

### 六·说明（必读：这是**旧快照**）

本节是自动生成段的**历史快照**（停在 v1.10.x 统计：新增 154 / 修改 49），**不含** 00–05 阶段技能与
`case_state.py` / `migrate.py` / `mcp-doctor.py` / `mcp-guard.py`。
原因：本机是 **shallow clone 且没有 `upstream` remote**，`fork-delta.py` 依赖 `upstream/main` 才能出数
（实跑会退 2）。要重生成：

```bash
git remote add upstream https://github.com/angusdevgo/Seep-Reverse-Lab.git   # upstream-origin
git fetch upstream --unshallow
python Tool/scripts/fork-delta.py        # 覆写 §六
```

在重跑之前，**以 §一–§3.7 的人工台账为准**（那部分已随每次发版更新）。


> 由 `python Tool/scripts/fork-delta.py` 生成，**请勿手改本节**。

<!-- AUTO-DELTA:BEGIN -->

**统计**：新增 154 · 修改 49 · 删除 0 · 重命名 3（相对 `upstream/main`，已排除 `Tool/upstream/`）

### 新增文件（只有我们有）

| 分类 | 文件 |
|---|---|
| MCP 服务 | `Tool/mcp/ghidra_scripts/DecompileToFile.java`<br>`Tool/mcp/test_ext_assets.py`<br>`Tool/mcp/tool_autodiscover.py` |
| 声明式配置 | `Tool/config/engine-tiers.json`<br>`Tool/config/tool-capabilities.json`<br>`Tool/config/tool-install.json`<br>`Tool/config/tool-runtimes.json`（通道阶梯）<br>`Tool/config/mcp-servers.json`（MCP 装配） |
| 技能 | `Tool/skill/softseep/scripts/preflight-classify.py`<br>`Tool/skill/unpack-loop/SKILL.md`<br>`Tool/skill/version-migration/SKILL.md` |
| 脚本 | `Tool/scripts/check-budget.py`<br>`Tool/scripts/fork-delta.py`<br>`Tool/scripts/new-skill.py`<br>`Tool/scripts/smoke-e2e.py`<br>`Tool/scripts/verify-routing-coherence.py` |
| 文档 | `MANUAL/BASELINE-FREEZE.md`<br>`MANUAL/SKILL-CREATION-GUIDE.md`<br>`MANUAL/ZERO-TO-HERO-WORKFLOW.md`<br>`Tool/docs/EXT-ASSETS.md`<br>`Tool/docs/FORK-DELTA.md`<br>`docs/history/HANDOFF-2026-10-19.md`<br>`Tool/docs/MERGE-PLAYBOOK.md` |
| 安装与校验 | `setup/merge_agent_config.py` |
| 根目录 | `README.en.md` |
| 其他 | `Tool/cases/案例-6.9换肤壳/.agents/notes/rejected/PAGE_GUARD内存断点.md`<br>`Tool/cases/案例-6.9换肤壳/.agents/notes/rejected/全量反编译带壳程序.md`<br>`Tool/cases/案例-6.9换肤壳/README.md`<br>`Tool/cases/案例-6.9换肤壳/docs/走查与思路沉淀.md`<br>`Tool/samples/README.md`<br>`Tool/samples/build.ps1`<br>`Tool/samples/real/README.md`<br>`Tool/samples/real/android-apks/AndroGoat.apk`<br>… 另 123 个 |

### 修改文件（两边都有，合并上游时重点看）

| 分类 | 文件 |
|---|---|
| MCP 服务 | `Tool/mcp/seep_mcp_server.py` |
| 技能 | `Tool/skill/apkseep/SKILL.md`<br>`Tool/skill/apkseep/scripts/devsh.py`<br>`Tool/skill/apkseep/scripts/doctor.py`<br>`Tool/skill/apkseep/scripts/tls_check.py`<br>`Tool/skill/apkseep/scripts/vmp_diff_harness.py`<br>`Tool/skill/ida-reverse/SKILL.md`<br>`Tool/skill/softseep/SKILL.md`<br>`Tool/skill/softseep/references/license-validation.md`<br>… 另 1 个 |
| 提示词/扩展 | `Tool/prompts/AGENTS.md`<br>`Tool/prompts/SEEP.md`<br>`Tool/prompts/extensions/load-system-prompt.ts`<br>`Tool/prompts/extensions/security-audit-interceptor.ts` |
| 脚本 | `Tool/scripts/case-init.ps1`<br>`Tool/scripts/compliance-relay/README.md`<br>`Tool/scripts/master-route.ps1`<br>`Tool/scripts/routing.json` |
| 文档 | `MANUAL/CROSS-PLATFORM.md`<br>`MANUAL/DEPLOYMENT-CHECKLIST.md`<br>`MANUAL/DEPLOYMENT.md`<br>`Tool/docs/DOWNLOADS.md`<br>`Tool/docs/MCP-SETUP.md`<br>`Tool/docs/PROVENANCE.md`<br>`Tool/docs/TOOLKIT_GUIDE.md` |
| 安装与校验 | `setup/clean-format.py`<br>`setup/generate-configs.ps1`<br>`setup/install-ida.ps1`<br>`setup/install-pi.ps1`<br>`setup/install-python.ps1`<br>`setup/install.sh`<br>`setup/uninstall.ps1`<br>`setup/uninstall.sh`<br>… 另 4 个 |
| 根目录 | `.gitignore`<br>`.mcp.json`<br>`docs/CHANGELOG.md`<br>`Tool/prompts/contracts/CLAUDE.md`<br>`Tool/prompts/contracts/DSH-PROFILE.md`<br>`README.md`<br>`README.zh.md`<br>`VERSION`<br>… 另 4 个 |

> 生成时间：见本次提交；重新生成：`python Tool/scripts/fork-delta.py`
<!-- AUTO-DELTA:END -->
