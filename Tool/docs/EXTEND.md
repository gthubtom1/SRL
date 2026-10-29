# 增补技能、工具、MCP 与领域

复用现有入口进行增量维护。接入后核对契约、部署与实际任务，不以文件增加或安装退出码证明能力完成。所有相对命令从仓库根目录执行。

## 0.1 领域命名空间（先分清再接线）

正式领域由 `Tool/scripts/lib/domain_registry.py` 从 pack 载入，别名与横切分类在 `Tool/config/domain-aliases.json`。入口分为：

- **正式域**：`Tool/skill/<domain>/pack.json` 的 `id`，当前 9 个。只有正式域进入正式路由、`domain_spec` 和领域适配器；新增正式域必须有 pack，不得只在矩阵里写名字。
- **横切技能**：例如 `seep-router`、`unpack-loop`。它们可以被多个正式域复用，但不是客户可见的独立域，也不计入正式域数量。
- **pending 子技能**：`Tool/skill/_pending/` 下按 `pending_patterns` 发现的技能。它们是候选或历史资产，不代表已接入路由、部署或行为能力。

旧名字放在 `aliases`，必须同时写 `alias_to` 和 `status`。保留旧配方、矩阵、任务卡和案例内容是兼容策略；保留不等于 alias 成为正式域。修改域索引后运行：

```bash
python Tool/scripts/domain-contract-check.py --json
python Tool/scripts/domain-contract-check.py --strict
```

## 0.2 两类案例来源是刻意分开的

`pack.json` 的 `cases` 是 pack 自己登记的 witness/交付案例集合；`pack.json.depth_contract.case_globs` 经 `Tool/scripts/lib/domain_spec.py` 载入的扫描范围 是 `domain-gate.py` 的深度门禁扫描集合。前者回答“这个 pack 明确拿哪些案例作见证”，后者回答“深度门禁按现有案例目录扫描哪些范围”。历史范围不完全相同，所以 `domain-contract-check` 只报告 `declared_only`、`glob_only`、`missing_on_disk` 和 `invalid` 的 drift。

不要直接让 `domain-gate.py` 改读 pack cases；这会同时改变深度门禁现有的案例数量、字段和产物契约。先解决 drift，再由单独迁移变更决定是否收口来源。


---

## 0. 先记住三条铁律

1. **通道优先级**：工具自带 MCP > CLI/headless > GUI > 人工。**能用 headless 就绝不开 GUI**。
2. **单一事实源**：每类东西只有一处配置。**不要在提示词里写工具数量、不要把路径写死。**
3. **按结果验收**：先跑相关契约，再跑 `python Tool/scripts/check.py --runtime --json`，部署与实际加载单独验证；WARN、跳过和缺项如实保留。

---

## 1. 加一个「工具」（x64dbg / Frida / mitmproxy / Burp …）

| 步 | 动作 | 改哪个文件 |
|---|---|---|
| 1 | 声明能力（是否 MCP / headless / CLI / GUI） | `Tool/config/tool-capabilities.json` → `tools.<id>` |
| 2 | 若有可执行入口，声明通道阶梯（按优先级） | `Tool/config/tool-runtimes.json` → `tools.<id>.modes[]` |
| 3 | 声明安装方式、动作效果及实际消费者 | 按需补 `Tool/config/tool-install.json`、`Tool/config/tool-effects.json`；由相关技能引用 |
| 4 | 契约与回归 | `python Tool/scripts/tool-contract-check.py`；`python Tool/scripts/check.py --runtime --json` |

新增通道的写法（配置驱动，`tool-run.ps1` 不用改）：

```jsonc
// Tool/config/tool-runtimes.json
"mitmproxy": {
  "prefer": ["cli"],
  "modes": [
    { "id": "cli", "kind": "cli", "why": "mitmdump 无头抓包，不需要 GUI",
      "command": "\"{exeDir}/mitmdump.exe\" -p 8080 -w {workDir}/flow.dump", "toolId": "mitmproxy" }
  ]
}
```

> **判断口诀**：有 CLI/headless → 只写 CLI 那条就够了；**只有必须靠宿主进程才能控制的**（如 x64dbg 调试）
> 才写 `gui`/`mcp-http` 通道，并在 `why` 里写清"为什么没有 headless 等价物"。

---

## 2. 加一个「MCP 服务」

| 步 | 动作 | 改哪个文件 |
|---|---|---|
| 1 | 追加一条服务声明（唯一改动点） | `Tool/config/mcp-servers.json` → `servers.<name>` |
| 2 | 契约核对与部署 | `python Tool/scripts/check.py --runtime --json`；Windows 用 `setup/install-pi.ps1 -SkipPackages`，其他平台见部署手册 |
| 3 | 新开会话验证 | 检查宿主实际加载、initialize/tools/list 和任务所需调用，列表登记不代替动作成功 |

- 两个安装器（`install-pi.ps1`、`merge_agent_config.py`）都读这个文件，**不再各写一份硬编码**。
- 需要用户凭据的条目加 `"onlyIfMissing": true`，重装时不覆盖用户已填的 token。
- 带 token 的条目**不要把 token 写进 mcp.json**：用 pi 的 `!命令` 动态取（示例见 `mcp-servers.json` 的 `_可选条目示例`）。

---

## 3. 加一个「技能」（单入口 `skill-import.py`）

唯一入口是 `Tool/scripts/skill-import.py`：**用户只说一句"加这个"**，判型建议、落位、备份、
部署、核验、回执都由它完成；用户不需要填技术表。旧调用方式仍然可用。

```bash
# 旧入口（兼容）：无 pack 时不再靠关键词自封正式域，会如实报 needs_classification(rc=2)
python Tool/scripts/skill-import.py --from <目录或 SKILL.md> [--name N] [--dry-run]
python Tool/scripts/skill-import.py --selftest

# 单入口：kind 由 Agent 显式选择（auto 只给建议，不落盘）
python Tool/scripts/skill-import.py import --kind auto|domain|crosscutting|subskill|tool \
    --from <路径> [--name N] [--parent <真实域名>] [--pack <pack.json>] [--tool-id T] \
    [--skill-dir Tool/skill] [--deploy-root <skills 根> ...] [--no-deploy] [--replace] [--dry-run] [--json]

# 内部阶段（诊断/复验，可分步）+ 只读恢复报告
python Tool/scripts/skill-import.py plan|stage|validate|deploy|verify ...
python Tool/scripts/skill-import.py status --skill-dir Tool/skill [--deploy-root <根>] [--name N] [--json]
```

**判型口径（建议 ≠ 身份）**：关键词/后缀/技法（A/B/C 三选二）只产出 `kind_suggestion`；

| kind | 判据 | 落点 | 能否 `effective=true` |
|---|---|---|---|
| `domain` | **必须**有 `pack.json`，`id == 目录名`，且过真实 `gate.g2_schema` + `route.check`（死路由/坏正则/重复优先级/SKILL.md 在场） | `Tool/skill/<name>/` | 还要路由可发现 + 部署 hash 一致 + **全局领域契约与部署验证通过** |
| `crosscutting` | 显式声明（或已在 `domain-aliases.json#cross_cutting`） | `Tool/skill/<name>/` | 只代表"已部署可达"，不是客户可见正式域 |
| `subskill` | **必须** `--parent <真实 pack 域>`，父 SKILL.md 锚点唯一 | `Tool/skill/_pending/<name>/` | 永不：不部署成顶层技能、不自动选中（父域**按需**可达 ≠ 全局选中） |
| `tool` | `--from` 是 tool manifest | 无（只声明） | 永不：只报 `declared` / `registered` / `not_available` |

**事务顺序**：`plan → 多资源锁 → journal(intent) → stage(同卷) → validate → commit(备份+改名) → 父引用 → deploy(逐 root 同卷) → verify → receipt`。

三条硬规则（IMPORT-02 修的就是它们）：

1. **改名失败即放弃**：`staging`/`backup` 只做同卷 `os.replace`/`os.rename`，**失败直接拒（rc=5）**，
   绝不退回“逐文件复制再删源”（那会把旧目录拆成两半）。所以 staging 与 backup 一律与被改目标同卷：
   仓库侧在 `<skill-dir>/.import-{staging,backup}/`，**每个部署根在自己的** `<root>/.import-{staging,backup}/`
   ——不跨盘把旧部署搬回仓库备份。
2. **journal 先 intent、后 done**：回滚按**磁盘事实**逐项检查（源/目标各自在不在），报
   `rolled_back` / `rollback_partial` + 可复查位置；旧内容真的丢了就如实报 `rolled_back=false`，不谎报 true。
3. **多资源锁**：按**规范化目标路径全局排序**同时持有 skill 锁 / 仓库父目录锁 / 父 SKILL.md 锁 /
   每个部署父目录+dest 锁（跨进程 `O_CREAT|O_EXCL`，有界等待，不是进程内线程锁）；
   不同子技能同父域并发导入不丢引用，回滚不覆盖另一个已提交事务。

覆盖已有技能必须显式 `--replace`（实现是“先备份再改名”，绝不 `rmtree` 旧目录后 `copy`）。
回滚后备份保留在 `<skill-dir>/.import-backup/<name>-<ts>/`（父 SKILL.md 原件在 `_parent/` 下）可复查。

**子技能引用写在模型真正读得到的地方**（两处都要，缺一就是“写了没人读”）：

| 侧 | 写在哪 | 那一行长什么样 | 为什么 |
|---|---|---|---|
| 仓库 | `Tool/skill/<parent>/SKILL.md` | `` - `../_pending/<child>/SKILL.md` —— 何时读 `` | 按**父技能目录**相对解析（pi 口径），不依赖 repo cwd |
| 部署 | `<root>/<parent>/SKILL.md` | `` - `references/imported-subskills/<child>/GUIDE.md` —— 何时读 `` | 模型只读部署根，仓库那行它看不到 |

部署侧把子技能本体复制到 `<root>/<parent>/references/imported-subskills/<child>/`（连同相对资产），
入口 `SKILL.md` 改名为 `GUIDE.md` ——**这样它不会被当成新的全局技能被自动选中**；
同目录 `import-map.json` 记录路径映射与逐文件 hash。父域未部署到该 root 时如实报
`deploy_pending=true` 并明说“按需可达尚未建立”，**不自动把父域整块搬过去**，也不把
`pending` 说成已可达。

**部署根边界（先拒后写，拒之前零写）**：`plan`/`import`/`deploy`/`verify`/`status` 共用同一套解析——
给了 `--deploy-root` 就逐个校验；自定义 `--skill-dir` 且**没给**根时直接 `deploy_root_required`（不写真实 `~/.pi`）；
部署根与 `--skill-dir` / 仓库根 / 源目录重叠或互为祖先、是符号链接/junction → `deploy_root_overlap` /
`deploy_root_symlink`。`verify`/`status` 没给根时不兜底真实用户根（只核仓库侧并标 `verify_scope=repo_only`）。

**回执分开报，不许合并读**：`files_imported`（仓库落盘文件数）/ `deployed`（每个 root 的路径 + `hashes_equal` +
`pending`）/ `available_next_session`（下次会话能不能加载）/ `formal_domain_active`（算不算正式域）/
`rollback`（逐项磁盘事实）/ `recovery`（残留锁/staging/journal + `pending_manual`）。

**verify 按 kind 分开判**：`domain`/`crosscutting` 核 manifest（含“多出来的文件”）+ 路由 + 每个 root 逐文件 hash；
`subskill` **不**做顶层部署等价（它本来就不在 `<root>/<name>`），而是核**父入口能否解析到真实文档**
（仓库 `../_pending/…`、部署 `references/imported-subskills/…/GUIDE.md`）+ 映射 hash；
引用丢了/部署副本被改 → `rc=5 verify_failed`，不会给绿。尚未部署但合法时状态是 `pending_subskill`
（如实说“不生效、不自动选中”），不宣称已可达。

**退出码**：`0` 成功 · `2` 判型未定或用法错误 · `3` 能力缺口（tool 模式只声明）·
`4` 策略拒绝（无 pack / 父域不存在 / 路径逃逸 / 部署根不合法 / 并发锁 / 目标已存在）·
`5` 写了盘但 verify 失败（已回滚，或如实报 `rollback_partial`）。

**中断后怎么办（`status` 只读）**：`python Tool/scripts/skill-import.py status --skill-dir Tool/skill --json`
列出残留 `.lock`（含 pid/ts/角色/被保护路径）、`.import-staging/*`（含 `journals/*.jsonl` 的动作阶段）、
`.import-backup/*`；有残留就 `pending_manual=true`，并给“确认 pid 已退出后人工删锁”的指引。
**本批不自动恢复、不自动删疑似活锁、也不删用户目录里的任何东西**。

**本入口不做什么**（不假装修好）：

- 不写 `Tool/config/domain-aliases.json#formal_domains` —— 新域落盘后 `domain-contract-check.py` 会报
  `formal_domains 缺少 pack id`，这是**想要的**红灯（人来确认，不由导入器自封）。
- 不生成/回填 witness、`witness_tool`、案例、`case_roles`、能力矩阵；也不实跑 witness
  （回执 `witness_ran=false`），缺声明的 pack 直接被真实 `g2_schema` 拒。
- 不替新域补齐深度契约、领域别名分类或案例模板。正式集合已由 pack 注册表载入，不需要维护旧的五处固定名单；仍须查看 `registered_pending_contracts` 的实际结果，补齐模板、别名和领域契约后复验。缺项时 `formal_domain_active=false`，不能把落盘当作正式生效。
- `--kind tool` 只 `validate` manifest 并报 `staged`/`not_available`：**不写**
  `tool-capabilities.json` / `tool-runtimes.json` / `tool-effects.json`，不下载、不安装、不运行。
  这是 `capability_gap 待 adapter`，不是"工具扩展完成"。

**接线四处**（能被选中的前提）：

| # | 位置 | 谁负责 |
|---|---|---|
| 1 | `Tool/skill/<name>/SKILL.md` | 本脚本 |
| 2 | `Tool/skill/_pending/<name>/` + 父 `SKILL.md` 的 `../_pending/<name>/SKILL.md` 引用行 | 本脚本（幂等插一行，带备份） |
| 3 | `Tool/skill/<name>/pack.json` 的 `routes` + `priority` | **人/Agent**（真实 pack，不给就拒） |
| 4 | `~/.pi/agent/skills/<name>/`（或显式 `--deploy-root`） | 本脚本（**该 root 本地同卷**备份 + 改名 + hash 核验） |
| 5 | 子技能的部署侧：`<root>/<parent>/references/imported-subskills/<name>/` + 父部署 SKILL.md 的引用行 | 本脚本（父域已部署时才建；否则报 `deploy_pending`） |

契约核对：`python Tool/scripts/route.py --check`、`python Tool/scripts/skill-handoff-check.py`、`python Tool/scripts/domain-contract-check.py --json`；统一回归：`python Tool/scripts/check.py --runtime --json`。导入专项回归包含判型、事务、并发、回滚、根目录边界与部署漂移。

## 3bis. 组合已有方法

任务阶段由主模型根据用户目标与证据决定，不要求所有项目走完整改造链。正式领域间用实际技能入口衔接；专项参考从 `Tool/skill/_pending/INDEX.md` 按源码路径读取，不以 `00-analysis` 等归档目录名调用已安装技能。跨版本追版的实际入口为 `Tool/skill/softseep/scripts/version-migrate.py`，方法见 [MIGRATION](MIGRATION.md)。

## 4. 改「提示词层 / 纪律」

| 改什么 | 改哪 | 注意 |
|---|---|---|
| 跨宿主纪律（Lab/反退缩/G-Auth/工具纪律） | `Tool/prompts/AGENTS.md` 对应章节 | 只插段落，别复制到别处 |
| pi 装配契约 / 层间裁决 | `Tool/prompts/SEEP.md` | **≤2500 字符，只放指针**；门禁会查 |
| 人格 / 风格 | `~/.pi/agent/personas/*.md` | **不入仓库**，用户自管 |

---

## 4bis. 域快捷指令已取消

用户通过自然语言开始项目，Agent依据技能描述选域并读取技能正文。本项目不新增或自动生成 `Tool/prompts/tasks/` 的域快捷卡，取消的命令不因扩展技能而恢复。

领域内部的六段任务配方供Agent按需阅读，与用户斜杠指令不同。功能范围只取 `REQUIREMENTS.md`，工作台当前进度只取 `docs/CURRENT-STATE.md`。

---

## 4ter. 怎么给新工具选 `kind`（决定"要不要开 GUI"）

按这个顺序问，问到一个"是"就停：

1. 它自带 **stdio MCP** 吗？→ `mcp-stdio`（pi 自拉，用户不用管）
2. 它有 **CLI / headless** 能做同样的事吗？→ `cli`（**绝不启动 GUI**）
3. 它的控制面只在**宿主进程内**（调试钩子/断点/注入/内存读写）吗？→ `mcp-http` / `mcp-sse`（Agent 用 `tool-run.ps1` 按需自启，单实例，用完关）
4. 只有 GUI 能操作、且没有 MCP？→ `gui`（最后手段；`why` 里必须写清"为什么没有 headless 等价物"）
5. 必须人看屏幕（首次许可/崩溃恢复弹窗）？→ `manual`（此时才找用户）

**"度"的三条**：按需自启（不做开机常驻）· 单实例（同端口只开一个）· 用完即关（`StopDebug`/退出）。
判据只有一句：**这次任务需不需要在目标进程里下钩子或断点**；不需要就不启动宿主。

---

## 5. 检查与验证

```bash
python Tool/scripts/check.py --runtime --json
python Tool/scripts/env-check.py
```

运行回归验证当前实现；环境检查验证当前 Pi AgentRoot。两者均不能替代新增能力的具体任务见证和新会话加载。历史 `check.py` 默认门禁仍保留，其 WARN、跳过及旧基线漂移需独立解释；不要将某个入口通过说成所有检查通过。

工具库条目在 `Tool/config/tool-install.json` 声明 `kind: "python_lib"` 与 `module`，例如 `pefile`。当前解释器新进程实际导入用于就绪判定，pip 成功后再次导入；库没有同名 EXE 不算缺工具。CLI 入口仍检查可执行路径。

## 6. 回滚

- 单文件：`git revert <commit>` 或直接删掉新增条目；
- 技能：`python Tool/scripts/skill-import.py import ...` 的回执里 `backups` 字段给出真实备份路径
  （`<skill-dir>/.import-backup/<name>-<ts>/` 与 `<deploy-root>/.import-backup/<name>-<ts>/`，含被替换掉的
  旧目录与父 `SKILL.md` 原件）；回滚就是把备份 `rename` 回去，不需要重建内容。
  失败事务会自动回滚并打印 `rollback` 逐项结果（`applied` = 该 intent 是否真的执行过）；
  **回滚不完整时 `rolled_back=false` + `rollback_partial=true`**，并指出可复查位置——不谎报“已回滚”；
- 中断（kill/断电）后先跑 `python Tool/scripts/skill-import.py status --skill-dir Tool/skill --json`
  看残留锁/staging/journal 与上次停在哪个阶段，再人工处理（本批不自动恢复）；
- 本机配置：安装器每次都会备份到 `~/.pi/agent/backup-*`。

---

## 6bis. 换机器或新装工具

| 步骤 | 命令 | 结果 |
|---|---|---|
| 探测 | `python Tool/scripts/tool-acquire.py --sweep` | 当前可用/缺失与发现来源，不能推广成所有机器零漏检 |
| 查询缺项 | `python Tool/scripts/tool-acquire.py --tool <id> --json` | 当前能力状态、安装或启动建议 |
| 登记 CLI 路径 | `python Tool/scripts/tool-acquire.py --add <id> --exe <真实路径>` | 只登记当前机器；不存在的路径被拒绝 |

工具安装后重新发现并验证实际动作。缓存用于复用本机探测结果，不是另一个通用能力证明。面向所有机器的候选名称、库模块与安装方式更新配置表；机器绝对路径不写进仓库。

## 7. 反面清单（违反即返工）

- ❌ 在提示词里硬编码工具数量 / 技能清单（会立刻过期，门禁会红）；
- ❌ 写死某台机器的绝对路径（用 `seep_tool_discover` / `{exeDir}` / `{ROOT_POSIX}`）；
- ❌ 给 GUI 工具写自动启动却忘了"没有 headless 等价物"这个前提；
- ❌ 往 `Tool/mcp/Tool/**`（vendored 上游树）加内容 —— 重新 vendor 会被覆盖，本地内容放 `Tool/mcp/kb_local/`；
- ❌ 只登记配置或生成文件就宣布连接、加载和任务成功；缺项、WARN 与跳过必须分别报告。
