# 增补技能、工具、MCP 与领域

复用现有入口进行增量维护。接入后核对契约、部署与实际任务，不以文件增加或安装退出码证明能力完成。所有相对命令从仓库根目录执行。

## 0.1 领域命名空间（先分清再接线）

正式领域由 `Tool/scripts/lib/domain_registry.py` 从 pack 载入，别名与横切分类在 `Tool/config/domain-aliases.json`。入口分为：

- **正式域**：`Tool/skill/<domain>/pack.json` 的 `id`，当前 9 个。只有正式域进入正式路由、`domain_spec` 和领域适配器；新增正式域必须有 pack，不得只在矩阵里写名字。
- **横切技能**：例如 `seep-router`、`unpack-loop`。它们可以被多个正式域复用，但不是客户可见的独立域，也不计入正式域数量。
- **域内专属子技能**：`Tool/skill/<domain>/subskills/<name>/`。它们是归属于具体正式领域的细分专业技能，由父领域的【子技能导航表】按需相对引用；随父域部署并按需读取，不作为额外顶层入口。旧 `_pending` 仅保留有明确身份的历史参考，不接受新的活跃子技能。

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

用户只需说希望增加什么能力；Agent先检查已有方法，再选择类型、父域和部署根。正式入口负责计划、验证、同卷事务、父引用、部署、核验与回滚；用户不填写内部规划字段。

| 类型 | 条件与源码落点 | 生效口径 |
|---|---|---|
| `domain` | 合法`pack.json`、`id`等于目录名，真实路由/深度/见证契约；`Tool/skill/<name>/` | 全局契约、部署、宿主发现和实际任务分别验证 |
| `crosscutting` | 显式的多域共用方法；顶层技能目录 | 已部署可发现，不成为额外业务领域 |
| `subskill` | 必须指定真实父域；`Tool/skill/<parent>/subskills/<name>/` | 由父技能按需读取，不是顶层自动选中 |
| `tool` | 工具manifest | 只处理声明，实际注册/安装/执行另走工具入口 |

所有命令从仓库根运行。以下由Agent填入真实路径；`<skills-root>`为选定AgentRoot下的`skills`目录：

```bash
python Tool/scripts/skill-import.py plan --kind subskill --parent softseep --from <source> --deploy-root <skills-root> --json
python Tool/scripts/skill-import.py import --kind subskill --parent softseep --from <source> --deploy-root <skills-root> --json
python Tool/scripts/skill-import.py verify --name <child> --parent softseep --deploy-root <skills-root> --json
python Tool/scripts/skill-import.py status --name <child> --parent softseep --deploy-root <skills-root> --json
```

`auto`只提供判型建议。覆盖已有内容必须显式`--replace`；独立部署使用`deploy --name <child> --parent <domain> --deploy-root <skills-root>`，替换同样需要`--replace`。`verify/status/deploy`省略父域时只接受唯一身份，同名跨父域返回`skill_ambiguous`；不会用旧`_pending`副本抢占当前子技能。

### 源码与部署保持同一结构

源码、完整安装和增量导入均采用：

```text
<skill-root>/<parent>/
  SKILL.md
  subskills/<child>/SKILL.md
  subskills/<child>/references/...
  subskills/<child>/scripts/...
```

父导航引用`subskills/<child>/SKILL.md`，按父技能目录解析；子技能自己的资源按子技能目录解析。当前Pi加载器发现父`SKILL.md`后不继续向下发现全局技能，因此嵌套子技能可保留原名，不再生成`GUIDE.md`或第二份映射副本。其他宿主须验证其发现规则，不能据文件复制推断加载。

父域尚未部署时只报告`pending=true`，不偷偷整块部署父域。旧`references/imported-subskills`只有在映射、哈希与受管文件身份都可核验时才通过事务移入备份；额外用户文件、坏清单或内容漂移会拒绝迁移并保留原件。

### 事务与失败保护

`plan → 排序持有多资源锁 → journal intent → 同卷stage → validate → commit → 父引用 → 逐root deploy → verify → receipt`。同卷改名失败不降级为拆散目录复制；journal先记intent再记done。回滚依据磁盘事实报告`rolled_back`或`rollback_partial`，不能覆盖并发事务已提交的父引用。

源码和每个部署根各自保留备份。子技能合法变更在同一锁和事务内更新已导入父域的manifest；修改前先核旧清单，只接纳本次父导航和指定子树的增量，拒绝借导入重签其他漂移。已有四列导航表就在表内新增或更新一行，保留无表父技能的唯一锚点兼容。

中断恢复同时核对文件系统对象身份、原始字节与成员/类型/空目录快照；发现后续提交或用户改动时先拒绝撤销并保留现场，`recovery_review`给Agent只读核对命令。回撤过的发布内容保留到同卷备份，通过`retained_staging`报告；安全拒绝不等于部署完成。自定义`--skill-dir`必须显式指定独立部署根；源码、源目录、部署根互相重叠或经过不允许的链接时先拒后写。`verify/status`没有部署根时仅核仓库侧并说明范围，不兜底写真实用户目录。

默认 AgentRoot 推导出的部署根也执行相同边界校验。恢复 journal 必须属于当前技能仓库；暂存、备份、父文件和部署目标分别限定在该技能事务的范围内。复制旧 journal 到另一仓库不会授权撤销原仓库，也不能把无关技能目录当作暂存目录清理；拒绝时保留日志与现场。

### 怎样读回执

- `files_imported`：仓库落盘数量；不代表任务成功。
- `entry_reachable`：仓库父入口可解析到子技能。
- `deployed[].status=ok`与`hashes_equal=true`：该部署根文件和引用可达；`pending=true`表示父域未部署。
- 子技能仍为`effective=false`、`available_next_session=false`、`effective_status=pending_subskill`：这些字段表示它不作为顶层技能自动选中，不能误读为父域永远无法按需读取。
- `formal_domain_active`只适用于正式域契约；导入器不伪造见证或替工具完成安装。
- `rollback/recovery`按实际锁、journal、staging与备份报告；不自动删除疑似活锁。

旧`--from`兼容入口与`--selftest`仍保留，不能绕过类型和身份契约。退出码以实际CLI为准：判型/参数未定、能力缺口、策略拒绝、写入后核验失败分别报告；非零不当作生效。

### 验证

```bash
python Tool/scripts/route.py --check
python Tool/scripts/skill-handoff-check.py
python Tool/scripts/domain-contract-check.py --json
python -m unittest discover -s Tool/scripts -p 'test*import*.py' -v
python Tool/scripts/check.py --runtime --json
```

专项覆盖正常导入、替换、同名不同父域、并发、缺文件、篡改、父域未部署、跨root失败回滚、旧受管副本迁移与中断恢复。安装后再增量导入、重复安装、独立verify和新进程读取需要一起验证；最终再用代表性任务检查方法是否有用。

## 3bis. 组合已有方法

任务阶段由主模型根据用户目标与证据决定，不要求所有项目走完整改造链。正式领域间用实际技能入口衔接；各域专属子技能从 `Tool/skill/<domain>/subskills/` 按需读取，专项历史参考可从 `Tool/skill/_pending/INDEX.md` 按源码路径追溯，不以 `00-analysis` 等归档目录名调用已安装技能。跨版本追版的实际入口为 `Tool/skill/softseep/scripts/version-migrate.py`，方法见 [MIGRATION](MIGRATION.md)。

九域能力扩充先核对已有子技能、references、KB 与工具通道。已有任务优先扩原入口；有独立输入、步骤、输出及失败条件时再新增域内子技能。API/认证、游戏运行时/渲染、云/容器、取证和批处理等专题均按目标组合现有主辅域，不因一个技术名词新增正式领域或另一套项目管理框架。

每次增量明确适用平台/版本、实际工具与环境、可复查正例和反例、失败恢复及旧入口兼容。工具路径存在、版本探针命中、技能文件部署、宿主加载和目标任务完成分别记录；知识库导航或一份新文档不能替代后四项验证。完整的新任务链按小版本交付，已支持任务的错误路径、参数和判据修正按补丁维护。

## 4. 改「提示词层 / 纪律」

| 改什么 | 改哪 | 注意 |
|---|---|---|
| 跨宿主纪律（Lab/反退缩/G-Auth/工具纪律） | `Tool/prompts/AGENTS.md` 对应章节 | 只插段落，别复制到别处 |
| pi 装配契约 / 层间裁决 | `Tool/prompts/SEEP.md` | **≤2500 字符，只放指针**；门禁会查 |
| 人格 / 风格 | `~/.pi/agent/personas/*.md` | **不入仓库**，用户自管 |

原 `/persona`、`/rewind`、`/undo-reply` 来自 `gthubtom1/agent-plugins` 的 `pi-seep-ext`。本仓在 `Tool/prompts/packages/pi-seep-ext/` 保留上游两扩展及其依赖，并适配工作台的提示词装配和设置保存（来源与改动见 [PROVENANCE](PROVENANCE.md)）。安装器把它同步到 `<AgentRoot>/packages/pi-seep-ext`，在 `settings.json` 的 `packages` 中声明 `./packages/pi-seep-ext`，受管文件哈希记录在现有 `seep-install-manifest.json`。

用相对路径而不是 git source 的原因：
- 兼容改动必须随包分发，git source 只能取上游原文；
- 相对路径从 `settings.json` 所在目录解析，仓库在 D:、AgentRoot 在 C: 这类跨盘符情况也不会失效；
- 不依赖任何临时 clone 目录，卸载后不留悬空声明。

只补这一对插件（PowerShell，从仓库根执行，`$targetAgentRoot` 换成实际 AgentRoot）：

```powershell
python setup/merge_agent_config.py --root . --agent-dir $targetAgentRoot --persona-rewind-only
if ($LASTEXITCODE -ne 0) { throw '配置合并失败，停止安装' }
```

合并前先核验完整包、本地导入依赖、路径、配置和所有权。只更新受管且哈希未漂移的文件；未知或被修改的冲突文件保留并报错。包文件、配置和所有权记录共同保存；失败时恢复原位置并核验，恢复未完成则返回非零并保留备份证据。同 source 的声明不重复添加，不改 MCP、retry 档位或用户人设卡。

`cached` 保留 SDK 的系统提示词增量；`every-turn` 在每次模型请求时重放完整系统提示词和当前人设，包括工具续轮。两种模式都保留 SEEP、规则、边界与项目上下文。人设选择跟随对话，注入模式是全局设置；选择「无人设」后，回退、压缩或重新打开该会话也不会复活旧人设。

完整安装/更新走 `setup/install-pi.ps1`（或 `setup/install.sh`）的正式入口，它同样会同步这个包；`-SkipPackages` / `--skip-packages` 只是跳过 npm 包安装，不影响本包的同步。

**加载与生效分开看**：文件和配置到位不等于运行中的模块已更新。升级后在待使用的会话执行 `/reload`；本轮实测，同一个长期运行的 Piweb 进程中新建会话也可能复用旧模块，仅看到命令不能证明已加载最终代码。完整重启宿主也会重新加载。其他已开着的会话仍需各自重载。验收要点：

1. 命令列表出现 `/persona`、`/rewind`、`/undo-reply`，且没有重复项；
2. `/persona` 列出 `无人设` + `personas/*.md` 里的每个文件 + `⚙ 注入模式`；Esc 不改任何选择；
3. 选一个后状态栏变成 `🧑‍🎤 人设：<名字>`，再选「无人设」后提示词里不再有它，也不会被 `PERSONALITY.md` 补回；
4. `/undo-reply` 只把最后一条纯文本回复移出上下文并把问题放回输入框；带工具调用时会先确认，**文件与命令的副作用不会撤销**。

专项复验：

```powershell
python -m unittest setup.test_merge_agent_config
python -m unittest Tool.scripts.test_runtime_install_delivery
node setup/test_persona_rewind_sdk.mjs '<pi-coding-agent 包目录>'
```

SDK 检查在临时 AgentRoot 里跑真实安装器和真实 loader，用合成卡与临时会话，结束后清理临时目录；不碰真实用户会话、真实人设卡与 auth/models。

卸载使用正式入口的包清理选项。`merge_agent_config.py --root . --agent-dir <AgentRoot> --remove-packages` 会清理工作台声明的全部配套包条目（不只这一对），同时只删除 persona/rewind 副本中受管哈希仍吻合的文件；用户自建、修改或归属不明的内容留在原位。需保留其他包时，不要用该全量选项。完整卸载的 `KeepPackages`／`--keep-packages` 同时保留包声明和相应所有权。

出现部署冲突时保留现场与备份，按已登记哈希确定来源后处理；不得为消除报错而把未知文件补签为受管。旧候选若没有所有权记录，先核对其来源和内容，再按具体迁移记录备份与重新部署。

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
