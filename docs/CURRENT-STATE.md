# 当前状态

## 2026-11-01 独立分支：减少不必要人工代操作

用户确认本轮目标是修正 Agent 总把启动、点击和普通技术步骤交给用户的行为，适用于九域和日常开发；工具/技能引用修复由另一对话负责。本批在 `codex/workbench-autonomy` 的独立 worktree 实施，不部署到活动宿主，不改九域技能或工具引用注册表。

- 公共提示、询问模板与操作手册统一沿用已有范围，取消默认用户双击和无依据重复确认；普通开发不强制逆向案件流程。
- 熔断按完整输入身份区分；成功改代码后可重测，失败编辑不解除计数，旧异步结果不恢复过期计数，系统影响守卫保留。
- Windows 启动器默认自动 shell 启动，按完整映像路径、PID/创建时间观察；多实例需准确选择，显式人工模式立即返回，进程/窗口/功能结果分开。
- 仅上述实现完成本批自测；尚未接入通用桌面截图/点击后端，不宣称已解决任意软件所有人工操作。完整预检未通过：worktree 缺未跟踪 APK、部署根不同，另有工具别名检查失败；不在本批追修。

具体回归、基线提交与合并边界见 [本批回执与合并说明](verification/autonomy-behavior-2026-11-01.md)。以下 1.30.0 基线记录仍保留，不表示本分支已发布或部署。

**当前源码版本为 1.30.0，已完成定制分支跟随更新并保持既有稳定基线。** 2026-10-30 增加“软件更新后复用旧补丁、我方定制 UI、构建和验收记录”的追版闭环；没有新增正式域、固定阶段链或第二套项目状态模型。完整范围及残余边界见[本轮交付说明](verification/custom-branch-follow-2026-10-30.md)。当前 Pi 界面仍需重载后确认，不把文件部署等同于宿主已加载。

本页是当前基线、完成状态和使用边界的唯一入口。有效需求见 [REQUIREMENTS](../REQUIREMENTS.md)，职责见 [ARCHITECTURE](ARCHITECTURE.md)。本轮证据见[1.30.0 定制分支跟随更新回执](verification/custom-branch-follow-2026-10-30.md)及[结构化结果](verification/custom-branch-follow-2026-10-30.json)；1.29.0 的九域能力融合证据继续保留在[上一轮回执](verification/capability-integration-2026-10-30.md)。此前报告不作为新的待办来源。

## 2026-11-01 第三工作线：跨场景风险感知执行详细方案（未实现、未部署）

本工作线使用独立 `codex/risk-aware-analysis-plan` 分支/worktree，从 `8c6c268c` 建立；未覆盖主目录已知未提交修改，不改另两工作线的运行代码。

- 已完成详细设计：保护层/权威层与观察路线、Windows/Android 和网站/JS/接口分支、自主执行兼容、外部资产预算/租约/暂停/未知结果、跨宿主通道覆盖、实施批次和合成验收。
- 已核对项目已有反调试与协议风控规则；发现旧手册自动内核升级、网站示例速率及从首次 429 序号推安全阈值等口径需协调，不声称真实目标已复现封禁。
- 已提供 31 项资料入口、14 项设计目标/68 个待实施验收场景和三分支对接/合并交接。核对时能力发现分支 `9c8a2e80` 已包含自主执行分支 `4d229016`；最终集成须重新确认 ancestry。
- 用户追加实战研究后，补入 20 个社区讨论入口：16 个取得相关正文/可见讨论，4 个受限；明确维护者解释、作者更正、未解决和个人自述的差别。新增暂停/崩溃/进程交接、工具自身故障、匹配运行时自测、请求断点暂停与响应导出、采样业务相关性等设计。浏览器直开失败，实质内容来自可用公开检索通道，未绕登录/验证/付费限制。
- 本轮仅设计交付，未实现风险执行体，未运行客户样本/提交真实凭据，未部署、未合并；文档/结构检查不能替代运行验收或完整工程检查。

入口：[详细方案](audits/RISK-AWARE-ANALYSIS-PLAN-2026-11-01.md)、[对接交接](audits/RISK-AWARE-ANALYSIS-INTEGRATION-2026-11-01.md)、[设计校验回执](verification/risk-aware-analysis-design-2026-11-01.json)。后续运行优化继续在自己的实施分支分批完成，三条线完成后由新对话最终合并；本轮设计完成不等于运行优化完成。

## 当前基线

2026-10-30，开发、验证、部署和发布检查已收尾，代码维护基线为 **1.30.0**。1.29.0 稳定回退标签为 `baseline-v1.29.0-20261030`，对应提交 `bec1b3dbd200015d499b2e48cf6b7e1c256b532d`。正式技能导入通道已同步 `softseep`、`apkseep`，运行时注册已从新的源码根校验；后续按明确缺陷、技能、依赖兼容和上游适配做小版本维护。

## 2026-11-01 跨宿主能力引用增量（已实现并合并，未部署）

用户已确认九域作为维护归属、普通开发按当前问题借用能力。新增只读共享实现 `Tool/scripts/lib/capability_discovery.py`，由 `route.py --discover` 与 `seep_capability_discover` 同核调用；通用规则、路由技能、接入模板与配方说明接回该入口，不依赖 Pi 扩展，不执行目标或另建账本。

候选提供方法、类型化引用、原有资格与限制，区分工具软件、MCP 服务、方法及脚本；reserved/probe、静态注册和历史案例不证明当前执行或成功。修复 React/EAC、泛分析及会员订阅的误分类；泛分析通过声明式 `requires_peer_match` 依赖已有具体专业信号，保留有效的跨域辅助路由，不靠不断增加材料关键词。源码工具面基线明确追加新接口，历史机器握手快照未改写。

实现提交 `82146a81`，与自主执行分支 `4d229016` 合并于 `9c8a2e80`，最终代码复验为 `25cae554`。最新专项：能力发现 **34/34**（含真实 stdio MCP schema、正常/错误调用、CLI 同核和 OAuth 离线验证链），路由完整性 **12/12**，项目工作流 **52/52**，技能路由探针 **42/42**，既有领域串味矩阵 **67/67**（在发现专项内逐条复核，不与主测试数相加）。

组合全量曾完整执行 **106 套：96 PASS / 10 FAIL**，未改阈值；其后修复实际路由兼容性问题，并用短路径同盘工作树复验 Windows 路径/盘符相关失败。短路径 8 套复验均通过，具体代码版本和每套结果见[结构化回执](verification/capability-discovery-2026-11-01.json)，不能拼成一次全量全绿。恢复已登记且被 Git 忽略的测试输入时逐一核对 SHA256，仅复制到验证树，不运行目标、不提交二进制。

最终领域门禁为 **90/92**，仍有历史插件案例命令 cwd 绑定原仓库、已部署技能与验证树字节不等价两项失败；历史证据与部署判据均未重写。用户主目录、全局配置与活动会话未覆盖/重载。核心不依赖 Pi 插件；指定宿主的新会话自然语言选用仍需正式切换源码和部署后验证，仅重载仍指向 main 的旧部署不会加载本分支。不宣称整个项目已全绿或任意模型必然遵循。

## 2026-10-31 边界锚口径调整（凭据去向）

用户要求：凭据 / Token 在日常开发里必须能用，红线改成“放指定地方”而不是“不准落盘”。改动：

- 边界锚第 1 条（`Tool/prompts/extensions/load-system-prompt.ts`）与请求期兜底（`security-audit-interceptor.ts`）：从“发现即停、不写入任何输出、不落盘”改为“可读、可用、可落盘，落盘只进凭据仓；三个出口恒禁（git 跟踪文件 / 报告交付产物 / 客户可见材料）；正文引用 `<CRED:case/name>`”。
- 新增 `Tool/scripts/cred-store.py`：凭据仓 `~/.seep/secrets/<case>/`（仓库外，0600/icacls），`put/ls/get/path/env/purge/check/self-test`。manifest 只存指纹，不存值；`check` 拿真实值反扫已跟踪文件、case 账本、work 报告与审计证据，只报“文件:行 + 名字”。
- 同步口径：`AGENTS.md` §〇-4、`SEEP.md` §0/§1、`REQUIREMENTS.md` §6、`MANUAL/PROMPT-LAYERS.md`（T7 判据）、`Tool/docs/AUTONOMY.md` §2.2、MCP 证据面文案；`.gitignore` 加 `work/**/secrets/`。
- 证据面脱敏保留（`seep_http_security` / `session_file`）：那是防“值顺着证据漏进报告”，不是禁止使用。

验证：新增 `cred-store` 套件（`self-test` 14/14，含“命中只报名字不回显值”“仓根在仓库内拒绝写入”）；`check.py --fast` 为 **36 PASS / 1 WARN（既有 4 条 WARN/INFO，非本轮引入）/ 0 FAIL**，跳过 18 套为 `--fast` 定义，不代表全量通过。扩展与提示词已用 `setup/install-pi.ps1 -SkipPackages` 部署，锚文本实测 522 字符（旧 368）。全量 `check.py` 与宿主重载后的人工复核未做。

## 2026-10-31 守卫边界收窄（读/拷放行，只拦改系统）

用户反馈：下载目录里的文件被拦到“读不到、也不让拷进来”，而真实诉求从一开始就只是**别改我的系统**（历史事故：逆向时被改了网卡）。彻查后确认是三个独立拦截点叠在一起，逐条改：

| 拦截点 | 旧行为 | 现行为 |
| :-- | :-- | :-- |
| `cmd-guard.rules.json` `fs-bash-read-userprofile` | block：`Downloads` / `Desktop` / `Documents` 与 `.ssh` / `AppData` 同一条正则 | 拆两条：`fs-bash-read-secrets`（凭据载荷）+ `fs-bash-read-userdirs`（用户目录），**均为 warn**（读/拷放行 + 留来源提示） |
| `answer-gate.ts` `read-guard` | block：`read`/`grep`/`find`/`ls` 命中路径名即拦，`credentials`/`passwords` 这类普通文件名也在名单 | 改为 **notify 不拦**；名单删掉普通文件名词，只留真实凭据载荷（`.ssh` / `.aws` / 浏览器 cookie 库 / 私钥） |
| `interp-os-delete` / `interp-shutil-wipe` / `interp-ctypes-memwrite` / `interp-net-replay` | block | **warn**（用户决定 A）：删/搬文件、进程内存写（L1 本就允许）、协议重放都属正常工作，与 `AGENTS.md` §〇-2 的层级判定对齐 |
| `blockRootScan` | true：`dir /s C:\\` / `find /` 物理拦 | **false**：只把 timeout 抬到 `scanTimeout`，不再阻断 |
| `ask_user_question` | 硬拦（只许对话里 A/B/C） | **放行**：宿主弹窗每道题自带「Type something.」自由输入，选项不够可手打；`AGENTS.md` §〇-6 同步改为“两种都行” |
| `disableDeny` | 只对 `cmd-guard.ts` 内置表生效，rules.json 的 39 条按 id 关不掉 | 对全部规则生效（含 rules.json），关掉的 id 会打一行 `console.info` |

保留不变（用户要的就是这部分）：网卡 / IP / DNS / 路由 / WinHTTP / 防火墙 / 驱动 / 服务 / BCD / 固件 / 计划任务 / 系统信任根 / HKLM / 系统 hosts / 清日志 / 分区格式化 / 删卷影，以及删用户数据的 `rm -rf` 出 `work/`、`del /s`、`Remove-Item -Recurse` 出 `work/`、`git clean -xdf`。

验证：`test_gates.py` **44/44 PASS**（含新增 D18 / D18b / D18c：删文件降级为提示、用户目录读拷放行、凭据目录可读）；node 直调 `decideCommand` 实测 `dir /s C:\`、`find /`、`python -c os.remove`、`requests.post(https://…)`、`ctypes WriteProcessMemory` → allow + note，`netsh winhttp set proxy`、`bcdedit /set` → 仍 BLOCK。`rules.json` 30 秒热加载；`cmd-guard.ts` / `answer-gate.ts` 需宿主重载后生效（未重启前旧逻辑仍在跑）。

## 既有基线完成项

- `version-migrate` 从 AOB 追版扩展为“找回旧项目 → 比较旧上游/新上游/我方定制 → 优先复用 UI 与资源 → 按需调用 AOB、差分、脱壳、协议和授权技能 → 重建、回归、写回账本”的固定生命周期；具体技术路线仍由目标材料决定。
- `version-migrate.py add-ui` 向现有 `seep-reverse-baseline/1` 的 `ui[]` 写入受验证 UI 层，记录技术栈、应用方式、上游锚点、`ui-inventory.json`、资产、前后截图、验收项、SHA256 和大小。它只登记已验证定制，不自动执行 UI。
- 新增精确追版入口，覆盖普通软件、PE、APK/AAB 和拖入新版文件；普通依赖、文档、系统更新有负例约束，不会误命中追版。
- 首次 UI 定制必须同时留下人工清单、机读清单、上游锚点、我方资源、前后截图、构建入口/输出、功能验收和回滚；新版新增页面或入口未并入定制 UI 时，追版判定失败。
- `patch-verify.py` 只负责补丁验证，版本身份、AOB 对齐和追版报告统一走 `version-migrate.py`；旧 `_pending/00..05` 仅保留历史参考。
- 首版追版支持面明确为 PE/Windows 与 APK。其他载体仍需按各自技能处理，不能套用已支持载体的结论。
- 本机活动技能重新同步后移走 `.import-backup` 活跃残留；11 个技能部署哈希一致，运行时注册指向当前 1.30.0 源码。

## 验证

| 检查 | 实际结果 |
|---|---|
| 追版交付专项 | **15/15 PASS**，覆盖合法 UI 账本、重复 ID、路径越界、符号链接、缺文件、缺资产/截图/验收、枚举和清单 schema 拒绝且基线不变 |
| 路由与意图 | **11/11 路由测试 PASS**；106/106 意图覆盖，0 violation；拖入新版文件、保留 UI、旧补丁追版均命中，依赖/文档/系统更新不误命中 |
| 运行专项 | **104/104 PASS、0 WARN/FAIL/SKIP，退出码 0**；从发布提交 `22e2bd6f` 完整运行 |
| 工程总检 | 54 套首次 **53 PASS、1 个可移植路径失败**；改为通用探针后 preflight 为 **0 FAIL、0 unverified**，5 条既有 WARN/INFO 保留 |
| 九域端到端 | **92/92 PASS**；域契约、案例证据、反例、仓库清理和 11 个技能部署哈希全部通过 |
| 架构不变量 | 9 域 × 9 项全部成立；`I8 部署等价` 的 `softseep`、`apkseep` 已重新同步 |
| 运行时注册 | `runtime_version=1.30.0`；AgentRoot 与源码根校验通过，从外部工作目录运行部署版追版自测通过 |
| 文档与发布前 | 70 份文档、60 个命令示例 0 error；敏感文件 0、内容级凭据命中 0 |
| 真实追版 | 本轮只有合成账本与拒绝路径证据；未用真实客户软件宣称“新版已追成”，首个真实目标仍需按具体壳、签名、UI 栈、服务端和设备验收 |

工程总检保留原有提示：用户同名子代理定义不冒认受管所有权；提示词软预算由用户明确豁免，但仍继续报告且硬上限未改。没有降低判据、删除负例或上传用户材料来消除失败。

## 生效与使用

**当前已运行的 Pi 会话执行一次 `/reload`，或完整重启宿主。** 同一长期运行进程中新建会话也可能复用旧模块；文件同步、真实 SDK 加载和当前界面加载分别判断。日常仍使用自然语言加文件、目录或 URL，`lab：`不是必需入口。

追版时用户只需说明软件已更新，并提供新版文件或路径。首次定制成功后的后续结构化记录由工作台补齐，用户不需要填写内部字段。发生多个旧项目候选、产品身份冲突、壳或保护变化、签名或设备阻断时，系统会保留具体原因和下一步，不静默覆盖或假报完成。

人设文件由用户管理，工作台不替用户选择风格。回退改变会话上下文与草稿，不撤销文件或命令副作用。用户项目继续通过既有资产、路线、证据、报告和归档接口接续；不另建管理框架。

## 适用边界与维护

本轮验证为本机 Windows、PowerShell、Git Bash 和有限专业任务；未据此宣称原生 Linux/macOS、托管 GitHub CI、所有真实设备或未知目标已通过。追版 MVP 只对 PE/Windows 与 APK 给出正式生命周期；其他载体按目标技术栈另行适配。

公开 CI 的明确范围见 [.github/public-suites.json](../.github/public-suites.json)。完整领域验收保留全部 witness/depth 判据，仍需要本机案例原件和匹配的历史执行目录；客户 APK 保持 Git 忽略、不执行、不上传。历史协议验收单独成套，其原断言和产物未改；其余公开协议反例及隔离故障注入均进入公开复验。

Core 保证身份、记录和接续一致性，不替代专业语义判断；`project_workflow` 仍为 `workflow-entry-only`。后续先读本页及需求，再按 [EXTEND](../Tool/docs/EXTEND.md)、[技能编写](../MANUAL/SKILL-CREATION-GUIDE.md) 和 [稳定基线维护](../MANUAL/BASELINE-FREEZE.md) 处理明确增量，不从旧报告衍生无限优化。

从仓库根、使用同一 AgentRoot 复查：

```powershell
python Tool/scripts/check.py --runtime --json
python Tool/scripts/env-check.py
```

新改动按影响范围验证；新机器重新确认材料、安装、加载和实际调用。完整复查不能用旧回执、文件存在或工具列表替代。
