# Changelog

> 本文件面向**已部署用户**，说明每次更新带来什么变化、需要注意什么。
> 更新操作见 [MANUAL/DEPLOYMENT.md — 更新指南](MANUAL/DEPLOYMENT.md#八-已有用户更新指南)。
>
> **模型选型与拒答排查**见 [MANUAL/MODEL-REFUSAL-MATRIX.md](MANUAL/MODEL-REFUSAL-MATRIX.md)（实测对照表）。

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

## [1.8.5] — 2026-10-19

### 文档：全仓口径与目录树同步（"该改的都改"）

- **版本号**：README / README.zh / README.en 的 Release 徽章、正文版本、基线定档起始版本统一到 **v1.8.4**；
  `check.ps1` / `check.bat` / `update.ps1` / `update.bat` **去掉硬编码版本号**（改为"版本取自 VERSION 文件"），永不因升版而过期。
- **技能数**：README 目录树 `10 大逆向专业技能` → **11 个**，并补上 `version-migration` 与 `unpack-loop` 两行；
  `apkseep` 文件数 115 → **113**（真实值）。
- **MANUAL 树**：11 份 → **13 份**，补 `BASELINE-FREEZE` / `SKILL-CREATION-GUIDE`。
- **CLAUDE.md 目录树**：案例 14 → **15**；手册 9 → **13**；`docs/` 补 `FORK-DELTA`；`scripts/` 说明改为真实职责。
- **PROVENANCE 溯源表**：9 行 → **11 行**，补 `version-migration` / `unpack-loop`；`ida-assistant` 路径修正。
- **TOOLKIT_GUIDE 脚本表**：补 6 个新脚本（master-route / 路由自洽 / 端到端冒烟 / 预算自检 / 差分台账 / 技能脚手架）。
- **README 新增「工程侧增强」表**：脱壳闭环 / 工具可移植 / 工具自愈 / 端到端验收 / 反臃肿预算 / 差分台账 / 防崩纪律。

### 修复：BOM 回归（本轮文档批量改写引入）

- 批量改文档时用了 `utf-8-sig` 写回，导致 **15 个 .md 与 1 个 .py 被加上 BOM** —— 其中
  `Tool/scripts/new-skill.py` 带 BOM 会直接 `SyntaxError`，`SKILL.md` 带 BOM 会被 Agent 静默跳过（体检当场转红）。
- 处置：`setup/clean-format.py` 增加**通用 BOM 剥离**（除 `.ps1/.psm1/.bat/.cmd` 外一律去 BOM），
  并在本次全仓执行（112 个 Python 文件语法校验全过）。

## [1.8.4] — 2026-10-19

### 文档：统一「MCP 工具数」口径（消除误读）

同一个"工具数"有三种含义，此前文档混用，容易误判。现统一为三口径并写明核实方法：

| 口径 | 含义 | 数值 |
|---|---|---|
| ① 自有工具数 | 我们 `seep` MCP 暴露的 `@server.tool()` 函数 | **38**（可离线 grep，等于运行时 `tools/list`） |
| ② 单个外部 MCP | 四个外部服务各自进程的工具，由各自项目决定 | 约 100+（随版本）/ 23（v4.0.5）/ 随版本 |
| ③ 全工作台可见总数 | ① + 所有② | **不固定**，取决于装了哪些外部 MCP 与版本 |

- 修正 5 处**未经验证**的历史数字（原写 243 / 12 / 18）：实测本包内置的
  `ida-pro-mcp` 源码约 **100** 个 `@tool`、`js-reverse-mcp` 源码 **23** 个工具，
  故改为"约 100 / 23，以运行时 `tools/list` 为准"。
- `Tool/docs/MCP-SETUP.md` 新增「附：MCP 工具数到底怎么算」专节；
  明确**反臃肿预算（≤45）只约束"自有工具"**，与外部 MCP 无关。

## [1.8.3] — 2026-10-19

> 主题：**补上最后一块架构缺口（端到端链路验收），然后冻结。**

### 新增：`Tool/scripts/smoke-e2e.py`（端到端冒烟）

- **为什么**：体检 60 项 + 三套单测只证明"资产在位 / 单元正确"，**不证明链路连通**。
  弱模型真正会卡住的地方恰恰是"链条中段断了"（如：triage 出结果 → 判壳 → 反编译，中间某一环报错）。
- **做什么**：用 `Tool/samples/real/` 里的真实样本（自动挑最小），一次跑完 12 个环节：
  `auto_triage → 整文件哈希 → packer_detect → r2_info → r2_functions → decompile_auto →
   kb_search → task_init → gen_security_report → tool_discover`，
  全部在临时工作区（`SEEP_WORKSPACE`）执行，**不污染仓库**；约 13 秒；不联网、不依赖商业工具。
- **怎么用**：`python Tool/scripts/smoke-e2e.py`（`--sample` 指定样本，`--keep` 保留现场排障）。
- **接入**：`FORK-DELTA` §五 与 `BASELINE-FREEZE` 的验收闸门从"五道"扩为"六道"
  （体检仍 60 项不变，端到端独立一条）。

### 其它

- `VERSION` → **1.8.3**；技能 11 个 / 工具 38 个 / 预算全部在限内。

## [1.8.2] — 2026-10-19

> 主题：**脱壳闭环落地 + 差分台账（未来接手的 AI 只看一份文件）**。

### 新增技能：`unpack-loop`（脱壳与内存转储闭环）

- **为什么**：加壳软件是后续最高频的战场，而原先只有"判壳工具 + 手册"，没有一条走得通的闭环。
- **设计（关键：不固定步骤，固定判据）**：
  - **入口判定门**：壳类型 × 反调试强度 × 权威位置 → 三路线之一
    **A 可脱** / **B 只能运行期打补丁** / **C 建议放弃（转协议层）**；
  - **路线 A** 阶段图（判壳 → 反反调试 → OEP → dump → IAT → 校验 → 回主线），
    每阶段写死**完成判据**与**失败升级条件**，允许回退边，**不强制走完**；
  - **两次熔断**：同一阶段同类尝试失败 2 次 → 停手汇报，换路线；
  - **常见壳差异对待**：UPX 一行 `upx -d`、Themida 别死磕、**VMProtect 明确不追求静态脱壳**、
    .NET 混淆走 dnSpy/de4dot 而非 PE 脱壳思路。
- **接入**：`routing.json` 新增 R9（脱壳路由，priority 前移）；`softseep` 判型表「脱壳/解包」改为分发到本技能；
  技能数 **10 → 11**（仍在反臃肿上限 12 之内）。

### 新增文档：`Tool/docs/FORK-DELTA.md`（差分台账）

- **为什么**：未来接手的人/AI 不该把 4800 个文件重读一遍；上游更新后也要有依据判断"值不值得并入"。
- **内容**：一句话结论（纯超集 0 删除）→ 三类差分的判读法 → **能力差分台账**（工具/技能/配置/工程修复/证据类修复，
  逐条含"解决什么 + 文件位置 + 回滚方式"）→ **上游同步 SOP（5 步命令）** → **并入前五问评估表** →
  **5 个冲突高发区** → 五道闸验收 → 自动生成的文件级差分清单。
- **新增生成器** `Tool/scripts/fork-delta.py`：文件级差分由脚本刷新（手写部分只维护"为什么/值不值得/怎么撤"），
  **彻底避免台账过期**；无 `upstream` remote 时给出一次性配置提示。

### 修复

- 清掉误提交的两个临时审计脚本（`.tmp_linkaudit*.py`）。
- 技能数口径全仓统一（10 → 11）：`CLAUDE.md` / `DSH-PROFILE.md` / `DEPLOYMENT` / `DEPLOYMENT-CHECKLIST`（含 S11 行）/
  `PROVENANCE` / `install-pi.ps1` / `uninstall.*` / `BASELINE-FREEZE` 预算表。

## [1.8.1] — 2026-10-19

> **基线定档版（Baseline Freeze）**：本版之后骨架冻结，只做小步纯增量叠加。
> 规约见 [MANUAL/BASELINE-FREEZE.md](MANUAL/BASELINE-FREEZE.md)。

### 修复（P0：会静默毁功能 / 毁证据）

- **`security-audit-interceptor.ts` 拒答残渣清洗正则把正文碾碎**：原写法 `/[Safe Security Testing Flow]/gi`
  是**字符类**而非字面量，会把任意文本里每个 s/a/f/e/空格… 逐字符替换成 27 字符串面量。
  该 bug **继承自原版 upstream**（`upstream/main` 同一行）。现已用 `\[ \]` 转义 + 常量集中管理 +
  "不含标记则零误伤直接返回" 三重收口。
- **`seep_auto_triage` 只读前 50MB 算哈希**：>50MB 样本返回**截断哈希**（实测 126MB 文件 MD5 错成 `853b…`，
  真值 `8218…`）。已改为 1MB 分块**流式整文件**哈希，并加 `hash_scope: full-file` 字段。该 bug 亦继承自原版。
- **Linux/macOS 安装链生成的 `mcp.json` 是坏的**：旧实现用 `sed` 替换模板，导致
  ① seep 路径是 Windows 反斜杠（非 Windows 下文件不存在，核心 MCP 起不来）；
  ② `ida` 条目塞着未替换的 `<IDA_PYTHON>` 占位符且 `lifecycle=eager`；
  ③ 整文件覆写，用户自建 MCP 条目被清空且无备份。
  新增 `setup/merge_agent_config.py`（跨平台增量合并器：POSIX 路径、无占位符、只增不删、写前备份、备份轮转 3 份），
  `install.sh` 改走它，并顺带补齐 `settings.json` 的 packages 合并与项目级 `.mcp.json` 生成。
- **`install.sh` 在 `unzip` 返回 1 时整脚本中断**：`set -e` + `unzip` 对"反斜杠路径"只给 warning 但退出码非 0，
  导致 Linux 安装停在解压步骤。已显式兜住并提示。

### 修复（P1：承诺与实现不符）

- **`register_mcp` 无条件写仓库根 `.mcp.json`**：即使设了 `SEEP_AGENT_MCP`（测试隔离）也照写，跑一次自测就把
  测试工具写进**受跟踪文件**，并在仓库根堆出 36 个 `.bak-<时间戳>`。现在：设了 `SEEP_AGENT_MCP` 只写该目标；
  新增 `SEEP_SYNC_ROOT_MCP=0` 开关；备份自动轮转保留 3 份；已清理历史堆积的 36 个备份。
- **`uninstall` 会删用户自己的扩展**：旧实现无差别枚举 `~/.pi/agent/extensions/*.ts`（实测 dry-run 把用户的
  `cmd-guard.ts` 列入移除清单）。已改为**白名单**（只删 `Tool/prompts/extensions/` 里随包分发的 `.ts`），
  `uninstall.ps1` / `uninstall.sh` 同步修正。
- **`generate-configs.ps1` 与已提交的 `.mcp.json` 不一致**：生成内容缺 `ghidra`，跑一次 `install.ps1` 就产生 diff
  并丢掉条目。现已与仓库版本严格一致，并改为**内容相同则跳过写入**（幂等）。
- **`Tool/scripts/master-route.ps1` 一跑就 exit 2**：`configPath` 指向 `Tool/config/routing.json`，实际文件在
  `Tool/scripts/routing.json`。已修路径解析（含旧布局兜底）与技能落位解析（三种布局），输出不再硬编码 `skills/` 前缀。
- **`routing.json` 44 条路由全部指向不存在的技能**（vendor 自上游 reverse-skill 大仓的残留：mobile-reverse /
  firmware-pentest / pwn-chain 等本包均未内置，连 fallback R0 也解析不到）。已按**本包真实内置的 9 个技能**重写
  为 9 条路由（apkseep / client-license-validation-bypass / version-migration / ida-reverse / radare2 /
  mcp-js-reverse-playbook / reverse-engineering / apk-reverse / softseep 兜底），并新增可执行的
  `Tool/scripts/verify-routing-coherence.py`（routes ↔ priority ↔ fallback ↔ 技能落位 四重断言，已接入体检）。
- **`case-init` 生成的 scope/workitems 引用不存在的 `skills/ops/*`**：已改为指向本包真实文件
  （`MANUAL/POC-VALIDATION.md` / `Tool/skill/softseep/SKILL.md` / `Tool/scripts/case-init.ps1`）。
- **`seep_task_init` / `seep_gen_security_report` 把任务产物建进 `Tool/mcp/`**：已改为 `<仓库根>/work/`
  （或 `SEEP_WORKSPACE` 覆盖），并把 `/work/` 加入 `.gitignore`。
- **`seep_apk_gen_hook` 的 before/after 生成同一份脚本、`replace` + void 返回 `null`**：三时机语义已真正区分
  （before 前置观察 / after 后置观察 / replace 不调用原方法），void 时裸 `return;`，并按需生成 overload 块；
  模板缺失时优雅返回而不是抛异常。
- **`load-system-prompt.ts` 丢了上游的小写 `system.md` 支持**：二开重写时只认大写。已恢复为**上游超集**
  （项目级/用户级均做大小写变体探测，并兼容 `~/.pi/<name>` 老布局）。

### 修复（技能同名静默覆盖 —— 本轮审查新发现）

- **`safe-skills/ida-reverse` 覆盖了顶层 `ida-reverse`**：两者安装名相同，`install-pi.ps1` 按目录序
  先装顶层（1 文件的 IDA 全自动唤醒规约）再装 safe-skills（3 文件的辅助版），后者把前者**静默覆盖**——
  结果机器上 `~/.pi/agent/skills/ida-reverse` 里没有 **13337 端口全自动唤醒规约**，
  而体检只查"SKILL.md 在不在"，一直是假绿。
  - 处置：safe-skills 那份**改名 `ida-assistant`**（回归上游 DEPLOYMENT-CHECKLIST 原本设计的 S9 名称），
    两份共存 → 工作台技能数 **9 → 10**；
  - 安装器（`install-pi.ps1` / `install.sh`）加**同名冲突守卫**（子技能与顶层同名则跳过并告警）；
  - 体检加**功能性断言**：`ida-reverse/SKILL.md` 必须含 `13337`（防再次被覆盖后仍假绿）。

### 变更（去硬编码：换电脑 / 换盘 / 换目录都能用）

- **工具根目录改为动态生成**（`tool_autodiscover.candidate_roots()`）：
  环境变量 → 用户级（`~/.seep/tools`、`~/Tools`）→ Windows 用户级安装位置（`LOCALAPPDATA\Programs`、
  Android SDK、`APPDATA`）→ **各盘符常见目录名（动态枚举存在的盘，不预设 C/D/F）** → POSIX。
  原做法是写死 `D:\Tools` / `D:\Tool`，只对作者那台机器成立；现在任何人任意盘都能被扫到。
- **安装目标固定用户级** `~/.seep/tools`（可用 `SEEP_TOOL_INSTALL_DIR` 覆盖），不再往 `D:\Tools` 落盘。
- **扫描加预算**：12 万目录 / 20 秒上限，避免多盘大目录把 MCP 探测拖到超时。
- `seep_mcp_server.py` 的 `_TOOL_ROOTS`、`_find_java`、`_find_java_home`、tshark 探测同步去硬编码
  （改用 `JAVA_HOME` / `ProgramFiles` 等系统环境变量 + 动态根）。
- 文档与提示词同步：`MERGE-PLAYBOOK`、`ZERO-TO-HERO-WORKFLOW`、安装提示语不再出现单机盘符。

### 新增（防"把靶机搞崩"的硬约束）

- **提示词层（SYSTEM.md / AGENTS.md）新增「工具使用纪律」**：
  ① **禁止 `-h` / `--help` / 无参试探二进制**（商业软件/加壳软件/驱动一探就崩）；
     正确顺序 = `seep_tool_research` 读能力表 → 表外联网查官方文档 → 仍不确定就问用户；
  ② 路径一律动态探测，禁止写死盘符；交付物不得含单机绝对路径；
  ③ **动态操作预算**：同一目标同类动态尝试最多 2 次，第二次失败必须停下汇报。

### 新增（反臃肿预算）

- `MANUAL/BASELINE-FREEZE.md` 新增 §七「反臃肿预算」：数量硬上限（工具 ≤45 / 技能 ≤12 / setup ≤22 /
  MANUAL ≤16 / 单文件 ≤3200 行 / first-party ≤900 文件）、**三不原则**（不加框架层、同一能力只允许一个实现、
  不加并行状态）、**加功能前四问**。
- 新增 `Tool/scripts/check-budget.py`：一条命令核对上述预算，超限即非零退出。

### 修复（链路断点 —— 全仓断链审计发现）

- **`softseep/SKILL.md` 资源表 4 处路径指向不存在的目录**（调度时会「在外面乱转」的根因）：
  - `Tool/client-license-validation-bypass/SKILL.md` → `Tool/skill/client-license-validation-bypass/SKILL.md`
  - `Tool/safe/skills/` → `Tool/skill/safe-skills/`（并列出真实 5 个技能名）
  - `Tool/reverselab/kb/`（316 文件）→ `Tool/mcp/Tool/reverselab/kb/`（292 篇 .md）
  - `Tool/aotopsy/`（**该目录根本不存在**，上游也从未分发）→ 删除该行
  - 新增一行「运行时 `Tool/mcp/Tool/` 严禁搬动」提醒。
- **`ida-reverse` 措辞误导**：原文写「后台内置的 mcp-plugin.py / idapythonrc.py 会自动开启 13337」，
  但这两个文件**不随本包分发**（由 `pip install ida-pro-mcp` + IDA 内加载生成）。已改为明确来源 + 排障指引。
- **`apkseep` 两个孤儿参考文件**（`patch-audit.md` / `runtime-data.md` 存在但主 SKILL.md 未索引，
  等于模型不知道有这两套战术）→ 已补进症状索引表。

### 修复（工具发现 → 连通 → 使用 链路加固）

- **`x64dbg` 探测命中错误目标**：x64dbg 包内同时有 `x96dbg.exe`（GUI 启动器，会弹选择框）
  和 `release/x64/x64dbg.exe`（真调试器）。旧扫描把候选名并成一个集合一次 walk，
  会先撞上父目录的启动器 → 自动化被 GUI 卡死。已改为**按候选名优先级逐个全树扫描**，
  实测现在命中 `release/x64/x64dbg.exe`。
- **别名扩展**：`windbgx / windbgxp / ntsd / kd → cdb`、`pe-sieve64 / pe_sieve / pesieve → pe-sieve`、
  `flare-floss → floss`。
- **能力表 10 → 15 个工具**：新增 `x32dbg`（GUI + 同源 MCP）、`binwalk`（headless 提取）、
  `capa`（能力语义）、`floss`（解码字符串）、`pe-sieve`（内存 dump/篡改识别）。
  此前这 5 个都是「发现得到但不知道怎么控」。
- **安装表 20 → 22 项**：新增 `pe-sieve`（绿色便携包）、`binwalk`（pip），
  让「缺工具」有可执行答案而不是让模型现场手搓脚本。

### 新增（与 pi-web 回退功能协同）

- **`input` 钩子加幂等保护**：pi-web 的「回退 + 回填草稿」会把**已改写过的**用户消息（带合规前缀）
  放回输入框，重发时钩子会再跑一次 —— 正文里未被词表替换的触发词（逆向 / hook / patch / IDA / 收费…）
  会让整段再被包一层，变成 `[前缀][前缀]正文`。现在凡以本扩展横幅开头（`[合规安全测试与授权白盒审计任务`
  / `[授权白盒审计任务]` / `[环境体检任务]` / `[工作台极简看板请求]` / `[外挂技能自动化脚手架任务]` /
  `[实验工作环境已开启]`）的文本一律 `continue` 放行，绝不二次改写。

### 修复（跨平台一致性）

- **`verify.sh` 与 `verify.ps1` 对齐**：补齐「扩展资产功能自测（实跑）」「自动发现测试覆盖」两项；
  强化 KB（≥280 篇）/ cases（≥14 工程）/ softseep（≥8 refs）/ apkseep（refs + scripts）/ safe-skills（≥5）判定；
  新增「Pi Agent mcp.json 的 seep 启动路径可解析」「任务路由表自洽」两项功能性体检。
  **两平台现在同为 60 项全绿**（此前 Windows 58 / Linux 仅约 50 项且不实跑测试）。

### 清理

- 删除误提交的根目录垃圾文件 `提示词`（内容只是一句粘贴残留）。
- 清除两处作者本机绝对路径（`Tool/mcp/test_ext_assets.py`、`Tool/skill/version-migration/SKILL.md`），
  并把隐私门禁正则从"只认原作者昵称"扩展为"个人绝对路径（用户目录 / 个人项目目录形态，含反斜杠与正斜杠两种写法）"。
- `Tool/mcp/seep_mcp_server.py` 工作副本 CRLF 归位为 LF（与 `.gitattributes` 一致）。

### 文档数字口径统一（全仓）

- MCP 工具 **37 → 38**（README / README.zh / SKILL-CREATION-GUIDE / EXT-ASSETS / DEPLOYMENT-CHECKLIST 示例）。
- 体检项 **55/58 → 60**（check.ps1 / check.bat / README / DEPLOYMENT / SKILL-CREATION-GUIDE / CROSS-PLATFORM）。
- 扩展工具 **14 → 15**；扩展自测 **60 → 63**；中继单测 **44 → 84**；KB 示例篇数 **318 → 292**（真值）。
- `DEPLOYMENT-CHECKLIST` 版本 **v1.3.0 → v1.8.1**；技能表 S5-S9 改为真实存在的技能
  （删掉不存在的 `apk-diff` / `ida-assistant`，补 `version-migration`）；手册 8 → 12 份；案例 14 → 15 个工程。
- `HANDOFF-交接文档` 不再写死提交号（避免每次提交后过期），版本与数字同步到本版。

### 与上游（angusdevgo/Seep-Reverse-Lab）差异复核

- `git diff upstream/main -- Tool/mcp/seep_mcp_server.py` = **1298 行纯追加、0 删除**（宣称属实）。
- 相对上游**无任何文件级删除**（147 新增 / 39 修改，0 删除 / 0 重命名）。
- 上游继承的两个 P0（正则碾碎、50MB 截断哈希）本版已修 → **本版严格优于原版**。

## [1.8.0] — 2026-10-19

### 新增（任务A：轻量「工具自动发现 + 自动适配 MCP」小插件，全部纯增量）

> 定位：干活的 AI 缺工具时，**先搜本机 → 决定怎么控它 → 绝不卡住**。
> 设计铁律：**逻辑进仓库（小插件），发现状态留本机（`~/.seep/tools.local.json`，gitignore），绝不让 GitHub 变重**。

- **插件**：`Tool/mcp/tool_autodiscover.py`（可被 `seep_mcp_server.py` 以 import 调用，也可独立 CLI 运行）。
- **声明式能力表**：`Tool/config/tool-capabilities.json` —— 已知工具（IDA/x64dbg/cdb/Ghidra/r2/tshark/diec/jadx/apktool/frida）的「可执行/MCP/headless/GUI/CLI + 控制命令」全部写死。
  - ★ **判断依据全部来自联网检索（GitHub README / 官方文档 / MCP 生态），绝不用 `-h/--help` 现场试探二进制**（有些软件没 `-h`，一探就崩或返回错误码）。
  - **表外未知工具只报「路径已发现」，绝不假装能控**，并返回 `research_queries` 供联网检索后补表。
- **六层递进发现**：环境变量 → PATH → 常见安装目录 → **Windows 注册表「已安装程序」** → 递归扫描（带 deny 规则）→ 别名映射（`windbg→cdb`、`die→diec`、`radare2→r2`…）。
- **架构/版本匹配**：读目标 PE 的 `machine` 字段，32 位选 `x32dbg`、64 位选 `x64dbg`；IDA 区分 GUI(`ida`) / headless(`idat`)。
- **MCP 自动适配**：`register_mcp()` 增量写入当前 agent 的 `mcp.json`（**绝不删用户既有条目**、自动备份 `.bak-时间戳`、UTF-8 无 BOM），返回 `restart_required=True`（协议层死规矩：需重启会话生效）。
- **降级链（绝不卡住）**：已注册MCP → 现注册MCP(提示重启) → headless/CLI 直调 → GUI(不推荐) → 自写 Py 脚本兜底。走不通如实报。
- **半自动安装**：`propose_install()` 探测 → 给安装命令+来源 → 用户确认 → 装 → 重探；只对 `pip/winget/npm/go` 白名单执行，`manual` 永不自动。不做无脑全自动下载。
- **本机状态隔离**：发现结果写 `~/.seep/tools.local.json`（`.gitignore` 已忽略 `.seep/` 与 `tools.local.json`），换机各自缓存，永不入库。
- **6 个 MCP 工具（薄封装，末尾追加）**：`seep_tool_discover` / `seep_tool_control_plan` / `seep_tool_research` / `seep_tool_register_mcp` / `seep_tool_install` / `seep_tool_state`。
- **接入**：`softseep/SKILL.md` 新增「工具自动发现与自动适配 MCP（新增 6 个）」速查表。

### 全仓逐文件审查修复（任务B 扩展：脚本功能性 bug + 文档数字/版本全量对齐）

- **`setup/install-ida.ps1`**：修复 `$ToolDir` 变量未定义（真实 bug，导致无 `mcp.json` 时回退模板路径拼错）；已补定义。
- **`setup/update.ps1` / `setup/update.sh`**：修复**升级脚本把 origin 硬编码成原版 `angusdevgo/Seep-Reverse-Lab.git`** 的问题——fork 用户“更新工作台”会去拉原版仓库、把本地优化覆盖/回退。改为**以当前工作副本实际 origin 为准**（原版用户行为不变；无 origin 时回退 `SEEP_REPO_URL`，都没有则跳过而不指向错误仓库）。同时修 `update.ps1` 非 git 分支 `$proxyArgs` 未定义的老 bug。
- **`setup/verify.ps1`**：Python 解释器检测由“仅存在”改为**真执行 + 校验 >= 3.11**，避开 Windows Store `python3` 占位程序造成的假绿。
- **文档数字/版本全量对齐**（工具 23/31 → **37**；体检 52/51 → **55**；版本 v1.6/v1.7 → **v1.8.0**）：`README.md` / `README.zh.md`（badge、正文、MCP 矩阵补 6 个 `seep_tool_*`、英文版补“二开增强版”说明、Star History 指回 fork）/ `CLAUDE.md` / `MANUAL/DEPLOYMENT.md` / `MANUAL/DEPLOYMENT-CHECKLIST.md` / `MANUAL/CROSS-PLATFORM.md` / `Tool/docs/PROVENANCE.md` / `Tool/docs/EXT-ASSETS.md` / `Tool/docs/MCP-SETUP.md` / `Tool/docs/HANDOFF-交接文档.md`。

### 部署健壮性修复（任务B 从零部署审查发现并修好）

- **`setup/verify.sh`**：Python 探测改为「存在且能真正执行」——避开 Windows 上 Microsoft Store 的 `python3` 占位程序（存在但不运行、返回非零，会把自检误判为失败）。
- **`setup/verify.sh`**：修复 Radare2 检测项（原先直接 `command ... || test` 作为 `check_item` 的命令，`||` 会把 `test -f` 拆成参数导致永远判失败）；包成 `test_radare2()` 函数，现在内置 r2 能正确识别。
- **`setup/verify.sh`**：新增「工具自动发现插件」体检项（与 verify.ps1 对齐，Linux/macOS 也校验）。
- **`setup/install.sh`**：同上修复 Python 探测（真正可执行才用，否则回退 `python`），后续 pip 安装统一用 `$PY`。

### 体检

- `setup/verify.ps1` 追加 2 项：插件+能力表+状态不入库校验、自动发现功能自测。工具总数 31 → 37；核心检查 53 → 55 项。
- `test_ext_assets.py` 追加自动发现用例（6 层探测 / 能力表 / 表外不假装 / 降级链 / MCP 增量注册 / 架构匹配 / wrapper 存在性），32 → 60 项全过。
- `check.ps1` / `test_seep_mcp.py`(9/9) 基线保持不动。

---

## [1.7.0] — 2026-10-19

### 新增（扩展资产，源自 relab2 实战与 REA 降级思想，全部为纯增量）

> 定位：补齐原版在「资源层 / 内存层 / 协议层 / 加壳判型 / 工具发现」上的空白。
> 全部为**末尾追加 / 新增文件 / 插入段落**，不改任何既有函数体（相对原版 `seep_mcp_server.py` 净删除 0 行）。

- **协议层**：
  - `seep_http_replay()`：构造/重放 HTTP 请求，curl_cffi TLS 指纹伪装（chrome/safari/edge/ff）+ Cookie 会话保持 + 任意方法/头/体；无 curl_cffi 自动降级 requests。治协议签到/接口重放/回包验证。
  - `seep_pcap_extract()`：tshark 提取 pcap 端点 / HTTP 请求响应 / 指定端口 TCP 载荷。
- **资源/内存层**：
  - `seep_pe_resources()`：枚举 PE 资源树 + 节熵 + 容器嗅探（zstd/zip/pe），可选剥离。治“皮肤包/内嵌 DLL 藏在资源里”。
  - `seep_mem_strings()`：只读扫活体进程内存，提 ASCII/UTF-16 字符串 + 虚拟地址。治“运行期才解密”。
- **加壳/反调试**：
  - `seep_packer_detect()`：节名/节熵判壳 + 反调试导入 + 反虚拟机字符串，直接给“读 UNPACKING.md / ANTI-DEBUG.md 哪一节”的路由（把已有 190+188 行手册工具化）。
- **工具发现与反编译**：
  - `seep_ensure_tool()`：四级探测（env→PATH→map→scan，带 deny 规则），缺工具给 `install_plan`；`allow_install=True` 且方法在白名单才自动装。
  - `seep_decompile_auto()`：反编译入口（r2 保底 + 高阶引擎告知）。
- **Web 侦察（渗透轻量）**：
  - `seep_web_recon()`：只读侦察（响应头/技术栈指纹/安全头缺失/常见入口），不攻击；重型渗透走独立 MCP。
- **声明式配置**：`Tool/config/engine-tiers.json`（引擎降级链）、`Tool/config/tool-install.json`（按需下载清单）。
- **文档**：`Tool/docs/EXT-ASSETS.md`（资产说明）、`Tool/docs/MERGE-PLAYBOOK.md`（给未来 AI 的融合标准流程）。
- **接入**：8 个新工具已写入 `softseep/SKILL.md` 判型表 + 扩展工具速查表；协议工具接入 `license-validation.md §6`；判壳工具接入 `windows-sop.md Step 1`。
- **依赖**：`setup/install-python.ps1` / `install.sh` 新增可选依赖 `pefile / curl-cffi / zstandard / requests`（缺失时对应工具优雅降级，不阻断）。

### 体检

- `setup/verify.ps1` 新增一项“扩展资产在位”校验；工具总数 23 → 31；核心检查 50 → 51 项。

---

## [Unreleased]

### 新增

- **🌐 上游定点隔离同步与防外溢体系 (Zero-Spillover Upstream Sync)**：
  - 新增 `setup/upstream-rules.json`：声明式上游规则清单，严格绑定每个上游仓库的唯一目标目录与白名单边界。
  - 新增 `setup/sync-upstream.py`（纯标准库）：物理边界硬性断言 (`realpath` 严格前缀匹配)，上游 A 仓库更新只能并入 A 目录，绝对阻断跨目录外溢；保留本地定制文档。
  - 新增 `setup/sync-upstream.ps1` / `setup/sync-upstream.sh`：本地一键定点同步脚本，支持 `-Target`、`-DryRun`、`-CheckOnly`。
  - 新增 `.github/workflows/upstream-sync.yml`：云端定时巡检工作流，发现上游新提交自动按仓库切独立分支提 PR，Diff 严格限定在专属目录内。
  - 新增 `setup/test_sync_upstream.py`：防外溢熔断与路径越界安全单元测试套件（6 项全部通过）。
- **⚡ 下游使用者极简更新体验升级**：
  - 项目根目录新增 **`update.bat`** 与 **`update.ps1`**：双击即可全自动检测代理、安全暂存修改、无损增量拉取并跑完 52 项体检。
  - 增强 `setup/update.ps1` 与 `setup/update.sh`：新增 `-Check` / `--check` 轻量版本检查，支持非阻塞版本探测。
  - 体检系统升级至 **52 项核心校验**：全面覆盖上游规则与防外溢引擎在位状态。

### 变更

- **📦 项目D 案例更新至 v1.5.0**（跨版本补丁迁移 · 五版本 AOB 特征码）
  - 版本谱系由 3 个扩展到 **5 个**（新增 build 12 / build 15），位点偏移表与特征码表全面刷新。
  - 新增 **§8「静默自动更新 + 数据段填充漂移」**：记录官方内置更新器静默覆盖已打补丁主程序导致的授权失效链，
    以及数据段填充漂移使滑动汉明距离误命中（距离仅 2、位置早 2 字节）的陷阱与修正流程。
  - `docs/algorithm.md`：五版本指纹表、五版本位点偏移对照、新增 §3.2 填充漂移专项。
  - `tools/` 流水线脚本改为**基于脚本位置自动解析路径**，去除作者本地绝对路径。
  - 回归断言由 61 项扩充至 **89 项**（五版本端到端），并断言既有版本产物哈希零变化。
- **📚 知识库新增笔记**：`pe-reverse/10-license-keygen/10-multiversion-signature-narrowing.md`
  —— 多版本特征码收窄与数据段填充漂移陷阱（含三重确认流程与零回归断言清单）。

---

## [Unreleased]

### 新增

- **🌐 项目D 案例更新至 v1.6.0**（全栈中英双语国际化架构）
  - 纯代码内嵌双语字典（零 `.resx` / 零附属程序集），保持单源码 `csc.exe` 秒级编译。
  - 首启自动探测 `CultureInfo.CurrentUICulture`，非中文系统直接呈现专业英文。
  - 侧边栏 `[ 🌐 EN / 简 ]` 胶囊按钮实现毫秒级内存热重绘（保留 Tab 状态与控制台日志）。
  - 运行日志实时翻译层（`TranslateLog`）：115+ 条模式替换，覆盖 AOB 补丁 / ACL 冻结 / 备份归档全链路。
  - 回归断言由 89 项扩充至 **98 项**（新增 9 项国际化单元测试）。
  - 文档新增「全栈中英双语国际化架构」章节，含四项关键工程决策（为何弃用 `.resx`、为何热重绘而非重建、日志为何必须走翻译层、CLI 同步国际化）。

---

## [1.6.0] — 2026-10-11

### 新增

- **🔁 中继拒答自动重试**（`Tool/scripts/compliance-relay/refusal.py`）★
  - Gemini 对「命令式要求对具体目标执行攻击性分析」的请求会**静默拦截**：
    `HTTP 200 + {"choices": [], "usage": {"completion_tokens": 377}}` ——
    模型生成了 token 但内容被丢弃，**不报错、不提示**，异常处理根本捕获不到。
  - 中继现在会检测这类拒答，**自动换一种写法重发**，对客户端完全透明。
  - 策略级联（全部**保留用户指定的目标**）：
    `original` → `S1 评审清单式` → `S2 设计评审框架` → `S3 英文评审式`
  - 实测：原句被拦（377 tokens 丢弃）→ 改写后返回 **2611~3324 字**完整回答。
  - 支持非流式（OpenAI / Anthropic / Google 原生形状）与流式 SSE 两类拒答检测。
  - 性能保障：只缓冲到「可判定」为止（SSE 8KB / JSON 4MB），超出上限即视为肯定没被拦，直接透传。
  - 可配置：`relay-config.json` 中 `refusalRetry` / `refusalRetryAttempts`（默认开、3 次）。
  - 新增 **40 项单元与集成测试**（共 84 项全绿），含「上游先拒答再放行」的端到端验证。

### 变更

- `relay.py` 响应转发改为「缓冲到可判定 → 需要时重试 → 再透传」，
  非拒答的正常长回答仍为流式透传。

---

## [1.5.0] — 2026-10-11

### 新增

- **🔍 L1 可观测性日志**（`security-audit-interceptor.ts`）
  - 动机：L1 有两类**不会报错的失效方式** —— 对 OpenAI 兼容端点乱注入会 400；
    对「名字叫 gemini 但实际走 OpenAI 格式」的链路注入则**被中转静默丢弃**。
  - 设 `PI_SAFETY_LOG=1` 后，每次判定写入 `~/.pi/agent/logs/l1-safety.log`，
    判定分为 `INJECT` / `SKIP` / **`SKIP-INEFFECTIVE`**（名字像 Gemini 但形状是 `messages`，
    注入必然无效的告警）。日志超 512KB 自动截断。
- **🧪 Gemini 安全设置验证工具**（`Tool/scripts/check-gemini-safety.py`）
  - 用同一提示词分别以「不注入 / 注入 `BLOCK_NONE`」请求 Google 原生接口，
    对比 `finishReason` 给出**可证伪的结论**：有效 / 无法区分 / 无效。
  - 纯标准库，密钥仅从 `GEMINI_API_KEY` 环境变量读取，**绝不打印、绝不落盘**。
  - 支持 `--list-models` / `--model` / `--prompt`。
- **🗑️ 一键卸载脚本**（`setup/uninstall.ps1` / `setup/uninstall.sh`）—— 回应 Issue #8
  - 原则：**只移除工作台自己装的东西，绝不碰你的数据**
  - 移除范围：工作台自带的 9 大技能、`AGENTS.md` / `SYSTEM.md`、`extensions/*.ts`、
    `mcp.json` 中的 `seep` / `js-reverse` / `playwright`、工作台加入的 12 个 packages、`lab-mode.flag`
  - **永不触碰**：`models.json` / `auth.json` / `sessions/` / `logs/`、
    你自己添加的 Skill 与 MCP 条目、`settings.json` 的其他字段
  - MCP 条目采用**外科手术式**判定：只有 `args` 确实指向工作台组件时才认为归工作台所有
  - 支持 `-DryRun` 预览、逐项 `-Keep*` 保留、`-Purge` 深度清理、`-Restore` 反向恢复
  - 卸载前自动整体备份到 `~/.pi/agent/backup-uninstall-<时间戳>/`
  - 手册：[MANUAL/DEPLOYMENT.md — 卸载与回滚](MANUAL/DEPLOYMENT.md)
- **🔁 已有用户一键更新机制**（`setup/update.ps1` / `update.sh` + `VERSION` + 本 CHANGELOG）
  - 自动 `git stash` 保护本地改动 → `git pull` → 预览变更 → 备份 → 幂等增量同步 → 校验零丢失 → 全量自检

### 修复

- **🚨 安装/更新会静默覆盖用户 `mcp.json`（严重）**
  - 根因：`$raw.StartsWith([char]0xFEFF)` 在**无 BOM** 的文件上也会返回 `TRUE`。
    .NET 默认 `StartsWith` 使用**文化敏感比较**，而 `U+FEFF`（BOM 字符）是
    「可忽略字符」，等价于空字符串，因此**任何字符串都「以它开头」**，
    随后的 `Substring(1)` 便削掉了首个 `{`，把合法 JSON 破坏成非法。
  - 后果：`install-pi.ps1` 读取失败后静默回退到空配置，
    用模板**覆盖**用户 `mcp.json`，丢失自定义 MCP 条目（如 `ida`）与真实 Playwright token。
  - 修复：`install-pi.ps1`（mcp.json + settings.json）、`install-ida.ps1`、`update.ps1`
    共 4 处改为序数/字符比较。
- **🧩 3 个技能被 Agent 静默跳过**（Issue #6，由 @xiaozhi1218 报告）
  - 根因：`safe-skills/{apk-reverse,ida-reverse,radare2}/SKILL.md` 带 UTF-8 BOM，
    而 DSH 的 frontmatter 解析要求首行**严格等于** `---`，于是整条技能被静默丢弃（9 条只发现 6 条）。
  - 修复：`setup/clean-format.py` 新增 Markdown / JSON **剥离 BOM** 规则（`.ps1` 仍保留 BOM），
    并排除 `Tool/upstream/` 以保持上游镜像字节保真；共修复 8 个文件。
  - 新增门禁：`verify.ps1` / `verify.sh` 会阻断任何带 BOM 的 `SKILL.md`，防止回归。
- **🛑 Ctrl+C 退出时 MCP 子进程打印 KeyboardInterrupt 堆栈**（Issue #7）
  - `seep_mcp_server.py` 现在捕获 `KeyboardInterrupt` / `BrokenPipeError` / `EOFError` 静默收尾，
    并为 POSIX 注册 `SIGTERM` 处理器。
- **🔌 Gemini 私有字段被注入到所有 provider（由 PR #9 @linbei0 贡献）**
  - L1 底座级解封不再无差别写入 `safetySettings` / `config`，
    改为**仅对 Google/Gemini 端点注入**；OpenAI 兼容网关不再返回 `400 UNKNOWN_FIELD`。
  - 可用环境变量 `PI_SAFETY_PAYLOAD=off|all|auto` 覆盖（默认 `auto`）。
- **🍎 macOS / Linux 自动安装 radare2（由 PR #5 @iscodeminister 贡献）**
  - `setup/install.sh` 新增引擎探测：macOS + Homebrew 自动安装，其他平台给出清晰指引；幂等且非致命。
- **🔒 隐私门禁改为只扫描 git 跟踪文件**
  - 本地已 gitignore 的生成配置不再造成误报，同时更准确地反映「实际会发布的内容」。

### 变更

- `verify.ps1` 增至 **52 项**核心检查，`verify.sh` 增至 **51 项**。

---

## [1.4.0] — 2026-09-30

### 新增

- **🌐 链路层合规转译中继**（`Tool/scripts/compliance-relay/`）
  - 本机回环中继，在请求离开本机前把口语平滑转译为合规术语
  - 覆盖三种协议：`openai-completions`（Pi Agent 主力）、`anthropic-messages`（Claude Code）、`openai-responses`（Codex）
  - 纯 Python 标准库实现，**零新增依赖**；**零落盘**（日志只记命中条数）
  - 默认关闭，需显式运行 `python relay.py`；受 `lab-mode.flag` 门控，mtime 热加载
  - 手册：[MANUAL/COMPLIANCE-RELAY.md](MANUAL/COMPLIANCE-RELAY.md)
- **🔒 脱敏与个人隐私门禁**（`verify.ps1` / `verify.sh` 第 9 节）
  - 全深度递归扫描个人路径、身份标识、私有域名、凭据
  - 生成物追踪检查（含本机路径的配置文件不得入库）
  - 脱敏基准表 D1–D6 记录于 `MANUAL/DEPLOYMENT-CHECKLIST.md`
- **🖥️ 跨平台支持**（macOS / Linux）
  - 新增 `setup/install.sh`、`setup/verify.sh` 原生 Bash 脚本
  - `seep_mcp_server.py` 自动探测系统 `radare2` / `rabin2` 与各平台 JDK 路径
  - 手册：[MANUAL/CROSS-PLATFORM.md](MANUAL/CROSS-PLATFORM.md)
- **📖 部署与校验体系**
  - `MANUAL/DEPLOYMENT.md` 全景部署手册（含 4 大 Agent 接入 SOP 与排障 FAQ）
  - `MANUAL/DEPLOYMENT-CHECKLIST.md` 官方基准核验清单（单一真值源）
  - `verify.ps1 -Detailed` 输出结构化基准校对看板
- **📦 案例库扩充至 14 个**（项目 A ~ 项目 N）
  - 新增 项目M（Java + install4j 双层鉴权）、项目N（.NET x64 + VM 混淆加固）

### 变更

- **⚙️ 安装脚本重构为幂等 + 无损模式**
  - `install-pi.ps1` 改为**增量合并** `mcp.json` / `settings.json`，不再覆盖用户自定义 MCP
  - 所有 JSON 配置统一以 **UTF-8 无 BOM** 写入，修复 Node.js `JSON.parse` 报错
  - 路径统一转为正斜杠，修复 Windows 反斜杠导致的 JSON 非法转义
- **🛡️ 安全审计扩展双加固**（`security-audit-interceptor.ts`）
  - 新增 25 项 `INJECTED_PREFIXES` 上下文守卫：Agent 自注入的环境 / AGENTS.md / 技能清单**不再被误改写**
  - 顺序 `replace` 改为**单趟最长优先匹配**：算法保证「绕过会员」优先于「绕过」，且替换产物不回扫（杜绝级联污染）
- **🔍 IDA Pro 探测强化**（`install-ida.ps1`）
  - 支持 `-IdaRoot` 参数、注册表探测、交互式输入自定义路径
  - 支持 IDA 9.x 原生 `idalib_supervisor` 模块模式
- **🔗 上游镜像归位**
  - `apk-reverse`、`open-tgtylab`、`open-reverselab` 三大开源项目完整镜像至 `Tool/upstream/`
- **⚖️ 许可证更正为 GPL-3.0**
  - 因整合了两个 GPL-3.0 上游项目，整体许可证由 MIT 更正为 **GNU GPL-3.0**

### 修复

- 修复 Windows PowerShell 5.1 下 `Set-Content -Encoding UTF8` 写入 BOM 导致 Node.js JSON 解析崩溃
- 修复 Windows 路径反斜杠未转义导致的 `Bad escaped character in JSON`
- 修复 `install-pi.ps1` 全量覆盖导致用户自定义 MCP（如 x64dbg）被抹除
- 修复 IDA 路径写死 `D:\Tool\IDA Pro`、非标准安装位置无法识别
- 修复 Bash 脚本 CRLF 换行污染导致的 `bad interpreter` 报错（13 个脚本）
- 修复 70 个 PowerShell 脚本缺失 UTF-8 BOM 导致的中文乱码与语法解析中断

### 安全

- **清理个人隐私与凭据残留**（发布前强制门禁）
  - 移除全部个人绝对路径、个人身份标识、私有中转站域名
  - 移除案例中残留的真实产品名 / 厂商域名 / **真实加密 Salt**
  - 含本机路径的生成物（`opencode.jsonc`、`cordis.generated.yml`）不再入库
  - 中继运行配置 `relay-config.json`（含访问 token）纳入 `.gitignore`

---

## [1.3.0] — 2026-09-28

### 新增

- 案例库扩充至 13 个（新增 项目L Qt5 C++、项目M Java + install4j）
- `seep_r2_xrefs` 工具：交叉引用查询，内置分页与统计摘要
- 上下文预算控制：`seep_r2_decompile` 支持 `fold`（省 ~60% Token）/ `summary`（省 ~90%）

### 变更

- `MANUAL/` 战术手册扩充至 6 份

---

## [1.2.0] — 2026-09-26

### 新增

- `MANUAL/ANTI-DEBUG.md`：反调试绕过字典与代理 DLL 框架
- `MANUAL/UNPACKING.md`：UPX / MPRESS / Themida / VMP 脱壳 SOP
- `MANUAL/POC-VALIDATION.md`：Frida 自愈循环与 PoC 沙箱验证

### 变更

- `verify.ps1` 升级为 7 大维度体检

---

## [1.1.0] — 2026-09-25

### 新增

- `check.bat` / `check.ps1` 根目录一键体检入口
- `setup/verify.ps1 -Detailed` 结构化基准校对看板
- 部署完备性校验体系（7 大维度）

---

## [1.0.0] — 2026-09-24

### 新增

- 首个公开版本
- 9 大逆向 Skill（`softseep` 总控 + `apkseep` + `ida-reverse` + `safe-skills` 5 组）
- 自研 `seep` MCP 服务（23 项原生工具）
- 289+ 篇攻防知识库
- 9 个脱敏工业案例范式（项目 A ~ 项目 I）
- Lab Mode 磁盘状态机与三层防拒体系

---

## 更新类型说明

| 变更类型 | 含义 | 用户需要做什么 |
|---|---|---|
| **新增** | 新功能、新工具、新案例 | 跑一次更新脚本即可 |
| **变更** | 行为或接口调整 | 建议读一下具体条目 |
| **修复** | 缺陷修复 | 跑一次更新脚本即可 |
| **安全** | 安全或隐私相关 | **强烈建议立即更新** |

> **兼容性承诺**：本工作台的用户自有数据（`models.json`、`auth.json`、自定义 MCP 条目、
> `lab-mode.flag`）在更新过程中**永不被覆盖**。若某次更新需要用户手工干预，
> 会在对应条目中显式标注「**需要手工操作**」。
