# FORK-BRIEF —— 给「外部审查模型」的交接书

> **你是谁、该干什么**：你被要求审查并优化本仓库。它是某个上游项目的**二开（fork）**，不是原创项目。
> 本文是**唯一交接事实源**：身份、差异、需求、契约、已知债务、以及「哪些文档不能当现状」。
> 读完本文 + 跑一遍第 9 节的门禁，你就能在不误解的前提下给出可信报告。
>
> 版本基线：`v1.26.1`｜门禁实测：`preflight 55/55`、`domain-gate --all 110/110`、`verify 65/0`、`smoke-e2e 12/12`
> 权威交接台账：`docs/RELEASE-1.26.1.md`（做了什么 / 每条证据 / 剩余项）
> 若你是被请来做**只读审查**的：直接看 `docs/AUDIT-REQUEST.md`（权限边界 + 只读命令白名单 + 报告必答项）与 `docs/AUDIT-REPORT-TEMPLATE.md`（报告骨架）。**不要修改仓库。**

---

## 0. 一页速览

| 问题 | 答案 |
| :-- | :-- |
| 这是什么 | 面向**客户端授权白盒审计 + 二进制/Web/移动/固件逆向**的「AI 作战系统」：技能 + 配方 + 能力 + 门禁 + 知识库 + MCP 工具链 |
| 从哪来 | 上游 `angusdevgo/Seep-Reverse-Lab`（本仓 `origin` = `gthubtom1/Seep-Reverse-Lab`，`upstream` 已配置） |
| 规模 | 31 个技能 / 11 个域 / 24 篇配方 / 51 个能力 / 34 条路由 / 412 篇 KB / 53 个案例 / 40 个 MCP 工具（seep 服务） |
| 形态 | 纯本地、可离线；自带工具链（radare2 / jadx / apktool / frida 模板）约 565MB |
| 设计哲学 | **判据优先、反造假**：每条结论必须能在 `case_state` 里证明；写不出可机检判据的内容不进技能 |
| 现在状态 | 功能完整，门禁全绿；有 14 条**已登记债务**（第 8 节），无「假装完成」的项 |

**阅读顺序（按这个顺序读，不要跳）**：
1. 本文（FORK-BRIEF）
2. `docs/RELEASE-1.26.1.md` —— 本轮交付台账（做了什么 / 证据 / 剩余）
3. `docs/history/X-DOMAIN-SPEC-v2.md` —— 域契约（九件套）
4. `docs/UPSTREAM.md` —— 与上游的差异口径与吸收纪律
5. `docs/DEFERRALS.md` —— 延迟项 + **明确不做**（含理由）
6. `ROADMAP.md` —— 现在能做什么 / 下一步
7. 需要细节时再看 `docs/QUICKSTART.md` 与各域 `SKILL.md`

---

## 1. 身份、来源与许可

- **上游**：`https://github.com/angusdevgo/Seep-Reverse-Lab`（remote 名 `upstream`）。
- **本仓**：`https://github.com/gthubtom1/Seep-Reverse-Lab`（remote 名 `origin`）。
- **许可**：GPLv3（`LICENSE`，34KB 原文，未修改）。
- **二开原则**（`docs/UPSTREAM.md` §2）：只做**单文件 cherry-pick**，不整仓 merge；每次同步按「五问」评估；共享文件（routing / gate / spec / README）只在主分支改。
- **同步状态（2026-10-22 快照）**：仅上游有 140 条 / 仅本仓有 1015 条 / 两边都有但内容不同 82 条 / 相同 273 条。
  口径与复跑命令见 `docs/UPSTREAM.md` §1（`python Tool/scripts/upstream-delta.py --print`）。

---

## 2. 我们加了什么（相对上游）

按「能干什么」分类，**每条都给可复现的验证命令**。不要凭 README 的宣传语判断，跑命令。

| 类别 | 加的东西 | 怎么验 |
| :-- | :-- | :-- |
| **门禁层（最大差异）** | `preflight.py`（45 项）、`domain-gate.py`（域深度 110 项）、`capability-gate.py`、`playbook-check.py`、`skill-route-probe.py`、`mcp-param-contract.py`、`intent-coverage.py`、`check-budget.py`、`case_state.py`（案子账/深度门/出口闸） | `python Tool/scripts/preflight.py`、`python Tool/scripts/domain-gate.py --all` |
| **判据化域（11 个）** | 每域九件套：判据表 / 失败判据表 / 模型坑 / 走查 / 脚本（`--help`+`--self-test` 双绿）/ 案例（≥1 real）/ KB / 矩阵 / 任务卡 / 路由片段 | `python Tool/scripts/domain-gate.py --domain <域>` |
| **五阶段流水线** | `00-analysis`（先摸透再动手）→ `01-gate-bypass`（旁路卡密）→ `02-ui-rebrand`（改 UI 去品牌）→ `03-license-hookup`（接自有授权）→ `04-version-migrate`（跨版本追版）→ `05-backend-rebuild`（T2/T3 才触发） | 各 `Tool/skill/0*/SKILL.md` + `case_state.py` 闸 |
| **MCP 工具层** | 23 → 40 个工具（pcap / 资源雕刻 / 内存字符串 / 加壳识别 / web recon / 多引擎反编译 / 六层工具发现 / 案例检索）；**统一路径参数别名**（8 个名字互通） | `python Tool/scripts/mcp-param-contract.py`、`python Tool/scripts/smoke-e2e.py` |
| **反造假机制** | `case_state.py` 拒绝不存在的证据路径；`gate` 要求 D0–D5 全 pass + ≥2 条候选路线 + ≥2 种仪器；`deliver` 按 M1–M4 分级，越级被拒 | `python Tool/scripts/case_state.py --help`、`case_state.py prove --evidence <不存在路径>` 会 rc≠0 |
| **能力/配方层** | 51 个能力（DAG，悬空 0）+ 24 篇可跑配方（命令进闸，`--help` 实跑校验） | `python Tool/scripts/capability-gate.py --json`、`python Tool/scripts/playbook-check.py` |
| **知识库** | 412 篇（含 `field_journal_*` 现场日志、`_archive/` 归档索引）；检索走 MCP `seep_kb_search` | `python Tool/scripts/kb_acceptance.py` |
| **外部技术库吸收** | 用户桌面 Pentest 技能库按「好用就融」处理：MIT 部分重写吸收；`offensive-*` 79 篇建索引（`kb/_archive/pentest-checklist/`）；6 篇课程转录不收 | 读 `docs/UPSTREAM.md` §6 |

**量化（本轮 36 个提交，基线 `41fcc4f` → `8242dbf`）**：94 个文件变更，+11743 / −263 行。

---

## 3. 为什么要加这些（用户需求 → 设计目标）

这是**审查时的判断依据**：偏离下列目标的设计就是问题，符合的就是有意为之。

1. **核心业务**：对客户端软件的**授权/卡密/激活**做白盒审计并交付可用成品（CWE-602 类：客户端信任了不该信任的判定）。
2. **交付形态**：不是"报告写完就完"，而是"产物能用"——旁路 → 改品牌 → 接自有授权 → 追版，四个阶段各有出口闸。
3. **覆盖广度**：Windows/PE、Android、Web/JS、iOS/macOS、固件/IoT、内网/AD/云、协议、插件、供应链、LLM/Agent、站点复刻，共 11 域，每域要能**独立开打**。
4. **可信性（最重要）**：模型容易"看起来很懂"——所以全仓的硬约束是**可机检判据** + **证据落地** + **反造假闸**。任何"大概/通常/可能"式结论，必须有判据或标 `hypothesis`。
5. **跨模型稳定**：同一套技能/路由/门禁要给不同模型（强/弱）用，所以：路由有探针（39 条大白话）、工具有别名（不必猜参数名）、文档有单一事实源（避免各说一套）。
6. **可维护**：新增能力走"注册表 + 门禁 + 配方"，不靠堆脚本；文档数字由机器对账，不靠人记。

---

## 4. 不可破坏的契约（改之前必须知道）

| # | 契约 | 位置 | 破坏后果 |
| :-- | :-- | :-- | :-- |
| C1 | 路由**单一事实源**是 `Tool/scripts/routing.json`；片段改 `Tool/config/routing-fragments/*.json` 后必须 `python Tool/scripts/merge-routing-fragment.py --write` | `verify-routing-coherence.py` / `merge-routing-fragment.py --check` | 路由静默失效、`domain-gate` 串味测试红 |
| C2 | 域契约（九件套）：SKILL ≤600 行；references 6–10 篇、每篇 60–400 行；脚本 2–4 个且 `--help`/`--self-test` rc=0；KB 6–10 篇；矩阵 ≥12 条；任务卡 20–30 张；链路无孤儿 | `docs/history/X-DOMAIN-SPEC-v2.md` + `Tool/scripts/lib/domain_spec.py` | `domain-gate` 直接红 |
| C3 | 计数**单一事实源**：`（已删除：数字口径取消）`（preflight 条数、MCP 工具数基线）；first-party 预算口径 = `git ls-files` | `check-budget.py` / `check_numbers()` in `preflight.py` | 文档数字对账红 |
| C4 | 技能必须与部署目录哈希一致（`~/.pi/agent/skills`） | `domain-gate` 部署项 | 换机后行为不一致 |
| C5 | PowerShell 脚本必须 **UTF-8 with BOM**；文档换行 LF | `check_ps_encoding()` | PS 5.1 解析失败 |
| C6 | 案例证据必须真实存在（`case_state.py prove` 校验路径）+ sha256 可复算 | `Tool/cases/` + `domain-gate` | 反造假机制失效 |
| C7 | MCP 主服务 `Tool/mcp/seep_mcp_server.py` ≤3200 行（体积预算） | `check-budget.py` | 门禁红 |
| C8 | 路径参数必须支持 8 个别名（`binary_path` / `target_path` / `apk_path` / `file_path` / `sample_path` / `artifact_path` / `pcap_path` / `dir_path`），且主参数不出现在 `required` | `mcp-param-contract.py` | 模型一次调错就退回手搓 |
| C9 | 措辞 lint：技能/提示词/文档里不写任务禁令式表述（scope 由用户声明） | `check_language()` | 门禁红 |
| C10 | 禁止把机器专用绝对路径写进脚本/技能（用 `~`、`%VAR%`、`shutil.which`） | `check_portable()` | 换机即坏 |
| C11 | 新增脚本/文件会改变 first-party 计数，必须同步 `MANUAL/BASELINE-FREEZE.md` | `check_numbers()` | 「文档数字 vs 实测」红 |
| C12 | 上游文件（`Tool/upstream/`）与内置工具链（`Tool/mcp/Tool/safe/`）**不是本仓源码**，不要按业务代码审查 | `.gitignore` / 预算排除 | 会写出错误结论（把第三方代码当我们的缺陷） |

---

## 5. 明确不做（不要把这些当"缺失"提改进建议）

| 项 | 决定 | 理由 |
| :-- | :-- | :-- |
| 无线近场升独立域 | 不做 | 域契约要求 ≥1 个 real 案例 + sha256；本机探针实测 `monitor_capable=false`（无硬件），升域只能得到空壳。现形态：R22 路由 + `hardware-interfaces.md` 无线章 + `probe_matrix.py --radio-only` 探针 |
| `00-analysis` 纳入九件套 | 不做 | 它是阶段技能，产物是报告 + 裁定；硬套矩阵/案例会与自身产物重复计量 |
| C2 武器化 / 课程转录（6 篇 5.6 万行） | 不做 | 与本仓「可复现判据 + 取证」定位正交；转录内容与 `pwn-crypto` 重叠 |
| 把全部 236 篇外部技能原样并入 | 不做 | 会撑成第二个素材库；已按「重写成判据表」的方式吸收 10 篇高价值内容，其余建索引（`kb/_archive/pentest-checklist/`） |

---

## 6. 文档地图：哪些是**权威**，哪些是**历史**（最容易误解的地方）

### 6.1 权威（当现状读）

| 文件 | 作用 |
| :-- | :-- |
| `docs/RELEASE-1.26.1.md` | 本轮交付台账（做了什么/证据/剩余），**审查入口** |
| `docs/history/X-DOMAIN-SPEC-v2.md` | 域契约（九件套判据） |
| `docs/UPSTREAM.md` | 与上游差异、吸收纪律、许可分层 |
| `docs/DEFERRALS.md` | 延迟项 + 明确不做 |
| `ROADMAP.md` | 现在能做什么 / 下一步 |
| `docs/CHANGELOG.md` | 版本变更（顶部为最新） |
| `MANUAL/*.md` | 部署、卸载、提示词分层、BASELINE 冻结口径 |
| 各域 `Tool/skill/<域>/SKILL.md` + `references/` | 该域判据与方法（**以文件为准，不以 README 摘要为准**） |

### 6.2 历史（**不是现状**，不要拿来判缺陷）

| 文件 | 性质 | 为什么会误导 |
| :-- | :-- | :-- |
| `docs/history/AUDIT-2026-10-21.md` + `docs/history/audit/*` | v1.19–v1.25 多轮审查台账（R1–R8） | 里面有「门禁 41 项」「first-party 823」「38 项」之类旧口径，与今天不同 |
| `docs/history/audit/A.md … E.md`、`CLOSURE.md` | 早期审计报告与闭环记录 | 它们描述的是**当时**发现的问题；部分已修、部分转 DEFERRALS |
| `docs/history/OPTIMIZATION-2.0.md` | v1.25 之后的一次优化清单 | 条目多以「待做」语态写；实际已完成大半，见 RELEASE 台账 |
| `work/plans/优化方案*.md` | 用户本地规划笔记（gitignored，**不进版本库**） | 是过程稿，非规格；clone 下来不会存在 |
| `docs/PROMOTION.md` | 「三次规则」晋升流程说明 | 流程文档，不是能力清单 |

### 6.3 本地运行产物（gitignored，审查时忽略）

`work/`（案子与临时产物）、`.pi/`（目标状态与本地会话元数据）、`evidence/`（本地产物目录）、
`__pycache__/`、`.pytest_cache/`。

### 6.4 仓内但**不是本仓业务代码**

| 目录 | 是什么 |
| :-- | :-- |
| `Tool/upstream/{apk-reverse,open-reverselab,open-tgtylab}/` | 三份上游镜像，仅用于差分溯源 |
| `Tool/mcp/Tool/safe/`（约 565MB） | 内置工具链二进制（radare2 / jadx / apktool / node_modules） |
| `破甲卡生成/`（123 个文件） | **用户另一个侧项目**（jailbreak 人设卡生成器），按用户要求同仓备份；不在 seep 引擎的审查范围，也不参与预算计数 |

---

## 7. 已知债务（供审查模型重点看，每条都可复现）

| 编号 | 债务 | 影响面 | 复现/证据 |
| :-- | :-- | :-- | :-- |
| DEBT-01 | MCP 参数别名层依赖 FastMCP 对 `__signature__` 的处理 | 升级 `mcp` SDK 可能失效 | `python Tool/scripts/mcp-param-contract.py` |
| DEBT-02 | `race-probe.py` 的竞态结论按「账本差值」判定，不是内核级语义 | 对"中间态可回滚"的系统可能误判 | `--self-test` 22+34 项；`h2-race-e2e.py` 双档对照 |
| DEBT-03 | `h2-race-e2e.py` 只覆盖明文 h2c，无 TLS/前置代理 | 真实目标可能「打不出时间窗压缩」 | `docs/RELEASE-1.26.1.md` §8 |
| DEBT-04 | `ad-repro.py --kind edge-fingerprint` 只用离线 fixture 验证过 | 真实设备指纹可能漏判 | `--fixture Tool/cases/ad-cloud01/input/edge-fingerprint.json` |
| DEBT-05 | `osint-h1-ref.py` 依赖 HackerOne 非公开 GraphQL schema | schema 变动时退化为 client-filter | `--self-test`（19 项，离线样本） |
| DEBT-06 | 无线判据未在真实硬件上实跑 | 判据正确性未经现场验证 | `probe_matrix.py --radio-only` |
| DEBT-07 | 仓库约 959MB（内置工具链 565MB + `.git` 250MB） | clone / CI 成本高 | `du -sh . Tool/mcp/Tool/safe .git` |
| DEBT-08 | `apkseep` 132 个文件 / 2.4MB，单域体量过大 | 认知负担、模型上下文压力 | `ls Tool/skill/apkseep | wc -l` |
| DEBT-09 | KB 是**冻结基线**（新知识走案例/配方，不往 KB 灌） | KB 可能落后于最新技术 | `MANUAL/DEPLOYMENT-CHECKLIST.md` K1 |
| DEBT-10 | 部分 reference 逼近 400 行上限（`ad-cloud/references/ad-attacks.md` 398、`web-pentest/references/06-auth-and-api.md` 396） | 再加内容必须先压缩旧段落 | `python Tool/scripts/domain-gate.py --links`（篇幅断言） |
| DEBT-11 | x64dbg 走 http(9094)：宿主晚于会话启动时本轮拿不到工具 | 调试流程多一步 `/mcp reconnect` | `python Tool/scripts/mcp-doctor.py --session` |
| DEBT-12 | `破甲卡生成/` 与主项目耦合低但同仓 | 审查者易误判为"无关代码" | 见 §6.4 |
| DEBT-13 | 历史审计文档与新口径并存（`docs/AUDIT.md` 等） | 数字误读风险 | 见 §6.2 |
| DEBT-14 | 路由探针覆盖 36 条口吻，尚未覆盖全部 34 条路由 | 新口吻可能掉兜底 | `python Tool/scripts/skill-route-probe.py` |

---

## 8. 审查指引（只读）

### 8.1 先跑这四条（不跑就下结论 = 报告不可信）

```bash
python Tool/scripts/preflight.py                # 期望 55/55
python Tool/scripts/domain-gate.py --all        # 期望 110/110
python Tool/scripts/smoke-e2e.py                # 期望 12/12（真调 9 个 MCP 工具）
powershell -File setup/verify.ps1 -Detailed     # 期望 65 项 / READY
```

### 8.2 你的权限：只读（**这份仓库不接受第三方直接改动**）

外部审查员的唯一交付物是**报告**。写文件、删文件、装依赖、改配置、改 git 状态一律不做——
否则「门禁全绿」就分不清是原本就绿，还是被改绿的。

- 只读委托书（权限边界 + 命令白名单 + 报告必答 10 问）：`docs/AUDIT-REQUEST.md`
- 报告骨架（逐字段填）：`docs/AUDIT-REPORT-TEMPLATE.md`
- 想验证但必须写文件才能验证的：**不验证**，写进报告的「不确定项」，说明需要什么条件。

### 8.3 只读审查期间不许做的事

1. 任何写入：`edit` / `write` / `patch` / 重定向 / `sed -i` / 生成文件进仓库
2. 任何 git 状态变更：`add` / `commit` / `checkout` / `reset` / `stash` / `clean` / `push` / `merge` / `worktree add`
3. 安装依赖：`pip install` / `npm i` / `winget` / `go install`
4. 安装/部署/卸载脚本：`setup/install*.ps1`、`setup/update.ps1`、`setup/uninstall.ps1`、`Tool/scripts/tool-run.ps1`、`Tool/scripts/mcp-doctor.py --fix`
5. 改动 `~/.pi/agent/`（提示词、技能部署目录、`mcp.json`、settings）
6. 删除或移动仓库内任何文件
7. 访问外部网络目标（审查阶段只跑离线/回环）

### 8.4 改动由谁实施

改动**只由项目方**（仓库所有者）按报告逐条实施。审查员在报告里给出：
「改哪个文件第几行 → 改成什么 → 为什么 → 改后能改良什么 → 风险 → 验收命令 → 工作量」，
**只写不实施**。项目方实施时走 `docs/AUDIT-REQUEST.md` 之外的另一条通道：

1. 改文件 → 2. `python Tool/scripts/domain-gate.py --domain <域>`（10/10）→
3. `python Tool/scripts/preflight.py --fast`（全绿；新增文件要同步 BASELINE 实测值）→
4. `python Tool/scripts/preflight.py`（55/55）→ 5. `docs/CHANGELOG.md` 顶部补一条 → 6. 提交（写清"改了什么/为什么/证据"）。

### 8.5 常见误解（审查时逐条自查）

| # | 错误理解 | 正确理解 |
| :-- | :-- | :-- |
| 1 | "`docs/AUDIT.md` 写门禁只有 41 项，所以现在也只跑 41 项" | 那是 v1.25 快照；现在 45 项，以 （已删除） 与实跑为准 |
| 2 | "README 说 11 域，但 wireless 没有独立 SKILL，所以是缺失" | 无线是**有意不做**独立域（§5），能力在 firmware-iot + R22 |
| 3 | "`race-probe` 报 `ok:true` 说明没漏洞" | `ok` 只表示结论可信；漏洞看 `vulnerable` / `reproduced` |
| 4 | "`seep_auto_triage` 说命中鉴权关键词，所以一定有" | 看 `auth_related_strings_sampled` 与 `next_actions[0]`，文案不再无条件断言 |
| 5 | "`Tool/upstream/` 里的代码有缺陷，是项目缺陷" | 那是上游镜像，不是本仓源码（C12） |
| 6 | "`破甲卡生成/` 是主项目功能" | 用户侧项目，同仓备份（§6.4） |
| 7 | "工作目录 `work/` 里有半成品，说明项目没做完" | 本地运行产物，gitignored（§6.3） |
| 8 | "工具参数随便传，rejected 就说明工具坏了" | 8 个别名互通；拿不准先 `describeTool()`（C8） |
| 9 | "文档数字和实测不一致 = 项目坏了" | 这是门禁要抓的缺陷；按 §8.4 的流程对齐，不要手改数字掩盖 |
| 10 | "把判据写成'通常/一般/可能'更通用" | 违反设计哲学（§3.4）；判据必须可机检，否则标 hypothesis |
| 11 | "KB 只有 412 篇，比上游的 183+ 少/多" | 口径不同：本仓含 field journal 与归档；以 `kb_acceptance.py` 与索引为准 |
| 12 | "加一个更强的模型就能自动修好所有债务" | 债务里 DEBT-03/04/06 缺的是**硬件或授权目标**，不是模型能力 |

---

## 9. 术语表

| 词 | 含义 |
| :-- | :-- |
| 域（domain） | 一个可独立开打的方向（如 web-pentest），必须满足九件套契约 |
| 配方（playbook） | 可复跑的命令序列（`Tool/playbooks/*.md`），命令会被 `playbook-check` 实跑校验 |
| 能力（capability） | 声明式能力单元（`Tool/capabilities/*.json`），带脚本/参考/成熟度，可 `compose` |
| 判据 / 失败判据 | 可机检的成立条件 / 什么现象就该停手换路 |
| proven / hypothesis / refuted / stale | `case_state` 里事实的四种状态；`deliver` 只认 proven |
| M1–M4 | 交付等级（M1 分析结论 → M4 全链复刻），越级被 `deliver` 拒绝 |
| R0–R36 | 路由编号；R0 是兜底（总控判型） |
| D1–D26 | 延迟项编号（`docs/DEFERRALS.md`），其中 D21/D26 已定为"不做" |
| 九件套 | 域契约的九个必备件（SKILL/refs/scripts/cases/KB/matrix/任务卡/链路/路由） |
| SSOT | 单一事实源：`routing.json`、（已删除）、`DOMAIN-SPEC-v2.md` |

---

## 10. 一句话给审查模型

**先跑门禁、再读台账、最后才看代码；把"历史文档"和"明确不做"排除掉之后，剩下的才是真缺陷。**
你的报告如果出现"README 说…所以…"这类推理，请改成"实测命令输出 → 结论"。
