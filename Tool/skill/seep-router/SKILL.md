---
name: seep-router
description: "还不确定这属于哪个领域时先读我/初步分析这个/先判断能不能做/该走哪个方向/我该准备什么/能不能去广告改会员 (.exe/.apk/.html/.bin/.pcap/.img 任意载体)。只做思考层：判型 → 选域 → 给上限 → 说缺什么 → 指路到具体领域技能。任何任务的第一步都先过这里。"
license: MIT
---

# seep-router —— 思考层（判型 / 选域 / 上限 / 缺什么）

> **本技能只做判断，不做具体手艺。** 判断完立刻按下面的表去读对应领域技能。
> 事实只有一处：**档位的唯一权威是 `Tool/config/levels.json`**（对外四句 + 内部代号映射）；本文件只负责「用户怎么说 → 落到哪个域」与必问三件，不重定义档位；每域的具体达标判据见该域 SKILL.md，不在这里重复。

路径约定：运行指引中以 `Tool/` 开头的路径相对已注册的源码根（Agent 目录下 `seep-runtime.json` 的 `source_root`），读取时展开成绝对路径。正式技能可按宿主技能名加载；`Tool/skill/_pending/` 中的材料是归档参考，只能按源码路径按需读取，不把旧名称当作已部署技能，也不把归档流程设为所有任务的前置。

## 上限怎么说（对客户）

- **只能看懂结构**：`只能先告诉你这是什么载体、有没有保护、关键判定在本地还是服务端——这还是一句判型结论，没落到任何一域的方法上`
- **能改到能用**：`改完能跑、原功能还在、原件没动`（见 REQUIREMENTS.md §2）
- **能完全自己接管**：`混合载体也能拆开：主域 + 辅域分派写明，上限与停手条件一次说清，降级时主动通知你而不是静默降档`
- **卡点通常是**：`判型两轮仍矛盾（两个域都像、各自证据都立得住），或关键判定在服务端/硬件——这时只能停下来让你二选一（BLK-10 证据不足：「我没法下结论」）`

> 依据：本文件 §第 1 步判型三问 / §第 3 步给上限（一次封顶；内部档位见账本）/ §什么时候停（BLK-10 证据不足、降级通知）

## 第 1 步 · 判型三问（30 秒内必须回答）

1. **用户要得到什么，材料是什么载体**（目标决定主域，扩展名/魔数/容器提供材料证据；不能只凭后缀选域）
2. **有没有保护**（壳/加固/混淆/加密/签名校验）
3. **关键判定在哪**（本地文件 / 注册表 / 服务端 / 硬件）

> 只做**零风险只读探测**（哈希、大小、魔数、头信息）。**不许**为了判型就运行它、解包它、改它。

## 第 2 步 · 载体 → 域（选完立刻读该域 SKILL.md）

| 载体 / 场景 | 去读 |
| :-- | :-- |
| `.exe .dll .sys .so .elf .dylib`（含 .NET/Go/Rust/Electron-PC/Unity-PC/wasm） | `Tool/skill/softseep/SKILL.md` |
| `.bin` 单独出现 | **不能按后缀判域**：先读目标/魔数/上下文；PC 可执行或裸二进制走 `softseep`，固件包或设备镜像走 `firmware-iot`，pcap 走 `protocol-plugin` |
| `.apk .aab .xapk .dex`、Unity-Android / IL2CPP 改包 | `Tool/skill/apkseep/SKILL.md` |
| `.html .php .har`、URL/网站/API 的渗透验证或整站复刻 | `Tool/skill/web-pentest/SKILL.md` |
| `.js`、前端 JS 混淆/签名算法/补环境/浏览器 Hook 的持续逆向 | `Tool/skill/softseep/SKILL.md` |
| `.img .trx .squashfs .ubi`、固件包、路由器/摄像头/NAS | `Tool/skill/firmware-iot/SKILL.md` |
| `.pcap .pcapng .proto`、私有协议、封包构造 | `Tool/skill/protocol-plugin/SKILL.md` |
| 二进制利用 / 密码学（栈堆溢出、ROP、RSA/AES/PRNG） | `Tool/skill/pwn-crypto/SKILL.md` |
| `.vmem .raw .dd`、iOS IPA/Mach-O、证书/钥匙串 | `Tool/skill/forensics-mobile/SKILL.md` |
| 可疑样本（任意载体，要判"是不是病毒"） | `Tool/skill/malware-analysis/SKILL.md` |
| 仓库/依赖/CI/制品签名 | `Tool/skill/supply-chain-security/SKILL.md` |
| 已加壳/虚拟化/反调试 | 先读主域；Windows PE 需要脱壳时加 `Tool/skill/unpack-loop/SKILL.md`，Android 留在 apkseep 的解壳参考，ELF/Mach-O 留在 softseep 的平台方法 |

**跨域很常见**：先读主域，再按当前缺口读辅域；例如 Android JNI 算法由 apkseep 主导、softseep 辅助。交接带材料/符号位置、已证与未知、需要回答的问题；结果回到同一项目/版本/run，不另起无关任务或强走全部阶段。
**判不出载体**：只问一个区分性问题（"这东西能直接运行，还是一堆文件？"），不猜。

## 配方（照这个跑）

输入面命中下面某行时，先照该配方的命令序列跑，再回来对判据；配方正文只在 playbooks 一处，本文件只指路。

- 多账号批量执行器（池 / 限速 / 幂等 / 通知）→ `Tool/playbooks/multi-account-runner.md`
- 青龙面板多账号签到与定时任务 → `Tool/playbooks/qinglong-signin.md`
- 开工前的逆向测绘与可行性裁定 → `Tool/playbooks/reverse-survey.md`

## 第 3 步 · 给上限（唯一口径，四句话）

| 级 | 客户语言 | 依据门槛 |
| :-: | :-- | :-- |
| M1 | **只能看懂结构** | ≥1 条 E1 观察 |
| M2 | **能改到能用** | 改动类结论 ≥E2（命令+期望+跑过两次一致） |
| M3 | **能完全自己接管** | 关键结论 ≥E3（交叉验证）或 E4（端到端） |
| M4 | **能完全自己接管**（客户话同 M3） | 端到端 E4（两路以上真跑目标）+ 复查单可照做（M4 是内部最高档，客户话不另加词） |
| — | **现在做不了** | 必须给 BLK 码 + 两条出路 |

> 「能改到能用」的统一含义就是 REQUIREMENTS.md §2 的「改完能跑、原功能还在、原件没动」；每域的具体判据见该域 SKILL.md 的『上限怎么说（对客户）』—— 本表只做统一命名，不重新定义。

**按具体结论封顶**：当前目标依赖的授权、服务端、硬件、运行、明文或证据不可得时，标明受限动作和上限。静态报告、数学求解或只读清单可以按其自身验收完成；不因未运行/未改包一律判整个任务失败，也不能借报告完成声称未验证的成品可用。

**承诺不可回收**：先说了 M2 后来只能 M1 ⇒ 必须发降级通知（`case_state.py downgrade`），不许静默降级。

> 别的域若用 T/L 等其它刻度，一律换算回 M 级再对客户说。**不向客户抛代号**。

## 第 4 步 · 核对三件（仅当前路线确实需要且上下文缺失时问）

| 序 | 问什么（客户语言） | 为什么问 |
| :-: | :-- | :-- |
| 1 | 许可 / 凭据：这个需要卡密、账号或加密狗吗？你有吗？ | 有→可做在线校验对比；没有→只能离线判定或止步 M1 |
| 2 | 运行许可与环境：允许在本机运行吗？有可回滚的虚拟机/快照吗？ | 加密/加固目标不运行拿不到真代码；但运行有系统副作用 |
| 3 | 样本完整性：有完整原件/现成抓包/一次真实请求响应吗？ | 不完整时任何结论都不可信 |

**选项必须写"选了会怎样"**（`A 有 → 走在线对比，能到 M2` / `B 没有 → 走离线，最多 M1` / `C 我不确定 → 我先查有没有校验痕迹`）。
**不弹窗**：只在对话里列，客户回一个字母。用 `case_state.py ask` 落账。

## 第 5 步 · 指路（判断完必须做）

1. 读对应域 SKILL.md（上表）
2. 有目标材料且需留下成果或接续的新任务，用 `project_workflow.py start --project <成果目录> --target <材料> --quote <用户原话> --primary-domain <主域> [--aux-domain <辅域>]` 登记项目、版本与运行；已有项目先 `status`，不重新 start。参数由 Agent 填，不问用户内部字段。单案专业结论仍用 `case_state.py`，不能代替项目登记。
3. 首答四要素自检：`case_state.py answer --template`；Pi 需要首答通行证时先 `init --case <案目录> --target <原件>`，再 `answer --check --case <案目录>`。无案的 adhoc 自检不是通行证。
4. 卡住时按码出失败五段：`case_state.py block --code BLK-1`（没工具）—— 编号与客户话只能取自 `Tool/config/blockers.json`，本文件不自写含义
5. 将实际输出通过 `act` 或 `project_state.py evidence` 绑定当前版本/运行；交付前按实际结果登记验收、`close`，用 `project_report.py` 生成并复查报告，再保留白话专业结论。独立单案交付做 `report --check` + `recheck`；仅为宿主首答绑定而建的 case 不重复项目报告/验收。只写普通 Markdown 不等于项目完成；无法登记时说明哪一步未完成，不自造另一套状态文件。

> **项目任务的默认编排入口（不替代本文件的判型）**：
> 判完域之后要「建项目 → 登记路线 → 执行 → 记账 → 验收」一次跑完时，用
> `python Tool/scripts/project_workflow.py classify|start|act|status|close`。
> 它只做编排：判型仍以本文件为准，主/辅域并列时它会把 `ambiguity` 交回主 Agent 决定，
> `act` 只跑审核过的只读映射动作（执行前必过 `manager_state.py check-action`，
> 执行后 capture 原始输出并由 `project_state.py evidence` 登记证据）。
> 范围：`enforcement_scope=workflow-entry-only` / `globally_enforced=false` ——
> 直接调 MCP、直接 `tool-run.ps1 -Run` 或在别的会话执行都不经过它。
> 具体参数先查各脚本 `--help`；项目、证据、报告与接续操作见 `MANUAL/WORKBENCH-USAGE.md`。
> 单个命令失败只说明该命令失败：例如 `rg` 崩溃先换文件工具列读，并用无副作用的 `python -c "print(1)"` 核对执行通道。文件检索失败不表示 Python 项目登记工具也失效；通道确实不可用才记录阻挡。

## 停手条件（命中即停，别硬做）

| 条件 | 动作 |
| :-- | :-- |
| 同一路线失败 2 次 | 换路线或出报告（禁止第 3 次同样尝试） |
| 需要改系统级配置/装驱动/装反作弊 | 停，说明原因，给两条替代 |
| 需要客户手里的东西（卡密/账号/狗/设备/抓包） | 停，列 A/B/C |
| 需要运行目标而这会加载内核驱动 | 停，先要客户明确同意 |
| 上限已降到 M1 但仍被要求"做出成品" | 说明天花板原因，不硬撑 |

## 不做什么（防止变成第二个"万能技能"）

- 不写具体域的方法论（那是各域的事）
- 不复制各域的判据表（只指路）
- 不在这里定义证据等级/结论等级之外的东西（证据分级见各域与 `case_state.py`）

## 子技能（按需读，不常驻）

判断完、选定域之后，需要时再读这些（都在 `Tool/skill/_pending/`，不占常驻上下文）：

- `Tool/skill/_pending/00-analysis/SKILL.md`
- `Tool/skill/_pending/00-triage/SKILL.md`
- `Tool/skill/_pending/01-gate-bypass/SKILL.md`
- `Tool/skill/_pending/02-ui-rebrand/SKILL.md`
- `Tool/skill/_pending/03-license-hookup/SKILL.md`
- `Tool/skill/_pending/04-version-migrate/SKILL.md`
- `Tool/skill/_pending/05-backend-rebuild/SKILL.md`
- `Tool/skill/_pending/ad-cloud/SKILL.md`
- `Tool/skill/_pending/binary-diff/SKILL.md`
- `Tool/skill/_pending/doc-hygiene/SKILL.md`
- `Tool/skill/_pending/ida-reverse/SKILL.md`
- `Tool/skill/_pending/llm-security/SKILL.md`
- `Tool/skill/_pending/plugin-targets/SKILL.md`
- `Tool/skill/_pending/pm-plan/SKILL.md`
- `Tool/skill/_pending/signin-automation/SKILL.md`
- `Tool/skill/_pending/site-clone/SKILL.md`
- `Tool/skill/_pending/version-migration/SKILL.md`

## 什么时候停（判废条件）

命中任一条，就地停手并按 `case_state block --code BLK-n` 渲染失败五段，不许往下猜。

**编号的唯一来源是 `Tool/config/blockers.json`**：本文件不自己写含义，只引用它的标题
（最后一栏就是 `blockers.json` 的 `name`，客户话取同一个码的 `customer`）。

| 现场情况 | 用哪个码 | 码的标题（= blockers.json 的 name）/ 客户话 |
| :-- | :-: | :-- |
| 目标拿不到（路径不存在 / 只有截图 / 只有文件名） | `BLK-0` | 目标不可读/无授权 ——「我没拿到东西 / 这事我不能做」 |
| 判型两轮仍矛盾（两个域都像，各自证据都成立） | `BLK-10` | 证据不足 ——「我没法下结论」，把两条候选写进 plan 让人选 |
| 需要的仪器/工具本机没有且无法替代 | `BLK-1` | 没工具 ——「我缺个工具」 |
| 必须真机或特定版本环境（设备/版本调试器） | `BLK-3` | 需硬件/环境 ——「需要一台设备或特定环境」 |
| 关键判定在服务端/硬件，手上没有 | `BLK-5` | 关键在服务端 ——「关键的东西在服务器上，不在你手上」 |
| 缺卡密 / 账号 / 密钥 / 授权 | `BLK-4` | 需凭据/许可 ——「需要账号、密钥或授权」 |
| 要改系统级配置 / 装驱动 / 做破坏性动作 | `BLK-6` | 需要破坏性动作 ——「要做这步得冒风险」 |
| 用户明确限制「不运行 / 不联网 / 不装工具」而路线依赖它 | `BLK-7` | 我不被允许做 ——「这条我不做」 |

- 同一"错误形状"连续两次失败 → 熔断（`seep-circuit`），停下来报告已试过什么

判废 ≠ 失败结论：写清「我做到哪一级（M1–M4）+ 缺什么」比硬凑一个结论有用。
