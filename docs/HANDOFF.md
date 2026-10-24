# HANDOFF —— 接手必读（防上下文压缩后失忆/漂移）

> 写这份的原因：会话上下文已用到 ~86%，压缩会丢细节。**任何人（包括我自己压缩后）从这一份就能接着干，不需要读聊天记录。**
> 最后更新：2026-10-24 09:55（写于 S1 执行之前）

---

## §0 三分钟上手顺序

1. **本文**（你在读）
2. `docs/BLUEPRINT.md`（272 行）—— **唯一架构口径**，五步迁移 + KPI
3. 需要证据时再翻：`work/audit/A1-local.md` / `A2-upstream.md` / `A3-rea.md`
4. **不要**再按 `docs/history/X-PLAN-FINAL.md` 走 —— 它已被 BLUEPRINT 取代（见 §2）

**一句话现状**：方向已从"继续加"改成"先减法"，Blueprint 写好、52/52 绿，**S1 还没开始**。

---

## §1 现在到底在哪

| 批次 | 状态 |
| :-- | :-- |
| P0 / P0.5 / P1（12 项）/ P2（5 项）/ P3（两个 M3 成品）/ P4（除人设卡）/ P5 / P6 | ✅ 完成 |
| 用户决策：人设卡**维持原样**（实测去重会削弱破甲）、派活工具**只给主对话**、GUI 交互**改由 Agent 自己做** | ✅ 已定 |
| 三仓库深度解剖（本地 / 上游 / REA） | ✅ 完成，四份报告落盘 |
| **架构重置 S1–S5** | ⬜ **没开始** |

---

## §2 权威文档（防止两套方案打架）

| 文档 | 角色 | 状态 |
| :-- | :-- | :-- |
| **`docs/BLUEPRINT.md`** | **唯一架构口径**（域包形状 / 7 个全局脚本 / 9 个闸 / 4 个状态文件 / S1–S5 / KPI） | ✅ 现行 |
| `docs/history/X-PLAN-FINAL.md` v6.2 | 上一代"逐批修"方案 | ⛔ **已被 BLUEPRINT 取代**，只作历史 |
| `docs/history/X-PLAN-v7-GAPS.md` | 审查挖出的 6 个缺口（G1–G6） | 🟡 **只有 G1/G4 现役（→S2/S3）；G2/G3/G5/G6 标 DEFERRED**，见该文件顶部横幅 |
| `docs/PLAN-SUMMARY.md` | 进度台账（每批打勾） | ✅ 仍有效，只记"做过什么" |
| `work/audit/A1/A2/A3-*.md` | 三仓解剖的原始证据 | ✅ 只读，结论的出处 |
| `docs/history/X-ARCH-RESET.md` | 上一版草案（R1–R4 迁移） | ⛔ **SUPERSEDED，R1–R4 勿执行**（目标值全不同：它说 ≤40/索引≤10，BLUEPRINT 说 7/9） |
| `docs/AUDIT-METHOD.md` | 六种"假完成"模式 + 五道审计 | 🟡 §一–§五仍有效；**§八/§九 的"数字由脚本同步"已被 BLUEPRINT 反转** |

---

## §3 硬事实（带复算命令，别凭记忆）

| 事实 | 数字 | 复算 |
| :-- | --: | :-- |
| 常驻注入 | 29,415 tok（人设 7,451 + AGENTS 3,614 + SEEP 624 + 技能索引 2,809 + 边界 234 + 宿主 14,683） | `python Tool/scripts/prompt-budget.py` |
| 强制语句 | 57 条（临界 20） | 同上最后一节 |
| `Tool/scripts` | **106 文件 / 36,103 行**（跟踪 87 / 29,399 + 未提交 19 / 6,704） | 跟踪：`git ls-files Tool/scripts \| xargs wc -l \| tail -1`；含未提交：`find Tool/scripts -type f \| wc -l` |
| 其中未提交 | **Tool/scripts 内 19 文件 / 6,704 行**；全仓 untracked **102 文件 / 26,566 行** | `git status --porcelain -uall` |
| `preflight` | 52 项，**12 项打不红** | `python Tool/scripts/preflight.py --fast` |
| 技能 | 32 个（19 个零样本，4 个无路由） | `ls -d Tool/skill/*/ | wc -l` |
| 路径叶子 | 27 条，**3 条有真样本** | `python path-walk.py(S1 已删)` |
| 状态文件 | 20 个，8 组重复副本 | 见 A1 §3.1 |
| MCP | 40 工具，**76 会话 4,536 toolCall 里调用 0 次** | 见 A1 §6/§8.1 |
| 上游 | 1,828★ / 13 脚本 / 5 技能 / 45 条路由全死 / `master-route` exit 2 | `work/audit/A2-upstream.md` |
| REA | 373,415★ / 221 工具 / 无 agent loop / `unknown` 不计 pass | `work/audit/A3-rea.md` |
| 成品 | 2 个 M3：`golden-crackme`（无壳）、`leaf-pe-packed`（UPX） | `Tool/cases/*/artifacts/*.patched.exe` |

---

## §4 用户已拍板（不可推翻，别再问）

| # | 决策 | 依据 |
| :-- | :-- | :-- |
| 1 | **人设卡维持原样（28,667 B / 7,451 tok / 36 条）** | A 方案实测破甲探针 BA2/BA3 从 2/2 掉到 1/2 → 已回滚。**这 7,451 tok 是承重的** |
| 2 | **派活工具只给主对话**；子代理拿不到 `Agent`（pi-web 强制 `excludeTools`，改不了） | P5-D 实测 |
| 3 | **GUI 交互由 Agent 自己做**（截图/找坐标/点击/输入），**只有"凭据字符串"和"物理动作"才问用户** | 用户明确要求；`01a1685a` 的 `guictl.py` 已证明可行（`clicked 127 683 -> 603 894`） |
| 4 | 问人**只用对话内 A/B/C**，弹窗已被 `cmd-guard` 拦截 | 用户多次强调 |
| 5 | 顺序只认权威文档，不许临时另立顺序 | 用户明确要求 |

---

## §5 待执行：S1–S5（详细到可派活）

### S1 · 只删不加（**3h，第一步，不要跳**）

**删**：
1. 12 个打不红的门禁（清单见 BLUEPRINT §3.2）—— 含 `gate-counts.json`、`sync-gate-counts.py`、文档里所有 `N/N`
2. 4 个孤儿脚本：`apk/frida-run.sh`、`apk/rebuild-sign-install.sh`、`circuit-selftest.mjs`、`lib/BootstrapSupplyChain.ps1`
3. 5 个兼容壳：`adcloud-check.py`、`forensics-check.py`、`fw-triage.py`、`plugin-triage.py`、`pcap-summary.py`
4. 8 个 APK 全局重复脚本（`Tool/scripts/apk/*`），保留 `Tool/skill/apkseep/scripts/*`
5. 9 个一次性脚本 + 生成器 7 个（`gen-case-index.py`、`new-skill.py` 等）
6. 6 个重复状态文件副本（`memory/facts.jsonl`、`memory/events.jsonl`、`events.jsonl`、`state.json`、`ai_manifest#seep`、`cases/index.json`）
7. `Tool/scripts` 内 19 个未提交文件 / 6,704 行（**只删本节点名的；其余 untracked 一律 commit，见 BLUEPRINT §3.3**）

**例外（必须反向：改成提交）**：`Tool/cases/leaf-apk/`、`Tool/cases/leaf-pe-packed/`、`Tool/cases/_p2fixture/`（2 个绿色叶子的 fixture 来源）、以及 `preflight.py`/`prompt-budget.py`/`mcp-launch.py`/`canary.py`/`path-walk.py`/`liveness-check.py`/`session-manifest.py`/「path-tree.json」(S1 已删)/`seep-circuit.ts`/`seep-events.ts` 与全部权威文档。

**S1 的完整删除清单以 `BLUEPRINT.md` §3.2–§3.4 为准，本节不重抄。**

**判据**：① `preflight --fast` rc=0 且项数 52→**≤47**；② `git status --porcelain Tool/scripts` 的 untracked = 0（其余 untracked 一律 commit）；③ `grep -r "gate-counts\|sync-gate-counts"` = 0；④ 无脚本 import 已删文件（`python -m compileall Tool/scripts`）。

⚠️ **顺序陷阱**：`preflight.py` 第 1105、1141、1175 行硬依赖 `path-walk.py`/`liveness-check.py`/`session-manifest.py`。**必须先改 preflight 去掉这三处依赖，再删这三个脚本**，否则判据①永远不成立。

### S2 · 杀 fail-open（1 天）
`seep_gen_security_report` / `seep_auto_triage` 无证据则拒绝；返回超限改 `resource_constraint`（不截断）；`unknown` 不计 pass。
**判据**：空参调报告生成器 → `ok:false` 且 `reports/` 新增 0 文件；`grep -c "TRUNCATED\|\[Success, no output\]"` = 0。

### S3 · 立包与闸（2 天）
8 个 `pack.json` + `SKILL.md ≤3KB` + `gate.py`/`route.py`；索引 32→9；`ad-cloud` 进 `_pending/`。
**判据**：`gate.py --all` 每包有绿或红、`unknown→pass`=0；`route.py --index` 死路由=0。

### S4 · 全局收口（1 天）
`Tool/scripts` → 7 个；状态 → 4 个；`tool-effects.json` 登记（缺一条 server 起不来）；工具面 40→16。
**判据**：`ls Tool/scripts/*.py | wc -l`=7；状态文件**种类**=4；删任一登记 → `import seep_mcp_server` 非 0。

### S5 · KPI 回放（1 天）
3 个靶（`crackerjack/a.exe`、`leaf-pe-packed`、`leaf-apk/diva.apk`）+ 1 个真实目标，填 `KPI.md`。
**判据**：表 3+1 行填满；任一行 `fail`/`unknown` → 不发版。

---

## §6 已知陷阱（今天踩过的，别重复）

1. **`load_extensions: true` 会让 profile 的工具白名单失效** → 子代理会拿到 bash/edit/write。要收窄工具面就必须 `false`，但 `false` 就没有 `cmd-guard`。二者不可兼得（实测）。
2. **`ask_user_question` 被 `cmd-guard` 拦截** —— 这是有意的，问人走 `case_state.py ask/ack`。
3. **`mcp.json` 变更必须重启会话**才生效；扩展 `.ts` 变更热加载。
4. **`mcp-handshake` 的 codeHash 对 5 个 server 取的是同一个 `mcp-launch.py`** → 改一行 5 个全 DRIFT（粗粒度）。
5. **`gen-case-index.py` 会硬编码 `"repro": {}`** 把真实 repro 抹掉 —— 这是 index.json 与 case.json 分叉的根因，S1 删它。
6. **`path-walk` 的 witness 只是"非空字符串"** —— 写"用户真机验证"就能过，是假检查。
7. **L3（MCP 0 调用）被 `liveness-baseline.json` 永久豁免** —— 别以为它是绿的。
8. **删门禁看起来像退步** —— 每次删都要在同一 commit 附 BLUEPRINT §3.2 的表。
9. **`compliance-relay/refusal.py` 有 2 个测试文件**，是仓库**唯一有测试的运行时**，删东西时别连带删掉。
10. **别再写新脚本**。105 → 7 是目标；任何新脚本要能回答"它测的东西我自己会不会给出不同答案"。

---

## §7 防漂移规则（写死）

1. **顺序唯一**：S1→S2→S3→S4→S5。不跳、不换序、不临时加批次。
2. **只在 BLUEPRINT 里改口径**，其它文档只许引用，不许各自再写一套。
3. **任何"完成"必须答三问**：谁触发 / 怎么看见生效 / 失效会看到什么。
4. **任何新增（脚本/技能/规则/契约）必须先有 KPI 前后对比**，没有就不加。
5. **主对话只做四件**：读台账 / 写决策 / 派子代理 / 问人（对话内 A/B/C）。
6. 每批收尾跑：`preflight --fast` + `prompt-budget`（当前基线 52/52、14,732）。**`liveness-check` 已由 G9 取代，S1 之后不再跑**。

---

## §8 如果只能做一件事

**做 S1。** 理由：
- 3 小时，只删不加，风险最低；
- 它砍掉的正是"元层的元层"（12 个自证门禁 + 8 个元脚本）—— 这是"越优化越差"的发动机；
- 做完如果五连验收仍全绿 → 就证明今天加的大部分是负债，方向对；
- 如果不做 S1 就直接做 S2/S3，`sync-gate-counts` 会把门禁数反向锚定，删不干净。

---

## §9 需要用户动作（目前只有一个）

**重启一次会话**（让 playwright 的 `--headless` 与 `seep-manager` profile 生效）。其余全部可由 Agent 完成。
