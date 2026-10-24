# BLUEPRINT · Seep-Reverse-Lab 架构重置

> 依据：`work/audit/A1-local.md`（我们）/ `A2-upstream.md`（上游 angusdevgo，1828★，2026-10-24 API 实测）/ `A3-rea.md`（REA，**373,559★**，同源实测）。
> 代码副本：`work/audit/refs/{upstream,rea}`。文中 `(A1 §5.3)` 指该报告章节。
> 口径：一切数字可复算；不可复算的数字不写进本文。

---

## §0 一句话诊断

**上游 13 脚本能用，是因为它的坏代码不在因果链上；我们 105 脚本更差，是因为每个坏门禁都在因果链上，系统性地把"没验证"签成 PASS。**

### 三条根因

**R1 · 耦合点在全局层，不在领域层。**
上游加一个领域 = 加一个技能目录（`softseep` 路由矩阵只有 4 列，A2 §2）；我们加一个领域要同步 8 处（`domain_spec.py` / `seep-start.py` / `domain-gate.py` / `playbook-domains` / `path-tree` / taskcard / `routing.json` / 部署）——`05-backend-rebuild` 已经掉队（A1 §5.1 #17）。
门禁体量 11,117 行 = 全仓第二大模块（A1 §2）。**能力越多，全局层越重；全局层越重，能力越难用**（A1 §8.1：常驻 29,415 token 对 4,536 次 toolCall 里 `read SKILL.md` **0 次**）。

**R2 · 技能是"写出来的"，不是"提炼出来的"。**
32 个技能里 19 个零样本；27 条路径叶子只有 3 条有真实样本，其中 2 条来自未提交目录（A1 §4、§7）。
技能正文 475,225 B，进索引的只有 9,094 B（1.9%），而 76 会话 4,536 次调用中 `SKILL.md` 被 read **0 次**。
→ 索引带来的是**选择噪声**（32 选 1 vs 5 选 1），不是能力。

**R3 · 闸长在元层且多副本已分叉，所以闸只能自证。**
52 项里 21 项是存在性/计数/枚举；**12 项打不红**（A1 §5.3）：
- `#46` canary 的记录是 `--record` **人工填**的，且 results 里有 2 条 `status:"executed"` 却仍报"护栏全拦"
- `#43` 的基线把唯一真实失效项 L3 永久豁免（`liveness-baseline.json`）
- `#44` 没有 manifest 直接 PASS
- `#42` 24 ≤ 24 等号通过
同时 8 组状态副本已分叉：`gen-case-index.py:43` 硬编码 `"repro": {}` → case.json 50/56 有 repro，index.json 55/55 全空；18.6% 脚本（6,704 行）只存在于未提交工作区。

### 那上游凭什么还能跑？

A2 已证实上游同样有：`seep_gen_security_report` 零证据默认文案、`seep_auto_triage` 模板结论且 >50MB 哈希是错的、`seep_r2_cmd`/`disasm` 无界返回、**45 条路由目标全不存在**、`master-route.ps1` 实跑 exit 2。

它还能跑，因为四个结构性差异：

1. **它的坏代码不在因果链上。** 路由链第一跳就断，但 `case-init.ps1:198` 用 `2>$null | Out-Null` 吞掉失败，而模型的真实路径是"读 SKILL.md → 照表执行"（A2 §5：驱动者**模型 ≈95%、代码 ≈5%**）。坏掉的路由不承担职责，所以坏得无害。**我们的 52 个门禁全部宣称"已验证"**，坏一个就静默删除一条保证。
2. **判据密度换可靠性。** 它不写编排代码，把经验压成照念的门与表（G0–G6 / G1–G4 / 13 问 / "done 六条" / 每条约束自带机检命令）。判据写在**动作发生处**（SKILL.md 正文），不是写在元层脚本里。
3. **具体样本压住幻觉。** 292 篇 KB + 14 个带真二进制的案例 + 每篇 reference 写明"什么症状打开我" → 模型做的是检索对照，不是推理。我们样本更少（27 叶 3 有样本）却给了 32 个索引槽位。
4. **破甲靠选型，不靠人设。** 最有效层是 `MANUAL/MODEL-REFUSAL-MATRIX.md`（Gemini 全系拒 / DeepSeek·Claude·MiMo 过）；L1/L2/L3 是保险，且 L3 因 `lab-mode.flag` 纯内存化**从未接上**（A2 §1.3 硬伤）。

**推论**：判据必须搬进包内（解 R1）、样本准入替代目录数量（解 R2）、闸从"验证元层"改成"验证产物"（解 R3）。

---

## §1 我们的真实定位

| 二开动机 | 上游 | REA | 我们必须自担 | 可直接照抄 |
| :-- | :-- | :-- | :-- | :-- |
| ① 破甲必须自己注入 | P 层（AGENTS+SYSTEM 双写，≈2.3K tok 冗余）是唯一真正起作用的一层；**M 层选型最有效**；L3 中继没接上 | 完全不涉及（无 LLM、无 loop，把"意愿"外包给客户端） | **100% 自担**（宿主×模型交界）。但自担 ≠ 自写 28.7KB 人设 | L3 `compliance-relay` 的"空 choices 检测 + S1→S2→S3 重试" + 规则双源同步校验 |
| ② 领域要比上游多 | 5 技能里只有 `apkseep` 是工程件，`softseep` 是目录，其余 3 个是文档；真实覆盖面 **2.5 域** | 域多但每域要 provider adapter + contracts + 890 测试 | **判据与样本**（A2 零判据可抄；A3 成本抄不起） | 证据/合同层（`pack.json` = 声明式 Evidence contract）+ A3 四条反膨胀机制 + A2 的"判据密度"写法 |

**两条落地结论**

- **破甲层做成"三件套 + 常驻 0 token"**：(a) 选型矩阵机器版（`破甲卡生成/models.json` + `probe-refusal.py` + `check-gemini-safety.py` 为唯一 owner，产出 refusal-matrix.json（待建））；(b) 请求层补丁（`security-audit-interceptor.ts`）；(c) 常驻侧只留 **≤1,200 token 的"流程违规定义"**（实测 36 条强制语句已越 `RULE_CLIFF=20`，再加只会降低遵循率）。
- **领域层照 A2 的写法、照 A3 的结构**：每包 SKILL.md 必须有上游式"退出判据 + 机检命令"；每包 `pack.json` 必须有 A3 式 `confidence/authority/limitations/evidence_links`。**迁移不是重写**——37 个执行器/15,547 行已实现域能力（A1 §2），只是不在包里，搬家即可。

---

## §2 目标架构

### 2.1 目录形状

```
Tool/skill/<pack>/                  ← 9 个（8 域包 + softseep 阶段协议）
├ pack.json                         ← 唯一声明源（路由/工具/witness/证据契约/失效条件）
├ SKILL.md                          ≤3 KB：阶段契约 4 行 + 3 步 + 判据 + 失败判据 + 机检命令
├ references/                       L3，按需（含"什么症状打开我"索引行）
└ scripts/                          ← 该域脚本唯一落点（全局 scripts 不接受领域逻辑）

Tool/cases/<case-id>/               ← 全局唯一证据库（不搬进包，避免 5.4MB 数据搬迁）
├ case.json    artifacts/MANIFEST.sha256    facts.jsonl    input/ target/

Tool/scripts/                       ← 7 个文件，冻结
├ route.py  case.py  gate.py  preflight.py  mcp-launch.py  budget.py  doctor.py
Tool/mcp/seep_mcp_server.py         ← 工具面 ≤16 个，每个必须在 tool-effects.json 登记
Tool/config/{tool-effects.json, refusal-matrix.json, packs.baseline.json}
```

### 2.2 `pack.json`（`.strict()` 语义：多一个字段即解析失败，照 A3 `domain/evidence.ts:132-151`）

```json
{
  "schema": "seep.pack/1",
  "id": "pwn-crypto",
  "l1": "≤140 字：只有触发条件，没有战术（进索引的唯一字符串）",
  "routes": [{"label": "pwn/加密逆向", "must": ["(?i)pwn|angr|keystone"], "priority": 41}],
  "stages": ["0-analysis", "1-ask", "2-dyn", "3-patch", "4-verify"],
  "tools": ["seep_r2_decompile"],
  "cases": ["pwn-crypto01", "pwn-crypto02"],
  "witness": {
    "cmd": "python scripts/witness.py --case pwn-crypto01",
    "expect": "exit0 + artifacts/MANIFEST.sha256 + facts>=3",
    "budget_s": 600
  },
  "evidence_contract": {
    "required_fields": ["confidence", "authority", "limitations", "evidence_links"],
    "authority_allow": ["shipped-artifact", "controlled-replay", "external-service"],
    "pass_forbids_confidence": ["inferred", "unknown"]
  },
  "limitations": ["已知不能做的事（必填，禁空）"],
  "invalidation": ["什么情况下本包判定整体失效"]
}
```

字段与 A3 对应：`confidence` 三态 `observed|derived|inferred`；`authority` 五态；`limitations[]`；`evidence_links[]`（派生边）。
**`witness` 是唯一可执行判据**——上游的 "done 六条" 是 prose，这里把它变成**退出码**。

### 2.3 全局层：7 个文件

| 上游文件 | 必需？ | 我们的落点 |
| :-- | :-: | :-- |
| `master-route.ps1` + `routing.json` | ✅ | 合为 `route.py`；**路由搬进 `pack.json`，索引运行时生成 → 取消 `routing.json` 这个可漂移副本** |
| `case-init.ps1` | ✅ | 并入 `case.py`（唯一状态写者） |
| `lib/WorkRoot` / `RouteScope` / `HostRuntime` | ✅ | **消失**（python 化后无宿主 exe 选择问题） |
| `lib/ToolDiscovery.ps1`（1,188 行） | ✅ | 由 `tool-effects.json` + `mcp-launch.py` 取代 |
| `start_mcp.py` | ✅ | `mcp-launch.py` |
| `lib/BootstrapSupplyChain.ps1` / `refresh-tool-index.ps1` / `trigger_ida_mcp.ps1`（写死 PID 11260）/ `shot_ida.ps1` / `temp_ocr.ps1` | ❌ | **删**（孤儿 / 换机即废 / 无调用者） |
| `probe-refusal.py` / `check-gemini-safety.py` | ✅ | **移入 `破甲卡生成/`**，不计入全局脚本 |

→ **`Tool/scripts/` = 7 个** + 1 个 MCP server 文件。

### 2.4 闸：52 项 → 9 项

| # | 闸 | 判据（红 = 失败，不接受 skipped/unknown 记 pass） |
| :-: | :-- | :-- |
| G1 | `budget` | 常驻可控制层 ≤8,000 tok 且强制语句 ≤20 条 |
| G2 | `pack-schema` | 每个 `pack.json` 过 `.strict()`；`limitations`/`witness`/`cases` 非空；`l1` ≤140 字 |
| G3 | `route-parity` | `route.py --index` 每条路由都解析到现存 pack id；**0 条死路由**（上游 45/45 全死就是反面教材） |
| G4 | `pack-witness` | 逐包真跑 `witness.cmd`；exit≠0 或产物缺失或 facts<3 → 红 |
| G5 | `evidence-integrity` | facts 每条 claim 含 4 必填字段；`evidence_links` 指向存在的 id；哈希重算不符 → 红 |
| G6 | `artifact-manifest` | 每 case 的 `artifacts/MANIFEST.sha256` 逐文件校验 |
| G7 | `tool-registry` | `@server.tool` 数 == `tool-effects.json` 条目数；缺登记 **server 拒绝启动**（import 期抛错） |
| G8 | `return-budget` | 对每工具发超量请求，须返回 `resource_constraint`；返回截断文本即红 |
| G9 | `tool-liveness` | 近 5 会话 0 调用的工具必须在**递减预算**内，只降不升；超预算即红（替代 `#43` 的永久豁免） |

其余 43 项：**删 31**（存在性/计数/自证），**并入 12**（`doc-audit`/`kb_acceptance`/`language` → 降级为 `doctor.py` 的只读报告，不参与判定）。

### 2.5 状态文件：20 → 4（唯一 owner）

| 状态文件 | 唯一 owner | 吸收了什么 |
| :-- | :-- | :-- |
| `case/<case>/case.json` | `case.py init` | 取代 `cases/index.json`（索引改运行时现算） |
| `case/<case>/facts.jsonl` | `case.py`（append-only + schema 校验） | 取代 `state.json`、`ai_manifest.json#seep`、`memory/facts.jsonl`、`memory/events.jsonl`、`events.jsonl`、`gaps.json`、`plan.json` |
| `case/<case>/artifacts/MANIFEST.sha256` | 执行器写 + `gate.py` 读 | 不变（已 49 实例） |
| packs.baseline.json（待建） | 人手工编辑；`gate.py` 只读；`--accept` 需 reason+date+sha | 合并 `gate-counts.json`、`path-tree-baseline.json`、`liveness-baseline.json`、`domain-pack-baseline.json`、`mcp/.baseline/tools.json`、`canary-results.json`、`session-manifest.json`、`mcp-handshake.json`（后者**无任何读取方**） |

**丢弃不落盘**：`index.json`、`tool-index.json`、`session-manifest.json`、`gate-counts.json` —— 都是派生视图，现场算。

---

## §3 保留 / 降级 / 删除

### 3.1 保留：13 个有真实样本 → **8 个 pack**

| pack | 证据（A1 §4） | 合并了谁 |
| :-- | :-- | :-- |
| `pwn-crypto` | real=2 + self-built=3、3 脚本（real 数 2，未达 real≥2 的临界，S3 时复核） | — |
| `apkseep` | 56 脚本 + `A-APK-PLAIN` 真 fixture `diva.apk` | `apk-reverse`（6 脚本，已 3 处漂移） |
| `web-pentest` | 5(3) real、5 脚本；与 site-clone 同工具链 | `site-clone` |
| `malware-analysis` | 4(2) real、3 脚本、3 个 case 有 `unpack.json`+MANIFEST | `unpack-loop`（2(1)、0 脚本） |
| `supply-chain-security` | 4(3) real、3 脚本 | — |
| `forensics-mobile` | 5(2) real、3 脚本 | — |
| `firmware-iot` | 5(2) real、3 脚本 | — |
| `protocol-plugin` | 4(2) real、3 脚本；与 plugin-targets 同"私有协议/目标体" | `plugin-targets` |
| （不占域包名额）`softseep` | 1(1) real、4 脚本、**唯一有阶段机与 7 条路由** | `01-gate-bypass` `02-ui-rebrand` `03-license-hookup` `04-version-migrate` `05-backend-rebuild` `client-license-validation-bypass` `signin-automation` `version-migration`（8 个都只是它的阶段文案） |

**进 `_pending/`（不索引、不路由）**：`ad-cloud`（5 case 但只有 1 个 real，未达 real≥2）。补上第二个真实标靶后自动升格。
**索引：32 → 9。**

### 3.2 降级/删除：12 个打不红或自证的门禁

| 项 | 病 | 处置 |
| :-- | :-- | :-- |
| `#46` canary | 记录是 `--record` **人工填**的；results 里 2 条 `executed` 仍报"全拦" | **删**；证据只能来自 `witness` 真跑 |
| `#44` 会话清单 | 无 manifest 直接 PASS | **删**；`doctor.py` 现算 |
| `#22` 案例真实性三分 | 只校验枚举值，标 `real` 即过 | **改**：`evidence_kind` 变**计算值**（facts 里 authority 统计）；无 facts → `unverified` |
| `#41` 每叶有见证物 | witness 只是非空字符串 | **删**（`path-walk.py` 一并删）；由 G4 替代 |
| `#42` 缺 fixture ≤ 基线 | 24 ≤ 24 等号通过 | **删**；G4 要求每包 witness 必有 fixture |
| `#43` 只测生效 | `allowed_fail=[L3,L4,L8]`，L3="20 工具 0 调用"被永久豁免 | **改**：G9，递减预算 |
| `#9` mcp-doctor | 只要 stdout 能 `json.loads` 就过 | **降级**：并入 `doctor.py` |
| `#8`/`#3` 平台 parity | 环境缺失时 `add(..., True, "skipped")` | **改**：环境缺失 = `unsupported` = **红**（unknown 永不记 pass） |
| `#7` 无机器绝对路径 | 只扫 4 个目录；宿主 `~/.pi/agent/mcp.json` 硬编码不在范围；7 条 `portable_allow` **整文件**豁免 | **改**：扫 `git ls-files` 全量；豁免粒度降为"行 + reason + sha" |
| `#33` MCP 契约 | 纯静态 AST，20 工具可调用性从未验证 | **改**：G7（登记即启动）+ G8（每工具一次活调用） |
| `#48` out-artifact | `rc in (0,3)`，目标连不上也算 PASS | **改**：只接受 rc=0 + ≥1 artifact + 入 MANIFEST |
| `#2` 文档数字 vs 实测 | "实测"全由本仓自身推算，文档与代码自洽即绿 | **删**（文档取消一切计数；数字只在 `doctor.py` 输出） |

### 3.3 删除/合并：**脚本 105 → 7 全局 + 28 进包 + 70 删**

- **孤儿 4 个 → 删**：`apk/frida-run.sh`、`apk/rebuild-sign-install.sh`、`circuit-selftest.mjs`、`lib/BootstrapSupplyChain.ps1`
- **兼容壳 5 个 → 删**：`adcloud-check.py` / `forensics-check.py` / `fw-triage.py` / `plugin-triage.py` / `pcap-summary.py`
- **APK 双份 → 删全局那份 7 个**（1,008 行），保留 `Tool/skill/apkseep/scripts/*`
- **元层的元层 → 删 8 个**：`path-walk.py` / `manager-audit.py` / `replay-history.py` / `p2-replay.py` / `receipt-check.py` / `session-manifest.py` / `impact.py` / `liveness-check.py`
- **生成器 7 个 → 删**：`forge.py` / `gen-case-index.py` / `gen-playbook-index.py` / `gen-task-cards.py` / `new-skill.py`（**它的存在本身就是"加技能零成本"，与反膨胀直接冲突**）/ `refresh-tool-index.ps1` / `sync-gate-counts.py`
- **一次性 9 个 → 删**，例外保留 2 个 → 移入 `破甲卡生成/`：`probe-refusal.py`、`check-gemini-safety.py`
- **只删本节点名的元层/生成器/一次性脚本**（`Tool/scripts` 内 19 个未提交文件 / 6,704 行）；**其余 untracked 一律 commit，不许删**（全仓 untracked 实为 102 文件 / 26,566 行，含 `preflight.py`/`prompt-budget.py`/`mcp-launch.py`/`canary.py`/`path-walk.py`/`liveness-check.py`/`session-manifest.py` 与全部权威文档本身）。3 个 case 目录（`leaf-apk`、`leaf-pe-packed`、`_p2fixture`）**必须提交**——它们是 3 个绿叶子中 2 个的 fixture 来源，也是 `apkseep`/`malware-analysis` 的准入证据
- **`probe_matrix.py`（1,643 行）+ `migrate.py` + `smoke-e2e.py` → 删**
- **MCP 工具面 40 → ≤16**：删 A1 §6 点名的 10 个"产出未经证实结论"的工具（`seep_gen_security_report`、`seep_auto_triage`、`seep_packer_detect`、`seep_web_recon`、`seep_decompile_auto`、`seep_status`、`seep_ida_status`、`seep_tool_control_plan`、`seep_case_search`、`seep_apk_gen_hook`）+ 把 `seep_tool_install`/`seep_ensure_tool`/`seep_tool_register_mcp` 降为**返回 ASK 卡文本，绝不 `apply`**

### 3.4 8 组重复副本怎么合

| 组 | 合到哪 |
| :-- | :-- |
| facts 双账 | 留 `<case>/facts.jsonl`；删 `memory/facts.jsonl` |
| events 双账 | 两个都删；工具调用事实以 `kind:"event"` 追加进 `facts.jsonl` |
| state 双恢复点 | 两个都删；状态 = `facts.jsonl` 重放（`case.py replay`），不存快照 |
| case 元数据 | 删 `cases/index.json`；`case.py index` 现算（顺带消灭 `"repro": {}` 那个坑） |
| 门禁数字三副本 | 删 `gate-counts.json` + `sync-gate-counts.py`；文档不再出现任何 `N/N` |
| 工具数三副本 | 唯一口径 = `tool-effects.json` 条目数（G7 强制相等） |
| 技能数 31/32 | 消失（文档无数字）；唯一口径 = `route.py --index | wc -l` |
| APK 适配器 | 留 `Tool/skill/apkseep/scripts/*`（唯一），删 `Tool/scripts/apk/*` 与 `safe-skills/apk-reverse/scripts/*` |

---

## §4 反膨胀纪律（从 A3 搬 3 条）

**D1 · 缺登记就抛错**（照 `toolEffects.ts:790-793`）
tool-effects.json（待建） 为每个工具登记 `{mutates_target, writes_filesystem, executes_foreign_code, touches_network, may_discard_data}` 并派生 MCP annotations。`seep_mcp_server.py` **在 import 期**比对 `@server.tool` 集合，缺一条 → `raise MissingEffectAudit`，**server 起不来**。
验收：删任意一条登记 → `python -c "import seep_mcp_server"` 非 0 退出。

**D2 · over-budget 拒绝，不截断**（照 `ToolResultDelivery.ts:200-250`）
现状恰好相反：`seep_r2_disasm(limit_tokens: int = 0)` **默认不限制**；超限时**截断并附 `[TRUNCATED at N chars]`**；`_run_cmd` 无输出时返回 `"[Success, no output]"`。
改为：`RESULT_BUDGET_BYTES = 64 KiB`，超限返回 `{ok:false, error:"resource_constraint", bytes, continuation:"用 offset 缩小 或分页", artifact_hint:"已落 artifacts/…"}`；`limit_tokens` 默认改 8000；**删除截断分支**（"被削过的证据"比"多调一次"危险）。
验收：G8 对每工具发超量请求，`grep -c "TRUNCATED"` = 0。

**D3 · unknown 永不计入 pass**（照 `reconstruction-readiness.md:49-52` + `evidenceCompletionLedger.ts:12-46`）
`facts.jsonl` 每条 claim 带 `confidence ∈ {observed, derived, inferred, unknown}` + `authority`；聚合规则写死在 `case.py verify`：**`fail / unknown / unsupported / truncated / skipped` 任意非零 → 整案不得为 pass**。
`repro.status` 从"人工填 recorded"改为**计算值**。
验收：对现有 4 个 case 跑 `case.py verify --all`，凡 facts 为空（如 aimbot）必须报 `unknown`，而当前它们被计为 recorded。

---

## §5 迁移顺序（5 步）

| 步 | 内容 | 可验收判据 | 成本 |
| :-: | :-- | :-- | --: |
| **S1 只删不加** | 删 12 个自证门禁（含 `gate-counts.json` 与文档里所有 `N/N`）、4 孤儿、5 兼容壳、7 个 APK 全局重复、9 个一次性脚本、6 个重复状态文件、**只删点名的元层/生成器/一次性脚本**（其余 untracked 一律 commit，见 §3.3） | ① `preflight.py --fast` rc=0 且项数 52→≤47（§3.2 里明确写“删”的只有 5 项，其余是“改/降级”）；② `git status --porcelain Tool/scripts` 的 untracked = 0（**其余 untracked 一律 commit，不是删除**）；③ `grep -r "gate-counts\|sync-gate-counts"` = 0；④ 无脚本 import 已删文件 | **3h** |
| **S2 杀 fail-open** | D2 + D3 + `seep_gen_security_report`/`seep_auto_triage` 改为"无证据则拒绝"；`_run_cmd` 空输出不再报 Success | ① 空参调报告生成器 → `ok:false`，`reports/` 新增 0 文件；② `grep -c "TRUNCATED\|\[Success, no output\]"` = 0；③ `case.py verify --all` 四个 case 报 `unknown` | 1 天 |
| **S3 立包与闸** | 8 个 `pack.json` + `SKILL.md` ≤3KB + `gate.py`/`route.py`；路由搬进 pack，删 `routing.json`；索引 32→9；`ad-cloud` 入 `_pending` | ① `gate.py --all --json`：每包有绿或红，`unknown→pass` = 0；② `route.py --index` 死路由 = 0；③ Σ`l1` ≤1,260 字 | 2 天 |
| **S4 全局层收口** | `Tool/scripts` → 7；状态 → 4；D1 登记表落地；工具面 40→16；`doctor.py` 接管 8 个诊断脚本 | ① `ls Tool/scripts/*.py | wc -l` = 7；② 状态文件**种类** = 4；③ `rg "state\.json|index\.json|ai_manifest|session-manifest|path-tree-baseline"` = 0；④ 删任一登记 → server 起不来；⑤ `tools/list` = 16 | 1 天 |
| **S5 KPI 回放** | 3 个靶：`crackerjack/a.exe`、`leaf-pe-packed`、`leaf-apk/diva.apk` + 1 个真实目标；填 KPI 表 | KPI 表 3+1 行填满；任一行 `fail`/`unknown` → 不发版 | 1 天 |

**依赖**：S1 必须先做（否则 S2 的门禁数还被 `sync-gate-counts` 反向锚定）；S3 依赖 S1 删掉 `routing.json` 的第二个读者；S4 依赖 S3 的 `pack.json` 作为 `tools` 来源；S5 依赖 S1 提交的三个 case 目录。

**风险**
1. `leaf-apk`/`leaf-pe-packed` 为 untracked，S1 漏提交 → `apkseep` 与 `malware-analysis` 当场失去 witness
2. 删 12 门禁会让"看起来覆盖率下降"，必须在同一次 commit 里附 §3.2 表
3. `compliance-relay` 的 `refusal.py` 有 2 个测试文件，是仓库**唯一有测试的运行时**，不得连带删除
4. `launch-gui.ps1` 属未提交件，若在用需先确认

---

## §6 唯一 KPI

**`KPI.md` 表头（每次真实任务后手工填一行；填不出改善 → 不加任何东西）**

| 日期 | 目标 | pack | 结果<br>(delivered/upper-bound/fail) | 证据<br>(MANIFEST 文件数/facts 条数/unknown 数) | 常驻 tok | 墙钟分 | ASK 次数 | 复现命令 |
| :-- | :-- | :-- | :-- | :-- | --: | --: | --: | :-- |

**"比上游强"的 5 条二值判据（任一为否即不算强）**

| # | 判据 | 上游对照 |
| :-: | :-- | :-- |
| K1 | **可复现**：第三人只跑 `python Tool/scripts/gate.py --pack <id>` 得到同一红/绿 | 上游 45 条路由目标全不存在、`master-route` exit 2 |
| K2 | **零编造**：报告里每条"已验证"都能在 `facts.jsonl` 找到 `observed`+`authority` 条目；找不到 → gate 红 | 上游零证据可生成"已验证"报告 |
| K3 | **覆盖面**：≥8 个域包各有 witness 且全绿 | 上游真实 2.5 域 |
| K4 | **成本**：常驻可控制层 ≤8,000 tok；工具 schema ≤13 KiB/工具 | 上游 lab 会话 12.5K 起步、读 apkseep 后 ≈30K；REA 221 工具仍 290KB |
| K5 | **人环可预期**：每题 ASK 次数写进表；`0` 或 `>2/阶段` 都算失败 | 上游"卡密是用户的操作"只在 prose 里 |

**刹车**：任何新增 pack / 工具 / 规则，PR 必须带一行 KPI 前后对比；没有 → 拒绝合并。
这条把 A1 §8.1 的正反馈环（效果差→加东西→更重→更差）第一次变成**有成本**的动作。
