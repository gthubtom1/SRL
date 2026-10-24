# 验收记录（2026-10-24 收尾）

> **本文件是一次性快照，不是常驻状态。** 想知道"现在"如何，跑下面第二节的命令。
> 为什么不用它当状态源：手写状态必腐烂（`docs/HANDOFF.md` 已经烂过一次）——
> 现行状态由 `case_state.py handoff --repo` 生成。

## 一、判据与结果（本轮实测）

| # | 判据 | 命令 | 结果 |
| :-: | :-- | :-- | :-- |
| 1 | 门禁（含 2 条新跨层判据） | `python Tool/scripts/preflight.py --fast` | **48/48 通过** |
| 2 | 按域判定（6 道/包，unknown 记 fail） | `python Tool/scripts/gate.py --all` | **pass 9 / fail 0** |
| 3 | 证据聚合 | `python Tool/scripts/case_state.py verify --all` | **pass 12 / fail 0 / unknown 52** |
| 4 | 路由死链 | `python Tool/scripts/route.py --check` | **0 条死路由** |
| 5 | 案例证据哈希 | 全部 `artifacts/MANIFEST.sha256` 逐条重算 | **879 个文件全对** |
| 6 | facts 账本结构 | 全部 `facts.jsonl` 解析 | **proven 都有 evidence，event 都有 rc** |
| 7 | 技能工具引用 | 25 处调用式引用 vs 服务端 20 个工具 | **全部存在** |
| 8 | 回执漂移 | `docs/verification/*.json` 的 source_sha256 | **18 条全对** |
| 9 | 扩展部署 | 仓库 7 个 `.ts` ↔ `~/.pi/agent/extensions` | **哈希全一致** |
| 10 | 从零可复现 | 全新 `git clone --depth 1` 后重跑 1–2 | **同样全绿** |

## 二、想自己复算时

```bash
python Tool/scripts/preflight.py --fast        # 门禁 48 项
python Tool/scripts/gate.py --all              # 9 个包
python Tool/scripts/case_state.py verify --all  # 证据强度
python Tool/scripts/case_state.py handoff --repo   # 当前状态（生成，不过期）
```

## 三、本轮验收抓到并已修的问题（都是 A 类：会导致"说谎"或"空转"）

| 问题 | 表现 | 修法 |
| :-- | :-- | :-- |
| 技能里引用的工具可能不存在 | 模型照文档调用 → 失败 → 重试循环（同 `output_mode='branch'` 那一类） | 新增判据：25 处调用式引用必须都在服务端有定义 |
| 回执可能替改过的代码作证 | 技能改了、回执还是旧的 → "证据"失效但没人发现 | 新增判据：回执 `source_sha256` 必须等于当前文件 |
| 守卫正则写坏时静默跳过 | `except: pass` → 这条禁手失效但门禁照绿 | 编译失败收集进「对抗陷阱对撞」项 → 红 |
| 扩展改了没部署查不出来 | 仓库是新的、跑的是旧的（实测踩到 `cmd-guard.ts`） | 新增判据：7 个扩展哈希必须与部署侧一致 |

## 四、已知但不修（按 `PLAN-v8` §9.2 分类：B 记账 / C 不修）

| 项 | 类 | 为什么不修 |
| :-- | :-: | :-- |
| 仓库内有 ~190MB vendored 依赖（jadx 74MB、js-reverse node_modules 52MB、apktool 23MB、venv.zip 20MB、radare2/VC_redist 等） | B | `setup/install.ps1` + `extract-deps.ps1` 依赖它们做**离线首装**；删掉会破坏"换机器一键装"，风险大于收益 |
| 52/64 个历史案例无事实账 | B | L15：不为已结束的目标回溯补账；新案例自动带账 |
| 8 个域深度不均（apkseep 468 行 vs forensics 208 行） | B | 能力积累问题，需真实样本 |
| 商业加固壳（DexVMP/jiagu/梆梆）未实测 | B | 需构建链 + 真实加固样本 |
| 4 条 refuted claim 缺 confidence | C | refuted 不计 pass，不影响任何判据 |

## 六、负向验收（变异测试）—— 证明"判据不是装饰"

只验"好代码绿"不够：那可能是判据根本不起作用（本项目就出过"空判据 0 条却 PASS"和"skip 记 pass"）。
所以在**一次性 clone**（`/d/tmp/fresh`）里故意弄坏 7 处，坏完 `git checkout` 还原，零风险。

| 变异 | 期望 | 实测 |
| :-- | :-- | :-: |
| MANIFEST 哈希篡改 | gate/preflight 变红 | ✅ |
| 删除被引用的证据文件 | 变红 | ✅ |
| 技能里写错工具名（`seep_r2_decompileXX`） | 新判据「技能里的工具引用」变红 | ✅ |
| 回执 source 哈希改错 | 新判据「回执未漂移」变红 | ✅ |
| 守卫正则写坏（`([unclosed`） | 「对抗陷阱对撞」变红 | ✅ |
| 扩展改一个字节（与部署不一致） | 「扩展部署一致」变红 | ✅ |
| facts 里删掉 evidence 但保留 proven | 变红 | ✅ |

**7/7 全部被抓**。再补一轮"精准变异"（同时把回执同步成篡改后的真实哈希，排除"回执替 gate 挡枪"）：
MANIFEST 哈希错 → `G4 pack-witness` 红；proven 无证据 → `G5 evidence-ledger` 红；强度降级 → `G6 verification-receipt` 红，**3/3**。

## 七、冷启动会话验收 —— 两个无上下文子代理（只读）

派两个全新会话（`explore` 型，无 shell、不能写文件），只给仓库路径，让它们自己判断"现在在哪、下一步做什么、这个目标能到哪一级"。

**它们抓到的真问题（已全部修复）**

| 问题 | 后果 |
| :-- | :-- |
| **4 个 witness 案例缺 `kind:"state"` 行** | `case_state.py deliver` 一律被拒（"还没给可行性裁定"）→ 交付闸门在一级功能上不可用。已按 case.json 自身记录补 state 行（写明迁移来源，不编造裁定），`deliver` 实测恢复可用 |
| **README / docs/README 的"冷启动必读"指向 S1 之前的世界**（写 preflight 55/55、domain-gate 110/110） | 新会话先读到的是旧世界数字。已改为"数字跑命令看"，入口改为 HANDOFF → NOW → PLAN-v8 |
| **`docs/history/DECISIONS-PENDING.md` 是 S1 之前的另一个世界**，却挂在 `docs/` 根 | 会被当现状读。已移入 `docs/history/`（`FORK-BRIEF.md` 同） |
| **`KPI.md` 标题说"9 个包已通过、下表保留为空"，表里却有 4 行 fail** | 自相矛盾。已修 |
| **HANDOFF 新鲜度判据把 HANDOFF 从"旧值残留机检"里排除了**，且容差 ≤3 让漂移静默变绿 | 专门防"手写状态腐烂"的护栏，正好对当前这次腐烂失效。已收紧到 ≤1 并从跳过名单移除 |
| `PLAN-v8` / `FINAL-VERDICT` 仍写 44/44 | 数字漂移。已改为跑命令看 |

**它们的判断是对的**：信 `ACCEPTANCE.md` 的实测数字、信 `PLAN-v8` §6.10 的"已决定不做"，
并把 `NOW.md` §五 的三件"待决定"识别为过期待办 —— 该处已改为"已定为不做"，与 §6.10 对齐。

> 结论：**冷启动验收比自审有效**。它不共享我的上下文，所以不会替我圆场。

## 八、结论

按 `PLAN-v8` §9 的终止条件（S1 门禁全绿 / S2 每域有见证 / S3 无已知 fail-open / S4 无已知伤机路径），
**四项全满足** ⇒ 判定"可用"，停止优化。

再往下做都属于 B/C 类（能力扩充或口味），不构成"修 bug"。

## 九、完整门禁清单（2026-10-24 补：此前只跑前两条就宣布"全绿"，漏掉 3 项）

**"完成"的唯一口径 = 下面 6 条全绿 + 故障注入全被抓。少跑一条就不算。**

```bash
python Tool/scripts/preflight.py --fast                              # 53 项（结构/契约/触发面/部署）
python Tool/scripts/gate.py --all                                    # 9 包 × 6 判据（证据强度）
python Tool/scripts/domain-gate.py --all                             # 109 项（域契约/证据链/清理/部署/串味）
python Tool/scripts/kb_acceptance.py                                 # 9 项（KB 检索验收语料）
python Tool/skill/softseep/scripts/intent-coverage.py --json          # 意图覆盖（90 条探针）
python Tool/skill/softseep/scripts/skill-route-probe.py --json        # 技能路由探针（含 CJK 边界）
```

本轮漏跑时抓到的真 bug（都是"检查项本身写错"，不是数据错）：
| bug | 表现 | 修法 |
| :-- | :-- | :-- |
| `domain-gate.check_spec()` 找 `docs/DOMAIN-SPEC-v2.md` | 文件其实在 `docs/history/X-DOMAIN-SPEC-v2.md` → 整条契约漂移判据永远红 | 改路径 |
| 3 个案例模板的 refs 指向归档前路径（`Tool/skill/ad-cloud/`） | 证据链判据报"幻影引用" | 批量改到 `_pending/` |
| `Tool/docs/tool-index.md` 把内置工具标 `Missing` | 会让人去联网装**已随仓库打包**的 radare2/jadx/apktool | 按 8 层探测重写（16/16 就位，不写机器路径） |
