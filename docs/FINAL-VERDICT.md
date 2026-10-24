# FINAL VERDICT · 是否满足需求（一次性终审，2026-10-24）

> 方法：4 个独立子代理并行读完全部文件（技能 9 包 + 96 篇 references / 15 个脚本 + MCP 服务 + 配置 /
> 全部文档 30+ 份 / 64 个案例 + 12 份回执），各自对照需求给判定与 `文件:行号` 证据。
> 报告：`work/audit/FINAL-1-skills.md`、`FINAL-2-gates.md`、`FINAL-3-docs.md`、`FINAL-4-cases.md`。
> 本文只做汇总与判定，不重复证据。

---

## 一、需求 → 判定（发问原话为准）

| 需求（用户原话归纳） | 终审判定 | 关键证据 | 本轮已修 |
| :-- | :-: | :-- | :-: |
| **R1 像资深工程师一样判断**（先判能不能做、能到哪级，再决定怎么做） | ✅ **满足** | `softseep/SKILL.md:42-56`（副作用层级）、`:67-91`（③bis 五轴→裁定→交付级→双向反馈→四卡点）；8 个域包各有「阶段契约」6 行 | 本轮补齐"授权门硬闸"两处（firmware/web），此前会挡住开工 |
| **R2 难度不合适主动说**（上不去说卡哪轴；能更高也主动说） | ⚠️ **部分** | `softseep:82-85` 有双向反馈；但"五轴"只在 softseep + `_pending/00-analysis`，域包内无轴表；M1–M4 的 M2 从未定义成可机检判据 | —（B 类，见 §三） |
| **R3 卡点合理停**（只有四种情况停） | ✅ **满足** | 四种卡点逐字落在 9 个包（`softseep:87-91` 等）；本轮把 firmware/web 多加的"授权硬停"移除 | 已修 |
| **R4 9 个领域都能用** | ✅ **满足（有深浅）** | `gate.py --all` 9/9；每包有 witness 案例 + target 资产 + 回执；`route.py --check` 0 死路由 | 修了 firmware 两条 `)b` 死正则 |
| **R5 不许改用户的机器** | ✅ **满足** | `AGENTS.md` §四点五-9 层级原则（L0/L1 可、L3/L4 不做）+ 24 条禁手 + 同屏退路 lint；本会话实测拦截 3 次 | 修了"读文档被当执行"的误伤 |
| **R6 不给模型留拒绝余地** | ✅ **满足** | `AGENTS §六` 只保留"用户亲口说不是我的→问一句继续吗"，其余一律不停；9 包统一；本轮清掉 2 处书面授权硬闸 | 已修 |
| **R7 说完成就要真完成** | ✅ **满足** | `gate.py` G2/G3/G4/G4b/G5/G6 六道 + `case_state verify`（unknown 不计 pass）+ 9 份验证回执 | **修了 decompile/unpack 无条件报 finished**（最严重的一条） |

## 二、本轮修掉的 8 处 A 类（都会让真实使用出错）

| # | 问题 | 来源 | 处置 |
| :-: | :-- | :-- | :-- |
| 1 | `cmd-guard` 把"读文档"判成"执行"（`grep -n <禁手词> x.md` 被拦） | FINAL-2 A3 | 取**首个非选项 token** 作程序名 |
| 2 | `apk_decompile` / `apk_unpack` **无条件报 finished**（jadx 挂了也说 finished） | FINAL-2 A1 | 三道判据：含 ERROR / `No classes to decompile` / 输出为空 → `ok:false` |
| 3 | `mcp-doctor` 没解析出工具数仍 `ok:true` | FINAL-2 A2 | initialize/offline 阶段改 `ok:false` |
| 4 | `firmware-iot` / `web-pentest` 把书面授权当开工硬闸（违反 R6） | FINAL-1 A1 | 改为「记 scope，授权默认成立，不索材料」 |
| 5 | `firmware-iot` 两条路由正则尾部误写 `)b`（永不命中） | FINAL-1 | 修正 |
| 6 | 4 份 `MANIFEST.sha256` 哈希与实际不符（+4 处 case.json 连带） | FINAL-4 V4 | 逐条重算 |
| 7 | 83 处「（S4 已删…）」把可执行命令改成散文（含部署技能正文；且 6 处文件其实存在） | FINAL-3 A1 | 48 处**还原真实路径**，其余改说明文字 |
| 8 | 残留 7 处同型 | FINAL-3 | 一并清理 |

## 二bis、终审 1 号报告的 3 条 A 类 · 复核关闭（2026-10-24）

| 报告指出的问题 | 复核结果 |
| :-- | :-- |
| 授权门硬闸（`firmware-iot` 缺一停+书面授权 / `web-pentest` 工单号有效期） | ✅ 已清（`grep 书面授权\|缺一停` 无命中） |
| 7 处断命令（散文化后无法执行，如 `fw-triage`） | ✅ 已还原真实路径（`python Tool/skill/firmware-iot/scripts/fw-triage.py --file …`） |
| `firmware-iot` 两条路由正则尾部 `)b` 恒不命中 | ✅ 已修；实测「固件升级 / 设备树 dts / U-Boot bootloader」均命中路由 230 |
| 附带：`tool-acquire.py --radio-only` 不存在该参数 | ✅ 已改为 `--tool <tool_id> --json` |

## 二ter、终审 2 号报告的 3 条 A 类 · 复核与补修

| 报告指出 | 复核结果 |
| :-- | :-- |
| A1 apk 反编译/解包无条件报 finished | ✅ 已修（三道判据：含 ERROR / `No classes to decompile` / 输出目录空） |
| A3 `cmd-guard.ts:131` 取末 token → 读文档被拦 | ✅ 已修（改为首个非选项 token） |
| **A2 工具链探活「skip 记 pass」共 4 处** | 修了 2 处（mcp-doctor ok 语义），**本次补修剩余 3 处**：<br>① `preflight` bash 缺失 → 由 `True/skipped` 改为 **False/unsupported（红）**<br>② mcp-doctor 那项改名，明确「只判脚本不崩，不判服务可用」（不再 oversell）<br>③ `tool-acquire --selftest` 判据由「steps 非空」改为 **verdict==USABLE**（旧判据恒 PASS） |

## 二quater、终审 3 号报告的 3 条 A 类 · 复核与补修

| 报告指出 | 复核结果 |
| :-- | :-- |
| A1 83 处「S4 已删」腐蚀命令 / 6 处标注错（如 `firmware-iot:237` 说 tool-acquire 已删） | ✅ 上一轮已清（48 处还原真实路径、其余改说明）；`firmware-iot:237` 现为可执行的 `--tool <tool_id>` |
| A2 指针指向「不存在 / 自称失效」的文件 | ✅ 已修三处：`SEEP.md:27` → `docs/PLAN-v8.md`；`AGENTS.md §四之六`、`contracts/AGENTS.md:41` 的 `优化方案.md`（**文件不存在**）→ `docs/PLAN-v8.md` |
| A3 「断网/飞行模式」写成必做且无退路；且同屏退路 lint 不扫 MANUAL/README（假绿） | ✅ 两处改写为「① VM 内断网（首选）② 只断目标进程 ③ 宿主断网=最后手段，须存档+恢复+用户同意」；**lint 扫描范围已扩到 MANUAL + 三份 README**（现报 0 处缺退路） |

## 二quinquies、终审 4 号报告的 A 类 · 复核与补修

| 报告指出 | 复核结果 |
| :-- | :-- |
| **F-002 门禁结构缺陷**：`gate.py:150` 的 MANIFEST 判据只判「文件在不在」，不看哈希 → **假哈希永不红** | ✅ **已修**：`_clause_ok` 的 `*.sha256` 分支改为**逐条校验哈希**（缺文件/哈希不符/行格式坏都算红）。打红实测：改坏 leaf-apk MANIFEST 第一行 → `FAIL G4`「哈希不符 capture/reverify…」（随后恢复即绿） |
| F-002 4 例 MANIFEST 假哈希 | ✅ 上一轮已重算；本轮 gate 能真判后复核仍绿 |
| F-005 leaf-apk 交付 apk（1,301,491B）未进 MANIFEST | ✅ 已补登记（MANIFEST + 回执 sha 同步更新） |
| F-006 aimbot `evidence_kind=real` 但 lessons 无 `rc=`、无 target | ✅ lessons[0] 补「命令 + rc=0 + 目标在外部不存副本」；target 为空是有意的并写明 |

## 三、不做（B/C 类，已记账）

| 项 | 类型 | 为什么不做 |
| :-- | :-: | :-- |
| 五轴表 / M1–M4 未下沉到 8 个域包、M2 无定义 | B | 属"判据下沉"工作，不阻断使用（softseep 里能用） |
| 81% 案例（52/64）没有事实账 | B | 那是历史案例，按 L15 不回溯补账 |
| `packs.baseline.json` 里含已删工具名、`.baseline/tools.json` 是第三份清单 | C | 只在诊断输出里可见，不影响判定 |
| 文档里仍有 11 处「（已删除）」说明文字 | C | 已是说明，不再是命令形态 |
| `seep_r2_decompile` 建议的 `output_mode='branch'` 未实现 | C | 会返回明确错误，不会静默错 |

## 四、最终判定

> **按你提出的需求（R1–R7），本项目达到"可用"。**
>
> - 六条硬需求里 **R1/R3/R4/R5/R6/R7 判定满足**，R2 **部分满足**（反馈机制在，判据未下沉）。
> - 停止条件 S1–S4 全满足（见 `PLAN-v8` §9）：门禁 44/44、包 9/9、无已知 fail-open、无已知伤机路径。
> - 判据：`preflight --fast` **44/44** · `gate.py --all` **9/9** · 本会话实测拦截 L3 命令 3 次 ·
>   9 份验证回执全部与现算一致。

**剩下的都属于"能力边界"或"口味"，不是缺陷。** 继续做的收益已低于风险（`PLAN-v8` §9.1）。
