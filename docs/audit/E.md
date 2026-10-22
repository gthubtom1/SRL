# E 轮独立复核：用户要求清单落地核对

- 仓库/基线：`D:/Seep-Reverse-Lab`，HEAD `a9d2a40`，`VERSION=1.23.1`，工作树仅有未跟踪的 `docs/audit/`。
- 方式：只读源码 + 跑门禁 + 独立计数（临时脚本在 /tmp，不落仓库）；未改代码、未 commit。
- 当前门禁：`domain-gate.py --all` 110/110；`preflight.py --fast` 31/33（2 个 FAIL 见第 8 行）。

| # | 用户要求 | 状态 | 证据（文件:行 / 命令输出） |
| :-- | :-- | :-- | :-- |
| 1 | 九件套 2.0：11 域各项数量与脚本自检 | 已落地 | `domain-gate.py --all` → 110/110。独立计数：11 域 SKILL 198–518 行（上限 600）；refs 8–10 篇、最大 399 行；脚本 3–4 个，全部 `--help`/`--self-test` rc=0；案例 4–5 个；KB 6–10 篇且均含 failure-criteria；矩阵 13–20 行；任务卡 24 张×六段。reverse 映射到 `softseep`/`pe-reverse` 后同样合规。 |
| 2 | 逆向域四篇补漏 | 已落地 | `Tool/skill/softseep/references/07-disassembly-deep-read.md`、`08-symbol-recovery.md`、`09-patch-engineering.md`、`10-anti-debug.md` 均在；`Tool/skill/softseep/SKILL.md:434-437` 逐篇登记篇幅与主题。 |
| 3 | 任务卡来源标注 + 每域 24 张六段 | 部分 | 11 域各 24 张，六段计数 24/24；10 域来源登记在 `Tool/config/taskcard-sources.json`（240 条）。但该文件无 site-clone 键，而 `Tool/prompts/domains/site-clone.md:5` 声称源名取自该文件；site-clone 卡实际是跨域借用并标「借」。离线无法逐条核验上游 818 库真实名。 |
| 4 | 零孤儿、案例 sha256 复算、路由串味测试集 | 已落地 | `domain-gate.py --links` 7/7：566 个文件有入链、858 条相对链接可解析；`--routing` 60/60，六件固定项及 `zipalign/spider/principal/bios/scaffold/src/xxx.dll` 均命中期望域；案例哈希在 `Tool/scripts/domain-gate.py:355-364` 用 hashlib 复算，非文档自述。 |
| 5 | 清理：根目录、优化方案、过程文档位置 | 部分 | 根目录 `*.md` 仅 README×3+ROADMAP；`find` 未发现「优化方案*」。但 `work/plans/` 不存在（`ls` 报 No such file），只有 `work/tmp/`；README、ROADMAP、UPSTREAM、DOMAIN-SPEC 均声称过程文档已移到该目录，与磁盘不符。 |
| 6 | 部署哈希、AUDIT R1–R8、DEFERRALS | 已落地 | `domain-gate.py --deploy` 1/1（11 域 SKILL/references/scripts 哈希一致）；`docs/AUDIT.md` 含 R1–R8 章节（`R5` 在 332 行、`R6` 在 374 行、`R7` 在 383 行、`R8` 在 394 行）；`docs/DEFERRALS.md` 存在（D1–D12）。标题仍写「R1–R4」，见第 3 节。 |
| 7 | 2026 基线 12 项 P0，每项有出处/命令/判据字段/失败判据 | 已落地 | 逐项在场：VMP `2026-vmp-ultralock.md`；Themida `2026-themida-vm-bypass.md`；CET-LACUNA `2026-cet-lacuna-pdata.md`；26H2 `2026-win11-26h2-kernel.md`；ESC9–17 `ad-cloud/references/kerberos-and-adcs.md:185`；ETag/cache/Next.js `web-pentest/references/01-criteria.md:45`；ChainDrop `supply-chain-security/references/dependency-confusion.md:133`；FirmPilot/Khost `firmware-iot/references/emulation-and-fuzz.md:196`；RFCLLM `protocol-plugin/references/06-app-state-machine.md:115`；MCP/A2A `llm-security/references/agent-protocol-security.md:169`；MemProcFS `forensics-mobile/references/memory-forensics.md:154`；ASAR/V8/IPC `plugin-targets/references/electron-and-asar.md:139`。抽查各节均有出处、命令块、判据字段/表和失败判据节。 |
| 8 | 全仓无任务禁令措辞 | 未达成 | `preflight.py --fast` 的 [13 措辞] FAIL：`docs/audit/D.md(1)`。逐字扫 tracked 全仓仍有 172 处命中/117 文件（主要在 cases、setup、Tool/docs、KB 归档）；`Tool/prompts/tasks/analyze.md:2` 仍写「本轮不产出成品」类阶段限制。门禁自身只扫 skill/prompts/docs/MANUAL 且跳过 CHANGELOG/AUDIT/DEFERRALS/STYLE/_archive，所以「全仓」并未被真正执行。 |
| 9 | 能力 44 + 配方 22 + 意图 60/60 + R34/R35 + site-clone 第 11 域 | 部分 | `capability-gate.py` → 44/44、dangling 0；`Tool/playbooks/` 去掉 INDEX/README 为 22 个；实时 `intent-coverage.py` → summary 60/60、uncovered 0；`Tool/scripts/routing.json:526,536` 有 R34/R35；site-clone 域、4 案例、24 卡均过门禁。但 `Tool/config/capability-matrix.json` 仍只有 10 个 families，无 site-clone 列；`Tool/playbooks/INDEX.md:7-9` 仍写 55/60、5 缺口、91.67%；`work/intent-coverage.json` 也是旧的 55/60。 |
| 10 | 快速路径、上游差分、每域真实战果 | 已落地 | `docs/QUICKSTART.md`、`docs/UPSTREAM.md` 存在；`python Tool/scripts/upstream-delta.py --help` rc=0。11 域均有 real/self-built 且 `repro.status=recorded` 的案例；`forensics06`、`plugin06` 为 real 且含命令/rc 与产物哈希。 |
| 11 | 未完成项：05 后端 4 脚本、forge.py、PROMOTION、playbook 可执行门禁 | 缺失 | `Tool/skill/05-backend-rebuild/` 仅有 `SKILL.md`（114 行），无 scripts/、references/；未找到 api-surface、schema-infer、backend-scaffold、switch-verify 任一命名或等价脚本。Tool/scripts/forge.py 不存在；docs/PROMOTION.md 不存在；除 intent-coverage 读取触发词/能力外，无任何门禁执行 playbook 命令做 rc 校验。替代现状：`Tool/playbooks/backend-rebuild.md` 借用 web-check、pcap-summary、proto-repro，但不是要求的四脚本升级。 |

## 遗漏清单（按影响排序）

1. **P0 阶段⑤仍只有文档**：05-backend-rebuild 无 scripts/references，4 个要求的脚本全部缺席；阶段⑤无法按「一条命令复现」交付，SKILL 里的七步只能靠跨域脚本拼。
2. **P0 生成链断裂**：Tool/scripts/forge.py 不存在，新增技能/配方/能力仍需手改 4–5 处；`new-skill.py` 只生成 SKILL 与一条路由，不生成 playbook/capability/intent/matrix，也无生成后门禁。
3. **P1 playbook「命令可执行」门禁不存在**：没有任何脚本解析 `Tool/playbooks/*.md` 的命令并实跑；步骤里大量 `<case>`/`<URL>` 占位与跨域命令，写错不会被门禁发现。
4. **P1 晋升规则未落文档**：docs/PROMOTION.md 不存在，「三次规则」在仓库内无定义；能力成熟度只能靠人记。
5. **P1 过程文档台账失真**：work/plans/ 实际不存在，但 README/ROADMAP/UPSTREAM/DOMAIN-SPEC/AUDIT 共多处声称已移入；换会话或审计时无法追溯计划原文。
6. **P1 措辞门禁当前红**：旧审计 docs/audit/D.md 既触发措辞 FAIL，又引用不存在的 forge.py 触发悬空引用 FAIL；`preflight --fast` 因此只有 31/33。
7. **P2 意图索引过期**：INDEX.md 与 work/intent-coverage.json 仍为 55/60，实时工具已是 60/60；两份产物会误导后续判断。
8. **P2 第 11 域集成不完整**：能力矩阵无 site-clone 列，任务卡来源表无 site-clone 键；「11 域」只在 domain-gate/技能层成立。

## 重复 / 矛盾 / 过期项

- `docs/AUDIT.md:1` 标题「R1–R4」与正文 R5–R8 并存；`domain-gate` 的 cleanup 断言也只检查 R1–R4。
- `docs/DOMAIN-SPEC-v2.md:13` 写「十域（重点）」却列 11 项；`§2/§10/§12` 仍用「十域」，而门禁实际遍历 11 域。
- `Tool/playbooks/INDEX.md:7-9` 的 55/60、91.67% 与 `intent-coverage.py` 的 60/60、100% 矛盾；`work/intent-coverage.json` 同旧。
- `Tool/config/capability-matrix.json` 只有 10 families，已上线第 11 域 site-clone 无列；与「site-clone 为第 11 域」不一致。
- README 三语仍写「23 个领域技能」，实测 skills=29；`docs/QUICKSTART.md:3` 写「101 条门禁和 24 个技能」，当前 domain-gate 为 110 条断言、技能 29 个。
- `ROADMAP.md` 仍写「九个安全域」且表内无 site-clone；第 11 域只在 domain-gate/技能目录体现，接力文档未同步。
- `docs/audit/D.md` 是上一轮未跟踪审计产物，内容已部分过期（forge.py 仍缺、AUDIT 旧数字），却继续作为工作树文件参与 preflight，形成「审计报告自己把门禁弄红」的循环。
