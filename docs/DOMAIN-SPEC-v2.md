# 领域深度契约 v2（九件套 2.0）

> v1.21.5 解决了「每域有技能」，本文件解决「每域能独立打一场」。
> 所有条目都是**机检**的：`python Tool/scripts/domain-gate.py --all` 直接给结论，不服就跑它。
> 契约变更必须改本文件 + `Tool/scripts/lib/domain_spec.py` + `domain-gate.py` 三处，缺一处即漂移。

---

## 0. 适用范围

| 集合 | 域 | 深度条款 |
| :-- | :-- | :-- |
| 十一域（重点） | `web-pentest` `pwn-crypto` `firmware-iot` `ad-cloud` `protocol-plugin` `plugin-targets` `forensics-mobile` `malware-analysis` `supply-chain-security` `site-clone` `reverse`（= `softseep`） | §1–§8 全部 |
| 其它技能 | `apkseep` `unpack-loop` `binary-diff` `ida-reverse` `llm-security` … | 仅 §7 链接图 + §6 单篇 ≤400 行 |

**逆向域同契约**：`reverse` 与其它十域一样执行 §1–§8（3–5 案例 / 6–10 篇 KB）。
历史沉淀**不删除**，而是归档：案例 → `Tool/cases/_archive/`，深层 KB → `kb/_archive/pe-reverse/`。
归档**不计入**域数量断言，但仍必须被索引、仍受链接完整性检查（§7）。

---

## 1. 篇幅上限（放开后的值）

| 文件 | 上限 | 下限 | 理由 |
| :-- | --: | --: | :-- |
| `SKILL.md` | 600 行 | 120 行 | 600 行够写判据表 + 失败判据 + 失误清单；再长就是没做取舍 |
| `references/*.md` | 400 行 | 60 行 | 60 行以下说明只是口号，不足以复现 |
| `kb/**/techniques/*.md` | 200 行 | 50 行 | 知识库条目是一招一页 |

## 2. references 篇数与必备篇（十域）

每域 **6–10 篇**，其中 4 篇是**固定职责**，文件名必须能被门禁识别：

| 必备篇 | 文件名模式 | 必须包含 |
| :-- | :-- | :-- |
| 判据表 | `01-criteria.md` | 表格列：场景 / 输入面 / 判据（可机检）/ 证据形态 / 误报风险 |
| 失败判据表 | `02-failure-criteria.md` | 表格列：现象 / 判定 / 改走哪条 / 代价；至少 8 行 |
| 模型常见失误 | `03-model-pitfalls.md` | 至少 10 条，每条：错误动作 → 为什么错 → 正确动作 |
| 真实案例走查 | `04-walkthrough-*.md` | 目标、命令、原始输出片段、结论、边界，能照着复跑 |

其余 2–6 篇为领域深度篇，文件名自由但必须被 SKILL/README/案例引用。

## 3. scripts（每域 20–40 行起步，2–4 个）

| 角色 | 命名 | 硬要求 |
| :-- | :-- | :-- |
| 探测/分诊 | `<dom>-check.py` / `<dom>-triage.py` / `<dom>-probe.py` | `--help` rc=0；只读，不联网写操作 |
| 解析/复现 | `<dom>-repro.py` / `<dom>-parse.py` / `<dom>-summary.py` | `--help` rc=0；输入本地样本/pcap/清单，输出 JSON |
| 验收 | `<dom>-accept.py` | `--help` rc=0；`--self-test` rc=0；跑案例目录复算判据 |

统一行为：

1. 任何脚本 `--self-test` 必须在**没有外网、没有真实目标**的情况下 rc=0，并打印 `{"ok": true, ...}`；
2. 失败必须输出结构化 `{"ok": false, "blocked_at": "...", "reason": "..."}` 且 rc=1/2，不许抛裸栈；
3. 路径必须由 `__file__` 推导或 `--root` 传入（本机绝对路径属返工）。

## 4. cases（每域 3–5 个）

`Tool/cases/<domain><NN>/case.json` 必填字段：

```json
{
  "id": "web-pentest03",
  "domain": "web-pentest",
  "target_type": "本地 Flask 靶场（夹具）",
  "evidence_kind": "fixture",
  "protection": [],
  "authority": "local",
  "goal_level": "L3",
  "outcome": "confirmed",
  "artifacts": [{"path": "artifacts/run.json", "sha256": "<门禁复算>"}],
  "lessons": ["..."],
  "refs": ["Tool/skill/web-pentest/references/01-criteria.md"],
  "updated": "2026-10-21"
}
```

- `evidence_kind` ∈ `fixture` | `real` | `self-built` | `historical`；`real`=对真实第三方/系统资产执行，`self-built`=现场编译/自建靶（真实产物，非手写数据），`historical`=历史归档（命令未留存，必须写 reason）。**每域至少 1 个 `real` 或 `self-built`，且其中 ≥1 个有命令+rc**；`historical` 不计入数量、不得单独成域（本地起服务、真样本、真 pcap、真 APK/固件都算 real，只要不是手写假输出），且 `lessons` 第一条必须写清「跑的是什么、命令是什么、rc 多少」；
- `target_type` 必须与 `evidence_kind` 自洽：`fixture` 的 target_type 必须含「夹具/教学/fixture」之一；`real` 的不得含这些词；
- `artifacts[].sha256` 由门禁**复算**，不一致即 FAIL；
- `refs` 指向的文件必须存在；
- `outcome` 只取实测值；想做的进 ROADMAP，不进案例。

## 5. KB（每域 6–10 篇，含 1 篇失败判据）

`Tool/mcp/Tool/reverselab/kb/<board>/`：

- `README.md`（board 索引，必须链接到每一篇 technique）；
- `techniques/` 5–9 篇，其中**必须有一篇**文件名含 `failure-criteria`，内容为失败判据表；
- 每篇 ≤200 行（`reverse` 例外：≤400 行，因为它是深度技术卷，与 references 同档），
  含：入口信号 / 可复制命令 / 确认判据 / 失败判据 / 边界。
- 归档：超出篇数上限的历史文章移入 `Tool/mcp/Tool/reverselab/kb/_archive/<board>/`，
  由其 `README.md` 逐篇索引；归档不计入数量，但仍受 §7 链接约束。

## 6. 矩阵

`Tool/config/<domain>-matrix.json`：`rows` 或 `families` ≥ 12 条，每条含
`match`/`tools`/`commands`/`criteria`/`fail`/`pitfalls`（字段名允许 `rows` 或 `families` 承载）。

## 7. 链接图（无孤儿）

仓库内每个 `references/*.md` 与 `kb/**/*.md`，必须被**至少一处其它文件**以路径字符串引用
（SKILL / README / routing 片段 / 案例 refs / 矩阵 / 本契约），否则 FAIL。
孤儿文件 = 写了没人读，等于没写。

## 8. 任务卡（每域 20–30 张）

`Tool/prompts/domains/<domain>.md`，每张卡固定六段：

```
### <编号> <卡名>（源：<上游技能名>）
- 触发词：...
- 前置：...
- 步骤：1) ... 2) ... 3) ...
- 判据：...
- 失败判据：...
- reference：Tool/skill/<domain>/references/<file>.md
```

门禁解析：卡片数 20–30；六段齐全；`reference` 路径必须存在；同一域内卡名不重复。

## 9. 路由（不得串味）

`Tool/scripts/routing.json` 的关键词必须带词边界或语境限定（`\b`、`(?i)`、前后锚定、组合 `mustAll`）。
`Tool/scripts/lib/domain_spec.py` 的 `ROUTING_TESTS` 是固定测试集，至少覆盖：
`zipalign`→apkseep、`spider`→web-pentest、`principal`→ad-cloud、`bios`→firmware-iot、
`scaffold`→supply-chain 或 plugin 之外的合理域、`src/xxx.dll`→不是 web。
门禁逐条跑，命中错域即 FAIL。

## 10. 部署一致

`~/.pi/agent/skills/<name>/SKILL.md` 若存在，其 sha256 必须与仓库同路径一致；
逐域（十域）比对，任一不一致 FAIL（提醒重跑 `setup/install.ps1 -SkillsOnly`）。

## 11. 清理

根目录 `*.md` **只允许** `README.md` / `README.zh.md` / `README.en.md` / `ROADMAP.md`。

其余一律移出：过程文档 → `work/plans/`（gitignore）；提示词与 agent 契约 →
`Tool/prompts/sources/`（提示词源）与 `Tool/prompts/contracts/`（AGENTS/CLAUDE/DSH）；
变更日志 → `docs/CHANGELOG.md`。宿主要读项目级契约时，从 `Tool/prompts/contracts/` 取。

- `ROADMAP.md` ≤80 行，只写「现在能做什么 / 下一步 / 已知延迟项」；
- `docs/AUDIT.md` 必须存在且含 R1–R4 四轮「证据/判定/处置」，不许留「待填」占位行；
- 门禁 `check_cleanup` 执行上述 allowlist（不在表内的根 `*.md` 即 FAIL）。

---

## 12. 门禁用法

```bash
python Tool/scripts/domain-gate.py --all            # 十域全量
python Tool/scripts/domain-gate.py --domain web-pentest --json
python Tool/scripts/domain-gate.py --links          # 只跑链接图
python Tool/scripts/domain-gate.py --routing        # 只跑串味测试集
python Tool/scripts/preflight.py --fast             # 全量门禁（含本节全部断言）
```

退出码：0 = 全绿；1 = 有 FAIL；2 = 契约自身漂移（`domain_spec.py` 与磁盘不一致）。
