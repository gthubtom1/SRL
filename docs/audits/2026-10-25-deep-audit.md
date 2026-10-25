# 深度审计（子代理 A/B，2026-10-25）

> 覆盖：A=技能层 190 文件/≈21.5k 行；B=脚本+配置层 127 文件/≈22.4k 行。只读。

## 已修（本轮）

| # | 问题（证据） | 修法 |
| :-: | :-- | :-- |
| 1 | `case_state.py` 的 `lock/unlock/who/ask` **四个子命令必崩**（`d, _, _ = paths(...)` 但 `paths()` 返回 2 元组）→ **唯一允许的问人方式 ask 与租约锁全失效** | 4 处改成 `d, _ = paths(...)`；四个命令实测通过（ask 能生成卡片） |
| 2 | `preflight.py` 引用**不存在的 `smoke-e2e.py`** → 全量 preflight 永远红（Agent 只看 `--fast` 所以从没发现） | 删除该项与文档提及 |
| 3 | `preflight.py` 有**重复函数定义**（`check_case_contract_files` ×3、`check_domain_commands` ×2）→ 前几版是死代码 | 各保留 1 个；同时修掉删空体导致的语法错 |
| 4 | `python Tool/scripts/check.py --env` **12 条断言全是归档前世界**（要求 `00-analysis`/`client-license…`/`safe-skills`/`routing.json` 在顶层）→ 用户双击 `check.bat` 一片红 | **退役** `python Tool/scripts/check.py --env/.sh` 到 `docs/history/legacy-verify/`；`check.ps1`/`check.bat` 改为直接调 `check.py`（**只留一个测试入口**）；全仓 26 处引用改指 |

## 待修（已写入规划，按 pm-plan 优先级）

### P0（会害人/白忙）
- `unpack-loop/references/anti-debug.md` 15+ 处引用不存在的 `probe_matrix.py`（同文件 `:3` 自己写"已不存在"）
- `_pending/binary-diff/SKILL.md:151` 指向不存在的 `references/symbol-migration.md`、`patch-diff.md`（该技能无 references 目录）
- `apkseep/SKILL.md:472` 要求跑 `check_routing.py`，该文件不在 skill 内
- `softseep/SKILL.md:347` 列 `refresh-tool-index.ps1`（已删）
- 技能里仍在用已删工具：`seep_pe_resources` / `seep_decompile_auto` / `seep_r2_functions` / `seep_tool_install`
- 技能里仍路由到已删技能：`_pending/ad-cloud`、`client-license-validation-bypass`
- 命令反引号嵌套破损（复制即非法）：`firmware-iot:152/205/213`、`forensics-mobile:216`、`_pending/02-ui-rebrand:86/119`
- 自相矛盾门：`firmware-iot:222` 要求 `--radio-only`，`:229` 说"不支持"；`web-pentest:11` 要工单 vs `:28` 不要
- `packs.baseline.json` 记 40 个工具（实际 20）；`mcp-servers.json` 3 个 vs baseline 5 个
- `criteria-inferred/*.json` 10 份同一句白名单 → 可整片关掉"≥1 脚本背书"断言
- `ad-cloud-matrix.json` 6 处 `commands` 是散文占位（不可执行）

### P1（能不能用）
- `_pending/INDEX.md` 三方计数不一致（README 19 / INDEX 标题 16 / 表 15 / 实际 17，且缺 `pm-plan`、`ad-cloud` 被写"已删除"却仍在）
- 5 个域 description 缺文件后缀（web-pentest / protocol-plugin / pwn-crypto / supply-chain-security / forensics-mobile）
- 阶段契约块在 8 个域 SKILL.md 里逐字重复（改一处要改 8 处）
- 三套交付刻度并存无换算：M1–M4 / T1–T3 / L1–L3
- `route.py` 的 `must` 语义（AND/OR）未定性：若为 AND，9–10 条 `must` 的域几乎永不命中
- `intent-probes.json` 记 90 条，families 88，实际 93
- `playbook-domains.json` 缺 `osint-recon` 键

### P2（好不好用）
- 6 个体检入口（preflight / check / domain-gate / verify（已退役）/ check.ps1 / env-check）
- 工具目录 4 套实现（ToolDiscovery.ps1 / tool-capabilities / tool-runtimes / tool_autodiscover）
- 死脚本：`domain-pack-check.py`（无调用）、`shot_ida.ps1`/`trigger_ida_mcp.ps1`（硬编码 PID 11260）
- 危险默认：`net-rollback.py do_restore` 默认不是 dry-run；`mcp-bridge-x64dbg` 被调用即拉起 GUI

---

## 第 2 批修复记录（2026-10-25）

| # | 项 | 状态 | 做法 |
| :-: | :-- | :-: | :-- |
| 1 | 8 个域 SKILL.md 逐字重复的"域契约块" | ✅ | 压成一行指针（内容只在 softseep 一份） |
| 2 | 三套交付刻度无换算（M1–M4 / T1–T3 / L1–L3） | ✅ | softseep 加换算表：T1≈M1、T2≈M2、T3≈M3、L1≈M1… |
| 3 | 死脚本 `domain-pack-check.py` / `shot_ida.ps1` / `trigger_ida_mcp.ps1` | ✅ | 删除；文档引用改指 `tool-acquire.py --tool ida` |
| 4 | `net-rollback restore` **默认真执行**（能一条命令改回整机网络） | ✅ | `ps()` 尊重 `_DRY`；不带 `--yes` 一律 dry-run（实测只打印 `[dry-run]`） |
| 5 | 15 个子技能描述是名词式（选不中） | ✅ | 全部改成"用户原话 + 文件后缀" |
| 6 | `ad-cloud-matrix.json` 8 处 `commands` 是散文占位 | ✅ | 换成真实脚本 `adcloud-check.py` |
| 7 | `criteria-inferred` 每字段都是同一句样板 | ⚠️ **保留并记账** | 文件之间不同（domain/fields 各异），样板句是"未背书字段"的统一说明；改成逐字段写验证方式属内容工程，先记 B 类 |
| 8 | 6 个体检入口 | ⚠️ 部分 | 已退役 `verify.*`（上批）→ 现为：`check.py`（唯一测试入口）+ `preflight/domain-gate`（内部套件）+ `check.ps1`（薄包装）+ `env-check.py`（环境） |
| 9 | 4 套工具目录（ToolDiscovery.ps1 / tool-capabilities / tool-runtimes / tool_autodiscover） | ⚠️ 保留 | 各有唯一消费者，合并需重写 PowerShell 侧，风险 > 收益（记 B 类） |
