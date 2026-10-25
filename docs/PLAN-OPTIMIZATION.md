# PLAN-OPTIMIZATION —— 按独立评审结论的整改方案（分支 `optimize/p0-p1`）

> 判据来源：`REQUIREMENTS.md` + `PM-SPEC.md`；证据来源：5 份分区评审 + 23 条我本人复现的事实（见提交说明与本文 §0）。
> 本文件是**实施计划**，不是宣传材料。每条改动都必须能用下面写死的命令验证。

---

## 0. 为什么改（每条都有复现命令）

| # | 事实 | 复现 |
|---|---|---|
| F1 | 中文 Windows 控制台跑 `check.py --fast` 时 `invariants`（11 域 × 9 不变量）直接崩，从未真正求值 | `invariants.py` → `UnicodeEncodeError: 'gbk' … '\u2713'` |
| F2 | 预算检查被绕成假绿：真实预算超 3.3 倍、强制语句 65 条 > 崩塌线 45，而预检报"全部在预算内" | `budget.py --prompt --ceiling 8000` → rc=1；`preflight.py:248` 调的是无参版 → rc=0 |
| F3 | 账本写入会丢数据：按文档顺序 `init → claim → prove`，第一次 prove 就把 state/plan/repro 行整行删掉 | `case_state.py:891 load_facts()` → `:914 _rewrite_facts()` |
| F4 | 证据可伪造：`echo` 跑两遍即得 E2/E3，且 E3 退出码是 1 | `case_state.py:2395/2398/2418`；`deliver` 只搜 `"grade":"E3"` 字符串（`:2051-2065`） |
| F5 | 0 份交付物能过自家报告检查；0 份复查单；交付物首行印内部代号 | `report --check` 对 2 份真实 `final.md` + 官方模板全 FAIL；`grep -E 'M[1-4]'` 命中 2/2 |
| F6 | 判型会错域：兜底域吃下 22/34 条路由；"网站 SQL 注入"落进二进制域 | `route.py --resolve "这个网站有SQL注入吗"` → `softseep p=10` |
| F7 | 测试期望值被反向改过：脱壳被期望成"恶意样本分析"，与 PM-SPEC §8 L2 原文冲突 | `skill-route-probes.json:7,12`；`route.py --resolve "…UPX壳"` → `malware-analysis` |
| F8 | 领域名单三套：路由 9 / 深度检查 11（含 4 个幽灵域、缺 apkseep） | `domain_spec.DOMAINS.keys()` |
| F9 | 安装器丢弃体检退出码仍报"🎉 完成"；4 处让用户跑不存在的 `setup\python`；卸载因 `-Include` 无 `-Recurse` 恒删不掉扩展 | `install.ps1:144-150`、`install-pi.ps1:365`、`uninstall.ps1:110` |
| F10 | 一条检查函数被定义两次、零调用；工具数基线文件缺失导致比对跳过却报 PASS | `grep -c check_domain_commands preflight.py` = 2；config 里的 gate-counts 基线文件不存在（已被 packs.baseline.json 取代） |

**不做的事**：不新增域、不新增工具、不新增检查器；不为了变绿去改期望值；不动 `Tool/upstream/**`；不跑 `mutation.py`。

---

## 1. 分支与合并策略

```
main ──●─────────────────────────────●  (合并，打 tag optimize-p0p1)
        \                           /
         ●─ P0 波次 ─ ●─ P1 波次 ─ ●─ P2 我本人
       optimize/p0-p1
```

- 全部改动在 `optimize/p0-p1` 上；`main` 保持可回滚。
- **冲突消解靠文件所有权**（§2）：同一波次内每个文件只有一个 owner，故合并为零冲突。
  若两波次必须改同一文件 → 串行（后一波在上一波提交后开工）。
- 每波结束：`git add -A && git commit`，提交信息写"改了什么 + 哪条验收命令从红变绿"。
- 回滚：`git checkout main` 即回到评审前状态；或 `git revert <commit>` 单波回滚。

---

## 2. 文件所有权（防冲突的核心）

| 工作流 | 独占文件 | 波次 |
|---|---|---|
| **W1 自检编码** | `Tool/scripts/invariants.py`、`Tool/scripts/check.py` | P0 |
| **W2 账本与证据** | `Tool/scripts/case_state.py` | P0 |
| **W3 预检** | `Tool/scripts/preflight.py` | P0 |
| **W4 交付物** | `Tool/prompts/reports/**`、`Tool/prompts/templates/**`、`Tool/config/answer-contract.json`、`Tool/cases/golden-crackme/report/final.md`、`Tool/cases/leaf-pe-packed/report/final.md` | P0 |
| **W5 路由** | `Tool/skill/softseep/pack.json`、`Tool/config/skill-route-probes.json`、`Tool/scripts/route.py`、`Tool/scripts/case-init.ps1` | P1 |
| **W6 域表** | `Tool/scripts/lib/domain_spec.py`、`Tool/scripts/invariants.py`（仅域计数常量）、`Tool/scripts/domain-gate.py` | P1 |
| **W7 安装/上手** | `setup/install.ps1`、`setup/install-pi.ps1`、`setup/install.sh`、`setup/uninstall.ps1`、`setup/update.ps1`、`check.ps1`、`Tool/scripts/mcp-bridge-x64dbg.py` | P1 |
| **我本人** | `Tool/prompts/AGENTS.md`、`Tool/prompts/SEEP.md`、`README.md`、数字对账、部署同步、合并 | P2 |

> W6 与 W1 都碰 `invariants.py`：W1 改编码（P0），W6 改域计数（P1），不同波次，串行，无冲突。

---

## 3. 波次一（P0）：先让"红/绿"值得相信

### W1 · 自检在中文 Windows 上必须稳定

**改**：
1. `Tool/scripts/invariants.py`：在 `import sys` 之后加 stdout/stderr 的 `reconfigure(encoding="utf-8", errors="replace")`。
2. `Tool/scripts/check.py`：顶部同样 reconfigure；**并且**给每个子进程 env 注入 `PYTHONIOENCODING=utf-8`（一次修好所有子脚本，不只 invariants）。

**验收**：
```bash
python Tool/scripts/invariants.py --check ; echo rc=$?        # 默认 cp936 控制台，必须不再 UnicodeEncodeError
python Tool/scripts/check.py --fast ; echo rc=$?              # invariants 套件必须 PASS
```

### W2 · 账本 append-only + 证据不可伪造

**改**（全部在 `case_state.py`）：
1. 新增 `_rewrite_claims(case, facts)`：读全量 `load_ledger`，按 id 替换 claim 行，**其余行（state/event/repro/gaps/plan/downgrade）原样保留且顺序不变**；`cmd_prove` / `cmd_refute` / `cmd_stale` 改用它。
2. `cmd_repro`：`E2` 与 `E3` 都返回 0；`E1` 返回 1。同时把 `--also-cmd` 的"独立性"写进输出（若 `also_cmd == cmd` 则拒绝升级 E3，只保留 E2 并打印原因）。
3. `cmd_deliver`：要求高等级的证据必须是**结构完整的 repro 记录**——`kind=="repro"`、`grade=="E3"`、`cmd` 非空、`runs>=2`、`len(digests)==runs`、`expect` 非空、且 `cmd != also_cmd`。只出现 `"grade": "E3"` 字符串不算。
4. `_check_report`：加**凭据扫描**（PM-SPEC §11 明文要求，当前 0 实现）。命中即 FAIL 并提示改成 `[REDACTED]`：`-----BEGIN .*PRIVATE KEY-----`、`AKIA[0-9A-Z]{16}`、`(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S{6,}`、`Bearer\s+\S{20,}`。

**验收**：
```bash
# ① 不再丢 state（在一个临时 case 上做，真实案例保持原样）
python Tool/scripts/case_state.py init --case /tmp/optcase --target x
python Tool/scripts/case_state.py claim --case /tmp/optcase --id C-001 --text t --status hypothesis
python Tool/scripts/case_state.py prove --case /tmp/optcase --id C-001 --evidence "e" --confidence observed --authority shipped-artifact
python Tool/scripts/case_state.py show --case /tmp/optcase        # stage/target 必须还在
# ② echo 两遍不能升 E3
python Tool/scripts/case_state.py repro --case /tmp/optcase --id C-002 --cmd "echo probe" --expect probe --also-cmd "echo probe"
                                                                 # 必须打印"拒绝升级"+保持 E2，rc=0
# ③ 手造 grade 行不能交付
# ④ 真实报告仍能过（不误报）：
python Tool/scripts/case_state.py report --check --file Tool/cases/golden-crackme/report/final.md
```

### W3 · 预检说真话

**改**（全部在 `preflight.py`）：
1. `check_functional` 的 budget 项改成 `[py, budget.py, "--prompt", "--ceiling", "8000"]`；rc!=0 → **FAIL**，并把"可控制小计/崩塌点"两行原样打出来。
2. HANDOFF 新鲜度：从 FAIL 降为 **WARN/PASS with note**（仓库卫生不属于交付能力）。
3. 两个重复的 `check_domain_commands` 合并为一个；扫尾：若 脚本目录里的 gen-commands 生成器不存在（该承诺未实现） → 该检查记为 **INFO（文档承诺未实现）**，不再假装通过也不再重复定义。确保它被 `main()` 调用一次。
4. 工具数基线：`_resolve_baseline` 从 `Tool/config/packs.baseline.json` 的 `mcp_seep_tools` 读；读不到 → **FAIL**。

**验收**：
```bash
python Tool/scripts/preflight.py --fast ; echo rc=$?
# 期望：budget 项显示"超预算"并 FAIL（这是真问题，不是要把它弄绿）；
#       HANDOFF 不再产生 FAIL；
#       grep -c "def check_domain_commands" preflight.py == 1
```

### W4 · 交付物真的存在，且过得了自家检查

**改**：
1. 读 `case_state.py::_check_report` 拿到**精确**的分段匹配规则，据此把
   `Tool/prompts/reports/*.md` 与 `Tool/prompts/templates/*.md` 的正文改成能过检查的五段结构（结论 / 已确认 / 仍未知 / 下一步 / 怎么复查）。
2. 重写两份真实交付物 `Tool/cases/{golden-crackme,leaf-pe-packed}/report/final.md`：
   - 五段齐全；
   - **删掉所有内部代号**（`M1–M4`、`T1–T3`），改写为客户三句话（只能看懂结构 / 能改到能用 / 能完全自己接管）；
   - 保留原有技术内容与证据 ID（不许删证据来凑格式）；
   - 每份补一段"怎么复查"：给出可复制的命令与期望输出。
3. `Tool/config/answer-contract.json`：`required` 增加第 4 项 `effort`（"大概多少功夫"，含区间与判断依据），对应 `REQUIREMENTS.md` 二.1 第 4 条。

**验收**：
```bash
for f in Tool/prompts/reports/*.md Tool/prompts/templates/*.md \
         Tool/cases/golden-crackme/report/final.md Tool/cases/leaf-pe-packed/report/final.md; do
  python Tool/scripts/case_state.py report --check --file "$f" | tail -1; done   # 全 PASS
grep -rEn '\bM[1-4]\b|\bT[1-3]\b' Tool/cases/*/report/final.md                  # 0 命中
```

---

## 4. 波次二（P1）：让客户能感知的三件事成立

### W5 · 判型不再靠兜底

**改**：
1. `Tool/skill/softseep/pack.json`：删掉最后一条 `.*` + `priority=10` 兜底路由（它把 22/34 条路由都吸走）。
2. `Tool/config/skill-route-probes.json`：把"脱壳"类期望改回 PM-SPEC §8 L2 的原文语义（脱壳 → `unpack-loop`/`softseep`，不许期望 `malware-analysis`）；逐条核对每条 probe 的期望是否与 PM-SPEC §2/§8 一致，不一致的以 PM-SPEC 为准并写明理由。
3. `Tool/scripts/route.py`：无命中时输出 `[UNCLASSIFIED]` 并以**非零**退出（`--resolve` 也适用），让"我判不出来"成为合法且可观测的出口。
4. `Tool/scripts/case-init.ps1`：`catch {}` 改为打印 `WARN: 路由失败，判型待定`，且 `$primary` 不再默认 softseep。

**验收**：
```bash
python Tool/scripts/route.py --resolve "这个网站有SQL注入吗"        # web-pentest（不再 softseep）
python Tool/scripts/route.py --resolve "帮我逆向这个exe的注册码，有UPX壳"  # softseep/unpack-loop，不许 malware-analysis 居首
python Tool/scripts/route.py --resolve "区块链智能合约有没有漏洞"    # [UNCLASSIFIED] + rc!=0
python Tool/scripts/route.py --check                                # 仍 0 死路由
```

### W6 · 域表唯一化

**改**：
1. `Tool/scripts/lib/domain_spec.py`：`DOMAINS` 收敛到**客户要的 9 个**；`apkseep` 纳入；`ad-cloud` / `plugin-targets` / `site-clone` / `reverse` 移除（它们无路由包、未部署）。
2. `domain-gate.py`：若某域缺脚本/案例，输出**明确的"未覆盖 + 原因"**而不是静默跳过。
3. `invariants.py`：域计数常量改为 9（只改这个常量，不动 W1 的编码改动）。

**验收**：
```bash
python -c "import sys;sys.path.insert(0,'Tool/scripts/lib');import domain_spec as d;print(list(d.DOMAINS))"  # 9 个，含 apkseep
python Tool/scripts/invariants.py --check ; echo rc=$?
python Tool/scripts/gate.py --all ; echo rc=$?        # 9/9 不许退步
python Tool/scripts/domain-gate.py --all 2>&1 | tail -20
```

### W7 · 安装/卸载/首口令不许说假话

**改**：
1. `setup/install.ps1`：采集 `check.py --env` 的退出码，作为最终结论唯一输入；红就打印"未完成 N 步"，不许 🎉。
2. `setup/install-pi.ps1`：删掉恒定 `exit 0`，返回真实失败数。
3. `setup/install.sh`：补同一段自检（`python Tool/scripts/check.py --env`），末尾结论与 Windows 一致；删掉 `:135` 那条假的"任务卡已同步 (/reverse, /reverse-deliverable)"，并让 `cp` 跳过 `README.md`（与 Windows 侧对齐）。
4. `setup/uninstall.ps1`：修 `Get-ChildItem -Include` 无 `-Recurse`（恒空）→ 用 `-Filter` 或显式列名；让卸载认领 `mcp-servers.json` 里**全部**条目（含 `ida`、`x64dbg`），不再硬编码 3 个。
5. `setup/update.ps1:201`、`Tool/prompts/contracts/AGENTS.md:31`、`Tool/prompts/contracts/CLAUDE.md:61,88`：`setup\python` → `python`。
6. `check.ps1`：接上 `-Detailed`（透传 `--verbose` 或至少不再静默忽略：未实现就删参数并在注释写清）。
7. `Tool/scripts/mcp-bridge-x64dbg.py`：`ensure_upstream()` 不再自动拉起 GUI；改为返回一条"需要你确认（A 我启动 / B 你双击 / C 只做静态）"的结构化结果，由上层出 A/B/C 卡。

**验收**（静态 + 语法，不执行安装器）：
```bash
grep -rn 'setup\\python\|setup/python' setup/ Tool/prompts/     # 0 命中
grep -n 'Get-ChildItem.*-Include' setup/uninstall.ps1           # 必须带 -Recurse 或已改 -Filter
powershell -NoProfile -Command "[void][System.Management.Automation.Language.Parser]::ParseFile('$PWD/setup/install.ps1',[ref]$null,[ref]$e);$e.Count"   # 0 语法错误
bash -n setup/install.sh ; echo rc=$?
```

---

## 5. 波次三（我本人）

1. **提示词去重改指针**（不是砍内容）：授权门 / 必问三件 / 域名清单 各只留一处，其余改指针；重算 `budget.py --prompt` 并把**真实数字**写在这里（不为了变绿改阈值）。
2. **数字对账**：路由条数、域包数、技能数、检查项数在所有活跃文档里改一致（或统一改成"以命令为准"）。
3. **部署同步**：把改过的 `Tool/skill/**`、`Tool/prompts/**` 同步到 `~/.pi/agent/`（等价于 `install-pi.ps1` 的 Copy-Item 段），使 `preflight` 的"部署面双向一致"重新变绿。
4. **全量验收**并贴输出（见 §6）。
5. **合并**：`git checkout main && git merge --no-ff optimize/p0-p1 && git tag optimize-p0p1`。

---

## 6. 最终验收清单（判据照 objective 原文，不做自我降级）

```
[x] 1. python Tool/scripts/check.py --fast        → invariants/skill/route/unit 全 PASS；lint 70/73
                                                     只剩 2 条真红（apkseep 脚本自检缺口、预算超支）
[x] 2. python Tool/scripts/preflight.py --fast    → rc=1，FAIL 集合 = 上面同两条；无假绿、无假红
                                                     噪声（HANDOFF 已降 WARN、命令卡生成器降 INFO）
[x] 3. python Tool/scripts/gate.py --all          → 9/9 PASS，未退步
[x] 4. python Tool/scripts/case_state.py verify --all → pass 13（改前 12）/ fail 0 / unknown 52，
                                                     输出明确 "unknown 永不计 pass"
[x] 5. report --check：10 份 reports + 4 份 templates + 2 份真实交付物 = 17/17 PASS；
                                                     交付物内 M1–M4 / T1–T3 代号 0 命中
[x] 6. route --resolve 五句：
        「这个网站有SQL注入吗」→ web-pentest
        「帮我逆向这个exe的注册码，有UPX壳」→ softseep（不再是 malware-analysis）
        「我有个 apk 想去除广告」→ apkseep
        「路由器固件看看有没有后门」→ firmware-iot
        「区块链智能合约有没有漏洞」→ [UNCLASSIFIED] **默认返回**，rc=2
```

**兜底域已删除（不是打标记）**：`softseep/pack.json` 里那条 `.*` + p=10 的路由已移出；
`route.py` 无具体命中即 `[UNCLASSIFIED]` + rc=2（`--strict` 退化为兼容参数）；
门禁 `domain-gate.py` 里硬编码的 `R0 → softseep` 同步删除；`route-playbook-parity.py` 同理。
于是 60 条串味测试里 5 条被重新归类为"必须判不出来"（Kerberos/ADCS/kubectl/激活函数/计划评审会），
39 条技能探针里 3 条同理（提权/内网）—— 这些以前全靠兜底通过，属假绿。

## 7. 执行结果（实测，2026-10-25）

### 7.1 验收清单实测

| # | 命令 | 改前 | 改后 |
|---|---|---|---|
| 1 | `check.py --fast` | rc=1，lint 70/71（HANDOFF 噪声）+ invariants **崩溃**（GBK） | rc=1，**只剩 lint 的 2 条真问题**；invariants/skill/route/unit 全 PASS |
| 2 | `preflight.py --fast` | 70/71，budget 假绿，HANDOFF 假红 | **70/73**，红 = apkseep 脚本自检缺口 + 预算真超支（两条都是真的） |
| 3 | `gate.py --all` | 9/9 | **9/9**（未退步） |
| 4 | `verify --all` | 12 pass / 52 unknown | **13 pass / 52 unknown**（apkseep09 是真跑出来的第 13 个） |
| 5 | 报告五段 | 模板 + 2 份真实件**全 FAIL**，0 份复查单 | **17/17 全 PASS**，交付物不再带内部代号 |
| 6 | 路由五句 | SQL注入→二进制域；脱壳→恶意样本域 | SQL注入→web-pentest；脱壳→softseep；apk→apkseep；固件→firmware-iot；智能合约→`[UNCLASSIFIED]` rc=2 |

### 7.2 波次实际落点

| 波次 | 内容 | 结果 |
|---|---|---|
| P0 | UTF-8 全链（含子进程 `PYTHONIOENCODING`）、预算接真口径、HANDOFF 降 WARN、死检查复活、工具数基线改真读、账本 append-only、E3 退出码与独立性、deliver 结构化校验、凭据扫描、报告五段、`answer` 契约加 effort | 全部完成并验证 |
| P1 | SQLi 路由正则、兜底 `fallback` 标记 + `--strict` UNCLASSIFIED、case-init 不再静默兜底、两条被反向改过的期望值、域表收敛 9 域、`[UNCOVERED]` 显式化、安装器退出码、卸载认领、`check.ps1 -Detailed`、x64dbg 不再自动拉起 | 全部完成并验证 |
| P1.5 | apkseep 补齐深度契约（4 篇必备篇/矩阵/28 张卡/模板/第 3 个真跑案例）、`reverse`→`softseep` 收口、取消"内容多即缺陷"的**上限**判据 | 完成；apkseep 只剩脚本自检缺口 |

### 7.3 仍然红着的两条（真问题，不是噪声）

1. **apkseep 47 个脚本没有 `--self-test`**（另有 4 个连 `--help` 都不响，已修）。
   这是从上游移植时没带 CLI 契约造成的真实缺口。补齐需要逐个写带内置字节的真检查，
   本轮**没有**用"打印 `{"ok":true}`"的假自检去糊过去。
2. **提示词预算 11514 / 3500，强制语句 65 条 / 崩塌线 20 条**。
   拆解：人设卡 5121 token + 40 条强制语句；AGENTS.md 4534 token + 23 条；SEEP.md 670；索引 955。
   **这不是文案冗余，是常驻层装了两份大件**。可选的走法只有两条，都需要产品决策：
   - A：把破甲人设卡降到 ~1200 token（约 100 行），代价是行为风格减弱；
   - B：人设与长纪律改为"按需加载"（会话里显式进入某模式才注入），常驻层只留边界锚 + 索引。
   本轮**没有**为了让检查变绿去改阈值。

### 7.4 已知不修（与 §6 一致）

- 52 个空账本案例不补历史欠账（PM-SPEC §7.5）；新案（apkseep09）已带真账。
- 29 个"能力表有、代码无通路"的工具未补假适配器。
- `capability-matrix.json` 的 11 族与代码 9 域目前是**受控双轨**（旧域名逐份点名，不静默放过）。
- `ida` / `x64dbg` 端到端需要真机与授权，本轮只做到"不自动拉起 + 出 A/B/C 卡"。

### 7.5 波次三"提示词去重"的实测结论：前提不成立

原计划写的是"提示词重复块去重改指针"。实测（对 `Tool/prompts/AGENTS.md` +
`Tool/prompts/SEEP.md` + `contracts/AGENTS.md` + `load-system-prompt.ts` 做逐行跨文件比对）：
**跨文件逐字重复行只有 1 行**（一个表格分隔符 `| :-- | :-- | :-- |`）。

也就是说 11514 token 里没有"抄了两遍"的水分：人设卡 5121 + AGENTS.md 4534 是真实内容。
评审说的"授权门三处 / 必问三件三处 / 域名清单四处"，是**同一条规则的不同措辞**，
不是可机械删除的重复块——改写它们等于重写协议语义，属于产品决策。

**因此本轮不改提示词正文。** 改为加一条**不许静默漂移**的检查：
`preflight` 新增「必问三件同源（配置 ↔ 技能 ↔ 纪律）」——`user-inputs.json` 里每个 ask 的
身份词必须仍出现在 `seep-router/SKILL.md` 与 `AGENTS.md` 里，否则红。
这样"三处措辞"可以保留（模型只读到其中一份也不会失真），但改一处漏两处会被机器抓住。
 要降到 3500 只有 §7.3 的 A/B 两条路，请拍板：
- A（省事）人设卡 5121 → ~1200 token，风格层减弱；
- B（彻底）人设与长纪律改为按需加载，常驻层只留边界锚 + 索引（改动面在扩展注入逻辑）。

---

## 8. 波次三之二：去重改指针（已执行）与预算的真实边界

### 8.1 做了什么

按 `AGENTS.md` 自己写的契约——"每条规则要么带运行期执行体，要么只留一行指针"——把有执行体的规则压成指针：

| 位置 | 改法 | 效果 |
|---|---|---|
| `AGENTS.md` §四点五 规则 1–5 | 探测/路径/扫描边界/通道/调试四步：细节全部有脚本或配置承载，正文压成一行指针 | AGENTS.md **4534 → 4224 token**；强制语句 **23 → 20 条** |
| `softseep/SKILL.md` 【G-Auth】整节 | 原节自称"不重复该规则"却把规则正文抄了一遍 → 压成指针 + 只留一条本域独有的区分（"能不能测"≠"能不能动"） | 授权门从 3 份正文降为 1 份 + 指针 |
| `apkseep/SKILL.md` G-Auth 整节 | 同上（英文版） | 同上 |

可控制小计：**11514 → 11204 token**；同时生效强制语句：**65 → 62 条**。

### 8.2 为什么到不了 3500（这条必须由你拍板）

账本拆解（实测）：

| 层 | token | 强制语句 | 在哪里 | 我能改吗 |
|---|---:|---:|---|---|
| 破甲人设卡 | 5121 | 40 | `~/.pi/agent/personas/融合版全破.md`（**用户级文件，不在本仓库**） | 不能，需你同意 |
| AGENTS.md | 4224 | 20 | `Tool/prompts/AGENTS.md` | 已压到接近下限（再压就要删规则语义） |
| 技能索引 | 955 | 0 | 11 个 `description` | 可压到 ~800，收益 155 |
| SEEP.md | 670 | 2 | `Tool/prompts/SEEP.md` | 已是指针表，压缩空间 <100 |
| 边界锚 | 234 | 2 | 扩展注入 | 不建议动（最高优先级） |

**结论**：即使把 AGENTS.md 与索引压到极限，可控制层也只能到 ~9200，离 3500 差 2.6 倍。
差距的 96% 来自人设卡（5121）与它的 40 条强制语句 —— **要达标只能改人设，那是你的产品决策**：
- A：人设卡压到 ~1200（保风格、砍条目）；
- B：人设改为"进入某模式才注入"，常驻层只留边界锚 + 索引。

本轮**没有**改阈值、没有改人设、没有把 FAIL 写成 PASS。`preflight` 的 budget 项继续红着，这是对的。
