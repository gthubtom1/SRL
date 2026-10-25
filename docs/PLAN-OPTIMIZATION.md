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

## 6. 最终验收清单（6 条，全绿才叫完成）

```
[ ] 1. python Tool/scripts/check.py --fast                       → rc=0 或只剩"已知未修"清单内的项
[ ] 2. python Tool/scripts/preflight.py --fast                   → 无假绿；budget 真红/真绿与账本一致
[ ] 3. python Tool/scripts/gate.py --all                         → 9/9，且不退步
[ ] 4. python Tool/scripts/case_state.py verify --all             → pass 数 ≥ 12 且空账本不再被算过
[ ] 5. 全部模板 + 2 份真实交付物 report --check 全绿；每案有 recheck 段
[ ] 6. route --resolve 五句用户原话：3 句落对域、2 句（SQL注入/智能合约）不出错域
```

**已知不修（诚实清单，不假装完成）**：
- 提示词预算 11514 → 目标 3500：本轮只做去重与指针化，**不承诺达标**；达标需要产品取舍（砍哪 20 条 "必须"），由用户拍板。
- 52 个空账本案例：本轮不补历史欠账（PM-SPEC §7.5 明确"旧目标不追溯"），只保证新案子不再空。
- 29 个"账本有、代码无"的工具：不补假适配器，改为在能力表里显式标"无通路"。
- `ida` / `x64dbg` 端到端：需要授权与真实 GUI，本轮只做到"不自动拉起 + 出确认卡"。
