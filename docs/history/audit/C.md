# C —— 可跑性与门禁真实性（独立审计）

> ⚠️ **历史快照（非现状）**：本文记录的是当时的口径与数字，可能与本仓当前状态不一致。
> 当前状态以 `docs/history/FORK-BRIEF.md` + `docs/RELEASE-1.26.1.md` + 实跑门禁为准。

> 口径：全新上下文、只读；scratch 只落 `work/auditC/`。基线 v1.23.1，实测窗口 2026-10-22 08:40–09:05。
> 审计期间有并行审计在改工作树（`Tool/scripts/preflight.py`、`Tool/skill/05-backend-rebuild/*` 出现 M），
> 下文所有数字均为该时点实测；复跑命令见各条「证据」列。

## 结论

- **门禁在它自己声明的那几条断言上很强**：`domain-gate --all` 110/110（连跑 3 次，`--json` 输出 sha256 完全一致
  `c797973b…`）；我注入的 4 类反例（改 sha / ref 401 行 / 伪 real / 注入 `generated_at`）**全部判红**。
- **但覆盖面被高估**：125 个脚本只有 43 个被断言；案例哈希只覆盖 `case.json` 自报的 `artifacts[]`
  （36 个案例里 80~700 个文件未登记）；`lessons` 里的命令只做文本匹配、**不执行**。
- **双平台实跑红**：`bash Tool/scripts/check.py` rc=1、`check.ps1` rc=1（64 PASS / 1 FAIL / 1 OPTN），
  `preflight.py` 34/36 FAIL 两项，红点同源。
- 判定：**可跑性 P0 未清**（双平台门禁实跑红 + 验收脚本空集判绿）；门禁"反例必红"成立，
  但存在 3 处可实证的「绿而实际坏」。

## P0

| # | 问题 | 证据（可复现） | 修复动作 |
| :-- | :-- | :-- | :-- |
| P0-1 | 双平台体检在 HEAD 就红：两个受跟踪案例脚本硬编码本机路径 | `Tool/cases/site-clone-drill01/scripts/crawl.py:42`、`replay_diff.py:44` = `<HOME>/AppData/Local/ms-playwright/chromium-1243/…/chrome.exe`；`bash Tool/scripts/check.py` rc=1「个人隐私零残留」；`verify.ps1` 同样 64/1 | 改为 `PLAYWRIGHT_BROWSERS_PATH` / `shutil.which` / `--chrome` 参数探测，缺失走 `blocked_at:"tool-missing"`；两处同时改，重跑两条 verify |
| P0-2 | 验收脚本对「不存在的案例」返回成功（空集判绿） | `python Tool/skill/supply-chain-security/scripts/sc-accept.py --case /nonexistent/nope --json` → rc=0，`{"ok":true,"cases":0,"real":0,"failures":[]}`；换 `--case nope-not-a-case` 同样 rc=0 | `--case` 解析失败 → `{"ok":false,"blocked_at":"case","reason":…}` + rc=2；`cases==0` 一律 rc=2 |
| P0-3 | 门禁只校验 `artifacts[]` 自报清单，未登记产物被篡改仍全绿 | 副本 `work/auditC/repo`：改 `Tool/cases/site-clone01/artifacts/accept.json`（该案例 217 个文件未登记）→ `domain-gate --all` 仍 **110/110，rc=0** | 增加断言「`artifacts/` 下每个文件必须登记 sha256（白名单仅 README/输入）」；36 个案例按实测补齐或写明豁免 |

## P1

| # | 问题 | 证据 | 修复动作 |
| :-- | :-- | :-- | :-- |
| P1-1 | 门禁只覆盖 43/125 脚本；82 个无 `--help`/`--self-test` 断言 | 统计见下「脚本矩阵」；`apkseep` 48 个脚本 **0 个**支持 `--self-test`（全部 rc=2），`signin-automation` 4 个、`Tool/scripts` 30 个编排脚本均不在 `domain_spec.DOMAINS` 内 | 把契约扩到「仓库内所有 `scripts/*.py`」或显式登记豁免清单；至少让 `apkseep`/`signin` 进 `DOMAINS` 的 `ext_scripts` |
| P1-2 | 失败路径契约不齐（抽样 30 个脚本 / 13 域：**19 合规、11 不合规**） | `web-check.py`（`--url http://127.0.0.1:1/ --timeout 1`）rc=**3**（脚本 588 行自述「目标不可达」），无 `blocked_at`，与 AGENT-BRIEF 统一的 rc=2 契约不符；`blob_decode.py --file /nonexistent` → **裸 Traceback rc=1**；`repack.py`、`dex_patch_bytes.py` rc=1 纯文本；`start_mcp.py --help` rc=1（`ModuleNotFoundError: idaapi`） | 统一 `Blocked(stage,reason)`；rc 只允许 0/1/2；模块级 `import idaapi` 挪进函数 |
| P1-3 | 5 个 accept 无顶层 `blocked_at/reason`，`fw-accept` rc=1 | `web-accept`/`proto-accept`/`plugin-accept`/`site-accept` 失败只给 `results[].issues`/`problems`；`fw-accept --case /nonexistent` rc=1 | 顶层补 `{ok:false,blocked_at,reason}`，rc=2；子项保留 |
| P1-4 | `--mutation-test` 只回归 4 类，且走**第二套实现** | 源码 795–852 行：`sha256/timeframe/readonly-claim/fake-real`，调用 `_case_errors()`（746 行）；而真门禁走 `check_cases()` 的内联逻辑——`generated_at` 只在后者里查。实测 `_case_errors()` 对含 `generated_at` 的案例返回 `[]`；任务要求的 4 类里 **ref>400 与 generated_at 未被 mutation-test 覆盖** | mutation-test 改为复用 `check_cases()`；用例扩到「ref 401 行 / 注入 generated_at / 未登记产物 / 空集 accept」 |
| P1-5 | 脚本断言只查子串：`'"ok"' in stdout` | `domain-gate.py:196`；副本里把 `crypto-verify.py --self-test` 改成打印 `{"ok": false}` 并 rc=0 → 该断言 **PASS**（唯一红是部署哈希，因副本改了文件） | 解析 JSON 并断言 `ok is True` 且 `checks>0` |
| P1-6 | `lessons` 命令不执行，只匹配文本 | 副本把 `pwn-crypto01` 的 lessons 换成 `python totally-not-a-real-script.py --file x; rc=0` 并重建索引 → **110/110 绿** | `repro.status=recorded` 时抽样真跑（或校验命令首词文件存在）；不存在的二进制/脚本直接判红 |
| P1-7 | 两个门禁对同一事实结论相反 | `preflight.py`「无机器专用绝对路径 — **0 处**」只扫 `Tool/config, setup, Tool/prompts, Tool/scripts`（268 行），漏掉 `Tool/cases`；verify 却对同一批文件判红。另有 28 个受跟踪案例文件内嵌 `D:\Seep-Reverse-Lab\…` 绝对路径 | 统一「可移植」检查的扫描根（至少加 `Tool/skill`、`Tool/cases`）；产物里的 `file` 字段写仓库相对路径 |

## 证据

### 脚本矩阵（125 = 87 skill + 38 `Tool/scripts`）

| 指标 | 结果 |
| :-- | :-- |
| `--help` rc | 120×rc0 / 4×rc2（`devsh` `dexutil` `patch_smali` `smtool`）/ 1×rc1（`start_mcp`） |
| `--self-test` rc | 54×rc0 / 70×rc2 / 1×rc1；53 个输出含 `"ok"` |
| 被门禁断言 | 43/125，且 **43/43** `--help` rc0 + `--self-test` rc0 且含 `"ok"`（契约在被执行处成立） |
| 未被断言 | 82/125：71 个 `--self-test` rc≠0、5 个 `--help` rc≠0 |
| 联网 | 沙箱拦截 250 次调用，仅 1 处 socket：`site-crawl --self-test` 连 `127.0.0.1:54241/54242`（自建本地 fixture），**无外网** |
| 写仓库 | 0 次（仅我自己的日志 `work/auditC/…`）；写仓库外 = `%TEMP%` 沙箱目录 |
| 临时残留 | 每次 `--self-test` 留 1 个 temp 目录：`pcap-self-test-*` 798、`proto-accept-*` 391、`plugin-accept-*` 187（累计 ≈1380）→ 建议 finally 清理 |

### 失败路径抽样（每域 2 个，13 域）

合规（rc=2 + `{ok:false,blocked_at,reason}`）：`pwn-check` `pwn-accept` `fw-triage` `fw-repro` `adcloud-check`
`ad-accept` `pcap-summary`（含坏 JSON `--state-model`）`plugin-triage` `forensics-check` `evidence-accept`
`mal-triage` `mal-accept` `sc-check` `site-diff` `patch-verify` `reverse-accept` `session-pool` `tls-fingerprint`
`ioc-extract`。
不合规清单见 P1-2 / P1-3 / P0-2。

### 确定性

- 同命令跑两次：`domain-gate --all --json` 两次 sha256 相同；`gen-case-index.py` 重写 `Tool/cases/index.json`
  后 `git status` 无差异（`generated_at` 已固定为 1970 纪元）。
- 但「案例产物可复现」不成立：`supply-chain01` 按 lessons 重跑，`locks` 1→0、`workflows` 2→0
  （`--max-files 1000` 截断点随仓库增长漂移），`case.json` 仍标 `recorded`；`pwn-crypto01` 重跑
  sha256=`19ffd77b…` ≠ 入库 `e9ca19ec…`——Windows 下 `--json > file` 产出 CRLF，去 CRLF 后 JSON 完全相等。
- 无动态 `generated_at`（案例侧 0 处）、无主机名；但 28 个受跟踪案例文件含 `D:\Seep-Reverse-Lab\…`。

### 门禁真实性（副本 `work/auditC/repo`，基线 110/110）

| 注入 | 期望 | 实测 |
| :-- | :-- | :-- |
| 改 sha（`pwn-crypto01/artifacts/run.json` 加 1 字节） | 红 | rc=1，sha256 不符 + accept rc=2 ✅ |
| ref 411 行（`web-pentest/references/01-criteria.md`） | 红 | rc=1，篇幅 549 行 + 全局 ≤400 + 部署哈希 3 红 ✅ |
| 伪 real（fixture 改 real、无命令） | 红 | rc=1，`real 却标成夹具` + `real 但无命令/rc` ✅ |
| 注入 `generated_at`（并重算 sha） | 红 | rc=1，`含非空 generated_at` ✅ |

## 修复动作（按顺序）

1. P0-1：两处 `<HOME>…` 改环境探测 → 重跑 `Tool/scripts/check.py` + `check.ps1` + `preflight.py` 必须全绿。
2. P0-2 / P1-3：所有 `*accept*.py` 统一「空集/不存在案例 = rc=2」，顶层补 `blocked_at/reason`。
3. P0-3 / P1-7：加「`artifacts/` 全量登记」+ 扩大可移植扫描根，并清掉产物里的绝对路径。
4. P1-4 / P1-5 / P1-6：mutation-test 复用真门禁逻辑、解析 `ok` 值、抽样真跑 lessons 命令。
5. P1-1：把 82 个未覆盖脚本纳入断言或写豁免清单（`apkseep` 优先）。
6. P1-2：失败路径统一 rc=2 + 结构化 JSON，`start_mcp.py` 延迟导入。

## 限制

- 未验证 `Tool/upstream/*` 与 `Tool/mcp/*`（不在本次范围）；`apkseep` 48 个脚本只做 CLI 层验证，未跑真机用例。
- 并行审计在改工作树，P0-1 之外的 preflight 项（`docs/audit/*` 悬空引用）随其修复而变化，未计入本报告。
