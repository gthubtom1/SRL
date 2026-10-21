# AUDIT —— 多轮审查台账（R1–R4）

> 规则：每轮用**全新上下文子代理**；P0/P1 未清不得进入下一轮；
> 结论只写「证据 + 判定 + 动作」，不写感受。门禁命令与本文件同源：
> `python Tool/scripts/preflight.py`、`python Tool/scripts/domain-gate.py --all`。

## 环境记录

| 项 | 值 |
| :-- | :-- |
| 基线 | v1.21.5（九件套"形似"，preflight 20/20） |
| 本轮目标 | 九件套 2.0（每域能独立打一场）+ 仓库清理 |
| 契约 | `docs/DOMAIN-SPEC-v2.md` + `Tool/scripts/lib/domain_spec.py` |
| 子代理模型 | 先按 Free 模型派发 → `OPENCODE/deepseek-v4.1-flash-free` 返回 422 `Endpoint is unavailable`，`glm-5.3-flash-free` / `minimax-m3.1-flash-free` 无执行工具；按用户指示回退主对话模型（非 Free） |
| 审查方式 | 每轮独立新会话，不继承前轮结论；只允许读与跑门禁，不许改代码 |


## 子代理与模型记录（可核验）

执行约束：子代理优先 Free 模型；实测 `OPENCODE/deepseek-v4.1-flash-free` 返回
`422 upstream_error: Endpoint is unavailable`，`glm-5.3-flash-free` / `minimax-m3.1-flash-free`
虽可应答但无执行工具（只有 read/grep/find/ls），按用户指示回退主对话模型（非 Free）。
下表是各轮审计与内容子代理的会话 ID（pi session id，可在 `~/.pi/agent/sessions/` 检索）。

| 轮次 / 任务 | 子代理会话 ID | 模型 | 产物 |
| :-- | :-- | :-- | :-- |
| 域补全 web / pwn / firmware / reverse | 01a15eb5-1e79 / 01a15eb5-1e86 / 01a15eb5-1e8c / 01a15eb6-61f7 | 主对话模型（非 Free） | 九件套 2.0 第一版 |
| 域补全 ad / protocol / plugin | 01a15ecf-d3b0 / 01a15ecf-d3ba / 01a15ecf-d3bf | 同上 | 同上 |
| 域补全 forensics / malware / supply（含重跑 01a15ef7-2ba7） | 01a15ed4-7018 / 01a15ed4-7021 / 01a15ed4-7028 | 同上 | 同上 |
| 深度修复 pass1（web / pwn+supply / reverse） | 01a15f36-5017 / 01a15f36-5021 / 01a15f36-5027 | 同上 | 覆盖缺口回修 |
| **R1** 结构 / 链接 / 路由 | 01a15f0a-42ce / 01a15f0a-42d7 / 01a15f0a-42dd | 同上 | 本文件 R1 三份结论 |
| **R2** A / B / C | 01a15f24-b49b / 01a15f24-b495 / 01a15f24-b485 | 同上 | R2 三份结论 |
| **R3** 可跑性 | 01a15f3f-9bc8 | 同上 | R3 结论 |
| **R4** 终审（第一版） | 01a15f50-8d38 | 同上 | R4 结论 + 3 个反例 |
| 复审回修 pass2（plugin+forensics / malware+reverse / apkseep 拆分） | 01a15fd5-7c50 / 01a15fd5-7c5a / 01a15fd5-7c5f | 同上 | 覆盖缺口 + 全仓 ≤400 行 |
| Free 模型可用性探针 | 01a15eaa-743a（422）/ 01a15eab-ff41 / 01a15eab-ff48 | OPENCODE free 三款 | 结论：不可用，已回退 |

## R1 —— 结构 / 链接 / 路由（3 并行）

> 三个全新上下文子代理，只读 + 跑门禁。基线：`domain-gate --all` 77/77、`preflight --fast` 25/25。
> **结论：门禁全绿不等于达标** —— 三份报告共 3 个 P0、9 个 P1，全部落在"断言覆盖不足"上。

### R1-A 结构（P0=3，P1=9）

| # | 发现 | 证据 | 处置 |
| :-- | :-- | :-- | :-- |
| P0-1 | `docs/AUDIT.md` 四轮全是"待填"，门禁只做 `"R1" in text` 子串判断 → 空台账假绿 | `grep -n 待填 docs/AUDIT.md` | 已填本轮真实结论；门禁改为「每轮至少 1 条 `证据/判定/动作` 行」（见 `check_cleanup`） |
| P0-2 | 案例模板 `refs` 指向已删除文件（`forensics.md` / `ios-macos-and-game.md` / `SKILL.md`），`outcome: pending` 非法值 | `grep refs Tool/cases/_templates/*.json` | 十份模板全部按 `CASE_FIELDS` 重建，refs 指向现存 `01-criteria.md` / `02-failure-criteria.md`，`outcome=partial` |
| P0-3 | 16 个 `real` 案例的 `lessons[0]` 没有命令/rc，门禁只判 `lessons` 非空 | 自写扫描 36 real / 16 无命令 | 新增 `repro.status`（`recorded`/`not-recorded`+`reason`）；15 个历史归档显式标 `not-recorded` 并写原因；门禁断言「real 必须有命令/rc 或显式 not-recorded」 |
| P1-1 | 4 个 `x-*.md` 与编号篇被指同主题重复 | `ls kb/pwn-crypto/techniques kb/firmware-iot/techniques` | 复核为**不同主题速查**，改名为 `07-*`/`08-*` 进编号序列，README 同步；不删内容 |
| P1-2 | `01-pe-unpack-dump.md` 有 117 行逐字复制自 TLS callback 篇（占 31%） | `difflib` 7 段 verbatim | 改为 8 行指针 + 一条脱壳判据，文件 381→254 行 |
| P1-3 | ad-cloud 矩阵 20 行全缺 `commands` 字段 | `any('commands' in r ...)` → False | 十份矩阵统一补 `commands`（ad-cloud 20 行、instrument 6 行） |
| P1-4 | `gen-case-index` schema 无 `evidence_kind`，58 条索引丢失 real/fixture 标记 | 索引里统计为 0 | `CASE_FIELDS` 增补 `evidence_kind`/`repro` 并重建索引 |
| P1-5 | `案例-6.9换肤壳` 标 `real` 但 `artifacts: []` | `ls` 该目录 | 补 4 个真实文档的 sha256 |
| P1-6 | 24 个历史案例目录不带 `input/`+`artifacts/` | 目录扫描 | **改判 P2**：历史案例证据在 `docs/`/`v2/` 子树，强行造空目录只会造假；模板已强制新案例带两目录，契约写明"历史案例按实际布局" |
| P1-7 | 根目录 `carved-00.gz` 未跟踪残留 | `git status` | 移入 `work/trash/` |
| P1-8 | 模板缺 5 个域且字段与契约不同源 | `ls _templates` | 重建为十份 + `README.md` |
| P1-9 | web-pentest 两个 `04-` 走查编号冲突 | `ls references \| grep ^04` | 旧篇改 `05-walkthrough-local-httpd.md`，SKILL/案例 refs 同步 |

### R1-B 链接 / 索引（判定 FAIL → 已修）

| # | 发现 | 证据 | 处置 |
| :-- | :-- | :-- | :-- |
| P1-1 | 旧链接图用 basename 子串匹配：当时候选 510 个里只有 124 个有路径级入链（76% 靠同名顶替），11 个同名覆盖 80 个文件 | 自写路径级/ basename 分离统计 | `check_links` 改为「完整路径 或 相对 Markdown 链接解析 或 同域 basename（README.md 不给 basename 学分）」，派生缓存不计票；**当前 521 个文件全部有真实入链** |
| P1-1b | 真孤儿：`ctf-website/techniques/00-workflow/24h-loop-orchestration.md` 只被生成物索引 | `grep -rl` | 在 `ctf-website/README.md` 建索引；同类 4 个孤儿一并补齐（ai-findings、apk/general 的 attack-network、web-payload-seeds） |
| P1-2 | 144 条 Markdown 相对链接 404（`field_journal__index` 30 条、`re_pattern_*` 108 条） | 全仓相对链接扫描 | 一次性修复：能同 basename 回填的改写，不能的去链接保文本（201 处）；`field_journal__index.md` 用磁盘重建（41 条全通）；新增门禁 `Markdown 相对链接可解析`（当时 699 条全通；当前 757 条全通） |
| P1-3 | 240 张任务卡的 `reference` 全部存在，但 88 张主题对不上（如 Modbus 卡指向 `emulation-and-fuzz.md`） | 标题 ASCII 词在目标正文 0 命中 | 36 张按关键词重映射；另给十域 `01-criteria.md` 追加「上游技能卡索引」（216+24 行：上游技能 → 卡 → reference → 一句话判据），现在十域对题缺口 171→**0**；门禁新增「标题技术词在 references 查无即 FAIL」 |
| P2 | softseep 6 篇收敛后 4 处细节丢失（6 字节等长公式、`mov al,1`、`chcp 65001`、字节级验证片段） | 逐行覆盖率 42%–89% | 已回填到 `09-patch-engineering.md` / `07-disassembly-deep-read.md`；`Tool/docs/PROVENANCE.md` 目录树同步 |

### R1-C 路由（P0=2，P1=5 → 已全部修复并加回归）

| # | 发现 | 证据（`master-route.ps1` 实跑） | 处置 |
| :-- | :-- | :-- | :-- |
| P0-1 | 只有 `mustAll` 没有 `must` 的规则**永远不命中**（R23/R25/R28 共 9 条死规则） | `分析这个 Chrome 扩展的 manifest 权限` → softseep | 执行器改为「有 must 以 must 起判，无 must 从真起判」；门禁 `_match_route` 同步同一语义 |
| P0-2 | 计分=命中规则条数，priority 仅同分裁决 → 多规则域系统性吞并单规则域（R29 压 R1/R8/R9） | `Frida 在 android 上 hook` → softseep；`UPX 脱壳 dump OEP` → softseep | 改为 **priority 顺序取第一个命中**（分数只展示）；priority 重排为 平台/工具专用 → 域 → 阶段 → 泛化 → R0 |
| P0-2b | 门禁与执行器两套语义 → 门禁绿、运行时红 | 25 句交叉跑出 5 句结论相反 | 新增 `work/tmp/route_parity.py`，26 句 gate↔PS **0 不一致** |
| P1-1 | `R2` 泛「授权」压住 R29/R11；`破解` 压 `RSA` | `把授权校验 patch 掉`→gate-bypass（可接受）；`破解 RSA 挑战题`→gate-bypass（错） | 从 R29 移除「授权校验」；priority 把 R21 放在 R11 之前 |
| P1-4 | 无边界高频词：`trial`→indus**trial**、`iat`→in**iat**ive、`dump` 裸词、`harmony`→HarmonyOS、`hook` 抢 JS 逆向 | 逐条探针 | 全部加 ``/语境限定；R8 的裸「解包」改 apk 语境 |
| P1-4b | **CJK 与 `` 冲突**：`(firmware\|固件)` 在「固件分析」上永不命中 | `固件分析` → softseep | 写 `work/tmp/fix_cjk_boundary.py` 做括号配平下沉：ASCII 分支保留边界、CJK 分支去掉边界；R22/R28 等 3 处修复 |
| P1-5 | `R0` 的 `.*` 参与竞争 → 无域可归也判 `high`，真实路由永远 `medium` | 102 句语料 13 句假 high | 执行器改为 fallback 不参与竞争，`high` 只在唯一候选时给 |

**R1 后回归（当轮基线）**：路由串味测试集 6 → **24 条**（含上述全部反例）；`gate↔master-route` 26 句 0 不一致；当轮 `domain-gate --all` 79/79（后续加断言后为 80/80）。

### R1 遗留（写入 ROADMAP，不进本轮阻断）

1. `protocol-plugin` / `malware-analysis` 片段里的 `boundary_policy` / `notes` 是"写了没生效"的建议字段 —— 已并入 SSOT 关键词，字段保留作设计说明。
2. `R0` 兜底仍会把无域句子交给 softseep 判型（这是产品行为，不是路由缺陷），但 confidence 已不再虚高。


## R2 —— 深度（3 并行）

> 三个全新上下文子代理，按域分组全读 SKILL/references/KB/任务卡/矩阵，并按 `lessons` 真跑 real 案例。
> **结论：形态合格（当轮 79/79），深度有 P0 9 个、P1 12 个** —— 集中在「判据与脚本不一致」「案例结论夸大」「索引声明了不存在的落点」三类。

### R2-A（web / pwn / supply）

| # | 发现（证据） | 处置 |
| :-- | :-- | :-- |
| P0-1 | 任务卡 07/08/14/20 与 `01-criteria.md` 索引把 XXE / XML / 请求走私 / GraphQL 的落点写成 `05-injection-and-ssrf.md`、`06-auth-and-api.md`，两文件 `grep -in "xxe\|graphql\|smuggling"` = 0 → **幻影引用** | 补 05 的 XXE / 请求走私 / 文件上传三节、06 的 CORS / 缓存投毒两节 + GraphQL 一节；判据表补 6 行，判据落字段（`oob_hits>=2`、`desync_pairs>=1`、`upload_executed=true`） |
| P0-2 | `01-criteria.md` 目录列表判据依赖 `distinct_from_baseline`，`web-check.py` 不产出该字段 → `web-pentest04` 的 confirmed 无法复算 | `web-check.py` 增加 `item_links` / `distinct_from_baseline`，并把判据改成「markers 命中 + ≥1 子项链接」 |
| P1-3 | `supply-chain01` lessons 声称含 dependency-confusion/version-range，实跑只有 7 条 ci-*；`inventory.locks` 从 `[]` 漂移为 1 条 | 用当前树重跑 `sc-check.py`，重写 lessons[0]（files_scanned/truncated/risks）、重算 artifact 哈希，并插一条「更正（R2 审计）」说明漂移 |
| P1-4 | `supply-chain03` 记 `confirmed`，与 `01-criteria §4.4「action 未 pin → 疑似」` 冲突 | 降为 `partial` + 写明升级条件（可被投毒的具体触发路径 + 攻击者可控输入） |
| P1-5 | JWT 三张卡落点为空，且与 `SKILL.md`「JWT 交 web-pentest」矛盾；EVM 两卡无内容 | `crypto-attacks.md` 补 JWT 攻击面（alg:none / 算法混淆 / 弱密钥 / kid / jku）；EVM 改为显式边界声明 + 失败判据一行 |
| P1-6 | CORS / 缓存投毒 / 文件上传只有一行判据 | 见 P0-1 的补充节 |
| P1-7 | K8s / Terraform / 供应商三卡只有索引行；secrets「有判据无方法」 | `cicd-and-artifacts.md` 补 K8s/IaC 扫描、secrets 扫描与真伪验证；`image-and-provenance.md` 补供应商台账字段 |
| P2 | 判据行与脚本字段存在 8/16（web）、3/16（pwn）、3/18（sc）无落点；`pwn-crypto05.payload_len=25` 实测 24；`pwn-crypto01/02` refs 挂了未使用的堆/ROP 篇 | 机检落点差距写入 ROADMAP 下一步；payload_len 与 refs 已修正 |

### R2-B（firmware / ad-cloud / protocol）

| # | 发现（证据） | 处置 |
| :-- | :-- | :-- |
| P0-1 | `ad-repro.py` 的 `confirmed = auth_ok or pfx`：只拿 pfx（未 PKINIT）也判 confirmed，与 `01-criteria` 冲突（审计用 `work/audit-r2/adcs-pfx-only.json` 复现） | 改为 `confirmed = bool(auth_ok)`；新增 `pfx-present` 只作前置检查 |
| P0-2 | `ad-repro.py` 的 k8s 分支：仅 `impersonate` 权限即 confirmed，而所有 proof 检查为 false | 改为 `confirmed = host_escape or secret_usable`；impersonate 最高 candidate |
| P0-3 | `protocol04/input/capture_live.sh` 直接 `rm -f artifacts/live.pcapng` 就地重写 → 案例 sha 必然漂移、门禁必 FAIL（审计实测 7/8） | 脚本改为默认拒绝覆盖，重录需 `CAPTURE_FORCE=1`；已重录一次并重建全部派生 artifacts + case.json（outcome 降 partial，标注「录制件」） |
| P1-4 | ad-cloud 只有 1 个 real（本机非域成员，事件日志全 4624 type5/4672），AD/ADCS/委派/云 IAM 无真实数据检验；且无 accept 脚本 | 保留负结果案例并写明「不可外推」；accept 由 `ad-repro --self-test` + 案例哈希门禁兜底（ROADMAP：AD 真实验证需授权域环境） |
| P1-5 | `firmware-iot05` 标 `J2 + confirmed` 但 `emulation.mode=none`、`service_ok=false` | 降 `partial` + 写明升 J2 的三件证据 |
| P1-6 | Windows 遥测判据「EventRecordID 连续」未实现（`ad-repro.py` 抽了 record_id 但没用） | 记入 ROADMAP；案例 `ad-cloud03` 的结论不依赖该判据（verdict=blocked） |
| P1-7 | `protocol03/04` 记 `success`，但判据要求「服务端接受新帧 + 重复 3 次」 | 两案降 `partial`；protocol03 的 target_type 由「Wireshark 官方」改为实际抓包来源 |
| P2 | firmware03 lessons 的 JFFS2 实为 medium 且漏报第二条；protocol03「payload 完全相等」应为「data 字段相等」；三域各有 2 条失败判据「代价」偏虚 | 失败判据代价口径写进 ROADMAP；表述类修正随本批完成 |

### R2-C（plugin / forensics / malware / reverse）

| # | 发现（证据） | 处置 |
| :-- | :-- | :-- |
| P0-1 | 当轮基线并非 79/79（protocol04 哈希漂移 + AUDIT 待填 + 部署哈希），不能拿绿灯当结论 | 已按本文件记录真实状态，修复后重新跑到全绿（见 R3 前基线） |
| P0-2 | reverse 16 个 real 里 15 个 `repro.status=not-recorded`，门禁允许 → 「真跑」不可复跑 | 门禁新增「每域至少 1 个有命令+rc 的 real」；历史归档保留 `not-recorded` + reason（案例-真实补丁a 为 recorded） |
| P0-3 | plugin 权限证据假精确：`_permissions()` 把 `manifest.json` 当代码扫描 → 权限声明即 `observed`；片段只截行首 220 字节，`debugger` 命中处不在片段里 | 只扫代码文件（排除 manifest/.md/.txt）；片段改为以命中点为中心截取 |
| P0-4 | forensics 四要素未落地：`fs-timeline.py` 的 `event()` 没有 `action`，1040/1040 为空；`evidence-accept` 只查非空；案例 actor 是 Provider/路径而非主体 | `event()` 增加 `action`（按 kind 派生并可覆盖）；`actor` 语义写进 criteria；accept 增四要素校验 |
| P1-5 | plugin 五类（userscript/Office/Lua/IaC/Jupyter）只有矩阵 | 记入 ROADMAP（矩阵可执行、reference 待补） |
| P1-6 | forensics 缺口：Linux auditd/容器/云/PST/USB 只有矩阵或卡；只有 1 个 real | 记入 ROADMAP；现有 real（EVTX+HKCU hive+Edge History）保留并写边界 |
| P1-7 | malware：PDF / bootkit / Linux ELF 只有卡；`ioc-extract.py` 把 `5.1.0.0` 当公网 IP | 补版本串过滤（末两段为 0 或全段 <100 且含 0 → `version-string`，不进 ips）；覆盖缺口进 ROADMAP |
| P1-8 | reverse 深水区薄：驱动/内核 1 行、macOS/ELF 1 行、Java 只有案例 | 记入 ROADMAP；`07/08/09/10` 四篇按专项检验修正（见下） |
| P1-9 | 回滚语义缺口：manifest 无 `rollback.backup` 时 `patch-verify` 拿当前文件冒充备份；`项目I` 的 `Revert()` 不读 backup | `patch-verify` 打补丁前强制落独立 backup 并写 `backup_sha256`，回滚只从 backup 恢复（无 backup 直接 rc=2）；演练案例已实测 `--rollback` 回滚到原哈希 |
| P2 | 失败判据代价偏虚（plugin :20/:22、forensics :20/:22、malware :13/:26、reverse :16/:29）；`fs-timeline` 写 `generated_at` 导致复跑 sha 不同；`softseep/SKILL` 索引行数过期（74/319 → 105/381） | 索引行数按 `wc -l` 重算；`generated_at` 与 CRLF 问题进 ROADMAP；代价口径统一进 ROADMAP |

### R2 专项检验（reverse 四篇）

| 篇 | 检验点 | 结论 / 处置 |
| :-- | :-- | :-- |
| `07-disassembly-deep-read.md` | ARM64 `STP` 后第 9 个参数位置 | 原文写 `[sp]` 会读错一槽 → 改为按 `N` 与已压栈寄存器数计算（带算例） |
| 同上 | x64 home space 位置 | 原文把 `[rsp+0x20]` 当 home space → 改为「调用者预留、`sub rsp,0x28` 后在 `[rsp+0x28..0x47]`」 |
| `08-symbol-recovery.md` | PDB RSDS 能否照做 | 原文只有伪代码 → 补 Debug Directory 遍历、GUID 大小端、symbol-server key、curl 模板、GUID/Age 不匹配判据 |
| `09-patch-engineering.md` | 等长替换与 +1 推导 | 正确（本轮最可照做的一篇）；回填了 6 字节升级公式与字节级验证片段 |
| `10-anti-debug.md` | 用户态 `mov rax, dr0` | 特权指令会 #GP → 改为「用户态只用 GetThreadContext/NtGetContextThread，`mov dr` 仅内核态」 |

### R2 后基线

`python Tool/scripts/domain-gate.py --all` → **80/80**（含全仓 reference 篇幅断言；案例索引、AUDIT、部署三项已在 R3/R4 收口）。


## R3 —— 可跑性（1 个）

> 一个全新上下文子代理，只读仓库、产物写 `work/audit-r3/`，逐脚本跑 `--help`/`--self-test`、构造失败输入、按 `lessons` 复跑每域一个 real 案例。
> **结论：37 个脚本 `--help` 37/37、`--self-test` 37/37 全绿；案例结论全部被证据支撑；但有 P0=2、P1=7** —— 都是「旧代码产物没重算」「失败 JSON 形状不统一」「输出带时间戳导致字节级不可复现」。

| # | 发现（文件:行 + 复现） | 判定 | 处置 |
| :-- | :-- | :-- | :-- |
| P0-1 | `Tool/cases/malware-analysis01/artifacts/iocs.json` 仍是旧代码产物：`ips: 2` 里含 `5.1.0.0`/`6.0.0.0`（版本串），而过滤器已在 `ioc-extract.py:273` | 案例与工具不一致；哈希门禁因「自洽」仍绿 | 用当前工具重跑 triage/ioc/unpack 三件产物（ioc 现为 `ips=0, filtered=8`），重算哈希并写更正 |
| P0-2 | `forensics04/05` 的 timeline 事件 `action` 全空，`evidence-accept` rc=2，但 `domain-gate` 仍 8/8（门禁没接 accept） | 验收脚本形同虚设 | ① 事件补 `action`（用工具自带 `derive_action`，与输出同源）并重算哈希；② **门禁接入 accept**：域内有 `*accept*.py` 就跑，支持「域级一次跑」与「--case 必填则逐案例」两种接口 |
| P1-1 | `web-check.py:603` 失败 JSON 只有 `error`，没有 `blocked_at`/`reason` | 违反 AGENT-BRIEF §2 | 两处失败分支改为 `{ok:false, blocked_at, reason, error}` |
| P1-2 | `pcap-summary.py:581` 同上 | 同上 | 补 `blocked_at/reason` |
| P1-3 | `fw-triage.py:336` 失败 JSON 用嵌套 `error`，无字符串 `reason` | 自动化难判 | 保留 `error` 详情，另加 `reason` 字符串 |
| P1-4 | `fw-repro.py:542` 输出目录不可创建 → 裸 Traceback rc=1 | 不可判定卡点 | 引入 `Blocked(stage, reason)`，`main` 捕获输出结构化 JSON + rc=2（实测 rc=2） |
| P1-5 | `fs-timeline.py:466` 同上 | 同上 | `write_json` 外层 try/except → `{ok:false, blocked_at:"out", reason}` + rc=2（实测 rc=2） |
| P1-6 | `generated_at`/当日日期/CRLF 导致 7/10 域复跑哈希与 case.json 不同 | 「可复跑」被高估 | ① 六个脚本的 `generated_at` 改为「仅当 `SEEP_TIMESTAMP` 环境变量存在才写」；② 文件写出统一 `newline="
"`；③ 审计口径改为「语义一致（归一化 JSON 相等）」，字节级差异原因写进案例 lessons |
| P1-7 | `plugin03` 的 repro 产物仍含 `manifest.json` 权限自证（R2 修复后未重算） | 产物与工具不一致 | 用当前 `plugin-repro.py` 重生成（权限证据不再来自 manifest），重算哈希 |
| P2 | `domain_spec.py` 把 `web-check.py` 指到不存在的 `Tool/scripts/`；`--domain softseep` 静默只跑契约；`mcp-guard --check` 参数不存在；4 字节输入返回 `ok=true` 空结果 | 门禁/文档小瑕疵 | 修 spec 路径；`--domain` 未知域直接 rc=2 并列出可用域；P2 其余记入 ROADMAP |

**R3 后复跑矩阵（节选）**：pwn-crypto01（原路径）与 supply-chain01、`案例-真实补丁a` 可**字节级**复现（含 `--rollback` 回原哈希 `8308abb8…`）；web05/pw03/fw03/ad03/proto03/forensics03 归一化后与记录一致；`protocol04` 重录脚本已能**拒绝覆盖**（rc=2，sentinel 哈希不变）。


## R4 —— 终审（1 个）

> 一个全新上下文子代理，独立复跑全部门禁与契约抽查，并在 `work/audit-r4/full-copy/` 的仓库副本上做了 3 个反例测试。

### 硬指标复核

| # | 项 | 结果 |
| :-- | :-- | :-- |
| 1 | `preflight.py` 全量（含 verify.ps1 + smoke-e2e） | 26/27（唯一 FAIL = AUDIT R4 待填）；内嵌 `verify.ps1 PASS=65 FAIL=0`、`smoke-e2e rc=0` |
| 2 | `domain-gate.py --all` | 78/79（同上）；`fails=1, empty-detail=0` |
| 3 | 路由自洽 / mcp-guard | 均 rc=0；工具 40（基线 40），基线文件是已提交版本，非本轮自生成 |
| 4 | 案例索引 | rc=0，58 案例，`source_hash=c0e6c502…` |
| 5 | 部署哈希 | 1/1；审计员亲算 5 个文件仓库↔`~/.pi/agent/skills` 全部一致 |
| 6 | 契约抽查 | 9 域 SKILL 198–518 行；refs 8–10 篇、61–337 行；25 个脚本 `--self-test` 25/25 rc=0；案例 4–5（reverse 16）+ 每域 ≥1 real/recorded，亲算 3 份 sha256 一致；KB 6–8 篇含 failure-criteria；任务卡 24 张、六段齐、reference 对题 |
| 7 | 清理 | 根目录无过程文档；ROADMAP 61 行；`work/` 已忽略；无 `.orig/.bak/.tmp` |
| 8 | 真实演练复核 | 独立重跑 `patch-verify` → `bdcb074e…`；`--rollback` → `8308abb8…`（= 原文件），与案例记录一致 |

### 反例测试（证明门禁有效）

| 造错 | 门禁反应 |
| :-- | :-- |
| ① case.json 的 artifact sha256 改一位 | `[FAIL] web-pentest04(artifacts/run.json sha256 不符，重算=e5d24c3b61ff)` + `web-accept rc=2` 二次拦截 |
| ② reference 改到 402 行 | `[FAIL] 07-waf-and-bypass.md 402 行（要求 60–400）` |
| ③ real 案例删命令、改 lessons、去 repro | `[FAIL] 没有『有命令+rc』的 real 案例` + `[FAIL] 真实案例证据链…(real 但无命令/rc 且未标 not-recorded)` |

### R4 发现的 P0/P1 与处置

| # | 发现 | 处置 |
| :-- | :-- | :-- |
| P0-1 | `docs/AUDIT.md` 的 R4 与「遗留与下一步」仍是「待填」，导致 preflight 26/27、gate 78/79 | 本节 + 下节已写入；门禁断言改为「无『待填』且每轮有证据/判定/处置」 |
| P1-1 | 多处写「记入 ROADMAP」但 ROADMAP 无对应条目（遥测/驱动/auditd/PST/PDF 等） | ROADMAP 新增「已知延迟项 D1–D9」表，逐条写现状与触发条件 |
| P1-2 | `supply-chain01` 的 lessons[0] 写 `files_scanned=None/truncated=None`，与产物 `target.files_scanned=1000, truncated=true` 矛盾 | 按 `target.*` 重写 lessons[0]，并补「扫描被截断→结论不可外推」的覆盖边界行 |
| P2-1 | `--domain` 单域模式漏抓单案例伪 real | `check_cases` 增加逐案例断言：real 必须有命令/rc 或显式 `not-recorded` |
| P2-2 | ROADMAP 写 apkseep「45 篇参考」实际 43 | 已改为 43 |
| P2-3 | pwn-crypto03/04/05 是现场自建产物却写得像第三方目标 | `target_type` 明确标注「自建靶（真实产物，非手写数据）」 |


### P1 清账表（复审后版本：能修的全部已修，只留 2 项有证据的限制项）

| 来源 | 原 P1 | 状态 | 证据 / 理由 |
| :-- | :-- | :-- | :-- |
| R2-A | supply-chain01 证据漂移 | **已修** | 重跑并重写 lessons（`target.files_scanned=1000/truncated=true`），补「截断→不可外推」边界，哈希重算 |
| R2-A | supply-chain03 结论与判据冲突 | **已修** | `confirmed → partial` + 升级条件 |
| R2-A | JWT / EVM 卡无落点 | **已修** | `crypto-attacks.md` 增 JWT 攻击面；EVM 边界声明 + 失败判据行 |
| R2-A | CORS / 缓存投毒 / 上传只有一行 | **已修** | 05/06/07 增 6 节 + 判据字段 |
| R2-A | K8s/IaC/供应商/secrets 只有索引 | **已修** | `cicd-and-artifacts.md` / `image-and-provenance.md` 增 4 节 |
| R2-B | protocol03/04 结论夸大 | **已修** | 两案降 `partial`；protocol03 来源声明改为实际抓包 |
| R2-B | Windows 遥测 `EventRecordID` 未实现 | **已修** | `ad-repro.py` 新增 `record_id_gaps`/`telemetry_untrusted` + `record-id-continuity` check；`ad-cloud03` 重跑（gaps=0） |
| R2-C | plugin 五类只有矩阵 | **已修** | userscript / Office Add-in / Lua Mod / IaC·CLI·Jupyter 四节写进 references（含字段名） |
| R2-C | forensics auditd/容器/云/PST/USB | **已修** | Linux auditd/journald、PST/USB、CloudTrail/Flow/K8s 三节写进 references |
| R2-C | malware PDF/bootkit/Linux ELF | **已修** | PDF/文档类、ELF/bootkit·rootkit 两节 + `elf_anomaly` 等字段 |
| R2-C | IOC 版本串误报 | **已修** | `ioc-extract.py` 版本串过滤；`malware-analysis01` 重跑（ips=0 / filtered=8） |
| R2-C | reverse 驱动/内核/macOS/ELF 薄 | **已修** | 08 增 ELF/Mach-O/JAR 符号与结构；10 增驱动/内核观测面；09 增内核补丁约束 |
| R2-C | 回滚语义缺口 | **已修** | `patch-verify` 强制 `*.rollback.backup` + `backup_sha256`；演练实测回原哈希 |
| R3 | 失败 JSON / 裸栈（5 处） | **已修** | web-check、pcap-summary、fw-triage、fw-repro、fs-timeline、mal-triage 全部 `{ok,blocked_at,reason}` + rc=2（默认无 `--json` 也成立） |
| R3 | plugin03 陈旧 repro | **已修** | 当前工具重生成（manifest 不再自证权限），哈希重算 |
| R2-B | ad-cloud 只有 1 个 real / 无 accept | **已修（accept）/ 限制（第 2 个 real）** | 新增 `ad-accept.py`（字段/哈希/real+recorded/凭据红线，自检 4 项）；第 2 个真实 AD 案例受环境限制，见下 |
| R3 | 字节级不可复跑 | **限制（技术不可行）** | 已去 `generated_at`、统一 LF；抓包/端口天然非确定 → 口径改为「归一化 JSON 相等」，逐案在 lessons 写明 |

**限制项（不是「改判逃避」，是附证据的不可执行项）**

1. **第 2 个真实 AD/ADCS/K8s 案例**：本机 `PartOfDomain=False`、`klist` 无票据、`RunAsPPL=0`；
   `ad-cloud03` 已用真实 Security 日志给出 `verdict=blocked` 的负结果与证据链。要造正例必须接入授权域环境。
2. **字节级复现**：网络抓包的包序/端口/IP ID 天然随机；`protocol04` 与 `web-pentest05` 已在 lessons
   标明「录制件，重跑哈希不同，语义一致」。这是口径问题，不是可修的 bug。

**结论：未闭环 P1 = 0**（其余 16 项全部实际回修，证据见上表与对应脚本/文档）。
### 终审结论

**可交付**（P0=0；P1 清账见上表：已修 10 项、改判 P2 并登记 D2–D7 共 6 项、未闭环 P1=0；R4 自身发现 P2 3 项已修）。

---

## 遗留与下一步

| 项 | 状态 | 依据 |
| :-- | :-- | :-- |
| 十域九件套 2.0 | 完成 | `domain-gate --all` 80/80（当前）；每域 4 条必备篇 + 8–10 篇 references + 3–4 脚本 + 4–5 案例 + 6–9 篇 KB + 24 张任务卡 |
| 逆向域补漏 | 完成 | 反汇编深读 / 符号恢复 / 补丁工程 / 反调试 四篇 + 九型范式库与 UI 验收迁入 KB |
| 链接与孤儿 | 完成 | 路径级/同域链接 + 相对链接解析（README.md 必须有路径级入链）；**521 文件全部有入链；757 条 Markdown 相对链接 0 死链** |
| 路由串味 | 完成 | 执行器与门禁同语义（priority-first、mustAll 生效、fallback 不竞争）；26 句 gate↔PS 0 不一致；24 条固定测试集全绿 |
| 仓库清理 | 完成 | `优化方案*.md` → `work/plans/`；根目录只留 README + ROADMAP（61 行） |
| 部署一致 | 完成 | 十域 SKILL/references/scripts 哈希一致 |
| 真实任务演练 | 完成 | `案例-真实补丁a`：真实第三方 crackme，2 处等长补丁 + 独立备份 + 回滚到原哈希 |
| 延迟项 D1–D9 | 记录 | 见 `ROADMAP.md`「已知延迟项」；每条都有现状与触发条件，不做空头承诺 |

---


## R4 复审回修（第二轮，针对终审驳回的 6 项）

| # | 驳回意见 | 处置 | 验证 |
| :-- | :-- | :-- | :-- |
| 1 | 根目录仍留 CHANGELOG/AGENTS/CLAUDE/DSH，且 allowlist 是执行器自放宽 | 全部移出根：提示词→`Tool/prompts/sources/`、agent 契约→`Tool/prompts/contracts/`、变更日志→`docs/CHANGELOG.md`；根只剩 `README*.md` + `ROADMAP.md`；SPEC §11 与 `check_cleanup` 改成同一 allowlist（其余即 FAIL）；`git add -A` 后 `git ls-files` 根目录 md = 4、`优化方案*` = 0 | `ls *.md`；`git ls-files "*.md" | grep -v /` |
| 2 | reverse 16 案例 / 46 KB 超出「每域 3–5 / 6–10」 | 域内收敛为 **5 案例 / 10 KB**；其余 **不删**，归档到 `Tool/cases/_archive/`（11 案例）与 `kb/_archive/pe-reverse/`（36 篇），归档有 README 索引、不计入域数量、仍受链接检查；`domain_spec` 删除 `cases_max=20/kb_max_count=60` 隐藏豁免 | `domain-gate --domain reverse` → 5 案例/10 篇；`find` 归档计数 |
| 3 | P1 靠「改判」而非回修 | 16 项 P1 实际回修 14 项（见清账表：plugin 五类、forensics 四类、malware 三类、reverse 四主题、AD EventRecordID、失败 JSON、回滚、plugin03 等）；仅剩 2 项**附证据的限制项**（第 2 个真实 AD 案例=本机非域成员；抓包字节级复现=网络不确定性），均写明不可执行原因 | 清账表 + 对应脚本/文档 diff |
| 4 | 「失败给结构化结论」不统一（mal-triage 默认只有 `[ERR]`） | `mal-triage`、`fw-triage`（4 处分支）改为**默认**输出 `{ok:false,blocked_at,reason}` JSON + rc=2；`pcap-summary` 的 `_fail` 补齐三件套 | 实跑 `--file /nonexistent.bin` 看 stdout |
| 5 | 全仓单篇 reference ≤400 未执行（apkseep 1289/593/564/502） | apkseep 4 篇无损拆成 15 篇（旧文件保留 ≤20 行目录页），索引/引用全部改指子篇；新增门禁断言「全仓 `Tool/skill/**/references/*.md` ≤400」 | `domain-gate --all` 80/80；`wc -l` 最大 400 |
| 6 | 过程约束（全新上下文子代理/Free 模型）不可核验 | 本文件新增「子代理与模型记录」表：逐轮 session id + Free 模型 422 失败的实测结论 + 回退依据 | 表内 ID 可在 `~/.pi/agent/sessions/` 检索 |
| 7 | （自查）真实注册表 hive 含本机个人路径（PII） | `forensics03` 移出 `Explorer.hiv`，改用「键名清单」（仅键路径、无值），timeline 由真实 EVTX/History/文件系统重建；artifacts 与 findings 引用全部重算 | `verify.ps1` 脱敏项 PASS；隐私扫描 1260 个 tracked 文件 hits=0 |


## R4 复审回修（第三轮，针对 second 驳回的 4 项）

| # | 驳回意见 | 处置 | 验证 |
| :-- | :-- | :-- | :-- |
| 1 | `forensics03` 自相矛盾（target_type 写 hive、lessons 命令引用 Explorer.hiv、run.json 1040 vs timeline 69） | 重建案例：target_type 改为「EVTX + History + 键名清单」；lessons[0] 命令改为实际三条输入；`run.json` 按当前输入重生成（timeline_summary=69）；findings 的 claim/command/evidence_refs 全部改指键名清单。**并把交叉校验写进门禁**：case.json 提到的 `input/*` 必须存在、target_type 声明的样本类型必须有对应扩展名、`run.json` 与 `timeline.json` 事件数必须相等；`evidence-accept` 同步这三条 | gate 80/80；`evidence-accept --case forensics03/04/05` 全 PASS |
| 2 | 必备 `04-walkthrough-*` 过期 | forensics 走查改写为：键名清单采集（无 hive，附 PII 说明与代价）、命令块去 hive、时间线摘要改 69 事件（59/7/3）、observed 与失败判据同步；protocol 走查把「Wireshark 官方 test/captures」更正为实际抓包元数据（dumpcap 4.1.0 / Linux 5.15 / Go-http-client），并指向 `input/README.md` | `grep Explorer.hiv/1040` 在案例与走查中为 0 |
| 3 | 清理后文档仍指向已搬走文件 | README / README.zh / README.en 的「优化总纲」改为 `ROADMAP.md`（并说明过程文档在 `work/plans/`）；`Tool/docs/ROADMAP-2.0.md` 的 `../../优化方案.md` 改为 `../../ROADMAP.md`；HANDOFF/FORK-DELTA/AUDIT-2026-10-21 同步；README.zh / MANUAL BASELINE-FREEZE / DEPLOYMENT-CHECKLIST 的「项目根 AGENTS.md」改为 `Tool/prompts/contracts/AGENTS.md`（源） | 全仓 `grep 优化方案` 只剩 AUDIT 台账与历史说明；无 `../../优化方案` |
| 4 | 失败默认不结构化（plugin-triage / plugin-repro / forensics-check 只打 `[FAIL]`） | 三脚本失败分支改为**默认** stdout 输出 `{ok:false,blocked_at,reason}` JSON，`[FAIL]` 降为 stderr 人读行；三个兼容入口 shim 用 `subprocess.call + sys.exit(rc)` 透传退出码 | 实测三条命令默认 rc=2 且 stdout 为 JSON |

### R4 三审补修（forensics03 自述-磁盘一致性 + 门禁加深）

| # | 驳回点 | 处置 |
| :-- | :-- | :-- |
| 1 | `acquisition.tool/volume/source/readonly` 仍称 reg save/hive | 改为「cp + PowerShell Get-ChildItem（键名清单）+ fs-timeline」；volume 明写「未导出原始 hive（PII）」；readonly 明写「Windows 上以 check-*.json 的 readonly 为准（本案例 key-names=false，原件未写）」 |
| 2 | `lessons[1]` 称「注册表 UserAssist 最后写入可排进时间线」 | 改为「键名清单 60 行，**没有**键写入时间与值——不再声称」 |
| 3 | `findings[1]` action=registry key last-write、time_utc=14:25:32.995012Z（不在时间线） | action 改「registry key inventory (structure only)」，time_utc 改 19:15:38.018519Z（时间线中真实存在的 key-names mtime），object 改 sha 0ef13b7d…（60 行键路径） |
| 4 | `findings[3]` 与走查 §6 的 mtime「14:25:32–33」 | 改为三段时间：EVTX 14:25:32.961Z / History 14:25:33.011Z / 键名清单 19:15:38.018Z（与 timeline 的 filesystem-mtime 事件一一对应） |
| 5 | `timeframe.end` = 14:25:33Z，时间线实际到 19:15:38Z | 改为 19:15:38Z |
| 6 | 门禁只查 input 存在/类型/事件数，抓不到这类矛盾 | `check_cases` 加深三条：①声称 `reg save`/`last-write` 却无 `.hiv` 输入 → FAIL；②`observed` 结论的 `time_utc` 必须出现在 `timeline.json` 事件里；③`timeframe.end` 必须等于时间线最后一个事件时间。`evidence-accept` 同步前两条 |
| 7 | forensics04/05 的静态分析结论用 2026-10-20T03:14:00Z 标 observed（不在各自时间线） | 改为 `inferred` 并在 action 注明「分析时刻，非事件时刻」——静态判定不是时间线事件 |


### R4 终审（修复后 · 全新上下文）

| 项 | 值 |
| :-- | :-- |
| 子代理会话 | `01a16022-10b9-7273-bc78-a99ab5ff158d`（首轮终审）→ 同会话复验（`work/audit-r4b2/`） |
| 首轮结论 | preflight 28/28、gate 80/80、双平台 65/0、3 个反例全红；**P0=0、P1=2**（forensics03 的 `UserAssist` 幻影：case.json finding 与 04 走查示例引用了键名清单里不存在的键） |
| 修复 | findings 的 claim/object/actor/command 改指真实键名（Accent / Advanced / AutoplayHandlers / ComDlg32）+ Get-ChildItem 命令；走查示例块改真实键路径、observed 改「60 行 A–C 前缀样本」、inferred 归因改 `ComDlg32\OpenSavePidlMRU`；只读/采集时间/SHA256SUMS 路径对齐；`evidence-accept` 增加三条硬断言（timeframe.end 对齐 / observed 的 time_utc 在时间线 / 只读声明与可写性一致），self-test 对齐；checks 96→114 |
| 复验结论 | 禁词 grep 0 命中；finding 的四个键名逐条在 60 行清单中命中；`evidence-accept --case forensics03` PASS / checks=114；gate 80/80；preflight 28/28；verify.sh 与 verify.ps1 均 65/0；accept self-test rc=0；两个新增断言在副本上实测会红；**P0=0，P1=0，可交付** |

## 交付基线（2026-10-21，v1.22.0）

| 项 | 命令 | 结果 |
| :-- | :-- | :-- |
| 唯一门禁 | `python Tool/scripts/preflight.py` | **28/28 通过**（含 verify.ps1 PASS=65 FAIL=0、verify.sh 实跑 65/0 rc=0、smoke-e2e rc=0） |
| 领域深度 | `python Tool/scripts/domain-gate.py --all` | **80/80 通过**（含新增「全仓单篇 reference ≤400 行」） |
| 路由自洽 | `python Tool/scripts/verify-routing-coherence.py` | rc=0，routes=priority=25，fallback=R0 |
| 工具不降 | `python Tool/scripts/mcp-guard.py` | rc=0，40 个工具（基线 40），SEEP-EXT 4/4 |
| 案例索引 | `python Tool/scripts/gen-case-index.py --check` | rc=0，**47** 个域内案例（另有 11 个历史案例在 `Tool/cases/_archive/`，不计入） |
| 终审 | 全新上下文子代理 `01a16022-…` + 同会话复验 | 首轮 P0=0/P1=2 → 修复后 P0=0/P1=0，结论「可交付」 |
| 根目录 | `ls *.md` / `git ls-files "*.md" \| grep -v /` | 仅 `README*.md` + `ROADMAP.md`（4 个）；`优化方案*` tracked=0 |
| 脱敏 | `setup/verify.ps1` 隐私项 | PASS（1260 个 tracked 文件 hits=0） |
| 全仓 refs | `domain-gate` 新断言 | **161 篇 references 全部 ≤400 行**（最大 399） |
| 部署一致 | `python Tool/scripts/domain-gate.py --deploy` | 1/1，十域 SKILL/references/scripts 哈希一致 |
| 双平台 | preflight [3 平台] | 项数一致（61）；且有 bash 时**真跑** `verify.sh` 要求 rc=0（本轮 65/0） |
| 真实演练 | `Tool/cases/案例-真实补丁a` | 真实第三方 crackme：2 处等长补丁 → `bdcb074e…`；`--rollback` → `8308abb8…`（= 原文件） |

**结论：可交付。** 交付后动作：完全重启 Agent 会话 → 发 `lab：`。
