# 优化清单 2.0（v1.25.0 之后）

> 输入：三个只读并行审计（原稿按目标第 5 条不入库，结论与证据已全部汇总到本文件）+ 主对话复核。
> 判定原则：**只修「会让人用错 / 给出错答案 / 关联对不上」的**；不加新域、不加新能力，除非某条配方真的缺原语。
> 每条都带验收方式；不带验收的不进清单。

---

## 0. 现状判断（一句话）

门禁层是真的（preflight 43/43、domain-gate 110/110、verify 65/0），但**「文档↔事实」「配方↔脚本」「证据链↔真实产物」三处仍在漂**；其中最危险的不是写错数字，是**脚本给出高置信度的错答案**（captcha-angle 在对称图上错 90° 仍报 0.974）。

---

## P0：真错（会让人用错 / 拿到假结论）——必须修

| # | 现象 | 证据 | 改法 | 验收 |
| :-- | :-- | :-- | :-- | :-- |
| P0-1 | `captcha-angle` 对 90° 对称图返回错角却高置信度 | 合成 25° 图 → `angle=245, angle_mod90=65, confidence=0.974` | 检出「等价类不可分」时返回 `ambiguous: true`、`confidence<=0.35`，并在 `limits` 写明；自测补一条「对称图必须 ambiguous」 | 新自测项全绿；25° 图输出 `ambiguous=true` |
| P0-2 | `temp_ocr.ps1` 不写 `ocr.json` 且失败仍 rc=0 | 配方第 2 步判据要求 `ocr.json`，实跑只打印 | 失败 → `{ok:false,blocked_at:"ocr-failed"}` rc=2；成功写 `ocr.json`（text/confidence） | 给一张空图 → rc=2；给正常图 → 文件存在 |
| P0-3 | `probe_api.py` 404 仍 rc=0，且只支持 GET | 配方第 6 步用它做重放验证 | 4xx/5xx → rc=3（`ok:true` 但 `http_status>=400`）；加 `--method/--data` | 404 → rc≠0；POST 可用 |
| P0-4 | `case_state` 把 URL target 存成本地路径 | `--target https://example.com` → state 里 `D:\...\https:\example.com` | target 以 `http(s)://` 开头时原样保存 | `show` 后 target 与输入一致 |
| P0-5 | `seep-start` 对真实 target 打印的是内置样例命令（零证据） | `--target https://example.com` 后 3 条命令都是 self-test / 内置案例 | 打印前加一行「以下为该域**样例路径**，把 `<case>`/证据换成你的；对真实目标先跑 web-check 取基线」；`--target` 为 URL 时第 1 条改为 `web-check --url <target>` | 输出含该提示；URL 目标首条命令带 `--url` |
| P0-6 | `capability-gate`「被引用」按脚本文名子串判定 → 假绿 | 47 能力里真正按 id 被配方引用的只有 8 个，gate 报 27 | 改为按 capability id 在配方 `用到的能力` 行精确匹配；`repo:<脚本名>` 命中需在报告中单列 | gate 报「精确引用 8 / 脚本别名 19 / reserved 20」三类分开 |
| P0-7 | MCP 工具数写成旧值，实际 40（11 个文件不一致） | `grep -c '^@server.tool()'`=40；`MCP-SETUP.md:27/36/314/318` 等写 38 | 全部改 40；README 工具矩阵补 `seep_case_search`/`seep_case_read` 两行 | 旧值在全部第一方 md 中 grep = 0（历史 CHANGELOG 除外） |
| P0-8 | KB 篇数写成旧值，实际 409 | `DEPLOYMENT-CHECKLIST:182`、`DEPLOYMENT:468` 写 292 | 统一 409（以磁盘为准） | 旧值在全部第一方 md 中 grep = 0（历史 CHANGELOG 除外） |
| P0-9 | 内置工具版本号错 | 文档 radare2 `v6.2.2`，`rabin2 -v`=5.9.8；apktool `v3.0.3`，jar=2.11.0 | 改为实测版本，并加一句「版本以 `--version` 为准，升级后同改此处」 | 文档版本 == 脚本实测 |
| P0-10 | 能力数 44/45/47 三套 | CHANGELOG=45、AUDIT=44、磁盘=47 | 统一 47（并注明 44 基线 + 3 新增） | `grep -c '"id"' Tool/capabilities/*.json` = 47 且文档一致 |
| P0-11 | `Tool/cases/README.md` 教不存在的域 | 示例 `"domain": "windows-license"` | 改为现行 11 域之一 | 示例 domain ∈ DOMAINS |
| P0-12 | QUICKSTART 的 `preflight-classify.py` 路径错 | 实跑 No such file | 改为 `Tool/skill/softseep/scripts/preflight-classify.py` | 命令 rc=0 |

---

## P1：关联没跟上 / 用起来不顺——本轮修

| # | 现象 | 改法 | 验收 |
| :-- | :-- | :-- | :-- |
| P1-1 | ROADMAP「十一域」表 9 行、softseep 域表 9 行（缺 site-clone/reverse） | 补齐 11 行 | 表行数=11 且域名与 DOMAINS 一致 |
| P1-2 | DEPLOYMENT-CHECKLIST 写「17 大组件」表只有 11 行 | 统一为实际数量 | 标题数字 == 表行数 |
| P1-3 | apkseep 计数三套（43/55、45/…、113） | 按磁盘实测重写 | 文档数 == `ls` 实测 |
| P1-4 | softseep references 写 8 篇，实测 10 | 改 10 | 一致 |
| P1-5 | ad-cloud SKILL 脚本表漏 `ad-accept.py` | 补一行 | 表覆盖目录内全部脚本 |
| P1-6 | AGENT-BRIEF/QUICKSTART/pwn-crypto SKILL 写错的本域断言条数，实测 10 | 改 10（或写「全绿」不写数字） | 一致 |
| P1-7 | README 目录树自指错位（`README.zh.md ← 本文件` 出现在 README.md） | 修正指代 | 三份各自指向自己 |
| P1-8 | AUDIT 标题 R1–R10，正文只有 R1–R4 | 标题改 R1–R8 | 标题与正文一致 |
| P1-9 | DEFERRALS D6 写 60 条剧本卡，实测 61 | 改 61 并写清分布 | 一致 |
| P1-10 | 配方步骤语义不匹配：`web-check` 无「脚本 URL/cookie/initiator」，`web-repro` 无 sign 组；web-api 第 4 步只给工具名 | 重写 web-api 第 2/4/5 步：用 `mcp__js_reverse__*` 具体工具（`new_page`→`list_scripts`→`break_on_xhr`→`get_request_initiator`），并说明产物落在 `work/<case>/artifacts/` | 每步命令可复制；工具名存在于 MCP |
| P1-11 | qinglong 第 5 步「env-ledger check → rc=0」，实测 rc=1 | 改为「rc=0 通过；rc=1 表示有未还原项，先修再走」 | 配方写清两种 rc 含义 |
| P1-12 | captcha-handling 第 5 步 `gaps → prove` 报「没有 claim C1」 | 补 `claim --id C1 --status hypothesis` 步骤 | 照配方走通 prove |
| P1-13 | 6/14 重依赖脚本缺结构化 `blocked_at` | 抽 6 个补齐（cv2/playwright/frida/ida 缺失时 `blocked_at:"tool-missing"` rc=2） | 断依赖实跑 → JSON 带 blocked_at |

---

## P2：整洁度（有时间再做，不阻塞）

- ~~3 个真死文件~~：实测 `Tool/scripts` 仅 `start_mcp.py` 一个未被引用，已改为延迟导入并接进 PROVENANCE（不再是死文件）。
- ~~KB 冻结~~：已在 `DEPLOYMENT-CHECKLIST` K1 写明「冻结基线：新增知识走案例与配方」。
- ~~Git Bash 路径改写~~：`QUICKSTART` 已加 `MSYS_NO_PATHCONV=1` 提示与示例。
- 审计稿曾推高 first-party 计数：`check-budget` 已排除 `/audit` 与 `/work`，并在 v1.26.1 把口径改为 `git ls-files`（只数已跟踪文件，消除 820↔834 漂移）；当前 first-party = 819；该口径在 `Tool/scripts/check-budget.py` 内注释说明。

---

## 明确「不做」

1. 不加新域（11 域够）。
2. 不加新 capability；只有配方真缺原语时才加（本轮只加了 captcha-gap/angle，已接线）。
3. 不追 264 张卡的剧本化：把卡分「可执行 / 提纲」两级标注，不假装全可跑。
4. 不做 11 份 accept 的全量重构（4015 行重复）：先抽**公共壳试点 2 份**（web-pentest + forensics-mobile），验证可行再推广。

---

## 执行批次（并行，按文件域分工避免冲突）

| 批次 | 范围 | 文件所有权 |
| :-- | :-- | :-- |
| F1 真错修复 | P0-1…P0-6 | `Tool/scripts/{captcha-angle,case_state,seep-start,capability-gate,probe_api}.py`、`Tool/scripts/temp_ocr.ps1` |
| F2 一致性 | P0-7…P0-12 + P1-1…P1-9 | `README*.md`、`MANUAL/*`、`docs/*`、`Tool/docs/*`、`Tool/cases/README.md`、`ROADMAP.md` |
| F3 配方可用性 | P1-10…P1-13 | `Tool/playbooks/*`、`Tool/skill/web-pentest/scripts/web-check.py`、6 个重依赖脚本 |

合并后统一跑：`preflight`（全量）、`domain-gate --all`、`bash setup/verify.sh`、`powershell setup/verify.ps1`、`playbook-check`、`capability-gate`，再 commit。

---

## 验收总门（合并后必须全绿）

```
python Tool/scripts/preflight.py                 # 43/43
python Tool/scripts/domain-gate.py --all         # 110/110
python Tool/scripts/playbook-check.py            # 坏命令 0
python Tool/scripts/capability-gate.py           # 47 / dangling 0 / cycles 0
bash setup/verify.sh                             # 65 / 0
git status --porcelain                           # 空
```

---

## 执行状态（本轮已落）

| 批次 | 状态 | 说明 |
| :-- | :-- | :-- |
| F1 P0-1…P0-6 | 已完成 | captcha-angle 歧义检测（`ambiguous` + `equivalence_class`，自测 9/9）；temp_ocr 落盘 `ocr.json` 且失败 rc=2（自测 7/7）；probe_api 非 2xx → rc=3、新增 `--method/--data`（自测 12/12）；case_state URL target 保真；seep-start 样例提示 + URL 首条命令；capability-gate 引用统计拆三类（精确 id 8 / 脚本别名 19 / reserved 20） |
| F2 P0-7…P0-12、P1-1…P1-9 | 已完成 | MCP 38→40（含 README 矩阵补两行）、KB 292→409、radare2 5.9.8 / apktool 2.11.0、能力 45/44→47、cases/README 旧域→现行 11 域、ROADMAP 与 softseep 域表 11 行、17→11 组件、apkseep 54/61/57/123、softseep refs 10、7→10 条、README 自指、AUDIT R1–R8、DEFERRALS 61 |
| F3 P1-10…P1-13 | 已完成 | web-api 配方改为 `mcp__js_reverse__*` 真实序列 + `sign_check.json` 判据；web-check 输出补 `url/status/headers`；qinglong 写明 rc=1 语义；captcha-handling 补 claim 步骤；6 个 frida/capstone 脚本统一 `blocked_at:"tool-missing"` rc=2 |
| P2 | 已完成 | `check-budget` 排除 `/audit` 与 `/work`，v1.26.1 起口径为 `git ls-files`（当前 819）；`start_mcp.py` 改为延迟导入（`--help` rc=0、无 IDA 时 `blocked_at:"tool-missing"` rc=2，不再是死文件）；`DEPLOYMENT-CHECKLIST` K1 写明 KB 是冻结基线；`QUICKSTART` 加 Git Bash `MSYS_NO_PATHCONV=1` 提示 |
| 不做 | 保持 | 不加域、不加 capability、不追 264 卡剧本化、accept 全量重构不做（试点未启动） |
