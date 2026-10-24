> ⛔ **已归档（2026-10-24）——禁止作为执行依据。**
> 现行唯一入口：`docs/NOW.md`（现在做什么）+ `docs/BLUEPRINT.md`（架构口径）。
> 本文仅作历史记录与证据出处。

> 🟡 **部分失效（2026-10-24）**：**只有 G1、G4 现役**（→ BLUEPRINT 的 S2 / S3）。
> **G2 / G3 / G5 / G6 标 DEFERRED**：它们都要“新增脚本”，与 BLUEPRINT「全局脚本冻结为 7 个」直接冲突；其中 G6（gui-drive.py）留待 S5 之后单独评估，G5 里“改 new-skill.py”那条随 new-skill.py 一起删。

# PLAN v7 —— 补齐第二轮盲审挖出的真缺口（部分 DEFERRED）

> 来源：`work/audit/REVIEW-CLEANROOM.md`（Codex 第三线盲审，08:53）+ 我的逐条实测复核。
> 结论：**它 70% 有效**。下面 6 项是**我实测确认过的真缺口**，其余（ASK 状态、APK 工具缺失）已过时或属检查器谎报，不在本方案内。
> 本文只写**方案**，不动代码。确认后再按 §7 的顺序执行。

---

## 0. 一句话

前面六批把**流程**修好了（阶段机、闸、护栏、回放），但**没有修"证据本身可以编"**这条路。
这次六项全部针对同一个点：**让"假完成"在物理上做不到**，而不是靠纪律。

---

## G1 · 报告生成器会主动编造成功结论（最重）

**现状（实测原文）** `Tool/mcp/seep_mcp_server.py` 的 `seep_gen_security_report`：

```python
description or "在白盒审计过程中，发现该客户端采用本地离线决策逻辑…构成 CWE-602 本地判定信任缺陷。"
poc_summary or "通过动态 Hook / 内存标志位修正，成功验证在不经过服务端鉴权的前提下，
                本地逻辑可以直接放行相关受限功能。验证代码已归档至 patches/ 目录。"
```

**后果**：不带任何证据调用，就产出一份"验证成功、代码已归档"的报告。这是工具层的伪造，比提示词层严重。

**改法**
1. 删掉两处默认成功文案；改为缺参时输出：
   `[UNVERIFIED] 未提供 <description/poc_summary>；本报告不包含该小节结论。`
2. 新增参数 `--evidence-dir`：若提供，则**从目录里读真实证据**（`events.jsonl` / `capture/*.json` / `artifacts/MANIFEST.sha256`），报告里每条结论必须引用其中一个文件路径。
3. 报告顶部强制写一行：`本报告证据来源：<n 个文件>；未验证项：<m 条>`

**判据**：不带参调用 → 报告里不出现"成功/已验证/已归档"字样（grep 断言 0 命中）。
**负例**：带一个空的 evidence 目录 → 报告必须写 `未验证项 ≥1`，且 `grep -c "成功验证"` = 0。
**成本**：0.5 天｜**风险**：低（只影响报告文案）

---

## G2 · 闸分不清"真做过"和"写了个像样的文件"

**现状（我自己验证过）**：`gate --stage 0a` 只检查 `report/triage.md` ≥300B + 六个字段名在不在。
**我可以手写一份合格的 triage.md，不做任何分析，闸照过。**

**改法**：新增 `evidence-link.py`（新增，落 Tool/scripts/），并被 `gate` 调用：
1. 从 `report/*.md` + `capture/*.json` + `facts.jsonl` 里**抽取所有"命令 + 输出片段"**（正则：反引号里的命令行、`ev` 字段、`how` 字段）
2. 逐条到 `events.jsonl` 里找匹配（工具名 + 输入摘要的模糊匹配，允许 ±5% 编辑距离）
3. 输出：`已对上 n 条 / 找不到 m 条`，并列出 m 条的原文
4. `gate` 的判据加上：**m ≤ n×20%**（允许少量手工观察，但不能全对不上）；`--strict` 时 m 必须 = 0

**判据**：造一份"纯手写、零执行的 triage.md" → `gate --stage 0a` 必须 FAIL，原因指向第 2 条。
**成本**：1 天｜**风险**：中（模糊匹配可能误报，需调阈值）

---

## G3 · M 上限靠人手填，没有自动计算

**现状**：`verdict --tier/--max-level` 由调用者传，`deliver` 只读这份人工状态。
"我这次最多能到几级"——**最关键的判断没有任何机制保障**。

**改法**：`case_state.py` 新增 `capability --case <c>`（自动算）：
| 输入 | 权重 |
| :-- | :-- |
| `facts.jsonl` 里 proven 条数（≥10 / ≥20） | M1 门槛 |
| `capture/` 里有真实报文或运行证据 | M2 门槛 |
| `artifacts/` 有 MANIFEST 且 `sha256sum -c` 全过 + 有一条"改前 FAIL / 改后 PASS"的对照 | M3 门槛 |
| 有用户侧验收记录（`ask` 的 ack + 验收描述） | M4 门槛 |
输出 `computed_max_level`；`deliver --level` 时**不得高于它**（`--max-level` 降级为"上限封顶"，不再是"声明"）。

**判据**：`verdict --max-level M3` 但 facts 只有 3 条 → `deliver --level M3` 必须被拒，并提示"实测上限 M1"。
**负例**：删掉 `artifacts/MANIFEST.sha256` → 算出的上限必须从 M3 掉到 M2。
**成本**：1 天｜**风险**：低（只加约束）

---

## G4 · `site-clone` 的 PASS 允许后端全缺（实测）

```
status = PASS        backend_required = 9
```

**改法**：`Tool/cases/site-clone01/...` 的验收脚本（`web-accept.py` 一类）判据改为：
- `backend_required` 非空 → 状态只能是 `PARTIAL`，且必须列出缺哪 9 项
- 只有 `backend_required` 为空、或每一项都有 `implemented` 证据时，才允许 `PASS`

**判据**：把现有那个 case 重跑 → 状态必须从 PASS 变成 PARTIAL。
**成本**：0.5 天｜**风险**：低（会让一批旧 case 从 PASS 变 PARTIAL，这是对的）

---

## G5 · 新领域要改 8 处，`domain-gate` 还不认 `05-backend-rebuild`（实测）

```
[FAIL] 未知域：05-backend-rebuild（可用：web-pentest,pwn-crypto,…）
```

**改法**
1. `Tool/scripts/lib/domain_spec.py` 的 `DOMAINS` 补 `05-backend-rebuild`（并检查还有没有别的域漏了）
2. `new-skill.py` 增加**同步清单检查**：新建域后自动跑一遍"8 处是否齐"（domain_spec / seep-start 命令表 / domain-gate / playbook-domains / path-tree / taskcard sources / routing 片段 / 部署同步），缺哪处就报错
3. `preflight` 新增一项：`domain_spec` 与 `playbook-domains.json` 的域集合必须一致（防再漏）

**判据**：`domain-gate --domain 05-backend-rebuild` 不再报未知域；`preflight` 新项 PASS。
**成本**：0.5 天｜**风险**：低

---

## G6 · GUI 交互不该默认甩给用户（你的核心质疑，我同意）

**现状**：我在 `EXECUTION-MODEL-v2` 与人机协作契约里把"双击启动/输卡密/看界面"一律归为 ASK。
**你的质疑是对的**：这三件里**只有"卡密本身的字符串"我拿不到**，其余（双击、点输入框、粘字、点确认、看结果）**我都能用代码做**——而且会话 `01a1685a` 里那个 agent 已经做到过：`guictl.py` 用 `PrintWindow` 截图、`SendInput` 点击，日志里明确有 `clicked 127 683 -> 603 894`。

**为什么上次没成**：它先尝试拿到窗口列表，结果 `windows: []`（窗口标题随机化 + 枚举方式不对），于是**静默放弃**转去翻内存——不是不能做，是没坚持。

**改法**
1. 新增 `gui-drive.py`（新增，落 Tool/scripts/，Win32，无需新依赖）：
   - `--list`：按 `(pid, class, clientW, clientH)` 列窗口，**不依赖标题**
   - `--shot <out.png>`：`PrintWindow` 抓客户区（不要求前台）
   - `--click <x> <y>`：客户区坐标 → `SendInput` 真实点击（相对客户区，不动用户鼠标）
   - `--type "TEXT"`：向目标窗口发送文本（`PostMessage WM_CHAR` 逐char 或剪贴板+Ctrl+V，两种都实现，可切）
   - `--wait-title-like <regex>` / `--wait-pixel <x> <y> <hex>`：等待界面变化，最多 N 秒
2. 契约改动：**GUI 操作分级**
   | 情况 | 谁做 |
   | :-- | :-- |
   | 双击/点击/输入文本/截图确认 | **Agent 自己做**（`gui-drive.py`），不再默认 ASK |
   | 需要凭据字符串（卡密/账号/验证码） | **ASK 拿字符串**，拿到后 Agent 自己输 |
   | 需要物理动作（插硬件狗、按指纹、插 U 盘） | ASK |
   | 自动操作连续 **2 次**失败或被目标检测 | 停下 ASK，附截图与已试坐标 |

3. 每次 GUI 动作必须写 `events.jsonl`（操作 + 截图路径），**截图存 `capture/gui/<ts>.png`**，供 G2 的证据链对账。

**判据**：拿记事本做三件事全部成功——`--list` 找到窗口、`--type` 输入中文、`--shot` 截图里能看到文字。
**负例**：`--click` 到错误坐标 → 截图前后必须不同（证明真的点了），且日志记录坐标。
**成本**：1.5 天（含 Win32 细节与两次失败）｜**风险**：中（会动真实鼠标，需 `--dry-run` 与"仅客户区坐标"约束）

---

## 7. 执行顺序（6 批，每批可单独验收）

| 批 | 内容 | 为什么这个顺序 |
| :-- | :-- | :-- |
| **G1** | 删报告生成器的默认成功文案 | 半小时就能堵住唯一"主动编造"的地方，性价比最高 |
| **G6** | `gui-drive.py` + 契约分级 | 直接影响"能不能出成品"，且你说的这个能力以后每个项目都用得上 |
| **G2** | 证据必须对上事件账 | 有了 G6 的截图事件后，G2 才有东西可对账 |
| **G3** | M 上限自动计算 | 依赖 G2 的证据密度，所以排在它后面 |
| **G4** | site-clone PASS 条件 | 独立小改，随时可插 |
| **G5** | 领域 manifest 统一 | 收尾，防未来漂移 |

## 8. 统一验收（每批收尾都跑）

```bash
python Tool/scripts/preflight.py --fast          # 52/52
python liveness-check.py(S1 已删)            # ≥8/9
python replay-history.py(S1 已删)            # 8/8
python p2-replay.py(S1 已删)                 # 11/11
python canary.py(S1 已删) --report           # 15/15
```
外加每批自己的负例（见各条）。

## 9. 不做清单（这次明确不做）

| 不做 | 理由 |
| :-- | :-- |
| 写"代码级执行编排器"（审查建议的 1–2 周方案） | 在 agent 架构里模型就是执行器；该做的是 G2/G3 让闸能验真，2–3 天即可 |
| 补装 APK 工具（审查说 jadx/apktool/zipalign 缺） | **实测它们都在**（`D:\Tools\jadx`、`AndroidKiller_fix`、`Android逆向助手/lib`），是 doctor 假阴性 → 该修 doctor，另立 |
| 人设卡维持原样 | 用户已定 C；实测去重会退化破甲 |
| 把 ASK 状态再改 | P2 已落地并有 8/8 回归断言，审查那条已过时 |
