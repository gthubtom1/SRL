# 上游同步与差分（UPSTREAM）

> **原版**：`angusdevgo/Seep-Reverse-Lab`（git remote 名 `upstream`，本仓 `origin` = `gthubtom1/Seep-Reverse-Lab`）
> **原则**：**只做单文件 cherry-pick**（整仓 merge 走 fork 同步流程）。先内容差分 → 按 FORK-DELTA §四 五问逐条评估 → 只 cherry-pick 单文件 → 跑门禁。
> 原因：两仓历史可能不共享祖先（浅克隆/重建过），merge 会把两套历史拧在一起，回滚成本极高。

## 0. 一次性配置（已做，换机器要重做）

```bash
git remote add upstream https://github.com/angusdevgo/Seep-Reverse-Lab.git
git fetch upstream main --deepen=200
```

## 1. 季度差分（10 分钟）

```bash
git fetch upstream main --deepen=200
python Tool/scripts/upstream-delta.py --print      # 输出计数 + 前 40 条
# 报告落在 work/upstream-delta/delta-<时间>.json（gitignore）
```

当前快照（2026-10-22，`upstream/main` = `dc95a90`，浅历史 100 层）：

| 类别 | 数量 | 含义 |
| :-- | --: | :-- |
| 仅上游有 | 140 | 多为 `Tool/cases/项目C|D/*` 的现场工件；本仓已归档到 `Tool/cases/_archive/` 或有意删除 |
| 仅本仓有 | 1015 | 九件套 2.0、11 域、KB 2026、门禁、脚本等增量 |
| 两边都有但内容不同 | 82 | **唯一需要逐条评估的部分**（多为我们改过的 SKILL/配置） |
| 两边相同 | 273 | 无需处理 |

## 2. 五问评估表（FORK-DELTA §四，逐文件过）

对 `both_changed` / `only_upstream` 里的每个**能力相关**文件：

1. 它解决的是**我们已有能力**还是**新能力**？（已有 → 先看我们是否更好，不重复引入）
2. 它是否带**可复现判据**（命令/字段/失败判据）？（没有 → 只进 KB 候选，不进 SKILL）
3. 它是否触碰**共享文件**（routing/gate/spec/README）？（是 → 只在主分支改）
4. 它会不会**引入回归**（依赖旧路径、旧工具名、CRLF 漂移）？（会 → 先跑 `preflight --fast`）
5. 它的**回滚方式**是否明确（单文件 cherry-pick / 删除即可）？

## 3. 合并动作（单文件，不 merge）

```bash
git checkout upstream/main -- <单个文件>        # 只取一个文件
python Tool/scripts/preflight.py --fast          # 悬空引用/篇幅/路由/清理
python Tool/scripts/domain-gate.py --domain <受影响域>
git commit -m "sync(upstream): <文件>（五问通过）"
```

> 若上游改的是 `Tool/skill/**/SKILL.md` 或 `routing.json`：**不要直接 checkout**，按我们的契约重写对应章节，
> 再跑对应域门禁。上游内容只作输入，不作事实来源。

## 4. 我们主动不回同步的内容（有意分歧）

| 类别 | 原因 |
| :-- | :-- |
| 过程文档（`优化方案*.md`） | 已移出仓库到 `work/plans/`，上游仍保留 |
| `Tool/cases/项目C|D` 现场工件 | 含真实目标产物，按脱敏纪律归档在 `_archive/` |
| 旧版 9 技能结构 | 本仓已扩到 24 技能 + 11 域，结构不可逆 |
| CRLF 记录的历史哈希 | 本仓已改为按字节保存（`.gitattributes -text`），上游仍是旧口径 |

## 5. 触发条件与负责人

- **触发**：每季度一次；或上游发布新版本 / 新增工具 / 修了安全问题时立即。
- **负责人**：主分支维护者（唯一可改 `routing.json` / `domain-gate.py` / `docs/DOMAIN-SPEC-v2.md` 的角色）。
- **验收**：`preflight.py` 全绿 + `domain-gate --all` 全绿 + 双平台 verify 65/0；差异写进 `docs/AUDIT.md`。

---

## 6. 第二个上游：Pentest-Skills-Merged（许可分层，按档吸收）

> 位置：用户桌面目录 `Pentest-Skills-Merged`（不在本仓树内，不进版本库）。
> 规模：236 个 `SKILL.md` / 258 篇 md / 153,390 行 / 6.9 MB / 7 个脚本。
> 结构：三套互不兼容模板（recon 137 / hunt 39 / offensive 79），**0 处**「失败判据」独立小节。

### 6.1 许可分层（决定「能不能抄」）

| 层 | 数量 | 依据 | 处置 |
| :-- | --: | :-- | :-- |
| `license: MIT` 自声明 | ~136 | frontmatter 有 `license: MIT`（`revision_date` 是自造未来日期，落地时改实际摄入日） | 可改写吸收，保留 MIT 声明 |
| `offensive-*`（来源 SnailSploit/offensive-checklist） | 79 | 文末 `Source: https://github.com/SnailSploit/offensive-checklist/...`，**无 license 行** | 按 UNKNOWN 处理：只读后**重写判据**，不原文复制、不进 MIT 树 |
| 课程转录（windows-boundaries / -mitigations / crash-analysis / basic-exploitation / fuzzing-course / vuln-classes） | 6（56,306 行） | 正文署名 `@Pwn3rzs Telegram channel`，属付费课程转帖 | **不收**（版权 + 与 pwn-crypto / kb/pe-reverse 重叠 + 单文件超篇幅 2–15 倍） |
| 7 个脚本 | 7 | 全无 `--help` / `--self-test` / 结构化失败 | 只作参考实现，吸收必须按 `docs/DOMAIN-SPEC-v2.md` §3 重写入口 |

### 6.2 已吸收（重写为本仓契约，非复制）

| 来源 | 落地 | 形态 |
| :-- | :-- | :-- |
| `triage-validation` + `recon-scope-triage` + `hunt-race-condition` | `Tool/skill/web-pentest/references/09-ownership-and-timing-proof.md` | 重写为「归属判据表 / 软 404 基线 / 竞态账本读回 / 失败判据表」 |
| 无线 14 篇（wifi / wpa2 / wpa3 / wpa-ent / wps / deauth / krack / evil-twin / ble / classic / z-wave / zigbee / lorawan / wifi-recon） | `Tool/skill/firmware-iot/references/hardware-interfaces.md` 的「无线与近场」章 | 重写为判据表 + 失败判据表 + 模型失误；路由挂 R22 |
| `osint-methodology` + `offensive-osint` 的工序 | `Tool/playbooks/osint-recon.md` + 路由 R36 | 重写为可跑命令序列（先被动、再存活、后代码/人员面），判据可机检 |
| `offensive-*` 79 篇（UNKNOWN 许可） | `Tool/mcp/Tool/reverselab/kb/_archive/pentest-checklist/README.md` + `NOT-ABSORBED.md` | 只建索引（79 行表 + 一句话价值 + 建议动作 + 复核命令），正文**不进树**；需要具体命令时按篇重写 |

### 6.3 待吸收（已分档，按需再取）

| 档 | 内容 | 前置条件 |
| :-- | :-- | :-- |
| 只摘片段 | `hunt-http-smuggling` 的 2026 适配矩阵 / `hunt-cache-poison` 的 Gate 0 / `hunt-oauth\|saml\|jwt` 的断言攻击表 / `offensive-lateral-movement\|data-exfiltration` 的通道可行性判据 | 每处 ≤1 张表，并入现有 reference，不得挤压 6–10 篇上限 |
| 独立新域 | 无线近场（若要升域） | 需 9 件套 + `domain_spec.py` / `routing` / `DOMAIN-SPEC-v2.md` 三处契约变更；当前以 R22 + 单章承载，够用不升域 |
| 不收 | 课程转录 6 篇、`hunt-misc` / `security-arsenal` / `wstg-web-pentest`（泛清单）、`offensive-c2-frameworks`（与本仓「可复现判据 + 取证」定位正交） | — |

### 6.4 吸收纪律（与 §2 五问并列）

1. **判据优先**：目标库里没有「失败判据表」就**不能整篇吸收**，必须先重写成表。
2. **篇幅上限**：reference 60–400 行、SKILL ≤600、KB 50–200；超了先压，不靠拆文件绕过。
3. **不增文件数**：域的 reference 已到 10 篇上限时，并入现有篇章，不新建第 11 篇。
4. **路由必须接线**：新能力必须同时加 `routing.json` 关键词 + `Tool/config/skill-route-probes.json` 探针，否则等于没接。
5. **来源可追**：每篇重写文件在 note 或表头标来源目录名（不复制原文），便于复核。
