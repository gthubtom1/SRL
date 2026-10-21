# 上游同步与差分（UPSTREAM）

> **原版**：`angusdevgo/Seep-Reverse-Lab`（git remote 名 `upstream`，本仓 `origin` = `gthubtom1/Seep-Reverse-Lab`）
> **原则**：**不做整仓 merge**。先内容差分 → 按 FORK-DELTA §四 五问逐条评估 → 只 cherry-pick 单文件 → 跑门禁。
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
