# AUDIT —— 审查档案索引（历史，**非现状**）

> 本文件曾经是"多轮审查台账（R1–R8）"的正文。为了不让冷启动的读者把旧数字当现状，
> **正文已整体移入 `docs/history/`**，这里只保留索引与阅读指引。
>
> **当前状态看这里**：`README.md` 顶部「现状卡」→ `docs/history/FORK-BRIEF.md` → `docs/RELEASE-1.26.1.md`
> **要跑门禁**：`python Tool/scripts/preflight.py`（应为 45/45）
> **外部审查（只读）**：`docs/AUDIT-REQUEST.md` + `docs/AUDIT-REPORT-TEMPLATE.md`

## 历史档案

| 文件 | 内容 |
| :-- | :-- |
| [history/AUDIT-2026-10-21.md](history/AUDIT-2026-10-21.md) | 2026-10-21 终审台账（P0/P1 逐条 + 终审留痕） |
| [history/audit/A.md](history/audit/A.md) | 审计 A：一致性 |
| [history/audit/B.md](history/audit/B.md) | 审计 B：领域深度 |
| [history/audit/C.md](history/audit/C.md) | 审计 C：可跑性 |
| [history/audit/D.md](history/audit/D.md) | 审计 D：架构 |
| [history/audit/E.md](history/audit/E.md) | 审计 E：上下文遗漏 |
| [history/audit/CLOSURE.md](history/audit/CLOSURE.md) | 上述审计的逐条闭环记录 |
| [history/HANDOFF-2026-10-19.md](history/HANDOFF-2026-10-19.md) | 2026-10-19 交接记录 |
| [history/OPTIMIZATION-2.0.md](history/OPTIMIZATION-2.0.md) | v1.25 之后的优化清单（旧语态） |

## 为什么保留而不是删掉

这些文件记录的是「当时为什么这么判」——出现回归时是唯一的对照物（例如"这条当时判为 P1 已修，为什么又出现"）。
但它们的**数字与结论都停留在当时**，因此：只作追溯，不作判据；引用时注明"历史"。
