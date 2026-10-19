# 轮次证据表 · 归档（en-r1 / gem-staged / space-r1 / zh-r2 / zh-r3）

> **2026-10-18 合并归档。** 原来五份散表（`en-r1-evidence.md`、`gem-staged-evidence.md`、
> `space-r1-evidence.md`、`zh-r2-evidence.md`、`zh-r3-evidence.md`）**全仓零引用**，
> 且它们共同的源 `data/sweep-*.json` **已经不在仓内**（`kernel/07-kernel-sweep/data/` 不存在）。
> 表里的百分比、条数、逐条失败原文**都无法复核**，不能当证据引用——这里只保留结论统计。
>
> 需要逐条原文时：`git show <merge-base>:kernel/07-kernel-sweep/rounds/<名>-evidence.md`
> （五份文件在本提交之前的版本里仍在）。

## 1. 总表（五轮并排）

| 轮次 | 源（已不在仓内） | 请求数 | 模型 | 达标 | 一次过 | 拒答 | 半成品 | 提纲 | 契约失败 | 空 | 被抹 | 网关 | 超时跳过 | 可达达标率 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| en-r1 | `data/sweep-en-r1.json` | 27 | gemini-3.8-flash-high | 3 | 2 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 100% |
| en-r1 | | | mimo-v2.6-flash-free | 8 | 6 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 89% |
| en-r1 | | | space-bunny-free | 7 | 4 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 78% |
| gem-staged | `data/sweep-gem-staged.json` | 8 | gemini-3.8-flash-high | 7 | 7 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 100% |
| space-r1 | `data/sweep-space-r1.json` | 16 | space-bunny-free | 13 | 11 | 2 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 81% |
| zh-r2 | `data/sweep-zh-r2.json` | 27 | gemini-3.8-flash-high | 2 | 2 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 50% |
| zh-r2 | | | mimo-v2.6-flash-free | 7 | 4 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 88% |
| zh-r2 | | | space-bunny-free | 5 | 3 | 1 | 1 | 0 | 0 | 2 | 0 | 0 | 0 | 71% |
| zh-r3 | `data/sweep-zh-r3.json` | 18 | mimo-v2.6-flash-free | 6 | 5 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 67% |
| zh-r3 | | | space-bunny-free | 9 | 7 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 100% |

可达达标率的分母扣掉了空/被抹/网关三类传输失败——它们不是卡片的成绩。

## 2. 这些表原来还带什么（已随删除消失）

- **逐条失败清单**：每题一行（题号 / 判定 / 传输 / 耗时 / 推理 token / 正文开场 110 字）。
- **候选禁用串**：从失败开场里自动抽的串，标 `ok` / `MISSING` 对照当时的卡。

要重新生成这种表，必须先有原始 JSON：
`python analyze.py data/<轮次>.json --out rounds/<轮次>-evidence.md`
（`analyze.py` 的输入就是 sweep 的原始响应；没有 JSON 就没有表。）
