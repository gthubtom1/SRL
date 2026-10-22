# PROVENANCE —— vendored KB 的出处与本地改动

> 这份文件回答一件事：**这个目录是从哪来的、我们改过什么、上游同步时不能覆盖哪些文件**。
> 没有它，重新 vendor 会把本地修复悄悄冲掉（审计 B/E2 指出的风险）。

## 出处

| 项 | 值 |
|---|---|
| 目录 | `Tool/mcp/Tool/reverselab/` |
| 上游项目 | `open-reverselab`（`Tool/upstream/open-reverselab/` 为镜像） |
| 用途 | `seep_kb_search` / `seep_kb_read` 的知识库根（409 篇 + 索引） |
| 同步方式 | `setup/sync-upstream.ps1` → 先落 `Tool/upstream/`，再按 `setup/upstream-rules.json` 的 `preserve_local` 选择是否覆盖 |

## 本地改动（**同步时必须保留**）

| 文件 | 改了什么 | 理由 |
|---|---|---|
| `kb/field_journal__template.md` | 加「归因 / 适用边界 / 反证条件」三列 | 与 `case_state` 的证据口径对齐（结论必须能写清"能证明什么、不能证明什么、什么能推翻它"） |

> 除上表外，`kb/` 其余文件应与上游一致；若发现差异，视为漂移，需在 `FORK-DELTA.md` 登记。

## 校验

```bash
python Tool/scripts/preflight.py --fast     # 悬空引用 0 / 可移植 0
python -c "import json;print(json.load(open('setup/upstream-rules.json',encoding='utf-8'))['upstreams']['open-reverselab']['preserve_local'])"
```
