# kb_local —— 本地知识库覆盖层（不属于 vendored 上游）

`Tool/mcp/Tool/reverselab/kb/` 是 **open-reverselab 的 vendored 副本**，重新 vendor 会被覆盖。
任何**自己写的**战术条目（踩坑记录、判据表、案例复盘）请放这里，`seep_kb_search` 会同时检索两个根。

约定：
- 目录结构随意，但文件名带 `field_journal_YYYY-MM-DD_主题.md` 会自动进入案例流；
- 每条失败记录必须写清三件事：**归因**（目标属性/手法/环境/执行）、**适用边界**、**反证条件**
  （模板见 `../Tool/reverselab/kb/field_journal__template.md`）。
