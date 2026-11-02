# kb_local —— 本地知识库覆盖层（不属于 vendored 上游）
# 本地知识增量层

此目录保存自写、可分享的知识增量，不直接改vendored知识库。已有主题先检索并阅读：无增量不写，有新条件/反例更新原文，真正新主题再按所属领域建立文章。经验的来源、适用性、成熟度及匿名证据指纹跟文章走，不能把聊天里的“成功”当作真实见证。

维护入口为 [资源维护配方](../../playbooks/resource-maintenance.md)，薄CLI为 `Tool/scripts/resource-maintain.py`。Markdown正文前可带有界的seep-resource JSON注释，文章是权威，检索视图由当前来源内容生成，不手抄另一份清单。

项目私密材料仍留项目，凭据仍进仓外凭据仓。个人外部知识根用显式本机来源配置，不把机器绝对路径、候选计划、原始聊天或备份提交到Git。新增文章仍受现行第一方预算约束，不修改阈值或来源分类。
`Tool/mcp/Tool/reverselab/kb/` 是 **open-reverselab 的 vendored 副本**，重新 vendor 会被覆盖。
任何**自己写的**战术条目（踩坑记录、判据表、案例复盘）请放这里，`seep_kb_search` 会同时检索两个根。

约定：
- 目录结构随意，但文件名带 `field_journal_YYYY-MM-DD_主题.md` 会自动进入案例流；
- 每条失败记录必须写清三件事：**归因**（目标属性/手法/环境/执行）、**适用边界**、**反证条件**
  （模板见 `../Tool/reverselab/kb/field_journal__template.md`）。
