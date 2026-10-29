# 技能编写与接入

用户只需描述希望补充的能力，由智能体检查已有技能、工具和知识是否能覆盖，再决定需要新增什么。技能说明提供选择和操作方法，专业判断由主模型完成；写出一个 Markdown 文件不等于已经接入或验证。

## 先确定类型

| 类型 | 条件与落点 |
|---|---|
| 正式领域 `domain` | 有真实 `pack.json`、领域技能、路由、深度契约与见证；全局契约和部署均通过后才能报告生效 |
| 横切技能 `crosscutting` | 多领域可复用的方法，放顶层技能目录，但不冒充新正式领域 |
| 子技能 `subskill` | 归属已有正式领域，落入 `Tool/skill/<parent>/subskills/<name>/`，经父领域引导表按需引用；不作为新的顶层技能名部署 |
| 工具声明 `tool` | 导入器仅处理声明；实际接线、安装和可用性验证另行完成 |

类型由智能体根据内容明确选择；`auto` 只给建议。完整参数、事务、备份和回执语义以 [EXTEND](../Tool/docs/EXTEND.md) 为准。

## 编写内容

`SKILL.md` 用标准 YAML frontmatter 声明 `name`、`description`，正文写清何时使用、需要哪些输入、如何选择路线、调用什么工具、如何验证、失败时怎么办，以及与其他技能的衔接条件。

- 先复用当前实际存在的 MCP、CLI、配方和知识，不以旧工具数量或旧 API 名作为接口。
- 活跃方法引用正式技能或当前域内子技能路径（`subskills/<name>/SKILL.md`）。`_pending`不接收新增活跃技能；历史证据中仍有用途的引用保留明确身份，不能机械替换或宣布已不存在。
- 每个正式域的 `SKILL.md` 顶部均维护【子技能导航表】（名称、功能、适用特征、相对路径），Agent 按需读取。
- 跨域结果绑定到同一项目的材料、运行和证据；不强制每个任务执行同一条全阶段流程。
- 工具文件存在、命令返回 0、模板产出都不能代替任务结果检查。未运行或依赖缺失时保留未验证状态。
- 安全与操作边界沿用宿主、用户授权和当前项目约定，不在技能中复制另一套全局规则。

## 接入与验收

先在独立源目录生成技能内容，再通过正式入口计划和导入。所有命令从仓库根目录执行；尖括号为智能体要替换的值。

```bash
python Tool/scripts/skill-import.py plan --kind subskill --parent <domain> --from <技能目录> --deploy-root <skills-root> --json
python Tool/scripts/skill-import.py import --kind subskill --parent <domain> --from <技能目录> --deploy-root <skills-root> --json
python Tool/scripts/skill-import.py verify --name <child> --parent <domain> --deploy-root <skills-root> --json
python Tool/scripts/route.py --check
python Tool/scripts/skill-handoff-check.py
python Tool/scripts/check.py --runtime --json
```

`<skills-root>`是选定AgentRoot下的`skills`目录；源码与部署均保留`<domain>/subskills/<child>/SKILL.md`。正式领域与横切方法替换为对应kind，并提供其必需pack或分类。自定义skill-dir时必须显式给出独立部署根，测试不能落入真实用户目录。覆盖已有技能必须明确`--replace`，并保留导入回执与备份。

读回执中的仓库落盘、逐部署根哈希、下次会话可用性、正式领域状态和回滚结果；有缺口就处理具体缺口。安装/更新后在新宿主会话确认加载，再用一个能代表该技能用途的任务验证结果，不能宣称“永不冲突”或“所有目标即插即用”。

用户可以直接说：“补充一个处理 WebSocket 帧的技能，先查已有能力，选择合适类型，通过当前导入、部署与任务验证后告诉我结果。”不要求用户填写内部接口参数。
