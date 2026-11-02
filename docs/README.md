# 文档入口

用户从 [README](../README.md) 了解项目；安装智能体从 [BOOTSTRAP](../Tool/docs/BOOTSTRAP.md) 开始。文档说明当前接口，实际可用性由当前代码与执行结果确定；历史报告不产生新需求。

| 场景 | 入口 |
|---|---|
| 安装、修复和验证 | [BOOTSTRAP](../Tool/docs/BOOTSTRAP.md)、[部署手册](../MANUAL/DEPLOYMENT.md)、[安装核对](../MANUAL/DEPLOYMENT-CHECKLIST.md) |
| 用户日常使用 | [工作台使用](../MANUAL/WORKBENCH-USAGE.md)、[快速开始](QUICKSTART.md) |
| 技术未知、外部查证与无进展 | [查证配方](../Tool/playbooks/evidence-led-investigation.md)，不强制普通开发进入完整项目流程 |
| 整理经验、补知识与维护技能 | [用户说法与结果](../MANUAL/WORKBENCH-USAGE.md#整理项目经验以后怎样说)、[资源维护配方](../Tool/playbooks/resource-maintenance.md)；先比较旧内容，再按范围更新和读回 |
| 功能范围 | [当前需求](../REQUIREMENTS.md)，当前用户指令优先 |
| 当前验证与适用范围 | [CURRENT-STATE](CURRENT-STATE.md) |
| 定位实现 | [架构](ARCHITECTURE.md)、[领域契约](DOMAIN-CONTRACT.md) |
| Agent 执行接口 | [执行手册](../Tool/docs/EXECUTION.md)、[项目接口](../Tool/prompts/contracts/AGENT-OPERATING-SPEC.md) |
| 新增技能、工具、MCP | [EXTEND](../Tool/docs/EXTEND.md)、[MCP 配置](../Tool/docs/MCP-SETUP.md) |
| 专业方法 | [手册索引](../MANUAL/README.md)、[经验](LESSONS.md) |
| 接续维护 | [HANDOFF](HANDOFF.md)；恢复客户项目时读取该项目自身状态 |
| 来源和历史 | [UPSTREAM](UPSTREAM.md)、[PROVENANCE](../Tool/docs/PROVENANCE.md)、[CHANGELOG](CHANGELOG.md) |

按当前任务读取相关代码和资料，不沿历史报告寻找新的优化任务。第三方资料、技术方法和旧案例不是新机器的安装完成证明。

## 当前文档与历史材料怎样分开

- README介绍产品；REQUIREMENTS决定需求与取消项；CURRENT-STATE只记当前事实和剩余步骤；ARCHITECTURE定位实现。它们不各自维护另一份待办或完成数字。
- EXTEND与具体配方保存现行维护步骤。完成的方案可以保留设计依据和最终回执，但不从其历史实施顺序恢复任务。
- verification下的日期/提交回执保留原通过、失败和证明范围；LESSONS、KPI及历史来源用于追溯，不是当前执行规则或全局能力声明。
- 新增/合并资料先查实际引用；不能为了目录看起来整齐就删掉案例见证、第三方许可、有效证据或其他工作线的文件。仓外备份、个人资源和本机缓存不属于公共知识清单。
