# 当前架构与实现落点

功能需求唯一来源为 [REQUIREMENTS.md](../REQUIREMENTS.md)，完成状态唯一来源为 [CURRENT-STATE.md](CURRENT-STATE.md)。本页描述代码职责，不新增产品要求或宣称所有路径已验收。

## 1. 一次项目的主路径

```text
用户自然语言 + 文件/目录/URL
→ Agent 判断目标、保护、主辅领域、可达上限和缺失材料
→ 读取 seep-router / 对应领域 SKILL / references，检索相关知识库
→ project_workflow 建项目和路线，Manager 检查动作准入
→ 实际 MCP / 已有脚本 / CLI / 必要 GUI
→ 捕获原始输出，登记目标/版本/run/资产身份和证据
→ 按明确判据验收，生成报告，结束或交接
→ 需要时导出/重新导入，换版本后重新验证
```

自然语言直接触发选域。额外域快捷命令已取消；本项目不生成命令卡。

## 2. 核心模块

| 位置 | 负责什么 | 关键边界 |
|---|---|---|
| `Tool/skill/seep-router/SKILL.md` | 判断、选域、上限和所缺材料 | 不替代各领域专业方法 |
| `Tool/skill/*/pack.json` | 正式域身份、工具、证据与深度声明 | 名单由实现读取，不在文档重复维护另一套注册表 |
| `Tool/skill/<域>/SKILL.md`、`subskills/`、references、playbooks | 父域导航、专业方法和具体判据 | 子技能随父域保持目录结构部署；跨域返回同一project/version/run，库存不是已验收能力 |
| `Tool/mcp/seep_mcp_server.py`、`seep_contract.py` | MCP 工具、参数/结果契约与共享校验 | 工具注册、连通、真实执行分别证明 |
| `Tool/scripts/project_state.py` | project/version/run、材料、证据、验收和交接 | 检查登记见证完整性，不代替人判断原始输出的全部专业语义 |
| `Tool/scripts/manager_state.py` | 规划、选择、等待、失败和换路，执行前准入 | 状态和证据绑定到当前 generation |
| `Tool/scripts/project_workflow.py` | classify/start/act/status/close 与受控捕获 | `workflow-entry-only`，不是宿主所有工具的全局拦截器 |
| `Tool/scripts/lib/typed_assets.py` | 文件、目录快照、URL描述身份 | URL描述不证明远端实际内容 |
| `Tool/scripts/project_report.py` | 报告、结论账、引用、适用性及状态复查 | 弱/缺支持/跨run结论不自动升为已确认 |
| `Tool/scripts/project_archive.py` | export/verify/import | 成员指纹、资源与路径边界，移位恢复不覆盖已有目的地 |
| `Tool/skill/softseep/scripts/version-migrate.py` | 版本基线与定位结果 | 唯一定位仍需当前版本验收 |
| `Tool/scripts/case_state.py` | 既有单案阶段、事实、复现与报告接口 | 旧case与新项目接口并存，不因结构不同而另造账本 |
| `Tool/scripts/skill-import.py` | 域内身份定位、导入、部署、核验与事务恢复 | 父域＋名称定位；源码/部署同为subskills，不将按需子技能冒充顶层自动选中 |
| `setup/`、`Tool/scripts/lib/runtime_root.py` | 安装、更新、卸载、根定位和注册 | 当前部署为源码运行时注册；保留源码目录 |

## 3. 提示词与部署

输入扩展保留原始任务、路径、代码、URL、JSON、附件和历史正文；lab只控制工作偏好与独立检索别名事件。`input-normalize.json`不再含全文改写输出；中继只作请求/响应字节透传，不改变任务或拒答后改写重发。输入控制语法、提示词边界装配、HTTP协议处理分别验证。

`Tool/prompts/AGENTS.md` 是共享行为规则源，`Tool/prompts/SEEP.md` 提供资源指针。安装器把规则、技能和扩展部署到 agent 目录；项目开发的接续入口为当前需求与当前状态。

`Tool/prompts/extensions/` 的执行守卫不因文档清理而更改。项目级bootstrap模板位于 `Tool/prompts/contracts/AGENTS.md`，由各宿主的接入方式加载；当前仓库根没有另放一份AGENTS副本。个人设置、第三方 MCP、凭据文件和宿主管理块不由项目文档重写。新进程加载与磁盘一致性分别验证。

## 4. 检查和证据

- `Tool/scripts/check.py --runtime --json` 验当前实现与专项回归，包含安装文档入口检查；默认历史工程门禁仍保留。`--fast` 会跳过套件，不能替代完整验收。
- `gate.py` 验证包与见证；`domain-gate.py` 消费领域注册、深度声明和 [当前领域契约](DOMAIN-CONTRACT.md)。
- `preflight.py` 检查结构、入口、契约与部署一致性；它不能决定功能是否应该存在。措辞检查识别无依据的整类任务禁令，不能把格式/版本适用条件、证据上限或系统副作用边界当成禁令；对应正反例保留。
- 案例/项目的原始证据留在各自工程中；本项目当前剩余问题只登记在 CURRENT-STATE。
- 文件清单与预算使用 `Tool/scripts/lib/source_inventory.py`，原始文件闭包和第一方/第三方来源角色均可核验，阈值不因文档整理而改变。

## 5. 扩展与维护

用户上手见 [工作台使用](../MANUAL/WORKBENCH-USAGE.md)，维护操作见 [工程扩展](../Tool/docs/EXTEND.md) 和 [手册索引](../MANUAL/README.md)。技术手册、知识库、案例和第三方说明是按需能力材料，不是本产品的功能待办来源。

已淘汰的产品规划、旧接力棒和“全绿”宣称删除；不再以归档副本维持另一套设计权威。
