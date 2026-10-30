# 手册场景索引

安装智能体先读 [BOOTSTRAP](../Tool/docs/BOOTSTRAP.md)。以下按任务选读；专业方法不代表本机已经安装、连通或验证。

## 一、部署与运行

| 手册 | 什么时候读 |
|---|---|
| [工作台使用](WORKBENCH-USAGE.md) | 提供材料、自然语言建项目、换会话接续、报告与归档 |
| [环境确认](PREREQUISITES.md) | 检测解释器、宿主和任务工具 |
| [部署手册](DEPLOYMENT.md) | 安装器参数、自定义目录、更新、卸载与其他宿主接入 |
| [安装核对](DEPLOYMENT-CHECKLIST.md) | 区分文件部署、握手、宿主加载与任务成功 |
| [跨平台](CROSS-PLATFORM.md) | Linux/macOS 与 Windows 的实际差异 |

## 二、提示词与边界

| 手册 | 什么时候读 |
|---|---|
| [模型行为记录](MODEL-REFUSAL-MATRIX.md) | 查阅历史模型表现与任务沟通方式 |
| [提示词分层](PROMPT-LAYERS.md) | 提示词归属、人格卡兼容与历史迁移说明 |
| [基线维护](BASELINE-FREEZE.md) | 变更接口、路径或配置前理解既有检查口径 |
| [中继配置](COMPLIANCE-RELAY.md) | 需要可选网络中继时按其独立步骤配置、验证 |

## 三、专业方法

| 手册 | 什么时候读 |
|---|---|
| [脱壳](UNPACKING.md) | 按实际保护类型选择方法 |
| [反调试](ANTI-DEBUG.md) | 分析反调试信号与工具路线 |
| [PoC 验证](POC-VALIDATION.md) | 执行、采集原始输出和复查结果 |
| [IDA 与替代工具](IDA-PRO.md) | 确定 IDA 是否需要、可用，替代路线覆盖哪些动作 |

## 四、扩展与学习

| 手册 | 什么时候读 |
|---|---|
| [技能编写](SKILL-CREATION-GUIDE.md) | 写技能并走正式导入与部署检查 |
| [从目标到成果](ZERO-TO-HERO-WORKFLOW.md) | 了解专业任务可提供什么材料、如何描述目标 |
| [扩展接口](../Tool/docs/EXTEND.md) | 增补技能、工具、MCP 或领域 |
| [维护与贡献](../CONTRIBUTING.md) | 复现问题、专项验证、CI 与提交变更 |
| [安全报告](../SECURITY.md) | 通过当前仓库可用的私密入口报告安全问题 |
| [上游维护](../docs/UPSTREAM.md) | 核对来源、同步范围和适配结果 |

## 五、工具与参考目录

| 目录 | 用途 |
|---|---|
| [任务配方](../Tool/playbooks/README.md) | 根据目标选用并调整已有方法，不强制整条照搬 |
| [归档参考](../Tool/skill/_pending/INDEX.md) | 按源码路径读取；不作为已部署的顶层技能名 |
| [网络中继](../Tool/scripts/compliance-relay/README.md) | 可选独立组件，不属于默认安装成功的充分条件 |
| [历史模型探针](../破甲卡生成/README.md) | 历史实验资料，不作为当前模型可用性的保证 |

新增维护手册时在本表登记；资源指针见 `Tool/prompts/SEEP.md`，当前验收记录见 [当前状态](../docs/CURRENT-STATE.md)。
