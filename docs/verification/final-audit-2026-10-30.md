# 1.28.1 独立审查回执（2026-10-30）

状态：实现整合中，完整验证尚未结束。此前已提交基线为 `0d2d756a`（1.28.0）。本页记录本轮证据，不建立第二套需求或待办；有效需求见 [REQUIREMENTS](../../REQUIREMENTS.md)，最终使用状态见 [CURRENT-STATE](../CURRENT-STATE.md)。

## 审查范围与方法

主代理负责整合、导入恢复和最终验证；六个子代理均使用 `codex/gpt-6.1-sol`，分别检查 Core、安装/插件、九域、工具/MCP、工程/CI，以及独立反证与源码清单。修改在独立 worktree 完成，各组采用互斥写集；关键修复有能检出旧实现问题的反例。

审查沿首方关键调用链及正常/异常分支展开，并核对相关测试、配置消费者、部署和文档。第三方按实际调用、固定来源与许可材料检查；没有声称逐行审查全部第三方代码、全部 KB 或每一种目标。

| 需求 | 本轮重点 | 主要验证入口 |
|---|---|---|
| D01–D02 | 自然语言分类、主辅资产、目录/URL 身份与资源边界 | `test_project_workflow.py`、`test_project_typed_inputs.py`、`test_typed_assets.py` |
| D03、D05 | 项目/版本/run 接续、等待/失败/重新规划、恢复事务 | `test_project_integration.py`、`test_manager_integration.py`、`test_project_transaction.py` |
| D04 | 九域真实工具有限任务、方法入口、主辅域交接 | `test_domain_task_delivery.py`、领域契约、技能交接与 MCP 专项 |
| D06–D07 | 证据归属、完整原始输出、验收与报告、完成后篡改复查 | `test_project_acceptance.py`、`test_acceptance_integrity.py`、报告与 closure 专项 |
| D08–D09 | 归档完整性、异位置恢复、版本定位与旧结果失效 | `test_project_archive.py`、`test_version_migrate_delivery.py` |
| D10 | 增量导入、默认根、跨根恢复、安装/卸载保留及插件真实 SDK | 导入三套专项、安装交付专项、`test_persona_rewind_sdk.mjs` |

## 能力适配方案的落实

`nine-domain-capability-adaptation-review.md` 的既有维护项已经逐项核对：现役 `_pending` 引用迁回所属父域，反调试 class/返回语义修正，OEP 不再以固定序言或得分替代证据，APK 方法与历史验证快照分开，内存初检明确不提供进程/模块实体解析。九份能力声明同步规范路径；已有游戏/API 等 KB 增加导航。

Nmap/Nuclei 补版本身份探针；身份通过仅证明对应程序可识别，不代表扫描或具体任务完成。API/认证、游戏运行时/渲染、云/容器、深度取证、fuzz 和批处理的新完整任务链，继续按 [EXTEND](../../Tool/docs/EXTEND.md) 逐项扩展，不新增正式领域或平行管理框架。

## 验证与部署

完整当前回归、工程检查、专项及部署结果将在最终验证后写入本节。中间失败和修前反例保留，不把专项通过相加当成全仓通过。

## 材料与平台边界

- 完整本机领域门禁包含 `apkseep08` 的用户提供 APK；它按登记 SHA-256 在本机核对，保持 Git 忽略，不执行、不上传。干净 Git checkout 不包含该材料，不能宣称公开 CI 已重现这项私有案例。
- 历史 `tmp/` 原始日志保留在本机，不随公开源码分发；历史摘要及哈希见相应已跟踪回执。它们不证明新机器或新版本已验证。
- 本机为 Windows；Git Bash 专项不能替代原生 Linux/macOS 验证。GitHub 工作流、真实宿主加载、工具身份、专业任务成功分别报告。
- 未通过新增空技能、放宽判据、伪造登录、改写历史案例或上传用户材料换取通过；未新增外部扫描或客户目标执行。
