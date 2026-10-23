# docs 索引

> **冷启动只读三份**：`../README.md` 顶部现状卡 → `FORK-BRIEF.md` → `RELEASE-1.26.1.md`。
> 其余按需查；带「历史」标记的一律**不作现状**。

## 1. 现状与交接（权威）

| 文件 | 作用 |
| :-- | :-- |
| [FORK-BRIEF.md](FORK-BRIEF.md) | 交接书：这个仓是谁、相对上游加了什么、用户需求、不可破坏的契约、已知债务、文档地图、常见误解 |
| [RELEASE-1.26.1.md](RELEASE-1.26.1.md) | 最近一轮交付台账（做了什么 / 证据 / 剩余项） |
| [DEFERRALS.md](DEFERRALS.md) | 延迟项台账 + **明确不做**（附理由） |
| [DOMAIN-SPEC-v2.md](DOMAIN-SPEC-v2.md) | 域契约（九件套判据） |
| [UPSTREAM.md](UPSTREAM.md) | 与上游差异口径、吸收纪律、外部技能库许可分层 |
| [CHANGELOG.md](CHANGELOG.md) | 版本变更（顶部为最新） |
| [QUICKSTART.md](QUICKSTART.md) | 第一次上手（命令 + 计数基线） |

## 2. 规格与流程（权威）

| 文件 | 作用 |
| :-- | :-- |
| [GLOSSARY.md](GLOSSARY.md) | 术语表 |
| [STYLE.md](STYLE.md) | 写作风格（判据优先、可机检） |
| [PROMOTION.md](PROMOTION.md) | 技能/能力的晋升流程 |
| [AGENT-BRIEF.md](AGENT-BRIEF.md) | **内部子代理**作业简报（外部审查另走只读流程） |

## 3. 审查（只读）

| 文件 | 作用 |
| :-- | :-- |
| [AUDIT-REQUEST.md](AUDIT-REQUEST.md) | 第三方只读委托书：权限边界 / 只读命令白名单 / 报告必答 10 问 |
| [AUDIT-REPORT-TEMPLATE.md](AUDIT-REPORT-TEMPLATE.md) | 报告骨架（逐字段填） |
| [AUDIT.md](AUDIT.md) | 审查档案**索引**（正文已归档到 `history/`） |

## 4. 历史归档（**不作现状**）

| 文件 | 是什么 |
| :-- | :-- |
| [history/README.md](history/README.md) | 归档规矩与清单 |
| [history/AUDIT-2026-10-21.md](history/AUDIT-2026-10-21.md) | 2026-10-21 终审台账 |
| [history/HANDOFF-2026-10-19.md](history/HANDOFF-2026-10-19.md) | 2026-10-19 交接记录 |
| [history/OPTIMIZATION-2.0.md](history/OPTIMIZATION-2.0.md) | v1.25 之后的优化清单（旧语态） |
| [history/audit/A.md](history/audit/A.md) · [B](history/audit/B.md) · [C](history/audit/C.md) · [D](history/audit/D.md) · [E](history/audit/E.md) · [CLOSURE](history/audit/CLOSURE.md) | 早期五份专项审计 + 闭环记录 |

## 5. 工程侧文档（`Tool/docs/`）

| 文件 | 作用 |
| :-- | :-- |
| [MCP-SETUP.md](../Tool/docs/MCP-SETUP.md) | MCP 服务接入与排障 |
| [BOOTSTRAP.md](../Tool/docs/BOOTSTRAP.md) | 新机器从零到可用 |
| [STAGE0.md](../Tool/docs/STAGE0.md) | 阶段零出口物与出口闸（`case_state.py`）详细说明 |
| [MEMORY.md](../Tool/docs/MEMORY.md) | 案子记忆层（扩展实现） |
| [AUTONOMY.md](../Tool/docs/AUTONOMY.md) | 长跑契约与环境收尾 |
| [FORK-DELTA.md](../Tool/docs/FORK-DELTA.md) | 与上游差异的五问评估法 |
| [PROVENANCE.md](../Tool/docs/PROVENANCE.md) | 资产来源与署名 |
| [EXTEND.md](../Tool/docs/EXTEND.md) | 加工具/能力/技能的流程 |
| [CASE-LIB.md](../Tool/docs/CASE-LIB.md) | 案例库规范 |
| [MERGE-PLAYBOOK.md](../Tool/docs/MERGE-PLAYBOOK.md) | 上游合并操作手册 |
| [WORKSPACE_RULES.md](../Tool/docs/WORKSPACE_RULES.md) | 工作区与产物落盘规则 |
| [DOWNLOADS.md](../Tool/docs/DOWNLOADS.md) | 离线资产清单与来源 |
| [EXT-ASSETS.md](../Tool/docs/EXT-ASSETS.md) | 扩展资产说明 |
| [TOOLKIT_GUIDE.md](../Tool/docs/TOOLKIT_GUIDE.md) | 工具链使用指南 |
| [tool-index.md](../Tool/docs/tool-index.md) | 工具索引（自动生成） |

## 6. 手册（`MANUAL/`）

部署、卸载、校验、提示词分层、模型拒答对照、脱壳、反调试、IDA、跨平台、基线冻结——见
[`MANUAL/`](../MANUAL/) 目录。
