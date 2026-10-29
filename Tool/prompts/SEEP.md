# SEEP —— 层间裁决与指针

> **本文件只放「裁决顺序 + 指针」，不复制任何规则正文。**
> 原版做法照抄：上游 `open-reverselab/CLAUDE.md` 只有 275 字节，内容就是"参见 AGENTS.md + 链接"。
> 规则正文的归属：宿主纪律 → `AGENTS.md`；边界锚 → 扩展注入；分层与迁移存档 → `MANUAL/PROMPT-LAYERS.md`。

---

## 0. 四层裁决（冲突时按此顺序）

| 顺序 | 层 | 载体 | 管什么 |
| :--: | :-- | :-- | :-- |
| **1** | 边界锚 | 扩展注入（`seep-boundary`） | 凭据红线 / 授权门 / 沙箱契约 |
| 2 | 宿主纪律 | `AGENTS.md` | 执行分档 / 判型 / 启动 / 网络 / 节律 |
| 3 | 能力 | `Tool/skill/*/pack.json`（路由）、`tool-capabilities.json`、`Tool/skill/*/SKILL.md` | 判型路由 / 工具能力 / 战术 |
| 4 | 风格人格 | `personas/*.md` | 语气 / 称谓 / 输出格式 |

**唯一铁律**：第 4 层只能决定"**怎么说**"，不能决定"**能不能做**"。与 1/2 冲突时，一律以 1/2 为准。

---

## 1. 指针（要什么去哪）

| 要什么 | 去哪 |
| :-- | :-- |
| 判型与分发（唯一入口） | `Tool/skill/seep-router/SKILL.md` |
| 当前需求与接续 | `REQUIREMENTS.md`（需求与取消项）→ `docs/CURRENT-STATE.md`（唯一当前进度与剩余工作） |
| 智能体安装与修复 | `Tool/docs/BOOTSTRAP.md` |
| 路由单一事实源 | `Tool/skill/*/pack.json`（现算入口 `Tool/scripts/route.py`） |
| 工具能力 / 降级 / 安装 | `Tool/config/tool-capabilities.json` + `python Tool/scripts/mcp-doctor.py` |
| 战术方法论 | `seep_kb_search` → `seep_kb_read` |
| 知识库根（固定路径，勿 find/grep 去找） | `Tool/mcp/Tool/reverselab/kb`（按「客户怎么问」找答案：`Tool/mcp/Tool/reverselab/kb/INDEX-BY-QUESTION.md`） |
| 手册索引（部署、专业方法与参考目录） | `MANUAL/README.md` |
| 提示词分层 / 人格卡兼容 / 迁移存档 / G-Auth 裁决 | `MANUAL/PROMPT-LAYERS.md` |
| 加技能 / 加 MCP / 加工具 | `Tool/docs/EXTEND.md` |
| Lab 状态机（`lab-mode.flag`） | `AGENTS.md` §一 |

---

## 2. 换东西只改这里，不动本文件

| 场景 | 只改 | 本文件 |
| :-- | :-- | :-- |
| 换人格卡 | `~/.pi/agent/personas/*.md` | 不动 |
| 加 / 换技能 | 按 `Tool/docs/EXTEND.md` 的类型契约导入、部署与验证 | 不动 |
| 加 / 换 MCP 工具 | 实际工具接口、依赖契约及 `Tool/config/mcp-servers.json` 声明 | 不动 |
| 改授权门 / 红线 | 扩展里的边界锚 + `AGENTS.md` §六 | 不动 |
