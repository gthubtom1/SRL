# _pending 历史参考与工程兼容入口

当前正式调用层次是 `seep-router` → 九个父领域 → `<父域>/subskills/<子技能>/SKILL.md`。`unpack-loop` 是跨域方法，`references/`、`scripts/` 是各技能的资源。

本目录保留历史方法、来源材料和仍被工程检查/旧案例调用的兼容文件，**不是等待全部启用的任务清单，也不作为现役顶层技能部署或预载**。读取归档不等于该能力已经接入或验收；执行现有任务优先使用下面列出的正式入口。不要整目录复制到宿主，也不要在未核对引用前删除它。

## 已有正式替代入口

| 历史目录 | 当前正式入口 |
|---|---|
| `ad-cloud` | `Tool/skill/pwn-crypto/subskills/ad-cloud/SKILL.md` |
| `binary-diff` | `Tool/skill/softseep/subskills/binary-diff/SKILL.md` |
| `ida-reverse` | `Tool/skill/softseep/subskills/ida-reverse/SKILL.md` |
| `plugin-targets` | `Tool/skill/protocol-plugin/subskills/plugin-targets/SKILL.md` |
| `signin-automation` | `Tool/skill/web-pentest/subskills/signin-automation/SKILL.md` |
| `site-clone` | `Tool/skill/web-pentest/subskills/site-clone/SKILL.md` |

## 其他保留材料

| 位置 | 保留用途及当前使用方式 |
|---|---|
| `00-analysis`、`00-triage`、`01-gate-bypass`、`02-ui-rebrand`、`03-license-hookup`、`04-version-migrate`、`05-backend-rebuild` | 旧阶段方法与案例参考；现役任务从 router 和所属父域出发，按需要读取对应 playbook，不恢复旧域快捷命令 |
| `version-migration` | 旧追版参考；当前执行入口为 `Tool/skill/softseep/scripts/version-migrate.py` |
| `doc-hygiene` | 工程文档检查仍调用其中脚本，保留路径兼容；不是新增业务领域 |
| `llm-security`、`pm-plan` | 保留专项方法参考，不自动宣称已形成当前环境的完整任务链 |
| `safe-skills/` | 保留上游/历史方法来源；按实际适用范围读取，当前 Android/Native 等任务仍由正式父域组织 |

归档文本可能保留过时路径、旧说明和当时结论。历史事实不改写成新验收结果；与当前用户要求、REQUIREMENTS 或现役技能冲突时，以当前入口和实际证据为准。

新增技能先在独立源目录准备，通过 `Tool/scripts/skill-import.py` 以真实父域身份导入，再核验父导航、部署和限定任务。三层结构的完成依据是入口和调用关系一致，不是这个目录必须为空。
