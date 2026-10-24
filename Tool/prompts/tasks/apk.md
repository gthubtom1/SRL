---
description: Android APK/AAB 逆向、去广告、重打包 —— 加载 apkseep 技能链，先判型再动手
argument-hint: "<目标路径或一句话需求>"
---

你正在使用 SEEP 的 **apkseep** 域技能链。目标/需求：`${@:-（未给，先问我）}`

**如果没有给目标（或只给了一句模糊需求）**：先只问一句「目标是什么 / 你想让我做到哪一步」，不要开始分析、不要写脚本。

**第一步（只做这三件事，不许动手）：**
1. 读 `@SEEP_ROOT@/Tool/skill/apkseep/SKILL.md`（这是本域方法论，必须整篇读）
2. 若目标涉及加壳/加密/虚拟化：再读 `@SEEP_ROOT@/MANUAL/UNPACKING.md` 与 `@SEEP_ROOT@/MANUAL/ANTI-DEBUG.md`
   - 需要时链接子技能：`@SEEP_ROOT@/Tool/skill/_pending/01-gate-bypass/SKILL.md`
   - 需要时链接子技能：`@SEEP_ROOT@/Tool/skill/_pending/02-ui-rebrand/SKILL.md`
3. 输出：**判型结论 + 交付上限 M1–M4 + 我缺什么（许可/凭据 · 运行许可与环境 · 样本完整性）**

**硬规则**：
- 用户给的后继目标（补丁/源码级）不改变第一步；第一步永远是判型与上限
- 缺输入就问（问不是退缩），不许假设"没有"就往下走
- 只有跑过命令拿到证据的结论才算结论；没跑过的写"未验证"
- 先 `seep_apk_info` 判包结构；重打包需 apksigner/zipalign，缺则按 NEED_USER 上报
