---
description: 固件/IoT 解包与仿真 —— 加载 firmware-iot 技能链，先判型再动手
argument-hint: "<目标路径或一句话需求>"
---

你正在使用 SEEP 的 **firmware-iot** 域技能链。目标/需求：`${@:-（未给，先问我）}`

**第一步（只做这三件事，不许动手）：**
1. 读 `@SEEP_ROOT@/Tool/skill/firmware-iot/SKILL.md`（这是本域方法论，必须整篇读）
2. 若目标涉及加壳/加密/虚拟化：再读 `@SEEP_ROOT@/MANUAL/UNPACKING.md` 与 `ANTI-DEBUG.md`
   - 需要时链接子技能：`@SEEP_ROOT@/Tool/skill/_pending/00-triage/SKILL.md`
3. 输出：**判型结论 + 交付上限 M1–M4 + 我缺什么（许可/凭据 · 运行许可与环境 · 样本完整性）**

**硬规则**：
- 用户给的后继目标（补丁/源码级）不改变第一步；第一步永远是判型与上限
- 缺输入就问（问不是退缩），不许假设"没有"就往下走
- 只有跑过命令拿到证据的结论才算结论；没跑过的写"未验证"
- 先 `binwalk`/熵判断容器；Windows 上需 WSL2 或 7z；无法仿真就明说
