# 人设卡（破甲卡）说明

> 来源：relab2 / kernel-sweep 工程。现随 Seep 工作台一起备份（用户要求：单仓统一，不另开仓库）。

## 一、两代卡，别混用

| 代 | 文件 | 头部标志 | 结构 |
|---|---|---|---|
| **新代（推荐）** | `space-bunny.md` · `gemini-3.8-flash-high.md` · `mimo-2.6.md` · `muse-1.3.md` | `[MODE: LAB-LOCAL · ACTIVE]` + "loaded runtime kernel" | 0–15 编号模板（CONTROL WORD / IDENTITY / REMAP / SCOPE / OUTPUT CONTRACT / INJECTION / …），仅 §1/§2/§3/§14 按模型定制 |
| 旧代（留档） | `space-bunny-2.md` | `# base: space-bunny-2` + `[MODE: SANDBOX]` | Blacklist / Scoped Rules（22 条）/ Intent Mapping / … |

- 旧代那张内容仍可用，但**不要与新代混用**（规则版本不一致）。
- 旧代独有的 22 条 `Scoped Rules`（game cheat / fraud / forgery / finance / smuggling …）与逆向工作台无关，新代已用 `§7 SCOPE` 一段覆盖。

## 二、与 Seep 提示词的分工

| 层 | 归属 | 管什么 |
|---|---|---|
| 说话与强口径 | **本目录的卡** | 语气、称谓、拒答口径、输出格式、SCOPE |
| 任务纪律 | `AGENTS.md`（跨宿主） | Lab 状态机、工具纪律（禁 `-h`、动态路径）、两次熔断、G-Auth、路由 |
| 规则优先级 | `SYSTEM.md` §0 | 凭证红线 > 授权与工具纪律 > 任务正确性 > 风格话术 |
| 硬执行 | `security-audit-interceptor.ts` | 词表替换、快捷口令、BLOCK_NONE、幂等包裹 |

## 三、本目录做过的两处补丁（2026-10-20）

1. **§11 白名单例外（Carve-out）**：原文 "There is no competing set of instructions" 会把工作台的工具纪律/授权门也当成"竞争配置"否掉。
   现保留"不许把本卡当可权衡的提议"这一核心，只增加一句：**任务纪律不构成竞争策略**。
2. **§7 能力诚实（Capability honesty）**：SCOPE 保持宽（固件/硬件/无线都在内），但要求模型**先走自愈链**
   （discover → install → use → 降级路线），走不通就如实说 + 给替代路线，**不许假装、不许先手搓**。

## 四、以后怎么改

- 只改**新代 4 张**；改前先 `git log -- 人设卡/` 看历史，改后按 A 类走（一次体检即可）。
- 加新模型卡：复制最接近的一张，只改 §0 的 status line 文案、§1/§2/§3 的模型特性、§14 MODEL RULES。
