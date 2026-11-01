# 保护分析、网站风控与执行止损：资料及实践依据

> 历史来源材料，不是当前实施方案或待办。当前产品范围与状态只取 REQUIREMENTS.md / docs/CURRENT-STATE.md；示例须按当前执行边界和目标验证，不能从旧建议恢复已取消行为。
> 检索/核对：2026-11-01。31 项入口，优先标准、官方工程文档、OWASP 和上游项目。
> “读取”指访问相关页面/段落或上游说明，不声称每个仓库/长篇文档都逐行审计。
> 下列是方法依据，不证明 SEEP 已安装相应工具、真实目标可被绕过或本方案已经执行。

## 1. 原有研究补入的资料

| ID | 入口 | 借用内容 | 适用与证据限制 |
| --- | --- | --- | --- |
| S01 | [Check Point Anti-Debug Encyclopedia 说明](https://research.checkpoint.com/2020/cpr-anti-debug-encyclopedia-the-check-point-anti-debug-techniques-repository/) | 调试器有可观察副作用，检测面不止进程名 | 方法资料，非当前目标实测 |
| S02 | [Check Point Debug Flags](https://evasions.checkpoint.com/src/Anti-Debug/techniques/debug-flags.html) | 本地检测机制的分类线索 | 具体实现依系统/架构；不按 API 名直接下结论 |
| S03 | [OWASP Android Anti-Reversing Defenses](https://mas.owasp.org/MASTG/0x05j-Testing-Resiliency-Against-Reverse-Engineering/) | 反调试、完整性、混淆、绑定与证明应分开 | 本地分析讨论不等于能取得远端权威 |
| S04 | [OWASP Reverse Engineering Tool Detection](https://mas.owasp.org/MASTG-KNOW-0030/) | 工具文件、包、模块等痕迹 | 可见性受权限和平台限制 |
| S05 | [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) | 账号锁定、上下文和认证节流 | 不把示例锁定次数当未知软件安全上限 |
| S06 | [OWASP WSTG Lock Out Mechanism](https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism) | 锁号测试使用能承受被锁的账号 | 只支持测试资产选择原则，不授权测正式卡阈值 |
| S07 | [RFC 9110 HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.2) | 非幂等重试边界，幂等语义与日志副作用不同 | 不能据方法名推出无风控影响 |
| S08 | [RFC 6585 §4](https://www.rfc-editor.org/rfc/rfc6585.html#section-4) | 429 与可选 Retry-After | 无 429 不表示不限流；冷却不等于必须重发 |
| S09 | [AWS Timeouts, retries, backoff and jitter](https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/) | 失败/超时可能已有副作用，限制重试与退避 | 退避是可靠性机制，不是危险操作的许可 |
| S10 | [AWS Control and limit retry calls](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_mitigate_interaction_failure_limit_retries.html) | 有界重试、避免非幂等副作用 | 需覆盖实际调用链，不能只限制外层循环 |
| S11 | [Android Network security configuration](https://developer.android.com/privacy-and-security/security-config) | debug-overrides、信任配置和 pinning | 适用于可控构建，不是任意 APK 开关 |
| S12 | [Play Integrity overview](https://developer.android.com/google/play/integrity/overview) | 应用/设备信号由后端决定响应 | 说明远端判断存在，不泛化所有软件 |
| S13 | [Play Integrity verdicts](https://developer.android.com/google/play/integrity/verdicts) | 请求绑定、设备与环境 verdict 的不同维度 | 功能可用条件/政策随版本变化 |
| S14 | [Windows Sandbox configuration](https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file) | 禁网、共享映射等隔离配置 | 沙箱存在不等于已经正确配置，也不消除绑定风险 |
| S15 | [Microsoft Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon) | 文件、注册表和进程活动的观测能力 | 工具使用也可能改变环境；不是隐形观测 |
| S16 | [Frida Troubleshooting](https://frida.re/docs/troubleshooting/) | attach 故障可能是权限或运行环境 | 系统修改建议不自动适用于用户主机 |
| S17 | [x64dbg/ScyllaHide](https://github.com/x64dbg/ScyllaHide) | 明确用户态工具范围 | 未安装/验证，不保证对内核和远端证明有效 |
| S18 | [mitmproxy Certificates](https://docs.mitmproxy.org/stable/concepts/certificates/) | CA、pinning 和 mTLS 应分别理解 | 不是装 CA 就全流量可解密 |
| S19 | [morluto/rea](https://github.com/morluto/rea) | MCP 连接分析工具并组织证据/限制 | 只参照方法，不全量接入、不把宣传当任务见证 |
| S20 | [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | 模型控制分析工具的接口形式 | 不是自动化保护绕过器 |
| S21 | [Automatically Attacking Software Reverse Engineering AI Agents](https://arxiv.org/abs/2605.30667) | 样本派生内容误导逆向 AI 的威胁模型 | 2026 年预印本；不把实验比例当本项目实测 |
| S22 | [When Binaries Talk Back](https://arxiv.org/abs/2607.12507) | 数据被提升为指令/状态、同源证据假互证 | 2026 年预印本；仅作为测试设计依据 |

## 2. 本轮重点扩展的网站与工程控制资料

| ID | 入口 | 借用内容 | 适用与证据限制 |
| --- | --- | --- | --- |
| S23 | [Burp Tasks settings: Resource pools](https://portswigger.net/burp/documentation/desktop/settings/project/tasks) | 跨任务资源池、并发、请求间隔和响应触发节流 | 该产品项目级设置不代表跨工具/跨宿主全局限制 |
| S24 | [ZAP Modes](https://www.zaproxy.org/docs/desktop/start/features/modes/) | 模式与 scope 联合限制行为 | 不能仅按工具模式推断实际浏览器业务无副作用 |
| S25 | [Cloudflare Supported browsers](https://developers.cloudflare.com/cloudflare-challenges/reference/supported-browsers/) | JS/浏览器环境差异，生产挑战不支持自动化浏览器求解 | 不承诺 Playwright/改 UA 就可通过；与自有自动测试分开 |
| S26 | [Cloudflare Challenge solve issues](https://developers.cloudflare.com/cloudflare-challenges/troubleshooting/challenge-solve-issues/) | 区分 Cookie/DOM storage/WebView 问题，收集 HAR/控制台证据 | 排障页的换网络建议不自动变成规避限制的路线 |
| S27 | [Cloudflare API rate limits](https://developers.cloudflare.com/fundamentals/api/reference/limits/) | 某些限制跨仪表盘、API key、token 累计 | 仅证明共享配额确实存在；不复制其数值给其他服务 |
| S28 | [OWASP Mobile App Tampering and Reverse Engineering](https://mas.owasp.org/MASTG/0x04c-Tampering-and-Reverse-Engineering/) | 静态、动态、脚本化分析的用途和复杂保护的成本 | 不从“本地逆向可行”推出无限工时或服务器可复制 |
| S29 | [Cloudflare Turnstile testing](https://developers.cloudflare.com/turnstile/troubleshooting/testing/) | 自有实现用测试 key，避免真实挑战干扰自动测试 | 仅限可控测试构建/配置，不对第三方生产目标套用 |
| S30 | [RFC 9309 Robots Exclusion Protocol](https://www.rfc-editor.org/rfc/rfc9309.html) | robots 规则不是访问授权 | 也不是费用、配额或无副作用证明 |
| S31 | [GitHub REST API rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) | 多维主/次限流、并发、跨入口累计与重试约束 | 用作服务特定策略范例，不当作所有 API 固定规则 |

## 3. 资料转化为执行能力的要求

每条稳定经验要带输入条件、适用平台/版本、观察证据、输出、失败/停止条件与恢复边界。只找到资料入口，不代表当前宿主具备执行能力。

经验应落在原有域内 references/playbooks 或横切的窄执行 helper；常驻规则只放最短指针。不能再形成一套“另一个知识库存在但 Agent 不读取”的孤立文档。

不直接导入网上的全部绕过脚本、隐藏驱动或任意二进制。需要工具时走已有发现/获取/验证链路，按真实依赖和 schema 检查，再在合成目标上验收。

本清单没有把论坛经验、社区成功截图或营销标题当作任何真实付费软件已经可以自动绕过的证据。未知厂商的阈值仍然未知。
