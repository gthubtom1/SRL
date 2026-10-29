# 身份权限分析常见误判

入口：[SKILL](../SKILL.md)。逐项修正判断与证据，不能用“补一次攻击”解决证据缺失。

| 错误推断 | 正确核对 | 正反边界 |
|---|---|---|
| cluster-admin 名称或 JWT claims 就是有效权限 | 用户侧认证身份别名、subject/组与实际绑定/决策 | 不读取真实 JWT；能解码不代表验签/授权有效 |
| can-i=yes 说明动作完成 | 精确 verb/resource/subresource/namespace、resourceNames，再对照用户侧预先准备的非秘密 canary | 授权检查不执行动作；admission/Quota/运行时是后续条件 |
| get secrets 权限需读真实 Secret 验证 | 核 RBAC 与用户侧合成标记/安全授权结果 | 不取 SA Token、registry 凭据，不接收真实值或其 hash |
| TGS/AS-REP 加密响应可直接 PtH | 这是不同类型的材料；只评估账号配置、加密策略与既有遥测 | 不采集/破解/复用，不从 SPN 推出口令已恢复 |
| 机器号或 krbtgt 永远不能出现在风险分析中 | 按真实账号类型、凭据管理、权限与协议条件分析 | 不把账号名当绝对排除条件，也不因此请求秘密 |
| certipy 的 vulnerable/ESC 标签证明已利用 | 核工具版本、模板发布/Enroll、EKU、审批、CA/KDC/服务策略、补丁 | 配置 confirmed 与用户侧认证观察分别写；不要求 PFX/TGT/私钥 |
| 所有委派都要求同一个协议转换标志 | 区分 unconstrained、传统 constrained、RBCD 与用户限制/补丁 | 不把 RBCD 套成传统 KCD；属性可读不等于可写或可冒用 |
| 有 privileged/CAP/hostPath 就已逃逸 | 核挂载来源、namespace、userns、PSA/seccomp/LSM、runtime 与已有节点审计 | 不通过 mount/nsenter、改 runtime 或读宿主秘密补证据 |
| 云身份 ARN 变化就是提权 | 身份与有效权限分开，核 trust、policy、boundary/SCP/条件和用户侧测试决策 | ARN/策略名称不表达实际授权；不 AssumeRole 获取临时凭据 |
| 另一 allow 可以覆盖显式 deny | 对适用策略中的显式 deny 保持优先，核全部相关层 | 有限离线模型不等于云端决策，条件未知不能猜真 |
| S3 list/head 成功说明 GetObject 内容可读 | 分 action/resource 与条件；canary 读取结果只覆盖那个对象 | 不下载 tfstate、备份或配置寻找下一跳凭据 |
| metadata HTTP 200 说明云凭据可用 | 记录端点/配置/安全测试服务的可达性，真实身份与权限另由用户侧核验 | 不请求 metadata Token/临时 key，不导出响应后脱敏 |
| 4624/4672 或 Pwn3d!/SUCCEED 就是横向成功 | 结合执行者、源目标、LogonId、时间、会话/进程与独立审计 | 正常管理也会产生这些事件，认证不等于执行，执行不等于恶意 |
| 无 4768/4769 或 RecordId 不连续说明没发生/已删日志 | 核主机角色、channel、采集过滤、滚动/转发与审计覆盖 | 原始 channel 的缺口也需解释；筛选结果不应要求 ID 连续 |
| hash/票据前缀与指纹足够安全 | 真实秘密从不进入 Agent，不先读后散列 | 安全证据文件的完整性 hash 与秘密指纹是两回事 |
| 只读工具必然无系统副作用 | 核认证预算、自动读取凭据、远程服务/插件行为和输出 | 工具无法安全限制输入/字段时不用该通道 |
| 预算按工具算，换账号就能继续 | 账号/资产/时间窗统一约束，同形失败两次重判 | 不通过换工具、来源或身份绕锁定/速率限制 |
| 回滚步骤能授权建服务/任务或改系统 | 这些动作不属于本技能执行范围 | 不做持久化、删日志、DoS、系统网络/时钟/驱动改动，也不为清理再提供反向命令 |
| 脚本 verdict=confirmed/退出 0 就完成 | 核输入来源、脚本实际覆盖、原输出与独立证据 | 合成夹具/用户声明不升级成真实攻击见证；missing/unknown 保留 |

正例：两组安全 canary 测试分别允许/拒绝，与对应策略版本一致，可确认该测试授权行为。反例：只把历史脚本的 cracked=true 填入 JSON，不能证明破解发生，更不能补写真实命令。

历史清单保留于 `Tool/skill/_pending/ad-cloud/references/03-model-pitfalls.md`，只供来源/旧判断追溯；活跃判据见 [01-criteria](01-criteria.md)，停止与恢复见 [02-failure-criteria](02-failure-criteria.md)。
