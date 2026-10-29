# AD / 云身份权限判据

入口：[SKILL](../SKILL.md)。输入是用户侧筛选的非秘密配置、元数据、审计与合成测试结果；不以凭据/票据/私钥/Token 的取得、指纹或可复用性作为验收要求。

## 结论分层

| 结论对象 | confirmed 的含义 | 不能外推 |
|---|---|---|
| 配置事实 | 来源、版本、对象和时点明确，字段/有效权限可复查 | 配置存在不等于可利用/动作执行 |
| 风险候选 | 用 candidate，列完整前提、支持/反证和缺件 | 不把单个属性/ESC 标签升级为攻击见证 |
| 遥测事件 | 事件字段与同一主体/源目标/时间窗对应，独立记录支持具体动作 | 单条事件不能证明提权、因果或恶意 |
| 用户侧 canary | 指定身份别名、资源、动作、策略版本和非秘密标记的预期/实际一致 | 仅覆盖测试环境/路径，不证明真实 Secret 可读或任意身份可冒用 |
| 验证受阻 | blocked + 原因/恢复条件；风险未知另列 | 不把验证受阻写成“安全”，不改系统或收取秘密补证据 |

## 逐项核验

| 场景 | 必要配置/上下文 | 可交付证据与限制 |
|---|---|---|
| Kerberos 服务账号 | SPN、实际账号类型/启用状态、预认证与加密策略、采集时点 | 确认暴露条件及对应 KDC 遥测；不请求/导出可破解响应，不要求破解成功。加密 TGS 响应不是 NT hash |
| ADCS 模板 | 有效 Enroll、发布到哪个 CA、EKU/应用策略、subject/SAN、审批与 authorized signatures | 分模板/CA/KDC/服务/版本分析，缺任一关键前提保留 candidate；不要求 PFX/TGT |
| ADCS 权限 | 模板/PKI 对象 ACL、CA 管理权限、继承/deny 与主体成员关系 | 确认可写配置风险，不能以“写入后认证”作必选验证，不修改对象 |
| ADCS relay 风险 | 对应注册端点、协议认证、EPA/通道绑定或 RPC 加密要求 | 分协议判断，SMB signing 不自动决定 HTTP/LDAPS 安全；不触发强制认证/中继 |
| 委派/RBCD | 主体、目标 SPN、委派属性、安全描述符和用户身份限制 | 属性与有效权限互证；S4U/服务访问结果若已有则仅取用户侧安全摘要，不导出票据 |
| K8s RBAC | subject/组、Role/ClusterRole、绑定、namespace、resourceNames/subresource | 精确授权决策；can-i 是权限检查，真实动作/admission/运行时条件另核 |
| 容器隔离 | securityContext、capability、挂载来源、namespace、PSA/seccomp/LSM、runtime 版本 | 确认配置风险；hostNetwork/privileged 单项不证明宿主访问，不执行逃逸 |
| 云 IAM | 身份别名、完整相关策略/trust/条件、boundary/SCP/资源/会话策略 | 文本模型与用户侧非秘密决策分开；显式 deny 不能被另一 allow 覆盖 |
| 元数据/CI | workload identity、挂载/访问策略、触发来源、Secret 引用与数据流 | 配置或合成端点/标记证明暴露路径，不读取 metadata Token、SecretValue、CI 环境秘密 |
| Windows 认证 | 事件来源/审计配置、时间窗、主体别名、LogonId、源/目标、独立会话/进程记录 | 4624/4672 只说明相应事件；日志缺口、PID/LogonId 复用与时间误差必须解释 |
| 公网信息面 | 资产归属、公开 metadata/安全协商字段与版本 | 可确认该信息可见；不据此判已攻破，也不扩展用户名/口令枚举 |

ESC 编号是工具/研究命名，需核真实来源、工具版本和适用机制。尤其旧表将 ESC9 简化为 KDC 一个注册表值，或把 ESC17/WSUS 的历史描述当通用已验证能力，均不可沿用；见 [Kerberos/ADCS](kerberos-and-adcs.md)。

## 最小安全证据包

资产与策略身份、来源/执行者、采集时点、检查范围、非秘密原输出/事件关联标识、支持/反证、结论类别及未知。安全文件可计算 SHA256；不得为生成“指纹”先读取真实秘密。用户侧自述标明为用户侧观察，缺原始安全记录时保留证据强度限制。

正例：指定 namespace 的合成 ConfigMap canary 允许读取，另一测试角色被拒，可确认该测试读取策略。反例：can-i get secrets=yes 或图谱出现高权节点，不能写“已读取秘密/已提权”。

历史判据与上游技能卡索引保留在 `Tool/skill/_pending/ad-cloud/references/01-criteria.md`，只供追溯，不作为当前执行或成熟度声明。[失败处理](02-failure-criteria.md) 负责缺条件时的停手与恢复。
