# Kerberos / ADCS 技术条件与安全核验

入口：[SKILL](../SKILL.md)。输入为用户侧安全目录/CA/KDC/服务配置、公有证书元数据、版本/补丁信息与已有事件；真实认证由用户侧完成，仅返回非秘密结果。此页没有凭据破解、发证/票据导出、强制认证或系统改动步骤。

## Kerberos

服务账号风险需核 SPN、账号类型/状态、实际允许的加密类型与密码管理策略；预认证风险需核 DONT_REQ_PREAUTH 及实际 KDC/账号策略。属性可确认，口令强度/可恢复性通常仍未知，不取得 TGS/AS-REP 或更换字典验证。

TGS/AS-REP 的加密响应与可用于 PtH 的 NT hash 不是同一种材料；不能声称请求响应后直接 PtH。机器账号、krbtgt 与用户服务账号的密钥管理/用途不同，不能把一个账号名规则当所有风险的排除条件。

用户侧认证失败时记录错误类别、源/目标别名与时间。KRB_AP_ERR_SKEW 提示时间条件，但容忍范围以实际策略为准，不能一律定 5 分钟；只读比较时间源/误差，不修改时钟或重取/导出票据。锁定或同形失败两次即停，不换身份规避。

委派三种机制、S4U、目标 SPN、用户不可委派/Protected Users 与补丁差异见 [05-delegation-and-rbcd](05-delegation-and-rbcd.md)。不通过抓 TGT、写 RBCD、改 UPN/SPN 或远程执行来补证据。

## ADCS 必须分层

模板是否发布到目标 CA、有效 Enroll/ACL、EKU/应用策略、subject/SAN 控制、manager approval、authorized signatures、CA 配置与权限、目标认证服务、证书映射/强绑定及补丁必须共同核验。public cert 的 EKU/SAN/链/有效期可用，私钥、PFX、TGT、hash 不进入 Agent。

| 风险机制/常见标签 | 需核事实 | 不可从单项推出 |
|---|---|---|
| 主体/SAN 与认证用途（ESC1/2） | 可注册主体、模板/CA subject 策略、可用认证 EKU/应用策略、审批/签名要求、实际证书映射 | 能提供 SAN/Any Purpose/无 EKU 不等于任意用户能认证 |
| Enrollment Agent（ESC3） | 注册代理用途、代理限制、目标模板授权/签名要求、目标主体和认证策略 | 有代理模板不等于任意代签 |
| 模板/PKI 对象/CA 权限（ESC4/5/7） | 精确对象的有效 ACL 或 CA 管理权限、可影响的配置与签发流程 | ManageCA/ManageCertificates 或 WriteDACL 不等于已签任意证书；不改配置验证 |
| CA SAN 标志（ESC6） | CA 标志、模板条件、SID 安全扩展和当前映射/强绑定/补丁 | 该标志单独不证明现代已修补环境可冒用 |
| HTTP 注册 relay（ESC8） | 注册端点/NTLM、EPA/认证强制条件及网络边界 | HTTP 可达或 SMB signing 关闭不等于该 HTTP 端点可利用；不触发 relay |
| SID 安全扩展缺失（ESC9/16） | ESC9 关注模板安全扩展抑制，ESC16 关注 CA 级扩展禁用；核 SID 扩展 OID 1.3.6.1.4.1.311.25.2 与 KDC/服务实际映射/补丁 | ESC9 不能定义为某 KDC 注册表值等于 0；缺 SID 扩展不等于强绑定失效，更不使模板 ACL 自动失效 |
| 弱证书映射（ESC10/14） | 实际 KDC/Schannel 路径、映射配置/类型、目标属性有效权限、对应补丁 | 不混淆 Schannel 与 PKINIT；老注册表值在新版/强制阶段未必仍控制行为 |
| RPC 注册保护（ESC11） | 对应 RPC 注册接口是否要求请求加密、认证/网络条件 | HTTP EPA、LDAP signing 和 RPC 加密是不同控制；不以一项代替所有端点 |
| CA 主机/签名密钥保护 | 管理/备份权限、HSM/密钥提供程序配置及既有审计，具体研究标签按来源版本核实 | 有管理权限不证明私钥可导出；不备份/导出 key，不停起 CertSvc |
| 颁发策略与组（ESC13） | Issuance Policy OID、目录组链接/类型、模板/注册权限及支持的认证机制 | OID/组链接不证明用户实际获组权限；只核公有配置与用户侧结果 |
| Application Policies（ESC15 / CVE-2024-49019） | 受影响版本/补丁、模板 schema、注册/审批与请求扩展处理 | schema v1 单独不证明漏洞；不申请攻击证书补证据 |

标签和工具输出随来源/版本变化，scanner 的 esc_flags/verdict 是有限规则。不能从输出一个编号宣布全条件成立，不能改字段迎合旧 ad-repro 的 confirmed。

## 新标签与历史 WSUS 描述

旧资料中的“ESC17 / HTTPS WSUS 中继”缺少足以作为本地规范的已核来源与版本边界，保留为历史候选，不沿用其标签、命令或能力声明。WSUS/更新链若属于当前问题，只分析公有 TLS/企业 CA 信任、内容签名/发布权限、更新来源配置及已有客户端/服务端日志；TLS 证书受信不证明任意更新内容能被安装。

不导出/申请私钥材料、不 ARP/DNS 劫持、不改代理/网络/更新策略、不投递或触发安装。缺版本、签名链或端到端安全证据就保持 unknown，不要求重现“恶意更新落地”。

## 用户侧结果与验收

用户侧预先准备的合成身份/端点可返回：主体别名、模板/公有证书身份、目标服务、时间、正常/错误条件、非秘密 canary、认证与授权结果及关联审计。证书认证成功与业务资源授权分开；不要求把真实 PFX/TGT 交给 Agent。

正例：安全配置证明模板要求审批，可确认该条件，并保留其他路径未知。反例：find 标 vulnerable、证书有 Client Auth 或 KDC 单个值宽松，就写“已拿域管”，均不成立。拒绝结果也只覆盖具体身份/端点/时刻。

历史原件 `Tool/skill/_pending/ad-cloud/references/kerberos-and-adcs.md` 保留旧命令与来源描述，仅供溯源。当前活跃步骤是上述配置/遥测/用户侧结果核验；失败见 [02-failure-criteria](02-failure-criteria.md)，全部证据回原 project/version/run。
