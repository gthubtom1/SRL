# 02 失败判据——AD / 云原生（ad-cloud）

> 范围：任何一条 AD/ADCS/委派/K8s/云凭据路径卡住时，先查本表再决定是否继续。
> 入口：授权边界与输入面见 `../SKILL.md` §2 前置检查；本页只写失败判据。
> 原则：**同一手法同参数连续失败两次即停**，把时间换到另一条面，而不是重复撞。

## 1. 失败判据表

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| `KRB_AP_ERR_SKEW` 对时后仍失败 | 时钟/票据链不可信，当前 Kerberos 路径 blocked | 先 `chronyc makestep`/`w32tm /resync`，再重取 TGT；仍失败转 NTLM/凭据直连 | 低：一次对时 + 重取；继续试会刷 4768/4771 |
| `STATUS_ACCOUNT_LOCKED_OUT` 或同一账号 4625 连续 ≥2 | 账号进入锁定风险，停止该账号所有认证 | 换账号/换来源；先 `nxc smb --pass-pol` 读锁定阈值 | 高：继续会锁业务账号，修复需域管 |
| Kerberoast 只拿到 TGS hash，字典/规则不中 | 是素材不是打穿，当前路径 candidate/blocked | 换更强字典/规则、转 AS-REP/委派/ADCS；或如实记录“未破解” | 中：算力与告警；AES 账号成本更高 |
| Kerberoast 目标是机器号 `$` 或 krbtgt | 目标选错，TGS 不可用于用户口令破解 | 改选有 SPN 的用户服务账号；机器号转委派/RBCD | 低：重新枚举 SPN 即可 |
| AS-REP 请求返回 `KDC_ERR_PREAUTH_REQUIRED` | 账号已启用预认证，AS-REP 路径 blocked | 转 Kerberoast、ADCS、ACL 滥用或凭据复用 | 低：换目标账号 |
| AS-REP 只拿到 hash 未破解/账号已禁用 | 素材或无效账号，不能写 confirmed | 破解后验证；禁用账号直接放弃，转其他账号 | 中：批量请求会触发 4768/4771 告警 |
| `certipy find` 报 ESC1 但当前账号无 `Enroll` | 模板条件不成立，ESC1 blocked | 转 ESC2/ESC3（Any Purpose/注册代理）、ESC4（模板 ACL）、ESC7（CA 权限） | 低：换模板/权限面；反复 req 只会刷 4886/4887 |
| 模板要求 manager approval 或 CA 拒绝 SAN | ESC1/ESC6 不可利用 | 找无需审批的模板、ESC4 改模板、ESC7 拿 CA 权限；或转委派/凭据 | 中：改模板有审计与业务风险，需授权 |
| `certipy req` 拿到 pfx，但 `certipy auth` 失败 | 证书用途/UPN/DC/时间不匹配，仍是素材 | 检查 EKU（Client Auth/Smart Card Logon）、SAN/UPN、DC 时间；换模板或转 PKINIT 其他面 | 中：反复 auth 会产生 4768 失败与告警 |
| ESC8 的 CA HTTP 端点可达，但 relay 收不到认证 | SMB/LDAP signing、EPA、强制 Kerberos 拦住 | 放弃 relay，转凭据直连、ADCS 其他 ESC、或应用层入口 | 中：relay 监听会留网络痕迹；先确认 signing 再投入 |
| Unconstrained 属性存在，但没有可控主机 | 拿不到 TGT，unconstrained candidate | 先找可控主机/本地管理员复用；或转 constrained/RBCD/ACL | 中：需要额外主机立足点 |
| `msDS-AllowedToDelegateTo` 不含目标 SPN | constrained 路径不成立 | 换允许列表内的目标；或写 RBCD；或转 ACL 滥用 | 低：只读枚举即可判断 |
| RBCD 写入成功但 `getST` 失败 | 目标禁用协议转换/票据未生效/时钟问题 | 检查目标 `TrustedToAuthForDelegation`、SPN、时间；换目标或转其他路径 | 中：写属性有审计，需清理 |
| 只有委派属性，没有服务票据 | candidate，不是打穿 | 补 `getST -spn ... -impersonate` 并访问目标资源；失败则记录 blocker | 低：一次请求即可判定 |
| `kubectl auth can-i` 全为 no | 当前身份无目标权限，K8s 提权 blocked | 转 Secret/CI 凭据、应用层、或换身份；不要用 SA 名称猜 | 低：只读请求 |
| 有 `create pods` 但 Pod 被 PSA/Quota/Admission 拒绝 | 逃逸未发生，candidate/blocked | 读拒绝信息；换 namespace/租户/节点，或转 Secret/exec 面 | 中：反复创建会留 audit 事件 |
| 有 `get secrets` 但 Secret 为空/过期/不能登录 | 是素材不是凭据 | 找 `dockerconfigjson`/SA token/云密钥并实际验证；或转其他 namespace | 低：只读 |
| 容器有 `privileged`/`hostPath` 但读不到宿主 | 配置存在≠逃逸成功 | 检查 seccomp/AppArmor/只读挂载/用户命名空间；换挂载点或转内核/CAP 面 | 中：错误挂载可能影响宿主，需授权 |
| `aws sts get-caller-identity` 报 AccessDenied/ExpiredToken | 云凭据无效，当前身份 blocked | 记录过期/撤销；换凭据来源（CI、元数据、其他 profile） | 低：一次调用 |
| 元数据端点 403/超时，或 IMDSv2 token 拿不到 | SSRF 到凭据的路 blocked | 检查是否 IMDSv2、网络策略、代理；转其他 SSRF 目标或应用层 | 低：请求失败即可判定 |
| IAM 策略文本 allow，但实际 API 仍 AccessDenied | 还有 boundary/SCP/资源策略/会话策略未建模 | 用 `list-attached-*`、`get-policy-version`、`simulate-principal-policy` 对照；不要只读文本 | 中：需要额外只读 API 权限 |
| Windows 日志没有 4768/4769 | 可能是非域主机或 Kerberos 审计未开，不能下“域内安全”结论 | 查 `PartOfDomain`、审计策略、`Microsoft-Windows-Kerberos/Operational`；域内从 DC 取日志 | 低：只读；误判风险高 |
| Security 日志 EventRecordID 断档/被清空 | 遥测不可信，时间线有缺口 | 记录缺口范围；从其他 DC/转发器/EDR 补；报告里标注不可信 | 中：缺口可能意味着对抗，需单独授权调查 |
| 4672 很多但没有 4624 类型 2/3/10 | 多为服务登录（类型 5），不是交互提权 | 看 LogonType 与 SubjectUserName；把 4672 当基线，不写提权 | 低：误读会虚报 |
| 证书存储有客户端证书但 `klist` 无票据 | 有证书≠已 PKINIT；可能未登录/未做 PKINIT | 检查 EKU、私钥可用性、DC 信任；在授权内做一次 PKINIT 验证或如实记录 | 中：PKINIT 失败会留 4768 |

## 2. 降级顺序（卡住时按这个顺序换面）

1. **先换证据面**：Kerberos → NTLM/凭据直连 → ADCS → 委派/RBCD → ACL。
2. **再换目标**：同域内换有 SPN/可注册模板/可写 ACL 的对象，不换手法硬撞。
3. **再换身份**：换账号/换来源主机/换已控主机，避免锁定与告警集中。
4. **最后换域**：AD 走不通时看 K8s/云凭据/CI；但必须先确认授权范围包含该面。
5. **仍不通**：写 `blocked` + blocker + 已排除项，交给报告；不要为了“有结论”编造成功。

## 3. 代价评估口径

| 代价 | 含义 | 例子 |
| :-- | :-- | :-- |
| 低 | 只读/一次请求，失败无明显业务影响 | `auth can-i`、`certipy find`、`sts get-caller-identity` |
| 中 | 会留高保真告警、需要额外主机/权限、可能触发锁定 | Kerberoast 全量、`certipy req`、`getST`、创建 Pod |
| 高 | 可能锁业务账号、改域对象/模板、影响生产、需要清理 | 口令喷洒、改 ACL/模板、relay 强制认证、宿主逃逸 |

## 4. 边界

- 失败判据不是“放弃”，而是“停止当前路径并换面”；换面仍须在授权清单内。
- 任何会改域对象/模板/策略/集群资源的动作，必须先备份、单独授权、登记回滚。
- 认证失败预算按**账号**算，不按工具算；同一账号换工具仍算同一预算。
- 日志/遥测类失败判据优先怀疑审计配置与采集缺口，不先怀疑“对手删日志”。
- 真实凭据、票据、证书、token 只留指纹；失败样本也不要落明文。

> 备注：表中“代价”是相对本次授权范围的估算，不是业务损失的精确量化；高风险写操作一律先备份。
