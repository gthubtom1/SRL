# 01 判据表——AD / 云原生（ad-cloud）

> 适用：已授权内网 foothold、域账号、kubeconfig、云凭据或 Windows 主机遥测。
> 不适用：纯 Web/API 漏洞（走 `web-pentest`）、二进制逆向（走 `ida-reverse`）、固件（走 `firmware-iot`）。
> 本表只回答“这条路径是否已被证据确认”，不把名称、配置或单条日志当成提权。

## 0. 使用方式

1. 先选行：按**输入面**找到你手里实际有的东西（凭据、票据、kubeconfig、日志、策略 JSON）。
2. 跑**判据（可机检）**列里的检查；能离线跑的先跑，不能离线的明确标 `unknown`。
3. 对照**证据形态**：没有该形态就只能写 `candidate`/`blocked`，不能写 `confirmed`。
4. 报告里同时写**误报风险**与失败判据，避免把“配置存在”写成“攻击成功”。

统一结论词：

| 结论 | 含义 | 允许的下一步 |
| :-- | :-- | :-- |
| `confirmed` | 有可复现的凭据/权限提升/宿主证据，换机照做仍成立 | 归档、写报告、给修复 |
| `candidate` | 路径条件成立，但缺最后一步在线证据 | 补一次只读/低影响验证 |
| `blocked` | 关键条件不成立或预算耗尽 | 换路线，停止重复尝试 |

## 1. 判据主表

| 场景 | 输入面 | 判据（可机检） | 证据形态 | 误报风险 |
| :-- | :-- | :-- | :-- | :-- |
| Kerberoasting | 域账号可请求 TGS；`GetUserSPNs.py` 输出 | TGS etype ∈ {23,17,18}；账号有 SPN、非机器号/krbtgt；hash 可离线校验；`hashcat -m 13100/19700/19800` 命中或票据可直接复用 | TGS 文件指纹（sha256 前 16 位）+ etype + 破解命令与命中行（口令只留指纹） | 只拿到 TGS 未破解=素材；AES 账号用 RC4 字典会假阴性；机器号不是 Kerberoast 目标 |
| AS-REP Roasting | 域账号枚举；`DONT_REQ_PREAUTH` | `userAccountControl` 含 `DONT_REQ_PREAUTH`；`GetNPUsers.py` 返回 AS-REP；hash 破解或可直接预认证；账号未禁用/未锁定 | AS-REP 指纹 + etype + 破解结果；账号状态与锁定策略 | 账号已启用预认证会失败；批量请求触发 4625/4771；禁用账号不能登录 |
| ADCS ESC1/ESC2/ESC3 | `certipy find -vulnerable` 模板 JSON | 当前主体对模板有 `Enroll`；`san_enforced=false` 或 Any Purpose；无需 manager approval；CA 允许 SAN/请求者提供 subject；ESC3 需注册代理模板 | `certipy req` 得到的 pfx 指纹 + `certipy auth` 成功拿到 TGT/ccache | find 报 vulnerable ≠ 可利用；模板需审批/CA 拒绝 SAN；pfx 用途不匹配 |
| ADCS ESC4/ESC5/ESC7 | 模板/PKI 对象 ACL、CA 权限 | 当前主体对模板对象有 WriteDACL/WriteOwner/GenericAll；或对 CA 有 ManageCA/ManageCertificates；改后能重新注册并 `auth` 成功 | ACL 前后对比 + 修改命令 + 新证书/票据 | 有写权限但触发了审计/备份回滚；CA 权限不等于能签发任意模板 |
| ADCS ESC8 / NTLM relay | CA HTTP 端点、SMB/LDAP signing、EPA | HTTP 端点可达；目标未强制 SMB/LDAP signing 或 EPA；`ntlmrelayx --adcs`/`certipy relay` 收到证书；证书可 `auth` | relay 日志中的认证来源 + 颁发的证书指纹 + TGT | 端点存在但 EPA/signing 已开；只能 relay 到 LDAP 不代表能拿证书；强制认证可能触发告警 |
| 委派（Unconstrained） | `TRUSTED_FOR_DELEGATION` 账号 + 可控主机 | 账号/主机开启 unconstrained；攻击者能在这台主机上以管理员运行并导出 TGT；票据可导入并访问目标 | 主机控制证据 + 票据指纹 + 目标服务访问返回 | 只是属性存在、没有可控主机；TGT 过期；目标已禁用委派 |
| 委派（Constrained/RBCD） | `msDS-AllowedToDelegateTo`、`msDS-AllowedToActOnBehalfOfOtherIdentity` | 目标 SPN 在允许列表；协议转换可用；或对目标计算机对象有写权限并成功写 RBCD；`getST` 返回可用服务票据 | S4U2Self/S4U2Proxy 命令 + 服务票据 + 目标资源访问 | SPN 不匹配；目标禁用协议转换；RBCD 写后被清理/未生效 |
| K8s 宽权限 RBAC | kubeconfig / SA token / `kubectl auth can-i --list` | `create pods/daemonsets/jobs`、`get secrets`、`impersonate`、`bind`、`escalate` 中至少一条返回 `yes`；名称与 JWT 组只作线索 | `auth can-i` 原始输出 + 绑定对象 + 实际只读动作返回 | 名称像 cluster-admin 但绑定很窄；有权限被 PSA/Quota/Admission 拒绝；token 过期 |
| K8s 容器逃逸 | Pod securityContext、CapEff、mount、socket | `privileged`/`CAP_SYS_ADMIN`/`hostPath`/`hostPID`/`hostNetwork` 之一可用；创建带标记 Pod 后能读宿主文件或在宿主命名空间执行 `id` | Pod YAML + `id`/宿主文件读取输出 + 清理记录 | 配置存在但 seccomp/PSA 拦住；hostNetwork ≠ 宿主文件系统；只读挂载 |
| 云 AK/SK 泄露 | `~/.aws/credentials`、CI 变量、镜像层 | 本地文件出现 `AKIA`/`ASIA` + secret（硬编码）；`aws sts get-caller-identity` 返回同一身份；策略允许目标动作 | 凭据指纹（AK 后 4 位 + sha256 前 8 位）+ STS 返回 + 策略 JSON | 占位/已撤销 key；环境变量引用不是硬编码；低权账号 |
| 云元数据 SSRF | 应用请求可控 URL；169.254.169.254 | IMDSv2 先 `PUT /latest/api/token` 成功；拿到角色临时凭据；`sts get-caller-identity` 成功 | 请求/响应片段（token 只留指纹）+ STS 返回 | 端点 403/超时；IMDSv1 已禁用；SSRF 只能打内网但取不到凭据 |
| IAM 提权 | IAM 策略 JSON、`list-*` 输出 | 策略文本允许 `iam:CreatePolicyVersion`/`PassRole`/`AttachUserPolicy`/`CreateAccessKey` 等组合；boundary/SCP 不拦；在线动作成功 | 策略语句 + 决策结果 + 实际 API 返回 | 只看 `Action:*` 不看 Resource/Condition；policy 名称猜测；文本 allow ≠ 凭据有效 |
| Windows 认证遥测 | Security.evtx / `wevtutil` XML | 4768/4769=Kerberos，4776=NTLM，4624 LogonType 3/10=网络/RDP，4672=特殊权限，4625/4771=失败；EventRecordID 连续 | 事件计数 + 时间窗 + 账号/来源（脱敏）+ 日志断档说明 | 单机日志不能代表域；审计未开导致假阴性；4672 服务登录是常态 |
| 主机凭据面 | 证书存储、LSA 注册表、`klist` | 证书 EKU 是否含 Client Authentication/Smart Card Logon；是否有私钥；`RunAsPPL`/`NoLmHash`/`EnableLUA` 值；票据缓存数量 | 证书 subject/thumbprint/EKU（不导出私钥）+ 注册表键值 + 票据计数 | 有证书≠能 PKINIT；UAC 关闭是加固缺口不是域提权；服务证书不能当客户端证书 |

## 2. 每条结论的最小证据包

| 结论类型 | 必须有的四件 |
| :-- | :-- |
| 凭据 | 来源路径/命令、获取时间、指纹（不落明文）、一次低噪音验证返回 |
| 票据/证书 | 类型与用途、有效期、指纹、`auth`/`getST` 成功返回、目标资源访问 |
| 权限提升 | 前后 `whoami /all`、`auth can-i`、`sts get-caller-identity` 或组成员对比 |
| 逃逸 | Pod/容器配置、宿主命名空间命令、宿主文件或 `id` 输出、清理记录 |
| 遥测 | 事件 ID 计数、时间窗、来源主机、脱敏声明、日志缺口 |

## 3. 失败判据（看到即降级）

- 只有 hash/票据/证书，没有明文、TGT 或可用会话 → `candidate`，转 `02-failure-criteria.md`。
- `certipy find` 报 vulnerable 但无 `Enroll`、需审批、CA 拒绝 SAN → 不成立，转 ESC4/ESC5/ESC7。
- SMB/LDAP signing 或 EPA 已开 → relay 失败，转凭据直连或非 relay 面。
- `auth can-i` 全 no、PSA/Quota 拒绝、缺 `CAP_SYS_ADMIN` → 停手，转 Secret/CI 凭据。
- `sts get-caller-identity` 报 AccessDenied/ExpiredToken → 凭据无效，记录后换来源。
- 认证失败达到锁定预算（默认同一账号 2 次）→ 立即停，换账号/来源。
- 同一手法同参数连续失败两次 → 换路线；不要靠重复请求“撞”成功。

## 4. 边界

- 只处理授权清单内的域、主机、集群、云账号；清单外不扫、不碰。
- 不把真实口令、hash、AK/SK、token、私钥写进报告或仓库；只写指纹与声明。
- 不做破坏性动作、不默认持久化、不删改日志；持久化需单独授权并登记清理。
- 离线判定必须标 `offline` 与 `unknown`；在线动作只做只读或明确授权的低影响验证。
- Web/API 应用层漏洞、二进制逆向、固件分析不在本表范围，分别转邻域技能。

## 附：上游技能卡索引（24 张）

> 上游 = `mukul975/Anthropic-Cybersecurity-Skills`（818 技能库）。本表只回答一件事：这条上游技能在本域**落到哪张卡、哪篇 reference、判据是什么**。

| 上游技能 | 本域任务卡 | 落点 reference | 一句话判据 |
|---|---|---|---|
| `performing-active-directory-bloodhound-analysis` | BloodHound 采集与图谱复核（源：performing-active-directory-bloodhound-analysis） | `Tool/skill/ad-cloud/references/ad-attacks.md` | 图谱里存在从当前身份到高权目标的连续边，且每条边能在 LDAP 原始属性/ACL 上复现；记录采集时间与 zip 指纹 |
| `exploiting-active-directory-with-bloodhound` | BloodHound 路径落到可利用动作（源：exploiting-active-directory-with-bloodhound） | `Tool/skill/ad-cloud/references/ad-attacks.md` | 边对应的原始属性/ACL 可读且与图谱一致；最小验证返回预期结果；记录前后权限对比 |
| `relaying-ntlm-for-adcs-esc8` | NTLM relay 打 ADCS ESC8（源：relaying-ntlm-for-adcs-esc8） | `Tool/skill/ad-cloud/references/ad-attacks.md` | relay 日志收到认证、CA 颁发了目标模板证书、`certipy auth` 出 TGT/ccache；三步缺一不可 |
| `exploiting-active-directory-certificate-services-esc1` | ADCS ESC1 模板验证（源：exploiting-active-directory-certificate-services-esc1） | `Tool/skill/ad-cloud/references/kerberos-and-adcs.md` | pfx 的 EKU 含 Client Auth/Smart Card Logon，`certipy auth` 返回 T… |
| `coercing-authentication-with-coercer-petitpotam` | 强制认证（PetitPotam/Coercer）前提核查（源：coercing-authentication-with-coercer-petitpotam） | `Tool/skill/ad-cloud/references/ad-attacks.md` | 监听端收到目标机器账号认证（含来源 IP/时间），且未造成业务中断；认证可被 relay 到授权端点 |
| `analyzing-active-directory-acl-abuse` | AD ACL 滥用只读核查（源：analyzing-active-directory-acl-abuse） | `Tool/skill/ad-cloud/references/ad-attacks.md` | 原始 ACL 显示当前主体对目标有目标权限；最小验证成功；前后权限/属性对比可复现 |
| `executing-active-directory-attack-simulation` | 域内攻击模拟的边界与节奏（源：executing-active-directory-attack-simulation） | `Tool/skill/ad-cloud/references/01-criteria.md` | 每个动作都能映射到授权等级；没有越界资产；关键动作有前后证据与清理记录 |
| `detecting-dcsync-attack-in-active-directory` | DCSync 检测与只读复核（源：detecting-dcsync-attack-in-active-directory） | `Tool/skill/ad-cloud/references/05-delegation-and-rbcd.md` | 4662 的对象 GUID 指向域命名上下文、账号具备复制权限、时间线与 4769 对齐；三条同时成立才是强证据 |
| `conducting-domain-persistence-with-dcsync` | 域持久化的授权与清理（源：conducting-domain-persistence-with-dcsync） | `Tool/skill/ad-cloud/references/02-failure-criteria.md` | 持久化动作有授权编号、前后对比、回滚成功证据；没有遗留计划任务/账号/票据 |
| `configuring-active-directory-tiered-model` | 分层模型下的路径降噪（源：configuring-active-directory-tiered-model） | `Tool/skill/ad-cloud/references/ad-attacks.md` | 存在跨层凭据复用或委派路径，且能在原始属性/会话上复现；记录层级与资产 |
| `deploying-active-directory-honeytokens` | 蜜罐/蜜标识别与避免误报（源：deploying-active-directory-honeytokens） | `Tool/skill/ad-cloud/references/03-model-pitfalls.md` | 对象属性与真实业务不符（无登录、无邮箱、名称诱导、单独 OU），且多源一致；标“疑似蜜标”并停止接触 |
| `performing-aws-privilege-escalation-assessment` | AWS 提权评估的身份与策略面（源：performing-aws-privilege-escalation-assessment） | `Tool/skill/ad-cloud/references/cloud-native.md` | 身份有效、策略文本允许目标动作、boundary/SCP 不拦、实际只读 API 成功；写操作需额外授权 |
| `enumerating-cloud-with-cloudfox` | CloudFox 云枚举的只读边界（源：enumerating-cloud-with-cloudfox） | `Tool/skill/ad-cloud/references/cloud-native.md` | 枚举结果能映射到账号/订阅/项目；关键资源有 ARN/ID 与权限来源；没有写操作 |
| `detecting-aws-iam-privilege-escalation` | AWS IAM 提权检测规则（源：detecting-aws-iam-privilege-escalation） | `Tool/skill/ad-cloud/references/cloud-native.md` | 高风险 API 调用者、时间、策略版本、资源四者对齐；变更有实际权限提升证据 |
| `securing-aws-iam-permissions` | 收敛 AWS IAM 权限的验证（源：securing-aws-iam-permissions） | `Tool/skill/ad-cloud/references/02-failure-criteria.md` | 修复后目标业务动作成功、越权动作 deny、回滚路径可用；记录版本与时间 |
| `performing-gcp-penetration-testing-with-gcpbucketbrute` | GCP 存储枚举的授权与判据（源：performing-gcp-penetration-testing-with-gcpbucketbrute） | `Tool/skill/ad-cloud/references/cloud-native.md` | 桶存在且当前身份可 list/read，返回官方 API 响应；记录项目/桶/权限 |
| `managing-cloud-identity-with-okta` | Okta/云身份目录审计（源：managing-cloud-identity-with-okta） | `Tool/skill/ad-cloud/references/cloud-native.md` | 高风险配置能在 API/审计日志复现，且有明确影响（如无 MFA 管理员可登录）；记录对象 ID |
| `auditing-azure-active-directory-configuration` | Azure AD/Entra 配置审计（源：auditing-azure-active-directory-configuration） | `Tool/skill/ad-cloud/references/cloud-native.md` | 高风险配置有对象 ID、API 返回、日志证据；能说明影响与修复 |
| `performing-kubernetes-penetration-testing` | Kubernetes 渗透测试的只读起步（源：performing-kubernetes-penetration-testing） | `Tool/skill/ad-cloud/references/k8s-and-container.md` | context/token 有效、auth can-i 有明确结果、只读枚举成功；记录 API server 与 nam… |
| `auditing-kubernetes-rbac-privilege-escalation` | K8s RBAC 提权审计（源：auditing-kubernetes-rbac-privilege-escalation） | `Tool/skill/ad-cloud/references/k8s-and-container.md` | 绑定 subject 与当前身份匹配、规则确实允许目标 verb/resource、只读验证成功 |
| `escaping-containers-to-host` | 容器逃逸到宿主的证据链（源：escaping-containers-to-host） | `Tool/skill/ad-cloud/references/k8s-and-container.md` | 宿主命名空间 `id` 或宿主文件读取成功，且能复现；Pod/容器配置与命令完整 |
| `detecting-privilege-escalation-in-kubernetes-pods` | K8s Pod 提权检测（源：detecting-privilege-escalation-in-kubernetes-pods） | `Tool/skill/ad-cloud/references/k8s-and-container.md` | 配置允许特权/hostPath/hostPID 且 audit 有对应创建/执行；有实际宿主证据才升级为 confirm… |
| `performing-kubernetes-etcd-security-assessment` | etcd 安全评估的只读边界（源：performing-kubernetes-etcd-security-assessment） | `Tool/skill/ad-cloud/references/k8s-and-container.md` | 未授权访问被拒或授权只读成功；证书/端口/权限有客观返回；不修改任何 key |
| `performing-kubernetes-cis-benchmark-with-kube-bench` | kube-bench CIS 基线复核（源：performing-kubernetes-cis-benchmark-with-kube-bench） | `Tool/skill/ad-cloud/references/k8s-and-container.md` | FAIL 项有配置文件/进程参数证据；能映射到具体风险与修复；不把 FAIL 直接写成提权 |
