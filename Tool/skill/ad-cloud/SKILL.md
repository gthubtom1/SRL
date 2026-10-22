---
name: ad-cloud
description: 【内网/AD/云原生】用于授权范围内的内网渗透、Active Directory 攻击链与云原生环境评估。覆盖域内枚举与 BloodHound、Kerberoasting / AS-REP、ADCS ESC1-17（含 ESC9/10 弱绑定、ESC11 ICPR relay、ESC13/14 映射、ESC15 旧 schema、ESC16 CA 全局扩展限制、ESC17 HTTPS WSUS 中继）、NTLM relay、委派/RBCD、PtH/WMI/WinRM/SMB 横向，以及 AK-SK 泄露、元数据 SSRF、K8s RBAC 与容器逃逸、CI/CD 凭据、Windows 认证遥测。判据是拿到可复现的凭据或权限提升证据；Web 漏洞由 R20 承担。
---

# 内网 / AD / 云原生作业规范

本 skill 只处理**已授权**的内网与云环境评估。目标不是“讲全攻击”，而是每条路径都能回答：
**判据是什么、失败长什么样、证据怎么留**。命令细节见 `references/`，判定复算见
`scripts/ad-repro.py` 与 `scripts/cloud-iam-eval.py`。

## 1. 范围与路由

### 本域输入面

- 已有内网 foothold（shell / 跳板机 / 低权域账号），要判断能走多远。
- 域内枚举、BloodHound、Kerberoast/AS-REP、ACL 滥用、委派/RBCD、ADCS、relay、横向。
- 已有 kubeconfig/SA token/容器执行权限，要判断 RBAC、Secret、逃逸面。
- 已有 AK/SK、CI 变量、元数据响应，要判断云身份与权限面。
- 已有 Windows Security 日志/证书存储/注册表，要做 AD 遥测与主机基线复核。
- 公网/DMZ 只出现 445/389/88，需要只读判定暴露面（NTLM type 2、LDAP rootDSE、Kerberos 用户名枚举），不爆破/不写/不投毒。
- 外部接入面只有登录页：SSL VPN（ASA/FortiGate/NetScaler/GlobalProtect/Pulse）、邮件前端（OWA/Zimbra）、身份云（Okta/Entra）——只读指纹与公开 metadata，不提交凭据。
- 容器内只有 shell：需要判定逃逸原语（privileged/hostPath/socket/cgroup release_agent/runc）与集群控制面（kubelet 10250、etcd 2379、admission）能不能走。
- 需要输出“当前权限 → 目标权限”的可复现路径、证据与失败判据。

### 相邻域与路由

- 纯 Web/API 漏洞（SQLi/XSS/SSRF 打应用层、反序列化、文件上传、越权接口）→ **R20 / web-pentest**。
- 纯二进制逆向/脱壳 → `ida-reverse`、`unpack-loop`；固件/IoT → `firmware-iot`。
- 供应链投毒、钓鱼、免杀投递 → 不在本 skill 默认范围；供应链走 `supply-chain-security`。
- 目标清单与动作等级由 `scope` 声明；生产 DoS、删改日志、持久化按单独授权单执行。

## 2. 前置检查（3 件）

1. **授权边界**：资产清单（网段/域名/云账号/集群/主机）、允许的动作等级、时间窗、禁做项。
   扫描范围严格等于清单；持久化/写域对象/IAM 按单独授权单执行并登记回滚。
2. **基本盘**：域名/NetBIOS、DC/CA、DNS、当前账号与权限、已控主机、时间同步；
   K8s 的 context/cluster/user/token 有效期；云的身份/账号/订阅。
3. **凭据与预算**：凭据来源、锁定阈值（`--pass-pol`）、认证失败预算（同账号 ≤2 次即停）、
   证据目录与脱敏规则（口令/hash/票据/私钥/AK-SK/token 只留指纹）。

```bash
# 只读基本盘示例（按环境替换占位符）
nxc smb <DC_IP> --pass-pol -u '' -p ''
nxc smb <DC_IP> -u <user> -p '<pass>' -d <domain>
python Tool/scripts/adcloud-check.py --kubeconfig ~/.kube/config --json
aws sts get-caller-identity
```

## 3. 判据表（本域 10 类）

> 完整表（含输入面/证据形态/误报风险）见 `references/01-criteria.md`。
> 结论词：`confirmed`（可复现证据）/ `candidate`（条件成立但缺最后一步）/ `blocked`（不成立或预算耗尽）。

| 类别 | 确认（confirmed） | 疑似（candidate） |
| :-- | :-- | :-- |
| Kerberos roast | TGS/AS-REP hash 破解出明文，或票据可直接复用；账号非机器号/krbtgt；有命令与指纹 | 有 TGS/AS-REP 但未破解；etype/账号状态未核对 |
| ADCS | `certipy req` 得 pfx + `certipy auth` 出 TGT/ccache；ESC 条件逐条成立 | `find` 报 vulnerable/有 pfx，但无 Enroll、需审批、auth 未成功 |
| 委派/RBCD | `getST` 返回服务票据且能访问目标；RBCD 写入成功并回读；有清理 | 只有 `TRUSTED_FOR_DELEGATION`/`AllowedToDelegateTo` 属性；无控主机/无票据 |
| K8s RBAC/逃逸 | `auth can-i` yes + 实际只读动作成功；宿主 `id`/宿主文件读取；Secret 实际可用 | 有 create pods/get secrets 但被 PSA/Quota 拒绝，或 Secret 未验证 |
| 云凭据/IAM | `sts get-caller-identity` 成功；策略文本 + boundary/SCP 不拦 + 实际 API 成功；元数据取到临时凭据并验证 | 本地有 AK/SK 明文；策略文本 allow；元数据端点可达但未取到凭据 |
| 遥测/主机基线 | 事件 ID + LogonType + 账号/来源 + 时间线一致；证书 EKU/私钥/票据计数可复现 | 单条 4672/4624；单机无 4768/4769；有证书但未 PKINIT |
| 横向移动 | 目标侧有预期身份的 4688/7045/4698 或命令输出，源/目标/时间可复算；relay 需目标侧 4624 类型 3 + 4776 | 只有攻击端 SUCCEED/ReturnValue=0；目标拒绝/签名强制；无目标日志 |
| 公网外部视角 | 只读 negotiate/bind/AS-REQ 的原始返回：NTLM type 2 可解析、LDAP rootDSE resultCode=0、KDC 错误码可分类；不爆破/不写/不投毒 | 445 开放但无 type 2；匿名被拒；88 只回 PREAUTH_REQUIRED；把暴露面写成已打穿 |
| 容器逃逸原语 | 容器内原语机检为真 + 宿主侧独立证据（节点 hostname/节点文件哈希/auditd）+ 复现与清理齐全 | 有 privileged/hostPath/socket 配置，但缺 CAP/只读挂载/PSA 拦，或读到的仍是容器文件系统 |
| 外部接入面/身份云 | 指纹命中 + 公开端点返回可解析字段（metadata/well-known/版本串）；全程无凭据提交 | 只有登录页无厂商串；metadata 要登录；租户不匹配；把暴露面写成已攻破 |

### 3.1 每条结论的最小证据包

| 结论类型 | 必须四件 |
| :-- | :-- |
| 凭据 | 来源路径/命令、获取时间、指纹（不落明文）、一次低噪音验证返回 |
| 票据/证书 | 类型/用途、有效期、指纹、`auth`/`getST` 成功返回、目标资源访问 |
| 权限提升 | 前后 `whoami /all`、`auth can-i`、`sts get-caller-identity` 或组成员对比 |
| 逃逸 | Pod/容器配置、宿主命名空间命令、宿主文件或 `id` 输出、清理记录 |
| 遥测 | EventID 计数、时间窗、来源主机、脱敏声明、EventRecordID 连续性 |

## 4. 失败判据（看到即降级）

完整表（现象 / 判定 / 改走哪条 / 代价）见 `references/02-failure-criteria.md`。高频项：

- 认证侧：`KRB_AP_ERR_SKEW` 对时后仍失败、`STATUS_ACCOUNT_LOCKED_OUT`、同账号 4625 ≥2
  → 停，换账号/来源；不要撞锁定阈值。
- Roast：只拿到 TGS/AS-REP hash 未破解、AES 账号用 RC4 字典、目标机器号/krbtgt
  → 素材，不是打穿；转委派/ADCS 或如实记录。
- ADCS：`find` 报 vulnerable 但无 `Enroll`、模板需 manager approval、CA 拒绝 SAN、
  pfx 未 `certipy auth` 成功 → 不成立；转 ESC4/5/7 或非 relay 面。
- Relay：SMB/LDAP signing 强制、EPA 已开、目标只收 Kerberos → 放弃 relay。
- 委派：SPN 不在 `AllowedToDelegateTo`、目标禁用协议转换、无控主机、RBCD 无写权限
  → 当前分支 blocked，换目标或转 ACL/凭据。
- K8s：`auth can-i` 全 no、`create pods` 被 PSA/Quota 拒、缺 `CAP_SYS_ADMIN`/只读挂载
  → 停手，转 Secret/CI 凭据。
- 云：`sts` 报 AccessDenied/ExpiredToken、元数据 403/无 IMDSv2 token、策略只有 `List*`
  → 记录权限面，换来源。
- 遥测：单机无 4768/4769（非域或审计未开）、EventRecordID 断档、只有 4672 类型 5
  → 不能写域内提权；先查域成员/审计/缺口。
- 横向：目标无 4688/7045/4698/命令回显、relay 认证后无会话、WinRM 默认要求加密
  → 只到 candidate；转 WMI/schtasks/凭据直连，不要重复 relay。
- 公网：只有端口开放、type 2 解析失败、LDAP 匿名 49/8、KDC 只回 25
  → 暴露面记录，不写可利用；禁止用口令字典把“只读枚举”升级成爆破。
- 同一手法同参数连续失败两次 → 换路线，不堆时间。

## 5. 模型常见失误（≥8 条）

完整 14 条（错误动作 → 为什么错 → 正确动作）见 `references/03-model-pitfalls.md`。高频：

1. 把 `cluster-admin`/`system:masters` 名称写成“已提权” → 必须 `auth can-i` + 绑定核对。
2. 把 Kerberoast TGS 写成“已拿服务账号口令” → 未破解/不可复用只是素材。
3. 把 `certipy find` vulnerable 写成“ESC1 可利用” → 要 Enroll + 无审批 + `auth` 成功。
4. 把“有 create pods”写成“已逃逸” → 要宿主 `id`/宿主文件证据。
5. 把“无凭据 user”写成“匿名可访问 API server” → 在线只读确认 `system:anonymous`。
6. 把 AK 前缀/policy 名称写成“管理员” → `sts` 身份 + 策略内容 + boundary/SCP。
7. 把 `Action:*` 直接判“可提权” → 看 Deny/boundary/SCP/条件，文本 allow 只到 candidate。
8. 把 ADCS pfx 写成“已拿域管 TGT” → 必须 `certipy auth` 成功。
9. 把 Unconstrained 属性写成“已能读域控” → 要可控主机 + 高权 TGT。
10. 把 `auth can-i get secrets` 的 yes 写成“已读所有 Secret” → 要实际读取并证明可用。
11. 把单条 4672/4624 写成“提权/横向成功” → 看 LogonType/账号/来源/时间线。
12. 把单机无 Kerberos 事件写成“域内安全” → 先查域成员/审计/DC 日志。
13. 在锁定预算内换工具重复试 → 预算按账号算，不是按工具算。
14. 为“有结论”补写未执行命令/伪造输出 → 证据必须与 rc/哈希/时间对得上。

## 6. 流程（分阶段，每阶段有完成判据）

### 阶段 A：固定边界与身份

- 动作：确认授权清单、域/集群/云身份、当前权限、时间同步、锁定策略。
- 完成判据：能写出“我是谁、能碰谁、不能碰谁、失败预算多少”。
- 失败：清单不明/越界 → 停，先补授权。

### 阶段 B：只读枚举与出图

- AD：`nxc`/`ldapsearch`/BloodHound；K8s：`kubectl auth can-i --list`/RBAC 导出；
  云：`sts get-caller-identity`/`list-*`；主机：Security 日志/证书/LSA 只读。
- 完成判据：至少一条候选路径，且每条边能在原始属性/API/日志上复现。
- 失败：采集被拒/只有名称猜测 → 标 unknown，补权限或换面。

### 阶段 C：选最便宜路径做最小验证

- 优先级：只读 > 单账号低影响 > 需要写对象/创建资源 > 高噪音 relay/强制认证。
- 完成判据：`confirmed` 有完整证据包；`candidate` 有明确 blocker；`blocked` 有已排除项。
- 失败：同一路径两次失败 → 按 `02-failure-criteria.md` 换面。

### 阶段 D：证据归档与清理

- 动作：命令/时间/源/目标/rc/原始输出片段/指纹；写操作回滚；测试资源删除。
- 完成判据：换机照做能复现；没有遗留账号/计划任务/票据/容器/策略变更。
- 失败：无法回滚/证据缺口 → 在报告里标红，不藏。

## 7. 参考索引（逐篇）

| 文件 | 用途 |
| :-- | :-- |
| `references/01-criteria.md` | 判据主表：场景/输入面/可机检判据/证据形态/误报风险 |
| `references/02-failure-criteria.md` | 失败判据表：现象/判定/改走哪条/代价 |
| `references/03-model-pitfalls.md` | 14 条模型常见失误与纠正 |
| `references/04-walkthrough-windows-auth-events.md` | 真实 Windows Security 日志走查（wevtutil + ad-repro） |
| `references/05-delegation-and-rbcd.md` | 委派/RBCD 深水：属性、票据链、失败判据 |
| `references/ad-attacks.md` | AD 枚举/ACL/relay/横向命令速查 + 公网 445/389/88 只读外部视角 + 外部接入面（VPN/OWA/Zimbra/Okta/Entra）四列判据 |
| `references/06-lateral-movement.md` | 横向移动四列判据：relay→SMB/WinRM/LDAPS、PtH、WMI、schtasks、DCOM、RBCD |
| `references/kerberos-and-adcs.md` | Kerberos/ADCS 命令与 ESC 细节 |
| `references/k8s-and-container.md` | K8s RBAC/Secret/逃逸原语四列表/控制面五面（SA token/kubelet/etcd/admission）/CI 细节 |
| `references/cloud-native.md` | AK-SK 四步链（sts→枚举→提权）/提权路径逐条判据/元数据/IAM 失败与未建模项 |

## 8. 脚本用法

```bash
# 离线 kubeconfig / AWS 凭据分诊（只读，不联网）
python Tool/scripts/adcloud-check.py --kubeconfig ~/.kube/config --aws-creds ~/.aws/credentials --json

# 七类判定离线复算（Kerberoast/AS-REP/ADCS/ESC9-17/委派/K8s RBAC/Windows 事件）
python Tool/skill/ad-cloud/scripts/ad-repro.py --input bundle.json --json
python Tool/skill/ad-cloud/scripts/ad-repro.py --kind windows-events --input events.json
python Tool/skill/ad-cloud/scripts/ad-repro.py --kind adcs-esc --input adcs-find.json   # ESC9-17 离线判定（ESC12 需 CA 主机本地权限，只登记 blocker）
python Tool/skill/ad-cloud/scripts/ad-repro.py --kind ntlm-type2 --input ntlm-type2.json  # 公网 445：离线解析 NTLM type 2（域/OS/时间戳/指纹）
python Tool/skill/ad-cloud/scripts/ad-repro.py --kind edge-fingerprint --fixture Tool/cases/ad-cloud01  # 边缘接入面 10 类只读指纹（VPN/OWA/Zimbra/Okta/M365）
python Tool/skill/ad-cloud/scripts/ad-repro.py --extract-evtx-xml security.xml --redact --out events.json

# 案例证据链机检（字段/哈希/证明链/凭据红线）
python Tool/skill/ad-cloud/scripts/ad-accept.py --case Tool/cases/ad-cloud01 --json

# IAM 策略离线评估（不调用 STS/IAM）
python Tool/skill/ad-cloud/scripts/cloud-iam-eval.py --input policy.json \
  --action iam:CreatePolicyVersion --resource arn:aws:iam::123456789012:policy/demo

# 自检（离线，rc=0，输出含 "ok"）
python Tool/skill/ad-cloud/scripts/adcloud-check.py --self-test
python Tool/skill/ad-cloud/scripts/ad-repro.py --self-test
python Tool/skill/ad-cloud/scripts/cloud-iam-eval.py --self-test
```

失败时脚本输出 `{"ok": false, "blocked_at": "...", "reason": "..."}`，rc=2；
不抛裸栈。证据输入只放本地，不联网。

## 9. 任务卡入口

`Tool/prompts/domains/ad-cloud.md`：28 张卡，覆盖 BloodHound、ACL、ESC1/ESC8、强制认证、
DCSync 检测、持久化边界、AWS/GCP/Azure/Okta、K8s RBAC/逃逸/etcd/kube-bench、
横向移动路径选择、公网 445/389/88 只读外部视角、容器逃逸与集群控制面、边缘接入面与身份云。
每张卡含触发词/前置/步骤/判据/失败判据/reference；其中 13 张是“命令 → 期望 rc=0 → 期望字段”的剧本卡。

## 10. KB board 入口

`Tool/mcp/Tool/reverselab/kb/ad-cloud/README.md`：8 篇技术页 + 失败判据（共 9 篇）+ 三条硬判据 + 邻域边界。

| 页 | 用途 |
| :-- | :-- |
| `techniques/01-kerberos-and-adcs.md` | Kerberos/ADCS 条件与命令 |
| `techniques/02-k8s-and-container.md` | K8s/容器基础 |
| `techniques/03-k8s-rbac-escape.md` | RBAC → 逃逸/凭据 |
| `techniques/04-kerberos-paths.md` | Kerberos 路径速判 |
| `techniques/05-adcs-esc-decision.md` | ESC1–ESC8 成立条件 |
| `techniques/06-cloud-credentials-metadata.md` | 云凭据/元数据/IAM |
| `techniques/07-failure-criteria.md` | 失败判据表 |
| `techniques/2026-esc17-wsus-relay.md` | ESC17 HTTPS WSUS 中继判据（2026 基线） |

## 11. 边界

- Web 漏洞（SQLi/XSS/SSRF 打应用层、反序列化、文件上传、越权接口）由 R20 承担。
- 钓鱼/免杀/供应链投毒/生产 DoS 按 `scope` 清单执行；日志只读，删除/篡改需单独授权单。
- 不绕过客户明确声明的 EDR/审计要求；不把真实用户数据带出授权范围。
- 不默认持久化；持久化必须单独授权并登记清理方式。
- 云上操作严格限定在授权账号清单内；计费资源按需显式声明；IAM/集群策略变更按授权单执行并先备份。
- 真实口令、hash、票据、证书私钥、AK/SK、token 一律不落盘/不回传；只留指纹与声明。
- 离线结论必须标 `offline`/`unknown`；在线只做只读或明确授权的低影响验证。
- 风险与修复建议分开写；不把“能打穿”直接等同于“必须立刻修”。

## 12. 验收清单

- [ ] 授权边界文档在案，所有动作未越界。
- [ ] 每条结论都有命令 + 输出 + 时间 + 源/目标 + rc。
- [ ] 凭据/票据/证书有获取路径与指纹，敏感值脱敏。
- [ ] 提权有前后对比；逃逸有宿主证据与清理。
- [ ] 失败路径写明 blocker、已排除项、下一步与代价。
- [ ] 未在目标遗留持久化/计划任务/后门账号（除非单独授权并登记）。
- [ ] JSON/脚本产物做过语法校验；案例 `sha256` 与磁盘一致。
