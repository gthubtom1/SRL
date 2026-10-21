# 04 真实走查：本机 Windows Security 日志的 AD 遥测 triage

> 适用：拿到一台 Windows 主机的 Security.evtx/wevtutil 导出，想判断它有没有 AD/Kerberos/横向证据。
> 不适用：没有授权的主机、生产 DC 的高峰时段、或只拿到二手截图没有原始事件。
> 目标不是“打穿”，而是**把一条真实日志变成可复算的结论，并明确它不能证明什么**。

## 1. 目标与环境

| 项 | 值 |
| :-- | :-- |
| 目标 | 本机 Windows 10/11 工作站，只读 |
| 权限 | 当前本地用户可读 Security 日志与注册表 HKLM 只读 |
| 网络 | 不联网、不连 DC、不触发认证 |
| 输入 | `wevtutil qe Security /f:xml` 导出的 100 条事件 |
| 脚本 | `Tool/skill/ad-cloud/scripts/ad-repro.py` |
| 产物 | `Tool/cases/ad-cloud03/input/security-events.json`、`artifacts/run.json` |
| 结论 | `blocked`（本机无 Kerberos/NTLM 遥测）；不是“域内安全” |

先固定主机身份，避免把单机日志误当域日志：

```bash
powershell -NoProfile -Command "(Get-CimInstance Win32_ComputerSystem).Domain; (Get-CimInstance Win32_ComputerSystem).PartOfDomain"
# WORKGROUP
# False
```

```bash
klist
# 当前登录 ID 是 0:0x2e204
# 缓存的票据: (0)
```

`PartOfDomain=False` + 票据缓存为空，已经说明这台机器没有域登录/Kerberos 票据面；
后面的日志 triage 只用于验证这个判断，并给出可复用的方法。

## 2. 导出真实事件（只读）

只取与 AD 认证面相关的事件 ID，限制 100 条，避免把整份日志带出：

```bash
MSYS_NO_PATHCONV=1 wevtutil qe Security \
  '/q:*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4768 or EventID=4769 or EventID=4648)]]' \
  /f:xml /c:100 /rd:true > /tmp/sec2.xml
# rc=0
wc -c /tmp/sec2.xml
# 147202 /tmp/sec2.xml
```

`wevtutil /f:xml` 输出的是**连续的 `<Event>` 根元素**，不是单个 `<Events>` 文档；
所以脚本先把它包一层 `<Events>` 再解析。直接 `ET.parse` 会报 `junk after document element`。

转成脱敏 JSON（用户名/主机/IP 都替换）：

```bash
python Tool/skill/ad-cloud/scripts/ad-repro.py \
  --extract-evtx-xml /tmp/sec2.xml \
  --out Tool/cases/ad-cloud03/input/security-events.json
# {"ok": true, "out": ".../security-events.json", "events": 100}
```

脱敏字段：`TargetUserName`/`SubjectUserName` → `USER`，`Computer` → `HOST`，
`IpAddress` → `IP`；保留 EventID、LogonType、时间、EventRecordID、Channel。
原始 XML 只放 `/tmp`，不落仓库。

## 3. 复算判定

```bash
cd Tool/cases/ad-cloud03
python ../../skill/ad-cloud/scripts/ad-repro.py \
  --kind windows-events --input input/security-events.json --json > artifacts/run.json
echo $?
# 0
```

关键原始输出（节选）：

```json
{
  "kind": "windows-events",
  "verdict": "blocked",
  "checks": [
    {"check": "kerberos-events", "ok": false, "detail": "4768/4769/4770/4771=0"},
    {"check": "ntlm-events", "ok": false, "detail": "4776=0"},
    {"check": "special-privileges", "ok": true, "detail": "4672=50"},
    {"check": "account-enumeration", "ok": false, "detail": "4798=0"},
    {"check": "lockout-budget", "ok": true, "detail": "max failures for one principal=0"}
  ],
  "findings": [
    {"severity": "medium", "title": "Special privileges assigned", "evidence": "4672=50"}
  ],
  "summary": {
    "events": 100,
    "counts": {"4624": 50, "4672": 50},
    "logon_types": {"5": 50},
    "kerberos_events": 0,
    "ntlm_events": 0,
    "special_privileges": 50,
    "explicit_credentials": 0,
    "account_enumeration": 0,
    "max_failures_one_principal": 0
  }
}
```

解读：

1. 100 条事件只有 4624（登录成功）和 4672（分配特殊权限），比例 1:1。
2. 所有 4624 的 LogonType 都是 `5`（服务登录），不是交互 `2`、网络 `3` 或 RDP `10`。
3. 没有 4768/4769/4770/4771（Kerberos）、没有 4776（NTLM）、没有 4625（失败）、没有 4648（显式凭据）。
4. 因此：**本机日志没有任何 AD 认证/Kerberos 证据**；4672 是服务启动的常态，不能写成提权。

## 4. 补充真实主机面（不导出私钥）

证书存储（只取元数据，`HasPrivateKey` 是布尔值，不导出私钥）：

```bash
powershell -NoProfile -Command "\$s=New-Object System.Security.Cryptography.X509Certificates.X509Store('My','CurrentUser'); \$s.Open('ReadOnly'); \$s.Certificates | ForEach-Object { [pscustomobject]@{Subject=\$_.Subject; Thumbprint=\$_.Thumbprint; HasPrivateKey=\$_.HasPrivateKey; EKU=((\$_.EnhancedKeyUsageList | ForEach-Object {\$_.FriendlyName}) -join ';')} } | ConvertTo-Json -Depth 3; \$s.Close()"
```

输出（真实，单条）：

```json
{
  "Subject": "CN=localhost",
  "Thumbprint": "D7B480644BB35F8FE1F62E26BC26EA5C33556F8E",
  "HasPrivateKey": true,
  "EKU": "服务器身份验证"
}
```

判据：EKU 是**服务器身份验证**，不是 Client Authentication/Smart Card Logon；
即使有私钥，也不能据此写“可用于 PKINIT/ADCS 客户端证书”。这是典型的“有证书≠能打 ADCS”。

LSA 与 UAC 策略（真实值，只读）：

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' | grep -E 'NoLmHash|RunAsPPL|LimitBlankPasswordUse|restrictanonymous'
reg query 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' | grep -E 'EnableLUA|ConsentPromptBehaviorAdmin'
```

```text
NoLmHash                  REG_DWORD    0x1
RunAsPPL                  REG_DWORD    0x0
LimitBlankPasswordUse     REG_DWORD    0x1
restrictanonymous         REG_DWORD    0x1
EnableLUA                 REG_DWORD    0x0
ConsentPromptBehaviorAdmin REG_DWORD   0x0
```

解读：`NoLmHash=1`、`restrictanonymous=1`、`LimitBlankPasswordUse=1` 是收敛项；
`RunAsPPL=0` 与 `EnableLUA=0` 是主机加固缺口（LSA 未受保护、UAC 关闭），
但它们属于**本地提权面/加固建议**，不是 AD 域内提权证据，也不在本案例的 `confirmed` 范围。

## 5. 结论

- 本机不是域成员（`PartOfDomain=False`），票据缓存为 0。
- 真实 Security 日志 100 条只有 4624 类型 5 + 4672，无 Kerberos/NTLM/失败/显式凭据。
- `ad-repro` 判定 `blocked`：**本机没有可复算的 AD 认证遥测**；这既不是“域内安全”，也不是“主机被攻陷”。
- 真实证书是 `CN=localhost` 的服务器身份验证证书，不能用于 PKINIT/ADCS 客户端路径。
- 真实注册表显示 UAC 关闭、LSA PPL 关闭；作为加固项记录，不写成提权。

## 6. 边界与失败判据

- **单机 ≠ 域**：本机日志缺失不能证明 DC 没有 4768/4769；域内必须从 DC/CA/转发器取日志。
- **审计未开 = 假阴性**：没有 4768/4769 也可能是 Kerberos 审计没开；先查审计策略与
  `Microsoft-Windows-Kerberos/Operational`，再决定日志是否可信。
- **4672 不是提权**：服务登录（类型 5）常态出现；要看账号、时间、来源与前后权限。
- **证书用途必须匹配**：服务器身份验证证书不能当客户端证书；没有 `certipy auth` 成功就不写 ADCS 成功。
- **日志缺口**：记录 EventRecordID 断档；被清空/转发的日志不能单独支撑时间线。
- **不落敏感值**：原始 XML、用户名、主机名、IP、私钥都不进仓库；只留脱敏 JSON 与计数。

## 7. 复跑清单

```bash
# 1) 只读导出（授权主机）
MSYS_NO_PATHCONV=1 wevtutil qe Security '/q:*[System[(EventID=4624 or EventID=4625 or EventID=4672 or EventID=4768 or EventID=4769 or EventID=4648)]]' /f:xml /c:100 /rd:true > /tmp/sec2.xml
# 2) 脱敏转 JSON
python Tool/skill/ad-cloud/scripts/ad-repro.py --extract-evtx-xml /tmp/sec2.xml --out Tool/cases/ad-cloud03/input/security-events.json
# 3) 复算
cd Tool/cases/ad-cloud03
python ../../skill/ad-cloud/scripts/ad-repro.py --kind windows-events --input input/security-events.json --json > artifacts/run.json
# 4) 复算 sha256（与 case.json 对照）
python -c "import hashlib;print(hashlib.sha256(open('artifacts/run.json','rb').read()).hexdigest())"
```
