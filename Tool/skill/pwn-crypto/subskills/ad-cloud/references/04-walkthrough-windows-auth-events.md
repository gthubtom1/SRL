# Windows 认证事件：历史走查与当前复核

历史原始走查保留在 `Tool/skill/_pending/ad-cloud/references/04-walkthrough-windows-auth-events.md`，当时案例指向 `Tool/cases/ad-cloud03/`。本页不重写原始输出，也不把旧机器结论当当前环境结果；历史中的全量日志/票据查看或旧相对路径不是当前采集步骤。

## 旧案例可以说明什么

历史记录称该工作站为 WORKGROUP、PartOfDomain=False；所选 100 条事件中有 50 条 4624 和 50 条 4672，登录类型为 5；该采集面未见 Kerberos/NTLM 相关事件。这个统计只支持“该次选定日志范围没有相应观察”，不能由缓存为空/非域成员推出机器没有任何域认证活动，更不能推出域内安全。

公有证书元数据中 HasPrivateKey=true 只是私钥存在性标志，不是私钥内容；服务器身份验证 EKU 不证明可用于 PKINIT。旧注册表值只是当时主机的配置事实，不能复用为当前主机基线或域提权证据。

## 当前安全输入

由用户在自己的日志工具中限定时间窗、事件类型与字段，再提供不含秘密的记录。允许字段按任务选择：EventID、UTC 时间、EventRecordID、Channel、主机/账号别名、LogonType、LogonId、源目标别名与已筛选进程/会话标识。命令行、应用数据和证书 Subject 等也可能含敏感信息，不能默认全文安全；原始 EVTX/XML 不因“只放临时目录”就可先交 Agent 再脱敏。

保留执行者、采集工具/版本、过滤条件、记录数量、时间误差及缺字段。过滤后的事件 ID 可以不连续；应在原 channel 的采集范围判断滚动、转发与真实缺口。

## 已有工具的限定用法

当前活跃 [ad-repro.py](../scripts/ad-repro.py) 可复算 windows-events。以下是合成输入格式，账号字段按工具实际支持核验：

```json
{
  "kind": "windows-events",
  "events": [
    {"event_id": "4624", "logon_type": "5"},
    {"event_id": "4672", "logon_type": "5"}
  ]
}
```

从源码根对安全 JSON 副本执行：

```bash
python Tool/skill/pwn-crypto/subskills/ad-cloud/scripts/ad-repro.py --kind windows-events --input work/safe-events.json --json
```

这不是采集命令，不联系域控。脚本 verdict/计数是有限规则结果，不证明事件真实、完整或已发生攻击；不能补填 cracked、凭据/票据正文等字段迎合旧判据。XML 提取模式也不能代替采集前的秘密边界。

## 事件解释与反例

| 观察 | 可支持的事实 | 仍需核验 |
|---|---|---|
| 4624 类型 3/10 | 网络/远程交互登录事件 | 主体、源目标、认证机制、LogonId 与实际会话 |
| 4672 | 特殊权限分配给某登录会话 | 与 4624 的同一登录标识关联；服务/管理基线，不单独判提权 |
| 4768/4769/4771 | 相应 KDC 请求/失败遥测 | 审计版本、状态、服务、账号别名与采集覆盖；不要求导出票据 |
| 4776 | 凭据验证遥测 | 记录所在主机角色、返回状态、源与目标，不等同资源访问成功 |
| 无相关事件 | 本次范围未观察到 | 审计是否开启、主机角色、channel、时间窗、滚动/转发/采集缺口 |

正例：服务登录和相应特权分配可关联，报告为正常基线观察。反例：仅凭 4672 或无 Kerberos 事件，分别写“已提权”“域内安全”，均证据不足。

交付安全输入/输出身份、计数、关联方法、已证/未知与历史适用范围。同一 project/version/run 内接续；更详细的关联见 [06-lateral-movement](06-lateral-movement.md)，缺项见 [02-failure-criteria](02-failure-criteria.md)。不修改日志、审计策略、系统时钟或服务来重现旧案例。
