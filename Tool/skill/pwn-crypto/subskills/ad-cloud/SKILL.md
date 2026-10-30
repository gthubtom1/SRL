---
name: ad-cloud
description: "按需核对 AD/ADCS、云 IAM 与 K8s 的身份权限配置、认证遥测和合成 canary；真实认证留在用户侧，不新增正式领域。"
---

# AD / 云身份权限评估

本文件是 pwn-crypto 下的按需子技能，由现有九域按原始目标与材料组合调用，不新增 AD 正式路由。输入、派生材料和结果返回同一 project/version/run。方法存在不证明工具、平台或真实任务已验证。

## 输入与执行范围

接收用户侧筛选后的身份别名、目录属性/ACL、证书公有元数据、IAM/RBAC 策略、版本与审计事件，以及测试端点的非秘密授权结果。真实认证由用户在宿主完成；不接收账号口令、口令 hash、票据/ccache、PFX 私钥、AK/SK、kubeconfig 正文、Token、Key 或 Salt，也不读取后散列、截前缀或打码。用户持有这些材料不等于 Agent 可以读取。

Agent 可分析安全副本、复算有限策略模型与合成夹具，必要时在既有 scope 内读取能在采集前限定字段的非秘密元信息。涉及登录态的动作由用户侧完成并返回安全证据；缺安全通道时记 blocked。不要调用会自动加载真实凭据、导出全量环境/日志或输出 Secret 的通道。

不执行生产 DoS、清除/篡改日志、持久化、安装/改动服务或计划任务、系统网络/时钟/驱动/启动策略改动。本技能也不执行凭据捕获/破解/复用、强制认证/relay、写域对象/ADCS 模板/IAM/RBAC、创建特权工作负载或宿主逃逸；不把“另取授权”作为上述动作的默认下一步。已存在的事件可供只读调查。

## 先固定四件事

1. 问题与范围：资产、主体别名、目标资源、动作、时间窗，说明是配置审计、行为调查还是合成验证。
2. 身份与版本：域/租户/集群/namespace、系统/工具/策略版本、采集时间和安全输入来源。
3. 证据可见性：用户侧执行者、结果摘要、请求/事件关联标识、时间与错误类别；不把截图或自述当独立互证。
4. 停止条件：越界、秘密即将进入输出、账号锁定风险或同形失败两次即停；不换账号/工具规避预算，不修改环境补证据。

## 结论门槛

`confirmed` 必须写明确认的对象：配置事实、遥测事件或特定 canary 行为。`candidate` 表示风险条件或关联尚未证实；`blocked` 表示当前验证路线受阻，业务风险本身仍可 unknown。配置 confirmed 不等于攻击成功，脚本返回 confirmed 也不能替代专业判定。

| 问题 | 可确认的安全证据 | 保留条件与未知 |
|---|---|---|
| Kerberos/roast 风险 | 同一时点的 SPN、预认证/账号状态、允许的加密类型及相关 4768/4769/4771 遥测 | TGS/AS-REP 的加密响应不是可直接用于 PtH 的 NT hash；不采集或破解，不据此确认口令可恢复 |
| ADCS | 模板/CA 公有配置、有效 Enroll/ACL、审批/签名要求、EKU、映射/绑定与补丁信息 | scanner 的 ESC 标签不是利用证明；用户侧测试认证结果只覆盖该主体/模板/服务，不要求导出私钥或票据 |
| 委派/RBCD | 目录委派属性、目标 SPN、安全描述符/有效权限与独立目录审计 | 可读不等于可写；属性存在不等于可冒用；不改属性、捕获/导入票据 |
| K8s | subject/绑定/rules、用户侧精确 verb/resource/namespace 授权决策与既有 admission 配置 | can-i yes 不证明动作完成或逃逸；仅用预先准备的无秘密 canary，不能读真实 Secret |
| 云 IAM | 用户侧身份摘要、策略/trust、boundary/SCP/资源策略与安全测试结果 | ARN 不直接表达权限；文本 allow 不证明有效授权，缺条件/策略层时保留 unknown |
| 认证/横向遥测 | 源/目标、主体别名、LogonId/时间、目标进程/会话等独立记录 | 4624/4672、工具 SUCCEED 或请求返回 0 单独不能证明执行或恶意；不重放横向动作补证据 |
| 外部暴露面 | 既有安全协商字段、公开 metadata、资产归属与版本线索 | 端口/登录页/type 2 只证明可见面，不要求升级 relay/用户名枚举/口令尝试 |
| 容器隔离 | 工作负载/节点安全配置、runtime 版本和用户侧既有审计 | privileged/hostPath/CAP 是条件，不证明逃逸；不挂载宿主、不读宿主秘密、不改运行时 |

## 安全任务链与交付

先核配置和采集覆盖，再列每条风险的支持/反证，按需要请求用户侧提供一个限定测试结果或既有遥测。合成 canary 由用户预先准备，只含公开测试标记；与真实资产的差异必须写明，不能当真实凭据有效性或攻击见证。缺材料时保留未知，可完成有边界的评估，不强求发现漏洞或提权。

报告记录：结论类别与范围、资产/策略版本、执行者/命令形态或工具通道、时间/关联标识、非秘密原输出、反证、缺项与复查办法。只给建议，不执行线上策略修复或清理已有系统对象。工具失败、证据缺失和未执行保持原意。

## 云 / 容器实际任务路线

IAM 输入为平台、策略快照与附加层、主体别名、精确 action/resource 和条件上下文；按 [cloud-native](references/cloud-native.md) 的有限模型先复算，再与用户侧同主体/资源/时点的非秘密授权结果配对。K8s 输入为版本、namespace、subject、binding/rules 与 verb/resource/subresource/name；按 [k8s-and-container](references/k8s-and-container.md) 对齐决策、admission 和已有业务效果，不创建工作负载补证据。镜像来源/digest/构建链转供应链域，运行时授权留本技能。

每条结果输出“配置事实 → 有限模型结果 → 用户侧授权决策 → 已观察业务效果”四列；缺项写 unknown，不把后列由前列补齐。正反例至少比较 canary 与范围外资源、allow 与显式 deny/缺条件；namespace 错位不能用另一 namespace 的成功顶替。恢复时携带同一 project/version/run、策略/绑定快照身份、工具版本、命令、安全输出、缺层和待测项；策略已变则重新核对，不沿用旧 allow。没有用户侧授权见证时只交有限模型评估。

## 参考与工具

| 文件 | 当前职责 |
|---|---|
| [01-criteria](references/01-criteria.md) | 事实/风险/行为分层判据 |
| [02-failure-criteria](references/02-failure-criteria.md) | 停止与未知，不转秘密采集或系统改动 |
| [03-model-pitfalls](references/03-model-pitfalls.md) | 高频误判与反例 |
| [04-walkthrough](references/04-walkthrough-windows-auth-events.md) | 历史日志结论边界与安全复算 |
| [05-delegation-and-rbcd](references/05-delegation-and-rbcd.md) | 委派属性、SPN、身份限制与审计 |
| [06-lateral-movement](references/06-lateral-movement.md) | 既有认证/执行遥测关联 |
| [ad-attacks](references/ad-attacks.md) | AD 属性、图谱与公开暴露面分析 |
| [kerberos-and-adcs](references/kerberos-and-adcs.md) | Kerberos/ADCS 技术条件与版本限制 |
| [k8s-and-container](references/k8s-and-container.md) | RBAC、隔离配置及 canary 结果 |
| [cloud-native](references/cloud-native.md) | IAM/信任链、元数据/CI 暴露风险 |

现有 [ad-repro.py](scripts/ad-repro.py) 与 [cloud-iam-eval.py](scripts/cloud-iam-eval.py) 可按各自帮助复算支持的安全输入；前者有历史攻击判据和联网模式，不能一概称纯离线或把 verdict 当验收；后者是有限 IAM 文本模型，不能替代云端授权。`adcloud-check.py` 的真实凭据文件入口不作为当前路线。

```bash
python Tool/skill/pwn-crypto/subskills/ad-cloud/scripts/ad-repro.py --help
python Tool/skill/pwn-crypto/subskills/ad-cloud/scripts/cloud-iam-eval.py --help
```

纯 Web/API 问题读 `Tool/skill/web-pentest/SKILL.md`；二进制问题读 `Tool/skill/softseep/SKILL.md`；CI/制品来源读 `Tool/skill/supply-chain-security/SKILL.md`；时间线可请 `Tool/skill/forensics-mobile/SKILL.md`。交接只传安全证据与具体问题。

历史原件为 `Tool/skill/_pending/ad-cloud/SKILL.md`，只用于核对当时方法/来源和案例身份，不导入其凭据采集、攻击命令或系统改动步骤。当前范围和本目录活跃参考优先；历史原文保持不变。
