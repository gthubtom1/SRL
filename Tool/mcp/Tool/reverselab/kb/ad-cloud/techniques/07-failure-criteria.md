# AD/云失败判据（failure-criteria）

> 入口信号：一条路径跑不动、工具报错、只拿到素材、或结论开始“像猜”。
> 用法：先在表里找到现象，再按“改走哪条”换面；不要重复同参数硬撞。
> 配套：`references/02-failure-criteria.md`、`Tool/skill/ad-cloud/SKILL.md`。

## 1. 失败判据表

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| `KRB_AP_ERR_SKEW` 对时后仍失败 | Kerberos 链不可信 | 对时/重取 TGT；仍失败转 NTLM/凭据直连 | 低 |
| `STATUS_ACCOUNT_LOCKED_OUT` 或同账号 4625 ≥2 | 锁定风险 | 停该账号，换账号/来源，先读 pass-pol | 高 |
| Kerberoast 只有 TGS hash 未破解 | 素材 | 换字典/规则或转 AS-REP/委派/ADCS | 中 |
| 目标是机器号 `$`/krbtgt | 选错目标 | 换有 SPN 的用户账号；机器号转委派 | 低 |
| AS-REP 返回 PREAUTH_REQUIRED | 预认证已开 | 转 Kerberoast/ADCS/ACL | 低 |
| `certipy find` 报 ESC1 但无 Enroll | 不可利用 | 转 ESC2/3/4/7 | 低 |
| 模板需审批/CA 拒绝 SAN | ESC1/6 不成立 | 找无需审批模板/ESC4/ESC7 | 中 |
| pfx 拿到但 auth 失败 | 证书用途不匹配 | 查 EKU/UPN/DC 时间/证书链 | 中 |
| ESC8 端点可达但 relay 无认证 | signing/EPA 拦住 | 放弃 relay，转凭据直连/其他 ESC | 中 |
| Unconstrained 但无控主机 | 拿不到 TGT | 先找可控主机/本地管理员；转 RBCD | 中 |
| `AllowedToDelegateTo` 不含目标 SPN | constrained 不成立 | 换列表内目标或写 RBCD | 低 |
| RBCD 写入成功但 getST 失败 | 协议转换/时钟/票据问题 | 查目标属性/时间；换目标 | 中 |
| `auth can-i` 全 no | 无 RBAC 权限 | 转 Secret/CI/应用层；别用名称猜 | 低 |
| create pods 被 PSA/Quota 拒绝 | 未逃逸 | 读拒绝信息，换 ns/节点或转其他面 | 中 |
| Secret 可读但为空/过期 | 素材 | 找 dockerconfigjson/SA token/云密钥并验证 | 低 |
| privileged/hostPath 但读不到宿主 | 配置≠逃逸 | 查 seccomp/只读挂载/用户命名空间 | 中 |
| STS AccessDenied/ExpiredToken | 凭据无效 | 记录后换来源（CI/元数据/profile） | 低 |
| 元数据 403/无 IMDSv2 token | SSRF 到凭据 blocked | 查 IMDSv2/网络策略；转其他目标 | 低 |
| IAM 文本 allow 但 API 拒绝 | boundary/SCP/资源策略未建模 | 用 list/get-policy/simulate 对照 | 中 |
| 无 4768/4769 | 非域主机或审计未开 | 查 PartOfDomain/审计/Kerberos 日志；域内取 DC 日志 | 低 |
| EventRecordID 断档/日志清空 | 遥测不可信 | 记录缺口；从其他 DC/转发器/EDR 补 | 中 |
| 4672 多但无类型 2/3/10 | 多为服务登录 | 看 LogonType/账号/来源，当基线不写提权 | 低 |
| 客户端证书但 klist 无票据 | 有证书≠PKINIT | 查 EKU/私钥/DC 信任，授权内验证或记录 | 中 |

## 2. 降级顺序

1. 换证据面：Kerberos → NTLM/凭据直连 → ADCS → 委派/RBCD → ACL。
2. 换目标：换有 SPN/可注册模板/可写 ACL 的对象。
3. 换身份/来源：避免锁定与告警集中。
4. 换域：AD 不通再看 K8s/云/CI，但必须在授权清单内。
5. 仍不通：写 `blocked` + blocker + 已排除项；不编造成功。

## 3. 最小复现命令

```bash
# 认证预算与时钟
nxc smb <DC> --pass-pol -u '' -p ''
chronyc tracking || w32tm /stripchart /computer:<DC>

# Kerberos/ADCS 只读
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -vulnerable -stdout

# K8s 只读
kubectl auth can-i --list
kubectl get clusterrolebinding -o wide

# 云只读
aws sts get-caller-identity
```

## 4. 确认判据（失败时也要写清）

- 失败结论必须包含：现象、判定、blocker、已排除项、下一步、代价。
- 素材类（hash/pfx/Secret/日志）必须标“未验证”，不能进入 confirmed 列表。
- 认证失败类必须给出账号预算与停止条件；不要只写“再试一次”。
- 遥测类必须给出时间窗、EventRecordID 连续性、脱敏声明。

## 5. 边界

- 失败判据不是放弃，是换面；换面仍受授权范围约束。
- 高风险写操作（改模板/ACL/RBCD/IAM）必须先备份、单独授权、登记回滚。
- 不把单机日志/单条事件/策略名称当域级结论；不把失败样本的明文落盘。
