# ad-cloud KB board

> 面向 `ad-cloud` 域的知识看板：AD/Kerberos/ADCS 与 K8s/容器/云凭据的“下一步 + 判据 + 停止条件”。
> 命令细节在 `Tool/skill/ad-cloud/references/`，矩阵在 `Tool/config/ad-cloud-matrix.json`。

## 九件套导航

| 件 | 位置 | 用途 |
|---|---|---|
| 技能 | `Tool/skill/ad-cloud/SKILL.md` | 判据/失败判据/边界/验收 |
| 参考 1-2 | `references/ad-attacks.md`、`cloud-native.md` | AD 攻击链、云原生速查 |
| 参考 3-4 | `references/kerberos-and-adcs.md`、`k8s-and-container.md` | Kerberos/ADCS、K8s/容器 |
| 脚本 | `Tool/scripts/adcloud-check.py` | 离线 kubeconfig/AWS 凭据体检 |
| 矩阵 | `Tool/config/ad-cloud-matrix.json` | 16 类判据与误报 |
| 案例 | `Tool/cases/ad-cloud01/`、`ad-cloud02/` | ADCS/L3、K8s/L2 计划案例 |
| 路由 | R23（`routing-fragments/ad-cloud.json`） | 内网/AD/云原生 |

## 1. 先看哪一篇

| 手里的东西 | 先读 | 目标 |
|---|---|---|
| 一个域账号/内网 foothold | `kerberos-paths.md` | 判断 roast/委派/ADCS 哪条路可走 |
| kubeconfig、SA token、容器 shell | `k8s-rbac-escape.md` | 枚举 RBAC -> 找逃逸/凭据面 |
| AK/SK 或 CI 凭据 | 本页“云凭据” + `cloud-native.md` | 先验身份，再判权限，不猜管理员 |
| 只有 kubeconfig 文件、不能联网 | `adcloud-check.py` | 离线标出 TLS/匿名/宽权限名称/token 过期 |

## 2. 三条硬判据

1. **凭据可复现**：命令/路径完整，换干净机器重放仍得到同一凭据或权限。
2. **提权可见证**：`whoami /all`、`kubectl auth can-i`、`aws sts get-caller-identity`、组成员等客观输出。
3. **证据可归档**：时间、源/目标、原始输出、指纹；敏感值脱敏。

三条缺一条，只能写“待验证”。

## 3. AD 路径速判

| 观察 | 可能路径 | 先验证 |
|---|---|---|
| SPN 非空、可注册 | Kerberoast | `GetUserSPNs` 拿 TGS，再离线破解 |
| `DONT_REQ_PREAUTH` | AS-REP | `GetNPUsers`，注意锁定 |
| `TRUSTED_FOR_DELEGATION` | Unconstrained | 控制主机 + 捕获 TGT |
| `msDS-AllowedToDelegateTo` | Constrained | `getST -spn` + `-impersonate` |
| 模板 SAN/Any Purpose/ACL 可写 | ADCS ESC1-8 | `certipy find/req/auth`，以 auth 成功为准 |
| SMB/LDAP signing 未强制 | NTLM relay | 先 `--gen-relay-list`，再 relay |

## 4. K8s 路径速判

| 权限 | 先做什么 | 判据 |
|---|---|---|
| `create pods` | 创建带标记 Pod，挂 hostPath/privileged（授权内） | 宿主 `id` 或宿主文件可读 |
| `get secrets` | 读测试 Secret/SA token | Secret 实际可用于认证/拉镜像 |
| `impersonate` | 以目标身份执行只读请求 | 返回目标身份可见资源 |
| `bind`/`escalate` | 绑高权 Role 到当前主体 | `auth can-i` 前后对比 |
| 无凭据 context | 离线标匿名风险 | 在线只读请求确认是否 401/403 |

## 5. 云凭据

- AKIA/ASIA 只是格式；先 `aws sts get-caller-identity` 确认身份（授权内）。
- IAM 权限宽窄**不能离线猜**；必须枚举 policy/trust/SCP，或实际完成一个低影响动作。
- CI token 看 scope：能否读 protected env、推镜像、AssumeRole；不看变量名猜权限。
- 临时凭据记录 `exp`；过期后不得作为有效证据。

## 6. 常见误报

- `certipy find` 报 vulnerable，但模板需 manager approval / 当前账号无 Enroll。
- kubeconfig 里叫 `cluster-admin`，实际只绑了窄 Role。
- JWT 有 `system:masters` 组，但 API server 不接受该 token/组映射不同。
- 镜像有 HIGH CVE，但没有可达入口/利用链。
- 有 `create pods` 权限，但 PSA/Quota/Admission 拒绝。
- relay 收到认证请求，但没有可用会话/证书。

## 7. 失败与停止

| 现象 | 处理 |
|---|---|
| `KRB_AP_ERR_SKEW` | 同步时间，重试一次 |
| `STATUS_ACCOUNT_LOCKED_OUT` | 立即停，换账号/来源并报告 |
| `Forbidden` | `auth can-i --list`，换 SA/角色，不盲试 |
| `certipy auth` 失败 | 查 EKU/CA 链/审批/撤销 |
| relay 无会话 | 查 signing/EPA，换目标或改 ADCS HTTP |
| 逃逸 `Operation not permitted` | 缺 CAP/只读挂载/seccomp；换面或停 |

## 8. 边界

- 只在授权域/账号/集群/云账号内操作；不碰授权外资源。
- 不做未授权持久化、后门、批量喷洒、拒绝服务。
- 不伪造/篡改日志；证据脱敏。
- 纯 Web 漏洞走 R20；固件/IoT 走 R22。

## 9. 相关文件

- `Tool/skill/ad-cloud/SKILL.md`
- `Tool/skill/ad-cloud/references/kerberos-and-adcs.md`
- `Tool/skill/ad-cloud/references/k8s-and-container.md`
- `Tool/scripts/adcloud-check.py`
- `Tool/config/ad-cloud-matrix.json`
