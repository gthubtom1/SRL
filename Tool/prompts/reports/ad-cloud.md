# ad-cloud 报告模板

> 复制到 `evidence/<case>/report.md`。只留凭据指纹，不落明文。

## 1 目标与授权
- 目标：<域 / CA / AWS 账号 / K8s 集群 / 订阅>
- 授权：<授权编号 / 只读 / 是否允许认证验证 / 时间窗 / 速率>
- 范围外：<生产写操作 / 持久化 / 他人账号 / 跨租户>
- 环境：<DC / CA / 云区域 / kubeconfig 来源 / 工具版本>

## 2 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/ad-repro.json | <sha256> | `python Tool/skill/ad-cloud/scripts/ad-repro.py --input <bundle> --json` | 0 | ADCS/Kerberos/RBAC |
| E02 | artifacts/iam-eval.json | <sha256> | `python Tool/skill/ad-cloud/scripts/cloud-iam-eval.py --input <policy> --action <a> --resource <r>` | 0 | IAM allow/deny |
| E03 | artifacts/adcloud-check.json | <sha256> | `python Tool/scripts/adcloud-check.py --kubeconfig <kc> --json` | 0 | 本地 kubeconfig/AWS |

## 3 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| ACL/属性 | 原始 ACL/属性可读且与图谱一致 | <实测> | E01 | <结论> |
| ADCS | 模板可 Enroll + 证书可 auth 出 TGT/ccache | <实测> | E01 | <结论> |
| Kerberos | 票据/委派/S4U 有可复现响应 | <实测> | E01 | <结论> |
| IAM | 文本 allow 且 boundary/SCP 不拦，实际只读 API 成功 | <实测> | E02 | <结论> |
| K8s RBAC | subject 匹配 + verb/resource allow + auth can-i 一致 | <实测> | E01/E03 | <结论> |
| 高风险检测 | API 时间/调用者/策略版本/资源四者对位 | <实测> | E02 | <结论> |

## 4 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 只有 LDAP/图谱边，无原始属性 | <yes/no> | E01 | 标 candidate，补只读属性 |
| 证书签发但 auth 失败/KDC_ERR | <yes/no> | E01 | ESC 不成立，转 ESC4/ESC5 |
| signing/EPA 已开、CA 拒绝模板 | <yes/no> | E01 | 停 relay，换面 |
| IAM 文本 allow 但 API AccessDenied | <yes/no> | E02 | 记未建模条件，不写提权 |
| 名称像高权但绑定窄/全 no | <yes/no> | E01/E03 | blocked，转 Secret/CI |
| 凭据/票据明文落盘 | <yes/no> | - | 立即脱敏/删除并上报 |

## 5 影响与边界
- 影响：<可达对象 / 可读数据 / 可发证书 / 可枚举资源>
- 边界：<只读验证 / 单账号 / 未触碰生产>
- 误报风险：<蜜标、受保护对象、托管服务覆盖 CIS、合法自动化>
- 未覆盖：<未验证的路径、未拿到的日志、未建模的 SCP>

## 6 修复建议（厂商视角）
1. ADCS 强制 EPA/HTTPS、禁用 NTLM relay、收紧模板 SAN 与审批，监控 ESC 配置漂移。
2. 域内最小权限：清理 GenericAll/WriteDACL，启用 Tier 模型与 LAPS，监控 DCSync 权限。
3. IAM 移除 `*` 资源与 PassRole/CreatePolicyVersion 组合，边界策略与 SCP 双保险。
4. K8s 禁用匿名、收敛 cluster-admin、启用 PSA/审计日志，SA token 短时化。

## 7 复跑命令
```bash
python Tool/skill/ad-cloud/scripts/ad-repro.py --input evidence/<case>/artifacts/bundle.json --json
python Tool/skill/ad-cloud/scripts/cloud-iam-eval.py --input evidence/<case>/artifacts/policy.json --action s3:GetObject --resource '*'
python Tool/scripts/adcloud-check.py --kubeconfig evidence/<case>/artifacts/kubeconfig.yaml --json
```
