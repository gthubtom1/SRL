# ad-cloud 报告模板

> **客户视角五段（必须全在，缺一不算交付）**：下面五个是**真标题**——`python Tool/scripts/case_state.py report --check --file <本文件>`
> 按标题文字精确匹配「结论 / 已确认 / 仍未知 / 下一步 / 复查」，缺一段即 `[FAIL]`；每段标题下至少 2 行正文，
> 「结论」不超过 3 行，「已确认」里至少要有一个 `E-` / `C-` / `F-` 编号。「下一步 / 复查」别改名，改了检查器就找不到。

> 复制到 `work/<case>/report.md`。只留凭据指纹，不落明文。

## 1 结论（≤3 行：能不能用 / 到哪一步 / 卡在哪）
- 到哪一步：<只能看懂结构 | 能改到能用 | 能完全自己接管 | 现在做不了>
- 卡在哪：<卡点一句话 + 证据编号；没有卡点写「无」>
- 能不能用：<只按已有证据说一句；没跑过就写「未验证」>

## 2 已确认（每条：客户能听懂的一句话 + 证据 ID + 强度：强 / 中 / 弱）
- <客户能听懂的那句话>（`E-001`；强：同输入同输出可复现，命令与输出都能贴）—— 原始记录 `artifacts/<tool>-<时间>.json`
- <客户能听懂的那句话>（`E-002`；强：两路独立验证一致，不只是重复跑）—— 原始记录 `artifacts/<tool>-<时间>.json`
- 只有一次观测、没有可复跑命令的线索不进本段，写进第 3 段。

## 3 仍未知（每条：未知什么 + 为什么未知 + 缺什么才能知道）
- <未知什么>｜为什么未知：<环境限制 / 证据缺口 / 授权没给>｜还缺：<补什么才能知道>
- <未知什么>｜为什么未知：<同上>｜还缺：<同上>

## 4 下一步（省事路线 / 彻底路线 / 不建议做的事，各一条）
- 省事路线：<最小动作 + 拿到什么 + 大概要花多少功夫（区间 + 判断依据）>
- 彻底路线：<要补的证据或要动的位点 + 代价与工期>
- 不建议做：<哪条路会白费或越界，为什么>

## 5 怎么复查（复查单路径 + 关键重放命令 + 期望看到什么）
- 复查单：`python Tool/scripts/case_state.py recheck --case work/<case>` → 生成 `work/<case>/recheck.md`（目标哈希 / 环境 / 重放命令）
- 重放：<本域脚本命令；Windows 的 cmd 与 PowerShell 都能直接粘贴，见文末复跑命令>
- 期望：<关键字段或输出片段>；对不上先查「已知会变」（在线服务 / 证书 / IP / 时钟）

## 6 目标与授权
- 目标：<域 / CA / AWS 账号 / K8s 集群 / 订阅>
- 授权：<授权编号 / 只读 / 是否允许认证验证 / 时间窗 / 速率>
- 范围外：<生产写操作 / 持久化 / 他人账号 / 跨租户>
- 环境：<DC / CA / 云区域 / kubeconfig 来源 / 工具版本>

## 7 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/ad-repro.json | <sha256> | `python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --input <bundle> --json` | 0 | ADCS/Kerberos/RBAC |
| E02 | artifacts/iam-eval.json | <sha256> | `python Tool/skill/_pending/ad-cloud/scripts/cloud-iam-eval.py --input <policy> --action <a> --resource <r>` | 0 | IAM allow/deny |
| E03 | artifacts/adcloud-check.json | <sha256> | `python `Tool/skill/_pending/ad-cloud/scripts/adcloud-check.py` --kubeconfig <kc> --json` | 0 | 本地 kubeconfig/AWS |

## 8 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| ACL/属性 | 原始 ACL/属性可读且与图谱一致 | <实测> | E01 | <结论> |
| ADCS | 模板可 Enroll + 证书可 auth 出 TGT/ccache | <实测> | E01 | <结论> |
| Kerberos | 票据/委派/S4U 有可复现响应 | <实测> | E01 | <结论> |
| IAM | 文本 allow 且 boundary/SCP 不拦，实际只读 API 成功 | <实测> | E02 | <结论> |
| K8s RBAC | subject 匹配 + verb/resource allow + auth can-i 一致 | <实测> | E01/E03 | <结论> |
| 高风险检测 | API 时间/调用者/策略版本/资源四者对位 | <实测> | E02 | <结论> |

## 9 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 只有 LDAP/图谱边，无原始属性 | <yes/no> | E01 | 标 candidate，补只读属性 |
| 证书签发但 auth 失败/KDC_ERR | <yes/no> | E01 | ESC 不成立，转 ESC4/ESC5 |
| signing/EPA 已开、CA 拒绝模板 | <yes/no> | E01 | 停 relay，换面 |
| IAM 文本 allow 但 API AccessDenied | <yes/no> | E02 | 记未建模条件，不写提权 |
| 名称像高权但绑定窄/全 no | <yes/no> | E01/E03 | blocked，转 Secret/CI |
| 凭据/票据明文落盘 | <yes/no> | - | 立即脱敏/删除并上报 |

## 10 影响与边界
- 影响：<可达对象 / 可读数据 / 可发证书 / 可枚举资源>
- 边界：<只读验证 / 单账号 / 未触碰生产>
- 误报风险：<蜜标、受保护对象、托管服务覆盖 CIS、合法自动化>
- 未覆盖：<未验证的路径、未拿到的日志、未建模的 SCP>

## 11 修复建议（厂商视角）
1. ADCS 强制 EPA/HTTPS、禁用 NTLM relay、收紧模板 SAN 与审批，监控 ESC 配置漂移。
2. 域内最小权限：清理 GenericAll/WriteDACL，启用 Tier 模型与 LAPS，监控 DCSync 权限。
3. IAM 移除 `*` 资源与 PassRole/CreatePolicyVersion 组合，边界策略与 SCP 双保险。
4. K8s 禁用匿名、收敛 cluster-admin、启用 PSA/审计日志，SA token 短时化。

## 12 复跑命令
```bash
python Tool/skill/_pending/ad-cloud/scripts/ad-repro.py --input work/<case>/artifacts/bundle.json --json
python Tool/skill/_pending/ad-cloud/scripts/cloud-iam-eval.py --input work/<case>/artifacts/policy.json --action s3:GetObject --resource '*'
python `Tool/skill/_pending/ad-cloud/scripts/adcloud-check.py` --kubeconfig work/<case>/artifacts/kubeconfig.yaml --json
```
