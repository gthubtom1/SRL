# AD & Cloud 知识库 — 域内攻击链与云原生

> Board：`ad-cloud`。配套技能：`Tool/skill/ad-cloud/SKILL.md`。
> 只处理已授权的内网/云环境；结论必须是可复现的凭据或权限提升证据，不做 Web 漏洞。
> 本板卡的目标不是“讲全攻击”，而是让每条路径都能回答：**判据是什么、失败长什么样、证据怎么留。**

## 这个板卡管什么

- AD 枚举与 BloodHound、Kerberoasting/AS-REP、委派、NTLM relay、PtH/WMI/WinRM/SMB 横向。
- ADCS 枚举与 ESC1–ESC8 的条件、命令、成功/失败判据。
- 云原生：AK-SK 泄露、实例元数据 SSRF、K8s RBAC、容器逃逸、CI/CD 凭据链。
- Windows 主机遥测：Security.evtx 的 4768/4769/4776/4624/4672 读法与误判。
- 不负责：纯 Web/API 漏洞（`web-pentest`）、二进制逆向（`ida-reverse`）、
  固件/IoT（`firmware-iot`）、供应链投毒（`supply-chain-security`）。

## 技术页索引（逐篇）

| 页 | 入口信号 | 内容 |
| :-- | :-- | :-- |
| [01 Kerberos 与 ADCS](techniques/01-kerberos-and-adcs.md) | 88/389/445 开放、有域账号、SPN/模板 | Kerberoast/AS-REP、ADCS ESC 条件与命令 |
| [02 K8s 与容器](techniques/02-k8s-and-container.md) | kubeconfig、SA token、容器内 | RBAC 枚举、逃逸面、Secret/CI |
| [03 K8s RBAC 到逃逸](techniques/03-k8s-rbac-escape.md) | `auth can-i` 有 create/get | 权限→逃逸/凭据的判定与命令 |
| [04 Kerberos 路径速判](techniques/04-kerberos-paths.md) | 有一个域账号，想选路径 | 路径选择表与第一条命令 |
| [05 ADCS ESC 判据](techniques/05-adcs-esc-decision.md) | `certipy find -vulnerable` 有输出 | ESC1–ESC8 成立条件、auth 验证 |
| [06 云凭据与元数据](techniques/06-cloud-credentials-metadata.md) | AK/SK、CI 变量、169.254.169.254 | 身份校验、元数据、IAM 权限面 |
| [07 失败判据](techniques/07-failure-criteria.md) | 路径卡住、只拿到素材 | 现象→判定→改走哪条→代价 |
| [2026 ESC17](techniques/2026-esc17-wsus-relay.md) | WSUS 为 HTTPS、ADCS 可 NTLM 注册 | `wsus_https`/`esc17_chain` 两字段与六段判据 |

## 三条硬判据

同时满足三条才算 `confirmed`，缺一条只能写 `candidate`/`blocked`：

1. **凭据可复现**：给出获取命令/路径与返回；换一台干净机器照做仍能得到同一凭据或同一权限。
2. **权限提升可见证**：`whoami /all`、`kubectl auth can-i`、`aws sts get-caller-identity`、域管组成员、
   宿主 `id`/宿主文件读取等客观输出证明权限级别变化。
3. **证据可归档**：命令、时间、源/目标、rc、原始输出片段、凭据/票据/证书指纹（不回传明文），
   能支撑报告复现。

## 怎么用（分析链）

1. 先钉授权边界、域信息、凭据来源和锁定策略；每条凭据先做一次低噪音校验。

```bash
export DOMAIN='corp.local' DC='10.0.0.10' USER='alice' PASS='<pass>'
nxc smb "$DC" --pass-pol -u '' -p ''
nxc smb "$DC" -u "$USER" -p "$PASS" -d "$DOMAIN"
ldapsearch -x -H "ldap://$DC" -D "$USER@$DOMAIN" -w "$PASS" -b 'dc=corp,dc=local'
python Tool/scripts/adcloud-check.py --kubeconfig ~/.kube/config
```

2. 按信号选页：

| 信号 | 先读 |
| :-- | :-- |
| SPN/委派/ADCS/票据 | `01-kerberos-and-adcs.md`、`04-kerberos-paths.md`、`05-adcs-esc-decision.md` |
| kubeconfig、SA token、容器内、CI runner | `02-k8s-and-container.md`、`03-k8s-rbac-escape.md` |
| AK-SK/元数据/IAM | `06-cloud-credentials-metadata.md`、技能 `references/cloud-native.md` |
| BloodHound/ACL/relay/横向 | 技能 `references/ad-attacks.md` |
| 卡住/只拿到素材/结论像猜 | `07-failure-criteria.md`、技能 `references/02-failure-criteria.md` |

3. 每个动作记录：命令、时间、源/目标、返回码、关键输出；凭据只留类型、来源、
   有效期、SHA256 前 16 位。工具参数随版本变化（`certipy`、`nxc`、`impacket`），
   按本机版本核对，不现场编造命令。

4. 离线复算优先：

```bash
python Tool/skill/ad-cloud/scripts/ad-repro.py --kind adcs --input adcs.json
python Tool/skill/ad-cloud/scripts/cloud-iam-eval.py --input policy.json \
  --action iam:CreatePolicyVersion --resource arn:aws:iam::123456789012:policy/demo
```

## 失败判据（看到即降级）

- 只有 hash/TGS/pfx/Secret，没有明文、TGT 或可用会话 → 素材，不是打穿。
- `certipy find` vulnerable 但无 Enroll/需审批/CA 拒绝 SAN → ESC1/6 不成立。
- SMB/LDAP signing 或 EPA 已开 → relay 停，转凭据直连或其他 ESC。
- `auth can-i` 全 no、PSA/Quota 拒绝、缺 `CAP_SYS_ADMIN` → 停手，转 Secret/CI。
- `sts get-caller-identity` 报 AccessDenied/ExpiredToken → 凭据无效，换来源。
- 同账号认证失败 ≥2 次 → 立即停，避免锁定。
- 单机日志缺 4768/4769 → 先查域成员/审计，不能写“域内安全”。
- 同一手法同参数连续失败两次 → 换路线，不重复撞。

逐条现象/代价见 [07 失败判据](techniques/07-failure-criteria.md)。

## 和哪个技能配合

| 场景 | 技能路径 |
| :-- | :-- |
| 主流程、判据、坑与边界 | `Tool/skill/ad-cloud/SKILL.md` |
| AD 枚举/ACL/relay/横向细节 | 技能 `references/ad-attacks.md` |
| 云身份/元数据/CI 凭据 | 技能 `references/cloud-native.md` |
| Kerberos/ADCS 命令细节 | 技能 `references/kerberos-and-adcs.md` |
| K8s/容器细节 | 技能 `references/k8s-and-container.md` |
| 委派/RBCD 深水 | 技能 `references/05-delegation-and-rbcd.md` |
| 真实日志走查 | 技能 `references/04-walkthrough-windows-auth-events.md` |
| Web/API 入口或应用层漏洞 | `Tool/skill/web-pentest/SKILL.md` |
| 镜像/依赖/CI 制品供应链 | `Tool/skill/supply-chain-security/SKILL.md` |
| 拿到主机后的二进制分析 | `Tool/skill/ida-reverse/SKILL.md` |

## 边界

- 不做未授权钓鱼、免杀、供应链投毒、生产拒绝服务；不删除/篡改日志。
- 域内认证失败默认 ≤3 次/账号，实际按 2 次停；避开业务高峰。
- 不默认持久化；持久化必须单独授权并登记清理方式。云上不创建计费资源、
  不修改 IAM/集群策略（除非授权且已备份）。
- 真实口令、hash、票据、证书私钥、AK/SK、token 一律不落盘/不回传；只留指纹与声明。
