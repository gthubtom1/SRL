# AD & Cloud 知识库 — 域内攻击链与云原生

> Board：`ad-cloud`。配套技能：`Tool/skill/ad-cloud/SKILL.md`。
> 只处理已授权的内网/云环境；结论必须是可复现的凭据或权限提升证据，不做 Web 漏洞。

## 这个板卡管什么

- AD 枚举与 BloodHound、Kerberoasting/AS-REP、委派、NTLM relay、PtH/WMI/WinRM/SMB 横向。
- ADCS 枚举与 ESC1–ESC8 的条件、命令、成功/失败判据。
- 云原生：AK-SK 泄露、实例元数据 SSRF、K8s RBAC、容器逃逸、CI/CD 凭据链。
- 不负责：纯 Web/API 漏洞（`web-pentest`）、二进制逆向（`ida-reverse`）、
  固件/IoT（`firmware-iot`）。

当前技术页：

- [01 Kerberos 与 ADCS](techniques/01-kerberos-and-adcs.md)
- [02 K8s 与容器](techniques/02-k8s-and-container.md)

## 怎么用

1. 先钉授权边界、域信息、凭据来源和锁定策略；每条凭据先做一次低噪音校验。

```bash
export DOMAIN='corp.local' DC='10.0.0.10' USER='alice' PASS='P@ssw0rd'
nxc smb "$DC" --pass-pol -u '' -p ''
nxc smb "$DC" -u "$USER" -p "$PASS" -d "$DOMAIN"
ldapsearch -x -H "ldap://$DC" -D "$USER@$DOMAIN" -w "$PASS" -b 'dc=corp,dc=local'
python Tool/scripts/adcloud-check.py --kubeconfig ~/.kube/config
```

2. 按信号选页：

| 信号 | 先读 |
|---|---|
| 88/389/445 开放、有域账号、SPN/委派/ADCS | `01-kerberos-and-adcs.md` |
| kubeconfig、SA token、容器内、CI runner | `02-k8s-and-container.md` |
| AK-SK/元数据 SSRF/云身份 | 技能 `references/cloud-native.md` |
| BloodHound/ACL/relay/横向 | 技能 `references/ad-attacks.md` |

3. 每个动作记录：命令、时间、源/目标、返回码、关键输出；凭据只留类型、来源、
   有效期、SHA256 前 8 位。工具参数随版本变化（`certipy`、`nxc`、FirmAE 类工具），
   按本机版本核对，不现场编造命令。

4. 验收三条同时满足：凭据可复现、权限提升可见证（`whoami /all`、`auth can-i`、
   `sts get-caller-identity`）、证据可归档。缺一条只能写“待验证”。

## 和哪个技能配合

| 场景 | 技能路径 |
|---|---|
| 主流程、判据、坑与边界 | `Tool/skill/ad-cloud/SKILL.md` |
| AD 枚举/ACL/relay/横向细节 | 技能 `references/ad-attacks.md` |
| 云身份/元数据/CI 凭据 | 技能 `references/cloud-native.md` |
| Web/API 入口或应用层漏洞 | `Tool/skill/web-pentest/SKILL.md` |
| 镜像/依赖/CI 制品供应链 | `Tool/skill/supply-chain-security/SKILL.md` |
| 拿到主机后的二进制分析 | `Tool/skill/ida-reverse/SKILL.md` |

## 边界

- 不做未授权钓鱼、免杀、供应链投毒、生产拒绝服务；不删除/篡改日志。
- 域内认证失败默认 ≤3 次/账号，实际按 2 次停；避开业务高峰。
- 不默认持久化；持久化必须单独授权并登记清理方式。云上不创建计费资源、
  不修改 IAM/集群策略（除非授权且已备份）。
