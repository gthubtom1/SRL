# K8s RBAC、工作负载身份与容器隔离

入口：[SKILL](../SKILL.md)。输入为用户侧已过滤的身份/集群别名、绑定/rules、安全工作负载配置、runtime 版本、既有审计与测试结果。Agent 不读取 kubeconfig、SA Token、Secret.data/stringData、registry 凭据、节点 key/证书私钥或环境秘密；exec 插件也可能执行代码，不能把“离线看 kubeconfig”默认当安全解析。

## 认证与授权分开

从用户侧认证摘要核集群/namespace/subject/组与采集时点，不能从 SA 名称、未经验证的 claims 或配置中 user 为空推出身份/匿名访问。实际匿名认证、RBAC 与后续 admission/Quota/运行时结果分别核。

| 权限/配置 | 必须核的条件 | 当前可确认范围 |
|---|---|---|
| Role/ClusterRole 与 binding | 精确 subject、组、roleRef、namespace、聚合规则、verb/resource/subresource/resourceNames | 有效权限配置；不存在一般 RBAC deny 规则，其他授权器/后续阶段另核 |
| can-i/rules review | 用户侧实际身份、目标动作/namespace/名称与结果时点；rules review 是否标 incomplete | 权限决策，不代表动作完成；rules review 不完整不能证明无权限 |
| get/list/watch secrets | 各动作与资源范围、可见性/审计 | 都可能泄露对象正文；不以 list 为“只取名字”的安全保证，不发起真实 Secret 查询 |
| create pods/daemonsets/jobs | PSA/admission、Quota、镜像策略、serviceAccount、volume/securityContext 限制 | 工作负载创建能力候选，不证明节点逃逸；不创建资源或改现有工作负载 |
| impersonate/bind/escalate | 精确目标主体/角色、动作与命名限制、当前授权机制 | 配置风险；不 impersonate 高权主体或建立/更新绑定验证 |
| pods/exec、ephemeralcontainers、nodes/proxy | 精确子资源、实际 API 动词/路径和适用版本 | 远程访问/修改风险；不执行容器命令、注入 debug 容器或经 kubelet 运行命令 |

用户侧可核预先准备的无秘密 canary：优先读取隔离测试 namespace 中的公开标记对象并测试允许/拒绝；若要核 Secret 特定策略，由用户准备只含合成公开标记的测试对象且只返回非秘密结果。不得为了 canary 将真实生产 Secret 交 Agent，也不由本技能创建/变更测试资源。

## 身份投影与挂载

核 automountServiceAccountToken、projected/legacy 挂载声明、serviceAccountName、audience、TTL 与轮换配置、Workload Identity 绑定；只看配置和用户侧安全认证结果，不 cat/解码 JWT 或把它放入 curl/header。配置 TTL 不证明当前令牌未过期，真实令牌生命周期由用户侧验证。

K8s 版本、发行版和授权器影响特权组行为；不能把 subject 含 system:masters/cluster-admin 当通用免鉴权结论。401/403 是该路径的响应，不能在未知代理/认证链时唯一归因为过期或 RBAC。

## 隔离配置与节点风险

| 面 | 配置/既有遥测依据 | 反证与执行边界 |
|---|---|---|
| privileged/capability | Pod 与容器 securityContext、有效 capability、设备访问、userns、seccomp/LSM、节点版本 | 单项配置不证明可控制宿主；不 mount/unshare/nsenter、改接口或注入进程 |
| hostPath | volume 来源、路径、mount propagation、只读/写及节点策略 | 只读也可能暴露秘密；emptyDir/容器根不能冒充宿主。不读取宿主文件/凭据 |
| hostPID/hostNetwork | 实际 namespace 配置、已有节点/容器审计 | hostNetwork 不是宿主文件系统；PID 1 可能仍在容器，不通过执行命令探测逃逸 |
| runtime socket | 挂载/权限/代理配置和既有访问审计 | socket 文件存在/可写位不证明 API 可用；不调用 socket 建特权容器或枚举业务内容 |
| runtime/cgroup 漏洞 | 准确版本、发行版 backport、漏洞公告前提与配置 | 版本命中不等于可利用。release_agent 属 cgroup v1 机制，不存在通用“v2 同样写 agent”步骤；不改 cgroup/runtime 或跑 payload |

若调查已有逃逸事件，需独立节点审计、进程/namespace/容器身份与时间关联；容器自报 hostname/id 不足以证明宿主控制。只保留安全证据，不读取 shadow/kubelet.conf、挂载节点根或覆写 runtime 来补确认。

## 控制面与供应链

kubelet 的 /pods、/metrics、版本/health 响应不证明 exec/run；API 代理、流协议/版本、认证/授权应分别核，不用裸 HTTP 状态码判已执行。etcd 的 health/version 不证明 key/value 可读，不发起 /registry/secrets 范围读取或导出 snapshot。

admission 的 failurePolicy、namespaceSelector/objectSelector、PSA 标签与集群默认级别需核实际匹配语义和已存在审计；选择器为空通常全匹配，不能凭一个星号/标签猜覆盖。Ignore 也不代表服务正常时无检查。不改标签、禁用 webhook、写静态 Pod 清单或制造故障验证绕过。

镜像/CI 风险用 digest、SBOM、安装/触发链、Secret 引用和用户侧安全报告分析；不 secret dump、读 registry 配置、docker login 或推送镜像试用凭据。组件漏洞、配置宽松、数据流可达和实际行为分别给证据，不能互相替代。

## 正反例与交付

正例：用户侧测试角色在指定 namespace 可读公开 ConfigMap canary，另一角色拒绝，与同版本绑定一致；确认该测试读取策略。反例：can-i create pods=yes、privileged=true 或一项 CVE 命中，不能写“已逃逸/可读所有 Secret”。

交付配置来源/版本、主体与资源别名、授权/执行阶段、安全结果、支持/反证、未覆盖 namespace/授权器/节点及恢复条件。缺安全输入、预算到限或同形失败两次停止，不换身份/节点/Secret 来源继续。

历史原件 `Tool/skill/_pending/ad-cloud/references/k8s-and-container.md` 仅用于溯源，其中 Token 读取、mount/nsenter、Secret/etcd 导出、特权容器与清理命令不作为当前执行步骤。云身份见 [cloud-native](cloud-native.md)，失败处理见 [02-failure-criteria](02-failure-criteria.md)，结果回同一 project/version/run。
