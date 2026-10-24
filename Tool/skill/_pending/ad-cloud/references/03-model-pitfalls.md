# 03 模型常见失误——内网 / AD / 云原生

> 范围：用 LLM/助手辅助 AD、ADCS、K8s、云 IAM 分析时，用来对照检查输出有没有“像结论的猜测”。
> 入口：纯工具语法/版本问题按工具安装页处理；本页只收模型判断失误。
> 每条格式：**错误动作 → 为什么错 → 正确动作**。看到自己在做左列，立即停并改右列。

### 1. 把 `cluster-admin` / `system:masters` 名称直接写成“已提权”

**错误动作**：看到 kubeconfig 里 SA 名叫 `cluster-admin`、JWT 组含 `system:masters`，就在报告里写“已获得集群管理员权限”。

**为什么错**：名称只是线索；RBAC 以 RoleBinding/ClusterRoleBinding 为准，token 还可能过期、被 API server 拒绝、被 Admission 限制。`system:masters` 是否生效取决于认证链和 API server 配置。

**正确动作**：先跑 `kubectl auth can-i --list` 与 `get clusterrolebinding -o wide`，用一次只读动作（`get pods -A`）证明；离线只写 `candidate`，并在 `adcloud-check.py` 输出里保留 `offline_limits`。

### 2. 把 Kerberoast 拿到的 TGS 写成“已拿到服务账号口令”

**错误动作**：`GetUserSPNs.py -request` 导出 hash 后，报告写“破解了 svc_sql”。

**为什么错**：拿到 TGS 只证明 SPN 可请求；没有 `hashcat` 命中或票据复用，就没有口令/会话。AES 账号（etype 17/18）用 RC4 字典还会假阴性。

**正确动作**：记录 etype、hash 指纹、破解命令与命中行；未命中就写“素材，未破解”，转 AS-REP/委派/ADCS。ad-repro 的 `kerberoast` 判定只会在 `cracked|reusable` 时给 `confirmed`。

### 3. 把 `certipy find` 的 vulnerable 当成“可利用 ESC1”

**错误动作**：`certipy find -vulnerable` 列出模板后，直接写“ESC1 可利用，可打域管”。

**为什么错**：find 只说明模板属性组合像 ESC1；还需当前账号有 `Enroll`、无需 manager approval、CA 允许 SAN/请求者提供 subject，最后 `certipy req` + `certipy auth` 成功才算。

**正确动作**：逐条核对 `enroll_allowed`、`san_enforced`、`manager_approval`、`ca_san_allowed`、EKU；只有拿到 pfx 且 auth 出 TGT 才写 `confirmed`，否则写 `candidate` 并给 blocker。

### 4. 把“有 `create pods`”写成“已容器逃逸”

**错误动作**：`auth can-i create pods` 返回 yes，就写“可逃逸到宿主”。

**为什么错**：create 权限只说明能建 Pod；是否允许 privileged/hostPath/hostPID、PSA/Quota/Admission 是否放行、节点是否有可用挂载，都是独立条件。没有宿主 `id` 或宿主文件读取，就没有逃逸证据。

**正确动作**：读 Pod Security Admission 与 namespace 标签；创建带标记的最小 Pod；只有读到宿主文件或在宿主命名空间执行 `id` 才写 `confirmed`，并记录清理。

### 5. 把“无凭据 user”写成“匿名可访问 API server”

**错误动作**：kubeconfig 里 user 没有 token/cert，就断言“API server 允许匿名访问”。

**为什么错**：没有凭据的 user 可能被 API server 直接拒绝；`--anonymous-auth=true` 也不等于匿名主体有 RBAC 权限。离线只能判定“本地没有凭据材料”。

**正确动作**：在线用只读请求确认是否以 `system:anonymous` 返回资源；同时查 API server 启动参数/托管配置。离线写 `anonymous_risk` 而不是“可访问”。

### 6. 把 AK/SK 前缀或 policy 名称当成“管理员权限”

**错误动作**：看到 `AKIA...` 或 policy 名叫 `AdministratorAccess`，就写“拥有管理员权限”。

**为什么错**：AK 前缀只表示长期/临时类型；policy 名称不决定内容，boundary/SCP/资源策略还可能收窄。凭据还可能已撤销/过期。

**正确动作**：`aws sts get-caller-identity` 确认身份；`list-attached-user-policies` + `get-policy-version` 读实际语句；用 `cloud-iam-eval.py` 对目标 action/resource 做离线复算，再在线验证。

### 7. 把 `Action:"*"` + `Resource:"*"` 直接判成“可提权”

**错误动作**：策略里有 `Action:*`/`Resource:*`，就写“可 CreatePolicyVersion 提权”。

**为什么错**：还要看 Effect、Condition、boundary、SCP、会话策略；即使文本 allow，实际凭据也可能被撤销或受组织策略限制。

**正确动作**：先看显式 Deny（优先）与 boundary/SCP；用目标 action/resource 跑评估；最后用只读 API 或 `simulate-principal-policy` 验证。文本 allow 只写 `candidate`。

### 8. 把 ADCS 的 pfx 当成“已经拿到域管 TGT”

**错误动作**：`certipy req` 成功拿到 `administrator.pfx`，报告写“已接管域管”。

**为什么错**：pfx 只是证书；`certipy auth` 可能因 EKU 不匹配、UPN/SAN 错、DC 时间偏移、证书链不受信而失败。没有 TGT/ccache 就没有域身份。

**正确动作**：立即跑 `certipy auth -pfx ... -dc-ip ...`；成功才写 `confirmed` 并保存 TGT 指纹/有效期；失败写 blocker（EKU/UPN/DC/时间），转其他模板或路径。

### 9. 把 Unconstrained 委派属性当成“已能读域控”

**错误动作**：`findDelegation` 看到 `TRUSTED_FOR_DELEGATION`，就写“可捕获域管 TGT”。

**为什么错**：unconstrained 需要攻击者能在那台主机上以管理员权限运行并等待/强制高权登录；没有可控主机、没有高权会话，就没有 TGT。

**正确动作**：先证明主机可控（本地管理员、可执行监控/导出票据）；再触发/等待目标登录；拿到 TGT 后导入并访问目标服务。缺主机控制就写 `candidate`。

### 10. 把 `auth can-i` 的 “yes” 当成“动作已成功”

**错误动作**：`auth can-i get secrets` 返回 yes，就写“已读取集群所有 Secret”。

**为什么错**：can-i 只做授权判定，不执行动作；Secret 可能为空、命名空间不对、API 被 admission 拒绝，或 token 在请求时已过期。

**正确动作**：实际执行最小只读动作（指定 namespace/name），保存返回对象与时间；能证明 Secret 可用（登录/拉镜像/调 API）才写凭据证据。

### 11. 把一条 4672 或 4624 当成“域内提权/横向成功”

**错误动作**：Security 日志里看到 4672 或 4624，就写“攻击者获得特殊权限/横向成功”。

**为什么错**：4672 常见于服务登录（LogonType 5），4624 也有本地/服务/网络多种类型；没有账号、来源、时间线、前后权限对比，单条事件不能归因。

**正确动作**：按 EventID + LogonType + 账号 + 来源聚合；结合 4768/4769/4776、进程创建、EDR 与变更记录；把 4672 当基线，除非有异常账号/时间/来源。

### 12. 把单机日志的“无 Kerberos 事件”写成“域内没有攻击”

**错误动作**：本机 Security 日志没有 4768/4769，就下结论“域内没有 Kerberos 攻击”。

**为什么错**：本机可能不是域成员、Kerberos 审计未开、日志被转发/清空；域内攻击证据通常在 DC 的 4768/4769/4771 与 CA 的 4886/4887。

**正确动作**：先查 `PartOfDomain`、审计策略、`Microsoft-Windows-Kerberos/Operational`；域内从 DC 取日志并记录 EventRecordID 连续性。单机缺失只写“本机无遥测”。

### 13. 在锁定预算内重复请求，靠“再试一次”求成功

**错误动作**：同一账号 Kerberoast/AS-REP/口令验证失败后，换工具同参数继续试。

**为什么错**：锁定预算按账号算，不按工具算；连续 4625/4771 会锁业务账号，且高保真告警会暴露。

**正确动作**：先 `--pass-pol` 读阈值；同一账号失败 2 次即停；换账号/来源/路径。ad-repro 在 `lockout_policy.failures_observed >= 2` 时直接给 `blocked`。

### 14. 为了“有结论”补写未执行的命令或伪造输出

**错误动作**：报告里写“已执行 certipy auth，成功”，但实际只跑了 find；或把教学夹具输出写成真实域结果。

**为什么错**：这是证据造假，直接破坏报告可信度；门禁/复算也会发现哈希、时间、rc 对不上。

**正确动作**：命令、rc、原始输出片段、产物 sha256 一一对应；没跑就写“未执行/下一步”；失败就写失败判据。`evidence_kind` 必须与 target_type 自洽。

### 15. 把“复制出 krbtgt/NTLM hash”写成“已控域”

**错误动作**：`secretsdump` 导出 `krbtgt:502:aad3b435b51404ee:...` 或域管 NT hash 后，报告直接写“已完全控域 / 可随时打黄金票据”。

**为什么错**：hash 只是材料。能不能用取决于：账号是否可用、KDC 是否接受该 key（krbtgt 密码轮换 2 次后旧 hash 立即失效）、是否有到 DC 的网络路径。造黄金票据还需要 domain SID + 目标用户名 + 正确 etype；没有 KDC 侧时间线就无法证明票据真的被接受。

**正确动作**：三步取证：① **可复用**——用 hash 做 PtH（`nxc smb <dc> -u <user> -H <hash>` 拿到 `Pwn3d!` 或读到文件），或用 krbtgt hash 造票后 `klist` + 访问 `cifs/<dc>` 成功；② **时间线**——DC 侧取 4769（TGS 请求：服务名/账号/来源 IP）与 4662（目录对象访问；需开 DS Access 审计，黄金票据常伴随对域对象的异常访问），按攻击窗口对齐；③ **指纹**——只留 hash 前 8 位 + sha256，不留明文。任一步缺只写 `candidate`。

## 失败判据

- 报告中出现“已提权/已打穿”但没有前后权限对比或可用凭据 → 退回 `candidate`。
- 报告把 find/can-i/策略文本当执行结果 → 补一次真实只读动作，或降级。
- 报告没有时间、来源、rc、指纹 → 证据不完整，不能归档为 `confirmed`。
- 同一账号认证失败 ≥2 次仍继续 → 立即停并换面。

## 边界

- 这些失误清单只覆盖判断与证据，不替代授权、速率、清理与法律边界。
- 不同工具版本输出字段会变；以本机 `--help` 与实际返回为准，不照抄旧参数。
- 真实凭据/票据/证书只留指纹；失误复盘也不得回填明文。
