# 03 · 模型常见失误（取证 / 移动 / 游戏客户端）

> **适用**：让模型或助手独立做取证时的“高危直觉”。每条都给：错误动作 → 为什么错 → 正确动作。
> **不适用**：已有人工复核且证据链完整的报告；这里不是工具手册，而是纠偏清单。
> 用法：出现任一错误动作，先停，回到 `01-criteria.md` 找对应判据。

## 1. 把“工具跑通”当“证据闭环”

### 01 看到 `vol.py pslist` 有输出就写“进程列表正常”
- **错误动作**：只贴 `pslist` 表，不跑 `psscan`，不写 PID/PPID/时间。
- **为什么错**：`pslist` 依赖活动进程链表，隐藏/已退出进程不在链上；表里有进程不等于没有注入。
- **正确动作**：`pslist` 与 `psscan` 做差集；对差集逐 PID 拉 `cmdline`/`dlllist`/`malfind`；结论写“差集 N 个，其中 M 个有解释”。

### 02 用 `strings` 命中域名就认定“外联”
- **错误动作**：`strings mem.raw | grep evil` 后直接写“主机访问了 evil”。
- **为什么错**：字符串可能来自浏览器缓存、日志、未执行代码或别的进程；没有五元组/时间/进程归属。
- **正确动作**：用 `netscan`/pcap 找五元组，再用 `cmdline`/`dlllist` 把连接归到 PID；找不到就标 `inferred`。

### 03 把 pcap 的单向包当完整会话
- **错误动作**：只过滤 `ip.src==x`，看到请求就写“上传成功”。
- **为什么错**：没有响应码/响应体，无法判断服务端是否接收；NAT/代理还会改变源。
- **正确动作**：`tcp.stream` 双向重组；看请求行、状态码、Content-Length、响应体；导出对象算哈希。

### 04 忽略时间纪元，浏览器时间线整体错位
- **错误动作**：把 Chromium `visit_time` 当 FILETIME 除以 10，得到 1643 年还继续写。
- **为什么错**：Chromium/Edge 是“1601 起的微秒”，FILETIME 是“1601 起的 100ns”，Firefox 是“1970 起的微秒”。
- **正确动作**：按库类型选换算；先抽样 1 条与 UI/日志对照；在产物里写 `timestamp_basis`。

### 05 分区偏移用字节，误判“文件系统损坏”
- **错误动作**：`fsstat -o 1048576 disk.img` 失败后写“镜像损坏”。
- **为什么错**：`-o` 要的是 `mmls` 的 Start **扇区号**，不是字节偏移。
- **正确动作**：`mmls` 取 Start，`fsstat -o <start> disk.img`；仍失败再抽分区头 `xxd` 核对。

### 06 直接打开原库/原 hive，污染 WAL 或锁文件
- **错误动作**：`sqlite3 evidence/History`、`reg load` 原 hive、在原镜像上挂载。
- **为什么错**：SQLite 会建 `-wal/-shm` 或回滚，注册表会写日志，挂载会改超级块/atime；证据哈希随即失效。
- **正确动作**：先只读复制（含 `-wal/-shm/-journal`），SQLite 用 `mode=ro&immutable=1`；hive 用 `reg save` 导副本；镜像只读挂载或 `icat`。

### 07 把 iOS 加密二进制当明文分析
- **错误动作**：`otool`/`strings` 看到少量符号就下结论“没有某功能”。
- **为什么错**：`cryptid=1` 时 `__TEXT` 加密，符号/字符串是密文或残缺；静态结论不可信。
- **正确动作**：先 `otool -l | grep -A6 LC_ENCRYPTION_INFO` 看 `cryptid`；在授权测试机脱壳后再分析；否则只写包结构/签名/权限。

### 08 IL2CPP 元数据版本错配还继续 dump
- **错误动作**：拿旧版 `Il2CppDumper` 对新版 `global-metadata.dat` 跑，输出空表仍写“没有该方法”。
- **为什么错**：元数据布局随 Unity 版本变化，错版本会解析出垃圾地址/类型。
- **正确动作**：先读 magic/version，核对 `GameAssembly`/`UnityFramework` 与 Unity 版本；换对应工具；仍不行标 `tool-missing`。

### 09 把 AssetBundle 头当“一定能解”
- **错误动作**：`xxd` 看到 `UnityFS` 就承诺“资源全导出”。
- **为什么错**：头正确只说明容器格式；加密/自定义压缩/版本差异会让资源解析失败。
- **正确动作**：先读头与 Unity 版本，跑 AssetStudio/UnityPy 小样本；失败就标“未解”，只给熵/字符串/大小。

### 10 在线游戏直接 attach/注入
- **错误动作**：在正式服对带 EAC/BattlEye/Vanguard 的进程 `frida -p` 或读内存。
- **为什么错**：可能触发封号、蓝屏、驱动对抗；也越过“只读外部观测”的边界。
- **正确动作**：先识别反作弊组件；线上只抓包/看日志/录屏；动态分析放离线副本/授权测试服，并写明环境差异。

### 11 只写“可疑”，不写主体/对象/时间
- **错误动作**：报告写“发现可疑外联和可疑文件”。
- **为什么错**：没有 PID/用户/五元组/路径/哈希，第三方无法复述，也无法排除误报。
- **正确动作**：每条结论填四要素：时间（UTC+原时区）、主体（PID/SID/UID/Bundle ID）、动作、对象（路径/inode/URL/五元组/键）+ 哈希。

### 12 把“日志里出现”当“真实发生”
- **错误动作**：应用日志写 `curl -d @/etc/shadow` 就认定数据被上传。
- **为什么错**：日志可被伪造/截断/重放；没有进程树、pcap、文件哈希交叉验证。
- **正确动作**：至少两个独立证据源交叉；缺一个就降为 `observed-log`；检查日志完整性/时钟。

### 13 哈希只算一次，后续产物覆盖原文件
- **错误动作**：分析脚本把 `timeline.json` 写进 `input/`，或导出对象覆盖同名证据。
- **为什么错**：原证据哈希变化，证据链断裂；同名对象还会互相覆盖。
- **正确动作**：`input/` 只读；产物写 `artifacts/`；导出对象按 `tcp.stream`/inode 建唯一名；每次写产物后重算并在案例记录。

### 14 时区/时钟偏差不写，直接排因果
- **错误动作**：把设备本地时间、服务器 UTC、采集机时间混在一张表里排序。
- **为什么错**：整数小时偏移会让先后关系反转，因果结论失效。
- **正确动作**：统一 UTC，保留原值/偏移/时钟偏差；跨设备先做 NTP/登录日志校准；冲突要显式列出。

### 15 把“未解/缺工具”写成“目标不存在”
- **错误动作**：AssetBundle 解不开就写“没有该资源”；hive 读不到就写“没有持久化”。
- **为什么错**：这是把工具能力边界伪装成事实；会让后续决策漏掉关键证据。
- **正确动作**：写 `blocked_at: tool-missing|permission|parse`，给降级链和已证实的范围。

### 16 把“Provider 名”当“主体”
- **错误动作**：CloudTrail 里看到 `userIdentity.type=AWSAccount`/`invokedBy=ec2.amazonaws.com` 就写“某个 AWS 服务登录了”或“某用户操作”；Windows 事件里把 `Provider Name=Microsoft-Windows-Security-Auditing` 写成操作主体。
- **为什么错**：Provider/服务名只是“日志来源或代调用方”，主体在 `userIdentity.arn`（`IAMUser`/`assumed-role/<role>/<session>`）、`SubjectUserName`/`SubjectUserSid`、`_UID`/`auid` 里；`invokedBy` 恰好说明真主体在别处，是推断依据而不是结论。
- **正确动作**：主体字段先写 `actor.type` 与 `actor.id`，再用 `cloudtrail.userIdentity.arn`/`subject_user_sid`/`auid` 填充；只有 `invokedBy` 时标 `inferred` 并写“需回查调用方”。

## 2. 自检清单（提交前）

- [ ] 每个结论都有时间/主体/动作/对象，且标了 `observed/inferred/unverified`。
- [ ] 每个证据文件都有 SHA256，原件只读，产物在 `artifacts/`。
- [ ] 时间线统一 UTC，保留原时区与时钟偏差；纪元换算有抽样对照。
- [ ] 至少一个独立证据源交叉；没有就把结论降级。
- [ ] 加密/未脱壳/版本不匹配/反作弊等边界，明确写“停在哪、代价是什么”。
- [ ] 对外分享前脱敏 URL 参数、用户名、SID、设备标识。

## 3. 失败判据（出现即回退）

- 结论缺主体/对象/时间：不许进结论段，回 `01-criteria.md` 补判据。
- 只有单源日志/字符串：标 `observed-log`/`inferred`，不写“已执行/已外联”。
- 时间纪元/时区未校准：先修换算，再排因果；否则整条时间线作废。
- 加密未脱壳/版本不匹配/工具缺失：写 `blocked_at`，不写“没有该功能/资源”。
- 哈希不一致/原件被写：停，重采或说明污染范围。

## 4. 边界

- 本清单只纠偏“模型直觉”，不替代工具手册与人工复核。
- 不提供注入/挂钩/改内存/反取证/绕过授权或反作弊的手法。
- 反作弊/授权边界内的停止记录要保留时间、环境、触发点。

> 相关：`01-criteria.md`、`02-failure-criteria.md`、`04-walkthrough-windows-evtx-registry.md`、`evidence-chain.md`。
