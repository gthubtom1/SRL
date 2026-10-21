# forensics-mobile 任务卡（24 张）

> 用法：按触发词选卡；每张卡的 `reference` 指向本域 references 的具体篇。
> 铁律：原件只读、副本分析、全程哈希、时间统一 UTC、结论四要素；失败按 `02-failure-criteria.md` 停/降级。

### 01 内存镜像与 Volatility3 插件链（源：performing-memory-forensics-with-volatility3-plugins）
- 触发词：内存镜像、mem.raw、volatility3、pslist、psscan、malfind
- 前置：镜像哈希/采集记录/OS 版本；只读副本；授权范围
- 步骤：1) `banners`/`info` 定版本 2) `pslist`+`psscan` 差集 3) `cmdline`/`netscan`/`malfind` 落 PID 4) dump 可疑页并算哈希
- 判据：进程起止/父子/命令行/外联可列；dump 可二次识别
- 失败判据：符号不匹配/pslist 空/差集无法解释 → `blocked_at: symbols`，降级 strings
- reference：Tool/skill/forensics-mobile/references/02-failure-criteria.md

### 02 Windows 内存进程与网络归因（源：performing-memory-forensics-with-volatility3）
- 触发词：Windows 内存、netscan、cmdline、PID 归因、外联
- 前置：`windows.info` 成功；pcap/主机日志可用则一起对齐
- 步骤：1) 拉进程表与连接表 2) 按 PID 合并命令行/用户/模块 3) 与 pcap 五元组对齐 4) 标 observed/inferred
- 判据：连接能落到 PID+时间+五元组；主体（用户/SID）明确
- 失败判据：只有内存侧或只有 pcap 侧 → 降为 inferred，不写“已外联”
- reference：Tool/skill/forensics-mobile/references/memory-forensics.md

### 03 崩溃转储与休眠文件解析（源：analyzing-memory-dumps-with-volatility）
- 触发词：crash dump、dmp、hiberfil、minidump、蓝屏
- 前置：确认转储类型/完整性/采集时间；记录系统 build
- 步骤：1) `file`/头识别 2) 选对应符号 3) 进程/模块/异常码 4) 与事件日志蓝屏记录对齐
- 判据：能说明崩溃进程/模块/异常时间；与 EVTX/转储头一致
- 失败判据：转储截断/符号缺失/只含内核页 → 只做字符串/异常码线索
- reference：Tool/skill/forensics-mobile/references/memory-forensics.md

### 04 Rekall/strings 降级内存取证（源：extracting-memory-artifacts-with-rekall）
- 触发词：rekall、strings、bulk_extractor、volatility 不可用
- 前置：首选工具缺失或符号不匹配；已记录降级原因
- 步骤：1) `strings`/`bulk_extractor` 取域名/路径/命令 2) 用已知进程/端口特征定位 3) 与磁盘/日志交叉 4) 标 unverified
- 判据：至少一条线索能被独立源验证；报告写明降级链
- 失败判据：只有字符串命中、无时间/主体 → 只写“线索”，不写结论
- reference：Tool/skill/forensics-mobile/references/02-failure-criteria.md

### 05 Plaso 时间线重建（源：performing-timeline-reconstruction-with-plaso）
- 触发词：plaso、log2timeline、psort、plaso 存储、时间线重建
- 前置：镜像/目录/日志副本；时区/时钟偏差记录；输出目录可写
- 步骤：1) `log2timeline.py` 建 plaso 2) `psort.py -z UTC` 导出 3) 按来源/主体聚合 4) 标注冲突
- 判据：事件 UTC 可排序；来源/对象/主体/动作齐全；可复算
- 失败判据：时区缺失/解析器不匹配/输出截断 → 回退 mactime/fs-timeline
- reference：Tool/skill/forensics-mobile/references/disk-and-filesystem.md

### 06 超级时间线（多源合并）（源：building-super-timelines-with-plaso）
- 触发词：super timeline、多源时间线、EVTX+磁盘、跨设备
- 前置：至少两个独立证据源；每源有哈希/时区
- 步骤：1) 各源单独解析 2) 统一 UTC 3) 按时间排序并保留原值 4) 冲突并列
- 判据：跨源事件能对齐；冲突有解释；不掩盖矛盾
- 失败判据：时间差整数小时/纪元混用/源缺失 → 停，先校时区
- reference：Tool/skill/forensics-mobile/references/evidence-chain.md

### 07 Hayabusa EVTX 时间线（源：generating-forensic-timelines-with-hayabusa）
- 触发词：hayabusa、evtx 时间线、sigma、事件日志
- 前置：EVTX 副本；规则集版本记录；时区明确
- 步骤：1) 跑 hayabusa 输出 CSV/JSON 2) 按 EventId/Provider 聚合 3) 与 fs-timeline 对齐 4) 标检测规则误报
- 判据：事件数/首末时间可复算；规则命中可解释
- 失败判据：日志清除/规则版本不明/只输出告警无原始记录 → 降级原始 EVTX
- reference：Tool/skill/forensics-mobile/references/04-walkthrough-windows-evtx-registry.md

### 08 Timesketch 事件时间线协作（源：building-incident-timeline-with-timesketch）
- 触发词：timesketch、事件时间线、协作、调查
- 前置：时间线已归一 UTC；数据脱敏；访问授权
- 步骤：1) 导入 JSON/CSV 2) 建 sketch/timeline 3) 打标签/保存查询 4) 导出结论与证据引用
- 判据：查询可复现；事件到原始证据可追溯
- 失败判据：时间线未脱敏/缺原值/无证据引用 → 不共享，回本地
- reference：Tool/skill/forensics-mobile/references/evidence-chain.md

### 09 Autopsy 磁盘镜像分析（源：analyzing-disk-image-with-autopsy）
- 触发词：autopsy、磁盘镜像、数据源、文件系统
- 前置：镜像哈希/分区表；Autopsy 版本；只读数据源
- 步骤：1) 建 case/加数据源 2) 选分区/文件系统 3) 看文件/已删/时间线 4) 导出报告与哈希
- 判据：能定位 inode/路径/时间；导出内容哈希可校验
- 失败判据：分区偏移错/镜像加密/缩略图误判 → 回 sleuthkit 手工核对
- reference：Tool/skill/forensics-mobile/references/02-failure-criteria.md

### 10 dd/dcfldd 采集磁盘镜像（源：acquiring-disk-image-with-dd-and-dcfldd）
- 触发词：dd、dcfldd、镜像采集、块设备、哈希
- 前置：授权/只读挂载/目标空间；记录块大小/坏扇区策略
- 步骤：1) `lsblk`/设备确认 2) `dcfldd`/`dd` 只读采集 3) 同步算哈希 4) 记录采集日志
- 判据：镜像哈希与源一致（或说明坏扇区）；大小/扇区数一致
- 失败判据：设备写保护失败/空间不足/哈希不一致 → 停，重采
- reference：Tool/skill/forensics-mobile/references/disk-and-filesystem.md

### 11 $MFT 与已删文件恢复（源：analyzing-mft-for-deleted-file-recovery）
- 触发词：$MFT、MFT 记录、已删文件、inode 复用、恢复
- 前置：NTFS 镜像/`$MFT` 副本；`icat`/`istat` 可用
- 步骤：1) 定位 MFT/记录号 2) `istat` 看属性/时间 3) `icat` 取内容 4) 校验 magic/哈希
- 判据：内容可校验；`$SI`/`$FN` 时间并列；inode 复用被识别
- 失败判据：块被覆盖/内容乱码 → 标“不可恢复”，不引用
- reference：Tool/skill/forensics-mobile/references/disk-and-filesystem.md

### 12 Windows 注册表取证（源：analyzing-windows-registry-for-artifacts）
- 触发词：注册表、hive、NTUSER.DAT、reg save、UserAssist、Run
- 前置：`reg save` 副本或 hive 文件；带 LOG1/LOG2；权限记录
- 步骤：1) 校验 `regf` 头 2) 遍历 hbin/nk 3) 重建键路径/last-write 4) 对齐 EVTX/文件系统
- 判据：键路径/last-write 可复算；持久化项到键+值
- 失败判据：键级遍历 0/脏页未合并/父指针断链 → 降级头时间或 Registry Explorer
- reference：Tool/skill/forensics-mobile/references/memory-forensics.md

### 13 Amcache 程序执行痕迹（源：analyzing-windows-amcache-artifacts）
- 触发词：amcache、程序执行、安装痕迹、SHA1
- 前置：Amcache.hve 副本；系统版本；时区
- 步骤：1) 解析 Amcache 2) 取程序路径/哈希/时间 3) 与 Prefetch/EVTX 交叉 4) 标置信
- 判据：程序路径+哈希+时间齐全；与其它执行痕迹一致
- 失败判据：hive 损坏/时间字段缺失/仅文件名 → 降为线索
- reference：Tool/skill/forensics-mobile/references/disk-and-filesystem.md

### 14 ShellBag 目录访问痕迹（源：analyzing-windows-shellbag-artifacts）
- 触发词：shellbag、目录访问、USB、资源管理器
- 前置：UsrClass.dat/NTUSER.DAT 副本；用户 SID 明确
- 步骤：1) 解析 ShellBag 键 2) 还原目录路径/时间 3) 与 USBSTOR/lnk 交叉 4) 标主体
- 判据：目录路径+最后写入+用户可复述
- 失败判据：键损坏/路径断链/时间缺失 → 只写“曾访问”，不写“复制”
- reference：Tool/skill/forensics-mobile/references/disk-and-filesystem.md

### 15 LNK/JumpList 最近文件（源：analyzing-lnk-file-and-jump-list-artifacts）
- 触发词：lnk、jumplist、最近文件、快捷方式、目标路径
- 前置：LNK/JumpList 副本；用户目录/时区
- 步骤：1) 解析 LNK 头/目标/卷序列号 2) JumpList 取 AppID/条目 3) 与 ShellBag/EVTX 交叉 4) 标时间
- 判据：目标路径/卷/时间可复述；与文件系统时间线一致
- 失败判据：LNK 截断/目标不存在/时间只到本地 → 降为线索
- reference：Tool/skill/forensics-mobile/references/disk-and-filesystem.md

### 16 Prefetch 执行历史（源：analyzing-prefetch-files-for-execution-history）
- 触发词：prefetch、执行历史、pf、程序运行
- 前置：Prefetch 副本；Windows 版本（格式差异）；时区
- 步骤：1) 解析 PF 头/版本 2) 取可执行名/路径/运行次数/最后运行 3) 与 Amcache/EVTX 交叉 4) 标置信
- 判据：程序名+路径+运行次数+最后运行时间齐全
- 失败判据：PF 被禁用/损坏/版本不识别 → 换 Amcache/EVTX
- reference：Tool/skill/forensics-mobile/references/disk-and-filesystem.md

### 17 Eric Zimmerman 工具链解析（源：parsing-artifacts-with-eric-zimmerman-tools）
- 触发词：EZ Tools、MFTECmd、PECmd、EvtxECmd、JLECmd
- 前置：工具版本/输出目录；证据副本；时区
- 步骤：1) 选对应工具 2) 导出 CSV/JSON 3) 与 fs-timeline/EVTX 合并 4) 保留原始行/哈希
- 判据：导出字段可追溯到原始记录；时间 UTC 可排序
- 失败判据：工具版本不匹配/字段缺失/只给汇总 → 回原始解析
- reference：Tool/skill/forensics-mobile/references/disk-and-filesystem.md

### 18 浏览器 History 取证（Hindsight）（源：analyzing-browser-forensics-with-hindsight）
- 触发词：浏览器取证、History、Hindsight、places.sqlite、访问时间
- 前置：History 副本（含 WAL/SHM）；不读 cookies；授权
- 步骤：1) 只读复制 2) 解析 urls/visits 3) 时间纪元换算 4) 与下载/书签/EVTX 交叉
- 判据：URL+访问时间+行数可复算；不读取 cookie/Login Data
- 失败判据：时间落在 1601/1643/1970/缺 WAL → 先修换算/补副本
- reference：Tool/skill/forensics-mobile/references/04-walkthrough-windows-evtx-registry.md

### 19 Outlook PST 邮件取证（源：analyzing-outlook-pst-for-email-forensics）
- 触发词：PST、OST、邮件取证、附件、收发件人
- 前置：PST/OST 副本；密码/授权；时区
- 步骤：1) 只读打开 2) 导出邮件头/时间/收发件人 3) 附件哈希 4) 与网络/文件时间线对齐
- 判据：邮件时间/主体/对象/附件哈希齐全
- 失败判据：PST 加密/损坏/只有正文无头 → 标“不完整”，不引用
- reference：Tool/skill/forensics-mobile/references/01-criteria.md

### 20 USB 设备连接历史（源：analyzing-usb-device-connection-history）
- 触发词：USB、USBSTOR、设备连接、序列号、挂载
- 前置：SYSTEM hive/SetupAPI 日志/ShellBag 副本；时区
- 步骤：1) 解析 USBSTOR/Enum 2) 取 VID/PID/序列号/首次/最后连接 3) 与 ShellBag/lnk 交叉 4) 脱敏
- 判据：设备标识+连接时间+用户可复述
- 失败判据：hive 权限/日志缺失/序列号伪造 → 降为线索
- reference：Tool/skill/forensics-mobile/references/disk-and-filesystem.md

### 21 移动设备取证（Cellebrite 类）（源：performing-mobile-device-forensics-with-cellebrite）
- 触发词：移动取证、Cellebrite、手机备份、逻辑/物理提取
- 前置：设备授权/合法扣押；工具版本；提取类型
- 步骤：1) 记录设备/工具/提取类型 2) 逻辑/文件系统/物理提取 3) 校验提取哈希 4) 只分析副本
- 判据：提取范围/哈希/时间可复述；数据与应用对应
- 失败判据：设备锁定/加密/提取不完整 → 写 `blocked_at`，不猜内容
- reference：Tool/skill/forensics-mobile/references/ios-macos-artifacts.md

### 22 iOS 应用安全分析（Objection）（源：analyzing-ios-app-security-with-objection）
- 触发词：objection、iOS 应用、越狱检测、SSL pinning、运行时
- 前置：授权测试机/脱壳副本；frida-server 版本匹配；离线账号
- 步骤：1) 枚举应用/环境 2) 记录检测点 3) 只读观察 API 调用 4) 写绕过前后控制流差异
- 判据：检测点位置+设备状态+检测结果；不伪造“已绕过”
- 失败判据：加密二进制/attach 失败/触发反作弊 → 停，转静态/日志
- reference：Tool/skill/forensics-mobile/references/ios-macos-artifacts.md

### 23 Frida 逆向 iOS 应用（只读）（源：reverse-engineering-ios-app-with-frida）
- 触发词：frida、hook、iOS、函数参数、返回值
- 前置：授权测试机；frida-server 架构匹配；基线快照
- 步骤：1) `frida-ps -Uai` 定位 2) attach/launch 3) 记录参数/返回值/调用栈 4) 与落盘/网络对应
- 判据：二进制函数→运行时值→文件/网络链路可复述
- 失败判据：写内存/改返回值影响业务/触发保护 → 停，记录副作用
- reference：Tool/skill/forensics-mobile/references/ios-macos-artifacts.md

### 24 Docker/容器取证（源：analyzing-docker-container-forensics）
- 触发词：容器取证、docker、镜像层、容器日志、OverlayFS
- 前置：宿主机/容器只读副本；镜像/容器 ID；授权
- 步骤：1) 记录镜像/容器/挂载 2) 导出日志/配置/层 3) 定位进程/文件/网络 4) 与宿主时间线对齐
- 判据：容器 ID/镜像/挂载/日志时间可复述；文件哈希可校验
- 失败判据：容器已删除/层被覆盖/日志驱动不落盘 → 标“不完整”
- reference：Tool/skill/forensics-mobile/references/evidence-chain.md
