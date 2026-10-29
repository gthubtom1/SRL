---
name: artifact-triage
description: "移动端已有沙箱制品与日志的元数据、内容身份和时间线对照；保持来源链，不采集真实凭据。"
metadata:
  version: "2.1.0"
  target_runtimes: "Android / iOS 制品；采集权限与平台工具须核验"
---

# 移动制品与时间线

复用 [证据链](../../references/evidence-chain.md)、[磁盘与时间戳](../../references/disk-and-filesystem.md)、[iOS 制品](../../references/ios-macos-artifacts.md)。输入应为用户已提供的安全工作副本、采集记录、行为时间窗与具体问题；Android 动态操作可由 apkseep 协助，iOS 实机权限单独核验。没有设备/访问权限时只分析已取得材料，不绕权限补采。

## 元数据与内容身份分开

Android 常见 CE 私有目录为 `/data/user/<user-id>/<package>/`，`/data/data` 可能是其兼容路径；DE 数据、工作资料、多用户及 scoped storage 路径不同。iOS 沙箱路径带安装时 UUID。不要把固定路径当完整覆盖。

操作前后快照分别列相对路径、类型、大小、权限、mtime/其他可得时间、采集时间与采集器版本；符号链接不盲跟，遍历错误和缺权限逐项保留。`ls -la` 不计算 MD5/SHA256，也不能提供可靠全量差分。内容哈希单列，使用 SHA256；新增/删除/内容改动和仅元数据改动分别报告。

只有已经过用户侧筛选、确认不含凭据/Key/Salt/私钥的制品才进入 Agent。不要先批量复制整个 shared_prefs、日志、数据库或 tombstone 再脱敏；也不对真实秘密计算“脱敏哈希”。当前工具不能安全筛选时记录位置、类别、不可观察范围，由用户完成受控核验。

## 采集与时间精度

快照尽可能来自同一一致性点，活动应用会并发写文件，分次 find/read 不能称原子快照。取样期间发生变化的文件需重采或明确不稳定，时间线不能混用两个时刻的 DB/WAL。

仅针对合成夹具、已确认可运行的测试应用，可用设备帮助支持的 `adb logcat --pid <PID> -v epoch` 或 `-v threadtime` 观察允许事件。`-v time` 本身不保证微秒精度，PID 重启会变化，过滤需重新绑定进程开始时刻；全量日志可能含真实凭据，不能直接重定向交给 Agent。日志可用字段/精度以该设备 `logcat --help` 和实际输出为准。

记录设备时间源、时区、主机/抓包相对偏差及测量误差；只读测量，不修改系统时钟。UTC 归一化保留原始时间与单位，偏差不确定时给区间。mtime 表示文件写入时间，数据库内部时间可能是业务时间；POSIX ctime 是元数据变化时间，不能泛称创建时间。拷贝也可能改变时间。

## 已有时间线入口

从源码根处理已确认安全的文件系统/受支持日志副本：

```bash
python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input work/safe-artifacts --kind filesystem --out work/timeline.json
```

该脚本支持的 EVTX/REGF/浏览器 SQLite 与文件系统时间线不等于任意移动日志解析；保留 max-events 截断和解析 warning。应用专有时间戳按其格式另核，不能强喂通用解析器。

## 正反例与验收

正例：合成测试写入非敏感标记文件，前后快照发现新增与 SHA256，应用事件、文件时间、抓包时间在误差范围内一致。反例：大小相同且 mtime 未变但内容哈希变化；仅 `ls` 差分会漏报。目录无权限或读取时变动必须报“不完整”，不能写“无变更”。

交付范围、来源/哈希、变更清单、时间换算和误差、已证/推导/未知及复查办法；“完整”仅相对于实际成功覆盖的快照范围。时间重合不证明因果，必要时请 malware-analysis 判断行为、protocol-plugin 重组会话。返回同一 project/version/run，采集污染或两次同形失败须停止并重判。
