# forensics-mobile 报告模板

> **客户视角五段（必须全在，缺一不算交付）**
>
> | 段 | 标题 | 内容要求 |
> | :-: | :-- | :-- |
> | R1 | 结论 | 能不能用 / 到哪一步（三句话之一）/ 卡在哪。**≤3 行** |
> | R2 | 已确认 | 每条：客户语言结论 + 证据 ID + 等级（E1–E4） |
> | R3 | 仍未知 | 每条：未知什么 + 为什么未知 + 缺什么才能知道 |
> | R4 | 下一步 | 省事路线 / 彻底路线 / 不建议做的事（各一条） |
> | R5 | 怎么复查 | 复查单路径 + 关键重放命令 + 期望看到什么 |

> 复制到 `work/<case>/report.md`。取证结论必须能回到采集记录与哈希。

## 1 目标与授权
- 目标：<镜像/EVTX/hive/APK/IPA/容器 / 来源 / sha256>
- 授权：<采集授权 / 只读封存 / 时间窗 / 责任人>
- 范围外：<主机清单由 scope 声明 / 真实凭据只留指纹 / 写回设备按授权单>
- 环境：<采集工具 / 时区 / 时钟偏差 / 文件系统>

## 2 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/check.json | <sha256> | `python Tool/skill/forensics-mobile/scripts/forensics-check.py --file <ev> --json` | 0 | 类型/时间/完整性 |
| E02 | artifacts/timeline.json | <sha256> | `python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input <ev> --out ...` | 0 | UTC 时间线 |
| E03 | artifacts/accept.json | <sha256> | `python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case <case> --json` | 0 | 四要素验收 |

## 3 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| 采集四要素 | 方法/工具/时间/责任人齐全，时区明确 | <实测> | E03 | <结论> |
| 哈希 | 输入与 artifacts sha256 复算一致 | <实测> | E01/E03 | <结论> |
| 时间线 | 多源事件 UTC 对齐，冲突已标注 | <实测> | E02 | <结论> |
| 浏览器/EVTX | 记录数/首末时间与原始字段一致 | <实测> | E01/E02 | <结论> |
| 移动包 | IPA/APK 结构、Info.plist、keychain 可见 | <实测> | E01 | <结论> |
| 只读封存 | artifacts 只读，未被分析过程改写 | <实测> | E03 | <结论> |

## 4 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 哈希不一致或采集记录缺失 | <yes/no> | E01/E03 | 停止引用该证据，重新采集 |
| 时间线只有单源/时区不明 | <yes/no> | E02 | 不写确定时间，标 unknown |
| EVTX/History 解析失败或截断 | <yes/no> | E01 | 记录工具/权限限制，补其它源 |
| Prefetch/日志被清 | <yes/no> | E01 | 转文件系统/网络/内存 |
| 真实凭据明文入报告 | <yes/no> | - | 立即脱敏/删除并上报 |
| artifact 可写被当已封存 | <yes/no> | E03 | 修正权限后重跑验收 |

## 5 影响与边界
- 影响：<可证明的登录/浏览/执行/外联行为>
- 边界：<单机/单用户/时间窗；未覆盖其它主机>
- 误报风险：<时钟偏差、浏览器缓存、构造夹具>
- 未覆盖：<未解析的容器、未导出的内存、未对齐的日志>

## 6 修复建议（厂商视角）
1. 终端启用集中日志与 NTP，EVTX/Prefetch 保留周期满足取证要求。
2. 磁盘/镜像采集使用写保护与哈希清单，证据目录只读封存。
3. 移动端启用数据保护/Keychain 访问控制，企业设备保留审计与远程取证能力。
4. 浏览器/应用日志记录用户、时间、对象与关联 ID，避免只留 UI 截图。

## 7 复跑命令
```bash
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file work/<case>/artifacts/AppReadiness.evtx --json
python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input work/<case>/artifacts/History.sqlite --out work/<case>/artifacts/timeline.json --json
python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case work/<case> --json
```
