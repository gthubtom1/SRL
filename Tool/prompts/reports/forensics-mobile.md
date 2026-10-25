# forensics-mobile 报告模板

> **客户视角五段（必须全在，缺一不算交付）**：下面五个是**真标题**——`python Tool/scripts/case_state.py report --check --file <本文件>`
> 按标题文字精确匹配「结论 / 已确认 / 仍未知 / 下一步 / 复查」，缺一段即 `[FAIL]`；每段标题下至少 2 行正文，
> 「结论」不超过 3 行，「已确认」里至少要有一个 `E-` / `C-` / `F-` 编号。「下一步 / 复查」别改名，改了检查器就找不到。

> 复制到 `work/<case>/report.md`。取证结论必须能回到采集记录与哈希。

## 1 结论（≤3 行：能不能用 / 到哪一步 / 卡在哪）
- 到哪一步：<只能看懂结构 | 能改到能用 | 能完全自己接管 | 现在做不了>
- 卡在哪：<卡点一句话 + 证据编号；没有卡点写「无」>
- 能不能用：<只按已有证据说一句；没跑过就写「未验证」>

## 2 已确认（每条：客户能听懂的一句话 + 证据 ID + 强度：强 / 中 / 弱）
- <客户能听懂的那句话>（`E-001`；强：同输入同输出可复现，命令与输出都能贴）—— 原始记录 `artifacts/<tool>-<时间>.json`
- <客户能听懂的那句话>（`E-002`；强：两路独立验证一致，不只是重复跑）—— 原始记录 `artifacts/<tool>-<时间>.json`
- 只有一次观测、没有可复跑命令的线索不进本段，写进第 3 段。

## 3 仍未知（每条：未知什么 + 为什么未知 + 缺什么才能知道）
- <未知什么>｜为什么未知：<环境限制 / 证据缺口 / 授权没给>｜还缺：<补什么才能知道>
- <未知什么>｜为什么未知：<同上>｜还缺：<同上>

## 4 下一步（省事路线 / 彻底路线 / 不建议做的事，各一条）
- 省事路线：<最小动作 + 拿到什么 + 大概要花多少功夫（区间 + 判断依据）>
- 彻底路线：<要补的证据或要动的位点 + 代价与工期>
- 不建议做：<哪条路会白费或越界，为什么>

## 5 怎么复查（复查单路径 + 关键重放命令 + 期望看到什么）
- 复查单：`python Tool/scripts/case_state.py recheck --case work/<case>` → 生成 `work/<case>/recheck.md`（目标哈希 / 环境 / 重放命令）
- 重放：<本域脚本命令；Windows 的 cmd 与 PowerShell 都能直接粘贴，见文末复跑命令>
- 期望：<关键字段或输出片段>；对不上先查「已知会变」（在线服务 / 证书 / IP / 时钟）

## 6 目标与授权
- 目标：<镜像/EVTX/hive/APK/IPA/容器 / 来源 / sha256>
- 授权：<采集授权 / 只读封存 / 时间窗 / 责任人>
- 范围外：<主机清单由 scope 声明 / 真实凭据只留指纹 / 写回设备按授权单>
- 环境：<采集工具 / 时区 / 时钟偏差 / 文件系统>

## 7 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/check.json | <sha256> | `python Tool/skill/forensics-mobile/scripts/forensics-check.py --file <ev> --json` | 0 | 类型/时间/完整性 |
| E02 | artifacts/timeline.json | <sha256> | `python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input <ev> --out ...` | 0 | UTC 时间线 |
| E03 | artifacts/accept.json | <sha256> | `python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case <case> --json` | 0 | 四要素验收 |

## 8 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| 采集四要素 | 方法/工具/时间/责任人齐全，时区明确 | <实测> | E03 | <结论> |
| 哈希 | 输入与 artifacts sha256 复算一致 | <实测> | E01/E03 | <结论> |
| 时间线 | 多源事件 UTC 对齐，冲突已标注 | <实测> | E02 | <结论> |
| 浏览器/EVTX | 记录数/首末时间与原始字段一致 | <实测> | E01/E02 | <结论> |
| 移动包 | IPA/APK 结构、Info.plist、keychain 可见 | <实测> | E01 | <结论> |
| 只读封存 | artifacts 只读，未被分析过程改写 | <实测> | E03 | <结论> |

## 9 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 哈希不一致或采集记录缺失 | <yes/no> | E01/E03 | 停止引用该证据，重新采集 |
| 时间线只有单源/时区不明 | <yes/no> | E02 | 不写确定时间，标 unknown |
| EVTX/History 解析失败或截断 | <yes/no> | E01 | 记录工具/权限限制，补其它源 |
| Prefetch/日志被清 | <yes/no> | E01 | 转文件系统/网络/内存 |
| 真实凭据明文入报告 | <yes/no> | - | 立即脱敏/删除并上报 |
| artifact 可写被当已封存 | <yes/no> | E03 | 修正权限后重跑验收 |

## 10 影响与边界
- 影响：<可证明的登录/浏览/执行/外联行为>
- 边界：<单机/单用户/时间窗；未覆盖其它主机>
- 误报风险：<时钟偏差、浏览器缓存、构造夹具>
- 未覆盖：<未解析的容器、未导出的内存、未对齐的日志>

## 11 修复建议（厂商视角）
1. 终端启用集中日志与 NTP，EVTX/Prefetch 保留周期满足取证要求。
2. 磁盘/镜像采集使用写保护与哈希清单，证据目录只读封存。
3. 移动端启用数据保护/Keychain 访问控制，企业设备保留审计与远程取证能力。
4. 浏览器/应用日志记录用户、时间、对象与关联 ID，避免只留 UI 截图。

## 12 复跑命令
```bash
python Tool/skill/forensics-mobile/scripts/forensics-check.py --file work/<case>/artifacts/AppReadiness.evtx --json
python Tool/skill/forensics-mobile/scripts/fs-timeline.py --input work/<case>/artifacts/History.sqlite --out work/<case>/artifacts/timeline.json --json
python Tool/skill/forensics-mobile/scripts/evidence-accept.py --case work/<case> --json
```
