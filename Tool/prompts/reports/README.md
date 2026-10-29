# 报告模板总览

> 9 个正式域各一份，复制到 `work/<case>/report.md` 后填写。只写有证据的结论：
> `confirmed`（判据全中且可复跑）/ `candidate`（线索或环境不足）/ `blocked`（失败判据命中）。
> 单份模板 ≤90 行（五段固定 + 各域技术表）；不要把“疑似”写成“确认”。

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

## 6 用法

1. `python Tool/scripts/case_state.py init --domain <域> --case <case> [--target <路径>]`（旧 seep-start 已删：它就是 init + 目录布局）
2. 把原始输出放进 `work/<case>/artifacts/`，命令与 rc 写进模板「证据清单」。
3. 逐条填「判据命中表」与「失败判据记录」；缺证据的判据只能记 `candidate`。
4. 复跑命令必须从仓库根可执行；路径用相对路径或 `work/<case>/...`。

## 7 证据目录规范

```
work/<case>/
├── scope.md          # 目标、授权、时间窗、范围外、速率/只读边界
├── artifacts/        # 原始 JSON/日志/截图/导出的帧；不手改，只追加
│   ├── <tool>-<yyyymmdd-HHMMSS>.json
│   ├── <tool>-<yyyymmdd-HHMMSS>.log
│   └── SHA256SUMS    # 每个 artifact 一行：<sha256>  <文件名>
└── report.md         # 本模板填好的报告（结论、证据编号、复跑命令）
```

- 输入样本放 `artifacts/input/` 或只读挂载；原件只读，分析在副本上做。
- 每份证据在「证据清单」有编号 E01/E02…，表格里必须能反查到文件与命令。
- 含凭据/token/私钥的输出先脱敏（只留指纹），不得落明文。
- `generated_at`/时间戳若影响确定性，统一写 UTC；重跑前先记录输入 sha256。

## 8 模板索引

| 域 | 文件 | 主要判据 |
|---|---|---|
| web-pentest | `web-pentest.md` | 3/3 对照、越权唯一标记、缓存键歧义 |
| pwn-crypto | `pwn-crypto.md` | 偏移/保护位、密码回代、崩溃可复现 |
| firmware-iot | `firmware-iot.md` | 容器偏移/rootfs、J1/J2/J3、升级签名 |
| protocol-plugin | `protocol-plugin.md` | 帧长/CRC、状态机边覆盖、重放响应 |
| forensics-mobile | `forensics-mobile.md` | 四要素、哈希复算、多源时间线 |
| malware-analysis | `malware-analysis.md` | 静态高≠恶意、IOC 可复现、行为证据 |
| supply-chain-security | `supply-chain-security.md` | SBOM 触达、CI 权限/pin、resolved/integrity |
| apkseep | `apkseep.md` | APK 身份、壳/层归属、补丁最小性、安装后闭环 |
| softseep | `softseep.md` | 入口/符号、OEP/IAT、状态字+UI 三重证据 |

## 9 交付前自检

- [ ] 每份报告都过得了 `python Tool/scripts/case_state.py report --check --file <报告>`（五段齐全、结论 ≤3 行、已确认带编号）。
- [ ] 每个 confirmed 都有 ≥1 个 E 编号与可复跑命令（含 rc）。
- [ ] 失败判据命中时已写“降级/转路线/停”，没有硬写成功。
- [ ] 影响与边界、厂商修复建议各至少 2 条。
- [ ] 证据哈希复算一致；脱敏完成；`report.md` 与 `scope.md` 同目录。
