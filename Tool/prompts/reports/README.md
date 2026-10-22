# 报告模板总览

> 10 个域各一份，复制到 `work/<case>/report.md` 后填写。只写有证据的结论：
> `confirmed`（判据全中且可复跑）/ `candidate`（线索或环境不足）/ `blocked`（失败判据命中）。
> 单份模板 ≤60 行；不要把“疑似”写成“确认”。

## 用法

1. `python Tool/scripts/seep-start.py --domain <域> --case <case> [--target <路径>]`
2. 把原始输出放进 `work/<case>/artifacts/`，命令与 rc 写进模板「证据清单」。
3. 逐条填「判据命中表」与「失败判据记录」；缺证据的判据只能记 `candidate`。
4. 复跑命令必须从仓库根可执行；路径用相对路径或 `work/<case>/...`。

## 证据目录规范

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

## 模板索引

| 域 | 文件 | 主要判据 |
|---|---|---|
| web-pentest | `web-pentest.md` | 3/3 对照、越权唯一标记、缓存键歧义 |
| pwn-crypto | `pwn-crypto.md` | 偏移/保护位、密码回代、崩溃可复现 |
| firmware-iot | `firmware-iot.md` | 容器偏移/rootfs、J1/J2/J3、升级签名 |
| ad-cloud | `ad-cloud.md` | ACL/属性复现、证书+TGT、RBAC 绑定 |
| protocol-plugin | `protocol-plugin.md` | 帧长/CRC、状态机边覆盖、重放响应 |
| plugin-targets | `plugin-targets.md` | manifest/入口、update_url、asar integrity |
| forensics-mobile | `forensics-mobile.md` | 四要素、哈希复算、多源时间线 |
| malware-analysis | `malware-analysis.md` | 静态高≠恶意、IOC 可复现、行为证据 |
| supply-chain-security | `supply-chain-security.md` | SBOM 触达、CI 权限/pin、resolved/integrity |
| reverse | `reverse.md` | 入口/符号、OEP/IAT、状态字+UI 三重证据 |

## 交付前自检

- [ ] 每个 confirmed 都有 ≥1 个 E 编号与可复跑命令（含 rc）。
- [ ] 失败判据命中时已写“降级/转路线/停”，没有硬写成功。
- [ ] 影响与边界、厂商修复建议各至少 2 条。
- [ ] 证据哈希复算一致；脱敏完成；`report.md` 与 `scope.md` 同目录。
