# 已知延迟项（审计遗留）

> 本文件是审计延迟台账；`ROADMAP.md` 只写「现在能做什么 / 下一步」。
> 每条都写现状与触发条件，不承诺没有排期的能力。

## 台账

| # | 延迟项 | 现状 / 触发条件 |
| :-- | :-- | :-- |
| D1 | Web 判据表仍有 XSS/SSRF/反序列化的“浏览器执行/OOB 回连”靠人填证据 | 需要浏览器与外带基础设施；当前靠 `web-repro.py` 归一化 + 人工证据 |
| D2 | ad-cloud 无**第二个**真实 AD/ADCS/K8s 案例 | 本机 `PartOfDomain=False`、`klist` 无票据（证据在 `ad-cloud03` lessons），需授权域环境 |
| D3 | 字节级复跑：抓包/端口/路径随机器变化 | `generated_at` 已改为按 `SEEP_TIMESTAMP` 写、输出统一 LF；网络抓包天然非确定，判定口径为「归一化 JSON 相等」 |
| D4 | 失败判据的“代价”列部分只有风险描述，缺工时/机器/停手阈值 | 下一版统一 low<10min / medium<1h / high 需换机器 |
| D5 | `--domain` 单域模式只做本域检查，链接/路由/清理/部署属全局项 | 交付前必须跑 `--all` 或 `preflight.py` |
| D6 | task cards 已可执行但未做成“剧本级”（命令 + 退出码 + 期望输出） | 高频卡优先 |
| D7 | 归档库（`Tool/cases/_archive/`、`kb/_archive/pe-reverse/`）未纳入检索 UI | 内容完整、索引可读；`seep_kb_search` 默认只搜 board |

| D10 | `driver-triage.py`（IOCTL 评分/WDAC-HVCI 加载性）未实现 | 2026 内核面知识已进 KB；脚本需真实驱动样本，排下一批 |
| D11 | 判据字段「脚本背书」为「每域 ≥1」而非 ≥80% | 严格阈值会误伤仍在人读的证据；先监控比例（门禁 detail 有分子/分母） |
| D12 | iOS / 反作弊 / 托管运行时为路由 + KB 级覆盖 | 未升独立技能；连续 3 个案例稳定后再升 |
