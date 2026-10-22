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
| D6 | 任务卡剧本化 **已完成（v1.23.0）**：每域 5 张、共 60 条「命令+rc=0+期望」，150 条命令逐条实跑 | 全量 264 张剧本化排下一批 |
| D7 | 归档库（`Tool/cases/_archive/`、`kb/_archive/pe-reverse/`）未纳入检索 UI | 内容完整、索引可读；`seep_kb_search` 默认只搜 board |

| D10 | `driver-triage.py` **已实现（v1.23.0）**：815 行、self-test 19 项；HVCI/WDAC 仅静态线索 | 真实驱动样本复核 + 动态加载性判定排下一批 |
| D11 | 判据字段已改为「每个字段必须被脚本输出或在 inferred 白名单」，11 域 0 未覆盖 | 下一批把白名单占比降到 20% 以下 |
| D12 | iOS / 反作弊 / 托管运行时：已有独立 KB board（各 4 篇+README）与 R26/R29/R33 路由 | 未升独立技能；连续 3 个案例稳定后再升 |

## v1.25.0 终版后的 P1 台账（按使用顺序补）

| id | 项 | 触发条件 |
| :-- | :-- | :-- |
| D13 | B 报告 10 条深度 P1（sign-recompute / tls-decrypt / license-locate / permission-evidence / ipc-audit / yara-write 等） | 该能力被真实任务用到时，按 `docs/audit/CLOSURE.md` 对应行补脚本 |
| D14 | D 报告 4 条架构 P1（4 套注册表合并、能力独立判据、routing `playbook` 字段、new-skill 词边界） | 新增域/新增能力时优先做；不阻塞既有 11 域 |
| D15 | probe 级能力（`maturity=probe`）补独立脚本 | 该能力第一次产出真实案例时 |
| D16 | 11 个存量脚本失败路径 rc 不统一（裸 Traceback / rc=1 纯文本） | 该脚本所在域下次实跑时统一为 `{ok:false,blocked_at,reason}` + rc=2 |
| D17 | `domain-gate --mutation-test` 未注入 `generated_at` 反例 | 下次改 domain-gate 时补第 5 类注入 |
| D18 | `lessons` 只校验命令文本、不执行 | 需要沙箱重放该案例时补执行态 |
