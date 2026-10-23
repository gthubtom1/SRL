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
| D6 | 任务卡剧本化 **已完成（v1.23.0）**：全仓 264 张卡（11 域 × 24 张），其中 **61 张**已带「命令+rc=0+期望」并逐条实跑；分布：web-pentest 9 / plugin-targets 9 / pwn-crypto 7 / ad-cloud、firmware-iot、forensics-mobile、malware-analysis、protocol-plugin、reverse、supply-chain-security 各 5 / site-clone 1 | 剩余 203 张按需剧本化，排下一批 |
| D7 | 归档库（`Tool/cases/_archive/`、`kb/_archive/pe-reverse/`）未纳入检索 UI | 内容完整、索引可读；`seep_kb_search` 默认只搜 board |

| D10 | `driver-triage.py` **已实现（v1.23.0）**：815 行、self-test 19 项；HVCI/WDAC 仅静态线索 | 真实驱动样本复核 + 动态加载性判定排下一批 |
| D11 | 判据字段已改为「每个字段必须被脚本输出或在 inferred 白名单」，11 域 0 未覆盖 | 下一批把白名单占比降到 20% 以下 |
| D12 | iOS / 反作弊 / 托管运行时：已有独立 KB board（各 4 篇+README）与 R26/R29/R33 路由 | 未升独立技能；连续 3 个案例稳定后再升 |

## v1.25.0 终版后的 P1 台账（按使用顺序补）

| id | 项 | 触发条件 |
| :-- | :-- | :-- |
| D13 | B 报告 10 条深度 P1（sign-recompute / tls-decrypt / license-locate / permission-evidence / ipc-audit / yara-write 等） | 该能力被真实任务用到时，按 `docs/history/audit/CLOSURE.md` 对应行补脚本 |
| D14 | D 报告 4 条架构 P1（4 套注册表合并、能力独立判据、routing `playbook` 字段、new-skill 词边界） | 新增域/新增能力时优先做；不阻塞既有 11 域 |
| D15 | probe 级能力（`maturity=probe`）补独立脚本 | 该能力第一次产出真实案例时 |
| D16 | 11 个存量脚本失败路径 rc 不统一（裸 Traceback / rc=1 纯文本） | 该脚本所在域下次实跑时统一为 `{ok:false,blocked_at,reason}` + rc=2 |
| D17 | `domain-gate --mutation-test` 未注入 `generated_at` 反例 | 下次改 domain-gate 时补第 5 类注入 |
| D18 | `lessons` 只校验命令文本、不执行 | 需要沙箱重放该案例时补执行态 |

## v1.26.1 新增台账（Pentest 库吸收 + 无线近场）

| id | 延迟项 | 现状 / 触发条件 |
| :-- | :-- | :-- |
| D20 | **已完成（索引 + 正文）**：79 篇 `offensive-*`（UNKNOWN 许可）的归档索引在 `kb/_archive/pentest-checklist/README.md`（79 行表 + 建议动作），未收清单在同目录 `NOT-ABSORBED.md` | 10 篇「可重写吸收」正文已全部落库（anti-forensics / bluetooth-ble / cicd-secrets / netexec / osint / phishing / reporting / toctou / wifi-recon / wpa2-psk） | 无 |
| D21 | 无线近场未独立成域（当前挂 `firmware-iot` 的 `hardware-interfaces.md` 无线章 + 路由 R22） | 硬件探针（monitor 网卡 / BLE / 802.15.4 / sub-GHz）未纳入 `probe_matrix.py`；触发条件：连续 3 个无线案例稳定后升域 |
| D22 | **脚本已交付**：`Tool/skill/web-pentest/scripts/race-probe.py`（1029 行；`--mode concurrent|single-packet|h2-single-packet`；HTTP/1.1 最后一字节同步 + h2 单包（缺 `h2` 库时返回 `blocked_at=h2-lib-missing`）+ 账本读回 + 远端安全闸 + 默认 dry-run；`--self-test` 34 项；已接矩阵 23 条 / SKILL §9 / references 09 / 能力表 `race-test`） | 剩余缺口：**真实 HTTP/2 服务端多 stream 未端到端验证**（只用 stub 与「h2 打 HTTP/1.1 端点→blocked」覆盖了失败路径）；触发条件：遇到 h2 目标时补一次实跑 |
| D23 | **已完成**：`Tool/scripts/osint-secret-scan.py`（65 条模式、默认脱敏、self-test 37 项）与 `Tool/scripts/osint-h1-ref.py`（H1 公开 GraphQL，server-keyword + client-filter 兜底，self-test 19 项）已接入 `osint-recon` 配方与能力表 | 无（H1 schema 变动时以 `blocked_at=graphql-error` 暴露，不静默 0 条） |

| D24 | **已完成**：`Tool/scripts/h2-race-e2e.py`（内置 h2c 服务端 racy/safe 两档 + 账本，复用 race-probe 判定）已进 preflight（44 项里的「HTTP/2 单包 e2e」），racy=fail / safe=pass 实测稳定 | 无（TLS 分片/前置代理会退化，文档已写明只得出「未打出时间窗压缩」） |
| D25 | **已完成（离线可机检）**：`ad-repro.py --kind edge-fingerprint` 覆盖 10 类产品，`--fixture` 离线复算（9 high / 1 med）+ `--self-test` 24 项；在线路径仍需授权目标才跑 | 有授权目标时按卡 28 实跑一次，回写 `evidence_kind=real` |
| D26 | `00-analysis` 只有 SKILL + 1 篇 report-template，未纳入 `domain_spec.DOMAINS` 九件套（无 cases/矩阵/任务卡） | 若要把它当独立域考核，需补 01–04 必备篇 + 矩阵 + 任务卡；当前按「阶段技能」对待，不进 domain-gate |

## 明确不做（不排期，附理由）

| 项 | 决定 | 理由 |
| :-- | :-- | :-- |
| D21 无线近场升独立域 | **不做** | 仓库的域契约要求「≥1 个 real 案例 + sha256 证据」，本机没有无线硬件（`probe_matrix --radio-only` 实测 `monitor_capable=false`），升域只会得到一个没有真案例的空壳。当前形态=R22 路由 + `hardware-interfaces.md` 无线章 + `radio` 探针，能力已齐、判据可跑。等真有硬件并跑出 3 个真实案例再考虑。 |
| D26 `00-analysis` 纳入九件套 | **不做** | 它是「阶段技能」（开工前先摸透），由 `softseep` 总控在流程里调用；硬套九件套（矩阵/案例/KB/任务卡）会造成与 00 阶段产物（报告 + 裁定）重复计量。当前形态=SKILL + 报告模板，够用。 |
| C2 框架搭设 / 课程转录 6 篇 | **不做** | 与「可复现判据 + 取证」定位正交；课程转录 5.6 万行且与 pwn-crypto 重叠，进树只会撑大仓库。 |
