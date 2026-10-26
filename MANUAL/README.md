# MANUAL —— 手册索引（14 份，全在这一页）

> **这就是手册的唯一入口。** `AGENTS.md` / `SEEP.md` 只指到这里，不再各自列手册名。
> 加新手册：在本表加一行（机器判据 `preflight.py` 的「入口可达」会红着点名未登记的那一份）。
> 用法：先按「什么时候读」这一列对号，不要从头读。

## 一、部署与运行（第一次装、换机器、换系统）

| 手册 | 行数 | 什么时候读 |
| :-- | --: | :-- |
| [`MANUAL/PREREQUISITES.md`](PREREQUISITES.md) | 95 | `install.ps1` 报缺运行时 / 想先知道要装什么（Python、Node、7z…） |
| [`MANUAL/DEPLOYMENT.md`](DEPLOYMENT.md) | 474 | 首次部署、多 Agent（Pi / Claude Code / DSH / Codex / OpenCode）接入的权威步骤 |
| [`MANUAL/DEPLOYMENT-CHECKLIST.md`](DEPLOYMENT-CHECKLIST.md) | 187 | 想知道"装全了没"：K1–K5 资产全景核验基准清单 |
| [`MANUAL/CROSS-PLATFORM.md`](CROSS-PLATFORM.md) | 120 | 在 macOS（Apple Silicon / Intel）或 Linux 上跑，以及战术等价映射 |

## 二、边界与拒答（模型开始"讲道理"的时候）

| 手册 | 行数 | 什么时候读 |
| :-- | --: | :-- |
| [`MANUAL/MODEL-REFUSAL-MATRIX.md`](MODEL-REFUSAL-MATRIX.md) | 267 | 任务开始前选模型；模型开始免责/转介时查十种返工形态 |
| [`MANUAL/PROMPT-LAYERS.md`](PROMPT-LAYERS.md) | 166 | 提示词分层 / 人格卡兼容 / 迁移存档 / G-Auth 裁决的原委 |
| [`MANUAL/BASELINE-FREEZE.md`](BASELINE-FREEZE.md) | 183 | 想改架构/路径/接口/配置格式之前：哪些已冻结、增量怎么算 patch |
| [`MANUAL/COMPLIANCE-RELAY.md`](COMPLIANCE-RELAY.md) | 366 | 三层防拒体系的第三层（网络层合规转译中继）怎么配、边界在哪 |

## 三、战术 SOP（打的时候查）

| 手册 | 行数 | 什么时候读 |
| :-- | --: | :-- |
| [`MANUAL/UNPACKING.md`](UNPACKING.md) | 188 | 判出加壳后：MPRESS / UPX / Themida / VMP 3.x / .NET Reactor / 自定义混淆的处置流程 |
| [`MANUAL/ANTI-DEBUG.md`](ANTI-DEBUG.md) | 190 | G0/G1 阶段遇到反调试或强对抗：Windows 用户态技法 + 补丁模板 + 代理 DLL 框架 |
| [`MANUAL/POC-VALIDATION.md`](POC-VALIDATION.md) | 180 | 生成 PoC（Frida / Smali 补丁 / 代理 DLL）之后：自动执行、回显捕获、报错自愈 |
| [`MANUAL/IDA-PRO.md`](IDA-PRO.md) | 159 | 没有 IDA 授权 / 想确认替代方案（Ghidra / r2 / 反编译对照）时 |

## 四、扩展与上手（想加东西、想从零学）

| 手册 | 行数 | 什么时候读 |
| :-- | --: | :-- |
| [`MANUAL/SKILL-CREATION-GUIDE.md`](SKILL-CREATION-GUIDE.md) | 143 | 要写一个外挂技能：frontmatter、命名、判型、验收怎么写 |
| [`MANUAL/ZERO-TO-HERO-WORKFLOW.md`](ZERO-TO-HERO-WORKFLOW.md) | 107 | 完全不懂汇编/逆向，先看"这工作台能产出什么成品、我该发什么指令" |

---

## 五、工具目录（代码类资产，不是手册但同样有入口）

| 目录 | 是什么 | 什么时候用 |
| :-- | :-- | :-- |
| [`Tool/scripts/compliance-relay/`](../Tool/scripts/compliance-relay/README.md) | 合规转译**网络中继**（`relay.py` + `refusal.py` + `extract-rules.py` + 规则 json）：把"敏感口语 → 合规术语"从 Agent 插件下沉成通用 HTTP 网关，任何支持自定义 `baseUrl` 的 Agent 都能接。边界与三 Agent 接法见 [`MANUAL/COMPLIANCE-RELAY.md`](COMPLIANCE-RELAY.md) | 要给非 Pi 的 Agent（Cursor / Cline / 自建网关）也加防拒层；或规则表改了要 `extract-rules.py` 重新提取、`--scan-pi` 生成 upstream 映射时 |
| [`破甲卡生成/`](../破甲卡生成/README.md) | relab2 的 kernel-sweep **破甲卡工程**（人设卡 + 探针脚本 `probe-*.py` / `sweep*.py` / `apply.py` + 模型档案）：测"哪个模型在什么话术下会被拦"，产出可复用的卡 | 要给某个模型调防拒话术、复现某轮模型被拒、或改人设卡（权威顺序见该目录 `README.md` 的 L0–L4 表）时 |
| [`Tool/playbooks/`](../Tool/playbooks/README.md) | 24 份端到端**任务配方**（可复跑的命令序列 + 能力 id）。逐份目录见 [`Tool/playbooks/README.md`](../Tool/playbooks/README.md) 的索引表 | 有明确目标类型时先找配方，别现编流程；每份配方是什么：`anti-cheat-forensics`（反作弊取证）/ `apk-ad-removal`（APK 去广告）/ `apk-unpack`（APK 脱壳）/ `app-daily-task`（APP 每日任务）/ `backend-rebuild`（后端复刻）/ `captcha-handling`（验证码）/ `firmware-emulate`（固件仿真）/ `firmware-extract`（固件提取）/ `forensics-timeline`（取证时间线）/ `game-client-il2cpp`（IL2CPP 游戏客户端）/ `license-bypass-deliver`（卡密旁路交付）/ `license-hookup`（接自有授权）/ `malware-triage`（样本分诊）/ `multi-account-runner`（多账号）/ `osint-recon`（OSINT 侦察）/ `plugin-analysis`（插件分析）/ `protocol-replay`（协议重放）/ `qinglong-signin`（青龙签到）/ `reverse-survey`（逆向摸底）/ `site-clone-1to1`（站点 1:1）/ `supply-chain-audit`（供应链审计）/ `ui-rebrand`（UI 去品牌）/ `version-migrate`（跨版本追版）/ `web-api-sign-reverse`（Web 签名逆向） |
| [`Tool/skill/_pending/`](../Tool/skill/_pending/INDEX.md) | 18 个归档子技能：`00-analysis` `00-triage` `01-gate-bypass` `02-ui-rebrand` `03-license-hookup` `04-version-migrate` `05-backend-rebuild` `ad-cloud` `binary-diff` `doc-hygiene` `ida-reverse` `llm-security` `plugin-targets` `pm-plan` `safe-skills` `signin-automation` `site-clone` `version-migration`（不部署、不预载，按路径 `read`） | 需要某个专项能力时按 [`_pending/INDEX.md`](../Tool/skill/_pending/INDEX.md) 读；`safe-skills` 没进 INDEX，含 5 个上游技能安全审阅（`apk-reverse` / `ida-assistant` / `mcp-js-reverse-playbook` / `radare2` / `reverse-engineering`） |

- 加工具 / 加 MCP / 加技能的 4 步：`Tool/docs/EXTEND.md`
- 资源路径总表：`Tool/prompts/SEEP.md` §1
