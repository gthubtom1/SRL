# v1.26.1 成品说明（交付记录）

> 本文件是 **v1.26.1 的交付台账**：做了什么、每条改动的证据在哪、还剩什么没做。
> 目的很直接——读者只看这一篇，就能复核本轮所有主张，不用翻对话记录。
> 复核入口：`python Tool/scripts/preflight.py`（应为 43/43）。

## 0. 一句话

把「8.0/10 合格」推到「成品级」：**修掉 5 类真实摩擦（MCP 参数不一致、假话术、路由盲区、薄壳阶段技能、文档↔事实漂移）**，
新增 **2 条可机检门禁**（MCP 参数契约 / 技能路由探针）+ **1 处统计口径修正**（first-party 改 `git ls-files`，消除 820↔834 漂移），
并行硬化 **4 个域**（web-pentest / ad-cloud / llm-security / firmware-iot），
把外部 Pentest 技能库按许可分层**只索引不复制**地接入。

## 1. 门禁证据（本轮原样输出）

| 门禁 | 命令 | 结果 |
| :-- | :-- | :-- |
| 全量体检 | `python Tool/scripts/preflight.py` | **43/43 通过** |
| 域深度 | `python Tool/scripts/domain-gate.py --all` | **110/110 通过** |
| 部署体检 | `powershell -File setup/verify.ps1 -Detailed` | **核心 65 项通过 / [READY]** |
| 端到端 | `python Tool/scripts/smoke-e2e.py` | **12 passed, 0 failed** |
| MCP 参数契约 | `python Tool/scripts/mcp-param-contract.py` | 40 工具 / 17 吃路径，全绿 |
| 技能路由探针 | `python Tool/scripts/skill-route-probe.py` | **33 条，失败 0** |
| 知识库可用性 | `python Tool/scripts/kb_acceptance.py` | **9/9 通过** |

## 2. 五类摩擦的修法（问题 → 改动 → 证据）

### 2.1 MCP 工具参数命名不一致（最高性价比）
- 问题：`seep_auto_triage` 收 `target_path`，`seep_packer_detect` / `seep_r2_info` / `seep_decompile_auto` 收 `binary_path`。模型一次 rejected 之后会退回 bash 手搓 `strings`（历史血案 184 次调用）。
- 改动：`Tool/mcp/seep_mcp_server.py` 加 `_path_alias` 装饰器——17 个吃路径的工具全部同时暴露 `binary_path / target_path / apk_path / file_path / sample_path / artifact_path / pcap_path / dir_path` 八个别名，主参数不再出现在 `required`。
- 门禁：`Tool/scripts/mcp-param-contract.py`（判据：别名齐、required 不挡、description 非空、工具数对基线）。
- 证据：`mcp-param-contract.py --self-test` → `{"ok": true, "checks": 6}`；实跑 → `全绿：路径参数别名、required、description、工具数均一致`。

### 2.2 auto_triage 的硬编码假话术
- 问题：`seep_mcp_server.py` 无条件输出「检测到高价值鉴权关键词与符号」，而同一次返回里 `auth_related_strings_sampled` 是空数组——反造假仓库里留着一句假话术。
- 改动：改为 `_triage_next_actions()` 按实测分支生成（命中/未命中/.NET/解析失败各走一路），并新增结构化 `next_actions` 数组。
- 证据：对 `CrackMev1.exe` 实跑，`auth_related_strings_sampled: []` 时首条动作是「未命中鉴权关键词：先判壳、再全段重扫」，不再自称命中。

### 2.3 路由盲区（根因：`\b` 与 CJK 边界）
- 问题：.NET 正则把 CJK 也当 word 字符，「APK去广告」「Unity IL2CPP透视」里的 `\bapk\b` / `il2cpp\b` **永远匹配不上**，直接掉兜底。同类还有滑块验证码、suid 提权、小程序、前端 JS 签名、OSINT。
- 改动：
  - `Tool/scripts/master-route.ps1`：匹配前在 ASCII ↔ CJK 交界补空格（只改匹配副本，不动原输入）。
  - `routing.json` + `routing-fragments/`：补 R1（小程序）、R6（前端 JS/签名算法）、R23（本机提权）、R34（验证码/滑块）、R22（无线近场）；新增 **R36 OSINT**（配方 `osint-recon`）。
  - 新增门禁 `Tool/scripts/skill-route-probe.py` + `Tool/config/skill-route-probes.json`（33 条大白话 → 期望技能/路由）。
- 证据：探针 33 条全中；`verify-routing-coherence` 32 路由自洽；`domain-gate` 路由串味测试 60 条全中。

### 2.4 02/03 阶段技能是薄壳
- 问题：`02-ui-rebrand` 86 行、`03-license-hookup` 87 行，只有清单没有判据。
- 改动：02 补「判据表 8 行（品牌串残留=0 / 图标哈希 / 功能回归 / 流量差集 / 三档分辨率…）+ 失败判据表 + 模型失误 + 可跑命令」；03 补「判据表 8 行 + 失败判据表 + 离线 HMAC 发卡与校验最小实现 + 时间回拨防护 + 失败码表」。
- 证据：`domain-gate` 不受影响（阶段技能非域），`preflight` 43/43 含链接与措辞检查。

### 2.5 文档↔事实漂移（本轮审计自己抓到的）
- 问题：`check-budget.py` 用 `os.walk` 数 first-party 文件，把 `.pytest_cache/`、`.pi/` 等运行时目录算进去，同一份代码在不同机器得到 820↔834，`BASELINE-FREEZE` 无法对账。
- 改动：改成 `git ls-files`（未跟踪文件不计），口径写进 `MANUAL/BASELINE-FREEZE.md`；基线定为 **815/900**。
- 证据：`check-budget.py` → `OK first-party 引擎文件 815 / 900`，`preflight` 的「文档数字 vs 实测」项 PASS。

## 3. 四个域的硬化（并行分支，已合并）

| 域 | 加厚了什么 | 证据 |
| :-- | :-- | :-- |
| web-pentest | `race-probe.py`（608 行：并发批 + 账本读回 + 远端安全闸 + 默认 dry-run，self-test 22 项）；07 卷补 2026 前置适配矩阵；06 卷补断言类攻击（SAML/OAuth/JWT）对照表；KB 第 9 篇 `10-cache-poison-gate.md`；矩阵 18→19 条 | `domain-gate --domain web-pentest` 10/10；`race-probe --self-test` → 22 checks |
| ad-cloud | `06-lateral-movement.md`（210 行：relay→SMB/WinRM/LDAPS、PtH、WMI、schtasks、DCOM、RBCD 四列判据）；`ad-attacks.md` §11 公网 445/389/88 只读外部视角；`ad-repro.py --kind ntlm-type2`；任务卡 24→26 张，5 张剧本化真跑 | `domain-gate --domain ad-cloud` 10/10；`ad-repro --self-test` → 10 checks / 8 kinds |
| llm-security | `agentic-owasp-asi.md`（ASI01–ASI10 四列判据）、`mcp-attack-surface.md`（7 类入口 + 探针）、`probe-agent.py`（818 行 / 12 探针 / 离线 fixture） | `--self-test` ok:true；`--builtin vulnerable` → 0/12（设计预期） |
| firmware-iot | `hardware-interfaces.md` 并入「无线与近场」章（802.11 握手/PMKID/WPA3/企业级/WPS、BLE、802.15.4、Z-Wave、sub-GHz/LoRaWAN、NFC）；路由 R22 加无线关键词 | `domain-gate --domain firmware-iot` 10/10；无线探针 3 条全中 |

## 4. 外部 Pentest 技能库：按许可分层接入（结论）

- **不整体吸收**：236 篇里约 136 篇自声明 MIT（可改写），79 篇 `offensive-*` 来源 `SnailSploit/offensive-checklist` 且正文署名 `@Pwn3rzs Telegram channel`（付费课程转帖）→ 按 **UNKNOWN / 不可再分发** 处理；6 篇课程转录（合计约 56,200 行）不收。
- **已重写吸收**：归属/竞态判据（web-pentest 09 卷）、无线近场（firmware-iot）、OSINT 工序（配方 `osint-recon`）。
- **已建索引**：`Tool/mcp/Tool/reverselab/kb/_archive/pentest-checklist/README.md`（79 条表格 + 一句话价值 + 建议动作）与 `NOT-ABSORBED.md`（6 篇转录 + 7 个脚本为何不能直接跑）。
- 纪律写在 `docs/UPSTREAM.md` §6。

## 5. 还剩什么没做（延迟项，见 `docs/DEFERRALS.md`）

| id | 内容 | 触发条件 |
| :-- | :-- | :-- |
| D20 | 79 篇索引已建；其中「可重写吸收」10 篇**正文**尚未逐篇落库 | 需要某篇的具体命令时按篇重写 |
| D21 | 无线近场未独立成域（当前挂 R22 + 单章） | 连续 3 个无线案例稳定后升域；硬件探针未纳入 `probe_matrix.py` |
| D22 | `race-probe.py` 已交付（并发批 + 账本读回）；**HTTP/2 单包（last-byte sync）未实现** | 目标为 HTTP/2 且并发批打不出窗口压缩时补 |
| D23 | OSINT 只有配方，无专用脚本（secret_scan / h1-ref 未重写） | 需要批量密钥扫描或 H1 公开报告检索时 |

## 6. 复跑步骤（换机器也能验）

```bash
python Tool/scripts/preflight.py                 # 43/43
python Tool/scripts/domain-gate.py --all         # 110/110
python Tool/scripts/smoke-e2e.py                 # 12/12
python Tool/scripts/mcp-param-contract.py        # 契约
python Tool/scripts/skill-route-probe.py         # 33 条路由探针
powershell -File setup/verify.ps1 -Detailed      # 65 项 / READY
```
