# 组件溯源清单 (PROVENANCE)

> 回答一个问题：**每个 Skill / MCP 由哪些文件夹组成，依赖什么，装到哪。**
> 用于理解"为什么不能只复制一个配置文件"。

---

## 一、核心原则

> **Skill / MCP 不是单个文件，而是「配置 + 文件夹」的组合。**
> 只复制配置，目标机器必然跑不起来。

| 类别 | 由什么组成 |
| :--- | :--- |
| **Skill** | 一个目录（`SKILL.md` + `references/` + `scripts/` + `evals/` + `evidence/`） |
| **MCP** | 一个启动脚本 + 它读取的**外部数据目录** + 依赖的**外部工具** |
| **提示词** | `SEEP.md` / `AGENTS.md` + `extensions/*.ts` |

---

## 二、Skill 溯源（11 个）

| # | Skill | 本包位置 | 安装目标 | 文件数 | 体积 |
| :--- | :--- | :--- | :--- | :---: | :--- |
| 1 | **softseep** ⭐总控 | `Tool/skill/softseep/` | `~/.pi/agent/skills/softseep/` | 11 | 364 KB |
| 2 | **apkseep** | `Tool/skill/apkseep/` | `~/.pi/agent/skills/apkseep/` | 123 | 2.2 MB |
| 3 | **ida-reverse** | `Tool/skill/_pending/ida-reverse/` | `~/.pi/agent/skills/ida-reverse/` | 1 | 4 KB |
| 4 | **client-license-validation-bypass** | `Tool/skill/softseep/references/` | `~/.pi/agent/skills/` | 1 | 32 KB |
| 5 | **reverse-engineering** | `Tool/skill/_pending/safe-skills/reverse-engineering/` | 同上 | 15 | 380 KB |
| 6 | **apk-reverse** | `Tool/skill/_pending/safe-skills/apk-reverse/` | 同上 | 8 | 52 KB |
| 7 | **radare2** | `Tool/skill/_pending/safe-skills/radare2/` | 同上 | 3 | 20 KB |
| 8 | **mcp-js-reverse-playbook** | `Tool/skill/_pending/safe-skills/mcp-js-reverse-playbook/` | 同上 | 13 | 24 KB |
| 9 | **ida-assistant**（safe 版，IDA MCP HTTP 辅助脚本） | `Tool/skill/_pending/safe-skills/ida-assistant/` | 同上 | 3 | 28 KB |
| 10 | **version-migration** | `Tool/skill/_pending/version-migration/` | `~/.pi/agent/skills/version-migration/` | 1 | 6 KB |
| 11 | **unpack-loop** | `Tool/skill/unpack-loop/` | `~/.pi/agent/skills/unpack-loop/` | 1 | 8 KB |

### ⚠ 上游开源归属与完整镜像（合规声明）

本工作台深度融合并完整归档了以下三大开源项目镜像于 `Tool/upstream/`：

| 项目 | 上游仓库 | 许可协议 | 本包镜像位置 | 核心集成与贡献 |
| :--- | :--- | :--- | :--- | :--- |
| **apk-reverse** | https://github.com/newliver666/apk-reverse | MIT License | `Tool/upstream/apk-reverse/` | 移动端 G1-G4 硬性门禁、DEX 微创修补、离线测试套件与能力自检 |
| **Open-tgtylab** | https://github.com/GeniusHu-tgty/Open-tgtylab | GPL-3.0 License | `Tool/upstream/open-tgtylab/` | 攻防实验室架构、Zero-Waste Recon 信号路由、反退缩指令与 G-Auth 协议 |
| **open-reverselab** | https://github.com/LING71671/open-reverselab | GPL-3.0 License | `Tool/upstream/open-reverselab/` | 289+ 篇实战笔记知识库、boards 攻击网拓扑、MCP 自动化工具组件 |
| **pi-cmd-guard** | https://github.com/gthubtom1/agent-plugins（`plugins/pi/cmd-guard`） | MIT License | `Tool/prompts/extensions/cmd-guard.ts` + `cmd-guard.rules.json` + `TOOL-CHAIN.md` | 命令执行守卫：自动补 timeout、盘根扫描拦截、GUI 二进制拦截、ssh 有界化、卡死状态可视化（**vendored，规则按本仓场景调过**） |
| **retry-level** | https://github.com/gthubtom1/agent-plugins（`plugins/pi/retry-level`） | MIT License | `Tool/prompts/extensions/retry-level.ts` | 重试档位（关闭/3/5/10/15/30/无限）+ 状态栏常显；底层走 pi 官方 `settings.retry` 键 |

**上游比衍生组件保留的完整价值**：
- `Tool/upstream/apk-reverse/tests/`：包含 24 个离线 stdlib 单测套件与 benchmark 矩阵。
- `Tool/upstream/open-tgtylab/`：包含全套 CTF 24h 自动化工作流与跨 agent 指令配置。
- `Tool/upstream/open-reverselab/`：包含完整的桌面端架构、boards 拓扑与 MCP 原始实现。

> **为什么全量入包**：保留完整上游不仅保障开源协议合规性，更便于在断网隔离的离线靶场环境下直接对照原始测试用例与开发参考。


### softseep 内部构成（总控 + 按需加载的 references）

```
softseep/
├── SKILL.md                         ← 总控（518 行）：G-Auth 门 + 判据表 + 路由矩阵
└── references/                      ← 按需加载，不预先全读（10 篇，全部 ≤400 行）
    ├── 01-criteria.md               判据表（授权权威/补丁生效/脱壳/算法正确性）
    ├── 02-failure-criteria.md       失败判据表（现象→改走哪条→代价）
    ├── 03-model-pitfalls.md         模型常见失误（19 条）
    ├── 04-walkthrough-project-a.md  真实案例走查（项目A）
    ├── windows-sop.md               6 步流水线 + 工具索引 + 纵深防御
    ├── license-validation.md        许可/激活/卡密校验手册（16 节）
    ├── 07-disassembly-deep-read.md  x64/ARM64 调用约定、栈帧、编译器模式（吸收 compiler-pitfalls）
    ├── 08-symbol-recovery.md        PDB/RSDS、FLIRT/Lumina、RTTI、vtable
    ├── 09-patch-engineering.md      等长/重定位/IAT/回滚（吸收 patching-dictionary）
    └── 10-anti-debug.md             反调试识别与决策（单列卷）

九型范式库 → `kb/pe-reverse/techniques/11-project-paradigms/`
UI 验收工装 → `kb/pe-reverse/techniques/14-ui-verification/`
报告骨架   → `kb/pe-reverse/techniques/13-report-template/`
```

### apkseep 内部构成（渐进式披露）

```
apkseep/
├── SKILL.md        （432 行）
├── references/     54 个（含 `coverage/`、`precedents/` 子目录共 61 个）
├── scripts/        57 个（顶层 54 个 + `dexpatch/` 子目录 3 个）
├── evals/          （评测用例）
└── evidence/       （能力矩阵与已知限制）
```

---

## 三、MCP 溯源（3 个默认注册）

> 📖 **完整的 MCP 配置、验证与排障** → 见 **`Tool/docs/MCP-SETUP.md`**
> 本节只讲“由哪些文件夹组成”。
> 📦 **各工具下载来源** → 见 **`Tool/docs/DOWNLOADS.md`**

### ① seep MCP（20 工具）— 自研

| 组成 | 位置 | 说明 |
| :--- | :--- | :--- |
| **启动脚本** | `Tool/mcp/seep_mcp_server.py` | 42 KB，主程序 |
| **自检脚本** | `Tool/mcp/test_seep_mcp.py` | 9 个测试套件 |
| **启动器** | `Tool/mcp/run_seep_mcp.bat` | Windows 启动封装 |
| **⭐ 运行时根目录** | **`Tool/mcp/Tool/`** | MCP 内部硬编码 `TOOL_DIR = <脚本目录>/Tool` |
| **⭐ 知识库依赖** | `Tool/mcp/Tool/reverselab/kb/`（**412 篇 .md**） | `seep_kb_search` 等 4 个工具读这里 |
| **LLM 索引** | `Tool/mcp/Tool/reverselab/docs/llms.txt` | MCP 启动时读取 |
| **外部工具依赖** | `Tool/mcp/Tool/safe/radare2/bin/`（脚本下载） | `seep_r2_*` 8 个工具 |
| **外部工具依赖** | `Tool/mcp/Tool/safe/jadx/bin/` + `.../apktool/`（脚本下载） | `seep_apk_*` 5 个工具 |
| **Hook 模板** | `Tool/mcp/Tool/safe/hook-mcp/templates/` | `Tool/mcp/Tool/safe/hook-mcp/` |

> **关键（排障必读）**：`seep_mcp_server.py` 第 28–44 行硬编码：
> ```python
> BASE_DIR = os.path.dirname(os.path.abspath(__file__))   # = Tool/mcp/
> TOOL_DIR = os.path.join(BASE_DIR, "Tool")               # = Tool/mcp/Tool/
> SAFE_DIR = os.path.join(TOOL_DIR, "safe")               # = Tool/mcp/Tool/safe/
> R2_BIN_DIR = os.path.join(SAFE_DIR, "radare2", "bin")
> KB_DIR = os.path.join(TOOL_DIR, "reverselab", "kb")
> ```
> **所以 `Tool/` 必须与 `seep_mcp_server.py` 同级，不能搬动。**

**工具分组**：
```
状态环境(2)   mcp-doctor.py · mcp-doctor.py
二进制 r2(9)  seep_r2_info · _cmd · _strings · _functions · _disasm · _decompile · _diff · _asm · _xrefs
Android(5)    seep_apk_info · _decompile · _unpack · _smali_search · _gen_hook
知识库(4)     seep_kb_search · _read · _checklist · _payloads
流程编排(3)   mkdir -p <task>/{samples,exports,patches,reports} · seep_auto_triage · seep_gen_security_report
扩展资产(14)  seep_ensure_tool · seep_r2_decompile · seep_r2_cmd(iR) · seep_mem_strings ·
             seep_pcap_extract · seep_packer_detect · seep_http_replay · web-check.py ·
             seep_tool_discover · tool-acquire.py · tool-acquire.py --list ·
             tool-acquire.py（ASK） · tool-acquire.py --tool <id> · tool-acquire.py --json
```

### ② ida MCP（约 100 工具，随版本变化）

| 组成 | 位置 | 说明 |
| :--- | :--- | :--- |
| **MCP 服务** | `tools/ida-pro-mcp/`（脚本下载） | `server.py` + 插件 |
| **⭐ 宿主依赖** | **你自备的 IDA Pro** | 商业授权，**不随包分发** |
| **Python 运行时** | IDA 内置的 `python311` | 由 `install-pi.ps1` 探测 |

> 没有 IDA Pro 时，该 MCP 不可用；用 `seep_r2_*` + Ghidra 替代（见 `MANUAL/IDA-PRO.md`）。

### ③ playwright MCP

| 组成 | 位置 | 说明 |
| :--- | :--- | :--- |
| **MCP 服务** | npm `@playwright/mcp` | `npx` 按需拉取 |
| **扩展 token** | —（已移除） | **无需 token** —— 以 `--headless` 启动（旧版 `--extension` 模式才需自填，已废弃） |

### 可选注册：reverselab 自带的 3 个 MCP

源码在 `Tool/mcp/Tool/reverselab/tools/skills/mcp/`，**默认不注册**，需要时手动加入 `mcp.json`：

| MCP | 位置 | 用途 |
| :--- | :--- | :--- |
| **ReverseLabToolsMCP** | `Tool/mcp/Tool/reverselab/tools/skills/mcp/ReverseLabToolsMCP/` | reverselab 主 MCP（150+ 工具） |
| **JSHookLocal** | `Tool/mcp/Tool/reverselab/tools/skills/mcp/JSHookLocal/` | JS Hook 本地服务 |
| **GhidraMCP** | `Tool/mcp/Tool/reverselab/tools/skills/mcp/GhidraMCP/` | Ghidra 桥接 |

---

## 四、提示词与扩展溯源

| 文件 | 本包位置 | 安装目标 | 作用 |
| :--- | :--- | :--- | :--- |
| **SEEP.md** | `Tool/prompts/SEEP.md` | `~/.pi/agent/SEEP.md` | **装配契约**：五层裁决 + lab/拒答/能力的指针（战术与工具清单已迁至技能/配置/MANUAL/PROMPT-LAYERS.md） |
| **AGENTS.md** | `Tool/prompts/AGENTS.md` | `~/.pi/agent/AGENTS.md` | 跨 agent 通用版（Codex / Claude Code / OpenCode） |
| **security-audit-interceptor.ts** | `Tool/prompts/extensions/` | `~/.pi/agent/extensions/` | 底座 BLOCK_NONE 注入 + **lab 标志文件门控** + 快捷口令 + 敏感词替换 |
| **load-system-prompt.ts** | `Tool/prompts/extensions/` | `~/.pi/agent/extensions/` | 加载自定义提示词 |

### lab 模式状态文件

| 项 | 值 |
| :--- | :--- |
| 路径 | `~/.pi/agent/lab-mode.flag` |
| 写入时机 | 输入 `lab：` |
| 删除时机 | 输入 `退出实验` |
| 作用 | 扩展每次读此文件决定是否启用敏感词替换；**状态在磁盘，切模型/长上下文都不丢** |

---

## 五、知识库溯源

| 组成 | 本包位置 | 说明 |
| :--- | :--- | :--- |
| **kb/** | `Tool/mcp/Tool/reverselab/kb/` | **412 篇 .md**（ctf-website / apk-reverse / pe-reverse / general） |
| **boards/** | `Tool/mcp/Tool/reverselab/boards/` | 攻击网（按信号路由到技术文件） |
| **tools/skills/mcp/** | `Tool/mcp/Tool/reverselab/tools/skills/mcp/` | 3 个 MCP 源码 |
| **docs/** | `Tool/mcp/Tool/reverselab/docs/` | 含 `llms.txt`（seep MCP 引用的 LLM 索引） |
| **scripts/** | `Tool/mcp/Tool/reverselab/scripts/` | 知识库辅助脚本 |
| **AGENTS.md / Tool/prompts/contracts/CLAUDE.md / SKILLS.md / AI-USAGE.md** | `Tool/mcp/Tool/reverselab/` | reverselab 自带的 agent 协议 |

> 已剔除工作目录：`cases/ logs/ tmp/ exports/ samples/ projects/ patches/ reports/ notes/ site/`

---

## 六、脚本溯源

| 脚本 | 本包位置 | 作用 |
| :--- | :--- | :--- |
| `case-init.ps1` | `Tool/scripts/` | 任务建档门禁（一任务一目录） |
| `refresh-tool-index.ps1` | `Tool/scripts/` | 工具链健康自检 |
| ~~`trigger_ida_mcp.ps1`~~ | — | 已删除（硬编码 PID，改由 `tool-acquire.py --tool ida`） |
| `route.py` | `Tool/scripts/` | 主路由 |
| `start_mcp.py` | `Tool/scripts/` | MCP 启动 |
| `temp_ocr.ps1` | `Tool/scripts/` | OCR 辅助（`shot_ida.ps1` 已删） |
| `apk/decode.ps1` | `Tool/scripts/apk/` | jadx + apktool 一键解包 |
| `apk/rebuild-sign-install.ps1` | `Tool/scripts/apk/` | 重打包 → 对齐 → 签名 → 装机 |
| `apk/frida-run.ps1` | `Tool/scripts/apk/` | 设备枚举 + Spawn/Attach 注入 |
| `apk/manifest-summary.ps1` | `Tool/scripts/apk/` | Manifest 摘要 |

（`.sh` 版为 macOS/Linux 等价脚本）

---

## 七、外部工具依赖（脚本下载，不在包内）

> 下载目标统一为 **`Tool/mcp/Tool/safe/`**（MCP 硬编码要求）。

| 工具 | 服务的 MCP / Skill | 下载目标 | 体积 |
| :--- | :--- | :--- | :--- |
| **radare2** | `seep_r2_*`（8 工具） | `Tool/mcp/Tool/safe/radare2/` | ~38 MB |
| **jadx** | `seep_apk_decompile` | `Tool/mcp/Tool/safe/jadx/` | ~460 MB |
| **apktool** | `seep_apk_unpack` | `Tool/mcp/Tool/safe/apktool/` | ~24 MB |
| **playwright-mcp** | playwright MCP | `Tool/mcp/Tool/safe/playwright-mcp/` | ~45 MB |
| **js-reverse-mcp** | js-reverse-mcp MCP | `Tool/mcp/Tool/safe/js-reverse-mcp/` | ~234 MB |
| **ida-pro-mcp** | ida MCP | `Tool/mcp/Tool/safe/ida-pro-mcp/` | ~79 MB |

---

## 八、依赖链速查（排障用）

```
seep_kb_* 四个工具   →  Tool/mcp/Tool/reverselab/kb/（412 篇）
seep_r2_* 八个工具   →  Tool/mcp/Tool/safe/radare2/bin/
seep_apk_* 五个工具  →  Tool/mcp/Tool/safe/jadx/ + apktool/
Tool/mcp/Tool/safe/hook-mcp/   →  Tool/mcp/Tool/safe/hook-mcp/templates/
ida MCP              →  自备 IDA Pro + Tool/mcp/Tool/safe/ida-pro-mcp/
playwright MCP       →  npx + --headless（无需 token）
softseep 路由         →  Tool/skill/softseep/（含 8 个 references）
apkseep 全链路        →  Tool/skill/apkseep/（45 refs + 56 scripts）
```

**排障口诀**：某个 MCP 工具报错 → 先看它读哪个目录 → 检查该目录是否存在且非空。
**特别注意**：`Tool/mcp/Tool/` 不可搬动 —— MCP 内部硬编码了 `TOOL_DIR = <脚本目录>/Tool`。

---

## 九、案例层溯源（项目A~I）

| 案例 | 源（脱敏前） | 范式类型 |
| :--- | :--- | :--- |
| 项目A | 单进程经典工具 | 单进程纯离线 |
| 项目B | 多进程模拟器 | 多进程混合 |
| 项目C | 压缩工具商业套件 | 资源模板 + 显示层伪造 |
| 项目D | 下载工具 | 壳保护 + 多策略 |
| 项目E | 卸载工具 | VM + 在线 → patch |
| 项目F | 搜索工具 | .NET 混淆 → Keygen |
| 项目G | 播放工具 | 自引用校验 → 补判定点 |
| 项目H | 截图工具 | 公钥替换 Keygen |
| 项目I | 开始菜单工具 | RSA 弱模 → 验签入口 |

**脱敏范围**：产品名 / 公司名 / 同厂兄弟产品 / 哈希 / 绝对路径 / 版本号 / 厂商域名 → 全部替换。
**保留**：RVA / 文件偏移 / 原始字节 / 补丁字节 / 汇编指令 / 算法常量 / CWE 编号 / 工具名。
