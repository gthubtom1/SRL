# 交接文档 · 给新对话的 AI（2026-10-19）

> **你是谁**：接手 `gthubtom1/Seep-Reverse-Lab`（Seep 原版的个人二开增强版）的 AI。
> **主人（YG）的诉求**：把这个项目做成他个人专用的、功能最全的逆向工作台。**公开只是因为私有库有流量限制，不分发给别人，所以不在乎许可证**。
> **本文件是唯一交接入口**。先从头读完，再动手。

---

## 0. 一句话现状

- 仓库 `main` = `8c0ab32`，已推到 `https://github.com/gthubtom1/Seep-Reverse-Lab`。
- 版本 **1.8.0**；体检 `check.ps1` **58 项全绿 READY**；原 MCP 基线 9/9；扩展自测 60/60。
- 原版 23 工具 → 现 **37 工具**（14 个扩展，纯增量，相对原版 `seep_mcp_server.py` 净删除 0 行）。

---

## 1. 已经做完的（别重做）

| 批次 | 内容 |
|---|---|
| 扩展工具 8 个 | `seep_ensure_tool`(四级探测) / `seep_decompile_auto`(真·Ghidra→r2 降级) / `seep_pe_resources`(资源剥离) / `seep_mem_strings`(活体内存) / `seep_pcap_extract`(pcap) / `seep_packer_detect`(判壳+反调试+注入+CLR) / `seep_http_replay`(协议重放+TLS伪装+Cookie会话) / `seep_web_recon`(Web侦察) |
| 判型预判 | `Tool/skill/softseep/scripts/preflight-classify.py`（判型前读文件头/节表/壳/CLR/反调试） |
| 接入 | 8 工具全部写进 `softseep/SKILL.md` 判型表+扩展工具速查表；协议→`license-validation.md §6`；判壳→`windows-sop.md Step1` |
| 配置 | `Tool/config/engine-tiers.json`(引擎链) + `Tool/config/tool-install.json`(按需下载) |
| 真样本库 | `Tool/samples/real/`：PE 31 + APK 6 + ELF 3 + JS混淆 20 + pcap 5（全格式，随仓库提交，本地=GitHub） |
| 思路沉淀 | `Tool/cases/案例-6.9换肤壳/`（含 2 篇被否决方案笔记） |
| 文档 | `Tool/docs/EXT-ASSETS.md`、`Tool/docs/MERGE-PLAYBOOK.md`（融合标准流程+踩坑7条+13步清单） |
| 部署验证 | 已实测：全新 clone → extract-deps → install.ps1 → 58项全绿 → MCP 37工具可启动可调用 |

---

## 2. 还没做完的（新对话要接着做的）★ 最重要

### 任务A：轻量「工具自动发现 + 自动适配 MCP」小插件（主人明确要，尚未开始）

**主人的原话逻辑（要照这个做）**：
> AI 干活缺工具 → 先搜本机 → 有就直接用（headless 优先）→ 没 MCP 就适配注册 MCP → 都没有才自己写 Py 脚本 → **绝不卡住**。
> 而且**不能塞进 GitHub 让它变重**：逻辑进仓库（小插件），发现状态留本地（`~/.seep/tools.local.json`，gitignore）。

**关键设计约束（务必遵守，否则又会变成臃肿的 relab2）**：
1. **仓库只放"逻辑 + 声明式能力表"（约 300~500 行），状态放本机**。每台电脑工具不同，本地缓存不同，但**永不进 GitHub**。
2. **六层递进发现**：环境变量 → PATH → 常见安装目录 → **Windows 注册表"已安装程序"** → 递归扫描(带deny规则) → 别名映射。**不能只查 PATH**。
3. **匹配架构/版本**：读目标 PE 的 machine 字段，32位选 x32dbg、64位选 x64dbg；IDA 分 `ida.exe`(GUI)/`idat.exe`(headless)。
4. **"怎么控制它"靠声明式能力表**：已知工具(IDA/x64dbg/Ghidra/r2/tshark/diec/jadx/apktool/frida)写清"可执行/支持MCP/支持headless/GUI"。**表外未知工具只能探测路径，不能假装能控**。
5. **注册 MCP 要写当前 agent 的 mcp.json（增量合并），并提示"重启生效"**（协议层死规矩）。
6. **降级链**：已注册MCP → 现注册MCP(提示重启) → headless/CLI直调 → GUI(不推荐) → 自己写Py脚本。走不通如实报，不硬等。
7. **自动安装只做半自动**：探测→给安装命令+来源→用户确认→装→重探。**不做无脑全自动下载**。

### ★ 任务A 里主人最新补充的、极重要的一条（上一版设计要改）：
> **不要用 `-h` / `--help` 去探测工具能力！** 主人实测过：有些软件没有 `-h`，一探测就崩了，或者返回的代码不对。
> **正确做法：联网搜！** 去 GitHub / 官方文档 / 网络搜索"这个工具怎么用、支持什么 MCP、支持不支持 headless"，**搜出来的比现场 -h 试探靠谱得多**。
> 所以"发现工具→知道怎么控它"这一步，优先用**联网检索**（GitHub 仓库 README、官方文档、已知 MCP 生态），而不是对二进制执行 `-h`。

### 任务B：彻底最终审查（"真能用"审查，不是功能审查）
主人要求：不是审功能，是审**"从零部署到真正使用，整条流程到底能不能跑通、以后用会不会出问题"**。
- 已在全新 clone 上验证过一次部署（extract-deps→install.ps1→58项全绿→MCP可启动），但**要在新对话里再严格走一遍完整流程**（尤其：换一台没装 Ghidra/IDA 的机器会怎样、MCP 重启是否生效、样本反编译产物会不会污染仓库）。
- 要重点审：**二开加入的东西，在真实使用中到底用不用得上、会不会互相打架**。

---

## 3. 已确认的"诚实不足"（评测结论，供参考）

- `decompile_auto` 现在**真驱动 Ghidra**（已修好，实测出真 C 伪代码），Ghidra 缺失时降级 r2。
- **Web/JS 去混淆无专门工具**（三方都弱，靠 js-reverse-mcp + KB）。
- **协议重放只支持 HTTP**，不支持 WebSocket/私有 TCP 重放（缺口）。
- **冷门格式（WASM/EVM/固件/SQLite）没有**——这是 REA 的独家护城河，主人说固件暂不做。
- 每个格式样本深度不够（原版 593 fork 长期打磨，我们样本多但深挖少）。

---

## 4. 铁律（做任何改动都守，否则破坏原版）

- **纯增量**：只新增文件 / 末尾追加 / 插入段落。**不改既有函数体、不删原版内容、不改体检既有判据**。
- 每次改完**必跑三条验收**：`check.ps1`（须全绿）+ `python Tool/mcp/test_seep_mcp.py`（9/9）+ `python Tool/mcp/test_ext_assets.py`（须全过）。
- 加工具后**必须接进 SKILL/SOP**（grep 必须命中）+ **补 CHANGELOG/版本** + **全仓工具数同步** + **依赖进 setup**。
- 详细流程见 `Tool/docs/MERGE-PLAYBOOK.md`（含"踩过的 7 个坑"，务必读）。

---

## 5. 环境事实（本机）

- 仓库工作副本：`D:\work\seep-fork`（origin=你的 fork，upstream=angusdevgo 原版）。
- 本机有：Ghidra(`D:\Tools\Ghidra`, JDK21 at `D:\Tools\runtime\jdk21\jdk-21.0.12.1+1`)、r2(内置)、jadx/apktool(内置)、tshark、curl_cffi、pefile、zstandard。
- **本机没有 IDA**（商业软件，探测不到，靠 r2/Ghidra 兜底）。
- 推送偶发网络 reset，**push 要带重试**（`for i in $(seq 1 8)` 循环直到 `git ls-remote origin main` 等于本地 HEAD）。

---

## 6. 交接时新对话的第一句话建议

> "先读 `Tool/docs/HANDOFF-交接文档.md`（本文件）和 `Tool/docs/MERGE-PLAYBOOK.md`，然后做任务A：轻量工具自动发现+自动适配MCP插件（用联网检索判断工具能力，不要用 -h 试探），做完跑三条验收，再做任务B彻底部署审查。"
