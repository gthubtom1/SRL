# EXT-ASSETS · Seep 扩展资产说明（relab2 / REA 适配）

> 本文件说明在 Seep 基座上**纯增量**加入的扩展资产：加了什么、为什么加、怎么验收、怎么回退、以后怎么继续加。
> 所有扩展都是"增量挂载"——**不改 Seep 内核逻辑（既有工具/路由/体检脚本一行未动）**。
> 基线不变：`check.ps1` 核心 65 项全绿、原 `test_seep_mcp.py` 9/9、扩展自测 73 passed。

---

## 一、为什么加这些（补 Seep 的三个盲区）

Seep 在"授权/许可、APK、协议"上很强，但面对**加壳 / 反调试 / 资源藏载荷 / 卡密在云端**这类样本时，有四个具体不足（都来自 relab2 换肤 6.9 实战暴露）：

| Seep 原本的不足 | 后果（实战） | 本次补法 |
|---|---|---|
| 判型只看文件名/大白话 | 裸路径不带关键词 → 判型落空 | `preflight-classify.py`：判型前先读文件头 |
| 缺工具就报错/瞎猜路径 | 终端里 `NOT FOUND` 空转 | `seep_ensure_tool()`：四级探测 + 安装建议 |
| 反编译硬绑 R2 | 遇重型壳力道不够 | `seep_r2_decompile()`：IDA→Ghidra/REA→R2 降级 |
| **没有资源层/内存层/协议层工具** | 换肤器 21MB 皮肤包、运行期解密字符串、云端卡密回包——全都看不见 | `seep_r2_cmd(iR)` / `seep_mem_strings` / `seep_pcap_extract` |
| 缺"何时该换法"的硬阈值 | 单点死磕几百轮 | `windows-sop.md` 插入"攻坚者五条 + 换法阈值" |

---

## 二、加了哪些资产（三批，共 8 个 MCP 工具 + 1 个预判器 + 2 份配置 + 2 段姿态/文档）

> 汇总：MCP 工具 23 → **40**（17 个扩展）；核心体检 50 → **65 项**；原 MCP 基线 9/9 不变；扩展自测 73 passed。
> 相对原版 `upstream/main`，`seep_mcp_server.py` **净删除 0 行**（纯追加）。

### 第一批（判型 / 工具发现 / 反编译降级）

| 资产 | 类型 | 落点 |
|---|---|---|
| `preflight-classify.py` | 判型前预判脚本 | `Tool/skill/softseep/scripts/` + SKILL.md 加 6 行调用说明 |
| `seep_ensure_tool()` | MCP 工具 | `seep_mcp_server.py` 末尾追加 |
| `seep_r2_decompile()` + `engine-tiers.json` | MCP 工具 + 声明式配置 | `seep_mcp_server.py` + `Tool/config/` |
| 攻坚者五条 + 换法阈值 | 文档段 | `softseep/references/windows-sop.md` Step1 前插入 |

### 第二批（资源 / 内存 / 协议——治"Seep 看不到活体与载荷"）

| 资产 | 治什么样本 | 核心能力 |
|---|---|---|
| `seep_r2_cmd(iR)()` | 换肤器/皮肤包/内嵌 DLL | 枚举 PE 资源树 + 节熵 + 容器嗅探（zstd/zip/pe…），可选剥离落盘 |
| `seep_mem_strings()` | 运行期才解密的字符串 | 只读扫活体进程内存，提取 ASCII/UTF-16 字符串 + 虚拟地址 |
| `seep_pcap_extract()` | 卡密/授权在云端 | tshark 提取端点 / HTTP 请求响应 / 指定端口 TCP 载荷 |

配套：`Tool/mcp/test_ext_assets.py`（63 项扩展自测，已接进 `check.ps1` 自动跑，且不依赖外网）。

---

## 三、怎么验收（每次改动后必跑）

```powershell
# 1. 全量体检（必须 65 项全绿）
powershell -NoProfile -ExecutionPolicy Bypass -File ./check.ps1

# 2. 原 MCP 基线（必须仍 9/9）
cd Tool/mcp && python test_seep_mcp.py

# 3. 扩展资产自测（必须全过）
cd Tool/mcp && python test_ext_assets.py
```

> 三条全绿 = 增量没破坏内核。任何一条变红，先看 `git diff` 是否误改了既有文件。

---

## 四、怎么回退（安全）

所有扩展都是独立文件 + 末尾追加 + 插入段，回退极简单：

```bash
# 回退到扩展前的干净 Seep：
git checkout main            # 或 upstream/main
git branch -D feat/relab2-rea-assets

# 或只回退某个资产：删对应文件 / 用 git revert <commit>
```

因为**没有改动任何既有函数体**，回退不会留下"半截补丁"。

---

## 五、以后怎么继续加（照这个粒度，永远不破坏内核）

| 你要加什么 | 怎么做 | 改哪里 | 内核动吗 |
|---|---|---|---|
| 加一个 MCP 工具 | 在 `seep_mcp_server.py` 末尾追加 `@server.tool()` 函数 | 单文件追加 | ❌ |
| 加一个判型/辅助脚本 | 放进 `Tool/skill/softseep/scripts/`，SKILL.md 加一行调用说明 | 新增文件 | ❌ |
| 加一条引擎/降级链 | 改 `Tool/config/engine-tiers.json` | 改配置 | ❌ |
| 加一段实战姿态/阈值 | 在对应 `references/*.md` **插入**一段，不覆盖原文 | 插入 | ❌ |
| 加一个战场（如 macOS/固件） | 新建 `Tool/skill/<name>/SKILL.md` + `references/` | 新增目录 | ❌ |

**铁律：只做"新增文件 / 末尾追加 / 插入段落"，绝不改既有函数体、不改体检脚本、不改路由矩阵结构。**

---

## 五bis、第三批（P1 协议重放 / P2 加壳反调试工具化）

| 资产 | 治什么 | 核心能力 |
|---|---|---|
| `seep_http_replay()` | 协议签到 / 接口重放 / 回包验证 | curl_cffi TLS 指纹伪装（chrome/safari/edge/ff）+ Cookie 会话保持 + 任意方法/头/体；无 curl_cffi 自动降级 requests |
| `seep_packer_detect()` | 加壳 / 反调试样本 | 节名/节熵判壳 + 反调试导入 + 反虚拟机字符串，直接给"该读 UNPACKING.md / ANTI-DEBUG.md 哪一节"的路由 |

**P2 的定位（回应"基于 190+188 行手册是什么意思"）**：
Seep 原本已有 `MANUAL/ANTI-DEBUG.md`(190行) 和 `MANUAL/UNPACKING.md`(188行)——这两本手册已经写清了"反调试信号怎么判、壳怎么脱"的完整打法。
所以 P2 **不是从零写新知识**，而是把手册的"判断逻辑"做成一个自动工具 `seep_packer_detect`：一条命令判出"有没有壳、什么壳、有没有反调试"，并**指向手册对应章节**。
这样智能体不用人肉翻手册，也不重复造轮子——**工具负责判，手册负责打**。

---

## 五ter、第三批续（P3 渗透轻量 / P4 按需下载）

| 资产 | 治什么 | 核心能力 |
|---|---|---|
| `web-check.py()` | Web/API 逆向前的轻量侦察 | 响应头/技术栈指纹/安全头缺失/常见入口探测（robots/.git/.env）；**只读不攻击**，重型渗透走独立 MCP |
| `Tool/config/tool-install.json` + `seep_ensure_tool(allow_install)` | 真需要某工具时才装 | 声明式安装清单（pip/winget/npm/go/manual），`allow_install=True` 且方法在白名单才自动执行，装完自动重探 |

**P3 的定位（渗透只补一点点）**：只补"和逆向/协议相关"的那一小块——Web 指纹、接口发现、头分析。
**不塞扫描器/爆破/利用框架**（那会让主服务臃肿、且与逆向无关）。重型渗透若需要，走独立 MCP（如 pentestMCP），不并入 seep 内核。

**P4 的定位（按需下载，不无脑）**：`seep_ensure_tool` 缺工具时返回 `install_plan`（可执行命令 + 来源）；
只有显式 `allow_install=True` 且方法属 pip/winget/npm/go 白名单才自动装；`manual` 类（如 IDA 商业软件）永远只给下载链接不自动装。

---

## 六、资产来源与许可

- `preflight-classify` / `ensure_tool` 四级探测 / 攻坚者五条：源自 relab2 实战（本机项目）。
- 多引擎降级链：源自 REA 的 provider 降级思想。
- 全部为本仓纯增量实现，遵循本仓 GPL-3.0。
