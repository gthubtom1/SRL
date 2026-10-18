# EXT-ASSETS · Seep 扩展资产说明（relab2 / REA 适配）

> 本文件说明在 Seep 基座上**纯增量**加入的扩展资产：加了什么、为什么加、怎么验收、怎么回退、以后怎么继续加。
> 所有扩展都是"增量挂载"——**不改 Seep 内核逻辑（既有工具/路由/体检脚本一行未动）**。
> 基线不变：`check.ps1` 核心 50 项全绿、原 `test_seep_mcp.py` 9/9。

---

## 一、为什么加这些（补 Seep 的三个盲区）

Seep 在"授权/许可、APK、协议"上很强，但面对**加壳 / 反调试 / 资源藏载荷 / 卡密在云端**这类样本时，有四个具体不足（都来自 relab2 换肤 6.9 实战暴露）：

| Seep 原本的不足 | 后果（实战） | 本次补法 |
|---|---|---|
| 判型只看文件名/大白话 | 裸路径不带关键词 → 判型落空 | `preflight-classify.py`：判型前先读文件头 |
| 缺工具就报错/瞎猜路径 | 终端里 `NOT FOUND` 空转 | `seep_ensure_tool()`：四级探测 + 安装建议 |
| 反编译硬绑 R2 | 遇重型壳力道不够 | `seep_decompile_auto()`：IDA→Ghidra/REA→R2 降级 |
| **没有资源层/内存层/协议层工具** | 换肤器 21MB 皮肤包、运行期解密字符串、云端卡密回包——全都看不见 | `seep_pe_resources` / `seep_mem_strings` / `seep_pcap_extract` |
| 缺"何时该换法"的硬阈值 | 单点死磕几百轮 | `windows-sop.md` 插入"攻坚者五条 + 换法阈值" |

---

## 二、加了哪些资产（两批，共 5 个工具 + 1 个预判器 + 1 段姿态）

### 第一批（判型 / 工具发现 / 反编译降级）

| 资产 | 类型 | 落点 |
|---|---|---|
| `preflight-classify.py` | 判型前预判脚本 | `Tool/skill/softseep/scripts/` + SKILL.md 加 6 行调用说明 |
| `seep_ensure_tool()` | MCP 工具 | `seep_mcp_server.py` 末尾追加 |
| `seep_decompile_auto()` + `engine-tiers.json` | MCP 工具 + 声明式配置 | `seep_mcp_server.py` + `Tool/config/` |
| 攻坚者五条 + 换法阈值 | 文档段 | `softseep/references/windows-sop.md` Step1 前插入 |

### 第二批（资源 / 内存 / 协议——治"Seep 看不到活体与载荷"）

| 资产 | 治什么样本 | 核心能力 |
|---|---|---|
| `seep_pe_resources()` | 换肤器/皮肤包/内嵌 DLL | 枚举 PE 资源树 + 节熵 + 容器嗅探（zstd/zip/pe…），可选剥离落盘 |
| `seep_mem_strings()` | 运行期才解密的字符串 | 只读扫活体进程内存，提取 ASCII/UTF-16 字符串 + 虚拟地址 |
| `seep_pcap_extract()` | 卡密/授权在云端 | tshark 提取端点 / HTTP 请求响应 / 指定端口 TCP 载荷 |

配套：`Tool/mcp/test_ext_assets.py`（20 项扩展自测，独立于原 9/9 基线）。

---

## 三、怎么验收（每次改动后必跑）

```powershell
# 1. 全量体检（必须仍 50 项全绿）
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

## 六、资产来源与许可

- `preflight-classify` / `ensure_tool` 四级探测 / 攻坚者五条：源自 relab2 实战（本机项目）。
- 多引擎降级链：源自 REA 的 provider 降级思想。
- 全部为本仓纯增量实现，遵循本仓 GPL-3.0。
