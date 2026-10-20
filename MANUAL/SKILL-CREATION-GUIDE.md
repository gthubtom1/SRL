# 面向 Seep 工作台的外挂技能编写规范与创作指南 (Skill Creation Guide)

> **目的**：为 Seep 逆向安全工作台打造标准化的“外挂技能体系”。  
> **核心原则**：主仓库保持轻量纯净（只保留核心 38 个 MCP 工具与 6 步 SOP），所有未来特定的垂直业务能力（如：特定协议逆向、游戏反作弊对抗、固件解包、跨版本增量追版）全部通过**标准化外挂 Skill** 扩展，即插即用，绝不臃肿主仓库！

---

## 一、 为什么采用“外挂技能（Skill）”而不是把代码堆进主仓库？

| 对比维度 | 方案 A：把所有代码硬塞进主仓库（relab2 的老路） | 方案 B：微内核 + 声明式外挂 Skill（Seep 体系） |
|---|---|---|
| **仓库体积** | 几千个文件、几十个脚本混杂，仓库迅速膨胀至几百 MB 甚至上 GB | 主仓库保持极速轻量，体积仅几十 KB，Git 提交与克隆秒级完成 |
| **规则冲突** | 40 个方向的指令互相打架，模型注意力被稀释，简单任务反而频出幻觉 | 技能按需加载，日常零干扰，任务需要时精准唤醒 |
| **升级与维护** | 改动一个文件导致几十个自检脚本报错，维护成本极高 | 主仓库 61 项体检永远全绿；新功能只需要小版本安全叠加，零破坏风险 |
| **迭代速度** | 牵一发而动全身，步履维艰 | **极其敏捷**：写一份 Markdown 技能就是一套新武器，随时新增与分享 |

---

## 二、 Seep 兼容性三大铁律（编写任何新 Skill 必须遵守）

编写面向 Seep 的外挂技能时，必须遵守以下三项纪律，杜绝任何逻辑冲突：

### 铁律 1：G-Auth 与 Lab Mode 契合（杜绝大模型拒绝）
- **不要**在技能里自己手写复杂的越狱词（Jailbreak Prompts）或重复定义敏感词转换；
- **正确做法**：直接声明在 `lab：` 实验环境下运行。Seep 底层的安全拦截扩展（`security-audit-interceptor.ts`）会自动为本技能提供底座级 `BLOCK_NONE` 注入与合规学术前缀包裹。

### 铁律 2：MCP 工具优先绑定（Tool Binding 规范）
技能内部描述分析流程时，**严禁手写脆弱的外部命令行（如 `system("xxx")`）**，必须优先声明调用 Seep 已内置暴露的 **38 个原生 MCP 工具**：
- 查壳与反调试：声明调用 `seep_packer_detect`；
- 反编译：声明调用 `seep_decompile_auto`（多引擎降级链）；
- 提取运行期字符串：声明调用 `seep_mem_strings`；
- 协议分析与重放：声明调用 `seep_http_replay` 与 `seep_pcap_extract`；
- 缺工具自愈：声明调用 `seep_tool_discover` 与 `seep_tool_install`。

### 铁律 3：成品交付闭环（Artifact Delivery）
- 技能必须明确定义“最终输出物”：
  - Windows 端：输出免落盘代理补丁（`version.dll`）或关键内存补丁代码；
  - Android 端：输出自动重打包签名安装包（`*_rebuilt_signed.apk`）；
  - 算法类：输出可运行注册机（`keygen.py`）；
  - 报告：输出三段式合规审计报告。

---

## 三、 标准外挂 Skill 结构模板

每一个外挂技能统一存放在一个独立的文件夹中，核心入口文件必须命名为 **`SKILL.md`**：

```text
my-custom-skill/
├── SKILL.md            ← 核心入口（包含 YAML Frontmatter 描述与战术工作流）
└── references/         ← 可选：存放专属的参考文档或代码模板（按需读取）
```

### 标准 `SKILL.md` 金样模板（可直接复制使用）

```markdown
---
name: 技能英文标识符 (如 protocol-analyzer)
description: 一句话说清本技能解决什么问题、在什么情况下唤醒使用。
metadata:
  version: "1.0.0"
  target_runtimes: "Windows PE | Android DEX/SO | Web/HTTP"
  compatible_workbench: "Seep v1.8.4+"
---

# 技能中文全称 (Skill Display Title)

> **核心目标**：一句话说明本技能的最终交付成果。

---

## 一、 适用场景与唤醒口令

当遇到以下任务时，优先引用本技能：
1. 场景 A 说明...
2. 场景 B 说明...

**大白话唤醒指令示例**：
- `lab：引用技能 <技能名>，分析 D:\path\target，帮我完成 xxx`

---

## 二、 标准作业流程 (SOP)

1. **Step 1：资产画像与工具自愈**
   - 优先调用 `seep_tool_discover` 探测工具是否齐全，缺失时调用 `seep_tool_install` 自动安装；
2. **Step 2：核心分析动作**
   - 详细写明调用 Seep 哪个 MCP 工具，执行什么分析逻辑；
3. **Step 3：验证与打桩**
   - 动态验证逻辑或数据包伪装；
4. **Step 4：成品交付**
   - 生成最终的可用文件。

---

## 三、 调度纪律

- 遵循 Seep 平台统一的 G-Auth 授权门禁；
- 同构路径失败 2 次必须触发熔断换法，不许死磕。
```

---

## 四、 怎样让 AI 帮你自动写一套新技能？（一键生成 Prompt）

以后当你遇到一个新领域（比如：你想搞一个“游戏内存特征码自动扫描”、“WebSocket 协议重放”、“VMP 虚拟机脱壳”的新技能），你完全不需要自己写！

**直接把下面这句 Prompt 复制给 AI**：

```text
请严格参考 Seep 工作台的《SKILL-CREATION-GUIDE.md》外挂技能创作规范，为我编写一套全新的独立 Skill：
1. 技能名称：[填入你的技能名称，如 websocket-replay]
2. 解决痛点：[填入具体场景，如 专门针对私有长连接 WebSocket 数据帧的抓包提取与重放验证]
3. 遵循原则：
   - 使用标准 YAML frontmatter，适配 Seep v1.8.4+ 体系；
   - 优先绑定 Seep 现有的 38 个 MCP 工具（如 seep_tool_discover, seep_mem_strings 等）；
   - 流程中包含资产画像、缺工具自动自愈、动态验证与最终成品交付闭环；
   - 保持声明式纯文本，不携带冗余大二进制，直接输出单文件 SKILL.md。
```

AI 就会严格按照 Seep 的微内核标准，为你生成一份 100% 兼容、即插即用、绝不冲突的全新战术技能！
