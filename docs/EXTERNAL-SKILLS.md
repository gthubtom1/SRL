# 外部技能评估：exe-reverse（codeberg.org/reverse-skill-lab/exe-reverse）

> 评估日期：2026-10-25。目的：判断它能不能融入本项目、让逆向技能更完善。

## 一、它是什么

一个**面向 Windows x86/x64 本地软件**的 Agent Skill（Codeberg，MIT，Python 3.10+）：

| 维度 | 内容 |
| :-- | :-- |
| 形态 | `skills/exe-reverse/`：`SKILL.md`（流程+闸门）+ `references/`（按需加载）+ `scripts/`（可跑）+ `evals/` + `evidence/` |
| 覆盖 | 分诊、等长字节补丁、签名/特征、调试、注入、dump 修复、**授权机制分类**、算法还原、壳与代码虚拟化、托管程序集、内核驱动、**硬件观测层**（指令跟踪 / 硬件断点 / hypervisor 辅助） |
| 明确不覆盖 | 服务端权威、通用自动化 devirtualiser、把"能打某商业壳"当作产品承诺；Unity IL2CPP 元数据恢复与打包 Python 标为 `unverified` |
| 证据口径 | 强度标签 `observed / inferred / unverified` —— 与我们 `E1/E2` + `CM.OBS/INF` 同构 |
| 质量工程 | 6 个维护闸：`check_repo` / `check_refs` / `check_routing` / **`check_commands`** / `check_budget` / `build_scripts`；CI 跑 pytest + mypy + flake8 |
| 设计主张 | 「失败的形态不是无知，而是模型读完全文、点头同意，然后照样从第一性原理推理」→ 所以写成**带闸门的流程**，不是建议；两击熔断；"完成"有 6 项定义，干净日志不算 |

## 二、结论：**部分吸收，不整体并入**

### 不整体并入的理由

1. **领域名额**：我们 9 个域各有 `pack.json` + 见证 + 6 道 gate；把它做成第 10 个域要按 C1 给真见证，
   属结构变更（外部评审 Agent-3 也明确"不要再加领域"）。
2. **载体重叠**：它 = Windows PE 本地软件，与 `softseep`（PE/ELF/Mach-O 通用二进制）重叠，
   并排会导致"同一句话两个域都像"的串味。
3. **宿主差异**：它用 `npx skills add` 装，我们用 `Tool/skill/*` + `install-pi.ps1`；直接搬会破部署判据。

### 值得吸收的 5 条（按价值排序）

| # | 吸收什么 | 为什么值 | 落点 |
| :-: | :-- | :-- | :-- |
| 1 | **`check_commands.py` 思路：文档里的命令参数必须真存在于 argparse** | 两轮外部评审各抓到一次同类缺陷（`report --check`、`check.ps1 -Detailed`、已退役的 setup 自检脚本）；这是最便宜也最伤信任的一类 | ✅ **已落地**：`Tool/scripts/lib/doc_commands.py` + preflight 判据「文档命令参数存在」（负向验证过） |
| 2 | **"完成"的 6 项定义（干净日志不算完成）** | 我们只有"报告五段"，缺"什么不算完成"的明确否定表 | 待办：并入 `PM-SPEC §3.3` 与 `case_state.py report --check` |
| 3 | **硬件观测层**（指令跟踪 / 硬件断点 / hypervisor 辅助） | 我们的 ACE/VMProtect 类样本卡在"壳上做静态"，硬件层是唯一出路 | 待办：写成 `softseep/references/hw-observation.md`，并标注**需确认**（可能要管理员/hypervisor） |
| 4 | **`doctor.py` 能力探针的"下一步建议"输出**（每个 blocked 项给 next action + 成本） | 我们的 `tool-acquire --sweep` 只报可用/缺失，不给"下一步做什么" | 待办：`--sweep` 增加 `next` 字段 |
| 5 | **两击熔断 + 症状索引=停止信号** | 我们已有 `seep-circuit`（连续同形状失败 2 次即拦）与症状索引，口径一致 | ✅ 已有，无需动作 |

### 边界（避免破坏现有约束）

- 保持 9 个域：它做成第 10 个域需要按 C1 给真见证，且会与 softseep 串味
- 只吸收要点：直接搬它的 `SKILL.md` 会与我们 pack/gate/证据契约冲突（会破现有 6 道判据）
- 安装仍走我们的路径：`npx skills` 方式会破部署双向判据

## 三、如果要真用它的内容，正确路径

按 `PROMPT-LAYERS` / `EXTEND.md` 的加技能 4 步，而不是复制文件：

1. 把它的 `references/*` 里我们需要的那几篇（补丁工程、授权分类、壳/虚拟化、硬件观测）
   **改写**进 `softseep/references/`（保留出处注释）
2. 在 `softseep/SKILL.md` 的参考索引里加一行"何时加载"
3. 若引入新脚本，按 `Tool/config/tool-effects.json` 登记（缺登记 MCP 起不来）
4. 跑 `check.py --fix`；`skill-import.py` 面向"整包技能"；"吸收某几篇"要手工改写进 references

## 四、一句话总结

> **它是同类里质量最高的一份 PE 逆向 skill，但对我们来说价值不在"再加一个域"，
> 而在 5 个可吸收的做法**——其中最有价值的一条（文档命令必须存在）今天已经落地成判据。
