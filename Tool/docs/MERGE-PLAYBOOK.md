# MERGE-PLAYBOOK · 向 Seep 融合新项目/新技能的**唯一标准流程**

> **给任何未来接手的 AI（无论哪个模型、有没有上下文）**：
> 本文件是"往 Seep 里加东西"的**唯一规范**。照它做，内核永不被破坏、换机永不挑电脑、体检永远全绿。
> 不照它做（尤其是直接改既有函数体、或把别人的文档整坨倒进来）——就是在重蹈"越融越烂"的覆辙。

---

## 0. 一句话原则

> **只做三种动作：新增文件、末尾追加、插入段落。**
> **绝不修改任何既有函数体、绝不删除既有内容、绝不改体检脚本的既有判据。**
> 所有"融合"都是**增量挂载**，不是"改写重造"。

---

## 1. 先判断：这次要加的，属于哪一类？（决定放哪里）

| 你要加的东西 | 放哪里 | 动作 | 要不要登记 |
|---|---|---|---|
| 一个新的**分析能力**（如脱壳、反调试检测、资源提取） | `seep_mcp_server.py` 末尾追加 `@server.tool()` 函数 | 追加 | 在 `setup/verify.ps1` 加一条存在性校验（见 §4） |
| 一个新的**判型/辅助脚本**（不属于 MCP 工具） | `Tool/skill/softseep/scripts/` 新增 `.py` | 新增 | SKILL.md 里加一行调用说明 |
| 一条新的**引擎降级链**或工具别名 | `Tool/config/engine-tiers.json` | 改配置 | 无（配置驱动） |
| 一段新的**实战姿态/判据/阈值** | 对应 `references/*.md` **插入**一段 | 插入 | 无 |
| 一整套**新战场技能**（如 macOS、固件、内核） | `Tool/skill/<新名>/SKILL.md` + `references/` | 新增目录 | `softseep/SKILL.md` 的"可调度资源"表加一行 |
| 新的**知识库文章** | `Tool/mcp/Tool/reverselab/kb/<分类>/` | 新增 `.md` | 无（`seep_kb_search` 自动收录） |
| 别人的**整个上游仓库** | `Tool/upstream/<名>/` + `setup/upstream-rules.json` 加声明 | 新增目录 + 声明 | 用 `setup/sync-upstream.py` 定点同步 |
| 一段**跨宿主纪律**（Lab 开关 / 反退缩 / 工具纪律 / G-Auth） | `Tool/prompts/AGENTS.md` 对应章节 | **插入**一段 | 不要复制到别处；它已是唯一事实源 |
| **pi 装配契约 / 层间裁决** | `Tool/prompts/SEEP.md`（**硬上限 2,500 字符，只放指针**） | 改结构 | 必须跑 verify（体检项「SEEP.md 契约态」） |
| **人格卡 / 风格层的规则** | `~/.pi/agent/personas/*.md`（**不入仓库**） | 用户自管 | 人格卡只写风格；scope/授权/词表属 L0/L1 |

**判断口诀**：能被模型当"工具"调用的 → MCP 工具；能被模型"读"的战术 → references/kb；能被"自动探测"的 → config。

---

## 2. 融合前的准备（只读审计，不改）

1. **先读透对方**：`git log --oneline`（看它怎么迭代）、`ls Tool/`（看它的扩展位）、`cat setup/upstream-rules.json`（看它怎么管上游）。
2. **只挑"真本事"**：问一句"这东西解决的是 Seep 现在就有的痛点吗？" 不是就**不要加**（为加而加 = 熵增）。
3. **对照 Seep 现有能力**：先确认 Seep 真的没有（`grep -iE "def seep_(关键词)" seep_mcp_server.py`），避免重复造轮子。

---

## 3. 加 MCP 工具的硬性规范（最常用）

### 3.1 位置
永远加在 `seep_mcp_server.py` 的 `# 主入口` 注释块**之前**，`@server.tool()` 装饰器。

### 3.2 必须遵守的 5 条
1. **跨平台**：路径一律 `os.path` / `shutil.which` / `os.path.expanduser`；探测根由 `tool_autodiscover.candidate_roots()` **动态生成**（环境变量 → 用户级 `~/.seep/tools` → 各盘符常见目录名 → `/opt`、`/usr/bin`），安装目标固定用户级；**绝不写死某一台机器的盘符或绝对路径**。
2. **优雅降级**：依赖库缺失（如 pefile）→ 返回 `[ERROR]: 需要 xxx（pip install xxx）`，不抛异常、不崩溃。
3. **只读优先**：默认不修改目标文件；需要写盘时默认关，参数显式开启（如 `extract_dir=""`）。
4. **平台守卫**：仅 Windows 可用的（如 `ReadProcessMemory`）开头判断 `sys.platform != "win32"` 直接返回明确提示。
5. **返回结构化**：返回 `json.dumps(..., ensure_ascii=False, indent=2)`，字段名清晰；错误也返回可读字符串。

### 3.3 模板
```python
@server.tool()
def seep_你的工具名(arg1: str, arg2: int = 0) -> str:
    """一句话说清：治什么样本、做什么、返回什么。

    Args:
        arg1: ...
        arg2: ...
    """
    if not os.path.isfile(arg1):
        return f"[ERROR]: file not found: {arg1}"
    # 依赖缺失优雅降级
    try:
        import 某库  # noqa: F401
    except Exception:
        return "[ERROR]: 需要 某库（pip install 某库）"
    # ... 实现 ...
    return json.dumps({...}, indent=2, ensure_ascii=False)
```

---

## 3bis. 改「提示词层」的硬性规范（v1.10.0 起）

| 规则 | 为什么 |
|---|---|
| `SEEP.md` **只放指针**：层间裁决 + 去哪查；**不写**工具数量、不列技能清单、不复制拒答词表 | 这些每换一次就过期一次；写进去后 `verify.ps1` 的「SEEP.md 契约态」会判红（≤2500 字符 / 无「N 个工具」/ 必须保留 AGENTS.md、routing.json、seep_status 三个指针） |
| 战术细节写 `references/*.md` 或技能，**不写进提示词** | 提示词每轮都进上下文，写多了纯烧 token |
| 边界（凭据红线 / 授权门 / 沙箱契约）只写在**扩展常量**里，不写到人格卡 | 人格卡是用户随时替换的资产，边界不能跟着一起换 |
| 人格卡只写风格（语气/人称/开场/角色扮演）；**scope、授权、banned-token、路由表都属 L0/L1** | 人格卡一写这些就与边界锚正面冲突（锚会赢，但纯浪费上下文） |
| 改完必须验证两次：`verify.ps1 -Detailed` + 起一个会话看装配 dump | 位置类问题（锚在不在末尾、段有没有重复）只有实测能证明 |
| 层规则与人格卡兼容矩阵的唯一说明：`MANUAL/PROMPT-LAYERS.md` | 避免"改提示词"的知识散落在聊天记录里 |

---

## 4. 加工具后必须做的"体检登记"（否则换机测不到）

在 `setup/verify.ps1` 的 `[5/9]` 段，**追加**一条 `Test-CheckItem`（不改既有条目）：

```powershell
Test-CheckItem "MCP" "你的新能力（简述）" {
    $sp = Join-Path $ToolDir 'mcp\seep_mcp_server.py'
    if (Test-Path $sp) {
        $src = Get-Content -LiteralPath $sp -Raw -Encoding UTF8
        ($src -match 'def seep_你的工具名')
    } else { $false }
} "新能力缺失" "工具定义存在" "$ToolDir\mcp\seep_mcp_server.py"
```

这样任何新机器拉下来跑 `check.ps1`，都会验证你的工具在不在——**这就是"不挑电脑、拉下来就能用"的保证**。

---

## 5. 每加一批，必须跑的三条验收（缺一不可）

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File ./check.ps1   # 必须全绿（项数只增不减）
cd Tool/mcp && python test_seep_mcp.py                            # 原基线 9/9 不能掉
cd Tool/mcp && python test_ext_assets.py                          # 扩展自测全过
```

**新增工具必须同时在 `test_ext_assets.py` 加对应用例**（用 `check(name, cond)` 风格），并且：
- 测试用**自包含样本**（仓库内置的 PE/ELF/pcap），或 `os.environ.get("SEEP_TEST_xxx", 本机路径)` 回退到内置——**绝不能只依赖某台机器才有的文件**。

---

## 6. 融合"别人的上游仓库"（大块头）

Seep 已有现成机制，**照抄它的声明式做法**，不要手工 copy：

1. 在 `setup/upstream-rules.json` 的 `upstreams` 里加一条：
   ```json
   "某上游": {
     "repo": "https://github.com/xxx/yyy.git",
     "branch": "main",
     "target_dir": "Tool/upstream/某上游",
     "allowed_boundary": "Tool/upstream/某上游",
     "preserve_local": ["README.md"]
   }
   ```
2. 跑 `python setup/sync-upstream.py --target 某上游`（它会做 `realpath` 边界断言，防止外溢）。
3. 上游更新后，跑 `python setup/sync-upstream.py --target 某上游` 即可增量同步，**本地定制不被覆盖**。

> 这就是 Seep 融合别人项目的"正规军"方式——**声明式 + 物理边界隔离**。我们新增的 `Tool/upstream/relab2-*` 将来也照此管理。

---

## 6bis. 练习样本与"外部样本不入仓库"原则

- **练习样本**放在 `Tool/samples/`，全部**从源码现场编译**（`build.ps1`），构建产物（`*.exe`/`*.res`/`payload.bin`）已 gitignore，不入库。
- 好处：无版权/恶意软件传播风险、可复现、可审计。
- **许可证宽松（MIT/BSD/Apache）的真实样本可收进 `Tool/samples/real/`**：必须带原始 LICENSE、写清来源，随仓库分发（保证换机有真实样本可用）。当前已收 crackerjack(MIT) + MaxXor KeygenMe V7(MIT)。
- **无许可证 / 恶意样本绝不提交进仓库**：
  1. 放本地 `work/`（已 gitignore）；
  2. 用环境变量 `SEEP_TEST_PE=/path/sample.exe` 喂给测试；
  3. 仓库只保留"怎么采集、怎么喂"的说明，不保留二进制本身。

---

## 7. 回退（永远留后路）

- 单个工具：`git revert <commit>` 或删掉对应函数块。
- 整批：`git checkout <扩展前的commit> -- <文件>`。
- 因为全是增量，回退**不会留半截补丁**。

---

## 8. 反面清单（做了就是破坏内核，禁止）

- ❌ 修改既有 `@server.tool()` 函数的实现体（要改行为 → 新增一个工具，别动老的）
- ❌ 往 `Tool/mcp/Tool/**`（内置工具/知识库）这类 **vendored 上游树**里加新内容 —— 将来重新 vendor 会被覆盖。
  本地新增的 KB 内容请放 `Tool/mcp/kb_local/`；确需改 vendored 文件（如模板）时，必须在 `FORK-DELTA.md` 记一条"重新 vendor 需重放"。
- ❌ 删除/改写 `references/*.md` 既有正文（要补充 → 插入新段，标"新增"）
- ❌ 改 `setup/verify.ps1` 既有判据（要加 → 追加新 `Test-CheckItem`）
- ❌ 把别人的 2000+ 篇文档整坨倒进仓库（要知识 → 只挑真需要的几篇进 `kb/`）
- ❌ 生产代码里写死某台机器的绝对路径（带盘符的个人项目目录）
- ❌ 加工具不加体检项、不加测试用例

---

## 8bis. ⚠️ 真实踩过的坑（每次融合前必读，防复发）

> 以下是 2026-10-19 本轮二开时**真实发生过的错误**。第一次自审时，8 个工具做完了、体检也绿了，
> 但**如果没有主人要求“以第三人视角再审一次”，这些问题全会带进成品**。
> 所以这一节不是理论，是血泪——**你（未来的 AI）做融合时，先对照这一节自查，别重蹈覆辙。**

### 坑 1：工具做完了，但没接进 SKILL/SOP → 智能体根本不会用（最致命）
- **现象**：8 个工具写进 `seep_mcp_server.py`、MCP 也暴露了、测试也过了，但 `softseep/SKILL.md`、`references/`、`MANUAL/` 里**一次都没提**。
- **后果**：工具在列表里躺着，但智能体判型后不知道该调它们——等于“造了刀却没告诉人刀在哪”。
- **自查**：`grep -rl "seep_你的工具名" Tool/skill/`，**必须命中**。零命中 = 没接进流程 = 不算完成。
- **正确做法**：在 `softseep/SKILL.md` 判型表 + 资源表 + 扩展工具速查表里点名；必要时在对应 `references/*.md` 的 SOP 步骤里写“先调 X 再…”。

### 坑 2：包装上过度承诺（名不副实）
- **现象**：`seep_decompile_auto` 描述写“IDA→Ghidra/REA→R2 自动降级”，实际代码遇到 ida/ghidra/rea 一律 `continue`，只跑 r2。
- **后果**：智能体以为能自动驱动 IDA，结果拿到的永远是 r2 结果，产生误判。
- **正确做法**：docstring 如实写清“直接执行的是 r2，高阶引擎只探测并告知”。**宁可说小，不可说大。**

### 坑 3：CHANGELOG / VERSION 不更新
- **现象**：加了一堆功能，`docs/CHANGELOG.md` 无记录、`VERSION` 还是旧的。
- **后果**：破坏原版“严格维护 CHANGELOG + 语义化版本”的工程习惯，别人升级时不知道多了什么。
- **正确做法**：每批功能 → `docs/CHANGELOG.md` 加条目 + `VERSION` bump（如 1.6.0 → 1.7.0）。

### 坑 4：新工具的依赖没进 setup → 别人拉下来跑不了
- **现象**：`seep_pe_resources` 依赖 `pefile`、`http_replay` 依赖 `curl_cffi`，但 `setup/install-python.ps1` 只装 mcp/pytest/frida。
- **后果**：新机器上这些工具直接报错或降级，违背“拉下来就能用”。
- **正确做法**：新工具用到第三方库 → 加进 `setup/install-python.ps1` 和 `install.sh`（可选依赖，缺失时优雅降级，不阻断安装）。

### 坑 5：测试没进体检 / 依赖外网 → 坏了没人知道
- **现象**：`test_ext_assets.py` 只有手动跑，不在 `check.ps1`/CI 里；且用了 `httpbin.org` 外网。
- **后果**：别人拉下来，扩展一旦坏了，体检照样全绿；没网时测试跑不了。
- **正确做法**：测试必须接进 `check.ps1`（或 CI）；测试样本必须自包含（内置 PE/ELF，或用本地回环 HTTP 服务，不用外网）。

### 坑 6：全仓工具数/文档数字不同步
- **现象**：加了 8 个工具，但 README/README.zh/CLAUDE/DEPLOYMENT-CHECKLIST/PROVENANCE 里还写“23 工具 / 22 工具”。
- **后果**：文档与代码打架，误导使用者。
- **正确做法**：加工具后 `grep -rn "23 工具\|22 工具\|23 native"` 全仓扫一遍，统一更新。

### 坑 7（元教训）：不要相信“我做的肯定没问题”——必须做第三人视角自审
- **现象**：第一次做完时自己觉得“都绿了、完成了”，但实际有上面 6 个坑。**是主人要求“以第三人视角再评一次”才暴露的。**
- **教训**：**做完 ≠ 做好。** 每次融合后，必须强制做一次“陌生人视角”自审：
  1. 假装你第一次拿到这个仓库，问“智能体真会用到我加的东西吗？”
  2. 跑 `grep` 确认每个新工具都被 SKILL/SOP 引用；
  3. 跑一次**干净环境**（无外网、无本机特化文件）看是否真的可用；
  4. 对照上面 1–6 逐条打勾。
- **一句话**：**“功能写完”只是 60%，剩下 40% 是“接进流程 + 工程收尾 + 第三人自审”。**

---

## 9. 一次融合的标准动作清单（照着打勾）

```
[ ] 1. 只读审计对方，确认它解决的是 Seep 真实痛点（不是为加而加）
[ ] 2. 确定属于哪一类（MCP工具 / 脚本 / 配置 / 文档 / 上游仓库）
[ ] 3. 按 §3 规范新增（跨平台、优雅降级、只读优先、结构化返回）
[ ] 4. 按 §4 在 verify.ps1 追加体检项
[ ] 5. 按 §5 在 test_ext_assets.py 加自包含测试（不用外网）
[ ] 6. ★ 把新工具接进 SKILL/SOP（softseep/SKILL.md 判型表 + 资源表；必要时 references 的 SOP 步骤）——grep 必须命中
[ ] 7. ★ 依赖进 setup（install-python.ps1 / install.sh）
[ ] 8. ★ CHANGELOG 加条目 + VERSION bump
[ ] 9. ★ 全仓工具数/文档数字同步（grep 23/22 残留）
[ ] 10. 跑三条验收全绿（check.ps1 + test_seep_mcp 9/9 + test_ext_assets）
[ ] 11. ★ 第三人视角自审：假装第一次拿到仓库，问“智能体真会用我加的东西吗？干净环境真能跑吗？”
[ ] 12. git commit（message 写：加了什么/为什么/验收结果）
[ ] 13. 更新本文件 §10 的"已融合清单"
```

---

## 10. 已融合清单（持续追加，供后人追溯）

| 批次 | 资产 | 来源 | 落点 | 验收 |
|---|---|---|---|---|
| 批1 | `preflight-classify.py` | relab2 | `Tool/skill/softseep/scripts/` | 判型前预判，SKILL.md 已挂 |
| 批1 | `seep_ensure_tool()` | relab2 | `seep_mcp_server.py` | 四级探测，ext 测试覆盖 |
| 批1 | `seep_decompile_auto()` + `engine-tiers.json` | REA 思想 | `seep_mcp_server.py` + `Tool/config/` | 降级链，ext 测试覆盖 |
| 批1 | 攻坚者五条+换法阈值 | relab2 | `windows-sop.md` | 文档插入 |
| 批2 | `seep_pe_resources()` | relab2 实战 | `seep_mcp_server.py` | ext 测试覆盖 |
| 批2 | `seep_mem_strings()` | relab2 实战 | `seep_mcp_server.py` | ext 测试覆盖 |
| 批2 | `seep_pcap_extract()` | relab2 实战 | `seep_mcp_server.py` | ext 测试覆盖 |
| 批3 | `seep_http_replay()` | 协议重放需求 | `seep_mcp_server.py` | ext 测试覆盖 |
| 批3 | `seep_packer_detect()` | relab2 + 本仓 UNPACKING/ANTI-DEBUG 手册 | `seep_mcp_server.py` | ext 测试覆盖 |
| 批3 | `seep_web_recon()` | 渗透轻量侦察需求 | `seep_mcp_server.py` | ext 测试覆盖 |
| 批3 | `Tool/config/tool-install.json` | P4 按需下载 | `Tool/config/` + `seep_ensure_tool` | ext 测试覆盖 |

> 新批次请在此表追加一行，让下一个 AI 一眼知道"哪些已经融过、从哪来、怎么验的"。
| 批4 | `tool_autodiscover.py` + `tool-capabilities.json` | 任务A：工具自动发现+MCP适配（能力事实联网检索核实） | `Tool/mcp/` + `Tool/config/` | ext 测试覆盖（60项） |
| 批4 | `seep_tool_discover/control_plan/research/register_mcp/install/state`（6个） | 同上（薄封装） | `seep_mcp_server.py` 末尾追加 | ext 测试覆盖 + verify 追加 2 项 |
| 批4 | 本机状态 `~/.seep/tools.local.json` | 每机不同，绝不入库 | `.gitignore` 忽略 `.seep/` | 状态隔离校验 |
