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
1. **跨平台**：路径一律 `os.path` / `shutil.which` / `os.path.expanduser`；探测根同时列 Windows(`D:\Tools`) 与 Unix(`/opt`,`/usr/bin`) 候选；绝不写死某一台机器的绝对路径。
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

## 7. 回退（永远留后路）

- 单个工具：`git revert <commit>` 或删掉对应函数块。
- 整批：`git checkout <扩展前的commit> -- <文件>`。
- 因为全是增量，回退**不会留半截补丁**。

---

## 8. 反面清单（做了就是破坏内核，禁止）

- ❌ 修改既有 `@server.tool()` 函数的实现体（要改行为 → 新增一个工具，别动老的）
- ❌ 删除/改写 `references/*.md` 既有正文（要补充 → 插入新段，标"新增"）
- ❌ 改 `setup/verify.ps1` 既有判据（要加 → 追加新 `Test-CheckItem`）
- ❌ 把别人的 2000+ 篇文档整坨倒进仓库（要知识 → 只挑真需要的几篇进 `kb/`）
- ❌ 生产代码里写死某台机器的绝对路径（如 `D:\Project\xxx`）
- ❌ 加工具不加体检项、不加测试用例

---

## 9. 一次融合的标准动作清单（照着打勾）

```
[ ] 1. 只读审计对方，确认它解决的是 Seep 真实痛点
[ ] 2. 确定属于哪一类（MCP工具 / 脚本 / 配置 / 文档 / 上游仓库）
[ ] 3. 按 §3 规范新增（跨平台、优雅降级、只读优先、结构化返回）
[ ] 4. 按 §4 在 verify.ps1 追加体检项
[ ] 5. 按 §5 在 test_ext_assets.py 加自包含测试
[ ] 6. 跑三条验收全绿
[ ] 7. git commit（message 写：加了什么/为什么/验收结果）
[ ] 8. 更新本文件 §10 的"已融合清单"
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

> 新批次请在此表追加一行，让下一个 AI 一眼知道"哪些已经融过、从哪来、怎么验的"。
