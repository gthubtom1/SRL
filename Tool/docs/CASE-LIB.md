# 案例库（CASE-LIB）—— 与知识库的分工、索引与门禁

> 面向主线维护者与 AI Agent。案例库位于 `Tool/cases/`，知识库（KB）位于
> `Tool/mcp/Tool/reverselab/kb/` 与 `Tool/mcp/kb_local/`。
> 一句话：**KB 讲"通常怎么做"，案例讲"上次这个目标成了/失败了，为什么"**。

## 1. 为什么需要两套库

| 维度 | 知识库（KB） | 案例库（CASE-LIB） |
|---|---|---|
| 回答的问题 | 这类问题一般怎么打？ | 这个目标上次怎么打的？结果如何？ |
| 内容形态 | 通用战术、checklist、payload、CVE/CTF 套路 | 具体目标画像、保护层、补丁点、产物、被否决方案 |
| 时效性 | 长期有效，可跨目标复用 | 绑定版本/构建号，厂商更新即可能失效 |
| 失败记录 | 很少 | **重点保留**：`partial` / `blocked` 同样是资产 |
| 检索入口 | `seep_kb_search` / `seep_kb_read` | `seep_case_search` / `seep_case_read` |
| 事实来源 | 方法论与经验 | `case.json` + README/docs + `facts.jsonl` |

使用顺序建议：

1. 先 `seep_case_search` 找同目标 / 同保护 / 同领域的旧案例，避免重复踩坑；
2. 没有案例或案例已过期，再用 `seep_kb_search` 找通用战术；
3. 本次结束后回填 `case.json` 与 docs，把"判据"和"否决方案"写进 `lessons`。

## 2. 数据模型

每个案例目录必须有一个 `case.json`（字段定义见 `Tool/cases/README.md`）。
`index.json` 是**派生缓存**，由 `Tool/scripts/gen-case-index.py` 生成，禁止手改。

索引结构：

```json
{
  "schema": 1,
  "generated_at": "2026-10-21T00:00:00Z",
  "source_hash": "<sha256>",
  "case_count": 15,
  "cases": [
    {"dir": "项目A", "id": "项目A", "domain": "reverse", "...": "..."}
  ]
}
```

### `source_hash` 怎么算

按目录名排序，对每个 `case.json` 依次喂入：

```
"Tool/cases/<dir>/case.json" + "\0" + <文件原始字节> + "\0"
```

最后取 SHA-256。它覆盖"哪些案例存在"与"每个案例的元数据内容"，因此：

- 改任意 `case.json` → `source_hash` 变化；
- 新增/删除案例目录 → `source_hash` 变化；
- 只改 README/docs 或 `index.json` 自身 → **不**变化（正文由 `seep_case_read` 现读）。

## 3. 生成与校验

```bash
# 生成 / 刷新索引（并打印分布）
python Tool/scripts/gen-case-index.py --stats

# 门禁：索引与磁盘不一致则 rc=1
python Tool/scripts/gen-case-index.py --check

# 仅看分布
python Tool/scripts/gen-case-index.py --stats
```

`--check` 比较 `schema`、`source_hash`、`case_count`、`cases`，忽略 `generated_at`；
并额外检查"有案例目录但缺 `case.json`"的情况。输出示例：

```text
[OK] 案例索引已是最新：15 个案例，source_hash=18607e50437a
```

## 4. 新鲜度与 MCP 行为

`seep_case_search` / `seep_case_read` 在 `Tool/mcp/seep_mcp_server.py` 的
`SEEP-EXT: case-lib` 块中实现，不依赖 KB 的 glob 逻辑。

- 有 `index.json` 且 `source_hash` 与磁盘现算值一致 → 用索引；
- 索引缺失/过期/解析失败 → **实时扫 `case.json`**，并自行计算 `source_hash`；
- `seep_case_read` 始终现读文件，所以 README/docs 的更新无需重建索引；
- 所有错误都以字符串返回（`[ERROR]: ...`），不向 MCP 客户端抛异常。

`seep_case_search` 打分权重（简单子串，大小写不敏感）：

| 字段 | 权重 |
|---|---|
| `id` | 10 |
| `tags` | 6 |
| `lessons` | 4 |
| `domain` / `protection` | 3 |
| `target_type` | 2 |
| `authority` / `outcome` / `refs` | 1 |

多 token 查询按 token 累加；`domain` / `level` / `outcome` 为精确过滤（大小写不敏感），
`protection` 为子串过滤。返回 `{id, score, summary, path}`，按分数降序。

## 5. 接入门禁（给主线）

推荐在以下时机跑：

```bash
python Tool/scripts/gen-case-index.py --check
```

- PR / 提交前：新增或修改 `case.json` 后忘记重建索引会被拦下；
- CI：与 `preflight.py`、`verify.*` 并列，作为"案例库结构一致性"检查；
- 发布前：确保 `index.json` 的 `source_hash` 与仓库内案例一致。

建议的失败处理：

| 现象 | 处理 |
|---|---|
| `source_hash 过期` | 运行 `python Tool/scripts/gen-case-index.py` 后重跑 |
| `缺少 case.json` | 补元数据；无元数据的目录会被排除，检索不到 |
| `case id 重复` | 改 `id` 或目录名，保证唯一 |
| `schema 不一致` | 升级脚本与索引结构版本，勿手改 `schema` |

## 6. 维护约定

1. `case.json` 里的 `artifacts[].sha256` **只填实测值**；未测就留 `""`。
2. `lessons` 写可复用判据，不写过程流水账；失败路线单独成条。
3. 版本/哈希脱敏用 `<目标版本>`、`<redacted>`，不要写真实客户信息。
4. 新领域（`domain`）、新等级语义变更，必须同步更新
   `Tool/cases/README.md` 与本文档，再重建索引。
5. `index.json` 冲突时不要手工合并：取任意一侧，重跑生成脚本即可。
