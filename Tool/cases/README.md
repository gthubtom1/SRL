# 案例库（Tool/cases）使用说明

> 这里存放**已发生过的真实逆向案例**，不是"怎么做"的知识库。
> 知识库（`Tool/mcp/Tool/reverselab/kb/` + `Tool/mcp/kb_local/`）回答"这类问题通常怎么打"；
> 案例库回答"上一次这个目标，哪条路成了、哪条路炸了、为什么"。

## 1. 目录结构

```
Tool/cases/
├─ README.md                 ← 本文件（约定与流程）
├─ index.json                ← 由脚本生成的派生索引（不要手改）
├─ 项目A/
│  ├─ case.json              ← 必填：结构化元数据（唯一事实来源）
│  ├─ README.md / README.txt ← 建议：案例总览
│  ├─ docs/                  ← 建议：逆向方法论、算法、协议、复盘
│  ├─ src/ tools/ dist/      ← 按需：源码、脚本、产物
│  └─ facts.jsonl            ← 可选：逐条事实/证据（一行一个 JSON）
└─ 案例-6.9换肤壳/
   ├─ case.json
   ├─ README.md
   └─ docs/
```

- `case.json` 是**唯一结构性入口**；README/docs 负责细节与证据。
- `index.json` 是缓存，可随时用脚本重建，**不要手工编辑**。
- 二进制样本默认不入库；需要时放 `work/` 或案例自己的 `samples/`。

## 2. `case.json` 字段

```json
{
  "id": "项目A",
  "domain": "windows-license",
  "target_type": "PE32+ x64",
  "protection": ["self-vm", "veh-guard"],
  "authority": "server",
  "goal_level": "L2",
  "outcome": "success",
  "artifacts": [{"path": "artifacts/x.dll", "sha256": ""}],
  "lessons": ["父进程必须是 explorer", "npcap 会导致 0xC000023E"],
  "tags": ["卡密", "心跳", "代理DLL"],
  "refs": ["README.md"],
  "updated": "2026-10-21"
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | 案例唯一标识，默认与目录名一致 |
| `domain` | string | 领域。当前取值：`windows-license`、`dotnet-license`、`java-license`、`windows-shell`；新领域请先在本文档登记 |
| `target_type` | string | 目标形态，如 `PE32+ x64`、`PE32 x86`、`.NET/WPF`、`Java JAR` |
| `protection` | string[] | 观察到的保护层，用短横线小写：`packer`、`themida`、`self-vm`、`ed25519`、`antidebug`、`auto-updater` … |
| `authority` | string | 授权裁决权威：`local` / `server` / `hybrid`；不确定留 `""` |
| `goal_level` | string | 达成深度：`L1` 侦察/思路、`L2` 补丁级、`L3` 模块级（代理 DLL / keygen / 注入器）、`L4` 源码级 |
| `outcome` | string | `success` / `partial` / `blocked` |
| `artifacts` | object[] | 可交付产物；`path` 相对案例目录，`sha256` 实测才填，否则留 `""` |
| `lessons` | string[] | 最值钱的部分：可复用判据、踩过的坑、被否决的方案 |
| `tags` | string[] | 检索关键词（中英混排均可） |
| `refs` | string[] | 相对案例目录的文档路径，按重要性排序 |
| `updated` | string | 最后更新日期 `YYYY-MM-DD` |

约定：

- **不编造**：没实测过的哈希、版本号、端点一律留空或写 `<redacted>`。
- `lessons` 写"判据"而不是流水账：一句话能指导下一次决策。
- 失败/中止的案例同样入库，`outcome` 填 `partial` / `blocked`，价值往往更高。
- 新领域先在 `domain` 里落地，并同步更新本表和 `Tool/docs/CASE-LIB.md`。

## 3. 新增案例

1. 建目录：`Tool/cases/<案例名>/`。
2. 写 `case.json`，至少填 `id/domain/target_type/authority/goal_level/outcome/updated`。
3. 补 `README.md`（总览）与 `docs/`（方法论/算法/复盘），把路径写进 `refs`。
4. 有产物则放 `src/`、`tools/`、`dist/`，并在 `artifacts` 登记；能算哈希就填 `sha256`。
5. 重新生成索引：

   ```bash
   python Tool/scripts/gen-case-index.py --stats
   python Tool/scripts/gen-case-index.py --check   # 应 rc=0
   ```

6. 如果新增了案例目录却忘了写 `case.json`，`--check` 会报错并列出目录。

## 4. 索引与新鲜度

`gen-case-index.py` 扫描 `Tool/cases/*/case.json`，输出：

- `schema`：索引结构版本（当前 `1`）；
- `generated_at`：生成时间（UTC）；
- `source_hash`：所有 `case.json` 的**相对路径 + 内容字节**按目录名排序后的 SHA-256；
- `case_count` 与 `cases[]`：归一化后的案例条目（含 `dir`）。

`source_hash` 是新鲜度判据：MCP 读取时会用它和磁盘现算值比对，不一致就退回实时扫描，避免返回过期索引。
`--check` 忽略 `generated_at`，只比较 `schema`、`source_hash`、`case_count`、`cases`。

## 5. 如何被 MCP 检索

两个工具（见 `Tool/mcp/seep_mcp_server.py` 的 `SEEP-EXT: case-lib` 块）：

- `seep_case_search(query, domain, protection, level, outcome, limit)`：
  优先读 `index.json`，索引过期或缺失时实时扫 `case.json`；对 `id/tags/lessons/domain/target_type/protection` 做加权子串打分，返回
  `{id, score, summary, path}` 列表。
- `seep_case_read(case_id)`：
  返回该案 `case.json` 全文 + `facts.jsonl` 前 20 行 + README 前 80 行，用于把"上次怎么做的"直接喂给当前会话。

典型用法：

```text
seep_case_search(query="卡密 心跳", domain="windows-license")
seep_case_search(protection="themida", level="L3")
seep_case_read(case_id="项目K")
```
