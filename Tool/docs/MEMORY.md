# MEMORY —— 案子记忆层（自动记录 + 触发式读取）

> 配套实现：`Tool/prompts/extensions/seep-memory.ts`（pi 扩展）
> 设计来源：6.8 会话最后 40 分钟。核心要求只有两句：
> **记录由插件自动做，不要塞进提示词；读取要触发式，启动只给一张地图。**

---

## 0. 一分钟上手

```powershell
# 1. 每个案子一个目录，用环境变量指过去（不设则默认 ./.seep-case）
$env:SEEP_CASE_DIR = "D:/work/项目J"

# 2. 目录不存在时扩展完全空转：不创建、不记录、不报错。
#    开案子时先建目录，插件才会开始记账。
New-Item -ItemType Directory -Force "$env:SEEP_CASE_DIR/memory" | Out-Null
```

| 命令 | 作用 |
|---|---|
| `/map` | 打印 `memory/map.md`（最多 40 行） |
| `/facts` | 打印 `memory/facts.jsonl` 最近 20 条摘要 |
| `/traps` | 打印 `memory/traps.md`（最多 60 行） |
| `/memory-note <文本>` | 追加一条 `note` 到 `events.jsonl` |

插件注册的事件：`session_start` / `input` / `tool_call` / `turn_end` / `before_agent_start`。
所有 IO 都在 `try/catch` 里；写盘失败只会让这一条记忆丢失，**不会影响会话**。

---

## 1. 四层文件：谁写、写什么、什么时候读

| 文件 | 写入者 | 内容 | 默认读取时机 | 体积上限（约定） |
|---|---|---|---|---|
| `events.jsonl` | **插件自动**（`session_start` / `input` / `tool_call` / `turn_end` / `/memory-note`） | 原始事件流：时间、kind、工具名、摘要、cwd | **默认不读**。只在复盘时间线、对账、排查"到底做过什么"时读 | 只追加，不自动删；单案建议 ≤ 5 MB，超了人工归档 |
| `facts.jsonl` | agent（标记 `@@FACT`）/ `case_state.py` / `/memory-note` 以外的结论写入 | 结论 + 证据速记 | 阶段零闸、换会话、`/facts` | 读最近 20 条；文件建议 ≤ 500 行 |
| `map.md` | agent，每 20 分钟 checkpoint 维护 | 当前地图：已证 / 待验 / 下一步 / 坑 | **每次 run 开始自动注入**（硬上限 1.5 KB）+ `/map` | **≤ 40 行且 ≤ 1.5 KB** |
| `traps.md` | agent / 用户 / 标记 `@@TRAP` | 踩过的坑：停 npcap 抓包全空、父进程必须是 explorer、int3 崩…… | 同一手法失败 **2 次**后主动读；或 `/traps` | **≤ 20 行**（插件打印最多 60 行） |
| `gates.md` | 标记 `@@GATE` | 门禁结论（D0–D5 / gate 通过或阻塞原因） | 需要复核阶段结论时 | ≤ 50 行（约定） |
| `dead.md` | 标记 `@@DEAD` | 已证死的路线，防止绕回去 | 重判方向前 | ≤ 50 行（约定） |

> `gates.md` / `dead.md` 是标记通道的落点，不要求每个案子都有。

### 与 `case_state.py` 的关系

`case_state.py` 用的是 **`<case>/facts.jsonl`（案子根目录）**，那是权威结论账（带 `claim/status/evidence/ttl`、深度门、可行性裁定）。
`memory/facts.jsonl` 是**插件侧速记**，只保存模型在输出里标了 `@@FACT` 的短句。

- 两者**不互相覆盖**；正式结论以 `case_state.py` 为准。
- 需要机器可验的证据链 → 走 `case_state.py`；需要"刚才那句结论别丢" → `@@FACT` 落到 `memory/facts.jsonl`。
- 不要把 `memory/facts.jsonl` 当门禁输入；门禁只认 `case_state.py gate`。

---

## 2. 触发式读取：只注入地图，不注入流水账

`before_agent_start` 每次 run 只做一件事：

1. 读 `<case>/memory/map.md`；
2. 按 **40 行 + 1.5 KB** 双重截断（header/footer 也算在 1.5 KB 里）；
3. 挂到系统提示词的 `seep-memory-map` section；
4. 文件不存在或为空 → **连 section 都不建**。

明确不注入：

- `events.jsonl`（原始事件流，量最大、信噪比最低）；
- `facts.jsonl` / `traps.md` / `gates.md` / `dead.md`（按需用命令读，或由 agent 在失败 2 次后自己读）。

这样长跑时上下文不会被"我三个小时前跑过一条 ls"撑爆，但换会话又不会失忆。

---

## 3. 标记约定（只加权，不是唯一通道）

模型可以在回复里单独起一行写：

```text
@@FACT: 权威在服务端（证据：第 1 秒 winhttp 请求）
@@TRAP: 停 npcap 会导致抓包全空
@@GATE: D2 pass（LoadLibrary 命中 winhttp）
@@DEAD: 改 hosts 绕不过，服务端走 IP 直连
```

插件在 `turn_end` 解析这些行：

| 前缀 | 落点 | 存储格式 |
|---|---|---|
| `@@FACT` | `memory/facts.jsonl` | 一行 JSON：`{ts,source:"marker",kind:"fact",text,cwd}` |
| `@@TRAP` | `memory/traps.md` | `- [ts] 文本` |
| `@@GATE` | `memory/gates.md` | `- [ts] 文本` |
| `@@DEAD` | `memory/dead.md` | `- [ts] 文本` |

规则：

- 前缀**不落盘**：写入前会去掉 `@@FACT` 和其后的 `:` / `：` / `-` / 空白。
- 允许行首有列表符号：`- @@TRAP ...`、`* @@FACT ...`。
- 同一条消息里重复的标记只写一次。
- **标记只是加权**：没写标记，`events.jsonl` 仍然照常记录，不会"模型不写就全丢"。
- 标记内容同样过隐私检查：命中凭据词 → 不写目标文件，只在 `events.jsonl` 留一条 `redacted`。
- 标记不改变聊天记录本身；它只负责把内容**另存**到记忆层。

---

## 4. 隐私红线（硬约束）

1. **不写凭据**
   摘要命中 `Authorization` / `Bearer` / `token` / `password` / `secret` / `api_key` / `私钥` / `密码` 等词时，
   整条摘要丢弃，只写：

   ```json
   {"ts":"...","kind":"user","summary":"redacted","cwd":"...","redacted":true}
   ```

   不写原文、不写命中的片段、不写"疑似是什么"。

2. **不写文件内容**
   - `read` / `grep` / `find` / `ls`：只记路径、pattern、query。
   - `write` / `edit`：只记 `content:1234c(未记录正文)` 这样的**字符数**，绝不记正文、old/new 文本、patch。
   - `tool_call` 只记录"调用了什么"，不记录 `tool_result` 的结果正文。

3. **不记录会话 id / 用户目录以外的环境**
   事件里只有 `ts`、`kind`、`tool`、`summary`、`cwd`，以及 `redacted` 标记。

4. **写不进去就放弃**
   所有写盘都在 `try/catch` 内；权限不足、磁盘满、目录消失都只会静默丢这一条，不弹错、不阻断 run。

---

## 5. 体积治理

| 项 | 上限 | 超限行为 |
|---|---|---|
| 单条 `summary` | 200 字符 | 截断并加 `…` |
| 注入的 `map.md` | 40 行 + 1.5 KB | 截断并加 `…（截断）`，不阻断 run |
| `/map` 输出 | 40 行 | 截断并提示 |
| `/facts` 输出 | 最近 20 条 | 只取尾部 |
| `/traps` 输出 | 60 行 | 截断并提示 |
| `events.jsonl` | 单案建议 5 MB | 插件不自动删；人工归档/清空后再继续 |

`map.md` 是唯一进入提示词的记忆文件，所以它必须**短**：

```markdown
# 地图 · 项目J（2026-10-21 17:20）

## 已证
- 授权在服务端（winhttp，证据 C01）
- 客户端只做本地缓存校验（D2 pass）

## 待验
- 缓存文件是否签名（下一步：procmon 看写入路径）

## 下一步
1. 断网重放，确认是否回退到本地授权
2. 若回退 → 记录 @@FACT 并更新 verdict

## 坑
- 停 npcap 会让抓包全空；动之前先 env-ledger record
```

---

## 6. 运维与排错

| 现象 | 原因 / 处置 |
|---|---|
| 完全没有 `memory/` 目录 | `SEEP_CASE_DIR` 没设，或指向的目录不存在。插件对不存在的 case **不创建**。 |
| 有目录但没有 `events.jsonl` | 没有任何事件触发，或目录不可写。先跑一轮工具调用再看。 |
| 启动时没有注入地图 | `map.md` 不存在或为空。这是**故意**的：没地图就不占上下文。 |
| `/facts` 只有 redacted | 写结论时命中了凭据词。改写成不含密钥的描述，或只写证据位置。 |
| 想手工补一条 | `events.jsonl` 只追加；补历史直接追加一行 JSON 即可。`map.md` / `traps.md` 直接编辑。 |
| 想关掉 | 不设 `SEEP_CASE_DIR`，且当前目录没有 `.seep-case/`，扩展等同空转。 |

**是否需要在 settings 里启用？**
不需要单独开关。pi 会自动加载 `~/.pi/agent/extensions/` 下的 `.ts`（本仓安装器会把
`Tool/prompts/extensions/*.ts` 复制过去）。只有把扩展放到**自定义路径**时，才需要在
`settings.json` 的 `extensions` 数组里登记。扩展是否需要"启用"取决于 case 目录是否存在，
而不是 settings 开关。

---

## 7. 验收清单

- [ ] 设好 `SEEP_CASE_DIR`，建出 `<case>/memory/`。
- [ ] 跑一次工具调用 → `events.jsonl` 出现 `kind:"tool"`。
- [ ] 发一条含 `token=...` 的输入 → 只出现 `summary:"redacted"`，原文不在文件里。
- [ ] 让模型回一行 `@@FACT: ...` → `facts.jsonl` 出现去前缀的记录。
- [ ] 写一份 ≤ 40 行的 `map.md` → 新 run 的提示词里有 `seep-memory-map`，且 ≤ 1.5 KB。
- [ ] `map.md` 不存在 → 提示词里没有该 section。
- [ ] 目录不存在 → 不创建目录、不报错。
