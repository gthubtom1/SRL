# AUTONOMY —— 长跑契约与环境收尾

> 解决的问题只有两个：
> 1. 用户说"别一直停下来问"，模型却每 5 分钟请示一次；
> 2. 为了跑案子停了驱动 / 改了代理 / 改了系统时间，跑完忘了还原，机器留在半坏状态。
>
> 本文件是**行为契约**；可执行的账在 `Tool/skill/softseep/scripts/env-ledger.py`，可执行的记忆在
> `Tool/docs/MEMORY.md` + `seep-memory.ts`。

---

## 0. 契约速查

| 项 | 值 |
|---|---|
| 只在四类情况停 | 破坏性改动 / 凭据 / 需要用户操作 / 预算耗尽 |
| checkpoint 间隔 | **每 20 分钟**写一次 `map.md`（不打扰用户） |
| 请求确认门槛 | **连续 30 分钟无实质进展**才问 |
| 环境变更 | 必须先 `env-ledger record`，写清 `before/after/restore` |
| 退出前 | `restore` 全部 → `check` 返回 **0**，否则不许结案 |

---

## 1. 长跑模式声明

在案子根目录放 `<case>/autonomy.json`：

```json
{
  "mode": "long-run",
  "stop_only_on": [
    "destructive",
    "credential",
    "user-action-required",
    "budget-exhausted"
  ],
  "max_silent_minutes": 30,
  "checkpoint_every_minutes": 20
}
```

字段含义：

| 字段 | 含义 |
|---|---|
| `mode` | `long-run` = 用户已授权连续推进；`interactive` = 每阶段可停 |
| `stop_only_on` | **只有**这四类允许主动中断。其余情况继续做，把判断写进 `map.md` |
| `max_silent_minutes` | 连续多久没有实质进展才允许请求确认（默认 30） |
| `checkpoint_every_minutes` | 多久写一次 checkpoint（默认 20），只写文件，不弹问题 |

> 没有 `autonomy.json` 时按 `interactive` 处理：可以按阶段汇报，但仍受"四类才停"约束，
> 不能因为"这一步有点难"就停。

---

## 2. 只在这四类情况停

### 2.1 破坏性改动（destructive）

必须停、必须解释、必须等确认：

- 删除/覆盖**不可再生**的产物：原始样本、dump、报告、案例库、用户文档；
- 格式化磁盘、重建分区、批量删注册表、`reg delete HKLM\...` 整键；
- 卸载系统组件 / 驱动 / 安全软件；改系统时间并**不打算还原**；
- 对**非副本**目标做写操作（补丁只许打在副本上）；
- 任何"重装系统才能恢复"的操作。

不算破坏性、**不要停**：

- 停/起 npcap、vgk 这类可逆驱动（走 ledger，退出还原）；
- 改系统代理、hosts、loopback IP（走 ledger，退出还原）；
- 在副本目录里改文件、打补丁、删中间产物；
- 重启目标进程、换父进程、重新挂调试器。

### 2.2 凭据（credential）

发现即停、报告、**不写入任何输出/文件**：

- 明文密码、Token、API Key、私钥、证书私钥、Salt；
- 授权服务器地址 + 凭据组合；
- 用户目录下的浏览器 cookie / 凭据库。

处置：只说"在 `<文件/位置>` 发现了疑似凭据，已停止，未读取/未落盘"，不贴内容。
记忆层的 `redacted` 机制只负责"不落盘"，不能替代"发现即停"。

### 2.3 需要用户操作（user-action-required）

- 需要人工点 GUI、插设备、换网络、提供账号、在目标机器上执行命令；
- 需要用户确认法律/授权边界（用户已声明受权沙箱的除外）；
- 需要用户从外部获取文件（样本、安装包、License）。

请求时必须给出：**要用户做什么、为什么非他不可、做完后模型从哪继续**。

### 2.4 预算耗尽（budget-exhausted）

- token / 时间 / 轮次预算到上限；
- 连续两次同一手法失败且没有新假设（"同一形状失败两次即停"）；
- 外部服务持续不可用，重试只会烧钱。

停下时给：已花费、已证/未证、剩余可选项、建议下一步。

### 2.5 明确不要停的情况

以下都不是中断理由：

- 任务难、路径长、工具慢；
- 还没找到答案；
- 用户没回消息（长跑模式下继续，写 checkpoint）；
- 出现了"敏感"字样但目标在受权沙箱内；
- 单个命令超时（换路线/加 timeout，不是问用户）；
- 上下文快满了（先压缩/写 `map.md`，不是停）。

---

## 3. 每 20 分钟 checkpoint（不打扰用户）

到点后**不弹问题**，只做三件事：

1. 更新 `<case>/memory/map.md`（≤ 40 行）：
   - 已证（带证据指针）
   - 待验（下一条要跑什么）
   - 下一步（1–3 条，可执行）
   - 坑（新增的写 `traps.md`，地图里只留一行指针）
2. 追加一条 note：

   ```text
   /memory-note checkpoint 17:20 · 已证 C01/C02 · 下一步断网重放
   ```

   或直接写 `events.jsonl`（只追加）。
3. 如有环境变更，确认 `env-ledger list` 里没有漏记。

> checkpoint 是**写给下一个会话看的**，不是写给用户看的。判断标准：
> 换一个完全失忆的模型接手，只看 `map.md` 能不能在 5 分钟内继续干。

---

## 4. 30 分钟无进展才请求确认

"无进展"指**没有新增证据、没有缩小范围、没有排除假设**，不包括"命令跑了 20 分钟"。

请求确认时必须包含：

```text
已连续 30 分钟无实质进展。
已证：...
已排除：...（怎么排除的）
卡点：...（具体到哪一步、报什么错）
我打算：A ... / B ... / C ...
需要你定：选哪条，或给我一个新信息（账号/样本/环境）。
```

不许用"要不要继续"这种空问题；不许把"我没思路"包装成"需要授权"。

---

## 5. 环境变更必须走 `env-ledger`

### 5.1 先记后改

```powershell
# 停驱动
python Tool/skill/softseep/scripts/env-ledger.py record --case D:/work/项目J `
  --action "sc stop npcap" --before "running" --after "stopped" `
  --restore "sc start npcap"

# 改系统代理
python Tool/skill/softseep/scripts/env-ledger.py record --case D:/work/项目J `
  --action "设置系统代理 127.0.0.1:8080" --before "direct" --after "proxy=127.0.0.1:8080" `
  --restore "netsh winhttp reset proxy"

# 改系统时间（时间偏移实验）
python Tool/skill/softseep/scripts/env-ledger.py record --case D:/work/项目J `
  --action "系统时间 +30 天" --before "2026-10-21" --after "2026-11-20" `
  --restore "w32tm /resync"
```

顺序必须是：**record → 执行改动 → 验证 after → 继续分析**。
先改后记等于没记：中途崩溃就再也想不起 before 是什么。

### 5.2 台账规则

- 存储：`<case>/env-changes.jsonl`，一行一条，append-only 语义。
- `restore` 命令只允许白名单前缀：
  `sc ` / `net ` / `reg ` / `netsh ` / `w32tm ` / `powershell `
  （另允许 `echo `，仅用于自测，无副作用）。
- 非白名单 → **拒绝记录 / 拒绝执行**，提示人工。不要试图绕过。
- 拒绝链式与重定向：`&&` `||` `;` `|` `` ` `` `<` `>` `$(` 换行。要两步就记两条。
- 拒绝本机绝对路径（`C:\...`、`\\server\...`、`/home/...`）：台账要能换机复读，
  路径用环境变量（`%WINDIR%`）或相对路径。
- 单字段 400 字符；`restore` 留空 = 只能人工还原，`check` 会一直报未还原。

### 5.3 常用子命令

```powershell
python Tool/skill/softseep/scripts/env-ledger.py list    --case D:/work/项目J
python Tool/skill/softseep/scripts/env-ledger.py check   --case D:/work/项目J   # 未还原 → rc=1
python Tool/skill/softseep/scripts/env-ledger.py restore --case D:/work/项目J --dry-run
python Tool/skill/softseep/scripts/env-ledger.py restore --case D:/work/项目J
python Tool/skill/softseep/scripts/env-ledger.py check   --case D:/work/项目J   # 必须 rc=0
```

`restore` 的行为：

- 只处理 `restored:false` 的条目，按台账顺序执行；
- 成功 → 回写 `restored:true` + `restored_ts`；
- 失败 → 回写 `restore_error`，继续处理后面的条目，最终 rc=1；
- `--dry-run` 只打印命令，不执行、不回写。

---

## 6. 退出前收尾（硬门禁）

结案/换会话/交接前，按顺序执行：

```powershell
# 1. 还原所有环境变更
python Tool/skill/softseep/scripts/env-ledger.py restore --case D:/work/项目J

# 2. 门禁：必须返回 0
python Tool/skill/softseep/scripts/env-ledger.py check --case D:/work/项目J
if ($LASTEXITCODE -ne 0) { Write-Error "环境未还原，禁止结案"; exit 1 }

# 3. 记忆收尾：更新地图与结论
#    - map.md 写"最终状态 + 未完成项"
#    - @@FACT 落最终结论（或走 case_state.py claim/prove）
# 4. 报告里列出本次环境变更
python Tool/skill/softseep/scripts/env-ledger.py list --case D:/work/项目J
```

**禁止**：

- `check` 还有未还原项就写"已完成"；
- 用"重启后会自己恢复"当还原（驱动、代理、时间都不会）；
- 把 `restore_error` 藏起来不报告；
- 手工把 `restored` 改成 `true` 而不执行命令（除非用户明确说"这台机器不要了"）。

如果确实无法自动还原（比如需要重启、需要插回设备）：

1. 在 `--action` 里写清人工步骤；
2. `restore` 留空，让 `check` 保持 rc=1；
3. 在最终报告显眼位置列"未还原项 + 人工步骤"，不要假装通过门禁。

---

## 7. 报告与时间线

- 每个 checkpoint 的时间戳以 `events.jsonl` 为准；复盘时不要凭记忆改口径。
- 最终报告必须有两块：
  1. **环境变更**：`env-ledger list` 的结果（含已还原/未还原）；
  2. **结论证据**：`facts.jsonl` / `case_state.py` 里的 claim，不写没有证据的"已确认"。
- 如果中途改过判断，保留旧结论的 `refuted` 记录，不要删历史。

---

## 8. 与系统/用户指令的优先级

1. 平台安全策略、法律授权边界 **高于** 本契约；
2. 用户明确说"停" **高于** 本契约；
3. 本契约高于"模型自己觉得该问一下"的冲动；
4. 用户说"别停"不等于允许破坏性改动或碰凭据 —— 四类停仍然是硬边界。

---

## 9. 验收清单

- [ ] `<case>/autonomy.json` 存在，`mode=long-run`，四类停写全。
- [ ] 20 分钟 checkpoint 有落盘：`map.md` 的 mtime 在推进。
- [ ] 没有因为"难/慢/没回消息"主动停。
- [ ] 每次环境改动都有 `env-ledger record`，且 `restore` 非空（或明确写人工）。
- [ ] 退出前 `restore` 已跑，`check` rc=0。
- [ ] 最终报告列了环境变更与未还原项。
