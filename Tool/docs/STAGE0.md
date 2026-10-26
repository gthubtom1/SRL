# STAGE0 —— 阶段零出口物与出口闸（case_state.py）

> 对应技能：`Tool/skill/_pending/00-analysis/SKILL.md`
> 脚本：`Tool/scripts/case_state.py`
> 配置：`Tool/config/instrument-matrix.json`、`Tool/config/strategy.json`
>
> 本文是**详细说明**；技能文档里只保留结论与最短用法。两边冲突时以脚本行为为准（脚本可自测）。

---

## 0. 为什么要有这份文档

阶段零过去只要求"报告 8 节 + 可行性裁定"。实际事故里有三类反复出现：

1. **结论没有证据**，20 秒就报 GATE，还把旧报告当证据；
2. **没算缺件**：卡密拿不到、服务端已停，却在"直接重实现"上磨了 3 小时；
3. **没有路线菜单**：不写成功率、工时、失败判据，错了也不止损，一条路走到黑。

现在这些都被做成 `<case>/` 下的机读出口物，并由 `gate` 用退出码拦住：

| 文件 | 内容 | 谁写 |
|---|---|---|
| `facts.jsonl` | 事实账：结论 + 证据 + how + ttl + 状态 | `claim` / `prove` / `refute` / `stale` |
| `state.json`（或 `ai_manifest.json#seep`） | 深度、仪器、裁定、`goal_level` | `depth` / `instrument` / `verdict` / `choose` |
| `gaps.json` | 缺件经济学台账 | `gaps --add` |
| `plan.json` | L0–L4 路线菜单 + `chosen` | `plan` / `plan --from-advise` / `choose` |

> 上游 CTF 案子若已有 `ai_manifest.json`，状态仍写进它的 `seep` 子键（唯一恢复点不变）；
> `facts.jsonl` / `gaps.json` / `plan.json` 始终是独立文件。

---

## 1. 子命令总览

```bash
python Tool/scripts/case_state.py <cmd> --case <目录> ...
```

| 子命令 | 作用 | 退出码 |
|---|---|---|
| `init` | 建案（已存在且无 `--force` → 拒绝） | 0 / 2 |
| `claim` | 登记结论（`hypothesis` / `proven` / `refuted`，`proven` 必须有证据） | 0 / 2 |
| `prove` | 追加证据并置 `proven`；**可复活 `stale`** | 0 / 2 |
| `refute` | 标 `refuted` + `--by`（历史保留） | 0 / 2 |
| `stale` | TTL 失效：所有 `proven` → `stale`（保留证据） | 0 / 2 |
| `gaps` | 缺件台账：`--add` / `--list` | 0 / 2 |
| `plan` | 路线菜单：`--add`（逐条）/ `--list` / `--from-advise` | 0 / 2 |
| `choose` | 从菜单选定一条，写 `state.goal_level` | 0 / 2 |
| `advise` | 读两个矩阵 + 本案 gaps/instruments，打印建议菜单（**不写盘**） | 0 |
| `depth` | 深度门 D0–D7（`pass` / `fail` / `na`，`na` 必须写 note） | 0 / 2 |
| `instrument` | 仪器可行性 I0（至少 2 种，至少 1 种非 baseline 可用） | 0 / 2 |
| `verdict` | 可行性裁定 + 后端档位 → 交付上限 | 0 / 2 |
| `gate` | 阶段零出口闸 | **0 通过 / 1 未通过** |
| `deliver` | 交付分级闸（不许越级） | 0 / 2 |
| `show` / `resume` | 打印全量状态 / 接续摘要（含菜单与所选等级） | 0 |

参数/状态错误统一 `rc=2`；`gate` 不通过是 `rc=1`（不是参数错误）。

---

## 2. 事实账与 TTL

### 2.1 `claim` / `prove` / `refute`

```bash
claim --case $C --id C01 --text "权威在服务端" --status hypothesis --how triage
prove --case $C --id C01 --evidence "procmon 导出 <case>/artifacts/procmon.log → 第1秒出现 winhttp 请求"
refute --case $C --id C01 --by C05
```

- `proven` 必须有非空 `evidence`（空串/纯空格 = `rc 2`）；`proven` 还必须有 `how`（怎么测的）。
- `refuted` 必须带 `--by`。
- `claim --ttl "换 exe 即失效"` 记录失效条件（自由文本）+ `created`。

### 2.2 `stale`：整批失效 + 复验复活

```bash
stale --case $C --reason "换 exe:sha256 变了"
# 所有 proven → status=stale，写 stale_reason / staled_at，证据数组原样保留

prove --case $C --id C01 --evidence "复验：新 exe 同样第1秒 winhttp 出站"
# status 回 proven；旧 stale_reason 进 stale_history，证据累加
```

**闸规则**：只要还有 `stale` 且没有新的 `prove`，`gate` 拒绝，并提示"先复验或说明为何仍成立"。
"为何仍成立"也要落成一条新的 `prove --evidence`（可写"旧证据仍成立，因为 …"），不能只在聊天里说。

---

## 3. 缺件经济学（`gaps.json`）

### 3.1 登记

```bash
gaps --case $C --add --id G1 --missing "有效卡密" \
     --impact "拿不到合法响应/密钥" --repairable no --delta -0.45 \
     --alt "买真卡|旧版存档"
gaps --case $C --list
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `id` | string | `G1` / `G2`…，在 plan 的 `needs` 里引用 |
| `missing` | string | 缺少物（有效卡密 / 服务端私钥 / 旧版安装包） |
| `impact` | string | 拿不到会导致什么（要具体到"拿不到合法响应"） |
| `repairable` | `yes` / `no` / `partial` | 可补性 |
| `delta` | float `-1..1` | 概率折损（负数），如 `-0.45` |
| `alt` | string[] | 替代方案（CLI 用 `|` 分隔） |

### 3.2 阻断级缺件

定义：`repairable == "no"` 且 `delta <= -0.3`。

`gate` 对它做两件事：

1. **裁定 note 必须点名**（写 `G1` 或 `有效卡密` 都算），否则拒绝；
2. **菜单不得依赖它**：`plan` 条目的 `needs` 里出现缺件 id 或 `missing` 文本，即视为依赖 → 拒绝，
   并列出具体是哪几条路线。

> 注意："依赖"只认 `needs` 字段，不靠猜。所以登记路线时要把"需要卡密/需要服务端"写进 `needs`，
> 否则闸看不见，等于自己骗自己。

---

## 4. 路线菜单（`plan.json`）与 `choose`

### 4.1 逐条登记

```bash
plan --case $C --level L2 --route "字节补丁" --p 0.85 --hours "1-2" \
     --needs "" --fail "打完仍无界面"
plan --case $C --level L4 --route "源码级重实现" --p 0.4 --hours "12+" \
     --needs "完整行为规格" --fail "拿不到协议"
plan --case $C --list
```

| 字段 | 说明 |
|---|---|
| `level` | `L0` 只观测 / `L1` 旁路 / `L2` 补丁·代理 / `L3` 模块重写 / `L4` 源码级重实现 |
| `route` | 一句话路线名，阶段一按它执行 |
| `p` | 成功率先验 0–1（乘出来的，不是拍脑袋） |
| `hours` | 工时先验（区间） |
| `needs` | 依赖；引用阻断级缺件会被剔除 |
| `fail_criteria` | 失败判据（出现什么就停手） |
| `chosen` | 仅一条为 true，由 `choose` 维护 |

菜单样例（`plan --list` / `show` / `resume`）：

```text
级   成功率  工时      选中  路线 / 失败判据
L0    0.90   0.5-1           壳指纹 + 闸门盘点
L2    0.75   1-3       ✓     字节补丁（硬件断点定位）
      失败判据：打完仍无界面 / 校验和回滚
L4    0.40   12+            源码级重实现
      失败判据：拿不到协议或核心算法
      依赖/缺件：有效卡密(G1)
```

### 4.2 选定

```bash
choose --case $C --level L2 --route "字节补丁"
# plan.json: 该条 chosen=true，其余 false；state.goal_level=L2、goal_route=...
```

**闸规则**：

- `plan` 少于 2 条候选 → 拒绝；
- 已有 `verdict` 但 `chosen` 为空 → 拒绝（阶段一必须按选定等级执行）；
- 多条 `chosen` → 拒绝；
- `chosen.level` 与 `state.goal_level` 不一致 → 拒绝（重跑 `choose`）。

`deliver` 的越级检查仍按 `verdict` 的交付上限（M1–M4），不会被 `goal_level` 抬高。

---

## 5. 仪器矩阵与策略矩阵（`advise`）

### 5.1 `Tool/config/instrument-matrix.json`

按"壳/保护类型"给仪器建议，目前 6 类：

| id | 覆盖 |
|---|---|
| `integrity-shell` | 完整性校验壳（VMP / T壳 / 自校验） |
| `page-guard-veh` | 页守卫 / VEH 加密壳（Enigma / Obsidium / 自研） |
| `parent-process-check` | 父进程检测 / 启动链校验 |
| `kernel-driver-blacklist` | 内核驱动 + 进程黑名单（反作弊 / Themida+） |
| `unpacked-light` | 无壳 / 轻壳（UPX / NSIS / Delphi） |
| `dotnet-managed` | 托管 / .NET / IL2CPP / Unity |

结构：

```json
{
  "families": [
    {
      "id": "integrity-shell",
      "name": "完整性校验壳（VMP / T壳 / 自校验）",
      "match": ["vmp", "vmprotect", "themida", "t壳", "完整性校验", "自校验"],
      "allowed": ["hwbp", "external-read", "external", "network", "etw"],
      "banned": ["int3", "frida-spawn", "inject", "x64dbg"],
      "pitfalls": ["改 0xCC 必崩：软件断点会改字节，校验和/代码段 CRC 立刻发现"]
    }
  ]
}
```

仪器词表：`baseline` / `x64dbg` / `frida-spawn` / `frida-attach` / `external` / `network` /
`hwbp`（硬件断点 DR0–3）/ `int3`（软件断点）/ `external-read`（外部 RPM）/ `api-hook` /
`inject` / `etw` / `vm-snapshot` / `explorer-launch`。

`banned` 同时用于两件事：

1. `advise` 打印"禁用仪器 + 陷阱"；
2. 若某条策略路线声明了 `instruments` 且命中 `banned` → 该路线被剔除。

### 5.2 `Tool/config/strategy.json`

按形态 A–I（含 `plugin` / `backend`）给推荐路线，目前 10 个 form（A–I + `generic` 兜底）：

| id | 形态 |
|---|---|
| `local-unpacked` | A 纯本地 / 无壳原生 exe |
| `pe-shelled` | B PE 有壳（VMP / T壳 / 完整性校验） |
| `page-guard-veh` | C 页守卫 / VEH 加密壳 |
| `dotnet-managed` | D 托管 / .NET / IL2CPP / Unity |
| `server-cardkey` | E 服务端权威 + 卡密 / 授权票据 |
| `driver-anticheat` | F 内核驱动 + 进程黑名单 / 反作弊 |
| `plugin` | G 插件形态（宿主 + DLL/扩展） |
| `backend` | H 自带后端 / C-S 一体 |
| `multi-killswitch` | I 多层 kill-switch / 静默失败 |
| `generic` | 形态未定（兜底） |

结构：

```json
{
  "forms": [
    {
      "id": "pe-shelled",
      "letter": "B",
      "name": "PE 有壳（VMP / T壳 / 完整性校验）",
      "match": ["pe-shelled", "有壳", "vmp", "themida", "完整性校验"],
      "routes": [
        {"level": "L2", "route": "字节补丁（硬件断点定位）", "p": 0.75,
         "hours": "1-3", "needs": "可写副本 + 校验范围",
         "fail": "打完仍无界面 / 校验和回滚", "instruments": ["hwbp", "external"]}
      ]
    }
  ]
}
```

`needs` / `instruments` 是可选的（`fail` 为失败判据）。

### 5.3 `advise`

```bash
advise --case $C --form pe-shelled
advise --case $C            # 省略 --form：用 target + claim + 仪器名自动匹配，兜底 generic
```

- 只读：不写 `plan.json` / `state.json`；
- 过滤顺序：**阻断级缺件依赖** → **路线声明仪器被壳族禁用** → **路线声明仪器在本案被实测 blocked/killed**；
- 输出：形态、仪器族（可用/禁用/陷阱）、阻断缺件、可选路线（含 p/工时/失败判据）、已剔除路线及原因。

### 5.4 `plan --from-advise`

```bash
plan --case $C --from-advise --form pe-shelled
```

把 `advise` 的**可行路线**一次性写入 `plan.json`（`chosen=false`，`source="advise:<form>"`），
已存在的 `(level, route)` 自动跳过。若过滤后一条不剩 → `rc 2`，提示先补缺件/换形态。

---

## 6. 深度门 D0–D7

| 级 | 名称 | 要求 |
|---|---|---|
| D0 | 结构 | 节表/资源/导入/字符串/熵，能说出"东西都在哪" |
| D1 | 存活 | 能否到第一个窗口；双击 与 程序拉起**分开测** |
| D2 | 动态依赖 | 运行时实际加载的网络/加密库（加载器视角） |
| D3 | 出站行为 | DNS/TCP、明文或 TLS、时间点 |
| D4 | 对照实验 | 断网 / 换目录 / 改时间，各重跑，说"变/不变" |
| D5 | 钥匙归属 | 文件里 / 内存里 / 授权后产生；缺哪把、何时产生 |
| D6 | kill-switch 层数（可选） | 几层独立闸门，是否**逐层**验证 |
| D7 | 静默失败面（可选） | 进程活着但不干活：网络/文件/窗口/API 序列**四路**是否查过 |

```bash
depth --case $C --level D6 --result pass --note "发现 2 层独立闸门，均逐层验证"
depth --case $C --level D7 --result na   --note "本样本无静默失败面（窗口正常出现）"
```

规则：

- D0–D5 缺失、`fail`、`na` 无 note、D0–D5 **全 na** → `gate` 拒绝（原有规则）；
- D6/D7 缺失 → **只告警**，不阻断（避免老案子全红）；
- 裁定写 `可赢` 时，D6/D7 必须登记且 note 非空（结果可为 `pass` 或 `na`），
  且 D6/D7 不得为 `fail`，否则拒绝。

---

## 7. `gate` 规则汇总

### 阻断（`rc=1`）

1. D0–D5 未登记 / `fail` / `na` 无原因 / 全 na；
2. 没有 `proven`；`proven` 无证据；`proven` 缺 `how`；
3. 未给 `verdict`；裁定要求的深度级未 `pass`；
4. 仪器登记 < 2 种，或全部被阻断（无可用非 baseline 仪器）；
5. **存在 `stale` 且未复验**；
6. **`plan` 少于 2 条候选**；
7. **已 `verdict` 但未 `choose`** / 多条 `chosen` / `chosen` 与 `goal_level` 不一致；
8. **阻断级缺件未写进 `verdict --note`**；
9. **菜单含依赖阻断级缺件的路线**；
10. 裁定=可赢但 D6/D7 未登记或没写原因（或 D6/D7 = `fail`）；
11. `--strict` 下仍有 `hypothesis`。

### 只告警（不影响退出码）

- D6/D7 缺失；
- D6/D7 = `fail`（非"可赢"裁定时）。

### 通过时打印

裁定、交付上限、深度计数、事实数、**选定路线（level/route/p/工时/失败判据）**、下一步。

---

## 8. 最小自测序列（可直接粘贴）

```bash
export PYTHONUTF8=1 PYTHONIOENCODING=utf-8
CS="python D:/Seep-Reverse-Lab/Tool/scripts/case_state.py"
C="D:/tmp/b-audit/case1"
rm -rf "D:/tmp/b-audit"; mkdir -p "D:/tmp/b-audit"

$CS init   --case "$C" --target sample.exe                                   # rc 0
$CS claim  --case "$C" --id C01 --text "权威在服务端" --status proven \
           --evidence "procmon 导出 <case>/artifacts/procmon.log → 第1秒出现 winhttp 请求" --how "procmon+抓包（证据串必须是：路径 / 命令+产物(.log/.json/.md) / 哈希 / 账本编号，纯文字会被拒）" \
           --ttl "换 exe 即失效"                                              # rc 0
for lv in D0 D1 D2 D3 D4 D5; do
  $CS depth --case "$C" --level $lv --result pass --note "已测" >/dev/null
done
$CS depth  --case "$C" --level D6 --result pass --note "2 层独立闸门，逐层验证"   # rc 0
$CS depth  --case "$C" --level D7 --result na   --note "无静默失败面"           # rc 0
$CS instrument --case "$C" --name frida-attach --status ok --note "早期挂载会掐网络"
$CS instrument --case "$C" --name external     --status ok --note "Procmon 可观测"
$CS gaps   --case "$C" --add --id G1 --missing "有效卡密" --impact "拿不到合法响应" \
           --repairable no --delta -0.45 --alt "买真卡|旧版存档"                 # rc 0
$CS plan   --case "$C" --level L2 --route "字节补丁" --p 0.85 --hours "1-2" \
           --needs "可写副本" --fail "打完仍无界面"                             # rc 0
$CS plan   --case "$C" --level L1 --route "本地旁路" --p 0.6 --hours "0.5-1" \
           --needs "启动校验点" --fail "旁路后功能面仍缺"                       # rc 0
$CS verdict --case "$C" --value 部分可赢 --tier T1 \
            --note "缺有效卡密(G1)，服务端关掉 L4；只走本地旁路"                 # rc 0
$CS gate   --case "$C"; echo rc=$?          # rc 1：未 choose
$CS choose --case "$C" --level L2 --route "字节补丁"                          # rc 0
$CS gate   --case "$C"; echo rc=$?          # rc 0
$CS stale  --case "$C" --reason "换 exe:sha256 变了"                          # rc 0
$CS gate   --case "$C"; echo rc=$?          # rc 1：stale 未复验
$CS prove  --case "$C" --id C01 --evidence "复验：新 exe 同样第1秒出站"        # rc 0
$CS gate   --case "$C"; echo rc=$?          # rc 0
```

必保的既有负向（改动后仍应成立）：

| 场景 | 期望 |
|---|---|
| `claim --status proven --evidence "   "` | `rc 2` |
| `prove --evidence "  "` | `rc 2` |
| 空案子直接 `gate`（零事实） | `rc 1` |
| D0–D5 全 `na`（均写 note）`gate` | `rc 1` |
| `verdict --value 不可赢 --tier T3 --max-level M4` | `rc 2`（强制 M1） |
| `deliver --level M3`（上限 M2） | `rc 2` |
| 已存在状态再次 `init` | `rc 2` |

---

## 9. 常见坑

- **`needs` 不写缺件**：`gate` 看不见依赖，等于绕过规则；登记路线时把"需要卡密/需要服务端/需要真机"写清楚。
- **`p` 拍脑袋**：至少写出乘数因子（壳 × 反调试 × 缺件 × 签名），没有样本就先给保守值并在 note 说明。
- **`choose` 选了菜单外的路线**：`rc 2`；先 `plan --add` 或 `plan --from-advise`。
- **`stale` 后只改 note**：不算复验，必须走 `prove`（证据累加），否则 `gate` 一直拒绝。
- **D6/D7 当必填去卡老案子**：它们是告警级；只有裁定=可赢才强制登记。
- **`advise` 当成写盘**：它不写 `plan.json`，确认后才 `plan --from-advise`；导入后仍可手工增删。
- **配置改了不生效**：两个矩阵每次 `advise` 都现读 `Tool/config/*.json`，改完直接重跑即可。
