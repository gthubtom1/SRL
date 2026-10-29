# TRAP-LIBRARY —— 实测踩坑库（14 条）

> **这是提示不是规则；命中信号才用，不命中不要硬套。**
> 每条五段：**信号**（怎么察觉）→ **为什么**（机理）→ **必做**（可执行动作）→ **负例**（故意验证它不成立时该看到什么）→ **来源**（哪次实测 / 哪个 case + 指针）。

## 怎么用（三步）

1. 干到某一步觉得"这结果有点顺"或"这报错有点怪" → 先在下面按 **信号** 扫一眼。
2. 命中 → 照 **必做** 做那几条动作，不要只"注意一下"；没命中不要为了用而用。
3. **负例** 是给自己留的对照实验：跑一次对照，能区分"陷阱成立"和"我看错了"。不做对照就下结论 = 押注。

## 索引

| ID | 陷阱 | 触发面 |
| :-- | :-- | :-- |
| T01 | 磁盘改一字节即 `File corrupted` | 带壳 PE / 完整性自检 |
| T02 | dump 件保留运行时基址 | dump / 反编译地址换算 |
| T03 | 压缩件里的 AOB 假命中 | 壳上做字节搜索 |
| T04 | 补丁点换文件就打空 | 打补丁前没确认文件 |
| T05 | 早期 attach 改变行为 | 调试器 / Frida |
| T06 | MCP 参数别名空串泄漏 | MCP 工具真调用 |
| T07 | 端口在听 ≠ 工具在表 | MCP 注册 / L2 判据 |
| T08 | 子代理不加载扩展（除非显式开） | profile / 权限收窄 |
| T09 | `--extension` + 占位 token | playwright MCP |
| T10 | zipalign 必须在签名之后 | APK 重打包 |
| T11 | apktool 不带 `-r` 会卡死 | APK 解码 |
| T12 | `npx` 是无扩展名 shim | Windows 进程拉起 |
| T13 | "改成 nop 就旁路"是错的 | 补丁语义 |
| T14 | 拿退出码当判据 | 验收判据选取 |

---

### T01 · 磁盘改一字节即 `File corrupted`（壳 stub 层完整性自检）

- **信号**：改过的副本一启动就弹 `File corrupted!` 或秒退，而原件正常；并且拿这个串去 dump 出来的镜像里搜（`grep -a` 与 `grep -a -e $'F\x00i\x00l\x00e\x00'` 两条都试）得 **0 命中**。
- **为什么**：校验在壳 stub 里、执行早于解密，磁盘上任何一位改动都会先被它拦掉；"解密后才存在"的业务段在 dump 里才有，所以这个串在 dump 里搜不到反而是它在壳里的证据。
- **必做**：`cp 原件 副本` → 只改 1 字节（如 `DllCharacteristics` 或某节末尾 1 字节）→ 各启动一次做对照；若副本被打掉、原件正常 → 判定"文件面被哈希监视"，路线切 **内存**（内存补丁 / dump 后改内存 / 运行期 hook），并在 `case/decisions.md` 写一条「放弃磁盘补丁 + 依据」。
- **负例**：原件一字不改、连启动两次都正常 → 排除"启动方式/父进程"这个解释；dump 件能跑且里面搜 `File corrupted` 为 0 → 排除"这串是业务提示"。
- **来源**：aimbot 案（`Tool/cases/aimbot/case.json` 的 `lessons` 与 `protection` 字段；`Tool/docs/EXECUTION.md`）

### T02 · dump 件保留运行时基址

- **信号**：dump 出的 PE `OptionalHeader.ImageBase` 是 `0x7ff65e140000` 这类高地址，而原始首选基址是 `0x140000000`；按原基址问反编译器，连续回 `no function at 0x1400a1c90`（本例连吃 7 次）。
- **为什么**：内存 dump 记录的是装载后的真实地址，落盘时 PE 头没改回首选基址，于是"RVA + 原基址"算出来的每个 VA 都落在错误位置。
- **必做**：① `rabin2 -I <dump>` 读 ImageBase 并**落到报告里**；② 同时列两套 VA：`runtime_va = ImageBase + RVA`、`static_va = 0x140000000 + RVA`；③ 每次反编译/交叉引用前先断言用的是哪一套；④ `report/dynamic.md` 的地址台账必须 RVA / VA / 基址 三列齐（`case_state.py gate --stage 2` 会因此红）。
- **负例**：同一 RVA 先按原基址问 → `no function`；再按运行时基址问 → 返回真函数体与指令，说明差的是基址，不是"函数被剥了"。
- **来源**：aimbot 案 7 次 `no function`（`docs/history/X-HANDOFF-2-DETAIL.md:118`、`Tool/cases/aimbot/case.json`）；回归断言 R4（`work/audit/behavior/（replay-history 已删）.md` 总表）

### T03 · 压缩件里的 AOB 假命中

- **信号**：在 UPX 件上搜 `74 13` 命中 `0x815`，搜 `tran` 命中 `0xfb1`，命中数"看着不为零"；但同一文件 `aa; aflc` 只出 3 个解压桩函数、`afl~main` 是空的。
- **为什么**：压缩流里 2–4 字节组合必然随机撞到；命中偏移全部落在壳载荷区间（本例 UPX1 `0x200–0x2600`），既不在解压桩代码流里，也没有指令边界或交叉引用支撑 —— 成功率实际为 0。
- **必做**：命中先过**否证三连**：① `upx -l` / 壳识别确认载体已压缩；② 命中偏移是否落在壳载荷区间（`0x200 ≤ off < 0x2600`）；③ 该偏移有没有 `afl` / xref 结构支撑。任一不过 → 结论写"命中率不为零、成功率为 0"，改在脱壳件或内存里定位。
- **负例**：同一 pattern 在脱壳件上应命中 `0xb6b`（真值），且 `pdf @ sym.main` 能把 `0x140002882` 与它对齐；压缩件命中 `0x815` ≠ 真值 `0xb6b` → 假命中坐实。
- **来源**：leaf-pe-packed（`Tool/cases/leaf-pe-packed/facts.jsonl` F-108、`Tool/cases/leaf-pe-packed/report/static.md:47` §4 对照表）

### T04 · 补丁点换文件就打空

- **信号**：同一个**文件偏移** `0x1e82`，在脱壳件读到 `74 13`（映射 VA `0x140002882`，业务分叉），在压缩件读到 `73 00`（映射 `0x140014c82`，UPX1 解压桩）。
- **为什么**：文件偏移只在"同一种布局"下才等价于 RVA；压缩件占相同偏移的字节属于壳，不属于业务段，打上去既不生效也过不了壳自校验。
- **必做**：打之前写死四元组 **文件名 + 偏移 + 期望原字节 + 期望新字节**；改之前 `px 2 @ <file offset>` 回读断言（不等于期望就停，不许"大概就是这里"）；产物 `MANIFEST.sha256` 里记清"哪个文件被打了补丁"，报告里写明补丁只对哪一族文件成立。
- **负例**：在压缩件该偏移改字节 → `upx -t` 报 `checksum error`（`0 ok 1 error`）且行为不变；在脱壳件同偏移改 → 行为变了。两点一起才证明"文件族决定语义"。
- **来源**：leaf-pe-packed F-113 / F-004、`Tool/cases/leaf-pe-packed/report/dynamic.md:123`

### T05 · 早期 attach 改变行为

- **信号**：一挂调试器 / Frida 就不再发网络请求、或进程立刻退出；不挂任何东西裸启动时请求正常。
- **为什么**：反调试在 TLS callback / PEB / 父进程检查层，附加动作本身就被判成敌意环境 —— 此时你观察到的现象是被附加改出来的，不是目标原本行为。
- **必做**：① `O0–O2`（只读、裸启动、外部观测）阶段得到的每条结论都标"未受附加影响"；② 一旦 attach，先重跑一次裸启动对照（同命令、同环境、同时间窗）；③ 把差异列成三列登记：`我做了什么 → 哪个行为变了 → 哪条结论要重验`，写进 `case/decisions.md`，不登记则后续推理全部不可信。
- **负例**：裸启动连跑两次请求条数一致（排除抖动）；attach 后条数掉到 0，detach 后恢复 → 证明是附加造成的，不是服务端挂了。
- **来源**：`docs/CHANGELOG.md:772`（"早期挂载会让它静默不发网络请求"）；`Tool/prompts/contracts/DECISION-LOOP.md:42`（观测排序事实 2）

### T06 · MCP 参数别名把空串漏进函数

- **信号**：schema 看着齐（八个别名都在、主参数也不在 `required` 里），但真调一个只读工具就 `unexpected keyword argument` / `TypeError`；而且**连主参数名都挂** —— 不是"某些工具忘加装饰器"。
- **为什么**：FastMCP 把 `arg_model` 的全部字段按默认值 dump 下来，别名层只 `pop` **非空**别名 → 空串别名照样漏进原函数签名。
- **必做**：改完别名层必须跑**真调用探针**：`python Tool/skill/softseep/scripts/mcp-param-contract.py`，它的 `[6]` 就是拿非主参数名真调 5 个代表工具，回包出现 `unexpected keyword argument` / `Field required` 即判红。
- **负例**：只查 schema（`--no-runtime`）→ 全绿；再跑带 runtime 的版本 → 报错工具数 > 0。两次结果不同就证明"schema 齐"不等于"能调"，只查 schema 是假阳性。
- **来源**：`Tool/skill/softseep/scripts/mcp-param-contract.py:18–22`（判据 [6] 与 P1-8 记录）、实现见 `:72`；当前接口与本条所列案例（旧过程记录已删除）

### T07 · 端口在听 ≠ 工具在表里

- **信号**：`netstat` 看到 `9094` 在听、启动脚本报 READY，但当前会话的 `ALL_TOOLS` 里没有 `mcp__x64dbg`。
- **为什么**：MCP http 型工具只在**会话启动时**注册；服务后起 → 本轮根本没有工具可调 → 模型只能退回手搓一次性脚本（历史血案：手搓了 5 个）。
- **必做**：L2"连上"只认一条判据 —— `mcp__<server>` 出现在当前会话 `ALL_TOOLS` 里。不在就**重启会话让服务先起**（或用 `Tool/scripts/tool-acquire.py` 走阶梯），不要"再调一次试试"；报告里的 L2 结论必须引这个判据而不是端口/进程。
- **负例**：`tool-run.ps1` 报 READY、端口在听、`ALL_TOOLS` 无该命名空间 → L2 仍判**未连上**。这条负例的作用是把"进程在跑"从判据里剔出去。
- **来源**：`Tool/prompts/contracts/TOOL-LADDER.md:23,29`；`docs/history/X-PLAN-FINAL.md:132,142`（历史归档，仅作出处）

### T08 · 子代理不加载扩展（除非显式开）

- **信号**：profile 里写了 `loadExtensions: true`，但子代理里护栏完全不生效；或子代理拿到了全套工具，而不是你在 `tools:` 里收窄的那几个。
- **为什么**：引擎只认 snake_case `load_extensions`（手写 camelCase 等于没写）；并且一个 profile 只能选一边 —— 要护栏（`true`，全工具）或要最小权限（`false`，工具可控），两者不会同时成立。
- **必做**：写完 profile 立刻跑 `python Tool/scripts/gate.py --pack <id>` 断言 frontmatter（它专查 `loadExtensions` 这类 camelCase 误写与缺失 `load_extensions`）；以 UI 里保存生成的那份为准，手改后必须重跑一次再派活。
- **负例**：`load_extensions: false` + `tools: read,bash,grep,find,ls` → 子代理只剩这五个、没有 write/edit。若你看到子代理能 write，说明该键没生效（拼写或缩进层级错），此时"护栏在"是错觉。
- **来源**：`Tool/scripts/gate.py`（witness 判据）；`Tool/prompts/contracts/TOOL-LADDER.md:116,135,141,162`

### T09 · `--extension` + 占位 token

- **信号**：playwright MCP 每次报 `Playwright Extension not found`；工具列表能连上、一调真功能就死。
- **为什么**：扩展模式**同时**要求真 `PLAYWRIGHT_MCP_EXTENSION_TOKEN` 与本机装有对应浏览器扩展，缺任一个就起不来；占位 token 永远不是真的。
- **必做**：args 固定成 `-y @playwright/mcp@latest --headless`（无 token、无需预装扩展），重连后调一个真实页面动作验证；配置里保留"别改回 `--extension`"的注记，免得下次重装又被旧条目覆盖回来。
- **负例**：换 `--headless` 后同一页面动作返回正常结果（证明问题在启动参数，不在浏览器/网络）；token 字段留空也不影响（headless 不读它）。
- **来源**：`Tool/config/mcp-servers.json:10`；`Tool/docs/MCP-SETUP.md:95–98,203`

### T10 · zipalign 必须在签名之后

- **信号**：先 `zipalign` 再 `jarsigner`，随后 `zipalign -c -v 4` 报 `res/_N.png (BAD - 2)`、`resources.arsc (BAD - 1)`、`Verification FAILED`。
- **为什么**：v1 签名会重写 zip 目录区与条目偏移，把前面做好的对齐挪歪，于是对齐校验从"通过"变成 BAD。
- **必做**：顺序写死 `apktool b → jarsigner → zipalign`；收尾必须三条判据都过：`jarsigner -verify` rc=0、`zipalign -c -v 4` 输出 `Verification succesful`、`aapt dump badging` 能解析（证明 zip/manifest 没改坏）。
- **负例**：同一 APK、同一工具链只调换顺序（签名→对齐）后 `zipalign -c` 变 `Verification succesful`；先对齐后签名的产物复现 BAD。两次对照才算钉住因果。
- **来源**：`Tool/cases/leaf-apk/report/triage.md:46`；本条所列案例（旧过程记录已删除）

### T11 · apktool 不带 `-r` 在部分样本上卡死

- **信号**：`apktool d` 反复打印 `Load resource table`，180s 不退出；同一 APK 换 `-r` 秒过。
- **为什么**：资源表解码在某类畸形 / 加密 res 上死循环，而反编译 dex 本身并不需要它。
- **必做**：先 `apktool d -r` 拿 smali 旁路验证链路，并在报告里**写明代价**：res / manifest 不解码（manifest 改用 `aapt dump xmltree` 读）；确认需要改 res 时才回头单独处理资源表，不要一开始就等它。
- **负例**：`apktool d -r` 在 60s 内退出且 `smali/` 下有类文件 → 证明卡点在资源解码，不是"这个 APK 解不开"。
- **来源**：本条所列案例（旧过程记录已删除）；`Tool/cases/leaf-apk/report/triage.md:69`

### T12 · `npx` 在 Git-Bash PATH 上是无扩展名 shim

- **信号**：`spawn('npx')` 报 `OSError: [WinError 193] %1 不是有效的 Win32 应用程序`，而在同一 shell 里手敲 `npx` 正常。
- **为什么**：Git-Bash 的 `npx` 是无扩展名 sh shim，`CreateProcess` 不认；必须按 `PATHEXT` 找到伴生的 `.cmd` / `.exe`，且 `.cmd` 还要交给 `cmd /c` 才能起。
- **必做**：拉起前做一次解析：按 `PATHEXT` 顺序找 `<name>+ext` 命中的真实文件；`.cmd/.bat` 用 `["cmd", "/c", path, ...]`；把解析结果打进日志，别用"我这儿能跑"当结论。
- **负例**：解析结果应打印 `npx.cmd`（而非 `npx`）；用 `cmd /c npx.cmd ...` 手跑一次 rc=0 → 证明失败只在 spawn 形式，不在 npx 本身。
- **来源**：`Tool/skill/softseep/scripts/mcp-handshake.py:395,406–410`；`Tool/scripts/mcp-launch.py:289–290,341`

### T13 · "改成 nop 就旁路"是错的

- **信号**：把分叉 `74 13`（`je`）改成 `90 90`，本以为无条件放行，实测连**正确输入**都变 FAIL（不是"部分通过"，是全坏）。
- **为什么**：nop 掉条件跳转等于"顺序落入下一条"，而落进去的那条正是 FAIL 分支；要旁路得把控制流**主动改到** PASS 分支（本例 `je → jmp 0x1400028a1`，即 `eb 1d`）。
- **必做**：改之前先 `pdf` 画清两条分支目标（条件成立落到哪、fallthrough 落到哪、各自是 PASS 还是 FAIL），再选目的字节；打完必须用**正确输入 + 错误输入 + 空串**各跑一次，三条都 PASS 才算旁路成立。
- **负例**：`90 90` 版：错误输入 FAIL、正确输入也 FAIL（改坏）；同偏移 `eb 1d` 版：两者都 PASS。两个负例对撞，说明差别在补丁**语义**而不在位点选得对不对。
- **来源**：golden-crackme（`Tool/cases/golden-crackme/ask/20261024T055734.md:5`、`Tool/cases/golden-crackme/report/dynamic.md:98`）

### T14 · 拿退出码当判据

- **信号**：补丁前后跑 PASS / FAIL 都对，但退出码恒为 0；`pdf` 显示两条分支都汇到同一处 `xor eax,eax` 再 `ret`。
- **为什么**：所有分支共用清零的返回码，退出码不承载判定信息；真正的判据在 stdout 的 `PASS` / `FAIL` 字符串上。
- **必做**：先确认判据载体 —— `pdf` 看分支汇合点是否共用同一返回值；再用 `printf 'wrong' | prog` 抓 stdout 断言字符串（需要精确匹配），退出码只当"有没有崩"的旁证；把选定的判据写进验收命令，别留两套口径。
- **负例**：一字不改跑正确 / 错误输入 → 退出码都是 0、stdout 一个 `PASS` 一个 `FAIL`。这时若拿退出码当判据，正例与负例不可区分 —— 该负例就是"判据选错了"的证明。
- **来源**：golden-crackme（`Tool/cases/golden-crackme/facts.jsonl` F-010、`case.json:20`）

---

## 维护约定

- 新坑进来先问三句：**信号可观察吗？必做能执行吗？负例能跑吗？** 缺一句就先补，再入表。
- 每条只写"怎么察觉 + 怎么做 + 怎么否证"，不写长篇机理；机理挤到 `为什么` 一行里。
- 被推翻的条目保留而不是删：改 `为什么`、补 `负例`，并注明推翻它的那次实测。
