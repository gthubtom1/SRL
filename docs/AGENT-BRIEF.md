# 子代理作业简报（领域深度补全）

> ⚠️ **仅适用于内部子代理**（由项目方授权、在分支上执行并提交的执行者）。
> **外部审查员请按 AUDIT-REQUEST 走只读流程**：外部审查是只读的，读 `docs/AUDIT-REQUEST.md`，只出报告不改仓库。

> 你只负责**一个域**。契约在 `docs/history/X-DOMAIN-SPEC-v2.md`，机检在 `Tool/scripts/domain-gate.py`。
> 目标：让该域**能独立打一场**——判据可机检、脚本真跑、案例真跑、知识可复用。

## 0. 铁律

1. 只改自己域的目录：
   - `Tool/skill/<skill>/**`
   - `Tool/cases/<case_glob>*/**`
   - `Tool/mcp/Tool/reverselab/kb/<board>/**`
   - `Tool/config/<domain>-matrix.json`、`Tool/config/routing-fragments/<domain>.json`
   - `Tool/prompts/domains/<domain>.md`
2. **不许改**：`Tool/scripts/preflight.py`、`Tool/scripts/domain-gate.py`、`Tool/scripts/lib/*`、`docs/history/X-DOMAIN-SPEC-v2.md`、`Tool/scripts/routing.json`、其它域的任何文件、`docs/AUDIT.md`。
3. 不许 `git commit`、不许联网、不许写入仓库外的绝对路径；脚本与文档里只出现相对仓库根的路径或 `~` 相对路径。
4. 不许编造：命令必须真跑过；哈希必须真算；失败就写失败判据，不要粉饰。
5. Windows + Git Bash 环境，解释器是 `python`（3.12）。可用：`gcc`（mingw64）、`tshark`、`node`、`npm`、`dotnet`、`java`、`7z`（若存在）、`unzip`。

## 1. references（6–10 篇，每篇 60–400 行）

必备四篇（文件名严格）：

| 文件 | 内容要求 |
| :-- | :-- |
| `01-criteria.md` | 判据表，表头必须含：场景 / 输入面 / **判据（可机检）** / **证据形态** / **误报风险**；≥8 行数据行 |
| `02-failure-criteria.md` | 失败判据表：现象 / 判定 / **改走哪条** / 代价；≥8 行 |
| `03-model-pitfalls.md` | ≥10 条「错误动作 → 为什么错 → 正确动作」，每条 `###` 小标题 |
| `04-walkthrough-<slug>.md` | 一个真实案例走查：目标、命令、原始输出片段（≥2 个代码块）、结论、边界 |

其余 2–6 篇：本域独有的深水区（例如 web 的盲注对照实验设计、firmware 的仿真失败定位）。
保留原有 4 篇（可改名/合并），但**全库必须被 SKILL.md 或 KB README 或案例 refs 引用到**。
每篇开头写「范围与路由」，结尾写「失败判据」与「边界」。

## 2. scripts（2–4 个，全部真跑）

- 现有脚本保留并升级；新增至少 1 个「复现/验收」脚本。
- 每个脚本必须支持：
  - `--help` → rc=0，打印用途/输入/输出/退出码；
  - `--self-test` → rc=0，**离线**用内置小样本跑通，最后一行打印 `{"ok": true, "checks": N}`（JSON 必须含 `"ok"`）。
- 失败路径：捕获异常，输出 `{"ok": false, "blocked_at": "<阶段>", "reason": "<原因>"}` 且 rc=2。
- 纯标准库优先；需要 `tshark`/`gcc` 等外部工具时，先探测，缺失走降级分支并给出 `blocked_at: "tool-missing"`。
- 用 `--root` 或 `__file__` 推导路径。

## 3. cases（3–5 个，`Tool/cases/<前缀><NN>/`）

- 沿用现有目录（已存在 2 个），**新增 1–3 个**；每个目录自带 `input/` 与 `artifacts/`。
- `case.json` 字段：
  `id domain target_type evidence_kind protection authority goal_level outcome artifacts lessons refs updated`
- `evidence_kind`：`fixture`（手写教学输入）或 `real`（真工具链跑真实存在的文件/进程/抓包/编译产物）。
  - **每域至少 1 个 `real`**；`real` 的 `target_type` 不得出现「夹具/教学/fixture」字样；`fixture` 必须出现。
- `artifacts[]`：`{"path": "...", "sha256": "..."}`，sha256 用
  `python -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" <file>` 真算。
- `lessons[0]` 必须写：跑的是什么、命令、rc；`lessons` 后续写结论/边界/下一步。
- 真实案例的可行输入（不联网）：
  - `Tool/samples/real/**`（真实第三方 crackme / pcap / apk）
  - `Tool/samples/*.exe`（仓库内编译样本）
  - 本机系统文件（`/c/Windows/System32/*.exe`、`C:/Windows/System32/winevt/Logs/*.evtx`）
  - 现场编译：`gcc -O0 -o /tmp/x src.c`
  - 现场抓包：`tshark -i <iface> -a duration:5`（回环或本机流量）
  - 现场起服务：`python -m http.server`、`node -e`、`flask`（若无则用 http.server + 自写 handler）
  - 本机真实包元数据：`npm ls --json`、`pip freeze`、`dotnet --list-sdks`

## 4. KB（6–10 篇，含失败判据）

`Tool/mcp/Tool/reverselab/kb/<board>/`：

- `README.md` 重写：入口 + 分析链 + 三条硬判据 + 失败判据 + 邻域边界 + **逐篇链接**（每个 technique 的文件名至少出现一次）；
- `techniques/` 新增 3–5 篇（每篇 50–200 行），其中必须有一篇文件名含 `failure-criteria`。

## 5. 矩阵

`Tool/config/<domain>-matrix.json`：`families` 或 `rows` ≥12 条，每条含
`match` / `tools` / `commands` / `criteria` / `fail` / `pitfalls`（`match` 可为字符串数组）。
现有 `families` 结构可保留，只补缺字段与条目。

## 6. 路由片段

`Tool/config/routing-fragments/<domain>.json`：只改自己这份。
关键词必须带词边界或组合锚定（`\b`、`(?i)`、`mustAll`），避免与他域抢词。
必须能命中本域常见说法，且**不命中**：`zipalign`（apk）、`bios`（firmware）、`principal`（ad）、`scaffold`（supply）。

## 7. 任务卡（20–30 张）

`Tool/prompts/domains/<domain>.md`：
源技能名从 `Tool/config/taskcard-sources.json` 的 `<domain>` 取（已校验真实存在），每张卡格式：

```
### 01 <中文卡名>（源：<上游技能名>）
- 触发词：...
- 前置：...
- 步骤：1) ... 2) ... 3) ...
- 判据：...
- 失败判据：...
- reference：Tool/skill/<domain>/references/<file>.md
```

卡名不得重复；`reference` 必须真实存在；20–30 张（建议 24 张，正好用完源清单）。

## 8. SKILL.md（≤600 行，≥120 行）

结构固定：

1. 范围与路由（边界）
2. 前置检查（3 件以内）
3. **判据表**（本域 5–8 类，每类给「确认」与「疑似」）
4. **失败判据**（看到即降级，指向 `references/02-failure-criteria.md`）
5. **模型常见失误**（≥8 条，指向 `03-model-pitfalls.md`）
6. 流程（分阶段，每阶段有完成判据）
7. 参考索引（**逐篇列全** `references/*.md`）
8. 脚本用法（每个脚本一条示例命令）
9. 任务卡入口（`Tool/prompts/domains/<domain>.md`）
10. KB board 入口

## 9. 验收（必须自己跑到绿）

```bash
cd /d/Seep-Reverse-Lab
python Tool/scripts/domain-gate.py --domain <domain>
```

除「全局」四条（链接图/路由串味/清理/部署）外，本域 10 条必须全 PASS。
若 links 报你域的文件是孤儿，就去 SKILL/README/案例里加引用。

最后回报：

1. 新建/修改文件清单（带行数）；
2. `domain-gate --domain <domain>` 的最后 12 行输出；
3. 真实案例的命令 + 关键输出片段（≤10 行）+ 产物 sha256；
4. 仍未解决的卡点（没有就写「无」）。
