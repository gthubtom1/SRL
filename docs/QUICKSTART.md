# 5 分钟快速路径（新 agent / 换会话先看这个）

> 目标：**5 分钟内跑出第一条有效结论**，不被 110 条门禁和 30 个技能吓住。
> 详细契约见 `docs/DOMAIN-SPEC-v2.md`；接力棒见 `ROADMAP.md`；差分见 `docs/UPSTREAM.md`。

## 0. 一条命令确认环境（10 秒）

```bash
cd <repo>
python Tool/scripts/env-check.py --text     # 缺什么会直接说，并给安装命令
```

## 1. 一条命令开一个案子（30 秒）

```bash
python Tool/scripts/seep-start.py --domain <域> --case <案子名> [--target <样本/网址>]
```

- `<域>` ∈ `web-pentest` `pwn-crypto` `firmware-iot` `ad-cloud` `protocol-plugin`
  `plugin-targets` `forensics-mobile` `malware-analysis` `supply-chain-security` `reverse` `site-clone`
- 它会：建 `work/<案子名>/`（含 `artifacts/`、`scope.md` 与 `facts.jsonl`），打印该域**下一步 3 条命令**；要沉淀成正式案例时再按 `Tool/cases/_templates/` 复制到 `Tool/cases/<案子名>/`。

## 2. 读一张卡就动手（不读整本技能）

```bash
ls Tool/prompts/domains/<域>.md          # 24 张卡，每张=触发词/前置/步骤/判据/失败判据/reference
```

挑一张与目标最像的卡，照「步骤」里的命令跑；判据不成立就看该卡指向的 `references/02-failure-criteria.md` 换路。

## 3. 三条最常用的入口

| 场景 | 命令 |
| :-- | :-- |
| 不知道目标是什么 | `python Tool/skill/softseep/scripts/preflight-classify.py <样本>`（逆向域） |
| 网站/接口基线 | `python Tool/skill/web-pentest/scripts/web-check.py --url <URL>` |
| 网站 1:1 复刻 | `python Tool/skill/site-clone/scripts/site-crawl.py --url <URL> --out <目录>` |

## 4. 交付前只跑这两条

```bash
python Tool/scripts/domain-gate.py --domain <域>     # 本域 10 条断言
python Tool/scripts/preflight.py --fast              # 全局快检（悬空引用/篇幅/路由/清理）
# 当前基线：preflight --fast 41/41；preflight 全量 44/44
```

## 5. 常见卡点（先看这里，别硬猜）

> **Git Bash 下 `/path` 会被改写成 `C:/Program Files/Git/path`**：给 Python 脚本传绝对路径时加 `MSYS_NO_PATHCONV=1`（例：`MSYS_NO_PATHCONV=1 python Tool/skill/apkseep/scripts/probe_api.py --path /api/x`）。

| 现象 | 处理 |
| :-- | :-- |
| 工具找不到 / `mcp__x64dbg__*` 不存在 | 先 `python Tool/scripts/mcp-doctor.py --session` 判定是否要 `/mcp reconnect <name>`；宿主没起再 `--fix`（后台拉起 + 复验），也可 `tool-run.ps1 -Tool <id>` |
| 门禁说「案例 sha256 不符」 | 先 `git status` 看是否换行符漂移；案例证据按字节保存（`-text`），不要手改产物 |
| 路由把任务分错域 | 看 `Tool/scripts/routing.json` 的 priority；改路由只走主分支 |
| 不知道用哪篇 reference | 该域 `references/01-criteria.md` 顶部的「场景 → 判据」表 |

## 6. case_state.py 的宽容别名（照旧写法也不会报错）

`Tool/scripts/case_state.py` 对高频参数保留了口语别名，左右两列完全等价：

| 正式写法 | 等价别名 | 用途 |
| :-- | :-- | :-- |
| `depth --level D2` | `depth --set D2` | 登记深度 D0–D7 |
| `depth --note "..."` | `depth --prove "..."` | 备注；`--prove` 同时表示这一级已 pass |
| `plan --route "..."` | `plan --add "..."` | 登记一条候选路线 |
| `plan --p 0.85` | `plan --prob 0.85`（或 `--success`） | 成功率先验 0–1 |
| `plan --hours "1-2"` | `plan --eta "1-2"` | 预计工时 |
| `deliver --evidence "..."` | `deliver --ev "..."` | 交付证据 |

直接可拷的例子：

```bash
python Tool/scripts/case_state.py depth   --case work/<案子> --set D2 --prove "LoadLibrary 命中 winhttp"
python Tool/scripts/case_state.py plan    --case work/<案子> --add "字节补丁" --prob 0.85 --eta "1-2" \
                                          --fail "打完仍无界面"
python Tool/scripts/case_state.py gaps    --case work/<案子> --add --id G1 --missing "有效卡密" --repairable no
python Tool/scripts/case_state.py deliver --case work/<案子> --level L2 --ev "断网截图 + 复现日志"
```

> 旧写法里 `--add` 同时被 `plan`（加路线）和 `gaps`（登记缺件）使用；两者都受支持，不要因为帮助文本只写 `--route`/`--add` 其中一种就以为另一种报错。
