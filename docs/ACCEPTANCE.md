# 验收记录（2026-10-24 收尾）

> **本文件是一次性快照，不是常驻状态。** 想知道"现在"如何，跑下面第二节的命令。
> 为什么不用它当状态源：手写状态必腐烂（`docs/HANDOFF.md` 已经烂过一次）——
> 现行状态由 `case_state.py handoff --repo` 生成。

## 一、判据与结果（本轮实测）

| # | 判据 | 命令 | 结果 |
| :-: | :-- | :-- | :-- |
| 1 | 门禁（含 2 条新跨层判据） | `python Tool/scripts/preflight.py --fast` | **48/48 通过** |
| 2 | 按域判定（6 道/包，unknown 记 fail） | `python Tool/scripts/gate.py --all` | **pass 9 / fail 0** |
| 3 | 证据聚合 | `python Tool/scripts/case_state.py verify --all` | **pass 12 / fail 0 / unknown 52** |
| 4 | 路由死链 | `python Tool/scripts/route.py --check` | **0 条死路由** |
| 5 | 案例证据哈希 | 全部 `artifacts/MANIFEST.sha256` 逐条重算 | **879 个文件全对** |
| 6 | facts 账本结构 | 全部 `facts.jsonl` 解析 | **proven 都有 evidence，event 都有 rc** |
| 7 | 技能工具引用 | 25 处调用式引用 vs 服务端 20 个工具 | **全部存在** |
| 8 | 回执漂移 | `docs/verification/*.json` 的 source_sha256 | **18 条全对** |
| 9 | 扩展部署 | 仓库 7 个 `.ts` ↔ `~/.pi/agent/extensions` | **哈希全一致** |
| 10 | 从零可复现 | 全新 `git clone --depth 1` 后重跑 1–2 | **同样全绿** |

## 二、想自己复算时

```bash
python Tool/scripts/preflight.py --fast        # 门禁 48 项
python Tool/scripts/gate.py --all              # 9 个包
python Tool/scripts/case_state.py verify --all  # 证据强度
python Tool/scripts/case_state.py handoff --repo   # 当前状态（生成，不过期）
```

## 三、本轮验收抓到并已修的问题（都是 A 类：会导致"说谎"或"空转"）

| 问题 | 表现 | 修法 |
| :-- | :-- | :-- |
| 技能里引用的工具可能不存在 | 模型照文档调用 → 失败 → 重试循环（同 `output_mode='branch'` 那一类） | 新增判据：25 处调用式引用必须都在服务端有定义 |
| 回执可能替改过的代码作证 | 技能改了、回执还是旧的 → "证据"失效但没人发现 | 新增判据：回执 `source_sha256` 必须等于当前文件 |
| 守卫正则写坏时静默跳过 | `except: pass` → 这条禁手失效但门禁照绿 | 编译失败收集进「对抗陷阱对撞」项 → 红 |
| 扩展改了没部署查不出来 | 仓库是新的、跑的是旧的（实测踩到 `cmd-guard.ts`） | 新增判据：7 个扩展哈希必须与部署侧一致 |

## 四、已知但不修（按 `PLAN-v8` §9.2 分类：B 记账 / C 不修）

| 项 | 类 | 为什么不修 |
| :-- | :-: | :-- |
| 仓库内有 ~190MB vendored 依赖（jadx 74MB、js-reverse node_modules 52MB、apktool 23MB、venv.zip 20MB、radare2/VC_redist 等） | B | `setup/install.ps1` + `extract-deps.ps1` 依赖它们做**离线首装**；删掉会破坏"换机器一键装"，风险大于收益 |
| 52/64 个历史案例无事实账 | B | L15：不为已结束的目标回溯补账；新案例自动带账 |
| 8 个域深度不均（apkseep 468 行 vs forensics 208 行） | B | 能力积累问题，需真实样本 |
| 商业加固壳（DexVMP/jiagu/梆梆）未实测 | B | 需构建链 + 真实加固样本 |
| 4 条 refuted claim 缺 confidence | C | refuted 不计 pass，不影响任何判据 |

## 五、结论

按 `PLAN-v8` §9 的终止条件（S1 门禁全绿 / S2 每域有见证 / S3 无已知 fail-open / S4 无已知伤机路径），
**四项全满足** ⇒ 判定"可用"，停止优化。

再往下做都属于 B/C 类（能力扩充或口味），不构成"修 bug"。
