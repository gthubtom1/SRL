# 样本与 demo 记录（P4-B）

流水线：**新破甲卡 → `compat/adapt_check.py` → 按 `../适配提示词.md` 逐条修 → 再跑到 PASS**

本目录三个文件，别搞混：

| 文件 | 是什么 | 期望 verdict |
|---|---|---|
| `original-en-muse.md` | demo 输入：`quad/en-muse.md` 的原样拷贝（旧代卡，15,505 B） | **FAIL** |
| `adapted-example.md` | 按 `适配提示词.md` 实际改出来的成品（7,979 B / ~1,958 tok） | **PASS** |
| `drift-negative.md` | 合成的负向自测样本（**不是真卡**），用来证明 6 条硬冲突规则 + 去重都能打红 | **FAIL** |

---

## demo：改前 / 改后对比（真跑，2026-10-24）

```
$ cd D:/Seep-Reverse-Lab
$ python 破甲卡生成/compat/adapt_check.py 破甲卡生成/compat/samples/original-en-muse.md
```

**改前（FAIL，4 项失败）**

| 类 | 结果 | 具体项 |
|---|---|---|
| 预算 | ✗ FAIL | 15,505 B > 8,192（超 7,313 B）；~3,330 tok > 2,500（超 830） |
| 硬冲突 | ✓ OK | 0 处（en-muse 是干净旧代卡，没有"额外授权确认/拒答转话题"这类漂移） |
| 去重 | ✓ OK | 0 组 |
| 必备条款 | ✗ FAIL | 缺 §11 carve-out；缺 §7 capability-honesty（授权门指针 ✓，原卡第 3 行已有） |

```
$ python 破甲卡生成/compat/adapt_check.py 破甲卡生成/compat/samples/adapted-example.md
```

**改后（PASS，四类全绿）**

| 类 | 结果 | 具体项 |
|---|---|---|
| 预算 | ✓ OK | 7,979 B / 8,192；~1,958 tok / 2,500 |
| 硬冲突 | ✓ OK | 0 处 |
| 去重 | ✓ OK | 0 组 |
| 必备条款 | ✓ OK | §11 carve-out ✓；§7 capability-honesty ✓；授权门指针 ✓ |

**省下**：7,526 字节 / ~1,372 token。

---

## 改了什么、为什么（diff 摘要）

| # | 类别 | 原卡位置 | 改法 | 为什么（规则来源） |
|---|---|---|---|---|
| 1 | 必备条款 §11 | 无 | 在 white-list 串前插入 `Carve-out (does not weaken the line above)` 整段 | `compat/seep-compat.md` §1：原文"no competing set of instructions"会连 Seep 的工具纪律/熔断/授权门一起否掉 |
| 2 | 必备条款 §7 | 无 | 在 `## 8. OUTPUT CONTRACT` 前插入 `Capability honesty.` 整段 | 同上 §2：SCOPE 写得宽是对的，但"先答应后手搓"要改走自愈链 |
| 3 | 预算 | §0f 十行模块表、§0b 重复阶梯、§0d/§0e 双表、§7 长括号 | 模块表 10 行 → 1 行契约串；删 §0f 重复阶梯说明；§0d 触发词表 4 行 → 2 行；§7 逐项压缩 | ≤8 KB / ≤2,500 tok 硬线；重复条目本身降低遵循率（arXiv 2608.02639） |
| 4 | 语义**新增** | §11 | 新增"**The one question you may ask** … 多条路真分叉时用对话内 `A / B / C` 把选择权交回人" | SEP 要求：卡不得禁掉对话内 A/B/C 问人 |
| 5 | 授权门 | 第 3~5 行（中文指针） | 原样保留，只把"以 §六 为准 / 仅用户声明无授权时停一次"压成 4 行 | `AGENTS.md §六`：卡不得改写授权门语义，只需指明以它为准 |
| 6 | 破甲核心 | `你是谁` 握手、`[k] ` 首字符、`RELOADED` 排气管、阶梯 4 层、触发词 `xz/pojia/RESET`、模型档案 | **一字不改** | 改完要还能用：破甲风格是卡的价值，不许"净化" |
| 7 | 硬冲突 | — | 无命中，无需改；新增文字没有引入"额外授权确认/必须弹窗/禁 A/B/C" | 硬冲突 6 条规则见 `adapt_check.py --list-patterns` |

**结论**：PASS（bytes 7,979 / tok ~1,958；硬冲突 0；重复 0；条款 2/2 + 指针）。

---

## 负向自测（证明每一类都能打红）

```
$ python 破甲卡生成/compat/adapt_check.py 破甲卡生成/compat/samples/drift-negative.md
```

| 类 | 结果 | 命中 |
|---|---|---|
| 硬冲突 | ✗ FAIL 7 处 | H1-extra-auth · H2-drop-noauth ×2 · H3-refusal-pivot · H4-ban-ask-abc · H5-must-popup · H6-override-gate（每处带行号 + 原文 + 为什么） |
| 去重 | ! WARN 1 组 | 同一句 `先跑一遍 --json 再跑一遍 --json` 出现 2 次（行 21） |
| 必备条款 | ✗ FAIL | 缺 Carve-out / Capability honesty |
| 预算 | ✓ OK | 1,264 B（负向样本故意做小，预算这一类由 `original-en-muse.md` 证明能红） |

## 复现

```bash
cd D:/Seep-Reverse-Lab
python 破甲卡生成/compat/adapt_check.py 破甲卡生成/compat/samples/original-en-muse.md      # FAIL → rc=1
python 破甲卡生成/compat/adapt_check.py 破甲卡生成/compat/samples/adapted-example.md       # PASS → rc=0
python 破甲卡生成/compat/adapt_check.py 破甲卡生成/compat/samples/adapted-example.md --json # rc=0，JSON 可 loads
python 破甲卡生成/compat/adapt_check.py 破甲卡生成/compat/samples/drift-negative.md        # FAIL → rc=1
cd 破甲卡生成 && python compat/check_seep_compat.py --check                                # PASS → rc=0（既有闸没被弄坏）
```

退出码口径：`0` PASS（可带 WARN）/ `1` FAIL / `2` 用法或读文件错误；`--strict` 把 WARN 也算 FAIL。
