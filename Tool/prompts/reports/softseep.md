# softseep 报告模板

> **客户视角五段（必须全在，缺一不算交付）**：下面五个是**真标题**——`python Tool/scripts/case_state.py report --check --file <本文件>`
> 按标题文字精确匹配「结论 / 已确认 / 仍未知 / 下一步 / 复查」，缺一段即 `[FAIL]`；每段标题下至少 2 行正文，
> 「结论」不超过 3 行，「已确认」里至少要有一个 `E-` / `C-` / `F-` 编号。「下一步 / 复查」别改名，改了检查器就找不到。

> 复制到 `work/<case>/report.md`。逆向结论必须有函数/偏移/状态字证据。

## 1 结论（≤3 行：能不能用 / 到哪一步 / 卡在哪）
- 到哪一步：<只能看懂结构 | 能改到能用 | 能完全自己接管 | 现在做不了>
- 卡在哪：<卡点一句话 + 证据编号；没有卡点写「无」>
- 能不能用：<只按已有证据说一句；没跑过就写「未验证」>

## 2 已确认（每条：客户能听懂的一句话 + 证据 ID + 强度：强 / 中 / 弱）
- <客户能听懂的那句话>（`E-001`；强：同输入同输出可复现，命令与输出都能贴）—— 原始记录 `artifacts/<tool>-<时间>.json`
- <客户能听懂的那句话>（`E-002`；强：两路独立验证一致，不只是重复跑）—— 原始记录 `artifacts/<tool>-<时间>.json`
- 只有一次观测、没有可复跑命令的线索不进本段，写进第 3 段。

## 3 仍未知（每条：未知什么 + 为什么未知 + 缺什么才能知道）
- <未知什么>｜为什么未知：<环境限制 / 证据缺口 / 授权没给>｜还缺：<补什么才能知道>
- <未知什么>｜为什么未知：<同上>｜还缺：<同上>

## 4 下一步（省事路线 / 彻底路线 / 不建议做的事，各一条）
- 省事路线：<最小动作 + 拿到什么 + 大概要花多少功夫（区间 + 判断依据）>
- 彻底路线：<要补的证据或要动的位点 + 代价与工期>
- 不建议做：<哪条路会白费或越界，为什么>

## 5 怎么复查（复查单路径 + 关键重放命令 + 期望看到什么）
- 复查单：`python Tool/scripts/case_state.py recheck --case work/<case>` → 生成 `work/<case>/recheck.md`（目标哈希 / 环境 / 重放命令）
- 重放：<本域脚本命令；Windows 的 cmd 与 PowerShell 都能直接粘贴，见文末复跑命令>
- 期望：<关键字段或输出片段>；对不上先查「已知会变」（在线服务 / 证书 / IP / 时钟）

## 6 目标与授权
- 目标：<样本 / 版本 / sha256 / 架构 / 保护>
- 授权：<本地只读 / 是否允许动态 / 补丁回滚 / 时间窗>
- 范围外：<生产环境 / 真实授权服务器 / 分发补丁>
- 环境：<OS / Ghidra/x64dbg/Frida / 符号 / 时区>

## 7 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/preflight.json | <sha256> | `python Tool/skill/softseep/scripts/preflight-classify.py <sample>` | 0 | 平台/保护/节 |
| E02 | artifacts/triage.json | <sha256> | `python Tool/skill/malware-analysis/scripts/mal-triage.py --file <sample> --json` | 0 | 导入/字符串/overlay |
| E03 | artifacts/unpack.json | <sha256> | `python Tool/skill/malware-analysis/scripts/mal-unpack.py --file <sample> --json` | 0 | 壳/OEP/dump |
| E04 | artifacts/patch-verify.json | <sha256> | `python Tool/skill/softseep/scripts/patch-verify.py --file ... --manifest ...` | 0 | 补丁/回滚 |

## 8 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| 入口/符号 | 入口到关键节点路径可打印，命名有依据 | <实测> | E01/E02 | <结论> |
| 保护/壳 | 壳类型、OEP、IAT、节表可解释 | <实测> | E01/E03 | <结论> |
| 关键行为 | 网络/文件/注册表/加密调用有 xref 或动态证据 | <实测> | E02 | <结论> |
| 状态源 | 状态字/返回值/消费者三者一致 | <实测> | E02 | <结论> |
| 补丁闭环 | 最小补丁 + A/B/C 对照 + 可回滚 | <实测> | E04 | <结论> |
| 版本回归 | 新旧版指纹/偏移差可解释，唯一命中 | <实测> | E04 | <结论> |

## 9 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 只有 `sub_xxx`，无字符串/常量 | <yes/no> | E01/E02 | 转符号恢复/动态断点 |
| 只改 UI/`license_type`，状态源未动 | <yes/no> | E02 | 回状态源，不写闭环 |
| dump 后节仍高熵/IAT 坏 | <yes/no> | E03 | 继续找 OEP 或运行期取功能 |
| 多命中/偏移不可解释 | <yes/no> | E04 | 重新分析，不硬套 AOB |
| 补丁后崩溃/签名失败 | <yes/no> | E04 | 回滚并按 02/09 换路 |
| 无回滚/无备份 | <yes/no> | E04 | 不交付 |

## 10 影响与边界
- 影响：<可绕过/可读写的状态 / 可复现的功能路径>
- 边界：<本地样本 / 未连真实服务 / 未覆盖其它版本>
- 误报风险：<调试器/反调试造成的假路径、字符串误判>
- 未覆盖：<未分析的模块、未验证的授权服务端>

## 11 修复建议（厂商视角）
1. 关键状态放服务端或受完整性保护的区域，客户端只做展示。
2. 启用代码签名/ASLR/DEP/CFG，检测调试器与内存补丁，校验自身哈希。
3. 授权协议使用短期票据、设备绑定与重放保护；敏感分支做混淆但不要依赖单一状态字。
4. 发布可回滚补丁与版本 manifest，保留 AOB/符号映射便于跨版本回归。

## 12 复跑命令
```bash
python Tool/skill/softseep/scripts/preflight-classify.py work/<case>/artifacts/target.bin
python Tool/skill/malware-analysis/scripts/mal-triage.py --file work/<case>/artifacts/target.bin --json
python Tool/skill/softseep/scripts/patch-verify.py --self-test
```
