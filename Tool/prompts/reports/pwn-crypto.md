# pwn-crypto 报告模板

> **客户视角五段（必须全在，缺一不算交付）**：下面五个是**真标题**——`python Tool/scripts/case_state.py report --check --file <本文件>`
> 按标题文字精确匹配「结论 / 已确认 / 仍未知 / 下一步 / 复查」，缺一段即 `[FAIL]`；每段标题下至少 2 行正文，
> 「结论」不超过 3 行，「已确认」里至少要有一个 `E-` / `C-` / `F-` 编号。「下一步 / 复查」别改名，改了检查器就找不到。

> 复制到 `work/<case>/report.md`。只写有偏移/回代/崩溃证据的结论。

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
- 目标：<二进制 / 服务 / 密码挑战 / 版本 / sha256>
- 授权：<靶场 / 隔离环境 / 允许的利用等级 / DoS 另立授权>
- 范围外：<生产主机 / 真实凭据 / 持久化>
- 环境：<OS / 架构 / 保护位 / 工具版本>

## 7 证据清单
| # | 文件 | sha256 | 命令 | rc | 说明 |
|---|---|---|---|---|---|
| E01 | artifacts/pwn-check.json | <sha256> | `python Tool/skill/pwn-crypto/scripts/pwn-check.py --file <bin> --json` | 0 | 保护位/导入 |
| E02 | artifacts/repro.json | <sha256> | `python Tool/skill/pwn-crypto/scripts/pwn-repro.py --objdump ... --func ... --probe-log ...` | 0 | 偏移三源 |
| E03 | artifacts/crypto.json | <sha256> | `python Tool/skill/pwn-crypto/scripts/crypto-verify.py --rsa ...` | 0 | 密码回代 |

## 8 判据命中表
| 判据 | 期望 | 实测 | 证据# | 结论 |
|---|---|---|---|---|
| 栈偏移 | objdump 位移与运行时 probe 一致 | `offset=<n>, consistent=true` | E02 | <结论> |
| 保护位 | NX/PIE/Canary/RELRO 与利用路线一致 | <实测> | E01 | <结论> |
| 密码回代 | `verified=true`，明文/密钥可复算 | <实测> | E03 | <结论> |
| 崩溃可复现 | 3/3 命中同一偏移或同一异常 | <实测> | E02 | <结论> |
| JWT/哈希 | 签名剥离或弱密钥可验证，且有拒绝对照 | <实测> | E03 | <结论> |

## 9 失败判据记录
| 失败判据 | 是否命中 | 证据# | 处置 |
|---|---|---|---|
| 只崩溃不可控、偏移多解 | <yes/no> | E02 | 不写可利用，转信息泄露/其它路线 |
| 缓解策略阻断（Canary/ASLR/CFG） | <yes/no> | E01 | 标 blocked，换路线 |
| 密码回代失败或只验证密文 | <yes/no> | E03 | 不写“已还原” |
| 只拿到 hash 未破解 | <yes/no> | E03 | 素材，不是打穿 |
| 单次成功/环境相关 | <yes/no> | E02 | 重复 3 次或降级 |

## 10 影响与边界
- 影响：<可控寄存器/读写原语/密钥恢复范围>
- 边界：<本地/远程、是否需要账号、是否影响生产>
- 误报风险：<调试器改变时序、ASLR 偶然命中、样本非目标版本>
- 未覆盖：<未测的 gadget/符号/密码模式>

## 11 修复建议（厂商视角）
1. 编译启用 Canary/NX/PIE/RELRO/CFG，敏感比较使用常量时间实现。
2. 对长度、索引、整数回绕做服务端边界检查；用户输入只作数据，格式串固定。
3. 密码使用 AEAD（AES-GCM/ChaCha20-Poly1305）+ 随机 IV（ECB/固定 IV 属返工）。
4. 密钥放 HSM/KMS，限制导出；JWT 固定算法白名单并校验 iss/aud/exp。

## 12 复跑命令
```bash
python Tool/skill/pwn-crypto/scripts/pwn-check.py --file work/<case>/artifacts/target.bin --json
python Tool/skill/pwn-crypto/scripts/pwn-repro.py --objdump work/<case>/artifacts/target.dis --func <func> --probe-log work/<case>/artifacts/probe.txt
python Tool/skill/pwn-crypto/scripts/crypto-verify.py --self-test
```
