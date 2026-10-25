# P0/P1 收口清单（v1.25.0）

> ⚠️ **历史快照（非现状）**：本文记录的是当时的口径与数字，可能与本仓当前状态不一致。
> 当前状态以 `docs/history/FORK-BRIEF.md` + `docs/RELEASE-1.26.1.md` + 实跑门禁为准。

> 来源：docs/audit/A/B/C/D/E.md，去重排序。状态只有三种：已修 / 转为 DEFERRALS / 证据不足暂挂。

## P0

| # | 问题 | 来源 | 状态 | 证据 |
| :-- | :-- | :-- | :-- | :-- |
| 1 | 版本链断裂（VERSION/CHANGELOG/tag 不一致） | A-P0-1 | 已修 | CHANGELOG 补 1.23.1–1.25.0；VERSION=1.25.0；tag 同 HEAD |
| 2 | QUICKSTART 入口脚本路径错 | A-P0-2 | 已修 | 改为 `Tool/skill/softseep/scripts/preflight-classify.py` |
| 3 | 路由片段门禁假绿（11 份报成 14 份、字段丢失仍 rc=0） | A-P0-3 | 已修 | 按文件数报数；11 份片段全量从 SSOT 同步 label/skill/keywords |
| 4 | 能力层死层（44 id 与配方/意图脱钩） | D-P0-1 | 已修 | domain/triggers/aliases + DAG + 被引用断言 |
| 5 | forge 缺失、生成链断裂 | D-P0-2 / E-P0-2 | 已修 | `Tool/scripts/forge.py` 三合一 + 生成即门禁 |
| 6 | 路由与配方对同一句相反答案（Unity il2cpp） | D-P0-3 | 已修 | 归属按「谁真有配方」定：`apkseep/SKILL.md:150` 明示 Not covered Unity/IL2CPP，`forensics-mobile/references/game-client-il2cpp.md` 有 Il2CppDumper 链路 → ① R26 保留 il2cpp/gameassembly/global-metadata/assetbundle/unityfs，R1 移除这些词；② ROUTING_TESTS 三条用例回 `expect forensics-mobile / forbid apkseep`，`domain-gate --routing` 60/60；③ 新增配方 `game-client-il2cpp`（8 步均为仓库内真实脚本）；④ 意图探针 4 条指向该配方，覆盖 93/93；⑤ `apk-unpack` 收窄为 DexVMP/native，`apk-ad-removal` 去掉 Unity/IL2CPP/global-metadata/AssetBundle 名义声明；⑥ `route-playbook-parity`（60 用例 / 23 配方 / 0 不一致，自测含正负例）接入 preflight/verify/CI；⑦ CHANGELOG v1.25.0 记录归属修正 |
| 7 | 矩阵不可信 | D-P0-4 | 已修 | 脚本重算 45×11 |
| 8 | 配方命令漂移 15/22 | B-P0-2 | 已修 | 6 处 `--level L2`→`M2`、6 处 `--json`/参数/路径对齐；playbook-check 用 AST 读 argparse + 运行时错误文案枚举，对全部命令（含占位）校验参数名与枚举值；现 23 篇 / 170 条 / 坏命令 0；已接入 preflight/python Tool/scripts/check.py --env/python Tool/scripts/check.py --env/CI |
| 9 | 证据链可静默成功（prove 接受不存在的证据 / claim 裸栈 / 案目录两套口径） | B-P0-3 | 已修 | ① `case_state.require_evidence()`：形似路径（含 `/`、`\` 或已知扩展名）的 `--evidence` 必须存在，否则 `{ok:false,blocked_at:"evidence-missing"}` rc=2；纯文本证据（`来源: 说明`）照旧允许（契约写入帮助文本）；② `append_fact` 对缺失案例目录返回 `{ok:false,blocked_at:"case-not-found"}` rc=2（不再裸 Traceback）；③ 案目录统一 `work/<case>`：`seep-start` 与 20 个配方/报告模板/KB 页面全部改写，preflight 措辞检查并入「第一方文档残留 `evidence/<case>` 即 FAIL」；④ drill 脚本 chromium 探测改为 env → `PLAYWRIGHT_BROWSERS_PATH` → ms-playwright → PATH，未命中输出 `blocked_at:"tool-missing"` rc=2（实测 rc=2）；⑤ `MANUAL/BASELINE-FREEZE.md` first-party 812→817，并在 preflight「文档数字 vs 实测」里与 `check-budget` 对账；⑥ `web-check`/`sc-check` 的 `--out` 自动建父目录，写失败返回 `{ok:false,blocked_at:"out-unwritable"}` rc=2（原来只打一行 stderr 仍 rc=0）；⑦ `deliver` 与 claim/prove 同一证据校验（`ghost.json` → rc=2 evidence-missing）；⑧ preflight 新增 `out-artifact` 断言（--out 指到不存在目录必须落盘） |
| 10 | 05-backend-rebuild 只有文档 | B-P0-4 / E-P0-1 | 已修 | 4 脚本 + 8 refs + L3 演练 |
| 11 | site-clone 未接入三层（入口 `seep-start --domain site-clone` rc=2） | B-P0-1 | 已修 | 4 能力 + 配方 + 路由；`seep-start.py` DOMAINS 增 `site-clone`（3 条真实命令），入口实跑 rc=0 |
| 12 | `--case` 空集判绿 | C-P0-2 | 已修 | 不存在案例目录返回 rc=2 `case-not-found` |
| 13 | 门禁不枚举 artifacts 目录 | C-P0-3 | 已修 | 递归全量：未登记且未被 MANIFEST.sha256 覆盖即 FAIL |

## P1（已修）

计数漂移（README/ROADMAP/DEFERRALS/SPEC/AUDIT）、`work/plans/` 恢复、`docs/audit/` 不参与 lint、隐私路径脱敏、意图探针 93/93、ROADMAP「十一个域」。

## P1（转 DEFERRALS）

ad-cloud 第 2 个真实案例（本机非域环境）；全量 264 张卡剧本化（60 张已成）；probe 能力补脚本（按使用顺序）；A 审计未在 tag 前落盘（本文件即其收口记录）。

## 验证

```
python Tool/scripts/preflight.py            # 41/41（含四道门禁：配方命令/能力 DAG/意图覆盖/路由↔配方）
python Tool/scripts/domain-gate.py --all    # 110/110
python Tool/scripts/intent-coverage.py      # 93/93
bash Tool/scripts/check.py && powershell -File check.ps1   # 65/0
```

## C / A 报告其余 P1 处置

| 来源 | 问题 | 状态 | 说明 |
| :-- | :-- | :-- | :-- |
| C-P1-1 | 脚本覆盖不足（部分脚本无 self-test） | 转 DEFERRALS | 按使用顺序补，已列入 D 项 |
| C-P1-2 | 失败 rc 契约不统一（个别 rc=1） | 转 DEFERRALS | 新增脚本一律 rc=2；存量 11 个脚本按 DEFERRALS D16 在该域下次实跑时统一 |
| C-P1-3 | mutation-test 未扩到全部反例 | 转 DEFERRALS | 四类已覆盖；`generated_at` 注入反例见 D17 |
| C-P1-4 | 脚本断言只查子串 | 转 DEFERRALS | 需语义断言，排下一批 |
| C-P1-5 | lessons 不执行 | 转 DEFERRALS | 目前只校验命令文本；执行态见 D18（需沙箱重放） |
| C-P1-6/7 | 两个门禁结论相反 | 已修 | 片段门禁按文件数报数并与 SSOT 同步 |
| A-P1-6/10/11/12 | DOMAIN-SPEC 十域/文档 0 入链/清单计数 | 已修 | 统一十一域；`docs/README.md` 索引 docs/*.md 与 Tool/docs 全部 20 篇（STAGE0/WORKSPACE_RULES 有入链）；`WORKSPACE_RULES.md` 重写为「scope 由用户声明 + 产物归位」；lint 根并入 Tool/docs、Tool/playbooks、Tool/capabilities、Tool/cases（仅 3 处命中已改写）；清单计数同步 |

## B / D 报告 P1 台账

| 来源 | 问题 | 状态 | 依据 |
| :-- | :-- | :-- | :-- |
| B-P1-1 | `sign-recompute` 只取平台包签名，不是请求签名复算 | 转 DEFERRALS | 需新增请求签名复算脚本 |
| B-P1-2 | `site-crawl/site-rebuild/visual-diff` 注册表过期 | 已修 | 四能力已指向 `site-*.py` |
| B-P1-3 | `tls-decrypt` 只有证书体检 | 转 DEFERRALS | 需 keylog 解密脚本 |
| B-P1-4 | `license-locate` 无脚本 | 转 DEFERRALS | 依赖 IDA/Ghidra 交叉引用 |
| B-P1-5 | `permission-evidence` 脚本参数错配 | 转 DEFERRALS | 需 APK 侧 manifest 解析脚本 |
| B-P1-6 | `ipc-audit` 脚本不是 IPC | 转 DEFERRALS | 需 binder 服务枚举脚本 |
| B-P1-7 | `yara-write` 无编译校验 | 转 DEFERRALS | 依赖 `yarac`，本机缺失走降级分支 |
| B-P1-8 | memory/rootfs/adcs 缺 `blocked_at` 分支 | 转 DEFERRALS | 工具缺失时按文档手工走 |
| B-P1-9 | 配方判据字段与脚本输出不一致 | 已修 | `ioc_counts→iocs`、`entropy_blocks→entropy.overall`、`source_url→url`、去掉脚本不产出的 `pool_size` |
| B-P1-10 | `site-clone-drill01` 域标错 | 已修 | `case.json.domain=site-clone`，索引重算 |
| D-P1-1 | 意图覆盖自证 | 已修 | 探针 93 条（含 30 条极端说法），覆盖 93/93 |
| D-P1-2 | 30 条极端意图只命中 6/30 | 已修 | 词表补齐后同一批全部落到期望配方 |
| D-P1-3 | 词表漏项 / 误报 | 已修 | 小程序/鸿蒙/OTA/BLE/Modbus/Cloudflare/Docker/SaaS/PyInstaller/Go/Rust/套壳/电视车机 |
| D-P1-4 | 路由跨域误判 6/40 | 已修 | `\bast\b`（kerberoast→R23）、R9 去 `iat`、R12 增去广告/UI 改版 |
| D-P1-5 | R34/R35 与配方不一致 | 转 DEFERRALS | note 已对齐；`playbook` 字段见 D14 |
| D-P1-6 | 同一能力 4 套注册表 | 转 DEFERRALS | 合并成本高于收益，按别名映射维持 |
| D-P1-7 | 能力多为二次提纲 | 转 DEFERRALS | 按使用顺序补独立判据 |
| D-P1-8 | 计数与版本漂移 | 已修 | VERSION/README/INDEX/AUDIT/BASELINE 同步，INDEX 由 intent-coverage 生成 |
| D-P1-9 | `new-skill.py` 路由规则无词边界 | 转 DEFERRALS | 新技能命名以英文 id 为准 |

## 三层门禁接线（本轮新增）

| 位置 | 断言 |
| :-- | :-- |
| `preflight.py`（section 13） | `playbook-check --json`、`capability-gate --json`、`intent-coverage --json` 三者 rc=0 且 JSON `ok=true` |
| `Tool/scripts/check.py` | 原「路由自洽」项内追加 playbook-check + capability-gate（项数保持 65） |
| `check.ps1` | 同一位置追加两门禁（项数保持 65） |
| `.github/workflows/gates.yml` | windows job 增 playbook/capability/intent 三步 |

## 第四轮驳回补充（README 正文 / K3 / QUICKSTART / 门禁盲点）

| 来源 | 问题 | 状态 | 依据 |
| :-- | :-- | :-- | :-- |
| A-P1-1 | `README.en.md:52` 写 `23 → 38 MCP tools`、`:221` 58 items、`:371` 58 checks | 已修 | 现为 `23 → 40 MCP tools` / `65 items` / `65 checks`；`grep "58 items\|58 checks"` = 0 |
| A-P1-12 | `DEPLOYMENT-CHECKLIST.md:98` K3 案例数被改成 5 | 已修 | 改为「14 个项目工程（项目 A ~ N，含 `_archive/` 归档）+ 2 个复刻演练」；磁盘实测 `项目*` = 14 |
| A-P1-2 | `QUICKSTART.md:42` 写「本域 7 条」 | 已修 | 改为「本域 10 条断言」（单域实测 10/10） |
| 新门禁盲点 | `playbook-check` 只读 `add_argument(choices=…)`，`case_state.py` 用运行时 `die()` 报允许值 → `--level L2` 仍判绿 | 已修 | 新增 `runtime_enum()`：从源码报错文案（`只能是 / must be one of`）提取枚举并校验；自测 15/15；驳回用例复现 `ok=false, reason=参数 --level 取值非法: L2（允许 M1/M2/M3/M4）` |
| A-P1-6 漏网 | `domain-gate.py:1052` detail 硬编码「10 域覆盖」 | 已修 | 改为 `"%d 域覆盖" % len(DOMAINS)`（11） |

### 十域残留清零（实测）

| 位置 | 原值 | 现值 |
| :-- | :-- | :-- |
| `Tool/cases/_templates/README.md:1` | `# 案例模板（十域）` | `# 案例模板（十一域）` |
| `Tool/scripts/lib/domain_spec.py` | 注释「十域（重点域）」 | 「十一域（重点域）」 |
| `Tool/scripts/domain-gate.py:712` | 「不只十域」 | 「不只单域」 |
| `Tool/scripts/domain-gate.py:994` | detail「十域 SKILL…」 | 动态 `%d 域`（11） |
| `Tool/scripts/preflight.py` | 「十域深度契约」×3 | 「全域深度契约」 |
| `Tool/scripts/preflight.py:683` | 标签「（10 域）」 | 「（≥10 份）」 |

### 配方人类入口（Tool/playbooks/README.md）同步 + 防复发

| 项 | 处理 | 证据 |
| :-- | :-- | :-- |
| README 索引写「22 个」、缺 `game-client-il2cpp` 行、`apk-unpack` 仍挂 `il2cpp、metadata` | 已修 | 表头改 23；新增 `game-client-il2cpp` 行（触发词 il2cpp/global-metadata/GameAssembly/AssetBundle/Unity 客户端）；`apk-unpack` 行改为「加固脱壳、VMP、DexVMP、反调试」 |
| 门禁盲区（README 被 SKIP_FILES 跳过） | 已修 | `playbook-check.py` 增断言：README 索引行集合 == 磁盘配方集合、表头计数 == 磁盘数；不一致即 `bad` 项（`--self-test` 15/15 含该负例） |

## 第五轮驳回补充（QUICKSTART 首屏路径 / 文档命令路径 lint）

| 来源 | 问题 | 状态 | 证据 |
| :-- | :-- | :-- | :-- |
| 首屏路径错 | `docs/QUICKSTART.md:21` 写「建 `Tool/cases/<案子名>/`、`evidence/<案子名>/`」 | 已修 | 改为「建 `work/<案子名>/`（含 artifacts/scope/facts），正式案例再复制到 `Tool/cases/<案子名>/`」 |
| 门禁覆盖不到 | 旧扫描根只有 `Tool/prompts`+`Tool/skill`，且只匹配 `evidence/<case>` | 已修 | 扫描根扩到 docs/、MANUAL/、Tool/docs、Tool/playbooks、Tool/cases、README×3；匹配 `evidence/<case>`、`evidence/<案子名>`、`evidence/<C>`；并新增「README/QUICKSTART 里 `python Tool/...py` 必须存在」检查（明细带 relpath） |
| 域内口径 | `ad-cloud` 3 篇 references 用 `evidence/` 作为工作目录 | 已修 | 统一为 `work/<case>/`（22 处） |
| 文档命令路径错 | 4 个第一方文件把 `sc-check.py` 写在 `Tool/skill/supply-chain-security/scripts/`（实际在 `Tool/scripts/`） | 已修 | 全部改为 `Tool/scripts/sc-check.py`；案例产物重算哈希、索引重生成、部署副本同步 |
| 反例验证 | 新增 lint 是否真能拦住 | 已验证 | 临时在 QUICKSTART 追加 `python Tool/nope/missing.py` 与 `evidence/<案子名>/x` → `preflight --fast` **37/38 FAIL**；移除后 38/38 |
