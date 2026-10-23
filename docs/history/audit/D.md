# D 轮独立审计：三层架构能否“以后只小改”

> ⚠️ **历史快照（非现状）**：本文记录的是当时的口径与数字，可能与本仓当前状态不一致。
> 当前状态以 `docs/FORK-BRIEF.md` + `docs/RELEASE-1.26.1.md` + 实跑门禁为准。

- 仓库/基线：`D:/Seep-Reverse-Lab`，HEAD `a9d2a40`，`VERSION=1.23.1`，`git status` clean。
- 方式：只读 + 跑门禁 + 自写探针（放 `/tmp`，不落仓库）；未改代码、未 commit。
- 规模核对：11 域（`domain_spec.py`）、44 能力（`Tool/capabilities/*.json`）、22 配方（playbooks 去掉 INDEX/README）、31 路由（`routing.json`）。

## 结论

**当前不是“三层”，而是“域层 + 配方层”两套并行索引，外加一层没人消费的能力注册表。** 域层职责清楚（domain-gate 管篇幅/案例/KB/矩阵/任务卡）；配方层是一份份自洽的命令序列；能力层没有 `domain`、触发词、判据，只是把域里的脚本与参考卷再列一遍，职责不成立。门禁全绿，但层与层之间没有外键：44 个能力没有一条被配方按 id 引用，意图工具也读不到这 44 条（实测 0 条）；配方只认 `tool:/apk:/repo:/mcp:` 命名空间。结果是“改能力不影响行为、改配方不受能力约束、新增配方/能力没有生成与门禁路径”。以后的小改会在三处各写一遍，且两套匹配器（routing 与 playbook 触发词）已经给出互相矛盾的正确答案。

## P0（不修就不能承诺“只小改”）

### P0-1 能力层是死层：44 个 id 与配方/意图完全脱钩

- 证据 1：22 个配方全部使用 `tool:/apk:/repo:/mcp:` id；按 id 精确引用 44 个裸能力 **0/22**。10 个配方抽查（qinglong-signin、multi-account-runner、site-clone-1to1、apk-unpack、license-bypass-deliver、firmware-extract、protocol-replay、malware-triage、plugin-analysis、supply-chain-audit）均为 0。
- 证据 2：`intent-coverage.py --json` 的 `sources.capability_count=177`，全部来自 tool/apk/repo 扫描；`Catalog` 里没有任何裸 id（`sign-locate`/`traffic-capture`/`authz-test` 均不在）。原因在 `Tool/scripts/intent-coverage.py:301`：单对象文件只找 `capabilities/items/tools` 数组；即使传入，`:269` 又因 id 不含 `:` 直接丢弃。
- 影响：`sign-locate`、`traffic-capture`、`authz-test` 这类能力只在能力间 `compose` 和 `capability-matrix.json` 出现；改它们对路由、配方、意图命中没有任何影响。`capability-gate.py` 的 PASS 只是自证 44 个 JSON 格式自洽。

### P0-2 `forge.py` 不存在；生成链与门禁链都断了

- 证据：`Tool/scripts/forge.py` 不存在。`new-skill.py:180-187` 只生成 `SKILL.md`、写 `softseep/SKILL.md`、往 `routing.json` 插一条规则；不生成 playbook、capability、intent probe、matrix 行、INDEX/计数，也不调用任何门禁。
- 证据：`preflight.py` 与 `.github/workflows/gates.yml` 都没有 `capability-gate.py` / `intent-coverage.py`；`domain-gate.py` 完全不读 `Tool/playbooks/`。
- 影响：新增配方/能力没有标准生成器，也没有“生成后必跑”的自动门禁；只能手改 4–5 处，漏一处不会被任何 CI 发现。

### P0-3 路由与配方对同一句给出相反答案，且两边都绿

- 证据：`routing.json:291` 的 R26 用 `il2cpp|global-metadata|unity 客户端` 把 Unity 归到 `forensics-mobile`；`lib/domain_spec.py:157,211,230` 的 60 条路由测试还硬编码 `expect_any=["forensics-mobile"]` 并 `forbid=["apkseep","apk-reverse"]`。
- 证据：配方 `apk-unpack` 的触发词就是 `il2cpp/global-metadata`，`intent-probes.json` 的 `plug-03/04` 也期望 `apk-unpack`。`domain-gate --routing` 与 `intent-coverage 60/60` 同时 PASS。
- 影响：这不是某条正则写错，而是“路由单一事实源”和“配方触发词”没有共同事实源；测试集把错误答案固化了。

### P0-4 唯一的跨层映射表 `capability-matrix.json` 不可信

- 证据：矩阵只有 10 个 `families`，第 11 域 `site-clone` 没有列；`client-license` 的 14 个 `full` 里包含 `ad-enum`、`adcs-abuse`、`cloud-iam`、`k8s-enum`（AD/云枚举被判为客户端授权“全覆盖”）。
- 证据：`capability-gate.py` 只校验“行存在、10 族每格有值、值 ∈ full/partial/via-compose”，不校验语义、不校验域覆盖、不校验 `generated_at`。
- 影响：一旦有人按矩阵编排，会把 AD/K8s 能力当成授权交付能力；而第 11 域连一列都没有。

## P1（会持续制造返工）

- **P1-1 意图覆盖是自证，不是独立验收。** 60 条探针只覆盖 19/22 配方，`apk-ad-removal`、`captcha-handling`、`firmware-emulate` 为 0 条；`playbooks/INDEX.md` 仍写“55/60、缺口 5、91.67%”，实际 `intent-coverage` 是 60/60。60 条全绿不能证明能覆盖用户新说法。
- **P1-2 自写 30 条极端意图实测：命中期望配方 6/30（20%）；11 条无任何落点；8 条落到错误配方；5 条只落到工具能力。** 典型：小程序签到→仍落 qinglong 但无小程序词；Unity IL2CPP 去广告→`apk-unpack`（不是 apk-ad-removal）；SaaS 后台复刻→site-clone；IoT OTA 签名→supply-chain；Docker 镜像抠服务→firmware-extract；BLE/Modbus 手环/工控→无配方；iOS 砸壳→forensics；PyInstaller/Go/Rust/套壳/电视/车机→无配方。
- **P1-3 词表漏项（可复现）。** 缺：`小程序`、`wxapkg`、`鸿蒙/HAP/ArkTS`、`OTA`、`BLE`、`Modbus/工控`、`Cloudflare/人机验证`（配方只有“人机校验”）、`Docker`、`SaaS/本地版/云函数`、`PyInstaller`、`Go`、`Rust`、`套壳`、`电视/车机`；`apk-ad-removal` 只认“APK 去广告”，单独“去广告”不命中。误报：`签名`→supply-chain、`镜像`→firmware-extract、`驱动`→anti-cheat、`断网`→site-clone、`IPA`→forensics、`il2cpp`→forensics。
- **P1-4 路由跨域误判 6/40。** `kerberoast 拿 SPN`→R6（R6 的 `ast` 无边界，命中了 kerbero**ast**）；`去掉启动广告弹窗，出成品`→R0；`UI 改版，换标题和图标`→R0；`Unity il2cpp 去广告`→R26；`frida hook iOS app`→R26；`PE IAT`→R9 而非 R29（priority 次序歧义）。
- **P1-5 R34/R35 与配方不一致。** R34 的 `skill` 是 `softseep/SKILL.md`，note 却写“先落 playbook qinglong-signin / multi-account-runner”，且 R34 把 3 个配方压成 1 个内核技能；R35 落 `site-clone`，与 `site-clone-1to1` 同域但 schema 里没有 `playbook` 字段，无法机器校验；`把 SaaS 后台复刻成本地版` 不命中 R35 也不命中 backend-rebuild。
- **P1-6 同一能力有 4 套注册表。** `Tool/capabilities/*.json`（44）、`apkseep/scripts/capabilities.py`（apk:*）、`tool-capabilities.json`（36 个 tool:*）、`repo:*` 脚本自动扫描；互相没有 alias/映射。`compose` 是双向邻接而非执行 DAG（21 个 2-环，如 `ad-enum↔adcs-abuse`、`session-pool↔schedule-notify`），没有顺序与参数映射。
- **P1-7 抽查 10 个能力均为“二次提纲”。** apk-unpack/sign-locate/session-pool/site-crawl/license-bypass/firmware-extract/traffic-capture/patch-apply/ioc-extract/authz-test 的 `refs/scripts` 全部指向 skill 内已有文件，没有独立判据/触发词；`patch-apply` 同时列 4 个 apkseep 脚本，`traffic-capture` 指向协议分帧参考卷，`site-crawl` 的 `scripts` 为空却 `maturity=probe`。抽查 10 个配方：六段齐全、步骤带 rc，但 2 个 `repo:` id 按 README 规则解析不到（`rebuild-sign-install`/`temp_ocr` 实际是 `.ps1`）。
- **P1-8 计数与版本漂移。** `VERSION=1.23.1`、HEAD 提交写 `v1.24.0`；`docs/AUDIT.md` 写 `domain-gate 101/101`、`preflight 33/33`，实测 `domain-gate --all` 110/110；`ROADMAP.md` 仍写“九个安全域”（实际 11）；`playbooks/INDEX.md` 与 `intent-coverage` 数字相反。说明这些计数没有生成器/CI 校验。
- **P1-9 `new-skill.py` 的路由规则只有 `(?i)<name>` 字面量**（`:142`），无词边界、只认英文 id；新增 `bluetooth-re` 无法从“蓝牙手柄逆向”命中，且 `bluetooth-re` 会误吃子串。部署同步只写 `~/.pi/agent/skills/`，domain-gate 的部署哈希只查十域，新技能不在校验范围。

## 终版边界：6 条“只允许小改”判定

1. **算 bugfix（可直接小改）**：同一 id、同一输入/输出契约，只改命令参数、正则边界、文案错字；≤1 个代码文件 + ≤1 条回归；不动 `priority`、不动矩阵、不动能力 id。
2. **算小增量（可直接小改）**：给已有配方加触发词/探针/案例/reference；或新增 1 个只 `compose` 既有 id、且被 ≥1 配方按 id 引用的能力；不新增域、不新增命名空间。
3. **配方步骤、顺序或交付契约变更 = 不算小改**：走 minor 版本；必须重生 INDEX/矩阵/意图探针，并加“旧说法仍命中”的回归。
4. **能力 id、命名空间、域新增 = 不算小改**：走新版；必须一次改 SSOT + 全部引用 + 迁移表；禁止只在 playbook 里写 prose。
5. **路由主落点或 priority 变更 = 不算小改**：走新版；必须跑 60 条固定集 + 30 条 held-out + 配方一致性检查。
6. **发布门槛**：0 dangling、跨层引用 0 断链、held-out 覆盖率 ≥80%、INDEX/VERSION/计数全部由生成器产出；任一不满足即“不是小改”，不得合并。

## 仍会逼你大改的 3 个风险点

1. **能力 schema 缺 `domain/triggers/version/contracts`**：现在的能力只是“脚本+参考卷”的索引；一旦要真正做编排（依赖顺序、输入输出对接、版本兼容），44 个能力 + 22 个配方 + 矩阵必须一起迁移，属于破坏性改版。
2. **两套匹配器没有共同事实源**：routing 是全局 priority 的 31 条正则，playbook 是 22 份 Markdown 触发词；同义词要改两处，priority 靠人工排序，已经出现“绿-绿矛盾”（P0-3）。每加一个说法都在扩大矛盾面。
3. **分类轴是“客户端授权 + 11 安全域”**，装不下小程序/HarmonyOS/iOS/Unity/OTA/BLE 这类平台型需求；硬塞会新增 `miniapp:/harmony:` 命名空间或把 softseep 撑成万能域，最终逼一次 taxonomy/namespace 重写。

## 建议（按优先级）

1. 先修 P0-1：loader 接受单对象并允许裸 id；给能力加 `domain`、`triggers`、`aliases`、`version`；`capability-gate` 增加“被 ≥1 配方引用或显式 `reserved`”断言。
2. 建单一意图 SSOT：路由行增加 `playbook` 字段，playbook 触发词由同一张表生成；R34 拆到 qinglong/app-daily/multi-account，R35 补 `SaaS/本地版/后台` 并落到 backend-rebuild 或 site-clone。
3. 新增 `playbook-gate`（触发词、步骤命令存在、cap id 可解析、被意图探针引用、失败换路齐全）并接入 `preflight` + CI；CI 同时跑 `capability-gate` 与 `intent-coverage --check`。
4. 把 30 条 held-out 意图冻结为独立文件，不用于调触发词；每周统计“新说法→配方/能力”命中率，低于 80% 不允许发版。
5. 具体修：R6 的 `ast` 改 `\bast\b`；R26 的 `il2cpp/global-metadata` 移交 apk/reverse 或加 `exclude`；R11/R12 补“出成品/UI 改版”；补小程序/OTA/BLE/Modbus 词或明确写 DEFERRALS。
6. 矩阵从能力自带 `families` 生成，补 `site-clone` 列；在语义校验（每族 full 必须能被该族配方引用）通过前，禁止把它当编排输入。

## 证据命令（可复跑）

```bash
python Tool/scripts/capability-gate.py                  # PASS 44, 矩阵只查形状
python Tool/scripts/domain-gate.py --all                # 110/110 PASS（不含 playbook）
python Tool/scripts/intent-coverage.py --json           # 60/60；capability_count=177，无裸 id
python Tool/scripts/intent-coverage.py --probes /tmp/seepaudit/probes30.json  # 6/30
python Tool/scripts/domain-gate.py --routing            # 60 条全绿（含 Unity→forensics 的错误期望）
```
