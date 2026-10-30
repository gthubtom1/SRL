# 定制分支跟随更新

- 触发词：软件更新了，跟随更新、新版出来了，跟随我们的定制版、保留我们的 UI，更新到新版、把上一版补丁适配到新版、把上一版的补丁适配到新版、读取上次逆向记录，适配这个新版、新版路径是
- 输入：新版本文件或明确路径；新版本号可已知，也可先登记为 `pending` 并在指纹记录后填写。旧项目、旧原版、旧定制成品、补丁账、UI 清单和构建记录应优先从当前项目自动读取。
- 范围：第一版只承诺 PE/Windows 与 APK。Electron/asar、Unity/AssetBundle、Web、.NET/Java 等载体必须显式说明“尚无专用适配器”，不能套用 PE/APK 的结论冒充已验证。
- 能力：`repo:case_state`、`repo:patch-verify`、`repo:reverse-accept`、`repo:preflight-classify`、`tool:ida`、`tool:x64dbg`、`tool:r2`、`apk:static_apktool`、`apk:repack_signed`、`repo:install_test`，以及按变化调用的 `binary-diff`、`unpack-loop`、`ui-rebrand`、协议和授权相关技能。

## 1. 先找对旧项目

追版的第一个证据不是 AOB 命中，而是“新版确实属于同一个定制分支”。

1. 优先使用当前会话已经绑定的项目、版本和运行记录。
2. 不在同一项目时，依次按项目元数据、产品名与版本链、旧目标文件名和哈希、历史报告及 `versions/<version>/reverse-baseline.json` 查找候选。
3. 文件名相似只能产生候选，不能证明是同一软件。
4. 只有一个可信候选与新版的产品身份、升级链和来源证据同时相容时才继续。
5. 无候选、多个候选、产品名撞车、哈希/签名/包名冲突或版本链断裂时停止自动归并，明确列出候选并等待用户确认。
6. 旧项目缺失时按新任务处理，不能声称“已复用”；如项目状态中已有记录，用 `case_state.py` 建立原版、定制成品、清单和验收证据。

## 2. 比较三个对象，不比较两个成品

有效追版必须围绕三个对象建立差异表：

| 比较 | 要回答的问题 |
|---|---|
| 旧原版 → 新原版 | 上游新增、删除、重编译、换壳、接口和资源槽发生了什么变化 |
| 旧原版 → 旧定制成品 | 我们改了什么，包括授权、补丁、UI 层、品牌资产和构建包装 |
| 我们的定制改动 → 新原版 | 哪些能直接复用，哪些需要重定位，哪些因上游变化失效 |

不能把“旧定制成品 → 新原版”直接当成完整差异，否则会把上游新功能和旧定制补丁混在一起，难以判断新版功能是否丢失。

对每个受范围保护的项输出一个状态：

- `reused`：原锚点、哈希和语义均可复核，直接复用且有测试证据。
- `relocated`：旧锚点失效，但已通过新锚点重定位并完成语义和运行验证。
- `needs_manual`：可定位但语义、交互或资源映射尚不能确认。
- `missing`：新版中未找到目标。
- `multi`：出现多个同样可信的候选。
- `blocked`：壳、签名、设备、材料、许可或依赖阻断。

`reused` 和 `relocated` 才可计入完成；其余状态必须出现在报告的待办中。

## 3. 固定生命周期，技术路线随目标变化

固定的是顺序：

```text
找回旧项目
→ 读取旧版/旧定制记录
→ 登记新版并比对上游变化
→ 分类复用或重做
→ 合并新版新增功能
→ 重建并重新签名/打包
→ 补丁、UI 和功能回归
→ 写回新版本账本
```

不固定的是具体手段。壳、授权方式、UI 栈、服务端依赖、载体和打包方式不同，应按差异表选择现有技能。不要强制所有任务重走旧 `00 → 01 → … → 05` 阶段链；`_pending/00..05` 仅是历史归档，不是现役执行入口。

复用优先级：

1. 我方覆盖层、自有启动器或服务端下发内容。
2. 外部资源、配置、语言包和可替换数据文件。
3. 稳定接口字段、包名/类名、窗口类、文件键和资源容器锚点。
4. AOB/字节补丁候选。
5. 代码级重写或 hook。

前三层能完成时，不要为了“统一流程”退回高成本代码重写。只有高成本路径确有必要时才调用 `binary-diff`、反编译和逆向工具。

## 4. 首次逆向与定制时必须留下可追版记录

交付第一次定制版前，项目必须能回答“下次怎样从新原版重建”，至少包含：

- 上游原版：版本、SHA256、大小、格式/签名/包名、来源和项目内副本引用。
- 我方成品：路径、SHA256、构建时间，以及从原版复现的命令。
- 代码补丁：`versions/<version>/reverse-baseline.json` 中的语义、偏移、RVA、AOB、原/新字节和唯一性自检。
- UI 定制：`ui-inventory.json`、我方设计源和资源、上游对应锚点、应用方式、前后截图、定制资产哈希、验收项及已知未知项。
- 授权和接口：调用位置、协议字段、端点/资源引用及测试证据。
- 构建：入口、输入、输出、签名/打包参数、失败恢复和回滚方法。
- 验收：可执行的 UI 与功能回归项，而不是只写“看起来正常”。

缺少 UI 定制记录时，可以追补代码和构建，但不得把该次交付标成“UI 可追版基线已建立”。缺少唯一旧项目证据时同样不得开始静默合并。

## 5. 标准执行步骤

1. **恢复上下文。** 读取 `project_state`、`versions/<old>/version.json`、`reverse-baseline.json`、`patch.json`、`ui-inventory.json`、构建文件和验收记录；核对文件哈希。
2. **登记新版。** 通过 `version-migrate.py fingerprint` 记录新版身份，再按项目状态决定是否建立新 version。新版本号未知时可暂用唯一 `pending-*` ID，正式版本号确认后再走现有项目状态接口，不能覆盖旧版本。
3. **检查变化。** 先判断产品身份、格式、壳/保护、签名/包名、UI 栈、授权方式和构建依赖是否仍在支持范围。出现阻断变化时先调用 `unpack-loop` 或对应载体技能。
4. **重定位代码位点。** 用 `version-migrate.py align --case <project> --old <old> --new <new-file> --new-version <new>`。`unique` 只表示 AOB 定位候选，必须再核对原字节、语义、xref/调用关系和补丁可行性。
5. **迁移 UI。** 按 `ui[]` 逐项复用覆盖层、资源或锚点；先找新版原版对应对象，再叠加我方定制层。资源槽变化时按容器条目、资源名、内容和上下文匹配，并记录 old→new 映射。
6. **合并上游新功能。** 对照旧原版→新原版差异，把新版页面、入口、服务和依赖并入定制 UI。只恢复旧页面而漏掉新版入口，视为功能回归失败。
7. **重建。** 使用记录的构建入口从新原版重新生成，不直接把旧定制成品套在新安装包上。补丁、资源替换、重打包和 Android 重签名都必须在项目内可复现。
8. **验证。** 运行补丁复算、UI 截图/交互回归、功能清单、安装或启动测试、失败回滚和必要的安全/完整性检查。
9. **写回账本。** 将已验证的新位置、补丁、变更后的 UI 锚点、资产、构建输出、验收结果和未解决项写入新版本的记录。原版、旧版本和旧证据不改写。
10. **报告。** 汇总“复用、重定位、新版新增、人工处理、阻断”五类结果，并给出下一次追版可读取的入口。

## 6. 命令入口

版本身份、位点对齐和报告统一使用 `version-migrate.py`：

```text
python Tool/skill/softseep/scripts/version-migrate.py fingerprint --file <new-target>
python Tool/skill/softseep/scripts/version-migrate.py init --case <project> --version <old> --file <old-target> [--parent <parent>]
python Tool/skill/softseep/scripts/version-migrate.py add-site --case <project> --version <old> --file <old-target> --id <site-id> --sem <meaning> --aob <aob> ...
python Tool/skill/softseep/scripts/version-migrate.py add-ui --case <project> --version <old> --id <ui-id> --stack <stack> --apply-method <method> --inventory <relative-json> [--screenshot-upstream <png>] [--screenshot-custom <png>] ...
python Tool/skill/softseep/scripts/version-migrate.py align --case <project> --old <old> --new <new-target> --new-version <new>
python Tool/skill/softseep/scripts/version-migrate.py report --case <project> --old <old> --new-version <new>
python Tool/skill/softseep/scripts/patch-verify.py --file <target> --manifest <project>/patch.json --out <output>
python Tool/skill/softseep/scripts/reverse-accept.py --case <project>
python Tool/scripts/preflight.py --fast
```

方法以各命令的 `--help` 和项目内 schema 为准。`patch-verify.py` 不是版本账入口；不要继续使用旧文档里的 `patch-verify.py fingerprint`、`align` 或 `report`。

## 7. AOB、UI 与构建的失败规则

- `unique`、高相似度、文件名相同或旧 RVA 仍在范围内，都不是成功证据。
- `missing`、`multi`、`needs_manual` 和 `blocked` 必须保留在机器记录与最终报告中。
- 命中多处时先核对语义、加长窗口或增加稳定上下文；仍不唯一则保留 `multi`。
- 命中缺失时按“唯一字符串/配置锚 → xref → 函数常量与调用序列 → 二进制差异”顺序兜底；禁止用旧 RVA 盲写。
- UI 旧资源无法安全重映射时停止自动替换，保留上游原始界面可运行状态并报告人工项。
- 新版有新增功能而定制 UI 未覆盖入口、文案或交互时，状态为回归失败。
- 壳/保护明显变化时先走过壳路线；签名或设备限制未满足时标为 `blocked`，不能以静态截图代替运行验收。
- 构建、补丁验证、UI/功能回归或回滚任一失败，只能交“部分完成 + 具体待办”，不能宣称追版成功。

## 8. 完成判据

只有同时满足以下条件才可报告“追版完成”：

- 已证明旧项目与新版属于同一允许升级的产品；
- 范围内的代码、UI、授权、构建和验收记录均已读取；
- 所有受保护项均为 `reused` 或 `relocated`，或范围外且有用户明确排除证据；
- 上游新增功能已并入定制 UI 并通过入口/交互回归；
- 补丁复算、重建输出哈希、UI 前后截图、功能测试和回滚验证均有证据；
- 新版本 `reverse-baseline.json`、`align.json`、`migrate-report.md`、UI 和构建记录已写回；
- 报告明确列出未验证载体、设备、服务端或人工项。
