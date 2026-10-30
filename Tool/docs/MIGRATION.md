# 定制分支追版与版本账

本文说明如何把已经完成的定制分支迁移到软件的新上游版本。它是 PE/Windows 与 APK 第一版追版的规范入口，也为后续载体适配器提供统一边界。

## 1. 定位和范围

- 用户可以说“软件更新了，跟随更新”“保留我们的 UI，更新到新版”“把上一版补丁适配到新版”，并提供新版文件或路径。
- 唯一现役追版入口是 `Tool/playbooks/version-migrate.md`；脚本入口是 `Tool/skill/softseep/scripts/version-migrate.py`。
- 第一版 MVP 支持 PE/Windows 和 APK。其他载体可以继续使用各自技能完成分析，但不得在没有专用适配器和真实回归证据时宣称已纳入追版支持。
- 旧 `_pending/00..05` 阶段只作为历史资料归档，可提取思路，但不是现役执行链。不要新增第二个追版 playbook，也不要强制所有任务重走旧阶段。

追版固定的是生命周期，不是技术路线：

```text
找旧项目 → 读取记录 → 登记新版 → 对比变化 → 分类复用/重做
→ 合并新版功能 → 重建 → 补丁/UI/功能回归 → 写回账本
```

## 2. 先确认是同一个定制分支

脚本只负责处理已经确认身份的项目；Agent 负责在调用脚本前完成归属判断。

1. 当前会话或项目状态已经绑定旧任务时，优先复用该上下文。
2. 不在同一项目时，按项目元数据、产品名与版本链、旧目标文件名/哈希、历史报告和版本账查找候选。
3. 文件名相似不是同一软件的证明。产品名、签名/包名、来源、版本链或哈希出现冲突时停止。
4. 唯一可信候选才可继续；多个候选或无可靠候选必须报告歧义并等待用户确认。
5. 没有旧记录时按新任务分析，不得声称已有补丁或 UI 被复用。

## 3. 三个对象与代码差异

追版必须比较三个对象：

1. **旧上游原版**：上一次定制所基于的原版。
2. **新上游原版**：本次用户提供的新版。
3. **旧定制成品**：我们此前交付的带补丁、品牌和 UI 层的版本。

用途分别是：

| 比较 | 目的 |
|---|---|
| 旧原版 → 新原版 | 找上游新增功能、保护/壳、接口、资源槽和构建变化 |
| 旧原版 → 旧定制成品 | 找我们真正需要保留的补丁、UI 和品牌改动 |
| 定制改动 → 新原版 | 把需要的改动重新应用，避免覆盖新版新增内容 |

不能只比较旧定制成品和新原版，否则会把上游变化与我们的改动混在一起。

复用顺序固定为：

```text
覆盖层/自有启动器/服务端内容
→ 外部资源/配置/语言包
→ 稳定接口字段/文件键/资源容器锚点
→ AOB/字节补丁
→ 代码级重写或 hook
```

低层方案可以完成时，不必为了统一流程退回代码级重写。

## 4. 目录与职责

推荐的项目记录如下，沿用现有项目状态与证据目录：

```text
<project>/
  versions/
    1.0/
      version.json
      reverse-baseline.json
      patch.json
      ui-inventory.md
      ui-inventory.json
      build.ps1
      acceptance.json
    1.1/
      version.json
      reverse-baseline.json
      align.json
      align-revisions/<revision>.json
      migrate-report.md
      patch.json
      ui-inventory.md
      ui-inventory.json
      acceptance.json
```

职责边界：

- `project_state.py`：项目、版本、运行、目标哈希、证据和验收。
- `reverse-baseline.json`：下一次追版需要的代码位点、UI 层、构建和验收引用。
- `patch.json`：可复算、可回滚的补丁记录。
- `ui-inventory.*`：人工与机读 UI 清单。
- `build.*`：从上游原版重建成品。
- `align.json` / `migrate-report.md`：特定旧版到新版的定位结果和人工报告。

不要把这些内容全部塞入 `facts.jsonl`，也不要另造第二套项目状态系统。

## 5. 反向基线

现役 schema 是 `seep-reverse-baseline/1`，文件名是 `versions/<version>/reverse-baseline.json`。旧 `manifest.json` 的 `seep-migration/1` 只做兼容读取，不再作为新任务入口。

最小结构：

```json
{
  "schema": "seep-reverse-baseline/1",
  "version": "2.4.0",
  "parent_version": "2.3.0",
  "source_exe": "versions/2.4.0/reverse-target/app.exe",
  "binary": {
    "sha256": "<64 lowercase hex>",
    "size": 123456,
    "format": "PE32+",
    "machine": "x64",
    "local_path": "versions/2.4.0/reverse-target/app.exe"
  },
  "sites": [],
  "ui": [],
  "license": [],
  "acceptance": []
}
```

代码位点至少记录：

- `id` 和 `sem`：唯一 ID 与可供人判断的一句话语义。
- `offset`、`rva`：文件偏移与地址空间位置。
- `aob`：能唯一命中的特征码；相对地址操作数必须用 `??` 屏蔽。
- `patch.orig` / `patch.new`：等长、可复算的修改。
- `self_check`：旧版本内命中数、唯一性和“只表示定位候选”的含义。

UI 记录使用 `ui[]`。每条至少包含：

```json
{
  "id": "main-shell",
  "stack": "win32",
  "apply_method": "overlay",
  "anchor_type": "window-class",
  "anchor": "ExampleMainWindow",
  "inventory": {
    "path": "ui-inventory.json",
    "sha256": "<64 lowercase hex>",
    "size": 2345
  },
  "assets": [
    {
      "path": "ui/assets/main-shell/background.png",
      "sha256": "<64 lowercase hex>",
      "size": 1234
    }
  ],
  "screenshots": {
    "upstream": [
      {
        "path": "ui/shots/upstream/main-shell.png",
        "sha256": "<64 lowercase hex>",
        "size": 4567
      }
    ],
    "custom": [
      {
        "path": "ui/shots/custom/main-shell.png",
        "sha256": "<64 lowercase hex>",
        "size": 4567
      }
    ]
  },
  "acceptance": ["layout", "navigation", "feature-entry"]
}
```

`apply_method` 只允许 `overlay`、`resource_replace`、`code_patch`、`server_content`。资产、清单和截图必须位于项目内。`ui-inventory.json` 还应包含 `pages`、`components`、`brand_assets`、`upstream_anchor`、`custom_asset`、`screenshots_before`、`screenshots_after`、`acceptance` 和 `unknowns`。

## 6. 现役命令

```text
# 只记录目标身份，不声称已理解或已可追版
python Tool/skill/softseep/scripts/version-migrate.py fingerprint --file <target>

# 为上游原版建立版本账；会保存项目内副本
python Tool/skill/softseep/scripts/version-migrate.py init \
  --case <project> --version <version> --file <target> [--parent <parent>]

# 登记代码位点；AOB 旧版本内必须唯一命中
python Tool/skill/softseep/scripts/version-migrate.py add-site \
  --case <project> --version <version> --file <target> \
  --id <site-id> --sem <meaning> --aob "<aob>" ...

# 登记并校验 UI 定制层；不自动执行 UI 修改
python Tool/skill/softseep/scripts/version-migrate.py add-ui \
  --case <project> --version <version> \
  --id <ui-id> --stack <stack> --apply-method <method> \
  --anchor-type <type> --anchor <value> \
  --inventory ui-inventory.json \
  --asset <project-relative-asset> \
  --screenshot-upstream <project-relative-png> \
  --screenshot-custom <project-relative-png> \
  --acceptance <acceptance-id> ...

# 对齐旧位点到新版本；unique 仍只是定位候选
python Tool/skill/softseep/scripts/version-migrate.py align \
  --case <project> --old <old> --new <new-target> --new-version <new>

# 根据 align 生成可复核的迁移报告
python Tool/skill/softseep/scripts/version-migrate.py report \
  --case <project> --old <old> --new-version <new>
```

具体参数以各子命令 `--help` 和代码 schema 为准。版本账命令统一属于 `version-migrate.py`；不存在 `patch-verify.py fingerprint`、`patch-verify.py align` 或 `patch-verify.py report`。补丁验证使用：

```text
python Tool/skill/softseep/scripts/patch-verify.py \
  --file <target> --manifest <patch.json> --out <output-or-json>
```

## 7. 执行、失败与验收

执行顺序：

1. 找回旧项目和旧版本记录，核对文件哈希。
2. 指纹登记新版并识别壳、签名/包名、UI 栈、授权和构建变化。
3. 对比旧原版和新原版，列出上游新增功能与破坏性变化。
4. 对比旧原版和旧定制成品，恢复我方代码与 UI 改动。
5. 对齐 AOB；命中后再核对原字节、语义、xref、函数上下文和补丁可行性。
6. 重定位 UI 覆盖层、外部资源或代码锚点，并把新版功能并入定制 UI。
7. 从新原版执行构建、重打包、签名和输出哈希复算。
8. 运行补丁验证、UI 截图/交互回归、功能测试、安装/启动测试和回滚测试。
9. 调用 `reverse-accept.py --case <project>`，再运行 `preflight.py --fast`。
10. 将新版 `reverse-baseline.json`、`align.json`、`migrate-report.md`、UI 和构建记录写回。

每个受保护项必须归入以下状态之一：

- `reused`：锚点、哈希和语义可复核。
- `relocated`：已重定位并完成语义及运行验证。
- `needs_manual`：可定位但语义、交互或映射尚未确认。
- `missing`：新版未找到。
- `multi`：存在多个同样可信的候选。
- `blocked`：壳、签名、设备、材料、许可或依赖阻断。

失败规则：

- `unique` 不是成功，只有后续语义与验收通过才算 `relocated`。
- `missing`、`multi`、`needs_manual` 和 `blocked` 必须留在报告，不能改写成“基本完成”。
- AOB 缺失时依次尝试唯一字符串/配置锚、xref、函数常量与调用序列、二进制差异；禁止用旧 RVA 盲写。
- 壳/保护变化时先调用 `unpack-loop` 或对应载体技能，不要硬套旧补丁。
- UI 资源不能安全映射时保留上游可运行界面并报告人工项，不能自动覆盖。
- 新上游新增功能没有进入定制 UI 或功能回归时，视为追版失败。
- 构建、补丁验证、UI/功能回归、回滚任一失败时，只能交“部分完成 + 待办”。

追版完成要求：

- 旧项目与新版本同属已确认的定制分支；
- 范围内代码、UI、授权、构建和验收记录均已读取；
- 所有受保护项为 `reused` 或 `relocated`，或用户明确排除且有记录；
- 新上游功能已并入并通过回归；
- 补丁、构建输出、UI 前后截图、功能和回滚均有证据；
- 新版本账本和报告已写回，未验证载体/设备/服务端项明确列出。

## 8. 首次定制的收尾要求

首次逆向并不以“成品能启动”为追版基线完成的充分条件。交付前必须：

- 用 `version-migrate.py init` 保存上游原版身份和项目内副本；
- 用 `add-site` 保存已用代码位点；
- 用 `add-ui` 保存我方 UI 层、上游锚点、资产、前后截图和验收；
- 保存构建入口、输出、签名/打包参数和回滚方法；
- 运行补丁复算、功能/UI 回归和 `reverse-accept.py`；
- 在报告中标记“可追版基线已建立”，或明确列出缺失项。

旧 `_pending/00..05` 中的阶段思路仍可查阅，但任何新任务都使用当前九域路由和现有技能，不以恢复旧阶段链作为交付条件。
