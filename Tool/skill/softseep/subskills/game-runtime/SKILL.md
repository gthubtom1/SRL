---
name: game-runtime
description: 游戏运行时状态定位与启停恢复交付；比较同构建受控内存快照，组合现有 AOB、差分、补丁及 IL2CPP 方法，区分离线候选与真实效果。
---

# 游戏状态与生命周期

`Tool/...` 路径以宿主登记的工作台源码根为基准；KB 和配方不复制进技能部署目录。技能内相对路径仍以本技能目录为基准。

用于“数值在哪里、改动为什么重启失效、如何启停与恢复”的限定构建任务。PC 由 softseep 主导；Android 由 apkseep 主导并借用本方法。这里提供离线候选定位器和实测流程，不提供已完成的 Trainer、进程读写器或通用指针扫描器。

## 输入与路线

取得原件/模块 SHA256、平台/ABI/构建、状态含义及前后操作记录、非敏感受控区域的两份原始快照及其哈希、区域身份/起点/长度、同一 project/version/run。确认客户端显示、客户端实际计算与服务端权威分别在哪；仅改显示不能证明游戏状态改变。缺设备、受控快照或运行确认时先交静态分析及材料清单。

1. **先定位**：只改变一个已知标量（如自有夹具生命值 100→75），记录操作时刻、场景和对象生命周期。快照须来自同构建同布局的同一区域，采集方提供来源证据；不要导入整个含凭据的进程 dump。现有 AOB 脚本处理文件字节，缺少针对受控状态转换的离线比较，因此使用下述专用脚本。
2. **筛候选**：执行比较器；唯一结果也只是候选。用第三次独立转换、无操作控制组、类型/访问指令或对象字段语义复核；多命中保留全体并增加对照，不取第一项。零命中检查编码、类型、采集时机、加密/镜像或布局，不自动扩大读取。
3. **建立地址关系**：文件 offset、RVA、VA、对象字段偏移分别记。模块定位借 [multiver-aob](../multiver-aob/SKILL.md)；跨构建借 [binary-diff](../binary-diff/SKILL.md)，复核指令/调用关系后才能迁移。快照偏移不能直接作为进程地址或可靠指针链；堆对象销毁、重建、场景切换和重启后必须重新找对象并核所有权。
4. **引擎/动态观测**：Unity 读正式的 [apkseep IL2CPP](../../../apkseep/subskills/il2cpp-dump/SKILL.md)，同构建 GameAssembly/libil2cpp 与 metadata 配对，类型→字段/方法→native 映射→实际状态关联。Android Frida 按 [frida-hook](../../../apkseep/subskills/frida-hook/SKILL.md) 核客户端/服务端版本、ABI、加载时机及正向控制；该 Android 示例不当成 Windows API。PC 使用现有已连通调试器/Frida 通道的实际 schema，无通道不宣称已 attach。
5. **修改与恢复**：限定目标具备运行授权和工具通道后才进入现有 [补丁工程](../../references/09-patch-engineering.md)。先做未插桩基线，记录原字节/当前状态、模块实例和构建。启用前读回预期原字节并确认当前对象仍有效；启用只作用于选定实例。停用时先停定时写入/事件回调，再撤 hook；只在同一实例与原修改字节仍匹配时恢复保存字节，不向已释放或重用对象盲写旧值。模块重载/对象重建使旧句柄失效。退出清理工具资源，重启应回到未启用基线。文件副本补丁用 `Tool/skill/softseep/scripts/patch-verify.py --help` 核入口，字节验证不能替代运行回归。

深资料：仓库根 `Tool/mcp/Tool/reverselab/kb/general/techniques/cheating/01-memory-hacking.md`（数值与指针生命周期）；UE4 移动端读 `Tool/mcp/Tool/reverselab/kb/apk-reverse/techniques/02-native/03-ue4-offset-hunting.md`，不能推广成 PC/UE5 布局。深资料中的工具须核当前可用接口，不复制系统级路线。

## 离线比较器

从仓库根调用最终 canonical 路径；仅标准库、不连接进程、不写目标内存。每个快照上限 16 MiB、manifest 上限 16 KiB；拒绝不同构建、不同区域/起点、长度变化、篡改哈希、无效类型/数值。只读取本地普通文件，不使用网络工具；材料应放本地目录。两份都来自旧构建时也须对照独立的当前模块哈希，不能把旧构建标签换成当前值。

manifest 示例（`<...>` 必须换成实际的 64 位小写 SHA256；path 相对 manifest 所在目录）：

```json
{
  "project": "fixture", "version": "build1", "run": "capture1",
  "before": {"path": "before.bin", "sha256": "<before snapshot SHA256>", "build_sha256": "<current module SHA256>", "region_id": "player-buffer", "region_start": 0},
  "after": {"path": "after.bin", "sha256": "<after snapshot SHA256>", "build_sha256": "<current module SHA256>", "region_id": "player-buffer", "region_start": 0}
}
```

`region_start` 是采集布局内的区域起点标识，不用于计算进程地址；应由采集方保证布局相同。manifest 是采集声明与完整性校验，不证明来源真实或布局等价。

```bash
python Tool/skill/softseep/subskills/game-runtime/scripts/snapshot_candidates.py --help
python Tool/skill/softseep/subskills/game-runtime/scripts/snapshot_candidates.py --self-test --self-test-dir tmp/capability-logs/game-runtime
python Tool/skill/softseep/subskills/game-runtime/scripts/snapshot_candidates.py --manifest work/demo/pair.json --build-sha256 <current-module-sha256> --type i32 --endian little --before 100 --after 75
```

类型：i/u8/16/32/64、f32/f64；整数十进制，字节序 little/big。浮点按指定类型精确编码匹配，无容差；NaN/Inf/越界失败。编码相同的前后值不能形成有效对照。`--alignment` 默认 1，以快照起点对齐；需要自然对齐时显式给宽度。输出 JSON 的 offsets 为零基快照字节偏移，`candidate_count` 为总数；`--max-results` 截断展示时 `truncated=true`，不能把截断列表当完整候选集合。

退出 0 表示比较完成：状态为 `unique_candidate`、`ambiguous` 或 `not_found`；无命中不是输入错误，也不是成功定位。坏输入退出 2、`ok=false`；参数语法错误由 argparse 报 stderr/2。输出不含快照全文。

## 真目标验收与交接

记录实际工具版本/命令/原始安全输出、输入哈希、候选与反证，返回原项目当前 version/run；辅域符号和偏移同时带构建哈希，旧构建成果单独保留。交付定位表、地址换算依据、启停/恢复办法、运行证据和未验证范围，复用现有项目机制，不建立新账本。

真实验收在同一构建上比较：未启用→启用后约定行为变化→停用恢复→再次启用→退出/重启基线；同时检查原功能、场景切换/对象重建、模块重载、错误构建拒绝和异常退出后的恢复。用独立画面/行为或读回对照，不能只依据工具返回成功。若服务端刷新覆盖客户端值，记录本地瞬态效果与服务端拒绝/覆盖证据；没有服务端接受证据不能宣称持久修改、服务端状态接管或完整 Trainer 已交付。

正例：合成快照中唯一 100→75 转换位于偏移 3，独立变化后继续命中；仅证明搜索行为。反例：多个镜像均变化应返回歧义；旧构建、长度变化、区域变化、哈希不符应拒绝比较；对象销毁后旧地址作废。自测覆盖整数/浮点、小/大端、未找到、多命中截断和这些拒绝条件，不代表真设备/引擎、启停恢复或真实任务已验收。同形失败两次重判路线；缺布局或当前构建证据时停止地址推导并列出缺件。
