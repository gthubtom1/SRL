---
name: multiver-aob
description: "跨版本特征候选、原/补丁双态唯一性与语义复核；区分唯一、缺失、歧义和需人工处理。"
metadata:
  version: "1.1.0"
  target_runtimes: "当前脚本为文件字节候选；PE 地址映射与其他格式另核"
---

# 跨版本 AOB 与补丁迁移

输入是旧/新版本原件及哈希、旧位点的语义/原字节/改后字节、同模块/架构证据。主域仍是 softseep；Android DEX/SO 可由 apkseep 协作，但脚本不自动理解其指令/签名/重包规则。项目账、接续与当前版本绑定见 [router](../../../seep-router/SKILL.md)，迁移配方见 `Tool/playbooks/version-migrate.md`，不调用旧裸阶段名。

深度资料优先 [AOB 与签名](../exe-reverse/references/aob-and-signatures.md)、[版本差分](../exe-reverse/references/pe-diff-and-versions.md)、[补丁工程](../../references/09-patch-engineering.md)；复杂函数匹配读 [binary-diff](../binary-diff/SKILL.md)。

## 当前工具入口

先核连接与实际 schema。Seep MCP 参数形态是：

```text
seep_packer_detect(binary_path="<新版原件绝对路径>")
seep_r2_cmd(binary_path="<新版原件绝对路径>", command="iR", analyze=false)
seep_r2_decompile(binary_path="<新版原件绝对路径>", target="<已核函数地址>")
```

没有 `cmd=` 参数。资源枚举不能证明内嵌载荷已导出；伪代码不直接证明补丁语义。缺 MCP 时使用已核可用的 radare2 CLI 或其他现有 headless 通道，不把工具名当宿主技能。

域版本账引擎为 `Tool/skill/softseep/scripts/version-migrate.py`，子命令/字段先 `--help`。本目录还提供 [流水线脚本](scripts/09_multiversion_extend.py) 与 [旧案例配置](scripts/config_6v.example.json)。该脚本只有配置文件位置参数，**没有 argparse 的 `--help`**：不传参数会输出模块用法并退出 2；传 `--help` 会把它当文件名。不要把失败包装成支持帮助。

将配置放在当前项目工作目录，核内容后再运行（脚本只读输入文件并生成表，不运行目标，也不产出 DLL/APK）：

```bash
python Tool/skill/softseep/subskills/multiver-aob/scripts/09_multiversion_extend.py work/migration/config.json
```

`samples_dir` 相对于配置文件目录解析。versions 各有唯一 tag 与 file；points 指定 id/name、各版本的**文件偏移** offsets、expected/patch 十六进制和 optional，未知偏移为 null。至少有一个已验证锚点；所有版本都缺失的 optional 点当前可能触发异常，不能当已支持跳过。旧案例配置依赖仓外样本，不能直接当当前项目输入。

脚本输出到配置所在目录的 `final_table_multiver.json` 和 `aob_table_multiver.cs`，会覆盖同名文件，应使用独立 run 目录。缺失必需点退出 1，双态唯一性失败退出 2，0 仅表示其内部检查通过。模糊定位路径需要 numpy；脚本无稳定结构化错误契约，保留 stderr。

## 候选与证据门槛

脚本用汉明距离、锚点及期望字节搜索产生候选，再比较共同稳定区；其输出特征是连续十六进制字节，不能当支持任意 `??` 的通配引擎。通配重定位/分支操作数的设计属于另一条签名方法，要由相应扫描工具验证。

预先检查 offset 不越界、expected/patch 非空且等长、位点不重叠、原件当前字节与 expected 一致。当前脚本在原字节不符时会打印告警，不能指望返回码一定因此失败；未验证的已知 offset 也可能污染双态构造。看到告警必须拒收，即使最后 rc=0。

双态 1/1 只证明这些文件中原始/改后模式分别唯一，不证明候选函数语义相同。脚本的汉明最优候选不完整保留并列候选，因此还需独立扫描全部候选、核指令边界/调用点/控制流。唯一期望字节、相近地址、相同字符串都不足以单独确认。

## 正反例与追版结果

- 唯一：模式唯一且原字节、函数语义、地址映射与独立证据一致，才进入副本补丁验证。
- 缺失：可能删除、内联、保护变化或构建不同，记录未找到，不盲用旧 RVA。
- 歧义：重复模式/同距离候选需人工语义消歧，不能取第一个。
- 需人工：未知保护、架构/运行时变化或原字节不符，转重分析，不扩大窗口硬凑匹配。

正例：新版位移不均匀，候选经指令/调用链确认，副本字节回读、回滚及目标功能回归均成立。反例：全文件仅一次短 AOB 却落在资源数据中，或 rc=0 同时有原字节告警，均拒绝迁移结论。重编译可能改变整个拓扑，不承诺共同稳定区始终存在。

交付差异表、候选/反证、工具诊断、原件/产物身份及验证结果。修改成品还需实际启动与约定功能/邻接功能回归，表文件生成或编译成功不证明可用。同形失败两次换语义/差分路线；辅域输出和新证据归当前 project/version/run，旧报告保留旧身份，不混作当前完成见证。
