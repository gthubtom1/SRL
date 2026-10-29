---
name: db-decrypt
description: "SQLite/SQLCipher/WCDB 版本与一致性核对、用户侧解密结果验证和损坏边界；真实 Key/Salt 不进入 Agent。"
metadata:
  version: "2.1.0"
  target_runtimes: "Android / iOS 数据库副本；SQLCipher/WCDB 构建参数须匹配"
---

# 加密数据库条件与结果验证

本技能不采集真实密钥、Salt、口令、私钥或会话。用户在自己的受控工具中完成真实凭据输入与解密，只把不含秘密的结构统计、完整性结果或合成数据交给 Agent。不得用 Frida 打印 key 指针、hexdump、PRAGMA 明文命令、shell 参数/历史或环境转储收取秘密；读取后散列也不符合边界。

复用 [证据链](../../references/evidence-chain.md)、[数据库与制品](../../references/ios-macos-artifacts.md)、[磁盘/SQLite 一致性](../../references/disk-and-filesystem.md)。算法调用关系由 apkseep/softseep 辅助分析，真实凭据仍留在用户侧，结果返回同一 project/version/run。

## 先核格式与构建

输入包含数据库来源、App/数据库库版本、主库及 WAL/SHM 的同时间点获取说明、目标问题与安全采集范围。只读封存原件，在副本中处理。没有 `SQLite format 3` 头不直接证明加密，也可能压缩、截断、自定义容器；有明文头也可能启用 plaintext header 的 SQLCipher。

SQLCipher 各代的 page size、KDF 算法/迭代、HMAC、兼容模式、plaintext-header 与 raw-key 语义不同；WCDB 是否启用加密及后端版本由具体构建决定。不能默认 4096 页或将某个旧 App 的 IMEI+Uin 派生公式当通用规则。派生函数的存在也不证明当前文件使用它。

用户侧核对实际 provider 的 `PRAGMA cipher_version` 与帮助、版本说明，在读数据前设置该构建要求的兼容参数；`PRAGMA key` 等真实值不写入 Agent 命令、日志或报告。缺版本/参数时列候选，不盲试大量密码。需要黑盒验证可让用户返回“配置 A/B 是否打开、完整性是否通过、非敏感 schema 摘要”，不索取密码。

## 导出与一致性

用户侧确认密钥和配置后，可按其 SQLCipher 版本的 `sqlcipher_export` 流程导出到新库；导出不一定自动保留 user_version、应用自定义元数据与全部行为，需逐项核。输出可能含用户秘密，不能因为“解密了”就整库交给 Agent；优先合成夹具或用户侧安全摘要。

WAL 可能含已提交但未 checkpoint 的事务，不能笼统称“未提交日志”。主库/WAL/SHM 必须来自一致采集点；只复制活跃主库、随便合并或遗漏 WAL 都可能损失记录。不要让标准 SQLite 对加密原件自动 checkpoint；复制后由匹配引擎在用户侧处理，保留操作前后身份。`immutable=1` 不用于未经核实的活跃 WAL 数据库一致性推断。

## 结构验证与损坏恢复

对用户提供且确认安全的明文/合成副本，标准 SQLite 可做只读结构检查：

```bash
sqlite3 -readonly work/safe-export.sqlite "PRAGMA quick_check;"
sqlite3 -readonly work/safe-export.sqlite "PRAGMA integrity_check;"
```

先核 sqlite3 版本和参数；这些检查不证明所有业务记录完整或解密参数唯一。结合页数、schema、索引、业务表计数、事务/时间窗与用户侧预期对照；仅查 sqlite_master 的 count 能成功不足以验收。

损坏/删除记录另立恢复假设：页覆盖、freelist 重用、VACUUM、secure_delete、加密和 WAL 留存会限制恢复。`strings` 命中碎片不能证明完整记录或归属；必须有页号/offset、结构与上下文支持，无法恢复就明示。

## 正反例与交付

正例：已知合成 SQLCipher 夹具在匹配参数下导出，完整性检查、schema 与已知记录一致；错兼容模式受阻且不会覆盖原库。反例：只打开主库但缺 WAL 中已提交数据，或 quick_check 通过却缺预期表，不能称完整恢复。

交付 provider/版本、非秘密配置类别、采集一致性、检查结果、覆盖/缺失与未知；不附 Key、Salt、个人数据或“可用凭据”。若只有用户侧观察，明确谁执行、何时及证据限制。同形失败两次回格式/版本判断，不强迫破解或要求每案恢复删除记录。
