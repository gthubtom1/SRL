# 当前领域契约

本页说明现有领域检查的消费规则，不是扩功能计划。产品范围见 [REQUIREMENTS.md](../REQUIREMENTS.md)，状态见 [CURRENT-STATE.md](CURRENT-STATE.md)。

## 数据来源

正式域身份及逐域深度要求来自 `Tool/skill/<id>/pack.json` 的 `id` 与 `depth_contract`，公共阈值来自 `Tool/scripts/lib/domain_spec.py`，注册校验来自 `Tool/scripts/lib/domain_registry.py`。修改当前契约必须同步说明与消费者，不能依据本文给缺失能力自动造待办。

当前正式域：`softseep`、`apkseep`、`web-pentest`、`firmware-iot`、`protocol-plugin`、`pwn-crypto`、`forensics-mobile`、`malware-analysis`、`supply-chain-security`。`seep-router`、`unpack-loop` 是跨域技能，旧域名和 pending 项不因库存存在成为正式域。

## 现有深度与证据检查

| 对象 | 现有规则与来源 |
|---|---|
| 技能正文 | 公共上限 600 行，下限 120；实际按 LIMITS 求值 |
| references | 公共单篇 60–400 行，篇数 6–10；criteria、failure、pitfalls、walkthrough 为必备职责 |
| 知识库 | 公共单篇 50–200 行；逐域 `kb_line_max` 可声明允许的特定范围，按 pack 校验；失败判据与索引可达 |
| 脚本 | 既有脚本 `--help` / `--self-test` 实际运行；结构声明不替代成功退出和明确结果 |
| 案例 | 公共下限及逐域上限取 LIMITS/pack；资产、来源、证据类别、哈希、引用和命令需自洽；真实/公开见证不得被夹具冒充 |
| 领域任务配方 | `Tool/prompts/domains/` 每域现有 20–30 张六段配方，供 Agent 阅读；它们不是用户斜杠快捷指令，不生成或部署成 prompt 命令 |
| 路由与链接 | 测试用户说法及跨域边界，必需引用必须存在；正式路由来自 pack |
| 部署 | 当前技能源与部署文件核对；注册、部署、宿主加载分开验证 |

这些数字描述当前检查，并非新增数量目标。其他限制、例外和证据字段以机读来源为准；本次文档清理不改变它们。

## 检查方式

```text
python Tool/scripts/domain-gate.py --spec
python Tool/scripts/domain-gate.py --all
python Tool/scripts/gate.py --all
```

正例能通过，删必需契约/错域/篡改关键门槛仍必须失败。检查结果只证明所执行范围；专项成功不等于整个产品或所有目标均已验收。
