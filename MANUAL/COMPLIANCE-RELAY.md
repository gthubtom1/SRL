# HTTP中继与输入保真

当前中继保持HTTP请求体和响应体的原始字节，不改写用户任务、路径、代码、附件、历史或provider参数。一次客户端请求只发送一次上游请求；拒答、错误、空输出和流式响应按原结果返回。

旧版全文换词、Gemini清单替换和拒答后换写法重试已删除。原先手册将另一个任务的回答称作原任务恢复，不符合当前需求；该说明不再作为操作依据。详细实现和CLI参数见 [中继README](../Tool/scripts/compliance-relay/README.md)。

## 1. 三个不同职责

| 层 | 当前职责 | 验证边界 |
|---|---|---|
| Pi输入扩展 | 普通输入原样继续；lab控制工作偏好；检索别名另行派生 | 附件、代码、URL、JSON和任务后缀完整 |
| 提示词/请求装配 | 沿用当前宿主边界锚，不改历史正文或provider的safetySettings | 退出lab不等于移除所有宿主规则 |
| HTTP中继 | 按原字节转发正文、转发一次并保留上游状态 | 代理逐跳头、Host、长度和分块按HTTP协议处理 |

别名来源为`Tool/config/input-normalize.json`的`from/route_terms`。它们用于独立检索，不拼入领域判断输入或工具参数，不能用检索词重写文件身份。HTTP中继不加载词表来处理正文。

## 2. 使用与配置

从仓库根运行自有工具：

```bash
python Tool/scripts/compliance-relay/relay.py
```

首次配置、回环地址格式、upstream映射、状态兼容参数与配置文件位置见中继README。中继不会自动修改宿主配置。连接所需的本机凭据由用户本人保管，不进入Agent输出、报告或源码；启动日志不展示访问令牌、请求正文或认证头。

`--force-on/--force-off`只表示工作状态，不开启改写。旧`refusalRetry`字段不再启用任何重试。`gemini-safe.flag`和`PI_SAFETY_PAYLOAD`不改变任务或provider请求设置。

## 3. 失败怎样判断

分别检查传输是否完成、HTTP状态、协议错误字段、流是否完整、文本是否为空、以及模型是否明确表达无法执行。空choices、输出token数量或回答长度不能独立证明发生了哪一层过滤，更不能证明分析任务成功。

上游结果不满足任务时记录实际失败和仍缺条件。不得把“分析该文件”变成“列一个通用清单”后宣称已恢复，也不得把重复请求当作无副作用；请求是否可能已经到达上游应保留未知。通道诊断见 [模型响应诊断](MODEL-REFUSAL-MATRIX.md)。

## 4. 回归入口

```bash
python Tool/scripts/rewrite-route-parity.py --json
python -m unittest discover -s Tool/scripts/compliance-relay/tests -v
python Tool/scripts/test_prompt_extensions.py
python Tool/scripts/check.py --runtime --json
```

组合入口运行实际input钩子、回环HTTP中继及当前路由，检查原文、附件和完整主辅域集合。负例包含路径被改名和仅辅域漂移；两者都必须失败。中继专项检查一次转发、错误和流式响应保留、坏路由/访问令牌拒绝、损坏配置与资源关闭。

这些本机合成测试不证明远端模型接受了任务，也不证明真实宿主已重载。文件部署、配置、握手、新会话加载和任务验收分别记录在当前状态和验证回执中。
