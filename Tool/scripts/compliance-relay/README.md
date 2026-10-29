# compliance-relay：原文透传中继

P0-1 的当前契约：HTTP 中继保持请求体和响应体的原始字节，不替换用户材料，不更改 provider 参数，不在拒答后生成另一项任务。上游状态码、错误、空输出和拒答原样返回；一次客户端请求只发出一次上游请求。HTTP 逐跳头、Host、Content-Length 和传输分块按代理协议处理。

输入扩展 `Tool/prompts/extensions/security-audit-interceptor.ts` 的职责：

- 普通输入（含空白、路径、URL、代码、JSON、附件、RPC/API 和扩展来源）原样继续；旧操作短语也直接交给模型理解。
- `lab：` / `退出实验` 控制已有 `lab-mode.flag`，失败时报告真实状态；带任务的进入命令完整保留冒号后的内容和附件。状态文件仍为跨会话工作偏好，不声明目标授权。
- 开启 lab 时，从现有 `Tool/config/input-normalize.json` 的 `from/route_terms` 派生独立的 `seep:route-terms` 扩展事件（`purpose=retrieval-only`）。导出函数 `deriveRouteTerms(text)` 供独立检索使用。不得将别名拼入领域判定输入、任务正文、工具参数或材料。
- 请求层只保留既有 system 边界锚；它在退出 lab 后仍有效。历史上下文不清洗，provider safetySettings 不添加、不覆盖。`gemini-safe.flag`、`PI_SAFETY_PAYLOAD` 不再改变任务或 provider 配置。

词表 schema 为 `seep.input-normalize/2`，旧 `to` 字段已删除。缺失或损坏时明确 WARN 并停用派生别名，输入继续原样透传。没有另一份内嵌改写表。

relay 的 `--force-on` / `--force-off` 只保留工作状态兼容语义，任何状态下都不启用改写。旧配置中的 `refusalRetry` / `refusalRetryAttempts` 不会启用重试，读取本机中继配置时移除这两个淘汰字段。`refusal.py` 仅保留可独立使用的响应诊断；空结果本身不能证明服务端安全拒绝，relay 不依据诊断重试或改变结果。

从仓库根运行：

```bash
python Tool/scripts/compliance-relay/relay.py
```

本机配置 `relay-config.json` 保持既有结构：`port`、本机访问 `token`、`upstreams`。首次运行生成配置；令牌只保存在本机配置，启动输出不展示它。地址格式仍为：

```text
http://127.0.0.1:<port>/r/<token>/<upstream-key>/<原始路径>
```

显式 `--scan-pi` 仍可从 Pi 的模型配置读取 endpoint 生成映射。本次测试不执行此命令、不读取真实模型配置或凭据。中继不自动修改宿主配置。`--lab-flag` 指定工作状态文件；默认与输入扩展共同遵循 `PI_CODING_AGENT_DIR`，未设置时使用 `~/.pi/agent`。

`sensitive-rules.json` 是由现有 normalizer 生成的独立检索数据（仅 `from/route_terms`），保留历史文件名便于维护；HTTP relay 不加载它。生成与一致性检查：

```bash
python Tool/scripts/compliance-relay/extract-rules.py
python Tool/scripts/compliance-relay/extract-rules.py --check
```

旧 `guard-prefixes.json` 已删除；当前所有正文都受原样透传契约保护，不依赖前缀白名单。

提供给主流程接入 `check.py` 的入口：

```bash
python Tool/scripts/rewrite-route-parity.py --json
python -m unittest discover -s Tool/scripts/compliance-relay/tests -v
python Tool/scripts/test_prompt_extensions.py
```

第一条实际执行源码 input hook → 本机回环 HTTP relay → 当前 `route.resolve()`。覆盖现有路由探针、全部别名原词及 P0-1 复现文本，在 lab 开关、旧 safe 标志、interactive/RPC/extension 来源下检查主域和全部辅域集合、原始文本、事件、附件及三个协议的完整请求字节。Node 必须支持 TypeScript stripping；缺失不能报告通过。

专项测试还验证：开关及新进程重载、带缩进/CRLF 的控制命令任务后缀、损坏/缺失别名表、历史拒答文本保留、provider 字段不受 `PI_SAFETY_PAYLOAD=all` 影响、上游拒答/错误/流式结果单次透传、错误令牌/路由/上游、配置淘汰字段、日志不含材料、以及路径被故意改名时门禁失败。监听端口均为临时回环端口；使用合成数据，不运行客户样本。

旧测试预期修正的语义依据：全文替换、只改 user 文本和“改为许可清单后重试成功”均会改变用户任务，违反 P0-1。现在断言保真及一次调用；检索别名不再拼入 route 输入，也不再容许辅域变化只记 INFO。负例继续判失败。原有 lab 标志权限/写入/删除/临时文件清理负例留在 `test_prompt_extensions.py`。

本目录旧版手册之外的全局说明可能仍描述已删除的改写/重试能力，由主流程在其文档写集中统一修正。本专项没有验证真实宿主重载、远端模型、认证、客户任务或完整 runtime 门禁；本机专项通过不代表这些步骤已完成。
