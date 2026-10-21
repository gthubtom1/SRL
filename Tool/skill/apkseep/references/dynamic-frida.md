# Dynamic analysis with Frida — 拆分目录（2 篇，内容无损）

> 本篇范围：原 502 行 Frida 文档的入口页；正文拆成 2 篇，保留全部探测模板与反插桩内容。
> 前后篇：本页是目录；从 [dynamic-frida-1-setup-and-probe.md](dynamic-frida-1-setup-and-probe.md) 开始。

原文件按 `##` 小节拆分，小节标题与内容未摘要化。

| 子篇 | 覆盖小节 | 行数 |
|---|---|---|
| [dynamic-frida-1-setup-and-probe.md](dynamic-frida-1-setup-and-probe.md) | 版本对齐、Frida 17+ 陷阱、hook 策略、四层探测模板 | 384 |
| [dynamic-frida-2-failures-and-anti-instrumentation.md](dynamic-frida-2-failures-and-anti-instrumentation.md) | hook 不触发排查、`Java.choose` 死实例、混淆代码读取、反插桩、证据捕获 | 126 |
