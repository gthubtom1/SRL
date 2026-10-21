# PE Reverse — 逆向域知识入口（10 篇）

> 域契约：KB 6–10 篇。这里放**作战入口**；历史沉淀在 `../_archive/pe-reverse/`（不删内容、不计入域数量）。
> 配套技能：`Tool/skill/softseep/SKILL.md`。

## 作战入口

- [01-pe-header-parsing.md](techniques/02-pe-structure/01-pe-header-parsing.md)
- [02-tls-callback-analysis.md](techniques/02-pe-structure/02-tls-callback-analysis.md)
- [01-struct-reconstruction.md](techniques/03-static-analysis/01-struct-reconstruction.md)
- [05-anti-debug-bypass.md](techniques/04-dynamic-analysis/05-anti-debug-bypass.md)
- [01-pe-unpack-dump.md](techniques/05-crypto-unpack/01-pe-unpack-dump.md)
- [01-code-patching.md](techniques/08-patch/01-code-patching.md)
- [02-validation-function-location.md](techniques/10-license-keygen/02-validation-function-location.md)
- [failure-criteria.md](techniques/15-decision/failure-criteria.md)
- [attack-network.md](techniques/attack-network.md)

## 归档

- [PE Reverse 归档库（历史技术与范式库）](../_archive/pe-reverse/README.md)

## 分析链

```text
样本哈希/类型/保护 → 结构解析 → 静态重建 → 动态验证 → 脱壳/配置 → IOC
→ 补丁（等长/重定位/回滚）→ 报告
```

