# CTF Website 渗透测试知识库 — Web 攻击全表面 118 篇

Web CTF / 网站攻防技术库，共 **26 类、118 篇正文**。

## 入口

- [完整技术索引](techniques/README.md)
- [Web 攻击网](techniques/attack-network.md)
- [前 30 分钟 Checklist](checklists/web-ctf-first-30-min.md)
- [支付攻击技术目录](techniques/12-payment/README.md)

## 流程

```text
Recon → Fingerprint → kb_router → 多路径攻击脚本 → 服务端副作用/Flag 验证 → 证据落盘
```

```powershell
python scripts/ctf-website/kb_router.py "<发现的信号>"
python scripts/misc/kb_doc_audit.py
```

技术文档要求可运行示例、工作流、证据闭环和 MCP 工具映射。

写作口径统一为：入口信号、打点脚本、路径分叉、下一跳、成功标志和 Evidence。每篇文章都要能被 Agent 直接拿来执行一轮路径推进。

## 索引补充

- [Web payload 种子库](payloads/web-payload-seeds.md)
- [24h 循环编排（00-workflow）](techniques/00-workflow/24h-loop-orchestration.md)

## 子目录索引

- [checklists/README.md](checklists/README.md)
- [payloads/README.md](payloads/README.md)
- [techniques/02-auth/jwt/README.md](techniques/02-auth/jwt/README.md)
- [techniques/09-cve/README.md](techniques/09-cve/README.md)
- [techniques/11-dos/README.md](techniques/11-dos/README.md)
- [techniques/13-signature/README.md](techniques/13-signature/README.md)
- [techniques/24-database/README.md](techniques/24-database/README.md)
