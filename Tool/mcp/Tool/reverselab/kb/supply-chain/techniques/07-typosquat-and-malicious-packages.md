---
id: "supply-chain/07-typosquat-and-malicious-packages"
title: "抢注/仿冒与恶意包：名字相似度、安装脚本与外联"
title_en: "Typosquatting and Malicious Packages: Name Similarity, Install Scripts, and Egress"
summary: >
  在授权范围内识别仿冒包名、安装期下载/执行、外联与凭据读取信号；
  用包名相似度 + 锁文件来源 + 脚本行为三组证据判断，不凭名字像就下结论。
board: "supply-chain"
category: "07-typosquat-and-malicious-packages"
signals: ["typosquat", "homoglyph", "postinstall", "curl|sh", "base64", "process.env", "registry", "npm view"]
mcp_tools: ["sc-check.py", "sbom-reach.py", "npm view", "pip index"]
keywords: ["抢注", "仿冒包", "typosquat", "恶意 npm 包", "安装脚本", "外联"]
difficulty: "advanced"
tags: ["npm", "pypi", "typosquat", "malicious-package", "install-scripts"]
language: "zh-CN"
last_updated: "2026-10-21"
related_articles: ["supply-chain/01-dependency-confusion", "supply-chain/05-lockfile-integrity"]
---
# 抢注/仿冒与恶意包：名字相似度、安装脚本与外联

## 入口信号

- 包名与知名包只差一个字符/连字符/复数（`lodahs`、`reqeusts`、`python-dateutil` vs `python-dateutils`）。
- 安装脚本含 `curl|sh`、`wget`、`powershell -enc`、`base64 -d | sh`、`child_process.exec`。
- `postinstall` 读取 `process.env`（CI token、npm token）并发网络请求。
- 锁文件 `resolved` 指向个人仓库/临时域名，而不是官方 registry。

## 可复制命令

```bash
# 1) 名字相似度（离线，只看清单）
python - <<'PY'
import json, difflib
known = ["lodash","requests","express","react","pyyaml","python-dateutil","axios"]
names = list((json.load(open("package.json")).get("dependencies") or {}))
for n in names:
    for k in known:
        r = difflib.SequenceMatcher(None, n.lower(), k.lower()).ratio()
        if 0.75 <= r < 1.0:
            print("similar", n, "~", k, round(r, 3))
PY

# 2) 安装脚本执行面
jq -r '.scripts // {} | to_entries[] | "\(.key): \(.value)"' package.json
grep -RInE 'curl|wget|base64|eval|child_process|execSync|process\.env' \
  package.json scripts 2>/dev/null | head -30

# 3) 来源核对（需授权联网；离线只读锁文件）
jq -r '.packages | to_entries[] | select(.value.resolved) |
       [.key, .value.resolved] | @tsv' package-lock.json | head -20
python Tool/skill/supply-chain-security/scripts/sbom-reach.py \
  --lock package-lock.json --source . --out reach.json
```

## 判据（确认）

1. 名字相似度 ≥0.75 且该包不在团队白名单/不是已知官方包。
2. 锁文件 `resolved` 来源与官方 registry 不一致，或包主页/仓库缺失。
3. 安装脚本有下载并执行、混淆解码、读取 CI 凭据的行为。
4. 该包在源码中确实被 import/require（`reach.json` 有命中）。
5. 至少一条行为证据（脚本原文、下载 URL、外联域名），不是只有名字像。

## 失败判据

- 只凭名字相似：可能是正常缩写/内部包，写“疑似仿冒”并列出对照。
- 安装脚本下载二进制但 URL 是官方 CDN 且有 hash：正常原生包，不列恶意。
- 包未被任何源码引用且不在生产依赖：优先级下调，但仍记录来源。
- 未授权联网时不要调 `npm view`/`pip index`；只读锁文件并标注“未验证公共解析”。
- 发现凭据外联时，不在报告里贴明文 token；只留指纹并走轮换流程。

## 处置顺序

1. 固定证据：包名/版本/`resolved`/脚本原文/命中行号。
2. 隔离：从锁文件移除或 pin 到安全版本，`--ignore-scripts` 临时阻断。
3. 轮换：若脚本读过 env/token，按凭据事件处理，先撤销再排查。
4. 复核：重生成锁文件与 SBOM，确认来源与完整性。
5. 上报：给维护者最小 diff 与验证命令，不公开未修复细节。

## 边界

- 不发布仿冒包做实验、不抢注名字、不向公共 registry 上传样本。
- 不做恶意包武器化；只做识别、隔离、证据固定。
- 许可证/法务结论不在本文；CVE 可达性见 `03-sbom-and-reachability.md`。
- 真实恶意样本分析 → `malware-analysis`；本 board 只处理依赖与构建链。
