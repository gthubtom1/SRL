---
id: "supply-chain/05-lockfile-integrity"
title: "锁文件完整性：integrity、resolved 与冻结安装"
title_en: "Lockfile Integrity: integrity, resolved, and Frozen Installs"
summary: >
  锁文件必须与清单同源、条目带 integrity、resolved 指向受控 registry，CI 用冻结安装；
  缺一项就不能宣称“可复现构建”。
board: "supply-chain"
category: "05-lockfile-integrity"
signals: ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "go.sum", "Cargo.lock", "integrity", "resolved", "npm ci"]
mcp_tools: ["sc-check.py", "sbom-reach.py"]
keywords: ["锁文件", "integrity", "resolved", "npm ci", "frozen-lockfile", "可复现构建"]
difficulty: "beginner"
tags: ["lockfile", "npm", "pypi", "go", "cargo", "supply-chain"]
language: "zh-CN"
last_updated: "2026-10-21"
related_articles: ["supply-chain/01-dependency-confusion", "supply-chain/03-sbom-and-reachability"]
---
# 锁文件完整性：integrity、resolved 与冻结安装

## 入口信号

- 仓库有 manifest 但没锁文件，CI 直接 `npm install`/`pip install -r`。
- 锁文件条目缺 `integrity`，或 `resolved` 指向 `http://`/不明镜像。
- manifest 改了依赖，锁文件没跟着变；monorepo 根锁与子包不一致。
- `git+http://`、`file:`、`*`/`latest` 出现在生产依赖。

## 可复制命令

```bash
# npm：缺 integrity 的条目
jq -r '.packages | to_entries[] | select(.value.integrity|not) | .key' package-lock.json | head
# resolved 的来源分布
jq -r '.packages | to_entries[] | select(.value.resolved) | .value.resolved' package-lock.json \
  | sed -E 's#(https?://[^/]+).*#\1#' | sort | uniq -c

# Python / Go / Rust
grep -cE '^(--hash|--require-hashes)' requirements.txt
go mod verify
cargo tree --locked >/dev/null && echo cargo-locked-ok

# 仓库级盘点
python Tool/scripts/sc-check.py --path . --out sc.json
```

## 判据（确认）

1. 每个应用生态至少一个锁文件，且与 manifest 同目录/同 workspace。
2. 锁文件条目的直接依赖集合 = manifest 声明集合（多/少都要解释）。
3. npm 条目有 `integrity`，`resolved` host 与 `.npmrc` registry 一致。
4. CI 使用 `npm ci`/`pnpm install --frozen-lockfile`/`pip install --require-hashes`/`go mod download`（只读）。
5. 锁文件 sha256 已记录，报告写具体值。

## 失败判据

| 现象 | 判定 | 改走哪条 | 代价 |
| :-- | :-- | :-- | :-- |
| 锁文件存在但 integrity 缺失过半 | 完整性链断裂 | 重生成锁文件；CI 改冻结安装 | 中 |
| manifest 与锁文件集合不一致 | 锁文件过期 | 以 manifest 为准重生成 | 低 |
| resolved host 与 registry 不一致 | 来源漂移 | 锁 registry 后重生成，核对 CI 环境变量 | 中 |
| 库项目无 Cargo.lock | 可接受（库不锁定） | 改为记录 CI 解析结果 | 低 |
| 只有锁文件没有 CI 冻结命令 | 构建仍可能漂移 | 改 CI 安装命令 | 中 |

## 边界

- 锁文件解析不等于 CVE 扫描；可达性见 `03-sbom-and-reachability.md`。
- 不在生产机直接重装验证；用 `--dry-run` 或隔离环境。
- 私有 registry 使用自签 CA 时，记录证书固定方式，不直接判“不安全”。
- 依赖混淆的 registry 映射对账见 `01-dependency-confusion.md`。
