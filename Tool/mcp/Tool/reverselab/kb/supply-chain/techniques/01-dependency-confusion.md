---
id: "supply-chain/01-dependency-confusion"
title: "依赖混淆：scope、registry 与锁文件三方对账"
title_en: "Dependency Confusion: Reconciling Scope, Registry, and Lockfile"
summary: >
  用清单中的私有 scope/内部包名、包管理器的 registry/index 配置、锁文件 resolved/integrity 三方对账，判断同名公共包是否可能被解析；只读、不发布、不抢注。
summary_en: >
  Reconcile private scopes/internal names in manifests, the package manager registry/index configuration, and lockfile resolved/integrity entries to decide whether a same-name public package could be resolved. Read-only: never publish or squat.
board: "supply-chain"
category: "01-dependency-confusion"
signals: ["@corp/", "internal-", "corp-", ".npmrc", "pip.conf", "nuget.config", "resolved", "integrity"]
mcp_tools: ["sc-check.py", "npm config get", "pip config list", "git"]
keywords: ["依赖混淆", "dependency confusion", "scope", "registry", "锁文件", "抢注"]
difficulty: "intermediate"
tags: ["npm", "pip", "nuget", "registry", "lockfile", "dependency-confusion"]
language: "zh-CN"
last_updated: "2026-10-21"
related_articles: ["supply-chain/02-image-and-provenance"]
---
# 依赖混淆：scope、registry 与锁文件三方对账

## 场景
仓库使用私有包名（如 `@corp/auth`、`internal-billing`），但解析器可能回退到公共 registry。目标是判断“下一次安装会不会装到公共同名包”，并给最小修复。

## 输入信号
- `package.json` 出现 `@corp/*`，但没有 `.npmrc` 的 `@corp:registry=`。
- `requirements.txt` 出现 `internal-*`/`corp-*`，但没有 `--index-url`。
- `nuget.config` 同时列 nuget.org 与私有 feed，且无 `packageSourceMapping`。
- 锁文件缺失、`resolved` 指向公共源、或条目缺 `integrity`。
- CI 使用 `npm install` 而不是 `npm ci`。

## 步骤 1：离线盘点
```bash
python Tool/scripts/sc-check.py --path . --out sc.json
python - <<'PY'
import json
d=json.load(open('sc.json'))
for r in d['risks']:
    if r['category'] in ('dependency-confusion','lockfile','lock-integrity'):
        print(r['level'], r['category'], r['file'], '|', r['evidence'])
PY
```

## 步骤 2：npm 三方对账
```bash
cat .npmrc 2>/dev/null
npm config get registry
npm config get @corp:registry

python - <<'PY'
import json
lock=json.load(open('package-lock.json'))
for k,v in (lock.get('packages') or {}).items():
    if k.startswith('node_modules/@corp/'):
        print(k, 'resolved=', v.get('resolved'), 'integrity=', bool(v.get('integrity')))
PY
```

判据：私有 scope 有显式 registry 映射 + 锁文件 `resolved` 指向受控源 + `integrity` 存在，三者同时满足才算安全。

## 步骤 3：Python / NuGet / Maven
```bash
pip config list
cat /etc/pip.conf ~/.config/pip/pip.conf ~/.pip/pip.conf 2>/dev/null
grep -RInE '^(corp|internal|company|private)[-_]' requirements*.txt pyproject.toml 2>/dev/null

dotnet nuget list source
grep -nE 'packageSources|packageSourceMapping|nuget.org' nuget.config 2>/dev/null
mvn help:effective-settings 2>/dev/null | grep -A3 '<mirror>'
```

- pip：`--extra-index-url` 同时列公共源会合并候选，公共包可能因版本更高被选中。
- NuGet：没有 source mapping 时，私有包名可能回退到 nuget.org。
- Maven：私有 groupId 未镜像/锁定，或生产使用 SNAPSHOT。

## 步骤 4：只读确认同名公共包（需授权联网）
```bash
# 只看是否存在，不下载、不发布
npm view @corp/pkg name version 2>/dev/null
curl -sS -o /dev/null -w '%{http_code}\n' https://registry.npmjs.org/@corp%2fpkg
python -m pip index versions internal-billing 2>/dev/null | head
```

判据：公共源返回 200 且包不属于本公司，同时本仓库没有私有 registry 映射 → 可解析到攻击者包。
失败判据：只看到包名、只看到公共源 200、只看到宽版本，三者任一单独都不够。

## 确认判据
- 清单/锁文件/registry 配置三方证据齐全。
- 能说明解析顺序：哪个 scope、哪个 index、哪个版本被选中。
- 最好在隔离环境用 `npm ci`/`pip download --no-deps` 验证解析来源（需授权）。
- 报告写清“已存在同名包”还是“名字未注册、未来可被抢注”，两者风险等级不同。

## 失败判据
- 只看到私有风格包名，没有检查 registry 配置与实际解析。
- 只看到公共同名包存在，没有证明构建会解析到它。
- 把“未注册”写成“已被抢注”；把“宽版本”写成“已投毒”。
- 为验证而发布测试包、抢占名字、修改生产 registry。
- 探测越出授权仓库或 registry 账户。

## 修复清单
```text
npm:     @corp:registry=https://npm.corp.example/ + 提交锁文件 + npm ci
pip:     index-url=https://pypi.corp.example/simple + 禁用公共 extra-index + --require-hashes
NuGet:   packageSourceMapping 把 Company.* 只映射到私有 feed
Maven:   settings.xml 镜像到内部 Nexus/Artifactory + 禁止生产 SNAPSHOT
Go:      GOPRIVATE=corp.example.com/* + 内部 GOPROXY + go.sum
```

## 边界
- 不做抢注、不发布包、不向公共源上传任何内容。
- 不查询与授权范围无关的私有包名；不枚举公司内部 namespace。
- CVE 可达性、CI 权限、镜像签名分别见同 board 其他文档。
