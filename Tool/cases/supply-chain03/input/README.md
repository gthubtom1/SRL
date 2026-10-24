# 输入说明（真实 workflow，不是夹具）

目标文件：仓库内真实存在的 `.github/workflows/upstream-sync.yml`。
本案例不复制该文件，直接以仓库当前版本为输入；对象哈希记录在
`../artifacts/target.json` 的 `workflow_sha256`，复跑前先用 `sha256sum` 核对。

复现命令（在仓库根执行）：

```bash
sha256sum .github/workflows/upstream-sync.yml
git rev-parse HEAD
python Tool/skill/supply-chain-security/scripts/ci-perm-audit.py \
  --path .github/workflows --out Tool/cases/supply-chain03/artifacts/ci.json
python Tool/skill/supply-chain-security/scripts/sc-check.py \
  --path .github/workflows --out Tool/cases/supply-chain03/artifacts/sc.json
```

该文件真实内容含 `schedule` + `workflow_dispatch` 触发、顶层
`permissions: contents: write / pull-requests: write`、`actions/checkout@v4`
与 `actions/setup-python@v5`（tag 引用）、`secrets.GITHUB_TOKEN`。
