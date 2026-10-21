# 输入说明（夹具）

手写教学夹具，用于验证 `sbom-reach.py` 的“锁文件/freeze/SBOM → 源码入口”对账：

- `package-lock.json`：npm 锁文件，含 `left-pad` 与未被引用的 `@corp/auth`。
- `freeze.txt`：`pip freeze` 形态，含 `PyYAML`（import 名为 `yaml`）与未引用的 `requests`。
- `bom.json`：CycloneDX 1.5，组件集合与 lock/freeze 一致（用于验证 `missing_from_sbom` 为空）。
- `src/app.py`：Python 入口，`import yaml`。
- `src/index.js`：JS 入口，`require('left-pad')`。
- `src/util.py`：无第三方 import 的对照文件。

复现命令（仓库根）：

```bash
python Tool/skill/supply-chain-security/scripts/sbom-reach.py \
  --sbom Tool/cases/supply-chain04/input/bom.json \
  --lock Tool/cases/supply-chain04/input/package-lock.json \
  --freeze Tool/cases/supply-chain04/input/freeze.txt \
  --source Tool/cases/supply-chain04/input/src \
  --out Tool/cases/supply-chain04/artifacts/reach.json
```

预期：`left-pad` 与 `PyYAML` 可达（`entry_hit=true`），`@corp/auth`/`requests` 不可达，
`missing_from_sbom=[]`。这是夹具，不代表真实仓库的依赖状态。
