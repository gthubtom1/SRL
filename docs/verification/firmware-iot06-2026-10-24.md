# firmware-iot06 · verification receipt（2026-10-24）

## 1. 观测到的问题与更正
该案例为本轮为真实目标新建，此前无事实账（baseline = 空账）

## 2. 真实输入与范围
`Tool/cases/firmware-iot06`（`case.json` 里登记 target 与 evidence_kind）。源文件快照：
- `facts.jsonl` = `47ec21651b2c72f0bc81fbf4fa9f96133217f49eadb1de88f3c7d8d23551236e`
- `artifacts/MANIFEST.sha256` = `f36b1b0c14f3bf7ffabcfcd3b20e00c86e98b57d6c3ee40b4e34f40b3e30e5cc`

## 3. 复现命令
```bash
python Tool/scripts/case_state.py verify --case Tool/cases/firmware-iot06
```

## 4. 成本与边界
- baseline：claim 0 / proven 0 / **背书 0** / verdict `unknown`
- final：claim 7 / proven 7 / **背书 7** / verdict `pass`
- 建立案件 → 逐条实测登记为 observed，背书从 0 起算
- 未验证：仅覆盖本文件列出的结论；未验证部分见 case.json 的 limitations

## 5. 回归记录
本次改动后 `preflight --fast` 43/43、`gate.py --all` 9/9 仍全绿；
判据本身未放宽（`unknown` 依旧不计 pass）。
