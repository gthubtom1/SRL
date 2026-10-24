# supply-chain05 · verification receipt（2026-10-24）

## 1. 观测到的问题与更正
该案例为本轮为真实目标新建，此前无事实账（baseline = 空账）

## 2. 真实输入与范围
`Tool/cases/supply-chain05`（`case.json` 里登记 target 与 evidence_kind）。源文件快照：
- `facts.jsonl` = `6f7684f4fbddc80fe2d7fb4681616ca3c9ddb7b1ae69884c4d1c30caec505913`
- `artifacts/MANIFEST.sha256` = `67ac56aabb22721bf36d34a77f1ff943d1788f43da2ab9d6cec18f5b0c3b39a5`

## 3. 复现命令
```bash
python Tool/scripts/case_state.py verify --case Tool/cases/supply-chain05
```

## 4. 成本与边界
- baseline：claim 0 / proven 0 / **背书 0** / verdict `unknown`
- final：claim 8 / proven 8 / **背书 8** / verdict `pass`
- 建立案件 → 逐条实测登记为 observed，背书从 0 起算
- 未验证：仅覆盖本文件列出的结论；未验证部分见 case.json 的 limitations

## 5. 回归记录
本次改动后 `preflight --fast` 43/43、`gate.py --all` 9/9 仍全绿；
判据本身未放宽（`unknown` 依旧不计 pass）。
