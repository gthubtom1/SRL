# golden-crackme · verification receipt（2026-10-24）

## 1. 观测到的问题与更正
13 条 proven 全部没有 confidence/authority → 整案 unknown，不能作为交付依据

## 2. 真实输入与范围
`Tool/cases/golden-crackme`（`case.json` 里登记 target 与 evidence_kind）。源文件快照：
- `facts.jsonl` = `7fd04877ae348bb786691168e338944394f04a5097db108c27be0fcde6e1c942`
- `artifacts/MANIFEST.sha256` = `5ed4dfb155f731053571a5a8fbce0cb69ac464d826a8586d4a64196379365a22`

## 3. 复现命令
```bash
python Tool/scripts/case_state.py verify --case Tool/cases/golden-crackme
```

## 4. 成本与边界
- baseline：claim 13 / proven 13 / **背书 0** / verdict `unknown`
- final：claim 14 / proven 13 / **背书 13** / verdict `pass`
- 逐条重跑 r2/tool-acquire 后显式声明 observed+shipped-artifact，背书从 0 → 13；顺带 refute 了一条错版本号
- 未验证：未运行目标（宿主机启动纪律），行为层结论仍 inferred

## 5. 回归记录
本次改动后 `preflight --fast` 43/43、`gate.py --all` 9/9 仍全绿；
判据本身未放宽（`unknown` 依旧不计 pass）。
