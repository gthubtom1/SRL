# leaf-pe-packed · verification receipt（2026-10-24）

## 1. 观测到的问题与更正
19 条 proven 缺 confidence；F-106/F-110/F-111 三条与复测数字冲突

## 2. 真实输入与范围
`Tool/cases/leaf-pe-packed`（`case.json` 里登记 target 与 evidence_kind）。源文件快照：
- `facts.jsonl` = `9faa57278f9028164b878f0e8a8d3f516ad00eb13a25e65fca6ff63a6950e1a2`
- `artifacts/MANIFEST.sha256` = `92297e7dd8b1e5112bda7c7f7acde9d4c08ffd79bc67a728874cf9ecbc467ed7`

## 3. 复现命令
```bash
python Tool/scripts/case_state.py verify --case Tool/cases/leaf-pe-packed
```

## 4. 成本与边界
- baseline：claim 19 / proven 19 / **背书 0** / verdict `unknown`
- final：claim 21 / proven 18 / **背书 15** / verdict `pass`
- upx 3.91w 解壳 + r2 复测后声明 observed，背书 0 → 15；3 条需活体进程/运行的降为 inferred 并排除
- 未验证：未做活体内存比对；未运行补丁后二进 制

## 5. 回归记录
本次改动后 `preflight --fast` 43/43、`gate.py --all` 9/9 仍全绿；
判据本身未放宽（`unknown` 依旧不计 pass）。
