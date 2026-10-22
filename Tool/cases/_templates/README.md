# 案例模板（十一域）

> 每份模板的字段与 `Tool/scripts/domain-gate.py` 的 `CASE_FIELDS` 同源；
> `evidence_kind` 决定 `target_type` 的写法（fixture 必须含「夹具/教学/fixture」）。
> 新建案例：复制本域模板 → 改 id/target_type → 跑出真产物 → 用 sha256 回填。

- `domain-gate.py --domain <域>` 会复算 `artifacts[].sha256`、检查 `refs` 存在、
  要求至少一个 `evidence_kind=real`。
- `repro.status`：`recorded`（lessons 里有命令+rc）或 `not-recorded`（历史归档，必须写 reason）。
