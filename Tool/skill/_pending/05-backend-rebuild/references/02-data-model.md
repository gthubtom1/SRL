# 数据模型：从响应样本推表，而不是从想象写表

> `schema-infer.py` 只做一件事：把**已经录到的响应体**压成可执行 DDL 草案。
> 样本里没有的字段、枚举、时间格式，一律留空并在 `notes` 里写清楚——空着比编出来强。

## 1. 样本从哪来

| 来源 | 是否可信 | 备注 |
|---|---|---|
| api-surface 的 `samples/` | 高 | 抓包/录制的原始响应，`sha256` 可复算 |
| 录制回放的 HAR body | 高 | 与客户端看到的一致 |
| 手工构造的"示例数据" | 低 | 只能用于 self-test；进 schema 必须标 `derived` |
| 前端源码里的 TS 类型 | 中 | 结构对、值不对；枚举/时间仍需真实值 |

规则：**一个端点至少 2 条样本**才谈主键与枚举；只有 1 条时 schema 会写
`只有 N 行样本，主键不可判`，DDL 不加主键。演练案例（site-clone-drill01）就是这种情况：
`_next/data` 体只有 `pageProps.title` 一类 shell 字段，所以 6 张表的主键全为空——这是**正确结果**，不是脚本坏了。

## 2. 字段聚类

- 顶层数组 → 一张表；顶层对象 → 一行；对象里的"对象数组"字段 → 子表 `<父表>_<字段>`。
- 只有一层包装的形态（`{"data":[...]}` 且没有其它业务键）直接展开，不额外造父表。
- 字段顺序 = 首次出现顺序；输出时主键列排最前，其余保持原序（可复算）。
- 每个字段记录：`sql_type`、`json_types`、`nullable`、`null_rate`、`distinct`、`examples`（≤3）、
  可选 `enum`、`time_format`、`stored_as`。
- 空值参与 `null_rate`，但不参与类型判定；`null` 与缺失字段区别对待（缺失不计入 null）。

## 3. 类型映射

| JSON 观测 | 判定 | SQLite 类型 |
|---|---|---|
| 全是 integer | INTEGER | INTEGER |
| integer + real | REAL | REAL |
| 全是 bool | INTEGER | INTEGER（0/1） |
| 全是 text | TEXT | TEXT |
| object / array | TEXT（JSON 文本） | TEXT，加 `stored_as=json-text` |
| 混合（如 text + integer） | TEXT，降级并进 `warnings` | TEXT |

混合类型一定先修样本/接口约定，再上线；把 `"1"` 和 `1` 混存的字段，排序和索引都会坑。

## 4. 主键推断（按优先级，全部可复算）

1. `id`、`<表>_id`、`pk`、`uuid`、`guid`、`key`、`code` —— 唯一且非空才成立。
2. 任意 `*_id` 结尾的标量列 —— 唯一且非空。
3. 任意唯一非空**标量**列（json/array 列永不当主键）。
4. 2–3 列的**唯一组合**（按字段顺序枚举，先 2 后 3）。
5. 都不满足 → `primary_key=[]`，`primary_key_reason=none|insufficient-rows`。

硬约束：

- `rows < 2` 直接放弃（1 行必然"唯一"，会把 `pageProps` 这种 JSON blob 误判成主键）。
- 主键列必须 `null_rate == 0`；允许空值的列不进候选。
- 复合主键的每一列也必须是标量。

## 5. 枚举

判定条件（同时满足）：

- 字段类型是 text；
- `2 ≤ distinct ≤ max(2, min(--max-enum, int(rows*0.34)))`，`--max-enum` 默认 12；
- 每个值长度 ≤ 64 字符。

输出排序后的 `enum` 列表，并在 DDL 里以注释形式列出。注意：

- 枚举是"样本内观测值"，不是业务全集；上线前用真实流量复核。
- 状态机类字段（`status`）如果只观测到 1 个值，脚本不给 enum——单值不能证明枚举。
- 高基数字符串（用户名、URL）即使样本小也可能被误判，`--max-enum` 调小或加白名单。

## 6. 时间格式

| 观测 | 判定 | 存储建议 |
|---|---|---|
| 全部匹配 ISO8601（含 `Z`/时区/毫秒） | `iso8601` | TEXT（原样保留时区） |
| 全部匹配 `YYYY-MM-DD` | `date` | TEXT |
| 整数 + 字段名命中 `_at/_time/time/date/_ts/timestamp/expires/created/updated/deleted` + 量级 1e9–4e9 | `epoch_s` | INTEGER |
| 同上但量级 1e12–4e12 | `epoch_ms` | INTEGER |

字段名不命中时，整数一律按 INTEGER 处理，不猜时间——猜错会让"过期判断"整段错。

## 7. 子表与外键

- 父表字段是"对象数组"→ 子表 `<父>_<字段>`；父表有单列主键时，脚本补一列 `<父>_id`
  并标 `derived: true`（推断外键，不是抓来的列）。
- 子表行数 = 所有父行里该数组元素之和；子表没有父行上下文时不能推主键（行重复是正常的）。
- DDL 里外键只用注释表达，不写 `FOREIGN KEY`——SQLite 默认不强制，写了会给人虚假安全感。

## 8. 命令

```bash
# 从录制样本推 schema + DDL
python Tool/skill/_pending/05-backend-rebuild/scripts/schema-infer.py \
  --samples work/api/samples --out work/api/schema.json --ddl work/api/schema.sql

# 指定表名、收紧枚举上限
python Tool/skill/_pending/05-backend-rebuild/scripts/schema-infer.py \
  --samples work/api/samples --name scoreboard --max-enum 8 \
  --out work/api/schema.json

python Tool/skill/_pending/05-backend-rebuild/scripts/schema-infer.py --self-test
```

`--samples` 可以给多个文件/目录；目录递归只收 `.json`，读取用 `utf-8-sig`（兼容 BOM）。

## 9. 产物结构

```json
{
  "schema": "seep.schema-infer/1",
  "inputs": ["user.json", "scoreboard.json"],
  "tables": [
    {"name": "users", "rows": 3, "primary_key": ["id"], "primary_key_reason": "name-preference",
     "fields": [{"name": "id", "sql_type": "TEXT", "nullable": false, "distinct": 3,
                 "examples": ["u1","u2","u3"], "primary_key": true}],
     "foreign_keys": []}
  ],
  "ddl": "CREATE TABLE IF NOT EXISTS ...",
  "notes": ["users: 主键 ['id']（name-preference）"],
  "warnings": []
}
```

## 10. 验收判据

| # | 判据 | 通过线 |
|---|---|---|
| 1 | 每张表有来源 | `inputs` 覆盖所有样本文件，表名可追溯 |
| 2 | 主键不猜 | 有主键的表都能在样本里复算唯一性；`rows<2` 必须为空 |
| 3 | 枚举可复核 | `enum` 值与样本去重集合一致 |
| 4 | 时间不误判 | `time_format` 与样本值逐条匹配 |
| 5 | DDL 可执行 | `sqlite3 :memory: < schema.sql` 无报错 |
| 6 | 复算一致 | 同输入两次输出逐字节一致（脚本 self-test 已含） |

## 11. 常见误判与修法

| 症状 | 根因 | 修法 |
|---|---|---|
| `pageProps` 成主键 | 单行样本 + JSON 列参与候选 | 已修：`rows<2` 放弃、JSON 列不进候选 |
| 枚举把用户名收进去 | 样本小、`max-enum` 太大 | `--max-enum 4~8`，或改用状态字段白名单 |
| `created_at` 判成 INTEGER | 样本里是 `"2026-01-02"` 被当字符串但字段名命中 | 看 `time_format`：`date` 才对；不要手工改 DDL 类型 |
| 子表主键为空 | 子表行没有父上下文 | 正常；用 `<父>_id + 序号` 组复合键，写进 notes |
| DDL 与真实库不一致 | 样本来自旧版本 | 重新抓一版样本重跑；不要改脚本输出凑 |
