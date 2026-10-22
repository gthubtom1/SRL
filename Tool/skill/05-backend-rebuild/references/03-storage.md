# 存储与落库：把 mock 变成能记住状态的后端

> mock 服务的价值在"回放 + 骨架"，不负责持久化。
> 一旦进入 M3/M4，状态（会话、测验、作答、榜单）必须落库，否则重启即失忆。

## 1. 选型（按规模，不按喜好）

| 场景 | 选型 | 理由 |
|---|---|---|
| 单机演练 / 演示 / 回归 | SQLite（`sqlite3`，标准库） | 零部署、单文件、可整库拷贝做证据 |
| 多客户端并发 / 需要网络访问 | PostgreSQL | 行锁、事务隔离、并发写稳 |
| 已有企业库（MySQL/SQL Server） | 跟随现网 | 迁移成本最低，别为复刻造第二套 |
| 只读回放（录制快照） | 文件系统 + 内存索引 | 不落库，`snapshots/` 即数据源 |

硬规则：

1. **先 DDL 后服务**：`schema-infer.py` 出的 `schema.sql` 是唯一表结构来源，服务端代码不许内联建表。
2. **一环境一库文件**：`work/backend/var/app.db` 之类，路径由环境变量/参数给，不写死绝对路径。
3. **库文件不入库仓库**：`*.db`、`*.sqlite*` 进 `.gitignore`；证据只留迁移脚本和 sha256。

## 2. 从 schema 草案到可执行 DDL

```bash
python Tool/skill/05-backend-rebuild/scripts/schema-infer.py \
  --samples work/api/samples --out work/api/schema.json --ddl work/api/schema.sql
sqlite3 work/backend/var/app.db < work/api/schema.sql
```

草案到正式表之间要补的东西（脚本刻意不做）：

| 缺项 | 补法 | 判据 |
|---|---|---|
| 索引 | 按真实查询补 `CREATE INDEX`：外键列、`<表>_id`、状态列 | `EXPLAIN QUERY PLAN` 无全表扫（大表） |
| 唯一约束 | 业务唯一键（如 `quiz.code`）加 `UNIQUE` | 重复插入返回约束错误，不是静默覆盖 |
| 默认值 | `created_at DEFAULT (datetime('now'))` 之类 | 插入不带该列也有值 |
| 迁移 | 顺序编号 `migrations/0001_init.sql`、`0002_add_col.sql` | 空库执行到底 rc=0，重复执行幂等 |
| 软删除 | `deleted_at` 列 + 查询过滤 | 删除后列表不再出现，审计仍可查 |

## 3. 事务与幂等

写接口（登录、加入、提交、心跳计数）必须满足：

- **幂等键**：提交类接口接受 `Idempotency-Key` 或业务唯一键（`player_id + question_id`），
  重复提交返回同一结果，而不是插两行。
- **单事务**：一次业务动作（改分数 + 写答案 + 更新榜单）在一个事务里；失败回滚。
- **乐观锁**：并发改同一行用 `version` 列或 `UPDATE ... WHERE version=?`，冲突返回 409。
- **限流兜底**：心跳/轮询写库前先判"同 key 最近 N 秒已记"，避免把库写爆。

SQLite 注意：默认 `journal_mode` 在并发写时会 `database is locked`；服务端连接串开
`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`，并把写操作串行化。

## 4. 录制快照 vs 落库

| 数据 | 存哪 | 为什么 |
|---|---|---|
| 页面 HTML/静态资源 | 文件系统（`site/`） | 只读、按路径回放、可 diff |
| 录制 API 响应体 | `snapshots/<端点>.json` | 逐字节回放，sha256 可复算 |
| 会话 token | 内存/库表 `session` | 过期与顶号要可写 |
| 业务写入（测验/答案） | 库表 | 需要跨请求一致 |
| 心跳计数 | 内存 + 定期落库 | 高频、丢一点可接受，但要能解释 |

判断口径：**"重启后还要不要"** —— 要，就落库；不要，就放内存/文件。

## 5. 数据保留与审计

- 会话表按 `expires_at` 定期清理；清理任务写日志（删了多少行）。
- 作答/提交类保留原始请求体（脱敏后）与结果，便于复盘"为什么判错"。
- 审计表最小列：`id, at, actor, action, target, result, request_sha256`。
- 个人数据按授权窗口保留；到期删除并记录删除时间与范围。

## 6. 干净机器部署

后端交付物必须能在没有本机残留的机器上起来：

```bash
# 1) 建库（只用仓库里的 DDL）
sqlite3 var/app.db < api/schema.sql

# 2) 起服务（零依赖 mock）或起正式服务（按 README 的依赖）
python backend/server.py --host 127.0.0.1 --port 8787

# 3) 自检
curl -s http://127.0.0.1:8787/__health | python -m json.tool
```

检查表：

| 项 | 判据 |
|---|---|
| 依赖 | `requirements.txt`/`pyproject.toml` 存在且版本可装；mock 路径零第三方依赖 |
| 路径 | 全部相对路径或环境变量；`grep -R "D:\\\\|/home/" backend/` 为 0 |
| 建库 | 空目录执行 DDL + 迁移 rc=0 |
| 起服务 | 冷启动 ≤ 10 s，`/__health` 200 |
| 数据 | 首次启动不要求预置业务数据；空库也能回 404/空列表，而不是崩 |
| 停止 | Ctrl+C 退出码 0，库文件可再次打开 |

## 7. 备份与回滚

- 每次演练/回归前 `cp var/app.db var/app.db.bak-<阶段>`；失败可一键回滚。
- 迁移只增不改：删除列走"新列 + 回填 + 切换读 + 删旧列"四步，每步可回滚。
- 证据：迁移前后 `schema.sql` 的 sha256、行数统计，写进交付报告。

## 8. 与四脚本的衔接

| 脚本 | 对存储的责任 |
|---|---|
| `api-surface.py` | 只产出端点与样本，不读写库 |
| `schema-infer.py` | 产出 `schema.sql`；只推断、不建库 |
| `backend-scaffold.py` | 生成 `snapshots/` 与 `schema.json` 副本；默认**无状态**，重启即回放 |
| `switch-verify.py` | 只读探测；`submit` 类探针在 mock 上不改真实库 |

进入"有状态后端"是脚本之外的一步：拿 `schema.sql` 建库，把 mock 的 stub 处理替换成真实读写下表逻辑，
再用同一套 `switch-verify.py` 回归。口径写成 L3：**接口全通 + 状态可持久 + 关停表现一致**。

## 9. 失败判据

| 症状 | 根因 | 处理 |
|---|---|---|
| 重启后登录态丢失 | session 在内存 | 落 `session` 表 + `expires_at` |
| 并发提交出现两条记录 | 缺唯一键/幂等 | 加唯一索引 + 幂等键，重放同一请求验证 |
| `database is locked` | SQLite 并发写 | WAL + busy_timeout + 写串行化 |
| 迁移脚本重复执行报错 | 无幂等 | `IF NOT EXISTS` / 版本表 |
| 换机器起不来 | 绝对路径、缺目录 | 用 `--db` 参数 + 启动时 `makedirs` |
| DDL 与库不一致 | 手工改库 | 以 `schema.sql` 为准，重建库并重放迁移 |
