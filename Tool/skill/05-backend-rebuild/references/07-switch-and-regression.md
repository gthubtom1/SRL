# 切换与回归：hosts / PAC / patch 三选一，四类×三路必须全绿

> 切换不是"改一行 hosts 就完事"：要能**回滚**、能**解释**、能**在干净机器复算**。
> 回归不是"页面能开"：四类请求 × 正常/超时/错误码三路，一路缺就是没切干净。

## 1. 三种切换方式

| 方式 | 做法 | 优点 | 代价/风险 |
|---|---|---|---|
| hosts | `<host> 127.0.0.1` 写进系统 hosts | 客户端无感，不改包 | 需要管理员权限；端口固定 80/443；回滚要清行 |
| 代理/PAC | 客户端流量走本地代理或 PAC | 可保留原端口、可按 host 分流 | 客户端要支持代理；TLS 证书要匹配（或客户端忽略校验） |
| patch | 改客户端里的 host 常量/配置文件 | 精准、可版本化 | 需要重新打包/签名；改错会连带其它逻辑 |

`switch-verify.py` **不写系统文件**：它只产出 `hosts.fragment`、`proxy.pac`（由 scaffold 生成）
和 `switched.json`（`applied=false`）。应用动作交给人或容器：

```bash
# hosts（Linux/macOS；Windows 路径不同）
cat work/backend/hosts.fragment | sudo tee -a /etc/hosts
# 回滚：删掉对应行
sudo sed -i '/127.0.0.1 block.youtest.me/d' /etc/hosts

# PAC：客户端代理设置指向 work/backend/proxy.pac（端口与 scaffold 生成时一致）
```

容器化更干净：`docker run --add-host block.youtest.me:127.0.0.1 ...`，退出即回滚。

## 2. 四类 × 三路矩阵

| 类 | 探针 | normal 期望 | timeout 期望 | error_code 期望 |
|---|---|---|---|---|
| login | `POST /api/player` | 2xx + 会话字段 | 客户端超时（不崩） | 4xx + JSON error |
| list | 最短 GET 路径（`/api/share` 等） | 2xx + 可解析 JSON | 同上 | 同上 |
| submit | `POST /api/player/answer` | 2xx | 同上 | 同上 |
| heartbeat | `GET /info/country` | 2xx | 同上 | 同上 |

实现细节：

- 探针端点按 `role` 选，同 role 多条时取 path 最短的（稳定、可复算）。
- `normal` 的期望码 = 录制样本状态码（有样本时），否则 200；录制样本本身是 4xx 时会在报告里提示。
- `timeout` 先试 `?__delay=3` + 客户端 1.2 s 超时；服务端不支持钩子（回包过快）时自动改用
  进程内"黑洞 socket"（accept 后永不回包），保证超时语义可测。
- `error_code` 用 `?__status=401&__error=session_expired`；判定必须同时满足 `status ≥ 400`
  与 body 是 JSON 且含 `error` 字段。404 `not_implemented` 不算通过。
- `--closed-target` 可选：指向一个已关闭端口，验证"连接被拒"的停服形态。

## 3. 命令

```bash
# 自动起停 scaffold 生成的 server（推荐：端口随机，跑完即关）
python Tool/skill/05-backend-rebuild/scripts/switch-verify.py \
  --api work/api/api-surface.json \
  --server work/backend/server.py --port 0 \
  --timeout 1.2 --mode proxy \
  --out work/api/switched.json

# 对已在跑的后端（容器/CI）
python Tool/skill/05-backend-rebuild/scripts/switch-verify.py \
  --api work/api/api-surface.json --base http://127.0.0.1:8787 \
  --out work/api/switched.json

# 附带停服形态 + 把 hosts 片段写到指定文件（不写系统 hosts）
python Tool/skill/05-backend-rebuild/scripts/switch-verify.py \
  --api work/api/api-surface.json --server work/backend/server.py \
  --closed-target http://127.0.0.1:9 \
  --write-hosts work/backend/hosts.applied \
  --out work/api/switched.json

python Tool/skill/05-backend-rebuild/scripts/switch-verify.py --self-test
```

## 4. `switched.json` 结构

```json
{
  "schema": "seep.switch-verify/1",
  "switch": {"mode": "proxy", "base": "http://127.0.0.1:63430",
             "hosts": ["api.youtest.me", "block.youtest.me"],
             "hosts_fragment": "127.0.0.1 api.youtest.me\n127.0.0.1 block.youtest.me\n",
             "applied": false,
             "why": "脚本只产出片段；系统 hosts/代理由人或容器应用，避免污染本机"},
  "classes": {
    "login": {
      "normal":     [{"endpoint": "...", "expect": 200, "observed": {"status": 200, "source": "scaffold-stub"},
                      "pass": true, "why": "ok"}],
      "timeout":    [{"expect": "client-timeout", "observed": {"error_kind": "timeout"}, "pass": true}],
      "error_code": [{"expect": "4xx+json-error", "observed": {"status": 401, "error": "session_expired"}, "pass": true}]
    },
    "list": {}, "submit": {}, "heartbeat": {}
  },
  "closed": null,
  "counts": {"cases": 12, "pass": 12, "fail": 0},
  "verdict": "pass",
  "rules": ["..."]
}
```

字段口径：

- `counts.cases = 类数 × 3（+ closed 若启用）`；缺类直接 `blocked_at=roles`（rc=2），不偷偷少跑。
- `verdict=pass` 才允许 rc=0；任何 fail → rc=2 且 `blocked_at=regression`。
- 无时间戳、无随机端口写入稳定字段（`base` 是实际端口，属于运行事实），报告可复算其余部分。

## 5. 演练实测

`python Tool/skill/05-backend-rebuild/evals/run-drill.py` 在 site-clone-drill01 上：

| 项 | 值 |
|---|---|
| 输入清单 | 9 条 backend_required（7 页面 + 2 跨域 API） |
| 生成端点 | 15（9 能力 + 6 录制数据） |
| mock 路由 | 15（录制 6 / 骨架 9） |
| switch-verify | `verdict=pass`，`12/12`（4 类 × 3 路） |
| 产物 | `work/backend-rebuild-drill01/{api,backend,recorded}/`、`report.json`、`REPORT.md` |

复算：删掉 `work/backend-rebuild-drill01` 重跑同一条命令，除端口/耗时外结果一致。

## 6. 关停后端（M4 判据之一）

1. 先正常路径全绿；
2. 停掉本地后端（或 `--closed-target` 指向关闭端口）；
3. 观察客户端：应出现与原厂停服一致的表现（提示 + 有限重试 / 明确错误），
   而不是崩溃、无限重连、或静默卡死；
4. 记录：首错时间、重试次数、最终状态、客户端日志片段。

`switch-verify --closed-target` 只验证"连接被拒"这一层；客户端 UI 表现需要录屏/日志作为 M4 证据。

## 7. 可复现性检查

| 项 | 做法 |
|---|---|
| 端口 | `--port 0` 或显式固定，读启动行；报告写实际值 |
| 超时 | 固定 `--timeout`，不要依赖机器负载 |
| 顺序 | 四类固定顺序 login→list→submit→heartbeat；类内取最短 path |
| 样本 | 用 `recorded/` 的副本，不依赖案例目录在线 |
| 环境 | 只依赖标准库；`python -V` 写进报告 |
| 清理 | 进程 terminate + wait，端口释放；临时库/文件在 `work/` 下 |

## 8. 验收判据

| # | 判据 | 通过线 |
|---|---|---|
| 1 | 四类齐全 | `classes` 含四键，每键三路各 1 条 |
| 2 | 三路语义正确 | timeout 是客户端超时；error 是 4xx+JSON error；normal 是 2xx/录制码 |
| 3 | 切换可回滚 | hosts 片段可删、PAC 可关、patch 可还原；`applied=false` 有说明 |
| 4 | 停服可解释 | `closed` 或录屏/日志证明表现一致 |
| 5 | 产物可复算 | 重跑同命令结果一致（端口/耗时除外） |
| 6 | 不污染本机 | 系统 hosts 未被脚本修改 |

## 9. 失败判据

| 症状 | 根因 | 修法 |
|---|---|---|
| timeout 返回 200 | 服务端忽略 `__delay` | 用黑洞探针；或部署带钩子的镜像 |
| error_code 返回 404 | 路由没注册，401 只是假象 | 先补路由（见 api-surface 别名） |
| normal 返回录制 4xx | 录制样本本身是错误响应 | 先拿有效会话再录，或换样本 |
| 只跑 3 类 | 缺 role | 补抓包/改 role 规则，脚本会 blocked |
| 换机器结果不同 | 端口/时序/样本路径写死 | 按 §7 固定，报告写环境 |
| 切完 hosts 客户端连不上 | 端口/TLS/证书不匹配 | 用代理或 patch；或本地 443 + 证书 |
