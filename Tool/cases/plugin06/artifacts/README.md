# plugin06 产物（Tampermonkey 5.5.1 真实安装扩展）

| 文件 | 说明 | 是否计入 `case.json.artifacts[]` |
|---|---|---|
| `provenance.json` | 13 个源文件的来源路径（`<CHROME_EXT>` 占位）、字节数、sha256；字节级复制未改动 | 是 |
| `plugin-triage.json` | `plugin-triage.py --json` 输出：container=zip、13 文件、17 权限、`<all_urls>`、suspicious_apis 计数 | 是 |
| `repro/plugin-repro.json` | `plugin-repro.py --json` 输出：3 个入口 exists=true、17 权限中 9 条有代码行号证据、8 条 unexplained-static、`minimal_unit=background.js` | 是 |
| `repro/unpack/**` | repro 解包副本（13 个文件），供人工按行号复核；只在这里看，不回写源目录 | 否 |
| `run.json` | 上面两条命令的 cmd/rc/stdout 原样记录 | 是 |
| `accept.json（本地生成，不入库）` | `plugin-accept.py --root . --case Tool/cases/plugin06 --json` 的 rc=0 输出 | 否 |

`accept.json（本地生成，不入库）` 不列入 `artifacts[]`：它是验收脚本**本次运行的输出**，重跑会改写自身，列进去会形成自指哈希（第一次尝试就复现过 `sha256 不符（实算 e3b0c44298fc）`——shell 重定向先截断文件、accept 读到空文件）。它的 `root` 字段是本机 worktree 绝对路径，只作日志，不入证据链。

## 复跑顺序

```bash
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path Tool/cases/plugin06/input/real-extension.zip --json > /tmp/t.json
python Tool/skill/plugin-targets/scripts/plugin-repro.py  --path Tool/cases/plugin06/input/real-extension.zip --out Tool/cases/plugin06/artifacts/repro --json
python Tool/skill/plugin-targets/scripts/plugin-accept.py --root . --case Tool/cases/plugin06 --json
python Tool/scripts/domain-gate.py --domain plugin-targets
```

所有 JSON 产物都由脚本生成，无手改；不含 `generated_at`，复跑可复现同一字节（accept 的 `root` 字段除外）。
