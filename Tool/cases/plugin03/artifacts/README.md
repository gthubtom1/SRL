# plugin03 artifacts

真实样本：本机 Chrome MV3 扩展（Quicker 1.2.4）子集，输入为 `../input/real-extension.zip`。

| 文件 | 说明 |
|---|---|
| `provenance.json` | 6 个原始文件的来源路径、字节数、sha256；内容未修改 |
| `plugin-triage.json` | `plugin-triage.py --json` 的结构/权限面/可疑 API/URL |
| `repro/plugin-repro.json` | `plugin-repro.py --json` 的入口、权限证据、数据流、最小单元 |
| `run.json` | 实际命令、rc=0、stdout/stderr |

复跑（在仓库根）：

```bash
python Tool/skill/plugin-targets/scripts/plugin-triage.py --path Tool/cases/plugin03/input/real-extension.zip --json
python Tool/skill/plugin-targets/scripts/plugin-repro.py --path Tool/cases/plugin03/input/real-extension.zip --out /tmp/plugin03-repro --json
```

解包目录未入库；`plugin-repro.py` 会按需重建。动态观测（浏览器加载、native host）未做，结论只到静态证据。
