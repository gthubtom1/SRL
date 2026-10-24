# plugin04 artifacts

夹具：Electron asar（main/preload/renderer + IPC），输入为 `../input/app.asar`。

| 文件 | 说明 |
|---|---|
| `plugin-triage.json` | asar 头/条目/入口/`ipcMain`/`fetch` 命中 |
| `repro/plugin-repro.json` | 解包后的入口、IPC 数据流、最小单元 `main.js` |
| `run.json` | 实际命令、rc=0、stdout/stderr |

复跑（在仓库根）：

```bash
python Tool/skill/_pending/plugin-targets/scripts/plugin-triage.py --path Tool/cases/plugin04/input/app.asar --json
python Tool/skill/_pending/plugin-targets/scripts/plugin-repro.py --path Tool/cases/plugin04/input/app.asar --out /tmp/plugin04-repro --json
```

未运行 Electron；IPC 参数与远端响应未验证。
