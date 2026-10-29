# plugin05 artifacts

夹具：VS Code VSIX（`extension/package.json` + activationEvents + child_process），输入为 `../input/ext.vsix`。

| 文件 | 说明 |
|---|---|
| `plugin-triage.json` | VSIX 结构、激活事件、命令、`exec_spawn` 命中 |
| `repro/plugin-repro.json` | 入口 `extension/extension.js`、命令/激活链、最小单元 |
| `run.json` | 实际命令、rc=0、stdout/stderr |

复跑（在仓库根）：

```bash
python Tool/skill/protocol-plugin/scripts/plugin-triage.py --path Tool/cases/plugin05/input/ext.vsix --json
python Tool/skill/protocol-plugin/scripts/plugin-repro.py --path Tool/cases/plugin05/input/ext.vsix --out /tmp/plugin05-repro --json
```

未签名、未安装、未执行；`child_process` 只做静态定位。
