# UI 改版、去品牌与追版基线

- 触发：UI 改版、换品牌、去作者、去联系方式、换图标、换文案、关于页。
- 输入：`<target.exe/apk/asar>`、品牌名、图标与配色、要替换的页面/组件、保留功能和验收清单。第一版运行适配只承诺 PE/Windows 与 APK；其他 UI 栈可以改版，但必须明确是否已有追版适配器。
- 能力：`tool:resourcehacker`、`tool:imhex`、`tool:pe-bear`、`apk:static_apktool`、`apk:repack_signed`、`repo:case_state`、`repo:preflight-classify`、`repo:patch-verify`、`repo:reverse-accept`、`repo:install_test`。

## 1. 确定 UI 层和技术栈

1. 运行 `python Tool/skill/softseep/scripts/preflight-classify.py <TARGET> --hint`，确认载体与 UI 栈：Win32、Qt、自绘、Electron/Web、Android 原生、Unity 等。
2. 明确哪一层是用户定制 UI：覆盖层/启动器、外部资源、包内资源、代码内绘制或服务端内容。
3. 对每一页截取上游原版和定制版截图。截图必须能区分“上游旧 UI”“我方定制 UI”和“新上游新增 UI”，不能只保存最终成品图。
4. 识别上游锚点：窗口类、控件 ID、资源容器/路径、包名/Activity 与布局、文件键、路由或 API 字段。锚点属于新版要重新匹配的原版对象，不是我方旧成品的绝对地址。

## 2. 人工与机器清单同时交付

保留 `ui-inventory.md` 供人工阅读，并必须生成同目录的 `ui-inventory.json` 供追版恢复。最小结构如下：

```json
{
  "schema": "seep-ui-inventory/1",
  "project": "example",
  "version": "2.4.0",
  "pages": [
    {
      "id": "main-shell",
      "stack": "win32",
      "apply_method": "overlay",
      "upstream_anchor": {
        "type": "window-class",
        "value": "ExampleMainWindow"
      },
      "custom_asset": "ui/assets/main-shell/",
      "screenshots_before": ["ui/shots/upstream/main-shell.png"],
      "screenshots_after": ["ui/shots/custom/main-shell.png"],
      "acceptance": ["layout", "navigation", "feature-entry"]
    }
  ],
  "components": [],
  "brand_assets": [],
  "unknowns": []
}
```

记录要求：

- 每个页面/组件 ID 唯一，使用包含路径、哈希、语义的稳定引用。
- 应用方式限定为 `overlay`、`resource_replace`、`code_patch`、`server_content`；不确定时进入 `unknowns`，不能猜一个枚举值。
- 记录上游锚点类型和值、我方设计源、字体/图标/图片/文案资源、分辨率与缩放条件。
- 所有资源和截图路径必须位于项目内且真实存在；记录 SHA256 与大小。
- 变更前后的截图、可执行验收 ID 和已知无法自动重定位的项必须成对出现。

## 3. 实施和验证

1. **资源或字符串改动。** 先做最小、可回滚、尽量等长的修改，写入 `work/<case>/patch.json`；使用 `patch-verify.py --file <target> --manifest <patch> --out <output>` 生成并复算产物。
2. **覆盖层或外部资源。** 将图层与目标窗口/进程绑定，保存稳定窗口属性、尺寸边界和失败回退。不要把覆盖层截图当作功能实现。
3. **代码内绘制。** 只有在覆盖层和外部资源不可行时进入代码补丁；保存 hook/补丁语义、AOB 和回退路径，并把纯视觉差异与功能回归分开验证。
4. **Android 分支。** 使用 `Tool/scripts/apk/decode.ps1` 检查布局、资源和清单，使用 `Tool/scripts/apk/rebuild-sign-install.ps1` 重建、签名和安装。`res/`、`strings.xml`、图标与 Activity/Intent 改动均需记入清单。
5. **去品牌复查。** 用 `mal-triage.py --file <output> --json` 和资源/字符串证据核对作者名、邮箱、QQ、二维码、网址、证书/包名等目标项；只把范围内项目列为应移除，保留法律或许可要求保留的标识。
6. **功能与 UI 回归。** 页面/控件逐项检查，并验证原有功能入口和新版新增入口。Windows 运行主界面，APK 再运行 `install_test.py` 并保存启动与关键页面截图。
7. **失败回退。** 至少验证一次撤销资源、补丁或覆盖层后能回到上游可用状态；失败时保留可恢复项目状态。

## 4. 写回追版基线

UI 定制通过验收后，除了更新项目报告，还要把本次 UI 层写入当前版本的 `reverse-baseline.json` `ui[]`。使用受验证的版本账接口，例如：

```text
python Tool/skill/softseep/scripts/version-migrate.py add-ui \
  --case <project> --version <version> \
  --id main-shell --stack win32 --apply-method overlay \
  --anchor-type window-class --anchor ExampleMainWindow \
  --inventory ui-inventory.json \
  --asset ui/assets/main-shell/background.png \
  --screenshot-upstream ui/shots/upstream/main-shell.png \
  --screenshot-custom ui/shots/custom/main-shell.png \
  --acceptance layout --acceptance navigation --acceptance feature-entry
```

若当前命令版本尚未提供某个参数，以 `version-migrate.py add-ui --help` 为准；仍必须在 `reverse-baseline.json` 的 `ui[]` 中留下等价字段。构建入口、输出、签名/打包参数和回滚方法应写入项目构建记录与版本基线，确保下一次能从新上游原版重建。

以下情况不得标记“UI 可追版基线已建立”：

- 只有窗口标题、文字或截图，没有页面/组件与锚点；
- 资源路径在项目外、哈希变化或资产缺失；
- 只记录旧定制成品，没有记录它对应的旧上游；
- 无法说明应用方式或回退方法；
- 新上游新增功能没有进入 UI 功能回归；
- 只完成静态替换，未验证实际运行。

## 5. 完成判据

- `ui-inventory.md` 和 `ui-inventory.json` 内容一致，每个页面有前后截图和验收项；
- `reverse-baseline.json` 的 `ui[]` 可追踪到我方资产、上游锚点和应用方式；
- 补丁与产物可复算，资源变更可回滚；
- 去品牌范围逐项有证据，保留项说明理由；
- Windows/APK 的启动、页面、交互和功能清单全部通过；
- `reverse-accept.py` 成功，APK 安装测试成功；
- `preflight.py --fast` 成功，未验证项和新版差异已写入报告。
