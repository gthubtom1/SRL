# 快筛画像卡 · leaf-apk（A-APK-PLAIN）

- 案例：`leaf-apk`
- 证据类型：`public`
- 目标：`Tool/cases/leaf-apk/target/diva.apk`
- 目标身份：1249777 字节，sha256 `2228c2f40f8b0c7cd9194844b80f09b75a1cbd5534cd35131cf31e09aaaf25c5`
- 日期：2026-10-29

## 画像卡

**载体**：APK（zip）。当前可复核记录显示 379 个条目，只有 1 个
`classes.dex`（1931680 字节，魔数 `6465780a`，dex 版本 035）；没有
`lib/` 条目，也没有 `.so` 文件。历史 `aapt dump badging` 记录包名为
`jakhar.aseem.diva`，versionCode 1、versionName 1.0、minSdk 15、
targetSdk 23，启动 activity 为 `jakhar.aseem.diva.MainActivity`。

**保护**：16 个常见加固特征串在 `classes.dex` 中计数全为 0。结合单 dex
和无 native 库两项观察，可把本案当作普通、未观察加固入口的教学 APK。
本报告不再声称 manifest 的 application 节点没有 `android:name`：旧日志对
应段为空，已经没有可作为原始输出的 xmltree 结果。

**授权权威**：DIVA 是公开教学靶场，没有客户授权单、卡密或服务端权威面。
本案只提供普通 APK 的结构与成品字节基线，不把一个公开样本冒充客户真实目标。

**改动面**：现有 `artifacts/diva_repatched_signed.apk` 是 1301491 字节，
sha256 `1b5bae4ca11821cc2e743b395d224b230e4580dc500252ae7e00cd7803af5e90`。
案例内 MANIFEST 能把成品字节固定下来；旧捕获日志还记录了该成品的
`zipalign -c` 输出 `Verification succesful`。

这里能证明的是“这个现有 APK 成品存在、字节未漂移、历史捕获中留有对齐成功
记录”。不能仅凭这些文件证明旧任务里的 apktool 解包、1792 个 smali、改 smali、
apktool 构建或完整重签名过程在当前环境重新跑过；相关 claim 已降为
`hypothesis`，报告不再使用“构建闭环”这一表述。

**检测器**：当前原始输出不足以证明目标内部没有完整性自检、签名校验或
root/调试检测。壳特征计数为 0 只覆盖列出的 16 个字符串；没有命中不等于
所有检测器都不存在。要扩大结论，必须补当前版本的反编译、manifest/resource
解析和设备侧执行证据。

**交付壁垒**：旧捕获记录 `adb devices` 为空列表，因此没有完成真机安装和启动；
dex 中 `AdActivity`、`com/google/ads`、`admob`、`/ads/` 均未命中，因此本样本
不能用于验证“广告消失”。当前会话也不保证 `apktool`、`aapt`、`zipalign`
都在 PATH，缺少这些工具时只能复核已有成品和历史记录，不能重演完整构建链。

## 能证明什么

1. `target/diva.apk` 的尺寸、sha256 和案例登记一致。
2. target 中是单 `classes.dex`、无 `lib/`/`.so`，列出的 16 个壳特征计数为 0。
3. 历史 badging 记录与案例声明的包名、SDK 和启动 activity 一致。
4. 现有重打包成品存在，size/sha256 可用案例 MANIFEST 复核，历史日志记录了
   zipalign 成功。

F-101、F-102、F-104、F-106 分别通过 `evidence_contract` 要求证据文本中出现
对应输出。证据里缺少必需字符串、出现未处理 traceback、显式非零 rc 或 ERROR
时，`case_state.py verify` 会把该案判红。

## 不能证明什么

1. 无当前 `apktool`/`aapt` 原始输出，不能重演解包、修改、重打包和重签名。
2. 无当前 manifest xmltree 原始输出，不能维持“application 没有 name”的结论。
3. 无在线设备，未验证安装、启动或功能变化。
4. 样本没有观察到的广告 SDK，不能验证去广告效果。
5. 无当前 zipalign 工具，不能在本轮重新执行历史对齐检查。

## 三行结论

- 当前能下：DIVA 是这个普通 APK 案例的公开原件；结构、目标和现有成品字节可以复核。
- 当前不能下：旧构建链已被本轮复现，或 manifest application 没有自定义类。
- 下一步：安装/自动发现 apktool、aapt、zipalign 后按 F-103 的命令逐段保存原始输出；
  若要验证设备侧效果，再补充带广告目标、在线设备和安装/启动记录。

## 复跑入口

```powershell
python -B -X utf8 Tool/scripts/case_state.py verify --case Tool/cases/leaf-apk --json
python -B -X utf8 Tool/scripts/case_state.py verify-origin --case Tool/cases/leaf-apk
```

历史结构输出：`capture/reverify-2026-10-24.log`。
成品绑定：`artifacts/MANIFEST.sha256`。
公开来源说明：`Tool/samples/real/android-apks/README.md`。
