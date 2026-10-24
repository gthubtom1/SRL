# 快筛画像卡 · leaf-apk（A-APK-PLAIN）

- 案例：`leaf-apk`
- 目标：`Tool/cases/leaf-apk/target/diva.apk`（1249777 字节，sha256 `2228c2f40f8b0c7cd9194844b80f09b75a1cbd5534cd35131cf31e09aaaf25c5`）
- 来源：`Tool/samples/real/android-apks/diva.apk`（仓库自带教学靶场，DIVA = Damn Insecure and Vulnerable App；`Tool/samples/real/android-apks/README.md` 声明为公开安全教学 APK，随仓库分发）
- 日期：2026-10-24
- 授权口径：仓库自带夹具（`case.json.evidence_kind=fixture`；公开教学靶场，非第三方商用目标）

## 画像卡（六字段）

**载体**：APK（zip）单包，**单 DEX**（`classes.dex` 1931680B，dex 头 `6465780a` + 版本 `035\0` = dex 035），**零 native 库**（整包无 `lib/`、无 `.so`），379 个条目，`resources.arsc` 219316B。包名 `jakhar.aseem.diva`，versionCode 1 / versionName 1.0，`minSdk 15` / `targetSdk 23`，启动 activity `jakhar.aseem.diva.MainActivity`；权限仅 3 条（READ/WRITE_EXTERNAL_STORAGE、INTERNET）。判据：`unzip -l` 全表 + `aapt dump badging Tool/cases/leaf-apk/target/diva.apk` 输出 `package: name='jakhar.aseem.diva' … launchable-activity: name='jakhar.aseem.diva.MainActivity'`。

**保护**：**未加固（无壳、无整体 DEX 加密、无 native 保护、无签名校验迹象）**。四条识别依据：

1. **DEX 面完整可见**——只有 1 个 `classes.dex`，魔数正常、dex 035；加固包常见「壳 dex 极小 + 真实 dex 藏在 assets/ 或加密 + 运行期解密」，此处无第二份 dex、无 `assets/*.jar`、无加密体。
2. **无 native 层**——`unzip -l | grep -Ei '\.so|lib/'` 空输出；壳/加固（梆梆、爱加密、360 加固、腾讯乐固、DexHelper）几乎都带 loader `.so`。
3. **加固特征字符串全为零**——对 dex+manifest+arsc 联合体做计数：

   ```
   StubApp 0    stub.StubApp 0    libjiagu 0      DexHelper 0    libmobisec 0
   com.qihoo 0  SecShell 0        jiagu 0         bangcle 0      secneo 0
   libexec.so 0 libshell 0        AppWrapper 0    aliprotect 0   libnesec 0    libshella 0
   ```

4. **manifest 里没有自定义 Application 类**——`aapt dump xmltree diva.apk AndroidManifest.xml` 的 `<application>` 下只有 theme/label/icon/allowBackup，**没有 `android:name`**；加固包必须在 Application 上挂 StubApp/AppWrapper 之类入口，缺这一项直接排除加固。

**授权权威**：本样本**没有授权/卡密校验面**——它是教学靶场，功能入口是 manifest 里的 **17 个 activity + 1 个 provider**（`AccessControl1Activity`、`APICredsActivity`、`InsecureDataStorage1Activity`、`SQLInjectionActivity` 等，`aapt dump xmltree … AndroidManifest.xml | grep -c 'E: activity'` = 17；另见 `smali/jakhar/aseem/diva/*.smali`），没有登录、没有到期时间、没有机器码。所以「权威判定点」在本样本上不存在，本叶子的可验证部分是**「改得动、打得回、签得上」这条链路**，不是「绕过某个校验」。

**改动面**：**smali 字节码可直接改**（这是本叶子的核心结论）。实证一条完整回路（解包 → 改 smali → 重打包 → 对齐 → 签名 → 校验）：

```
apktool d -r -f -o /tmp/diva_r  Tool/cases/leaf-apk/target/diva.apk   → 1792 个 .smali 文件
# 改 smali：smali/jakhar/aseem/diva/APICredsActivity.smali:38
#   const-string v0, "API Key: 123secretapikey123\n…"
# → const-string v0, "API Key: PATCHED_BY_FIXTURE\n…"
apktool b /tmp/diva_patch -o /tmp/diva_rebuilt.apk                     → I: Built apk...
zipalign -f 4 diva_rebuilt.apk diva_aligned.apk
jarsigner -keystore fixture.keystore -storepass … diva_aligned.apk fixture
zipalign -f 4 diva_aligned.apk diva_final.apk                          → Verification succesful
```

成品落在 `Tool/cases/leaf-apk/artifacts/diva_repatched_signed.apk`（1301491B，sha256 `1b5bae4ca11821cc2e743b395d224b230e4580dc500252ae7e00cd7803af5e90`）。三道复核全过：`jarsigner -verify` rc=0；`aapt dump badging` 能解析出新包（`package: name='jakhar.aseem.diva' …`）；`unzip -p … classes.dex | grep -c PATCHED_BY_FIXTURE` = 1（改的字符串真的进了 dex）。

**检测器**：目标自身**无完整性自检、无签名校验、无 root/调试检测**（依据：无 native loader 可挂检测点、dex 与 manifest 里 16 个加固/检测特征串全为 0、`<application>` 无自定义类可承载校验代码）。对我方流程的判据只有可行性判据：① `apktool b` 返回 `I: Built apk...`；② `jarsigner -verify` rc=0；③ `zipalign -c -v 4` 输出 `Verification succesful`；④ `aapt dump badging` 能解析（证明 zip/manifest 结构没被改坏）。

**已知坑（实测）**：`zipalign` 必须在**签名之后**再做一遍。本次先对齐、后 jarsigner（v1 签名会重写 zip 目录区），`zipalign -c` 立刻报 `res/_N.png (BAD - 2)`、`resources.arsc (BAD - 1)`、`Verification FAILED`；改成"签名 → 再 zipalign"后通过。这是 path-tree 里 `改完装不上 → 签名/zipalign` 那个 fork 的实物证据。

**交付壁垒**：**中**，且壁垒不在目标而在环境：① 装真机需要 `adb` 设备（本机 `adb devices` 输出为空，见下），无设备就无法证明"装上、启动"；② 本样本**无广告 SDK**（`com/google/android/gms/ads`、`com/facebook/ads`、`com/unity3d/ads`、`com/applovin`、`com/mopub`、`com/inmobi`、`com/chartboost` 对所有 dex+xml 计数全 0），所以叶子见证物里的"广告消失"在本夹具上**不可能**被验证——只能验证链路，不能验证"去广告"的效果；③ 现代设备 API 24+ 需 v2/v3 签名，本机 `apksigner` MISSING（只有 `zipalign` 和 `jarsigner`），v1 签名只对 API ≤ 23 有效，`targetSdk 23` 恰好落在可用边界上。

## 本夹具能证明什么 / 不能证明什么（诚实边界）

**能证明**（已实测）：单 DEX + 无 native + 加固特征全零 + 无自定义 Application → 未加固；`apktool` 能解出 1792 个 smali；改 smali 后能重打包、能对齐、能签名、dex 里能查到改后的字符串。

**不能证明**（缺条件，非我方失误）：
1. **真机安装与启动**——`adb devices` 空列表，无设备/模拟器在线；叶子见证物「真机装上、启动」未验证。
2. **广告消失**——样本本身无广告 SDK（计数全 0），无广告可去；「去广告」这个见证物只能在用户提供的带广告 APK 上验证。
3. **完整资源解码**——`apktool 2.5.0 d`（不带 `-r`）在本样本上**卡死**（反复打印 `Loading resource table from file: …framework/1.apk`，180s 超时；早期也报 `Invalid data detected. Skipping: -3416 byte(s)` / `Unknown data detected. Skipping: 17756 byte(s)`），说明 `resources.arsc` 有畸形段。本次用 `-r`（保留 raw 资源）绕过，代价是 `res/` 不做 XML 反编译、manifest 也不是文本形式——要改布局资源就得换样本或换 apktool 版本。

## 为什么这条叶子重要

它是**「安卓这一支的最小可回放样本」**：其它 APK 叶子（加固 A-APK-HARDENED、native 校验 A-APK-NATIVE、小程序 A-MP-WXAPKG）都以「未加固可改」为对照基线——没有这个基线，加固叶子上的失败就无法归因（是壳挡住了，还是我们连基本的重打包都没跑通）。本夹具把 `解包→改 smali→重打包→对齐→签名` 五步跑成一条可复跑命令链，并顺手定位了「对齐必须在签名之后」这个真实坑。

同时它也是一条**否定式证据**：靶场样本没有授权面、没有广告，所以「去广告/去限制」这个见证物不能靠它糊过去——必须在有广告/有限制的真实 APK 上验，否则就是把链路能力冒充成交付能力。

## 三行结论

- 能不能赢：**链路可赢，效果未证**。判据：未加固四条依据齐（单 dex / 无 so / 16 个加固特征全零 / 无自定义 Application），改 smali → 重打包 → 对齐 → 签名 → `jarsigner -verify` rc=0 全跑通。
- 赢的天花板：**只到"能改能重签"（静态链路）**。叶子见证物要求「真机装上、启动、广告消失」，三项都没验：无设备、样本无广告、`apksigner` 缺失只够 v1。要抬到叶子口径，需用户给一台在线设备 + 一个带广告/限制的 APK。
- 第一刀切哪：先拿用户给的带广告 APK，`apktool d -r` → 在广告 SDK 初始化处（`com/google/android/gms/ads` 的 `MobileAds.initialize` 或 `AdView.loadAd` 调用点）改 smali → `apktool b` → `jarsigner` → **再** `zipalign` → `adb install -r`。

## 收尾自检

- 六字段齐全（载体/保护/授权权威/改动面/检测器/交付壁垒），「保护」点名**未加固**并给了四条识别依据（单 dex / 无 native / 特征串全零 / 无自定义 Application）。
- 每个值都指向实测命令 + 输出片段；仓库内路径为相对路径，临时产物在 `/tmp`（D:/tmp）不影响可复跑性。
- 授权口径已写清：仓库自带公开教学靶场。
- 缺件与不可验证项已单列（上面「不能证明」三条），未用「基本完成」之类模糊词冒充。

## 复跑命令

```bash
# ① 结构 + 加固特征
unzip -l Tool/cases/leaf-apk/target/diva.apk | grep -Ei '\.dex|\.so|lib/'
aapt dump badging Tool/cases/leaf-apk/target/diva.apk
aapt dump xmltree Tool/cases/leaf-apk/target/diva.apk AndroidManifest.xml | grep -A4 'E: application'
# ② 解包（-r 绕开 arsc 畸形导致的卡死）
apktool d -r -f -o /tmp/diva_r Tool/cases/leaf-apk/target/diva.apk
# ③ 改 smali（APICredsActivity.smali:38 的 const-string）
# ④ 重打包 → 签名 → 对齐（注意顺序）
apktool b /tmp/diva_patch -o /tmp/diva_rebuilt.apk
jarsigner -keystore /tmp/fixture.keystore -storepass fixture123 -keypass fixture123 /tmp/diva_rebuilt.apk fixture
zipalign -f 4 /tmp/diva_rebuilt.apk /tmp/diva_final.apk
zipalign -c -v 4 /tmp/diva_final.apk     # Verification succesful
jarsigner -verify /tmp/diva_final.apk    # rc=0
```

## 交叉引用

- 打法：`Tool/skill/_pending/00-triage/SKILL.md`、`Tool/skill/apkseep/SKILL.md`
- 样本来源声明：`Tool/samples/real/android-apks/README.md`
- 下一份：`report/static.md`（阶段 0b）
