# 真样本验收（不是我自问自答）· 2026-10-25

> 用户要求："你自己上网找样本真跑一次，别让我找。"
> 两个样本均从 GitHub 现拉，全程在本机执行，命令与输出可复算。

## 0. 样本

| 样本 | 来源 | 大小 | 说明 |
| :-- | :-- | --: | :-- |
| `work/samples/UnlockMe/UnlockMe.exe` | `KosBeg/ctf-writeups` → FireShell CTF 2019 `UnlockMe.zip` | 1,244,160 | CTF 逆向题，UPX 压缩壳 |
| `work/samples/wutiao360.apk` | `risecid/360Reverse-Engineering` → `wutiao360.apk` | 22,843,099 | 360 加固（jiagu）真实样本 |

哈希（sha256 前 16）：
- exe `7c4857b59f9704ac`
- apk 下载被截断过一次（GitHub raw 单次 2.6MB/22.8MB），用 `curl -C -` 续传 3 轮补齐后才通过
  `zipfile` 完整性校验 —— 这本身验证了"样本完整性"必须查，不能默认下来的就是全的。

---

## 1. EXE（UPX）：流程是否真的接上了

### 1.1 `seep_auto_triage`（MCP）

```json
{"ok": false, "error": "no_evidence", "blocked_at": "seep_auto_triage",
 "wrote_files": 0,
 "observed": {"sha256": "7c4857b59f9704ac0ee5a6d044a06bf93cbe5a5f6e312339b51d97a706284569"},
 "need_from_user": [credential, runtime, artifact],
 "reason": "rabin2 未能解析该文件，且鉴权关键词扫描零命中"}
```

**符合契约**：无证据 → `ok:false`，并列出三条必问（许可/运行许可/完整性），不编画像。

### 1.2 `seep_packer_detect`：判出壳

```
packed: true   packer_hints: section:UPX0, section:UPX1, string:UPX!
high_entropy_sections: UPX1(7.91)
sections: UPX0 raw=0 size=1851392 | UPX1 raw=1134592 ent=7.91 | .rsrc raw=108544 ent=1.36
warning: 原节 RawSize 基本全为 0、主体集中在一个高熵畸形节 → 文件字节是密文
forbidden_next: 对文件字节 capstone 反汇编 / strings 扫描 / 手工找 OEP
```

### 1.3 `unpack-loop/scripts/unpack-triage.py`：判型一致

```
证据（2 条，≥2 条才算判出壳）:
  - 单节占比>90% 且熵 7.91：UPX1
  - 入口点落在非代码节：UPX1（EP RVA=0x2d9c90）
判定: A 标准压缩壳（UPX）
路线: 先试官方解包（upx -d）；失败再走 OEP 法（references/oep-locate.md）
```

**两个工具结论一致，且都给出"下一步读哪篇"** —— 这正是"判型 → 路线"应当有的样子。

### 1.4 阶段零闸：真的会拦

```
$ case_state.py gate --case work/cases/unlockme
  - 未给可行性裁定（verdict）
  - 路线菜单（plan）不足 2 条候选（当前 0）
  - 未登记仪器可行性（I0）：至少 2 种
```

想跳过判型直接动手 → 被挡。**这一条是"模型不能自作主张"的硬约束。**

---

## 2. 验收当场发现的两个真问题（这才是真跑的价值）

### 2.1 `rabin2` 是假工具（A 类，已修并判据化）

| 检查 | 结果 |
| :-- | :-- |
| `tool-acquire --tool rabin2 --start` | `USABLE（停在 L0）` |
| `rabin2 -h` 里 `-I` 的说明 | `run script file before the file is opened` ← **这是 radare2 的旗标，不是 rabin2 的** |
| `strings rabin2.exe \| grep radare2` | `r_main_radare2`, `../binr/radare2/radare2.c` |
| 实际行为 | `rabin2 -I <pe>` → 被当成"加载脚本" → 进交互模式等 stdin → **一次调用卡死 900 秒** |

结论：本机 `D:\Tools\radare2\bin\rabin2.exe` 是 `radare2.exe` 改名。
后果链：`seep_auto_triage` 调它 → 超时 → `no_evidence` → 用户看到"拿不到二进制画像"，
而 `Tool/docs/tool-index.md` 写着"就位"。**工具存在 ≠ 工具可用。**

**修法（已落地）**
1. 新增 `Tool/scripts/lib/tool_identity.py`：每个工具一条**行为探针**（真 argv + 期望输出正则 + 超时 + 关 stdin）。
2. `tool-acquire`：L0/L1 命中后**必须过探针**，不过 → `USABLE_BUT_BROKEN`，并说明"存在但不是那个工具"。
3. `preflight` 新增判据 **「工具身份自检」**：文档声称"就位"的工具必须过探针；
   否则要么修好本机，要么把 `tool-index` 改成 `否（BROKEN：原因）` —— 强制"文档与现实一致"。
4. `tool-index.md` 如实改记：`rabin2 | 否（BROKEN：本机该文件是 radare2.exe 改名，-I 会进交互模式）`。

### 2.2 `apktool` 解包卡死（记账，未修）

`apktool d wutiao360.apk` 在 `Loading resource table from framework/1.apk` 之后不再返回（900s 超时）。
`jadx 1.5.6` 与 python `zipfile` 均正常 → 不是样本坏，是 apktool 2.5.0 在本机/本样本上挂住。
处置：APK 结构分析走 `zipfile` + `jadx`，需要 apktool 时加 `--no-res` 或先 kill 残留 java 进程。

---

## 3. APK（360 加固）：新加的脱壳指针是否生效

结构证据（`zipfile` 实测）：

```
条目 1956；dex 仅 1 个：classes.dex（4,932,612 字节）
assets/libjiagu.so, assets/libjiagu_x86.so          ← 壳的原生体
classes.dex 内含：StubApp / jiagu / libjiagu / 360   ← 壳入口类特征
```

判据对照（apkseep「判加固」三条）：
1. 壳入口类 `StubApp` 命中 ✅
2. `assets/libjiagu*.so` 命中 ✅
3. 只有壳 dex、真实业务 dex 缺失 ✅

→ **判为 360 加固（jiagu）**，按 `apkseep/SKILL.md 2.5` 转 `unpack-loop`。

上限：**M1（只能看懂结构，拿不到真代码）**。原因：壳把真实 dex 加密、解壳在运行时由
`libjiagu.so` 完成；要拿明文需要真机/模拟器跑起来（动态，需用户同意）或复刻 360 解密算法。

**缺什么**（按 `user-inputs.json` 三问）：① 是否有可用安卓真机/模拟器（可回滚）？② 是否允许在其上运行该 APP？③ 目标只是"看清结构"还是"必须拿到业务 dex"。

---

## 4. R2 三点验收结果（诚实版）

| 验的什么 | 结果 | 证据 |
| :-- | :-: | :-- |
| 第一句是否给「判型 + 能到哪级 + 缺什么」 | ✅ | triage 的 `need_from_user` + packer_detect 的 `route`/`forbidden_next`；本轮首条回复已按此写 |
| 是否真的读技能/工具（不是直接开干） | ✅ 部分 | 实跑了 `unpack-loop/scripts/unpack-triage.py`、`tool-acquire`、`case_state gate`；**未整篇读 apkseep SKILL**（只用了它的判据）→ 记一笔 |
| 判出壳后是否转脱壳闭环 | ✅ | exe → unpack-triage 判 A 类并指 oep-locate；apk → 按新增 2.5 条转 unpack-loop |
| 全流程能否在陌生机器复现 | ⚠️ | 本机 rabin2 坏、apktool 挂；换机器需先跑「工具身份自检」 |

## 5. 由这次验收产生的判据（不是文档，是机检）

| 判据 | 抓什么 |
| :-- | :-- |
| 脱壳指针 | 域声明"脱壳/加壳/加固"却不指向 `unpack-loop`（带壳 APK 会被直接改 dex） |
| 工具身份自检 | 文档说"就位"但行为探针失败（假工具 → 静默降级 → 用户被告知"没证据"） |
