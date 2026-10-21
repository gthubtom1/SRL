# 追版（跨版本迁移）规范 —— 版本账与迁移包

> 适用：01 旁路卡密 / 02 改 UI / 03 接授权 已经交付过一版，原作者发了新版本。
> 目标：**不重新逆向**，把三张资产清单迁移到新版，半小时内出可用成品。

---

## 1. 为什么要"账"，不能只靠报告

报告是给人看的，追版是脚本干的。脚本要的是**机读的位点清单**：每条位点带语义、带可搜索的
特征码（AOB）、带改前改后字节。没有这份账，第二次更新就只能从头再来。

所以阶段 01/02/03 每交付一次，必须顺手写一份 `versions/<版本>/manifest.json`（`migrate.py init` 建骨架）。

## 2. 目录约定

```text
<case 目录>/
  versions/
    6.8/
      manifest.json      ← 版本账（本文件规范）
      build.ps1          ← 一条命令从原件复现成品（01/02/03 阶段产出）
    6.9/
      manifest.json      ← 追版后生成（指纹 + 对齐结果）
      align.json         ← migrate.py align 的原始输出
      migrate-report.md  ← 《迁移差异报告》
```

## 3. manifest.json（schema = `seep-migration/1`）

```json
{
  "schema": "seep-migration/1",
  "version": "6.8",
  "source_exe": "<case 目录>/<旧版 exe>",
  "binary": {
    "sha256": "d66ec3a0…", "size": 26317824,
    "format": "PE32+", "machine": "x64", "entry_rva": "0x3d150",
    "packer_hint": ".pdata 熵 7.88；可疑节名 .ace0 —— 先过壳再追版"
  },
  "sites": [
    {
      "id": "gate-01", "sem": "卡密判定失败分支", "kind": "code",
      "aob": "B0 48 8B CD 44 8B C3 48 8D ?? ?? ?? ?? 00 E8 ?? ?? ?? ?? 85 C0 74 ?? 44",
      "rva": "0x4f9f4", "window": 24,
      "patch": { "orig": "44 8D 47 F6", "new": "6A 08 41 58" },
      "verified_by": "x64dbg 断点命中 @2026-10-20",
      "self_check": { "hits_in_own_binary": 1, "unique": true }
    }
  ],
  "ui": [
    { "id": "logo", "container": "RCDATA#102", "kind": "png",
      "old_sha256": "…", "new_file": "assets/logo.png" }
  ],
  "license": [
    { "id": "hk-1", "mode": "online-ticket", "site": "gate-01",
      "endpoint": "https://<你的平台>/api/verify" }
  ],
  "acceptance": [
    { "id": "A1", "desc": "双击启动出现主窗口", "check": "window_title.contains('…')" },
    { "id": "A2", "desc": "无卡密框", "check": "no_window_class('#32770')" }
  ]
}
```

字段要点：

| 字段 | 规则 |
|---|---|
| `aob` | **相对操作数必须掩成 `??`**（`call/jmp rel32`、`lea r64,[rip+disp]`、`jcc rel8`）。重编译后这些一定变，掩掉才能跨版本匹配。`add-site --wildcard-rel` 自动做。 |
| `window` | 特征窗口长度，默认 16；位点周围指令差异大时加到 24–32 换取唯一性。 |
| `rva` | 十进制或 `0x…` 都行；脚本内部统一转 RVA/文件偏移。 |
| `sem` | **一句话语义**（"卡密判定失败分支"），不是"这里改了 4 个字节"。追版时要靠它判断"新版这个位点还重不重要"。 |
| `self_check` | `add-site` 当场在旧版本体里搜一遍：必须唯一命中，否则 AOB 太短，先加长。 |

## 4. 追版七步（`04-version-migrate` 技能执行）

| 步 | 命令 | 判据 |
|---|---|---|
| ① 指纹比对 | `migrate.py fingerprint <新版exe>` | 壳线索变了 → 停，先回过壳（01 路线 A–D） |
| ② 位点对齐 | `migrate.py align --case C --old 6.8 --new <新版exe> --new-version 6.9` | 每条 `unique` 才算命中 |
| ③ UI 重定位 | 按 `ui[].container` 找新版对应资源槽 | 容器格式未变 → 直接贴；变了 → 报人工 |
| ④ 授权重挂 | 按 `license[].site` 指到 ② 得到的新 RVA | 走通自己的授权页 |
| ⑤ 构建 | `build.ps1` | 产物哈希与补丁清单可解释 |
| ⑥ 验收 | `acceptance[]` 逐条 | 全绿才算交付 |
| ⑦ 报告 | `migrate.py report --case C --old 6.8 --new-version 6.9` | 命中率 + 需人工清单 |

## 5. 对齐失败时的「兜底三重」

`miss` 不等于没救，按顺序试（每一步都要记录到 `align.json` 的 note 里）：

1. **唯一字符串锚**：位点附近的报错文案 / 注册表键 / URL → 在新版搜字符串 → 取 xref；
2. **xref 回溯**：找到引用该字符串的函数，比对函数开头 8–16 字节；
3. **反编译特征**：`seep_decompile_auto` 取新旧函数伪代码，按常量、调用顺序、分支数量比对。

三条都失败 → 该位点标 `need_manual`，**不许假装命中**。

## 6. 纪律

- 命中率 < 100% → 报告首行红字写明"K 处需人工"，并附定位指引；
- 任一步判据不过 → 只交"半成品 + 待办"，不交"成品"；
- 壳变了 → 不硬追，回到 `01-gate-bypass` 的 A–D 路线；
- 追版完必须更新 `versions/<新版本>/manifest.json` —— 下一次更新的账，从这一次开始。
