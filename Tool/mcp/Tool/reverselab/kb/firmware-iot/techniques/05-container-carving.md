# 05 容器切分与熵速查

> 目标：用最少命令判断“这是什么容器、从哪切、切出来值不值得解”，并避免 weak 魔术误报。
> 配套：`references/06-container-carving-and-entropy.md`、`scripts/fw-triage.py`、
> `scripts/fw-repro.py`。

## 0. 入口信号

- `binwalk` 输出一堆签名但不知道哪个是真的。
- `unsquashfs`/`ubireader` 报 `bad magic`，怀疑偏移或加密。
- 输入是裸 blob（`BRCM`/`TRX`/单 PE），没有 rootfs。

## 1. 三步固定动作

```bash
sha256sum fw.bin | tee orig.sha256
python Tool/scripts/fw-triage.py --file fw.bin --json > triage.json
python Tool/skill/firmware-iot/scripts/fw-repro.py --file fw.bin --json > repro.json
```

看三件事：

1. `containers[]` 的 `type/offset/confidence`；
2. `entropy.overall/max_block/high_block_ratio`；
3. `repro.primary` 与 `repro.extraction.status`。

## 2. strong / weak 分层

| 层 | 类型 | 处理 |
|---|---|---|
| strong | SquashFS/UBI/CramFS/ZIP/tar/cpio/uImage/DTB/TRX/PE/ELF | 可作为主格式；切出后必须验证目录树/头字段 |
| medium | gzip/XZ/bzip2/Zstd | 先解压再判断；解压失败即误报 |
| weak | JFFS2 `0x1985` | 必须校验节点头/长度/CRC，不能单独定主格式 |
| vendor | `BRCM`/厂商头 | 用长度表+尾部版本串交叉验证 |

## 3. 熵的读法

- `overall` 高 + `high_block_ratio` 低 → 局部压缩/资源段，不是全盘加密。
- `overall` 高 + `high_block_ratio` 高 + 无 strong 魔术 → 可能全盘压缩/加密。
- `overall` 低 + strong 魔术 → 未压缩文件系统/明文脚本。

样例：`SecConfig.efi` overall 6.489 / ratio 0.01 → PE；`43341b0rtecdc.bin`
overall 7.055 / ratio 0.00 → BRCM blob；两者都不是“加密固件”。

## 4. 切分命令

```bash
binwalk --dd='.*' -C work/raw fw.bin       # 只切不执行
python - <<'PY'
from pathlib import Path
src = Path("fw.bin").read_bytes(); off = 0x3dbbc
Path("work/part.bin").write_bytes(src[off:])
print("carved", len(src) - off)
PY
```

切出物先 `file`/`fw-triage` 复核；`fw-repro` 会自动切 `carved-0x<off>.bin` 并记录 SHA256。

## 5. 失败判据（本页）

| 现象 | 判定 | 改走哪条 |
|---|---|---|
| 多个 strong 魔术在不同偏移 | 嵌套/重复头 | 切最外层，解出后再看内层 |
| 只有 weak 命中 | 不能定主格式 | 找厂商头/strong 标签；分层选择 |
| 切出物 `file` 不识别 | 偏移/长度错或加密 | 回头核对头字段；用两个版本比对 |
| 7z 报 `Cannot open ... as archive` | 该偏移不是容器 | 回到格式识别，不连换 7z 参数 |
| 解出目录缺 `/etc`/`/bin` | 不是完整 rootfs | 查第二层容器/厂商头 |

## 6. 边界

- 切分/熵是侦察，不能单独作为 J1/J2/J3 证据。
- 厂商头随版本变化，需多样本交叉验证。
- 只在 `work/` 副本上 carve/解包，原始镜像只读。
