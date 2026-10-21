# 容器识别与解包决策（container-triage）

> 目标：用最少命令判断“这是什么容器、从哪里切、切完能不能得到 rootfs”。
> 配套：`references/filesystem-and-credentials.md`、`scripts/fw-triage.py`。

## 1. 先记录，再动手

```bash
sha256sum fw.bin | tee orig.sha256
file fw.bin; stat -c '%s bytes' fw.bin
python Tool/scripts/fw-triage.py --file fw.bin
```

输出至少看三件事：魔术/偏移、整体与分块熵、内嵌凭据线索。脚本只做分流，不代表解包成功。

## 2. 魔术 -> 路线

| 魔术 | 类型 | 下一条命令 | 完成判据 |
|---|---|---|---|
| `hsqs`/`sqsh` | SquashFS | `unsquashfs -s` -> `-d rootfs -f` | 有 `/etc`、`/bin/busybox`、`/lib` |
| `UBI#` | UBI | `ubireader_display_info` -> `extract_images/files` | 卷列表 + 卷内根目录 |
| `85 19` | JFFS2 | `jefferson -d out img` | 节点可解析、目录树完整 |
| `45 3d cd 28` | CramFS | `cramfsck -x out img` / `7z x` | init 与 `/bin` 可读 |
| `ustar`@257 | tar | `tar -xvf` / `7z x` | 条目名/长度一致 |
| `1f8b` | gzip | `gzip -dc` | 解出下一层签名 |
| `28 b5 2f fd` | zstd | `zstd -d` / `7z x` | 解出下一层签名 |

嵌入偏移：先 `dd if=fw.bin of=part.bin bs=1 skip=<OFFSET>`，再对 `part.bin` 跑对应命令；直接对整包跑 `unsquashfs` 会报 `invalid magic`。

## 3. 熵怎么读

- `<6.0`：偏明文/元数据，先找脚本、配置、头部。
- `6.0–7.2`：混合，常见“容器 + 压缩区/填充”。
- `>7.2` 且高熵块占比高：压缩/加密/打包文件系统；**没有魔术时**才怀疑加密。
- SquashFS/UBI 本身高熵，不能凭熵判加密；要看魔术和 `binwalk -E` 的分段。

## 4. 常见坑

1. 厂商头：镜像从 0x100/0x400 开始，直接解包失败；按头部长度/CRC 算负载偏移。
2. 非标 SquashFS：LZMA/XZ 变体、非标准块大小；`unsquashfs` 失败换 `sasquatch`。
3. UBI 缺 OOB：NAND dump 不带 OOB 会导致 LEB 映射失败；用 `nanddump -o` 或保留原始布局。
4. JFFS2 端序/OOB：大量坏节点先查端序和起始偏移，不要先判“加密”。
5. 多层容器：OTA 包 -> tar/zip -> SquashFS -> 第二层 initramfs；每层都要 `file` 复判。
6. 只切出内核/DTB：不算 rootfs；继续找第二层或转硬件/UART。

## 5. 缺 binwalk 的等价路线

```bash
# 1) 用 7z 先看/解常见容器
7z l fw.bin; 7z x fw.bin -oout

# 2) 用脚本给出的偏移切分（纯 Python）
OFFSET=1234
python - "$OFFSET" <<'PY'
import sys
from pathlib import Path
src = Path('fw.bin').read_bytes()
Path('part.bin').write_bytes(src[int(sys.argv[1]):])
PY

# 3) 按类型解
unsquashfs -d rootfs -f part.bin
ubireader_extract_images -o ubi part.bin
jefferson -d jffs2 part.bin
cramfsck -x cramfs part.bin
```

仍然失败时：保留原始镜像与偏移记录，转 UART/SPI 或内核挂载；不要反复试同一命令。

## 6. 停止条件

- 只有高熵、无魔术、无厂商头线索：先转硬件/解密研究，不要盲拆。
- 解包命令报错但目录“看起来有东西”：以 `etc/bin/lib` 完整性为准。
- 需要写原始闪存/OTA 分区才能继续：先备份并获得授权，否则停。

## 7. 交付

记录：镜像 SHA256、容器类型/偏移、工具版本、解包命令、rootfs 路径、缺失项与下一步。
