# Bundled radare2 license materials

The retained `include/libr/r_version.h` identifies radare2 **5.9.8**, commit
`4eb49d5ad8c99eaecc8850a2f10bad407067c898`. This matches the official
[5.9.8 source](https://github.com/radareorg/radare2/tree/4eb49d5ad8c99eaecc8850a2f10bad407067c898).
The workbench download catalog references the official
[radare2-5.9.8-w64.zip](https://github.com/radareorg/radare2/releases/download/5.9.8/radare2-5.9.8-w64.zip)
release. Its SHA-256 is
`0f4fd96967ddf3747277e37bb93b23493b0cb875acdc8303ab7e285edbe178de`,
matching the official release's `checksums.txt`. On 2026-10-30, all 37 EXE/DLL
files under the archive's `bin/` matched the retained files byte for byte.
The official Windows archive itself contains no root COPYING/COPYING.LESSER;
the license texts below come from the matching source commit.

The upstream README states that radare2 is distributed mostly under LGPLv3 and
that individual plugins can have different licenses. The missing root license
texts were restored verbatim from that exact official commit on 2026-10-30:

| Local file | Official source | Git blob SHA-1 |
|---|---|---|
| [COPYING](COPYING) | [COPYING](https://github.com/radareorg/radare2/blob/4eb49d5ad8c99eaecc8850a2f10bad407067c898/COPYING) | `e60008693e017bec1b4eb49c84be3898e26fcf2a` |
| [COPYING.LESSER](COPYING.LESSER) | [COPYING.LESSER](https://github.com/radareorg/radare2/blob/4eb49d5ad8c99eaecc8850a2f10bad407067c898/COPYING.LESSER) | `0a041280bd00a9d068f503b8ee7ce35214bd24a1` |

The existing nested `share/www/m/main.min.js.LICENSE.txt` is retained; it is not
a substitute for the GPL/LGPL texts. `share/scripts/licenses.r2.js` is a license
query script, not a license grant or a complete copy of the license texts.

Corresponding source for this version is available in the fixed source tree above
and its [source archive](https://github.com/radareorg/radare2/archive/4eb49d5ad8c99eaecc8850a2f10bad407067c898.tar.gz).
Per-file copyright and plugin/third-party terms remain with their original
authors; consult that source tree and the retained plugin metadata for individual
components. Restoring these texts changes no binary and grants no new license.
