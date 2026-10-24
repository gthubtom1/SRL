# -*- coding: utf-8 -*-
"""把 static.md / dynamic.md 里的证据表落到 facts.jsonl（同 id，机器可读账）。幂等：已存在则跳过。"""
import json, os, datetime

CASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FP = os.path.join(CASE, "facts.jsonl")
now = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

NEW = [
 ("F-101", "载体 PE32+ x86-64 CUI，41494B，首选基址 0x140000000，signed=false，hdr.csum 被 UPX 抹成 0",
  "r2 -c iI target/a_upx.exe: class PE32+ / machine AMD 64 / subsys Windows CUI / binsz 41494 / baddr 0x140000000 / signed false / hdr.csum 0x00000000",
  "Tool/cases/leaf-pe-packed/target/a_upx.exe:0x0 (DOS/PE 头)"),
 ("F-102", "节表只剩 UPX0(size=0)/UPX1(0x2400)/UPX2(0x400)；UPX0 磁盘无内容",
  "r2 -c iS: 0 0x200 size=0x0 vaddr=0x140001000 vsize=0x12000 UPX0；1 0x200 0x2400 UPX1；2 0x2600 0x400 UPX2",
  "Tool/cases/leaf-pe-packed/target/a_upx.exe:节表 0x1d8"),
 ("F-103", "UPX! 魔数在文件偏移 0x205；原件 0 处",
  "python buf.find(b'UPX!'): packed ['0x205'] / orig []",
  "Tool/cases/leaf-pe-packed/target/a_upx.exe:0x205"),
 ("F-104", "入口 0x140014fc0(paddr 0x21c0) 落在 UPX1；原件入口 0x1400013f0(paddr 0x9f0) 在 .text",
  "r2 -c ie: paddr 0x21c0 vaddr 0x140014fc0 对照 r2 -c ie 原件 paddr 0x9f0 vaddr 0x1400013f0",
  "Tool/cases/leaf-pe-packed/target/a_upx.exe:0x21c0"),
 ("F-105", "UPX1 载荷熵 7.638 bit/byte，原件 .text 熵 5.834",
  "python 香农熵: off 0x200 len 0x2400 -> 7.638; orig off 0x600 len 0x1a00 -> 5.834",
  "Tool/cases/leaf-pe-packed/target/a_upx.exe:0x200"),
 ("F-106", "函数面塌缩：压缩件可分析函数 3 个、无 sym.main；原件 75 个（含 sym.main 0x140002860 79B）。facts.jsonl F-003 记的 4/76 为旧版分析器口径",
  "r2 -c 'aa; aflc': packed=3 (entry0/fcn.140015030/entry1) / orig=75; r2 -c 'aa; afl~main' packed=空 / orig=sym.main 0x140002860 5 79",
  "Tool/cases/leaf-pe-packed/target/a_upx.exe:afl"),
 ("F-107", "业务字符串在盘上消失：b'PASS' 在压缩件完全不存在(-1)，b'trance' 也 -1；izz~trance 压缩件空、原件 0x2203",
  "python find: packed PASS=-1 trance=-1 / unpacked PASS=0x220a trance=0x2203; r2 izz~trance packed=空",
  "Tool/cases/leaf-pe-packed/target/a_upx.exe:UPX1 0x200-0x2600"),
 ("F-108", "压缩件上按 AOB 搜索全是假信号：74 13 @0x815、75 e3 @0x527、'tran' 立即数 @0xfb1，全部落在 UPX1 压缩流内且无指令边界/交叉引用支撑",
  "python find 对照表；0x815/0x527/0xfb1 均 ∈ [0x200,0x2600) UPX1 载荷；对应真值在脱壳件是 0xb6b/0xa73/0x1e7e",
  "Tool/cases/leaf-pe-packed/target/a_upx.exe:0x815 / 0xfb1"),
 ("F-109", "壳为标准可逆 UPX：upx -t [OK]、upx -l 报 win64/pe 77.15%，无改壳/加密/反调试迹象",
  "upx -t: testing ... [OK] Tested 1 file; upx -l: 53782 -> 41494 77.15% win64/pe",
  "Tool/cases/leaf-pe-packed/target/a_upx.exe:全文件"),
 ("F-110", "upx 5.2.1 成功还原 3.91w 压出的件：53782B、入口回 0x1400013f0、行为与原件一致（trance=PASS/wrong=FAIL）",
  "upx -d target/a_upx.exe -o unpacked/a_unpacked.exe: 53782 <- 41494, Unpacked 1 file, rc=0; r2 -c ie -> paddr 0x9f0 vaddr 0x1400013f0; printf 对照五行",
  "Tool/cases/leaf-pe-packed/unpacked/a_unpacked.exe:0x9f0 (入口)"),
 ("F-111", "脱壳件与原件仅 80 字节不同，全在头部(7)+.idata(73)，.text/.data/.rdata/.pdata/.xdata/.tls/.reloc 零差异；差异来源=PE 校验和清零、debug 数据目录清零、UPX 重建导入表(DLL 名大小写 DLL vs dll)",
  "cmp -l | wc -l = 80, first 0xd8 last 0x3638; 按节统计 .text 0 / .idata 73 / header 7; xxd 0xd8 unpacked 00000000 vs orig 886e0100; 0x34c9 'DLL' vs 'dll'",
  "Tool/cases/leaf-pe-packed/unpacked/a_unpacked.exe:0xd8 / 0x34c9"),
 ("F-112", "运行期内存复核：压缩件进程 ReadProcessMemory(base+0x2860,79) 与脱壳件磁盘 0x1e60 逐字节相同；base+0x2882 = 74 13。证明 UPX 自解压保持原 RVA 布局、upx -d 产物与内存解压结果一致",
  "ctypes CreateToolhelp32Snapshot+ReadProcessMemory: base=0x7ff715a90000, mem[:79]==disk[0x1e60:0x1eaf] -> True; mem[0x22:0x24]=74 13",
  "Tool/cases/leaf-pe-packed/target/a_upx.exe(运行期):RVA 0x2860"),
 ("F-113", "0x1e82 是文件偏移不是 RVA：脱壳件 0x1e82=74 13(VA 0x140002882 分叉)；压缩件 0x1e82=73 00(映射 VA 0x140014c82 UPX1 桩，反汇编 jae+invalid)；原件同为 74 13",
  "xxd -s 0x1e78 三件对照; r2 -c 'pd 6 @ 0x140014c82' packed -> jae 0x140014c84 / invalid",
  "Tool/cases/leaf-pe-packed/unpacked/a_unpacked.exe:0x1e82"),
 ("F-114", "补丁 0x1e82: 74 13 -> eb 1d（je 0x140002897 -> jmp 0x1400028a1 = lea rcx,str.PASS）实测生效：patched+wrong=PASS、patched 任意输入 PASS；负例 unpacked 未打补丁+wrong=FAIL",
  "printf 'wrong' | artifacts/a_upx.patched.exe -> PASS; printf 'wrong' | unpacked/a_unpacked.exe -> FAIL; r2 -c 'pd 5 @ 0x14000287a' -> 0x140002882 eb1d jmp 0x1400028a1; capture/run2.json negative_control.verified=true",
  "Tool/cases/leaf-pe-packed/artifacts/a_upx.patched.exe:0x1e82"),
]

existing = []
if os.path.isfile(FP):
    with open(FP, encoding="utf-8") as f:
        existing = [json.loads(l) for l in f if l.strip()]
have = {x["id"] for x in existing}
added = []
for fid, claim, how, ptr in NEW:
    if fid in have:
        continue
    added.append({"id": fid, "claim": claim, "status": "proven",
                  "evidence": ["%s  |  how: %s" % (ptr, how)],
                  "how": how, "ttl": "", "created": now, "refuted_by": None})
if added:
    with open(FP, "a", encoding="utf-8") as f:
        for x in added:
            f.write(json.dumps(x, ensure_ascii=False) + "\n")
print("appended", len(added), "facts; total", len(existing) + len(added))
