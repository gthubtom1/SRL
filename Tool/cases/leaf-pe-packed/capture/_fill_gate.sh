#!/usr/bin/env bash
# 补齐阶段零出口闸需要的账：深度 D0–D7、仪器 I0、路线菜单 2 条 + choose。
set -u
CASE=Tool/cases/leaf-pe-packed
CS="python Tool/scripts/case_state.py"

$CS depth --case $CASE --level D0 --result pass --note "结构已测绘：三节 UPX0(size=0)/UPX1(0x2400)/UPX2(0x400)，UPX! @0x205，入口 0x140014fc0 在 UPX1，UPX1 熵 7.638；导入表 43 条（KERNEL32 10 + api-ms-win-crt-*）；压缩后 strings 面清零（PASS/trance 均搜不到）。见 report/static.md §1/§2、facts F-101..F-107"
$CS depth --case $CASE --level D1 --result pass --note "存活：压缩件直接跑 trance=PASS / wrong=FAIL；脱壳件与补丁件同样起得来，五输入矩阵全对（capture/run.json、run2.json）；单次运行 2–4ms，无阻塞无崩溃"
$CS depth --case $CASE --level D2 --result pass --note "动态依赖：导入面 43 条全为 KERNEL32 + api-ms-win-crt-*，网络/加密命中数 0（grep -ciE 'winnet|winsock|winhttp|bcrypt|crypt|ws2_32|socket|internet' = 0）；无新增 LoadLibrary 面（iI injprot=false）"
$CS depth --case $CASE --level D3 --result pass --note "出站行为：无任何网络导入 + 无 sleep/等待 + 2–4ms 退出，判定完全本地；与 golden-crackme 同源，无 DNS/TCP/TLS 面。bypass 不依赖任何外部响应"
$CS depth --case $CASE --level D4 --result pass --note "对照实验：补丁件复制到 /tmp/contrast/t.exe 换目录换文件名运行 wrong 仍 PASS（2ms）；未打补丁的脱壳件同输入 FAIL（4ms）→ 判定与路径/工作目录无关，且差异只来自那 2 字节"
$CS depth --case $CASE --level D5 --result pass --note "钥匙归属=文件内立即数（本地）：期望值 'tran'+'nce' 编码在 sym.main 的 cmp 立即数里，脱壳后明文可见；不来自服务端、不来自机器绑定。见 report/dynamic.md §4"
$CS depth --case $CASE --level D6 --result na --note "无 kill-switch 层：只有一个判定函数 sym.main，两条 cmp 是同一函数的连续比较，不是独立闸门；不存在逐层验证结构"
$CS depth --case $CASE --level D7 --result na --note "无静默失败面：程序不写文件、不开窗口、不联网，失败即 stdout FAIL 并立即 exit；不存在'活着但不干活'的分支"

$CS instrument --case $CASE --name baseline --status ok --launch "printf 'wrong' | <exe>（stdin 直喂）" --note "压缩件/脱壳件/补丁件三件都实测，五行输入矩阵见 capture/run.json + run2.json"
$CS instrument --case $CASE --name external --status ok --launch "upx -d / r2 / cmp / python ctypes ReadProcessMemory" --note "upx 5.2.1 脱壳成功；r2 6.2.0 反汇编定位；ctypes 读运行期内存复核脱壳保真（F-110..F-112）"

$CS plan --case $CASE --level L2 --route "脱壳后字节补丁（upx -d → 改 0x1e82 74 13→eb 1d）" --p 0.95 --hours "0.5" --needs "upx 5.2.1、radare2（定位）、python（写字节）" --fail "脱壳件 .text 与原件不一致 / 补丁后 wrong 仍 FAIL / 程序崩溃"
$CS plan --case $CASE --level L3 --route "不脱壳运行期内存补丁（base+0x2882 写 eb 1d）" --p 0.7 --hours "2" --needs "x64dbg 或 frida-attach（写内存）、每次现算 ASLR 基址" --fail "进程在 OEP 前被断点打断 / 写内存失败 / 基址算错导致崩溃"
$CS plan --case $CASE --level L4 --route "重打包分发（补丁件再 upx --best 压回 + 换签名/授权壳）" --p 0.5 --hours "4" --needs "upx 重压、签名工具、自有授权平台" --fail "重压后 checksum/入口异常 / 目标环境校验和检查拦截"

$CS choose --case $CASE --level L2 --route "脱壳后字节补丁（upx -d → 改 0x1e82 74 13→eb 1d）"
