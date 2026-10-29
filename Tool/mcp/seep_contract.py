#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""seep_contract.py —— 结果契约层 + 只读参数/命令语法边界。

从 `seep_mcp_server.py` 拆出来的**契约与校验**模块：不注册任何 MCP 工具、不 import 主服务、
导入期不读盘、不建状态。但它**不是**纯函数模块 —— 如实说明这里的 IO 与可变缓存：

  * `strong_claim_ids`（读 `facts.jsonl`）、`audit_tool_effects`（读 `tool-effects.json`）、
    `case_evidence_dir`（`os.path.isfile` 探测候选目录）、
    `kb_load_synonyms`（读 `Tool/config/kb-synonyms.json` + `os.path.getmtime`）；
  * `KB_SYN_CACHE`：进程内**可变**缓存（dict，mtime/groups/stopwords），由
    `kb_load_synonyms` 按 mtime 刷新；`KB_SYN_CACHE` 也被主服务 import 共享。
  * 其余（预算闸/空态/分页/报告模板/参数语法/整数范围/r2 只读命令语法）是纯函数。

拆的理由只有一条：主服务单文件行数预算 ≤3200（`MANUAL/BASELINE-FREEZE.md` §7），
而 S2 要求「超限拒绝不截断 + 报告无证据则拒绝」，这些判据必须进代码。
（2026-10-27 修正：旧 docstring 自称"纯函数模块：无 IO、无全局状态"，与实现不符；
本批改为如实描述，并**不**把 IO 层搬回主服务，只是不再虚报。）

三个出口（都不返回"削过的证据"）：
  * `resource_constraint`  超预算 → {ok:false,error:"resource_constraint",bytes,continuation}
  * `empty_output`         零输出 / r2 报错 → {ok:false,error:"empty_output"}
  * `page_footer`          用户显式分页 → 返回 [PAGE] 续读指针（不是静默截断）

第五块（`pcap_*`）是 pcap 提取的执行契约：参数校验 / 执行记录 / 状态推导 /
分页口径。**纯函数**，不 spawn、不读盘；真正起 tshark 的 argv 组装仍在主服务里
（`-n -r <绝对路径>` 这个形状留在实现体内，供 AST 来源证据核对）。
"""
from __future__ import annotations

import json
import os
import re

RESULT_BUDGET_BYTES = 64 * 1024
RESULT_BUDGET_CHARS = 8000
REPORT_PLACEHOLDER_BRANCH = {"", "0x0", "0x00000000", "0", "none", "null",
                             "unknown", "tbd", "todo", "?", "-"}
STRONG_CONFIDENCE = ("observed", "derived")

# 报告五段（与 `Tool/scripts/case_state.py::SECTIONS` **同一份口径**）。
# 为什么写在这里：`seep_gen_security_report` 的产物必须能过
# `python Tool/scripts/case_state.py report --check --file <产物>`，
# 段名各写一套就会出现「工具出的报告自己不合格」（第 4 轮评审 P1-5）。
REPORT_SECTIONS = ("结论", "已确认", "仍未知", "下一步", "复查")
REPORT_SECTIONS_JOINED = " / ".join(REPORT_SECTIONS)


# ---------------------------------------------------------------------------
# 只读参数硬校验（**MCP 直接调用也走这里**，不依赖 workflow 入口）
#
# 背景（独立复核 r2-target-injection / kb-escape 两项 refuted）：
#   * `seep_r2_disasm/decompile` 把 `target` 用 f-string 拼进 radare2 的 `-c` 命令串，
#     `shell=False` 只保护 argv 边界，**不保护 r2 自己的命令解释器**；
#   * `seep_kb_search/kb_read` 把 `category` / `article_path` 直接 os.path.join，
#     `../` 可把检索/读取范围带出 KB 根。
# 所以边界必须在工具函数**入口**判定：语法白名单 + 真实路径解析 + 根边界 + symlink。
# 只读动作只需要「符号名 / 十六进制 / 十进制地址」三种目标写法；算式（main+0x10）
# **暂不支持**——要支持必须另写明确 parser，而不是放行任意字符串。
# ---------------------------------------------------------------------------
R2_TARGET_FORBIDDEN = (";", "\n", "\r", " ", "\t", "!", "$", "|", "&", ">", "<",
                       "`", "@", "'", '"', "\\", "/", "(", ")", "#", ",", "+",
                       "-", "*", "=", "~", "%", "{", "}", "[", "]")
_R2_SYMBOL_RE = re.compile(r"^[A-Za-z0-9_.]{1,128}$")
_R2_HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]{1,16}$")
_R2_DEC_RE = re.compile(r"^[0-9]{1,20}$")


def invalid_param(tool: str, detail: str) -> str:
    """参数被拒的统一出口：结构化 JSON（ok=False），不回显被拒的原始值。"""
    return json.dumps({
        "ok": False, "error": "invalid_parameters", "blocked_at": tool,
        "detail": detail,
        "hint": "只读工具只接受明确语法的参数：符号名/0x十六进制/十进制地址、"
                "KB 根内相对路径、整数范围内的计数；拒绝后不要拼接重试。",
    }, ensure_ascii=False, indent=2)


def r2_target_error(target) -> str:
    """r2 `@ <target>` 目标语法校验。返回 "" = 合法；否则返回**不含原值**的原因。

    这是 r2 target 语法的唯一来源；`project_workflow.py` 侧复用同一判定（workflow 无法
    import 本模块时不加载即拒），由 `Tool/mcp/test_readonly_parameters.py` 交叉对齐。
    """
    if not isinstance(target, str):
        return "target 必须是字符串"
    if not target:
        return "target 不能为空"
    if len(target) > 128:
        return "target 过长（≤128）"
    for ch in R2_TARGET_FORBIDDEN:
        if ch in target:
            return "target 含命令/表达式分隔符（只接受符号名或地址）"
    if _R2_HEX_RE.match(target) or _R2_DEC_RE.match(target) or _R2_SYMBOL_RE.match(target):
        return ""
    return "target 语法不被接受（符号名 / 0x十六进制 / 十进制地址）"


def int_range_error(name: str, value, low: int, high: int) -> str:
    """整数参数的**原因串**（不含原值）。"" = 合法；否则给人看的原因。

    这是「什么算合法整数」的唯一来源：`int_in_range`（MCP 工具）与
    `project_workflow.validate_args`（入口）都调它，避免两边各写一套语法。
    """
    if isinstance(value, bool):
        return "%s 不接受布尔值" % name
    if isinstance(value, float):
        if value != value:                      # NaN
            return "%s 必须是有限整数（不接受 NaN）" % name
        if value in (float("inf"), float("-inf")):
            return "%s 必须是有限整数（不接受 Inf）" % name
        if not value.is_integer():
            return "%s 必须是整数（不接受小数）" % name
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return "%s 必须是整数" % name
    if isinstance(value, float) and float(number) != value:
        return "%s 必须是整数" % name
    if number < low or number > high:
        return "%s 超出范围 %d..%d" % (name, low, high)
    return ""


def int_in_range(tool: str, name: str, value, low: int, high: int):
    """整数参数校验 → (值, 错误串)。bool 不算整数（True 不该被当成 1 行）。

    正常输入：CLI/int 或数字字符串（`"60"`）；纯整数不经过 float 截断。
    一律**结构化拒绝**（不抛 traceback）的边界值：
      * bool（True/False）—— Python 里 `int(True)==1`，不能当成 1 行；
      * NaN / ±Inf / 1e999（float('inf')）/ 超大整数（10**400）；
      * 非整数 float（1.5）/ 非数字字符串 / None / 容器；
      * 超出 [low, high] 的整数。

    为什么必须捕获 OverflowError：`int(float('inf'))` 抛的是 `OverflowError`，
    不在 `(TypeError, ValueError)` 里 —— 旧实现会让畸形 JSON 数值一路穿到 MCP 工具
    与 CLI（rc=1 + traceback），把"参数错"说成"工具故障"。类内 `int_range_error()`
    是真实现，本函数只把它包成结构化错误。
    """
    reason = int_range_error(name, value, low, high)
    if reason:
        return None, invalid_param(tool, reason)
    return int(value), ""


def kb_rel_error(value) -> str:
    """KB 根内相对路径/分类的语法校验。返回 "" = 合法；否则返回原因。
    拒绝：绝对路径、Windows 盘符、UNC（//host/share）、上跳（..）、空、超长、控制字符。
    只做**语法**判定；真实边界由 `kb_within()` 用 realpath 判（含 symlink）。
    """
    if not isinstance(value, str):
        return "必须是字符串"
    text = value.replace("\\", "/").strip()
    if not text:
        return "不能为空"
    if len(text) > 400:
        return "过长（≤400）"
    if any(ch in text for ch in ("\x00", "\n", "\r")):
        return "含控制字符"
    if text.startswith("//"):
        return "不接受 UNC 路径"
    if text.startswith("/"):
        return "不接受绝对路径"
    if re.match(r"^[A-Za-z]:", text):
        return "不接受 Windows 盘符路径"
    parts = [p for p in text.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return "不接受上跳（..）"
    return ""


def kb_within(path: str, root: str) -> bool:
    """realpath 边界判定：path 必须落在 root 内（symlink 指到外部同样算越界）。"""
    real_root = os.path.realpath(root)
    real = os.path.realpath(path)
    return real == real_root or real.startswith(real_root + os.sep)


def kb_join(root: str, rel: str) -> str:
    """相对路径按段拼接（不经 os.path.join 吸收 ".." / 绝对前缀）。"""
    parts = [p for p in rel.replace("\\", "/").strip().split("/") if p not in ("", ".")]
    return os.path.join(root, *parts) if parts else root


# ---------------------------------------------------------------------------
# r2 命令语法层：**已审核只读命令**（separate from 任意命令）
#
# 背景（独立验收 `workflow-independent-acceptance.md` §3.1 refuted）：
# `seep_r2_cmd` 旧实现只按「每段首 token 是不是 w* / o+ / oo+」判定，于是
#   `!id` / `!!id`（r2 起系统 shell）、`pd 20 > out.txt`（r2 内建重定向写文件）、
#   `aaa; C*`、`.`/`-`（执行脚本/编辑器）、`L <plugin>`（加载插件＝执行外部代码）
# 全部绕过。首字母黑名单不可用：必须把“已审核只读语法”写成**白名单**。
#
# 本模块只做**语法**判定，不执行任何命令：
#   * 拒绝 shell / 重定向 / 命令链 / 反引号 / 变量展开（r2 的 `!`、`>`、`<`、`|`、`&`、
#     `` ` ``、`$`、反斜杠、引号）—— 这些字符在已审核语法里没有合法位置；
#   * 多命令只能用 `;` 显式分段，**每段都全校验**（不接受空白分隔绕过）；
#   * 首 token 必须命中 `R2_READONLY_HEADS`（按 r2 的 `a?`/`i?`/`p?`/`s?` 等帮助逐条挑选）；
#   * 二次 deny（belt & braces）：写入/重开写模式/变更家族（w*, o+ 系列, r 尺寸变更,
#     L 加载插件, . - P 脚本/项目, mw/mg, y 粘贴, z-/C-/t-/f- 删除, e 赋值/编辑器）；
#   * 其余字符（参数）只允许 `[A-Za-z0-9_.:@+\-*/=,~?[]% 空格]`；
#   * 未知首 token / 未审核语法 → 结构化 `read_only_violation` + `kind=unknown_syntax`，
#     **不猜、不降级、不尝试解析执行**。
# ---------------------------------------------------------------------------
R2_COMMAND_MAX_LEN = 400
R2_COMMAND_MAX_SEGMENTS = 8

# 已审核只读命令首 token（含 j/*/... 变体由 `_r2_head_candidates` 归一后匹配）。
R2_READONLY_HEADS = frozenset((
    # --- 帮助 / 语法查询（不碰目标） ---
    "?", "??", "?v", "?V", "?x", "?j", "?e", "?f", "?b", "?i", "a?", "p?",
    "i?", "s?", "b?", "t?", "k?", "o?", "y?", "r?", "m?", "z?", "u?", "w?",
    "C?", "e?", "~?", "/?", "L?", "f?", "d?", "c?", "v?", "x?",
    # 注意：不列 `!` —— 它在 r2 里起系统 shell，已在 R2_FORBIDDEN_CHARS 硬拒。
    # --- 分析（只产生分析结果，不写目标） ---
    "aa", "aaa", "aac", "aae", "aai", "aar", "aas", "aav", "aap", "aa0",
    "af", "afj", "afi", "afij", "afl", "aflj", "afls", "aflm", "aflc",
    "afn", "afv", "afbj", "afB", "afM", "afs", "afb", "afc", "afd", "afu",
    "ah", "ahb", "ahj", "ah*", "ai", "aij", "aL", "aLj", "aLq",
    "an", "ao", "aoj", "aO", "ap", "ar", "arj", "as", "av", "avj",
    "avg", "ax", "axj", "axg", "axt", "axtj", "axtg", "axf", "axfj", "axg",
    # --- 文件/二进制信息（rabin2 语义，只读） ---
    "i", "ij", "iI", "iIj", "ia", "iaj", "ic", "icj", "iC", "iCj", "id",
    "idj", "ie", "iej", "iee", "iE", "iEj", "ig", "igh", "ih", "ihj", "iH",
    "ii", "iij", "iic", "iicj", "ik", "il", "iLj", "im", "imj", "iM", "iMj",
    "io", "ir", "irj", "iR", "iRj", "iR*", "is", "isj", "iS", "iSj", "iS.",
    "it", "itj", "iT", "iTj", "iV", "iVj", "iw", "iwj", "iz", "izj", "izz",
    "izzj", "i*", "i**",
    # --- 打印 / 反汇编（只读输出） ---
    "pd", "pdj", "pdf", "pdfj", "pdc", "pdcj", "pD", "pDj", "p8", "p8j",
    "px", "pxj", "pxo", "pxq", "pxw", "ps", "psj", "psw", "psz", "pw",
    "pi", "pij", "pI", "pIj", "pj", "po", "poj", "pv", "pvj", "pv1", "pv2",
    "pv4", "pv8", "pr", "prx", "prg", "pt", "ptj", "pu", "pz", "pm", "pmj",
    "ph", "phj", "pb", "pbj", "pk", "pp", "pC", "pA", "pl", "pf", "pfj",
    "pF", "pq", "p6", "p6d", "p6e", "pc", "pcp", "pwd",
    # --- 定位 / 块 / 标记（只读形式） ---
    "s", "s.", "s:", "sf", "sf.", "sfp", "sff", "sr",
    # 注意：`s+`/`s-`/`s--`/`s++`/`ss`/`so`/`sn`/`snp`/`spp`/`sg`/`sG`/`sC`/`sd`
    # 都是当前**进程内**的 seek 状态变更，不给只读查询增加能力，故不进白名单。
    "b", "bj", "b*",
    # 注意：`b+`/`b-`/`bf` 改块大小；`f name 12 @ 33` 在**会话内**设 flag。
    "f", "fj", "f*", "f.",
    "t", "tj", "t*", "ts", "tsj", "tc", "tcj", "tt", "ttj", "te", "tej",
    "tf", "tfj", "tu", "tuj", "tp", "tn", "tx", "txj", "tl", "tlj",
    "k", "kj",
    # 注意：`ks`（sdb 交互 shell）/ `ko`（打开 sdb 文件）/ `kd`（dump 到磁盘）不进白名单。
    "e", "ej", "eJ", "et", "ev", "evj", "es", "en", "e/", "e,",
    # 注意：`md`/`mi`/`mp`/`ms`（r2fs 浏览与 fs shell）不进白名单 —— 它们能读挂载的
    # 外部文件系统；`m`/`mj`/`mL`/`mLL` 只列挂载点与插件。
    "m", "mj", "mL", "mLL",
    # 注意：`zf`/`zfz`/`zfd`（读外部 FLIRT 签名文件）、`zs`/`zo` 不进白名单。
    "z", "zj", "zq", "zk", "zi", "z*", "z/", "zb", "zc",
    # 注意：`C` 家族**整族不进白名单** —— 它把 listing（`C`/`C*`/`Cj`）与
    # 写入类（`CC` 加注释 / `Cs` 加字符串 / `Ct` 加类型注释 / `C-` 删除 /
    # `Cd` 数据数组 / `Ch` hide / `Cr` 改反汇编）混在同一个字母下，
    # 逐字母挑选等于继续猜；本入口宁可拒整族（返回 unknown_syntax）。
    "y", "yj", "y*", "y8", "yp", "ys", "yx",
    "r", "rj", "rh",
    "u", "uname", "uid", "uniq", "us",
    # 注意：`cat [file]` 能读任意宿主文件（信息泄露）→ 不进白名单。
    #      `pushd`/`popd`/`sort`/`tail`/`tac`/`py`/`pkill`/`sh` 同样不进。
    # --- 搜索（只读） ---
    "/", "/j", "/i", "/x", "/a", "/d", "/e", "/E", "/f", "/F", "/g", "/h",
    "/k", "/m", "/o", "/O", "/p", "/P", "/r", "/R", "/s", "/v", "/V", "/c",
    "/w", "//",
))

# 硬拒字符：在“已审核只读语法”里没有任何合法位置。
# 理由逐条：`!` r2 起系统 shell；`>`/`<` r2 内建重定向/读文件；`|`/`&` 命令链；
# `` ` ``/`$` 变量与命令展开；`\`/引号 是 shell 引号与转义（r2 里不需要，且便于逃逸）；
# `\x00`/`\r`/`\n` 控制字符（`\n` 等价于第二条命令）。
R2_FORBIDDEN_CHARS = ("!", ">", "<", "|", "&", "`", "$", "\\", '"', "'",
                      "\x00", "\r", "\n", "\t")

# 二次 deny：变更/写入/代码执行/文件系统/编辑器家族（即使被误加进白名单也要拦）。
# 二次 deny：变更/写入/代码执行/文件系统/编辑器家族（即使被误加进白名单也要拦）。
# r2 的 command letter **大小写敏感**，所以这个正则不用 IGNORECASE
# 否则 `P` 会误伤 `pdf`/`pd`/`px` 整族。
R2_MUTATING_HEAD_RE = re.compile(
    r"^(?:"
    r"w(?!\?)"                                    # w* 全家族写入
    r"|o\+|o-|o:|oc|oe|of|om\+|om-|on\+|on-"
    r"|oo"                                        # oo / oo+ / oob… 重开（可写/调试）
    r"|r(?:[0-9]|-|\+)|rpm|rm|rmrf|reset|rb|"
    r"r2|rabin\w*|radare2|radiff2|rafind2|rahash2|rasm2|ravc2|rax2"
    r"|L(?![?jq*])"                              # L <plugin> 加载插件＝执行外部代码
    r"|\.|-"                                      # `.` 跑脚本；`-` 开编辑器跑命令
    r"|P"                                          # 项目保存/加载（写文件）
    r"|m(?:w|g|-)"                                 # 写/导出 r2fs
    r"|yy|yw|yf|ytf|y!"                            # 剪贴板粘贴/导出
    r"|z-|zo"
    r"|C-|CC!|Cr"
    r"|t-|to|td"
    r"|f-|fd-"
    r"|ed|ee|er|e!"
    r"|d(?!\?)"                                     # 调试：continue/step 会跑目标
    r")")

# 带参数就成了写入/变更的命令（无参数时是只读查询）：
#   `r` 显示文件长度 / `r 100` 把文件 resize 到 100 字节。
R2_ARG_ONLY_READONLY_HEADS = frozenset((
    "r", "rj", "rh",   # `r 100` = resize（改文件）
    "f",               # `f name 12 @ 33` = 在会话里设 flag（无参才是列 flag）
))

# 参数（首 token 之后）允许的字符集：地址/符号/长度/分隔/过滤。
# 故意**不含 `=`**：`e x=y` / `k foo=bar` 是设置而不是查询。
R2_ARG_CHARS_RE = re.compile(r"^[A-Za-z0-9_.:@+\-*/~?\[\]% ,]*$")


def _r2_head_candidates(token: str) -> list:
    """从首 token 归一出一组候选 head（处理 `pdf@main` / `afl~foo` / `s.` / `iS.` / `afl*`）。"""
    raw = str(token or "").strip()
    if not raw:
        return []
    head = re.split(r"[~@\s]", raw, 1)[0]
    cands = [head]
    if head.endswith("*"):
        cands.append(head.rstrip("*"))
    if "." in head:
        cands.append(head.split(".", 1)[0])
    return [c for c in dict.fromkeys(cands) if c]


def r2_readonly_command_check(command):
    """校验「已审核只读 r2 命令」→ (原因, 违规 token 列表, kind)。原因为空串 = 通过。

    `kind` 只用于结构化拒绝的分类（shell_or_redirect / mutation_or_exec /
    unknown_syntax / malformed），**不是**判定依据：判定只有白名单 + 硬拒字符 +
    二次 deny 家族 + 显式分段。

    失败时**不回显原命令**（只回归一后的首 token），调用方可把原因直接写进结构化
    拒绝而不泄露用户输入。
    """
    if not isinstance(command, str):
        return "命令必须是字符串", ["type"], "malformed"
    text = command.strip()
    if not text:
        return "命令不能为空", ["empty"], "malformed"
    if len(text) > R2_COMMAND_MAX_LEN:
        return "命令过长（≤%d）" % R2_COMMAND_MAX_LEN, ["length"], "malformed"
    hits = []
    for ch in R2_FORBIDDEN_CHARS:
        if ch in text:
            label = chr(ord(ch)) if ord(ch) >= 32 else "U+%04X" % ord(ch)
            hits.append("forbidden-char:" + label)
    if hits:
        return ("拒绝 shell/重定向/命令链/变量展开字符（只接受已审核只读语法）",
                hits, "shell_or_redirect")
    segments = text.split(";")
    if len(segments) > R2_COMMAND_MAX_SEGMENTS:
        return ("命令段数超限（≤%d）" % R2_COMMAND_MAX_SEGMENTS,
                ["segments"], "malformed")
    for segment in segments:
        seg = segment.strip()
        if not seg:
            # `aaa;;x` / 结尾 `;` / 前导 `;` 都拒绝：空白分隔不能当第二命令用。
            return ("命令段不能为空（多命令只用 `;` 显式分段，且每段都要合法）",
                    ["empty-segment"], "malformed")
        parts = seg.split(None, 1)
        token, rest = parts[0], (parts[1] if len(parts) > 1 else "")
        cands = _r2_head_candidates(token)
        head = cands[0] if cands else token
        if R2_MUTATING_HEAD_RE.match(head):
            return ("只读入口不接受写入/重开写模式/变更/执行类命令",
                    [head], "mutation_or_exec")
        # 这些 head 不带参数是查询，带参数就是写入/变更（`r 100`=resize、`f x 1 2`=设 flag）。
        if set(cands) & R2_ARG_ONLY_READONLY_HEADS and (rest or "").strip():
            return ("该命令带参数时为写入/变更（如 r 100 = resize），本入口只接受无参查询",
                    [head], "mutation_or_exec")
        if not any(c in R2_READONLY_HEADS for c in cands):
            return ("未审核为只读的命令（不是黑名单猜测：请用 afl/iz/i*/pdf/pd/axt 等"
                    "已审核只读命令）", [head], "unknown_syntax")
        tail = (token[len(head):] if token.startswith(head) else "") + (
            (" " + rest) if rest else "")
        if not R2_ARG_CHARS_RE.match(tail):
            return ("参数含未审核字符（只接受地址/符号/长度/过滤；`=` 赋值需走 e/k 专场）",
                    [head], "unknown_syntax")
    return "", [], ""


def r2_readonly_error(tool: str, problem: str, tokens=None, kind: str = "") -> str:
    """`seep_r2_cmd` 的只读拒绝出口：结构化 JSON（ok=False），不回显原命令。"""
    return json.dumps({
        "ok": False, "error": "read_only_violation", "blocked_at": tool,
        "kind": kind or "unknown_syntax", "reason": problem, "tokens": list(tokens or [])[:8],
        "hint": "seep_r2_cmd 只接受**已审核只读**的 r2 语法（afl / iz / i* / pdf / pd / "
                "axt / px / s / ? 等，多条用 `;` 分段）。写入、重定向、`!` shell、"
                "插件加载、脚本执行一律拒绝；要修改目标请走带 MANIFEST/回滚的专用补丁流程。",
    }, ensure_ascii=False, indent=2)


# === SEEP-EXT: kb-colloquial BEGIN ===
# 口语检索层（2026-11）：用户说「加壳了怎么脱」，库里写的是 unpack / packer / OEP。
# 三层通用机制（不写死任何查询串）：
#   1) 别名展开：Tool/config/kb-synonyms.json 把口语片段映射成 KB 正文里真实出现的术语；
#   2) CJK 2-gram：中文没空格，整词/整串都打不中时用双字切片兜底（权重低于整词）；
#   3) boost_paths（别名组声明的优先目录/文件加权）；空结果给 3 条最近邻 + 为什么近。
_MCP_DIR = os.path.dirname(os.path.abspath(__file__))
_KB_SYN_PATH = os.path.join(os.path.dirname(_MCP_DIR), "config", "kb-synonyms.json")
KB_SYN_CACHE = {"mtime": None, "groups": [], "stopwords": []}
KB_CJK_RUN_RE = re.compile("[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]+")
KB_ASCII_TOKEN_RE = re.compile(r"^[a-z0-9_\-]+$")


def kb_load_synonyms():
    """载入别名表（按 mtime 缓存）。表缺失/损坏 → 退化成纯 2-gram，不抛异常。"""
    try:
        mtime = os.path.getmtime(_KB_SYN_PATH)
    except OSError:
        return [], []
    if KB_SYN_CACHE["mtime"] == mtime:
        return KB_SYN_CACHE["groups"], KB_SYN_CACHE["stopwords"]
    groups, stopwords = [], []
    try:
        with open(_KB_SYN_PATH, encoding="utf-8") as fh:
            cfg = json.load(fh)
        groups = [g for g in cfg.get("groups", []) if isinstance(g, dict) and g.get("terms")]
        stopwords = [w for w in cfg.get("stopwords", []) if isinstance(w, str) and w]
    except Exception:  # noqa: BLE001 —— 别名表坏了不能让检索整体不可用
        groups, stopwords = [], []
    KB_SYN_CACHE.update({"mtime": mtime, "groups": groups, "stopwords": stopwords})
    return groups, stopwords


def kb_normalize_query(query: str, stopwords) -> str:
    """去疑问词/语气词 + 统一分隔符。只清疑问词，实词一个不动。"""
    s = (query or "").lower()
    for w in stopwords:
        if w:
            s = s.replace(str(w).lower(), " ")
    return re.sub(r"[\s,;/|、，。；：!?()（）\[\]【】“”\"'`~@#$%^&*+=<>{}]+", " ", s).strip()


def kb_cjk_bigrams(norm: str):
    """CJK 双字切片（2-gram）。ASCII 词不切：它们自带词边界。"""
    grams, seen = [], set()
    for run in KB_CJK_RUN_RE.findall(norm or ""):
        for i in range(len(run) - 1):
            g = run[i:i + 2]
            if g not in seen:
                seen.add(g)
                grams.append(g)
    return grams


def kb_alias_expand(norm: str, groups):
    """口语 → 术语：(terms, boost_paths, fired_groups)。多组同时触发时术语**轮流**取
    （不是第一组吃满配额）——一句话说几件事（"免杀+后门+卡密"）时每组都有词上榜。"""
    per_group, boosts, fired = [], [], []
    for g in groups:
        says = [str(s).strip().lower() for s in g.get("say", []) if str(s).strip()]
        hit_says = [s for s in says if s in norm]
        if not hit_says:
            continue
        fired.append({"id": str(g.get("id", "")), "say": hit_says[:3]})
        gterms = [str(t).strip().lower() for t in g.get("terms", []) if str(t).strip()]
        if gterms:
            per_group.append(list(dict.fromkeys(gterms)))
        for p in g.get("boost_paths", []) or []:
            p = str(p).strip().lower().replace("\\", "/")
            if p and p not in boosts:
                boosts.append(p)
    terms = []
    for _round in range(max((len(x) for x in per_group), default=0)):
        for _g in per_group:
            if _round < len(_g) and _g[_round] not in terms:
                terms.append(_g[_round])
    return terms, boosts, fired


def kb_hit_count(low: str, tok: str) -> int:
    """术语命中次数：ASCII 用词边界（EAC 不该命中 each/reach），CJK 用子串。

    先做子串预筛：绝大多数 token 在大多数文章里根本不出现，省掉几千次正则。
    """
    if not tok or tok not in low:
        return 0
    if KB_ASCII_TOKEN_RE.match(tok):
        return len(re.findall(r"(?<![a-z0-9_])" + re.escape(tok) + r"(?![a-z0-9_])", low))
    return low.count(tok)
# === SEEP-EXT: kb-colloquial END ===

def byte_len(payload: str) -> int:
    return len((payload or "").encode("utf-8", "replace"))


def resource_constraint(tool: str, payload: str, continuation: str,
                        artifact_hint: str = "") -> str:
    """超预算的唯一出口：结构化拒绝 + 续读方式。"""
    return json.dumps({
        "ok": False, "error": "resource_constraint", "blocked_at": tool,
        "bytes": byte_len(payload), "chars": len(payload or ""),
        "budget_bytes": RESULT_BUDGET_BYTES, "budget_chars": RESULT_BUDGET_CHARS,
        "continuation": continuation,
        "artifact_hint": artifact_hint or "输出未截断：缩小 target / 换 output_mode / 用 offset 分页后重读",
    }, ensure_ascii=False, indent=2)


def budget_gate(tool: str, payload: str, continuation: str, budget_chars: int = 0) -> str:
    """在预算内原样返回；超限返回 resource_constraint（绝不截断）。"""
    if byte_len(payload) > RESULT_BUDGET_BYTES:
        return resource_constraint(tool, payload, continuation)
    if budget_chars and budget_chars > 0 and len(payload) > budget_chars:
        return resource_constraint(tool, payload, continuation)
    return payload


def empty_output(tool: str, hint: str = "", diagnostics=None) -> str:
    """空输出不是成功；保留 rc/stdout/stderr/output_dir 等排障事实。

    旧实现只返回错误名与提示，调用方看不到原始 return code、stderr 或已生成的
    artifact。外部工具失败时，这会把可恢复的“部分产出”和被依赖的报错原因
    一并丢掉。``diagnostics`` 只接受 JSON 可序列化的字典并原样放进
    ``diagnostics`` 字段；不能序列化时退回 ``repr``，保证错误出口本身不崩。
    """
    payload = {
        "ok": False, "error": "empty_output", "blocked_at": tool,
        "hint": hint or "命令跑完了但零输出：先确认 target / 命令拼写，不要当成功处理",
    }
    if diagnostics is not None:
        try:
            json.dumps(diagnostics, ensure_ascii=False)
            payload["diagnostics"] = diagnostics
        except (TypeError, ValueError):
            payload["diagnostics"] = {"unserializable": repr(diagnostics)[:1000]}
    return json.dumps(payload, ensure_ascii=False, indent=2)


def is_err_payload(payload: str) -> str:
    """r2 把错误打到 stdout（如 "ERROR: Invalid tmpseek address 'main'"）：当空态，别冒充结果。"""
    for line in (payload or "").splitlines():
        t = line.strip()
        if t.lower().startswith(("error", "fatal", "cannot", "[error",
                                 "[stderr]: error", "[stderr]: fatal", "[stderr]: cannot")):
            return t
    return ""


def r2_focus_output(tool: str, target: str, lines: list[str], mode: str):
    """Filter validated r2 text without promoting a header-only output to success."""
    if mode == "branch":
        keywords = ("cmp ", "test ", "je ", "jne ", "jz ", "jnz ", "jb ", "jbe ",
                    "ja ", "jae ", "jl ", "jle ", "jg ", "jge ", "jmp ", "call ",
                    "ret", "jcc", "cbz ", "cbnz ", "bl ", "bne ", "beq ")
        selected = [line for line in lines if any(word in line.lower() for word in keywords)]
    elif mode == "fold":
        keywords = ("if ", "else", "switch", "case ", "return", "while ", "for ",
                    "do {", "goto ", "break", "continue", "call ", "(", "->")
        selected = [line for line in lines if line.strip().startswith("//")
                    or any(word in line.strip() for word in keywords)]
    else:
        raise ValueError("unsupported r2 focus mode")
    if not any(line.strip() for line in selected):
        return None, empty_output(tool, mode + " 模式未匹配到控制流或调用，使用 output_mode='full' 检查原始输出")
    header = (f"[{mode.upper()} MODE — 已过滤 {len(lines) - len(selected)}/{len(lines)} 行]\n"
              f"Target: {target} | 保留行: {len(selected)} | 完整输出请用 output_mode='full'\n"
              "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
    return header + "\n".join(selected), None


def page_footer(shown: int, total: int, tool: str, howto: str) -> str:
    """分页脚注：不是"被削的证据"，是明确的续读指针。"""
    return "[PAGE] 本次返回 %d / %d 条 —— 续读方式：%s（%s）" % (shown, total, howto, tool)


# ---------------------------------------------------------------------------
# pcap 提取执行契约（`seep_pcap_extract` 的唯一判据来源）
#
# 独立复核结论（旧实现三处硬伤）：
#   ① `return (p.stdout or "") + (p.stderr or "")` —— 忽略 `returncode`，并把两路
#      输出拼成一个串；于是 tshark 的告警行（"Running as user root ..."）会被当成
#      TCP 会话/HTTP 行，rc≠0 也能包装成"解析成功"。
#   ② argv 是 `[tshark, "-r", pcap]`，**没有 `-n`**：tshark 默认做名称解析，读一个
#      本地抓包也会触发 DNS/反查 —— 这正是"读文件"被误判成"联网动作"的来源。
#   ③ 空数据与工具崩溃同形（都是"看起来没行"），zero_results 无法与 error 区分。
#
# 现在：主服务每条调用固定 `-n -r <bound 绝对路径>`，本层只做纯函数判定：
#   参数枚举/整数/文本校验 → 执行记录（argv/rc/stdout/stderr 分开）→ 状态推导
#   （ok / partial / zero_results / error / unknown）→ 显式分页口径。
# ---------------------------------------------------------------------------
PCAP_MODES = ("summary", "http", "payload")
PCAP_PORT_RANGE = (0, 65535)
PCAP_MAX_ROWS_RANGE = (1, 10000)
PCAP_HOST_FILTER_MAX = 512
PCAP_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
# `tshark -q -z conv,tcp` 的数据行形如 `10.0.0.1:1234  <-> 10.0.0.2:80 ...`；
# 表头/分隔线（含 `|  <->  |` 方向列）不是会话，必须排除（否则空 pcap 也"有结果"）。
PCAP_CONV_ROW_RE = re.compile(r":\d+\s+<->\s+\S")
PCAP_WARNING_MAX_LINES = 40
# 实时抓包/接口选择类参数：出现任何一个都不能再声称"只读本地文件、不联网"。
PCAP_LIVE_CAPTURE_FLAGS = ("-i", "-I", "--capture", "--interface", "-D", "-L", "-w")
PCAP_FIELDS = {"summary": ("tcp_conversations", "http_hosts"),
               "http": ("http_rows",), "payload": ("payload_rows",)}

# 固定的 "-Y/-T/-e" 参数表：这些串只由本模块按 mode/port 派生，**不从调用方拼接**。
# 真正起进程的 argv（`[tshark, "-n", "-r", bound_path] + 本表`）留在主服务实现体内。
_PCAP_TCP_CONV = ["-q", "-z", "conv,tcp"]
_PCAP_HTTP_HOSTS = ["-Y", "http.host", "-T", "fields", "-e", "http.host",
                    "-e", "http.request.uri"]
_PCAP_HTTP_ROWS = ["-Y", "http.request or http.response", "-T", "fields",
                   "-e", "ip.dst", "-e", "http.request.method", "-e", "http.host",
                   "-e", "http.request.uri", "-e", "http.response.code",
                   "-e", "http.content_type"]
PCAP_NOTES = {
    "summary": "有外连 = 云端权威可能。下一步：mode='http' 看请求/响应，或 mode='payload' 看端口载荷。",
    "http": "http_rows 每行是 tshark 字段制表串（6 列），与旧版字段一致。",
    "payload": "data.data 为十六进制载荷，可据此还原协议/伪造回包。",
}


def pcap_queries(mode, port=0):
    """按 mode[+port] 返回 [(字段名, 固定 tshark 参数), ...]（纯函数，不读盘不 spawn）。"""
    if mode == "summary":
        return [("tcp_conversations", list(_PCAP_TCP_CONV)),
                ("http_hosts", list(_PCAP_HTTP_HOSTS))]
    if mode == "http":
        return [("http_rows", list(_PCAP_HTTP_ROWS))]
    if mode == "payload":
        filt = ("tcp.port==%d" % int(port)) if port else "tcp.len>0"
        return [("payload_rows", ["-Y", filt, "-T", "fields", "-e", "ip.src",
                                  "-e", "tcp.srcport", "-e", "ip.dst", "-e", "tcp.dstport",
                                  "-e", "tcp.len", "-e", "data.data"])]
    raise ValueError("unknown pcap mode")


def pcap_params(mode, port, max_rows, host_filter):
    """pcap 三模式的参数校验（**先于**任何文件/进程访问；MCP 直调也走这里）。

    返回 (params, reason)：`reason` 是给人看的原因串，且**不含被拒的原值**
    （被拒的 mode/host_filter 可能带注入载荷，回显等于二次污染日志）。
    合法数字字符串（`"60"`）照旧接受 —— 这是 main 已裁定的口径。
    """
    if not isinstance(mode, str) or mode not in PCAP_MODES:
        return None, "mode 只接受 %s（枚举，区分大小写）" % " / ".join(PCAP_MODES)
    reason = int_range_error("port", port, *PCAP_PORT_RANGE)
    if reason:
        return None, reason
    reason = int_range_error("max_rows", max_rows, *PCAP_MAX_ROWS_RANGE)
    if reason:
        return None, reason
    if host_filter is None:
        host_filter = ""
    if not isinstance(host_filter, str):
        return None, "host_filter 只接受字符串（仅对结果行做子串过滤，绝不进命令行）"
    if len(host_filter) > PCAP_HOST_FILTER_MAX:
        return None, "host_filter 过长（≤%d 字符）" % PCAP_HOST_FILTER_MAX
    if PCAP_CONTROL_RE.search(host_filter):
        return None, "host_filter 含控制字符（只接受可打印的纯文本过滤）"
    return {"mode": mode, "port": int(port), "max_rows": int(max_rows),
            "host_filter": host_filter}, ""


def pcap_execution(argv, rc=None, stdout="", stderr="", timeout=False, error=""):
    """一次 tshark 调用的执行记录：argv / rc / stdout / stderr **分开**保留。

    `ok` 只由「rc==0 且无 timeout/error」推出：stderr 不参与"是否成功"判定
    （rc==0 的告警不该拒数据），也绝不与 stdout 合并（合并后告警会变成数据行）。
    """
    return {"argv": [str(a) for a in (argv or [])], "rc": rc,
            "stdout": stdout or "", "stderr": stderr or "",
            "timeout": bool(timeout), "error": error or "",
            "ok": (not timeout) and not error and rc == 0}


def pcap_status(executions, raw_rows, returned_rows=None):
    """由执行记录 + 真实行数推导整体状态，返回 (status, reason)。

    * 没有执行记录 → (unknown, no_execution)；
    * 任一 timeout   → 有数据=partial，无数据=error；
    * 任一调用失败（rc≠0 / 抛错）→ 有数据=partial，无数据=error（**绝不 ok**）；
    * 全部 rc==0 且过滤后 0 行 → (zero_results, no_rows)；
    * 全部 rc==0、行都在但被 host_filter 全滤掉 → (zero_results, filtered_out)；
    * 全部 rc==0 且有行 → (ok, ok)（stderr 的 warning 不降级）。

    `partial` 的定义是"拿到一部分数据但整次调用没跑全"，因此它**不是** success，
    调用方仍要能把已得数据与执行记录一起看见。
    """
    records = list(executions or [])
    if returned_rows is None:
        returned_rows = raw_rows
    if not records:
        return "unknown", "no_execution"
    if any(record.get("timeout") for record in records):
        return ("partial" if returned_rows else "error"), "timeout"
    if any(record.get("ok") is not True for record in records):
        return ("partial" if returned_rows else "error"), "call_failed"
    if not raw_rows:
        # rc==0 但 stdout 空、stderr 有内容：只拿到错误/告警文本，不能声称"抓包为空"。
        # 与"真的空 pcap"（stdout/stderr 都干净）分开，两者都不是成功。
        if any(str(record.get("stderr") or "").strip() for record in records):
            return "unknown", "stderr_only"
        return "zero_results", "no_rows"
    if not returned_rows:
        return "zero_results", "filtered_out"
    return "ok", "ok"


def pcap_filter_rows(lines, host_filter=""):
    """结果行过滤：只做纯文本子串匹配（host_filter **从不**进 argv）。"""
    rows = [line for line in (lines or []) if str(line).strip()]
    if not host_filter:
        return rows
    return [line for line in rows if host_filter in line]


def pcap_rows(field, stdout_text, host_filter="", max_rows=0):
    """把一次 tshark 的 **stdout** 解析成某字段数据行，返回 (rows, total, prefilter)。

    * `rows`      = 过滤 + 分页后真正返回的行；
    * `total`     = host_filter 之后、分页之前的真实行数（分页口径的"总数"）；
    * `prefilter` = host_filter 之前的候选行数 —— 用它才能把"抓包里就没这东西"
      (`zero_results/no_rows`) 和"被过滤全灭"(`zero_results/filtered_out`) 分开。

    stderr 不参与解析：它只进执行记录与 `warnings` 摘录。
    """
    lines = pcap_filter_rows(str(stdout_text or "").splitlines(), "")
    if field == "tcp_conversations":
        lines = [line for line in lines if PCAP_CONV_ROW_RE.search(line)]
    prefilter = len(lines)
    if host_filter:
        lines = [line for line in lines if host_filter in line]
    total = len(lines)
    if max_rows and int(max_rows) > 0:
        return lines[:int(max_rows)], total, prefilter
    return lines, total, prefilter


def pcap_warnings(executions):
    """rc==0 的调用里 stderr 的告警行要保留（有告警 ≠ 无数据，不因 warning 一律拒）。

    返回 {lines, truncated, total_lines}。完整 stderr 始终在各条 `executions` 里，
    这里只是给人看的摘录，因此被截断时**显式**标 truncated（不是静默丢证据）。
    """
    lines = []
    for record in executions or []:
        if record.get("timeout") or record.get("rc") != 0:
            continue
        for line in str(record.get("stderr") or "").splitlines():
            if line.strip():
                lines.append(line.strip())
    return {"lines": lines[:PCAP_WARNING_MAX_LINES],
            "truncated": len(lines) > PCAP_WARNING_MAX_LINES,
            "total_lines": len(lines)}


def pcap_no_network(executions):
    """`no_network` 只能由 argv 推导，不能是一句空宣言。

    每条调用都必须带 `-n`（禁用名称解析），且不得出现实时抓包/接口选择参数。
    没有执行记录时返回 False（没跑过就别说没联网）。
    """
    records = list(executions or [])
    if not records:
        return False
    for record in records:
        argv = [str(a) for a in (record.get("argv") or [])]
        if "-n" not in argv:
            return False
        for flag in PCAP_LIVE_CAPTURE_FLAGS:
            if flag in argv:
                return False
    return True


def pcap_failure(tool, status, error, detail, hint=""):
    """pcap 工具的结构化失败信封（ok=False），不回显被拒/缺失的原始路径与参数值。

    `detail` 以 `[ERROR]` 开头是仓库既有惯例（既有自测/工具契约都把 `[ERROR]`
    当“工具没成”的标记）；结构化字段 `ok/status/error` 才是判据。
    """
    return json.dumps({
        "ok": False, "status": status, "has_result": False, "error": error,
        "blocked_at": tool, "executions": [], "warnings": [],
        "detail": "[ERROR] " + str(detail),
        "hint": hint or "先修正输入/依赖再重跑；拒绝结果不替路线背书",
    }, ensure_ascii=False, indent=2)


def pcap_envelope(tool, pcap_name, mode, executions, data, totals, note,
                  max_rows=0, extra=None, prefilters=None):
    """把「执行记录 + 各字段数据行」装成结果信封（兼容旧的字段名）。

    关键不变量：
      * `ok` 只在 status=="ok" 时为真；partial / zero_results / error / unknown 一律 False，
        `has_result` 同口径（status=="ok"），partial 的已得数据仍原样返回；
      * stderr 不混进 `data`，只出现在 `executions` 与 `warnings`（rc==0 的摘录）里；
      * `paging.total` 是过滤后、分页前的真实行数，`returned` 是本次返回条数，
        `truncated` 逐字段比较两者 —— max_rows 是显式分页，不是静默截断。
    `prefilters` 是 host_filter 之前的候选行数（用于区分 no_rows / filtered_out），
    缺省视为与 `totals` 相同。
    超预算由调用方用 `budget_gate` 拒绝并给 continuation，本函数不削证据。
    """
    records = list(executions or [])
    returned = {name: len(rows) for name, rows in data.items()}
    total = {name: int(totals.get(name, returned.get(name, 0))) for name in data}
    prefilter = ({name: int((prefilters or {}).get(name, total[name])) for name in data})
    status, reason = pcap_status(records, sum(prefilter.values()), sum(returned.values()))
    warnings = pcap_warnings(records)
    result = {
        "ok": status == "ok",
        "status": status,
        "reason": reason,
        "has_result": status == "ok",
        "partial": status == "partial",
        "pcap": pcap_name,
        "mode": mode,
        "executions": records,
        "warnings": warnings["lines"],
        "warnings_truncated": warnings["truncated"],
        "no_network": pcap_no_network(records),
        "paging": {"max_rows": max_rows, "returned": returned, "total": total,
                   "candidates": prefilter,
                   "truncated": {name: total[name] > returned[name] for name in data},
                   "howto": "调大 max_rows（≤10000），或先用 host_filter / port 缩小范围"
                            "再重跑（本工具不做静默截断）"},
        "note": note,
    }
    result.update({name: rows for name, rows in data.items()})
    if extra:
        result.update(extra)
    return json.dumps(result, ensure_ascii=False, indent=2)


def case_evidence_dir(task_name: str, case_dir: str, task_dir_fn, case_lib_dir_fn) -> str:
    """定位本案证据目录：显式 case_dir → 工作区任务目录 → Tool/cases/<task>。"""
    cands = [os.path.abspath(case_dir.strip())] if (case_dir or "").strip() else []
    for fn in (lambda: task_dir_fn(task_name),
               lambda: os.path.join(case_lib_dir_fn(),
                                    re.sub(r'[^\w\-]', '_', (task_name or "").strip()))):
        try:
            cands.append(fn())
        except Exception:
            pass
    for c in cands:
        if c and os.path.isfile(os.path.join(c, "facts.jsonl")):
            return c
    return ""


def strong_claim_ids(case_dir: str) -> list:
    """报告的**唯一**证据来源：status=proven + confidence∈{observed,derived} + 非空 evidence。"""
    out = []
    try:
        with open(os.path.join(case_dir, "facts.jsonl"), "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    o = json.loads(line)
                except Exception:
                    continue
                if not isinstance(o, dict):
                    continue
                if str(o.get("kind") or "claim").strip().lower() not in ("", "claim"):
                    continue
                if str(o.get("status") or "").strip().lower() != "proven":
                    continue
                if str(o.get("confidence") or "").strip().lower() not in STRONG_CONFIDENCE:
                    continue
                if any(str(e).strip() for e in (o.get("evidence") or [])):
                    out.append(str(o.get("id") or "?"))
    except Exception:
        return []
    return out


def missing_report_fields(task_name: str, target_name: str, description: str,
                          poc_summary: str, branch_location: str) -> list:
    """报告必填判据：占位值不算填了。"""
    miss = [n for n, v in (("task_name", task_name), ("target_name", target_name),
                           ("description", description), ("poc_summary", poc_summary))
            if not (v or "").strip()]
    if (branch_location or "").strip().lower() in REPORT_PLACEHOLDER_BRANCH:
        miss.append("branch_location")
    return miss


def build_report_md(task_name: str, target_name: str, vuln_type: str, branch_location: str,
                    description: str, poc_summary: str, defense_recommendation: str,
                    disasm_snippet: str, evidence_dir: str, strong: list, now_str: str) -> str:
    """报告正文：**五段**（结论 / 已确认 / 仍未知 / 下一步 / 复查），没有的东西写“未提供”。

    为什么是这五段：交付物只有一种格式。本函数出的 `.md` 必须能过
    `case_state.py report --check --file <产物>`（五段齐全 + 每段 ≥2 行 + 结论 ≤3 行 +
    已确认带 E-/C-/F- ID + 无禁用措辞）；旧版是另一套 6 段技术报告，客户拿到的两份
    交付物格式对不上（第 4 轮评审 P1-5）。

    保留的限制（不许煊）：本函数是**纯函数**（不读文件）——所以“复查”段给的是
    `recheck` 现算命令，不把哈希写死；反汇编/防御建议缺了就说缺了，绝不编造指令。
    """
    evdir = (evidence_dir or "").strip() or "<案例目录>"
    evfile = os.path.join(evdir, "facts.jsonl") if evdir != "<案例目录>" else "<案例目录>/facts.jsonl"
    ids = [str(i) for i in (strong or [])]

    remediation = (defense_recommendation or "").strip()
    used_generic = not remediation
    if used_generic:
        remediation = (
            "1. **服务端统一鉴权**：核心特权逻辑上云，客户端只做渲染；受限资源由服务端签发"
            "带时间戳与签名的凭据。\n"
            "2. **非对称签名防篡改**：离线场景用 RSA/ECC，客户端只留公钥验签，私钥在授权服务器。\n"
            "3. **内存完整性保护**：启用 `ProcessDynamicCodePolicy` 抑制动态内存写入，"
            "核心模块加代码段自校验哈希。")

    dis = (disasm_snippet or "").strip()
    disasm_block = ("```text\n%s\n```" % dis) if dis else (
        "（未提供反汇编摘录：本段不编造指令。用 r2/IDA 取到真实分支后再补 `disasm_snippet`。）")
    generic_note = "" if not used_generic else (
        chr(10) + "> 注：本节为通用加固建议，**未针对本目标逐条验证**。")

    # “仍未知”的输入侧缺口（与 missing_report_fields 分开：那四个字段缺了就不该出报告；
    # 这里只列「不出报告也能交、但必须在正文里承认没取」的部分）。
    unknown_input = []
    if not dis:
        unknown_input.append("反汇编摘录 `disasm_snippet`")
    if used_generic:
        unknown_input.append("针对本目标的防御建议 `defense_recommendation`（本节退化为通用建议，"
                             "**未逐条验证**）")
    if (branch_location or "").strip().lower() in REPORT_PLACEHOLDER_BRANCH:
        unknown_input.append("判定位点 `branch_location`（占位值，未取到真实位点）")
    unknown_txt = "、".join(unknown_input) if unknown_input else "必填字段之外无缺口（边界声明仍见下两行）"

    evidence_lines = "\n".join("- `%s`（proven / observed 或 derived / 带非空 evidence）" % i
                               for i in ids) or (
        "- （无强证据：本报告不该存在——先跑 `case_state.py verify --case %s`）" % evdir)

    return f"""# 软件安全评估与鉴权脆弱性走查报告

- **目标资产**: `{target_name}`
- **评估类型**: 白盒代码走查 / 客户端决策逻辑安全性验证
- **缺陷分类**: `{vuln_type}`
- **评估时间**: {now_str}
- **报告归属**: `{task_name}/reports/`
- **证据来源**: `{evfile}`

## 1 结论

- 已确认（可交付）：{len(ids)} 条结论，全部来自 facts.jsonl 的 proven + confidence 属 observed/derived + 非空 evidence；ID 逐条列在「已确认」段。
- 未确认（不得当结论）：本报告之外的一切都**未验证**，具体缺口逐条列在「仍未知」段。

## 2 已确认

- **目标资产**: `{target_name}`（归档于 `{task_name}/reports/`）
- **缺陷分类**: `{vuln_type}`；**判定函数 / 偏移位点**: `{branch_location}`
- **成因与影响**: {description}
- **PoC 与复现过程**: {poc_summary}
- **汇编指令与分支模式**:
{disasm_block}
- **证据明细（每一行都能在 `{evfile}` 找到对应 id；找不到即为无证据陈述）**:
{evidence_lines}

## 3 仍未知

- 输入侧未取（本次未取，**不代表不存在**）：{unknown_txt}
- 账本侧未证：facts.jsonl 里 status 不等于 proven、或 confidence 为 inferred/unknown 的条目全部不算结论。
- 覆盖边界：只覆盖「已确认」段这 {len(ids)} 条 ID；其他目标、其他版本、其他平台都未验证。

## 4 下一步

- 省事（先把账本补齐）：对每条缺口用 `python Tool/scripts/case_state.py claim --case {evdir} --id <新ID> --text "<实测结论>" --status proven --evidence "<实测输出>" --confidence observed --authority shipped-artifact` 落账，再重出报告。
- 彻底（补实测）：把 `{target_name}` 的其余判定位点用 r2/IDA 逐个取到反汇编、逐个跑通 PoC，让 `verify` 从 partial 走到 pass。
- 加固（纵深防护，随报告一起交）：
{remediation}{generic_note}

## 5 怎么复查

- 五段 + ID 对账：`python Tool/scripts/case_state.py report --check --file <本报告> --case {evdir}`
- 证据链：`python Tool/scripts/case_state.py verify --case {evdir}` —— 返回 `pass` 才算证据链完整；`fail` / `unknown` 时本报告不得作为交付依据。
- 接着做：`python Tool/scripts/case_state.py resume --case {evdir}`
- 目标哈希：`python Tool/scripts/case_state.py recheck --case {evdir}` 现算（本报告不写死哈希：换了 target 就必须重算）。
"""


# ── D1 · 工具效果登记审计（缺登记 → server 起不来）────────────────────────────
class MissingEffectAudit(RuntimeError):
    """有工具没在 tool-effects.json 登记：拒绝启动，而不是静默多给一个无标注的能力。"""


EFFECT_FIELDS = ("mutates_target", "writes_filesystem", "executes_foreign_code",
                 "touches_network", "may_discard_data")


def audit_tool_effects(tool_names, config_path):
    """比对 @server.tool() 集合与登记表；不一致抛 MissingEffectAudit。

    返回 name → annotations（MCP 语义：只读/破坏性/联网），供上层按需派生。
    """
    with open(config_path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    reg = doc.get("tools") or {}
    live, dead = set(tool_names), set(reg)
    missing, extra = sorted(live - dead), sorted(dead - live)
    bad_field = [n for n, e in reg.items()
                 if not isinstance(e, dict) or set(e) != set(EFFECT_FIELDS)]
    if missing or extra or bad_field:
        raise MissingEffectAudit(
            "tool-effects.json 与 @server.tool() 不一致 —— missing=%s extra=%s 字段不合规=%s"
            % (missing, extra, bad_field))
    ann = {}
    for name, e in reg.items():
        ann[name] = {
            "readOnlyHint": not (e["writes_filesystem"] or e["mutates_target"]
                                 or e["may_discard_data"]),
            "destructiveHint": bool(e["mutates_target"] or e["may_discard_data"]),
            "openWorldHint": bool(e["touches_network"]),
        }
    return ann
