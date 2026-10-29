#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tool/mcp/test_readonly_parameters.py —— 只读 MCP 工具的参数/路径边界回归。

范围（只测入口，不测业务算法）：
  1. `seep_r2_disasm` / `seep_r2_decompile` 的 `target` 在**工具函数入口**被校验：
     命令分隔符、换行、管道、重定向、反引号、`$()`、`!`、算式一律拒绝；合法
     `main` / `sym.imp.puts` / `sub_123` / `0x123` / 十进制地址通过。
     `lines` / `limit_tokens` / `output_mode` 的类型与范围同样在入口检查。
  2. `seep_kb_search` / `seep_kb_read` 的 `category` / `article_path` 被限制在
     真实 KB 根内（resolve + 根边界 + symlink）：`../`、绝对路径、Windows 盘符、
     UNC 全部拒绝，且**不读出根外内容**（用哨兵文件验证）。
  3. 两边（MCP 与 project_workflow.py）的 target 语法判定**同口径**（交叉对齐）。

约束：不执行任何 payload、不联网、不安装、不写仓库。
`_run_cmd` 一律被 spy 替换，只记录 argv；被拒绝的参数必须做到 **0 次 _run_cmd**。

用法：python -B -X utf8 Tool/mcp/test_readonly_parameters.py
退出码：0 全过 / 1 有断言失败 / 2 外部依赖缺失（UNVERIFIED，不计成功）
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
if os.path.join(ROOT, "Tool", "scripts") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "Tool", "scripts"))

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # pragma: no cover
        pass

try:
    import seep_mcp_server as S
except Exception as exc:  # pragma: no cover - 依赖缺失必须显式 skip，不当成功
    raise unittest.SkipTest("UNVERIFIED: 无法导入 seep_mcp_server（%s: %s）"
                            % (type(exc).__name__, exc))

BAD_TARGETS = (
    "entry0; !echo injected",
    "main;wx 90",
    "main\n!calc",
    "main | more",
    "main > out.txt",
    "main < in.txt",
    "main `id`",
    "main $(id)",
    "main $HOME",
    "main && calc",
    "main & calc",
    "main+0x10",
    "main-1",
    "main*2",
    "0x123+4",
    "main @ 0x10",
    "sym.imp.puts\ttail",
    "  main",
    "main ",
    "../outside",
    "..//..//etc",
    "/bin/sh",
    "C:/Windows/system32",
    "main;",
    "main'",
    'main"',
    "main\\x00",
    "main{}",
    "main[0]",
    "#comment",
)

GOOD_TARGETS = ("main", "sym.imp.puts", "sub_123", "0x123",
                "0x401000", "4198400", "entry0", "_start", "obj.__x")


class R2TargetGrammar(unittest.TestCase):
    """target 语法：MCP 入口拒绝畸形串，合法串照旧可用。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="readonly-params-")
        self.addCleanup(self.tmp.cleanup)
        self.base = self.tmp.name
        self.binary = os.path.join(self.base, "target.bin")
        with open(self.binary, "wb") as fh:
            fh.write(b"\x7fELF" + b"\x00" * 64)
        self.recorded = []
        self._real_run_cmd = S._run_cmd
        S._run_cmd = self._spy

    def tearDown(self):
        S._run_cmd = self._real_run_cmd

    def _spy(self, cmd, **_kwargs):
        self.recorded.append(list(cmd))
        return "fake-parser-output"

    def test_bad_targets_are_refused_without_building_an_r2_command(self):
        for bad in BAD_TARGETS:
            for fn in (S.seep_r2_disasm, S.seep_r2_decompile):
                out = fn(binary_path=self.binary, target=bad)
                payload = json.loads(out)
                self.assertFalse(payload.get("ok"), (fn.__name__, bad, out[:200]))
                self.assertEqual(payload.get("error"), "invalid_parameters",
                                 (fn.__name__, bad, out[:200]))
                self.assertNotIn(bad.strip(), out,
                                 "the refusal must not echo the rejected target")
        self.assertEqual(self.recorded, [],
                         "a rejected target must never reach the r2 command line")

    def test_good_targets_build_a_single_pinned_command(self):
        for good in GOOD_TARGETS:
            self.recorded.clear()
            devnull = S.seep_r2_disasm(binary_path=self.binary, target=good,
                                       output_mode="full")
            dev = S.seep_r2_decompile(binary_path=self.binary, target=good,
                                      output_mode="full")
            self.assertNotIn("invalid_parameters", devnull, good)
            self.assertNotIn("invalid_parameters", dev, good)
            self.assertTrue(self.recorded, "a legitimate target must reach r2")
            for cmd in self.recorded:
                self.assertIn("-c", cmd)
                command = cmd[cmd.index("-c") + 1]
                self.assertIn(" @ " + good, command, command)
                self.assertNotIn(";!", command)
            first = self.recorded[0]
            self.assertEqual(first[first.index("-c") + 1], "aaa; pdf @ " + good)

    def test_integer_and_enum_parameters_are_checked_at_the_entry(self):
        bad_calls = (
            {"lines": "abc"},
            {"lines": 0},
            {"lines": -5},
            {"lines": 10 ** 9},
            {"lines": True},
            {"limit_tokens": -1},
            {"limit_tokens": "many"},
            {"output_mode": "everything"},
            {"output_mode": "full; !calc"},
        )
        for kwargs in bad_calls:
            out = S.seep_r2_disasm(binary_path=self.binary, target="main", **kwargs)
            self.assertIn("invalid_parameters", out, (kwargs, out[:200]))
        for kwargs in ({"limit_tokens": -1}, {"output_mode": "nope"}):
            out = S.seep_r2_decompile(binary_path=self.binary, target="main", **kwargs)
            self.assertIn("invalid_parameters", out, (kwargs, out[:200]))
        self.assertEqual(self.recorded, [], "invalid scalars must not reach r2")

    def test_grammar_is_the_same_in_the_workflow_entry(self):
        """两侧语法必须同口径：MCP 接受的，workflow 也接受；反之亦然。"""
        try:
            import project_workflow as W
        except Exception as exc:  # pragma: no cover
            self.skipTest("UNVERIFIED: 无法导入 project_workflow（%s）" % exc)
        for bad in BAD_TARGETS:
            self.assertTrue(S.r2_target_error(bad), bad)
            self.assertTrue(W.r2_target_error(bad), bad)
        for good in GOOD_TARGETS:
            self.assertEqual(S.r2_target_error(good), "", good)
            self.assertEqual(W.r2_target_error(good), "", good)


class KbPathBoundary(unittest.TestCase):
    """KB category / article_path：只能落在真实 KB 根内（含 symlink 判定）。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="readonly-kb-")
        self.addCleanup(self.tmp.cleanup)
        self.base = self.tmp.name
        self.sentinel = os.path.join(self.base, "SENTINEL_KB_ESCAPE.md")
        with open(self.sentinel, "w", encoding="utf-8") as fh:
            fh.write("# SENTINEL_KB_ESCAPE_TOKEN\nsecret body\n")
        self.marker = "SENTINEL_KB_ESCAPE_TOKEN"

    def _rel_to_kb(self, absolute: str) -> str:
        return os.path.relpath(absolute, S.KB_DIR).replace(os.sep, "/")

    def test_traversal_and_absolute_paths_are_refused_without_reading(self):
        escapes = [
            self._rel_to_kb(self.sentinel),
            "../../../../" + os.path.basename(self.sentinel),
            "/etc/passwd",
            "//server/share/file.md",
            "C:/Windows/win.ini",
            "c:\\Windows\\win.ini",
            "..\\..\\secret.md",
            "general/../../../../OUTSIDE.md",
        ]
        for rel in escapes:
            out = S.seep_kb_read(article_path=rel)
            payload = json.loads(out)
            self.assertEqual(payload.get("error"), "invalid_parameters", (rel, out[:200]))
            self.assertNotIn(self.marker, out, "an escape must never read the sentinel")
        for category in ("../../..", "../", "/etc", "C:/Windows", "//host/share",
                         "..\\..", "a/../../b"):
            out = S.seep_kb_search(query="jwt", category=category)
            payload = json.loads(out)
            self.assertEqual(payload.get("error"), "invalid_parameters",
                             (category, out[:200]))
            self.assertNotIn(self.marker, out)

    def test_symlink_out_of_the_kb_root_is_refused(self):
        link = os.path.join(S.KB_DIR, "zzz-readonly-params-link.md")
        created = False
        try:
            if os.path.lexists(link):
                self.skipTest("UNVERIFIED: 临时 symlink 路径已被占用")
            os.symlink(self.sentinel, link) if hasattr(os, "symlink") else None
            created = os.path.lexists(link)
        except (OSError, NotImplementedError, AttributeError):
            created = False
        if not created:
            self.skipTest("UNVERIFIED: 当前环境不允许创建 symlink（需管理员/开发者模式）")
        try:
            out = S.seep_kb_read(article_path="zzz-readonly-params-link.md")
            self.assertNotIn(self.marker, out, "a symlink out of the KB root must not be read")
            payload = json.loads(out)
            self.assertEqual(payload.get("error"), "invalid_parameters", out[:200])
        finally:
            try:
                os.unlink(link)
            except OSError:
                pass

    def test_legitimate_kb_access_still_works(self):
        hits = json.loads(S.seep_kb_search(query="JWT", limit=3))
        self.assertIsInstance(hits, list)
        self.assertTrue(hits, "a real term query must still return hits")
        self.assertTrue(hits[0].get("path"))
        # 正常的分类限定仍然可用（不因边界检查而误禁）
        scoped = json.loads(S.seep_kb_search(query="jwt", category="ctf-website", limit=2))
        self.assertIsInstance(scoped, list)
        body = S.seep_kb_read(article_path=hits[0]["path"], max_chars=600)
        self.assertNotIn('"invalid_parameters"', body[:200])
        self.assertTrue(body.strip())

    def test_zero_match_is_not_reported_as_ok(self):
        out = S.seep_kb_search(query="synthetic-no-hit-zqxv-<&>-000", limit=1)
        payload = json.loads(out)
        self.assertFalse(payload.get("ok"), "zero hits must not report ok=true")
        self.assertEqual(payload.get("status"), "zero_match")
        self.assertEqual(payload.get("hits"), [])
        self.assertIn("zero_match", payload.get("hint", ""))

    def test_empty_and_oversized_scalars_are_refused(self):
        for kwargs in ({"query": ""}, {"query": "   "}, {"query": "x", "limit": 0},
                       {"query": "x", "limit": 10 ** 6}, {"query": "x", "limit": "many"}):
            payload = json.loads(S.seep_kb_search(**kwargs))
            self.assertEqual(payload.get("error"), "invalid_parameters", (kwargs, payload))
        for value in (0, -1, "many", 10 ** 9):
            payload = json.loads(S.seep_kb_read(
                article_path="general/techniques/methodology/01-reverse-checklist-first-30-min.md",
                max_chars=value))
            self.assertEqual(payload.get("error"), "invalid_parameters", (value, payload))


class R2ReadOnlyCommandGrammar(unittest.TestCase):
    """`seep_r2_cmd` 只接受**已审核只读**语法（独立验收 §3.1 refuted 的关闭负例）。

    旧实现只看每段首 token 是否 `w*` / `o+` / `oo+`，于是 `!id`（r2 起系统 shell）、
    `pd 20 > out.txt`（r2 内建重定向写文件）、`aaa; C*`、`.` / `-`（跑脚本 / 开编辑器）、
    `L <plugin>`（加载插件＝执行外部代码）全部绕过，最后还能拼进 `-c`。

    现在判定是**白名单**（`seep_contract.r2_readonly_command_check`）+ 硬拒字符 +
    二次 deny 家族 + 显式分段；**校验在拼 `-c` 之前**，被拒时 `_run_cmd` 记录为 0。
    本测试**不执行任何 payload**：`_run_cmd` 一律被 spy 替换。
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="readonly-r2cmd-")
        self.addCleanup(self.tmp.cleanup)
        self.binary = os.path.join(self.tmp.name, "target.bin")
        with open(self.binary, "wb") as fh:
            fh.write(b"\x7fELF" + b"\x00" * 64)
        self.recorded = []
        self._real_run_cmd = S._run_cmd
        S._run_cmd = self._spy

    def tearDown(self):
        S._run_cmd = self._real_run_cmd

    def _spy(self, cmd, **_kwargs):
        self.recorded.append(list(cmd))
        return "fake-parser-output"

    def test_shell_redirect_chain_and_plugin_commands_are_refused(self):
        dangerous = [
            "!id",                       # r2 起系统 shell
            "!!id",
            "!touch pwned",
            "pd 20 > /tmp/r2out.txt",    # r2 内建重定向写文件
            "pd 20 < /etc/passwd",
            "pd 10 | more",              # 管道
            "iz && calc",                # 命令链
            "`id`",                      # 反引号展开
            "$(id)",
            "iz\nw hello",              # 换行 = 第二条命令
            "L /tmp/evil.so",            # 加载插件 = 执行外部代码
            "-i script.r2",              # 开编辑器跑脚本
            "-c x",
            ". script.r2",               # `.` 跑脚本
            "P saveme",                  # 项目保存（写文件）
            "w hello",                   # 写入
            "aaa; wx 90",
            "o+ /tmp/x",                 # 可写模式打开
            "oo+",
            "ood",                       # 重开（调试）
            "r 100",                     # resize（带参数的 r 是写入）
            "r+100",
            "mg /foo /tmp/x",            # r2fs 导出
            "mw /foo data",
            "yy @ 0x10",                 # 剪贴板粘贴
            "ytf /tmp/x",
            "z-evil",                    # 删除 zignature
            "t-foo",                     # 删除类型
            "to /tmp/evil.h",            # 从 C 头文件加载类型（IO）
            "ed",                        # 开 ~/.radare2rc 编辑器
            "e!cfg",
            "e asm.arch=x86",            # 赋值（不是查询）
            "k foo=bar",                 # sdb 写入
            "d",                         # 调试 continue
            "dc",
            "db 0x10",
            "rm /tmp/x",
            "rmrf /tmp",
            "cat /etc/passwd",           # 读任意宿主文件
            "ms /mnt",                   # 打开 r2fs shell
            "md /",                      # 浏览挂载的外部文件系统
            "mi /etc/shadow",
            "zf /tmp/x.sig",             # 读外部 FLIRT 签名文件
            "zfs /tmp/x.sig",
            "ks",                        # sdb 交互 shell
            "ko /tmp/x.sdb",
            "kd /tmp/x.sdb",
            "s++", "s--", "so 2",        # 会话内 seek 状态变更（不给只读查询增能力）
            "f evil 12 @ 33",            # 会话内设 flag（带参数的 f 是写入）
            "f. blah 12 @ 33",           # 会话内设 local label
            "b+3",
            "unknowncmd",                # 未审核首 token
            "aaa;;iz",                   # 空段（空白分隔不能当第二命令）
            "; iz",
            "iz;",
            "",                          # 空命令
        ]
        for command in dangerous:
            self.recorded.clear()
            out = S.seep_r2_cmd(binary_path=self.binary, command=command)
            payload = json.loads(out)
            self.assertEqual(payload.get("ok"), False, command)
            self.assertEqual(payload.get("error"), "read_only_violation",
                             (command, out[:200]))
            self.assertTrue(payload.get("kind"), (command, out[:200]))
            self.assertEqual(self.recorded, [],
                             "a refused command must never build an r2 argv: %r" % command)
        # 结构化拒绝不得回显原命令（只回违规 token 类别）。
        self.assertNotIn("pwned", S.seep_r2_cmd(binary_path=self.binary,
                                               command="!touch pwned"))

    def test_reviewed_readonly_commands_still_reach_the_parser(self):
        """正对照：技能/文档里常用的只读查询必须照旧可用（不是一律禁）。"""
        allowed = [
            "afl",                  # 函数列表
            "aaa; afl",             # 分析 + 列表
            "iz",                   # 数据段字符串
            "izz",                  # 全段字符串
            "iR",                   # 资源树（技能常用：换壳/资源载荷）
            "iI", "iE", "is", "iS", "it", "iij",
            "iS.",                  # 段列表（带点变体）
            "pdf @ main",           # 反汇编
            "pdc @ main",           # 反编译
            "pd 20 @ 0x1000",
            "px 64 @ 0x1000",
            "ps @ 0x10",
            "axt @ main",           # 交叉引用
            "axf @ main",
            "afl~sym.imp",          # ~ grep 过滤
            "iRj",
            "s main",               # 定位
            "b 64",                 # 块大小查询/设置（只影响本次会话）
            "e asm.arch",           # 查询（不带 =）
            "k anal/meta/foo",
            "r",                    # 无参 = 查文件长度
            "?v",                   # 版本
            "/ jwt",                # 搜索
        ]
        for command in allowed:
            self.recorded.clear()
            out = S.seep_r2_cmd(binary_path=self.binary, command=command)
            self.assertEqual(len(self.recorded), 1,
                             "%r should reach r2 exactly once, got %s"
                             % (command, out[:160]))
            argv = self.recorded[0]
            built = argv[argv.index("-c") + 1]
            self.assertIn(command, built)

    def test_analysis_prefix_is_pinned_and_not_taken_from_input(self):
        """`analyze=True` 时前缀固定 `aaa; `；不接受输入里自带的 shell 前缀。"""
        for command in ("!id", "pd 10 > out", "aaa; `id`", "w x"):
            self.recorded.clear()
            S.seep_r2_cmd(binary_path=self.binary, command=command)
            self.assertEqual(self.recorded, [], command)
        self.recorded.clear()
        S.seep_r2_cmd(binary_path=self.binary, command="afl")
        self.assertEqual(self.recorded[0][self.recorded[0].index("-c") + 1], "aaa; afl")
        self.recorded.clear()
        S.seep_r2_cmd(binary_path=self.binary, command="iz", analyze=False)
        self.assertEqual(self.recorded[0][self.recorded[0].index("-c") + 1], "iz")

    def test_workflow_and_mcp_share_the_command_grammar(self):
        """两侧命令语法必须同口径（workflow 侧委托同一份 contract 实现）。"""
        try:
            import project_workflow as W
        except Exception as exc:  # pragma: no cover
            self.skipTest("UNVERIFIED: 无法导入 project_workflow（%s）" % exc)
        for command in ("afl", "!id", "pd 20 > out.txt", "aaa; C*", "w hello",
                        "L /tmp/x.so", "r 100", "iS.", "afl~sym", "zzz"):
            self.assertEqual(W.r2_command_error(command) != "",
                             S._r2_write_tokens(command) != [], command)


class PcapEntryParameters(unittest.TestCase):
    """`seep_pcap_extract` 的参数边界：先于文件/进程访问，且不进入 argv。

    契约来源是 `seep_contract.pcap_params`（MCP 直调与入口共用同一份）；这里只钉
    MCP 侧行为：Inf / bool / 注入 / 越界一律结构化拒，且 **spawn 0 次**。
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="readonly-pcap-")
        self.addCleanup(self.tmp.cleanup)
        import struct
        self.pcap = os.path.join(self.tmp.name, "x.pcap")
        with open(self.pcap, "wb") as fh:
            fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        self.recorded = []
        self._real_run = S.subprocess.run
        self._real_which = S.shutil.which
        S.shutil.which = lambda name: "/usr/bin/tshark" if name == "tshark" else None
        S.subprocess.run = self._spy

    def tearDown(self):
        S.subprocess.run = self._real_run
        S.shutil.which = self._real_which

    def _spy(self, argv, **_kwargs):
        self.recorded.append(list(argv))

        class _P(object):
            returncode, stdout, stderr = 0, "", ""
        return _P()

    def test_bad_parameters_are_refused_without_spawning(self):
        bad = [
            {"mode": "SUMMARY"}, {"mode": "summary|http"}, {"mode": "summary; id"},
            {"mode": ""}, {"mode": None},
            {"port": -1}, {"port": 65536}, {"port": 1.5}, {"port": True},
            {"port": float("inf")}, {"port": float("nan")}, {"port": 10 ** 400},
            {"port": "80; id"}, {"port": "eighty"},
            {"max_rows": 0}, {"max_rows": 10001}, {"max_rows": -1},
            {"max_rows": False}, {"max_rows": float("inf")}, {"max_rows": 1.5},
            {"host_filter": 7}, {"host_filter": "a\x00b"}, {"host_filter": "x" * 600},
        ]
        for kwargs in bad:
            out = S.seep_pcap_extract(pcap_path=self.pcap, **kwargs)
            payload = json.loads(out)
            self.assertIs(payload.get("ok"), False, (kwargs, out[:200]))
            self.assertEqual(payload.get("error"), "invalid_parameters",
                             (kwargs, out[:200]))
            self.assertEqual(payload.get("executions"), [], kwargs)
        self.assertEqual(self.recorded, [], "a refused pcap parameter must never spawn tshark")
        # 危险原值不回显
        self.assertNotIn("summary; id", S.seep_pcap_extract(pcap_path=self.pcap,
                                                            mode="summary; id"))

    def test_legal_numeric_strings_and_enums_still_work(self):
        """main 的裁定：`"60"` 这类数值字符串合法（不能因边界检查而误拒）。"""
        out = S.seep_pcap_extract(pcap_path=self.pcap, mode="payload", port="443",
                                  max_rows="60", host_filter="example.com")
        payload = json.loads(out)
        self.assertNotIn("invalid_parameters", out[:200], out[:200])
        self.assertEqual(payload.get("port"), 443)
        self.assertEqual(payload.get("paging", {}).get("max_rows"), 60)
        self.assertTrue(self.recorded, "a legitimate call must reach tshark")
        for argv in self.recorded:
            self.assertIn("-n", argv)
            self.assertIn("tcp.port==443", argv)
            self.assertNotIn("example.com", argv, "host_filter 只能过滤结果行，不进命令行")

    def test_grammar_matches_between_contract_and_entry(self):
        import seep_contract as C
        for kwargs in ({"mode": "summary", "port": 0, "max_rows": 40, "host_filter": ""},
                       {"mode": "http", "port": "8080", "max_rows": "1", "host_filter": "a"},
                       {"mode": "payload", "port": 65535, "max_rows": 10000, "host_filter": ""}):
            params, reason = C.pcap_params(kwargs["mode"], kwargs["port"],
                                           kwargs["max_rows"], kwargs["host_filter"])
            self.assertIsNotNone(params, reason)
        for kwargs in (("nope", 0, 40, ""), ("summary", 70000, 40, ""),
                       ("summary", 0, 0, "")):
            params, reason = C.pcap_params(*kwargs)
            self.assertIsNone(params, kwargs)
            self.assertTrue(reason, kwargs)
        # None 当"未传"处理（归一成空串），不是非法值
        params, reason = C.pcap_params("summary", 0, 40, None)
        self.assertEqual((params or {}).get("host_filter"), "", reason)


class IntegerBoundaryStructured(unittest.TestCase):
    """int_in_range 的 inf/huge 必须是**结构化**拒绝（独立验收 §3.3 refuted）。"""

    def test_non_finite_and_oversized_are_structured_not_raised(self):
        import seep_contract as C
        for value in (float("inf"), float("-inf"), float("nan"), 1e309,
                      10 ** 400, -(10 ** 400)):
            number, err = C.int_in_range("t", "lines", value, 1, 10000)
            self.assertIsNone(number, value)
            self.assertTrue(err, value)
            payload = json.loads(err)
            self.assertEqual(payload.get("error"), "invalid_parameters", (value, err[:200]))
        # 正常输入仍然可用：纯 int 与数字字符串（不做 float 截断）。
        self.assertEqual(C.int_in_range("t", "lines", 60, 1, 10000)[0], 60)
        self.assertEqual(C.int_in_range("t", "lines", "60", 1, 10000)[0], 60)
        self.assertEqual(C.int_in_range("t", "lines", 10000, 1, 10000)[0], 10000)
        # bool 不能冒充 1；1.5 不能截断成 1。
        self.assertIsNone(C.int_in_range("t", "lines", True, 1, 10000)[0])
        self.assertIsNone(C.int_in_range("t", "lines", 1.5, 1, 10000)[0])

    def test_r2_tools_refuse_non_finite_without_calling_the_parser(self):
        with tempfile.TemporaryDirectory(prefix="readonly-int-") as td:
            binary = os.path.join(td, "target.bin")
            with open(binary, "wb") as fh:
                fh.write(b"\x7fELF" + b"\x00" * 64)
            recorded = []
            real = S._run_cmd
            S._run_cmd = lambda cmd, **_k: (recorded.append(list(cmd)), "spy")[1]
            try:
                for value in (float("inf"), float("nan"), 1e309, 10 ** 400):
                    for tool in (S.seep_r2_disasm, S.seep_r2_decompile):
                        out = tool(binary_path=binary, limit_tokens=value)
                        self.assertEqual(json.loads(out).get("error"),
                                         "invalid_parameters", (tool.__name__, value))
            finally:
                S._run_cmd = real
            self.assertEqual(recorded, [], "a refused integer must never reach the parser")


if __name__ == "__main__":
    unittest.main(verbosity=2)
