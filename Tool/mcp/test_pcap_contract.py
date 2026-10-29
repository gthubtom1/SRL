#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tool/mcp/test_pcap_contract.py —— seep_pcap_extract 的真实执行契约回归。

修的是什么（独立复核的三处硬伤）：
  ① 旧实现 `return (p.stdout or "") + (p.stderr or "")` —— 忽略 `returncode`，把
     stdout/stderr 拼一个串；于是告警行成了 "TCP 会话/HTTP 行"，rc≠0 也能包装成成功。
  ② argv 是 `[tshark, "-r", pcap]`，**没有 `-n`**：tshark 默认做名称解析，读一个本地
     抓包会触发 DNS/反查 —— "读文件"被误标成"联网动作"的根源。
  ③ 空数据与工具崩溃同形，zero_results 无法与 error 区分；max_rows 静默切片。

本文件只做**临时合成 pcap + subprocess spy**：不调用实时抓包、不联网、不装工具、
不碰真实客户 pcap。spy 只记录 argv，不 spawn 任何进程（`CallSpy` 显式断言）。

用法：python -B -X utf8 Tool/mcp/test_pcap_contract.py
退出码：0 全过 / 1 有断言失败 / 2 外部依赖缺失（UNVERIFIED，不算成功）
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
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
    import seep_contract as C
    import seep_mcp_server as S
except Exception as exc:  # pragma: no cover - 依赖缺失必须显式 skip，不当成功
    raise unittest.SkipTest("UNVERIFIED: 无法导入 seep_mcp_server/seep_contract（%s: %s）"
                            % (type(exc).__name__, exc))


def _empty_pcap(path: str) -> None:
    """写一个**合法但零包**的经典 pcap 头（libpcap 24 字节全局头）。"""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))


CONV_STDOUT = (
    "=================================================================================\n"
    "TCP Conversations\n"
    "Filter:<No Filter>\n"
    "                                               |  Packets  | |  Bytes  | | Duration |\n"
    "10.0.0.1:1234      <-> 10.0.0.2:80                5    3    1200    800    1.5\n"
)
HOSTS_STDOUT = "evil.example.com\t/login\napi.example.com\t/v2/check\n"
WARN_STDERR = "Running as user \"root\" and group \"root\". This could be dangerous.\n"


class Proc(object):
    """伪造 subprocess.CompletedProcess（只有本实现读的字段）。"""

    def __init__(self, rc=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = rc, stdout, stderr


class CallSpy(object):
    """替换 subprocess.run：记录 argv，按需返回预设结果，**绝不 spawn**。

    `responses` 可以是 (rc, stdout, stderr) 三元组列表，或一个可调用对象
    (argv) -> Proc / 抛异常（用于测 timeout / spawn 失败）。
    """

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        choice = (self.responses(argv) if callable(self.responses)
                  else self.responses[min(len(self.calls) - 1, len(self.responses) - 1)])
        if isinstance(choice, Exception):
            raise choice
        if isinstance(choice, Proc):
            return choice
        rc, out, err = choice
        return Proc(rc, out, err)


class PcapContractBase(unittest.TestCase):
    """共享夹具：临时 pcap + subprocess.run spy + 假 tshark 路径。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="pcap-contract-")
        self.addCleanup(self.tmp.cleanup)
        self.pcap = os.path.join(self.tmp.name, "empty.pcap")
        _empty_pcap(self.pcap)
        self._real_run = subprocess.run
        self._real_which = S.shutil.which
        self._real_isfile = os.path.isfile
        self.spy = None
        # 固定 tshark 路径，避免本机是否装了 Wireshark 影响判定
        S.shutil.which = lambda name: "/usr/bin/tshark" if name == "tshark" else None
        self.addCleanup(self._restore)

    def _restore(self):
        subprocess.run = self._real_run
        S.shutil.which = self._real_which
        os.path.isfile = self._real_isfile

    def install(self, responses):
        self.spy = CallSpy(responses)
        subprocess.run = self.spy
        return self.spy

    def call(self, **kwargs):
        out = S.seep_pcap_extract(**kwargs)
        return out, json.loads(out)


class PinnedArgvEveryMode(PcapContractBase):
    """要求 1：每条 tshark 调用固定 `-n -r <bound 绝对路径>`，且无实时抓包参数。"""

    def test_every_mode_pins_dash_n_and_the_bound_absolute_path(self):
        for mode in ("summary", "http", "payload"):
            self.install([(0, CONV_STDOUT, ""), (0, HOSTS_STDOUT, "")])
            out, payload = self.call(pcap_path=self.pcap, mode=mode)
            self.assertTrue(self.spy.calls, mode)
            for argv in self.spy.calls:
                self.assertIn("-n", argv, (mode, argv))
                self.assertEqual(argv[argv.index("-r") + 1], os.path.abspath(self.pcap),
                                 (mode, argv))
                # `-n` 必须出现在 `-r` 之前（形状固定，不是"某处出现过"）
                self.assertLess(argv.index("-n"), argv.index("-r"), (mode, argv))
                for flag in C.PCAP_LIVE_CAPTURE_FLAGS:
                    self.assertNotIn(flag, argv, (mode, flag, argv))
            self.assertNotIn("no_network", payload.get("error", ""), out[:200])

    def test_no_network_flag_comes_from_argv_not_a_declaration(self):
        """`no_network` 必须由执行记录里的 argv 推导：去掉 -n 就必须变 False。"""
        self.install([(0, CONV_STDOUT, ""), (0, HOSTS_STDOUT, "")])
        _, payload = self.call(pcap_path=self.pcap, mode="summary")
        self.assertIs(payload["no_network"], True)
        self.assertTrue(all("-n" in r["argv"] for r in payload["executions"]))
        # 反例：手工构造一个没有 -n 的执行记录
        self.assertIs(C.pcap_no_network([
            C.pcap_execution(["/usr/bin/tshark", "-r", "/tmp/x.pcap"], rc=0)]), False)
        self.assertIs(C.pcap_no_network([]), False, "没跑过就不能声称没联网")

    def test_shell_and_user_argv_are_not_parameters_at_all(self):
        """不接受用户覆盖 argv/shell/target：显式传 argv/shell 会被 schema 拒绝。"""
        self.install([(0, CONV_STDOUT, "")])
        with self.assertRaises(TypeError):
            S.seep_pcap_extract(pcap_path=self.pcap, mode="summary",
                                argv=["/bin/sh", "-c", "id"])
        with self.assertRaises(TypeError):
            S.seep_pcap_extract(pcap_path=self.pcap, mode="summary", shell=True)
        self.assertEqual(self.spy.calls, [], "被拒的调用不得产生任何 argv")
        # & 在 host_filter 里只是纯文本，不拆参数、不进命令行
        with open(self.pcap, "rb") as fh:
            self.assertTrue(fh.read(4))

    def test_target_path_is_absolute_in_every_execution(self):
        self.install([(0, CONV_STDOUT, ""), (0, HOSTS_STDOUT, "")])
        rel = os.path.relpath(self.pcap)
        _, payload = self.call(pcap_path=rel, mode="summary")
        for record in payload["executions"]:
            self.assertTrue(os.path.isabs(record["argv"][record["argv"].index("-r") + 1]),
                            record["argv"])

    def test_parameters_are_validated_before_any_file_or_process_access(self):
        """要求 1：入口校验先于文件/进程访问（畸形参数 → spawn 0 次、不 stat 路径）。"""
        accesses = []
        self.install([(0, "", "")])
        real_isfile = os.path.isfile
        os.path.isfile = lambda p: (accesses.append(p), real_isfile(p))[1]
        bad = [
            {"mode": "Summary"},          # 枚举区分大小写
            {"mode": "summary; id"},
            {"mode": "everything"},
            {"mode": ""},
            {"port": -1},
            {"port": 65536},
            {"port": 1.5},
            {"port": "80; id"},
            {"port": True},
            {"port": float("inf")},
            {"port": 10 ** 400},
            {"max_rows": 0},
            {"max_rows": 10001},
            {"max_rows": -3},
            {"max_rows": 1.5},
            {"max_rows": False},
            {"max_rows": float("nan")},
            {"host_filter": 123},
            {"host_filter": "a\x00b"},
            {"host_filter": "x" * 600},
        ]
        for kwargs in bad:
            out, payload = self.call(pcap_path=self.pcap, **kwargs)
            self.assertIs(payload.get("ok"), False, (kwargs, out[:200]))
            self.assertEqual(payload.get("error"), "invalid_parameters",
                             (kwargs, out[:200]))
            self.assertEqual(payload.get("status"), "invalid", (kwargs, out[:200]))
            self.assertEqual(payload.get("executions"), [], kwargs)
        self.assertEqual(self.spy.calls, [], "被拒的参数不得 spawn 任何进程")
        self.assertEqual(accesses, [], "被拒的参数不得触碰文件系统")
        # 危险原值不得回显
        self.assertNotIn("summary; id", self.call(pcap_path=self.pcap,
                                                  mode="summary; id")[0])
        self.assertNotIn("80; id", self.call(pcap_path=self.pcap, port="80; id")[0])

    def test_legal_numeric_strings_are_still_accepted(self):
        """main 已裁定："60" 这类数字字符串是合法整数（不能误拒）。"""
        self.install([(0, CONV_STDOUT, ""), (0, HOSTS_STDOUT, "")])
        _, payload = self.call(pcap_path=self.pcap, mode="summary",
                              port="0", max_rows="60")
        self.assertIs(payload.get("ok"), True, payload)
        self.assertEqual(payload["port"], 0)
        self.assertEqual(payload["paging"]["max_rows"], 60)
        self.assertEqual(C.int_in_range("t", "port", "65535", 0, 65535)[0], 65535)


class ExecutionsKeepStreamsSeparate(PcapContractBase):
    """要求 2：argv/rc/stdout/stderr 保留；非零退出 / stderr-only 都不算成功。"""

    def test_execution_records_keep_argv_rc_stdout_stderr(self):
        self.install([(0, CONV_STDOUT, WARN_STDERR), (0, HOSTS_STDOUT, "")])
        _, payload = self.call(pcap_path=self.pcap, mode="summary")
        self.assertEqual(len(payload["executions"]), 2)
        for record in payload["executions"]:
            for field in ("argv", "rc", "stdout", "stderr", "timeout", "error", "ok"):
                self.assertIn(field, record)
        first = payload["executions"][0]
        self.assertEqual(first["rc"], 0)
        self.assertEqual(first["stderr"], WARN_STDERR, "stderr 必须原样留在执行记录里")
        self.assertNotIn(WARN_STDERR, first["stdout"])
        # stderr 不得混进数据行
        joined = json.dumps(payload.get("tcp_conversations", []), ensure_ascii=False)
        self.assertNotIn("Running as user", joined)

    def test_nonzero_rc_with_text_is_not_success(self):
        """核心负例：rc≠0 + 文本输出 → 不许当解析成功。"""
        self.install([(2, CONV_STDOUT, "tshark: The file isn't a capture file\n")] * 2)
        out, payload = self.call(pcap_path=self.pcap, mode="summary")
        self.assertIs(payload["ok"], False, out[:300])
        self.assertEqual(payload["status"], "error")
        self.assertIs(payload["has_result"], False)
        self.assertEqual(payload["reason"], "call_failed")
        self.assertEqual(payload["tcp_conversations"], [], "rc≠0 的 stdout 不是数据")
        self.assertEqual(payload["http_hosts"], [])
        self.assertTrue(all(r["rc"] == 2 for r in payload["executions"]))

    def test_stderr_only_output_is_unknown_not_empty_pcap(self):
        """rc==0、stdout 空、stderr 有内容：不能声称"抓包为空"（那是 unknown）。"""
        self.install([(0, "", WARN_STDERR)] * 2)
        out, payload = self.call(pcap_path=self.pcap, mode="summary")
        self.assertIs(payload["ok"], False, out[:300])
        self.assertEqual(payload["status"], "unknown")
        self.assertEqual(payload["reason"], "stderr_only")
        self.assertIs(payload["has_result"], False)

    def test_partial_summary_is_never_success(self):
        """summary 两次调用，第 2 次失败 → 整结果非 success，但保留已得部分数据。"""
        self.install([(0, CONV_STDOUT, ""), (1, "", "boom")])
        out, payload = self.call(pcap_path=self.pcap, mode="summary")
        self.assertIs(payload["ok"], False, out[:300])
        self.assertEqual(payload["status"], "partial")
        self.assertIs(payload["partial"], True)
        self.assertIs(payload["has_result"], False, "partial 不能算 success")
        self.assertEqual(len(payload["tcp_conversations"]), 1, "已得数据必须保留")
        self.assertEqual(len(payload["executions"]), 2, "两次调用都要留执行记录")
        self.assertEqual(payload["executions"][1]["rc"], 1)

    def test_timeout_is_error_or_partial_and_never_success(self):
        for responses, expected in (
                ((subprocess.TimeoutExpired(["tshark"], 120),), "error"),
                ((subprocess.TimeoutExpired(["tshark"], 120),), "partial")):
            self.install(responses if len(responses) == 1 else list(responses) * 2)
            if expected == "partial":
                # 第一次给数据、第二次超时
                self.install([(0, CONV_STDOUT, ""),
                              subprocess.TimeoutExpired(["tshark"], 120)])
            out, payload = self.call(pcap_path=self.pcap, mode="summary")
            self.assertIs(payload["ok"], False, out[:300])
            self.assertEqual(payload["status"], expected, (expected, out[:300]))
            self.assertEqual(payload["reason"], "timeout")
            self.assertTrue(any(r["timeout"] for r in payload["executions"]))

    def test_subprocess_spawn_failure_is_error_not_empty(self):
        self.install([OSError("no such binary")] * 2)
        out, payload = self.call(pcap_path=self.pcap, mode="http")
        self.assertIs(payload["ok"], False, out[:300])
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["executions"][0]["error"], "OSError")
        self.assertIsNone(payload["executions"][0]["rc"])

    def test_missing_tshark_is_structured_error(self):
        self.install([(0, "", "")])
        real_which, real_roots = S.shutil.which, S._tool_roots
        real_pf = os.environ.pop("ProgramFiles", None)
        S.shutil.which = lambda name: None
        S._tool_roots = lambda: []
        try:
            out, payload = self.call(pcap_path=self.pcap, mode="summary")
        finally:
            S.shutil.which, S._tool_roots = real_which, real_roots
            if real_pf is not None:
                os.environ["ProgramFiles"] = real_pf
        # 本机可能真的装了 tshark（/usr/bin 候选），两种结局都必须结构化
        if payload.get("ok"):
            self.skipTest("UNVERIFIED: 本机 /usr/bin 里有 tshark，无法构造缺工具场景")
        if payload.get("error") != "tshark_missing":
            self.skipTest("UNVERIFIED: 本机走候选路径找到了 tshark（%s）"
                          % payload.get("status"))
        self.assertIs(payload["has_result"], False)
        self.assertEqual(payload["executions"], [], "缺工具时不得起进程")
        self.assertEqual(self.spy.calls, [], "缺工具时不得起进程")

    def test_missing_pcap_is_structured_and_does_not_echo_path(self):
        self.install([(0, "", "")])
        missing = os.path.join(self.tmp.name, "SENTINEL-NO-SUCH.pcap")
        out, payload = self.call(pcap_path=missing, mode="summary")
        self.assertEqual(payload["error"], "pcap_not_found", out[:200])
        self.assertEqual(payload["status"], "error")
        self.assertNotIn("SENTINEL-NO-SUCH", out, "缺失路径不应回显")
        self.assertEqual(self.spy.calls, [])

    def test_empty_legal_pcap_is_zero_results_not_a_crash(self):
        """合法但零包：status=zero_results（工具没崩），但 ok=False，不替路线背书。"""
        self.install([(0, "", "")] * 2)
        out, payload = self.call(pcap_path=self.pcap, mode="summary")
        self.assertEqual(payload["status"], "zero_results", out[:300])
        self.assertIs(payload["ok"], False)
        self.assertIs(payload["has_result"], False)
        self.assertEqual(payload["reason"], "no_rows")
        self.assertEqual(payload["tcp_conversations"], [])
        self.assertEqual(len(payload["executions"]), 2, "空数据也要留执行记录")

    def test_conv_table_header_is_not_a_conversation(self):
        """表头/分隔线不是会话：否则空 pcap 也会"有结果"。"""
        header_only = CONV_STDOUT.split("10.0.0.1")[0]
        self.install([(0, header_only, ""), (0, "", "")])
        _, payload = self.call(pcap_path=self.pcap, mode="summary")
        self.assertEqual(payload["tcp_conversations"], [])
        self.assertEqual(payload["status"], "zero_results")


class CompatsAndPaging(PcapContractBase):
    """要求 3：旧字段名兼容 + 新增 ok/status/has_result/executions + 显式分页。"""

    def test_compat_field_names_are_preserved(self):
        self.install([(0, CONV_STDOUT, ""), (0, HOSTS_STDOUT, "")])
        _, summary = self.call(pcap_path=self.pcap, mode="summary")
        self.assertIn("tcp_conversations", summary)
        self.assertIn("http_hosts", summary)
        self.assertIn("pcap", summary)
        self.assertIn("note", summary)
        for key in ("ok", "status", "has_result", "executions", "paging", "no_network"):
            self.assertIn(key, summary, key)
        self.install([(0, "1.2.3.4\tGET\tevil.example.com\t/x\t200\ttext/html\n", "")])
        _, http = self.call(pcap_path=self.pcap, mode="http")
        self.assertIn("http_rows", http)
        self.assertEqual(len(http["http_rows"]), 1)
        self.install([(0, "1.2.3.4\t1234\t5.6.7.8\t80\t12\tabcd\n", "")])
        _, payload = self.call(pcap_path=self.pcap, mode="payload", port=80)
        self.assertIn("payload_rows", payload)
        self.assertEqual(len(payload["payload_rows"]), 1)
        self.assertEqual(self.spy.calls[-1][self.spy.calls[-1].index("-Y") + 1],
                         "tcp.port==80")

    def test_warning_with_rc0_still_returns_data_as_success(self):
        """rc==0 的告警不该拒数据（"不能拒所有 warning"），但要保留在 warnings 里。"""
        self.install([(0, CONV_STDOUT, WARN_STDERR), (0, HOSTS_STDOUT, WARN_STDERR)])
        out, payload = self.call(pcap_path=self.pcap, mode="summary")
        self.assertIs(payload["ok"], True, out[:300])
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(len(payload["tcp_conversations"]), 1)
        self.assertTrue(payload["warnings"], "rc==0 的告警必须保留")
        self.assertTrue(any("Running as user" in w for w in payload["warnings"]))

    def test_max_rows_is_explicit_paging_with_real_totals(self):
        many = "\n".join("10.0.0.%d:1 <-> 10.0.0.9:80 1 1 1 1 0.1" % i
                         for i in range(1, 8)) + "\n"
        self.install([(0, many, ""), (0, HOSTS_STDOUT, "")])
        out, payload = self.call(pcap_path=self.pcap, mode="summary", max_rows=3)
        self.assertEqual(len(payload["tcp_conversations"]), 3, out[:200])
        self.assertEqual(payload["paging"]["total"]["tcp_conversations"], 7,
                         "total 是过滤后、分页前的真实行数")
        self.assertEqual(payload["paging"]["returned"]["tcp_conversations"], 3)
        self.assertIs(payload["paging"]["truncated"]["tcp_conversations"], True)
        self.assertIs(payload["paging"]["truncated"]["http_hosts"], False)
        self.assertEqual(payload["paging"]["max_rows"], 3)
        # 截断时仍是 ok（数据真的拿到了），但分页口径必须真实、可续读
        self.assertIs(payload["ok"], True)

    def test_host_filter_zeroing_all_rows_is_zero_results(self):
        self.install([(0, CONV_STDOUT, ""), (0, HOSTS_STDOUT, "")])
        out, payload = self.call(pcap_path=self.pcap, mode="summary",
                                 host_filter="no-such-host-zqx")
        self.assertEqual(payload["status"], "zero_results", out[:300])
        self.assertIs(payload["ok"], False)
        self.assertEqual(payload["reason"], "filtered_out")
        self.assertIs(payload["has_result"], False)

    def test_host_filter_never_enters_argv(self):
        self.install([(0, CONV_STDOUT, ""), (0, HOSTS_STDOUT, "")])
        injected = "evil.example.com; rm -rf /"
        self.call(pcap_path=self.pcap, mode="summary", host_filter=injected)
        for argv in self.spy.calls:
            self.assertNotIn(injected, argv)
            self.assertNotIn("; rm -rf /", argv)

    def test_budget_overflow_is_refused_with_continuation_not_truncated(self):
        """超体积预算 → resource_constraint + continuation，绝不静默截断证据。"""
        huge = "\n".join("10.%d.%d.%d:1 <-> 10.0.0.9:80 x x x x 0.1"
                         % (i % 250, i % 200, i % 130) for i in range(4000)) + "\n"
        self.install([(0, huge, ""), (0, huge, "")])
        out, payload = self.call(pcap_path=self.pcap, mode="summary", max_rows=4000)
        self.assertIs(payload.get("ok"), False, out[:200])
        self.assertEqual(payload.get("error"), "resource_constraint")
        self.assertTrue(payload.get("continuation"))
        self.assertGreater(payload.get("bytes", 0), 0)
        self.assertNotIn("tcp_conversations", payload, "拒绝时不返回被截断的数据")


class StatusDerivationTable(unittest.TestCase):
    """纯函数层：状态推导表（不 spawn，便于逐例核对）。"""

    def test_status_table(self):
        ok0 = C.pcap_execution(["/usr/bin/tshark", "-n", "-r", "/x.pcap"], rc=0,
                               stdout="row\n", stderr=WARN_STDERR)
        bad = C.pcap_execution(["/usr/bin/tshark", "-n", "-r", "/x.pcap"], rc=2,
                               stdout="row\n", stderr="boom\n")
        slow = C.pcap_execution(["/usr/bin/tshark", "-n", "-r", "/x.pcap"],
                                timeout=True, error="TimeoutExpired")
        empty = C.pcap_execution(["/usr/bin/tshark", "-n", "-r", "/x.pcap"], rc=0)
        stderr_only = C.pcap_execution(["/usr/bin/tshark", "-n", "-r", "/x.pcap"],
                                       rc=0, stderr="warn\n")
        self.assertEqual(C.pcap_status([], 0), ("unknown", "no_execution"))
        self.assertEqual(C.pcap_status([ok0], 1), ("ok", "ok"))
        self.assertEqual(C.pcap_status([ok0, ok0], 2), ("ok", "ok"))
        self.assertEqual(C.pcap_status([bad], 0), ("error", "call_failed"))
        self.assertEqual(C.pcap_status([ok0, bad], 1), ("partial", "call_failed"))
        self.assertEqual(C.pcap_status([slow], 0), ("error", "timeout"))
        self.assertEqual(C.pcap_status([ok0, slow], 1), ("partial", "timeout"))
        self.assertEqual(C.pcap_status([empty], 0), ("zero_results", "no_rows"))
        self.assertEqual(C.pcap_status([stderr_only], 0), ("unknown", "stderr_only"))

    def test_rc_zero_but_timeout_flag_is_not_ok(self):
        record = C.pcap_execution(["/usr/bin/tshark", "-n", "-r", "/x"], rc=0,
                                  timeout=True)
        self.assertIs(record["ok"], False)
        self.assertEqual(C.pcap_status([record], 1), ("partial", "timeout"))

    def test_every_mode_query_table_pins_the_filter_shape(self):
        for mode in C.PCAP_MODES:
            queries = C.pcap_queries(mode, 80)
            self.assertTrue(queries, mode)
            for field, extra in queries:
                self.assertIn(field, C.PCAP_FIELDS[mode], (mode, field))
                for flag in C.PCAP_LIVE_CAPTURE_FLAGS:
                    self.assertNotIn(flag, extra, (mode, flag))
        self.assertEqual(dict(C.pcap_queries("payload", 80))["payload_rows"][1],
                         "tcp.port==80")
        self.assertEqual(dict(C.pcap_queries("payload", 0))["payload_rows"][1],
                         "tcp.len>0")

    def test_params_validation_is_the_single_source(self):
        good = C.pcap_params("payload", "443", "60", "host.example")
        self.assertIsNotNone(good[0], good)
        self.assertEqual(good[0], {"mode": "payload", "port": 443, "max_rows": 60,
                                   "host_filter": "host.example"})
        for args in (("SUMMARY", 0, 40, ""), ("summary", -1, 40, ""),
                     ("summary", 0, 0, ""), ("summary", 0, 40, 1),
                     ("summary", 0, 40, "a\nb")):
            params, reason = C.pcap_params(*args)
            self.assertIsNone(params, args)
            self.assertTrue(reason, args)

    def test_envelope_never_promotes_partial_or_zero_to_success(self):
        bad = C.pcap_execution(["/usr/bin/tshark", "-n", "-r", "/x"], rc=1,
                               stderr="boom\n")
        envelope = json.loads(C.pcap_envelope(
            "seep_pcap_extract", "x.pcap", "http", [bad], {"http_rows": ["row"]},
            {"http_rows": 1}, "note"))
        self.assertIs(envelope["ok"], False)
        self.assertEqual(envelope["status"], "partial")
        self.assertEqual(envelope["http_rows"], ["row"], "部分数据仍要返回")
        empty = json.loads(C.pcap_envelope(
            "seep_pcap_extract", "x.pcap", "http",
            [C.pcap_execution(["/usr/bin/tshark", "-n", "-r", "/x"], rc=0)],
            {"http_rows": []}, {"http_rows": 0}, "note"))
        self.assertIs(empty["ok"], False)
        self.assertEqual(empty["status"], "zero_results")


class WorkflowOutcomeContract(unittest.TestCase):
    """要求 4：只读证明 workflow 的 `classify_outcome` 如何处置本工具的新状态词。

    只看**不写**：导入 project_workflow，调它自己的纯函数，不跑动作、不写盘。

    实测结论（2026-10 本批，见回执 §4）：
      * `zero_results` / `partial` 会被判成 **failed**（非 success ✓），但 reason 是
        `tool_error:<status>`，且 `outcome_is_no_result()` 返回 False —— 即把"跑成了但
        没结果"标成"工具报错"。这是 workflow 侧词汇表缺项（COMMON_OUTCOME_STATUS
        里是 `zero_match`，不是 `zero_results`）。**不属本批范围，已报告主 Agent。**
      * `unknown` / `empty_output` / `resource_constraint` 已被正确识别为 no-result。

    因此本测试断言的是"不得被判成 succeeded"这个硬底线；词汇差异用显式注释钉住，
    不改 workflow 文件。
    """

    def test_no_new_status_can_ever_be_classified_as_succeeded(self):
        try:
            import project_workflow as W
        except Exception as exc:  # pragma: no cover
            self.skipTest("UNVERIFIED: 无法导入 project_workflow（%s）" % exc)
        spec = {"kind": "mcp", "tool": "seep_pcap_extract"}
        for status in ("zero_results", "partial", "error", "unknown", "invalid",
                       "tshark_missing", "pcap_not_found", "empty_output",
                       "resource_constraint"):
            for rc in (0, 1):
                outcome, reason = W.classify_outcome(
                    spec, {"tool_status": status, "rc": rc, "tool_ok": False,
                           "tool_payload_ok": False})
                self.assertEqual(outcome, "failed", (status, rc, outcome, reason))
                self.assertNotEqual(outcome, "succeeded", (status, rc))
        # 乐观位：真的成功仍然判 succeeded（不是一律拒）
        outcome, reason = W.classify_outcome(
            spec, {"tool_status": "ok", "rc": 0, "tool_ok": True,
                   "tool_payload_ok": True})
        self.assertEqual((outcome, reason), ("succeeded", "ok"))

    def test_workflow_classifies_zero_results_and_partial_without_success(self):
        """接线后：零结果与部分结果都不能成为完整成功。

        主对话更正旧缺口存在断言；此判据修改须由另一只读会话独立验收。
        partial 可保留真实数据，但不能混成空结果或工具崩溃。
        """
        try:
            import project_workflow as W
        except Exception as exc:  # pragma: no cover
            self.fail("required project_workflow import failed: %s" % type(exc).__name__)
        spec = {"kind": "mcp", "tool": "seep_pcap_extract"}
        outcome, reason = W.classify_outcome(
            spec, {"tool_status": "zero_results", "rc": 0, "tool_ok": False})
        self.assertEqual((outcome, reason), ("failed", "zero_results"))
        self.assertTrue(W.outcome_is_no_result(reason))
        self.assertFalse(W.outcome_is_partial(reason))
        self.assertEqual(W.outcome_class(outcome, reason), "no_result")
        self.assertFalse(W.action_has_result(outcome, reason, {"tool_has_result": True}))

        outcome, reason = W.classify_outcome(
            spec, {"tool_status": "partial", "rc": 0, "tool_ok": False})
        self.assertEqual((outcome, reason), ("failed", "partial"))
        self.assertTrue(W.outcome_is_partial(reason))
        self.assertFalse(W.outcome_is_no_result(reason))
        self.assertEqual(W.outcome_class(outcome, reason), "partial")
        self.assertTrue(W.action_has_result(outcome, reason, {"tool_has_result": True}))
        self.assertFalse(W.action_has_result(outcome, reason, {"tool_has_result": False}))

        # 既有无结果状态保留，不能因本次接线回退。
        for status in ("unknown", "empty_output", "resource_constraint"):
            self.assertIn(status, W.COMMON_OUTCOME_STATUS, status)
            outcome, reason = W.classify_outcome(
                spec, {"tool_status": status, "rc": 0, "tool_ok": False})
            self.assertEqual(reason, status, (status, reason))
            self.assertTrue(W.outcome_is_no_result(reason), status)
            self.assertEqual(outcome, "failed", status)


class TsharkSourceAnchor(unittest.TestCase):
    """要求 5：实现里保留显式 tshark 调用锚点（不靠假函数名/全文件 contains 刷绿）。

    用 AST 而不是文本 contains：docstring 里的 `-n -r` 不算证据（checker 也剥 docstring）。
    """

    @staticmethod
    def _body_nodes():
        import ast
        path = os.path.join(HERE, "seep_mcp_server.py")
        with open(path, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
        node = next(n for n in tree.body
                    if isinstance(n, ast.FunctionDef) and n.name == "seep_pcap_extract")
        body = node.body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            body = body[1:]
        return node, body

    def test_implementation_keeps_the_pinned_argv_anchor(self):
        import ast
        node, body = self._body_nodes()
        self.assertIsNotNone(node)
        argv_lists = []
        spawn_calls = []
        for sub in ast.walk(ast.Module(body=body, type_ignores=[])):
            if isinstance(sub, ast.List):
                argv_lists.append(sub)
            elif (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                  and sub.func.attr == "run"):
                spawn_calls.append(sub)
        # 必须真的有一个 spawn 调用（删掉真调用只留字面量不算使用）
        self.assertTrue(spawn_calls, "实现里必须真的调用 subprocess.run")
        # 必须有一个形如 [tshark, "-n", "-r", bound_path] 的 argv 列表字面量
        pinned = [lst for lst in argv_lists
                  if [e.value for e in lst.elts[:4]
                      if isinstance(e, ast.Constant)] == ["-n", "-r"]]
        self.assertTrue(pinned, "固定 `-n -r` 的 argv 列表字面量必须留在实现体里（AST 证据）")
        first = pinned[0]
        self.assertEqual([getattr(e, "id", getattr(e, "value", "")) for e in first.elts],
                         ["tshark", "-n", "-r", "bound_path"])
        # 不得出现 shell=True / stdout+stderr 拼接 / 外部传入的 argv
        for sub in ast.walk(node):
            self.assertFalse(isinstance(sub, ast.keyword) and sub.arg == "shell",
                             "不得给 tshark 传 shell=")
        source = ast.unparse(node)
        self.assertNotIn('p.stdout or "") + (p.stderr', source,
                         "stdout/stderr 拼串的旧写法不得回来")
        self.assertIn("timeout=120", source)

    def test_declared_evidence_via_helper_is_really_called(self):
        """配置里的 `evidence_via.helper` 必须在实现 AST（含同文件 helper 链）里被调用。"""
        import ast
        with open(os.path.join(os.path.dirname(os.path.dirname(HERE)), "Tool", "config",
                              "mcp-tool-dependencies.json"), "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        entry = doc["tools"]["seep_pcap_extract"]
        items = (entry["requires"].get("all_of") or [])
        vias = [i["evidence_via"] for i in items if isinstance(i.get("evidence_via"), dict)]
        self.assertTrue(vias, "pcap 应显式声明 helper 跳转（而不是靠全文件 contains）")
        node, body = self._body_nodes()
        called = {sub.func.id for sub in ast.walk(node)
                  if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name)}
        for via in vias:
            self.assertIn(via["module"], ("Tool/mcp/seep_contract.py",
                                           "Tool/mcp/tool_autodiscover.py"), via)
            self.assertIn(via["helper"], called,
                          "evidence_via.helper %r 没被实现调用 = 虚报依赖" % via["helper"])
            self.assertEqual(via["symbol"], "seep_contract.py", via)
        # 声明的 mode 枚举/分页上界必须与 contract 常量一致
        self.assertEqual(tuple(C.PCAP_MODES), ("summary", "http", "payload"))
        self.assertEqual(C.PCAP_PORT_RANGE, (0, 65535))
        self.assertEqual(C.PCAP_MAX_ROWS_RANGE, (1, 10000))


if __name__ == "__main__":
    unittest.main(verbosity=2)
