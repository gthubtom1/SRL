#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""h2-race-e2e.py —— HTTP/2 单包竞态的**真机**端到端自测（内置最小 h2c 服务端）。

为什么需要它
------------
`race-probe.py --mode h2-single-packet` 之前只被两条路径覆盖过：
  · 缺库 → `blocked_at=h2-lib-missing`（负路径，没有真发包）；
  · 对着 HTTP/1.1 端点 → 同样是 blocked（仍是失败路径）。
也就是说：**从来没有人验证过它真的能打出 N 个 HTTP/2 stream、拿到 N 个响应、
并把账本差值判对**。本脚本补上这一段：自带一个明文 h2c 服务端，用两种服务端
行为各跑一遍，断言 `race-probe.py` 的结论分别落在 fail / pass。

判据不重复实现
--------------
判定逻辑（`judge()` / `remote_gate()` / `h2_missing_payload()` / `run()`）**直接
import 复用** `Tool/skill/web-pentest/scripts/race-probe.py`，本脚本只负责：
  ① 起服务端（asyncio + h2，明文 h2c，只绑 127.0.0.1、端口随机）；
  ② 维护账本（每个 `POST /claim` 扣 1）；
  ③ 组 `argparse.Namespace` 调 `race_probe.run()`；
  ④ 断言返回值与账本。

两档服务端行为（`--server-mode`）
---------------------------------
  racy  不串行化、无幂等键：20 个 stream 全部扣账 → 账本 100→80 → |delta|=20
        → 期望 verdict=fail / vulnerable=true / reproduced=19
  safe  用锁串行化且只放行一次：只有第 1 个 stream 扣账，其余 409
        → 账本 100→99 → |delta|=1 → 期望 verdict=pass / vulnerable=false

两个监听端口（都在回环、端口随机）
  · POST /claim  —— h2c 明文 HTTP/2（prior knowledge，无 Upgrade）
  · GET  /balance —— 最小 HTTP/1.1 JSON（因为 race-probe 用 urllib 读账本）

缺 h2 时
--------
`h2` 是可选依赖。缺库时本脚本**不失败**：仍然验证 `race-probe.py` 的
`blocked_at=h2-lib-missing` 形状，然后打印 `skipped` 并以 rc=0 退出。

输出（`--json` 时为单行）
-------------------------
  {"schema":"seep.h2-race-e2e/1","ok":true,"checks":12,"server_mode":"both",
   "verdict":"racy=fail,safe=pass","blocked_at":null,"skipped":false,
   "runs":[{"server_mode":"racy","verdict":"fail",...}, ...],
   "missing_lib":{"ok":true,"blocked_at":"h2-lib-missing","probe_cli_rc":3,
                   "e2e_rc":0}}

退出码：0 通过（含 skipped）/ 1 有断言失败 / 2 用法或环境错误。

用法
----
  python Tool/scripts/h2-race-e2e.py                 # racy + safe 两档都跑
  python Tool/scripts/h2-race-e2e.py --server-mode safe
  python Tool/scripts/h2-race-e2e.py --self-test     # 离线：判定函数 + 服务端桩
  python Tool/scripts/h2-race-e2e.py --json
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time

SCHEMA = "seep.h2-race-e2e/1"
VERSION = "1.0.0"
SERVER_MODES = ("racy", "safe")
DEFAULT_BODY = '{"item":"coupon","qty":1}'
INIT_BALANCE = 100
DEFAULT_N = 20
LOOPBACK = "127.0.0.1"

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RACE_PROBE = os.path.join(ROOT, "Tool", "skill", "web-pentest", "scripts", "race-probe.py")


# ------------------------------------------------------------------ optional h2
def h2_available():
    """True only when the optional h2 library can actually be imported."""
    try:  # pragma: no cover - optional
        import h2.config      # noqa: F401
        import h2.connection  # noqa: F401
        import h2.events      # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


# ------------------------------------------------------- reuse race-probe logic
def load_race_probe(path=RACE_PROBE):
    """Import race-probe.py by path (the filename has a dash, so no plain import)."""
    if not os.path.isfile(path):
        raise RuntimeError("找不到 race-probe.py：%s" % path)
    spec = importlib.util.spec_from_file_location("seep_race_probe", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("无法加载 race-probe.py：%s" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ------------------------------------------------------------------- the ledger
class Ledger:
    """内存账本 + 两档服务端行为。纯逻辑，`--self-test` 直接驱动它。

    racy：读到快照后让出事件循环，再**直接扣减**——没有锁、没有幂等键，
          所以 N 个 stream 就是 N 次扣账（这正是要打出来的“竞态”）。
    safe：`asyncio.Lock` 串行化检查-扣减，并且只放行第一个请求，其余 409。
    """

    def __init__(self, mode, start=INIT_BALANCE):
        if mode not in SERVER_MODES:
            raise ValueError("server_mode must be racy|safe: %r" % (mode,))
        self.mode = mode
        self.start = int(start)
        self.balance = int(start)
        self.granted = 0
        self.attempts = 0
        self.events = []
        self._gate = asyncio.Lock()      # 只在 safe 档真正串行化

    async def claim(self, try_id=0):
        self.attempts += 1
        if self.mode == "safe":
            async with self._gate:
                if self.granted == 0 and self.balance > 0:
                    self.granted += 1
                    self.balance -= 1
                    return self._record(200, "granted", try_id)
                return self._record(409, "already-claimed", try_id)
        snapshot = self.balance          # ① 读快照（无锁）
        await asyncio.sleep(0)           # ② 让出事件循环：窗口在这里被拉开
        if snapshot <= 0:                # racy 档也只防超卖，不防“卖两次”
            return self._record(409, "out-of-stock", try_id)
        self.balance -= 1                # ③ 直接扣减，无幂等键
        self.granted += 1
        return self._record(200, "granted", try_id)

    def _record(self, status, claim_state, try_id):
        item = {"status": status, "claim": claim_state,
                "balance": self.balance, "try": try_id}
        self.events.append(item)
        return item

    def snapshot(self):
        return {"mode": self.mode, "start": self.start, "balance": self.balance,
                "granted": self.granted, "attempts": self.attempts}


# ----------------------------------------------------------------- the server
class H2RaceServer:
    """最小 h2c 服务端：一条 h2c 监听（/claim）+ 一条 HTTP/1.1 监听（/balance）。

    整个服务端跑在自己的线程 + 自己的事件循环里，主线程同步调 race-probe，
    避免“客户端 asyncio”和“服务端 asyncio”抢同一个 loop。
    """

    def __init__(self, mode, start=INIT_BALANCE):
        self.ledger = Ledger(mode, start)
        self.mode = mode
        self.h2_port = 0
        self.ledger_port = 0
        self.error = None
        self._loop = None
        self._thread = None
        self._ready = threading.Event()
        self._servers = []
        self.stats = {"h2_connections": 0, "h2_streams": 0, "http1_requests": 0}

    # -- lifecycle ------------------------------------------------------
    def start(self, timeout=15.0):
        if not h2_available():
            raise RuntimeError("h2 库缺失，不能起 h2c 服务端")
        self._thread = threading.Thread(target=self._run, name="h2-race-e2e-server",
                                        daemon=True)
        self._thread.start()
        if not self._ready.wait(timeout):
            raise RuntimeError("服务端启动超时（%.0fs）" % timeout)
        if self.error:
            raise RuntimeError(self.error)

    def stop(self, timeout=5.0):
        loop = self._loop
        if loop is None:
            return
        try:
            fut = asyncio.run_coroutine_threadsafe(self._close_all(), loop)
            fut.result(timeout=timeout)
        except Exception:  # noqa: BLE001 - shutdown must never mask a result
            pass
        try:
            loop.call_soon_threadsafe(loop.stop)
        except Exception:  # noqa: BLE001
            pass
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    def _run(self):
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._boot())
            self._ready.set()
            loop.run_forever()
        except BaseException as exc:  # noqa: BLE001 - surfaced through .error
            self.error = "%s: %s" % (type(exc).__name__, str(exc)[:160])
            self._ready.set()
        finally:
            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:  # noqa: BLE001
                pass
            loop.close()

    async def _boot(self):
        self._servers.append(await asyncio.start_server(
            self._h2_session, LOOPBACK, 0))
        self._servers.append(await asyncio.start_server(
            self._http1_session, LOOPBACK, 0))
        self.h2_port = self._servers[0].sockets[0].getsockname()[1]
        self.ledger_port = self._servers[1].sockets[0].getsockname()[1]

    async def _close_all(self):
        for srv in self._servers:
            try:
                srv.close()
            except Exception:  # noqa: BLE001
                pass
        for srv in self._servers:
            try:
                await srv.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    # -- h2c: POST /claim ----------------------------------------------
    async def _h2_session(self, reader, writer):
        import h2.config
        import h2.connection
        import h2.events
        import h2.exceptions

        config = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        conn = h2.connection.H2Connection(config=config)
        pending = {}
        self.stats["h2_connections"] += 1
        try:
            conn.initiate_connection()
            writer.write(conn.data_to_send())
            await writer.drain()
            while True:
                data = await reader.read(65535)
                if not data:
                    break
                try:
                    events = conn.receive_data(data)
                except h2.exceptions.ProtocolError:
                    break
                for event in events:
                    if isinstance(event, h2.events.RequestReceived):
                        pending[event.stream_id] = {
                            "headers": {k: v for k, v in event.headers}, "body": b""}
                    elif isinstance(event, h2.events.DataReceived):
                        state = pending.get(event.stream_id)
                        if state is not None:
                            state["body"] += event.data
                        try:
                            conn.acknowledge_received_data(
                                event.flow_controlled_length, event.stream_id)
                        except Exception:  # noqa: BLE001 - reset stream
                            pass
                    elif isinstance(event, h2.events.StreamEnded):
                        self.stats["h2_streams"] += 1
                        state = pending.pop(event.stream_id, None)
                        if state is not None:
                            await self._h2_handle(conn, writer, event.stream_id, state)
                    elif isinstance(event, h2.events.StreamReset):
                        pending.pop(event.stream_id, None)
                    elif isinstance(event, h2.events.ConnectionTerminated):
                        return
                out = conn.data_to_send()
                if out:
                    writer.write(out)
                    await writer.drain()
        except Exception:  # noqa: BLE001 - a probe that hangs up is not a verdict
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _h2_handle(self, conn, writer, stream_id, state):
        headers = state["headers"]
        method = headers.get(":method", "")
        path = (headers.get(":path", "") or "").split("?")[0]
        if method == "POST" and path == "/claim":
            item = await self.ledger.claim(try_id=len(self.ledger.events))
            await self._h2_respond(conn, writer, stream_id, item["status"], item)
            return
        if method == "GET" and path in ("/balance", "/"):
            await self._h2_respond(conn, writer, stream_id, 200, self.ledger.snapshot())
            return
        await self._h2_respond(conn, writer, stream_id, 404,
                              {"error": "not-found", "path": path})

    async def _h2_respond(self, conn, writer, stream_id, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            conn.send_headers(stream_id, [
                (":status", str(status)),
                ("content-type", "application/json"),
                ("content-length", str(len(body))),
                ("server", "seep-h2-race-e2e/%s" % VERSION),
            ])
            conn.send_data(stream_id, body, end_stream=True)
            writer.write(conn.data_to_send())
            await writer.drain()
        except Exception:  # noqa: BLE001 - client may have reset the stream
            pass

    # -- HTTP/1.1: GET /balance (race-probe reads the ledger with urllib) --
    async def _http1_session(self, reader, writer):
        self.stats["http1_requests"] += 1
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
            line = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = line.split(" ")
            method = parts[0].upper() if parts else ""
            path = (parts[1] if len(parts) > 1 else "").split("?")[0]
            if method == "GET" and path in ("/balance", "/"):
                status, payload = 200, self.ledger.snapshot()
            else:
                status, payload = 404, {"error": "not-found", "path": path}
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            writer.write(b"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n"
                         b"Content-Length: %d\r\nConnection: close\r\n\r\n%s"
                         % (status, b"OK" if status == 200 else b"Not Found",
                            len(body), body))
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass


# ------------------------------------------------------------- probe invoking
def probe_namespace(url, balance_url, n, body, timeout):
    """Same shape race-probe's CLI would build (so run() is exercised verbatim)."""
    return argparse.Namespace(
        url=url, method="POST", body=body, content_type="application/json",
        token="", balance_url=balance_url, n=n, batch=0,
        mode="h2-single-packet", timeout=timeout, allow_remote=False,
        dry_run=False, json=True, out="", self_test=False)


def run_probe(rp, url, balance_url, n, body, timeout):
    """Call race-probe's module entry points; judgement logic is NOT duplicated."""
    gate = rp.remote_gate(url, balance_url, False)
    if gate is not None:
        return gate
    return rp.run(probe_namespace(url, balance_url, n, body, timeout))


# --------------------------------------------------------------- expectations
def expected(server_mode, n=DEFAULT_N, start=INIT_BALANCE):
    """Pure expectation table: what the ledger and the verdict must be."""
    if server_mode == "racy":
        return {"verdict": "fail", "vulnerable": True, "reproduced": max(n - 1, 0),
                "after": start - n, "granted": n, "conflicts": 0}
    if server_mode == "safe":
        return {"verdict": "pass", "vulnerable": False, "reproduced": 0,
                "after": start - 1, "granted": 1, "conflicts": n - 1}
    raise ValueError("unknown server mode: %r" % (server_mode,))


def check_result(result, server_mode, n=DEFAULT_N, start=INIT_BALANCE):
    """Compare one race-probe result with the expectation table. Returns checks."""
    want = expected(server_mode, n, start)
    checks = []

    def ck(name, cond, detail=""):
        checks.append({"check": "probe/%s/%s" % (server_mode, name),
                       "ok": bool(cond), "detail": str(detail)[:300]})

    ck("mode-echo", result.get("mode") == "h2-single-packet",
       "mode=%r" % (result.get("mode"),))
    ck("verdict", result.get("verdict") == want["verdict"],
       "verdict=%r 期望 %r（reason=%s）" % (result.get("verdict"), want["verdict"],
                                        result.get("reason")))
    ck("vulnerable", result.get("vulnerable") is want["vulnerable"],
       "vulnerable=%r 期望 %r" % (result.get("vulnerable"), want["vulnerable"]))
    ck("reproduced", result.get("reproduced") == want["reproduced"],
       "reproduced=%r 期望 %r" % (result.get("reproduced"), want["reproduced"]))
    ck("blocked-at-null", not result.get("blocked_at"),
       "blocked_at=%r" % (result.get("blocked_at"),))
    ck("ledger-before", result.get("before") == start,
       "before=%r 期望 %d" % (result.get("before"), start))
    ck("ledger-after", result.get("after") == want["after"],
       "after=%r 期望 %d（delta=%r）" % (result.get("after"), want["after"],
                                     result.get("ledger_delta")))
    ck("ledger-delta",
       result.get("ledger_delta") == (want["after"] - start),
       "ledger_delta=%r 期望 %d" % (result.get("ledger_delta"), want["after"] - start))
    statuses = result.get("status_codes") or []
    counts = result.get("status_counts") or {}
    ck("responses-arrived", len(statuses) == n,
       "收到 %d/%d 个响应：%s" % (len(statuses), n, counts))
    ck("status-mix",
       counts.get("200", 0) == want["granted"] and counts.get("409", 0) == want["conflicts"],
       "status_counts=%s 期望 200×%d / 409×%d" % (counts, want["granted"],
                                                 want["conflicts"]))
    ck("sync-one-round",
       (result.get("sync") or {}).get("release_rounds") == 1
       and (result.get("sync") or {}).get("staged") == n,
       "sync=%s" % (result.get("sync"),))
    return checks


# -------------------------------------------------------------- missing h2 lib
def missing_lib_checks(rp, workdir):
    """Verify the `h2-lib-missing` contract without uninstalling h2.

    Two independent angles:
      · module level: run() short-circuits to h2_missing_payload() when h2_available()
        is false (simulated by monkeypatching the module attribute);
      · CLI level  : race-probe.py under a PYTHONPATH shadow where `h2` raises
        ImportError must print blocked_at=h2-lib-missing and exit 3.
    """
    checks = []
    original = getattr(rp, "h2_available", None)
    try:
        rp.h2_available = lambda: False
        payload = rp.run(probe_namespace(
            "http://127.0.0.1:9/claim", "http://127.0.0.1:9/balance",
            2, DEFAULT_BODY, 1.0))
    finally:
        if original is not None:
            rp.h2_available = original
    checks.append({
        "check": "missing-lib/module-blocked-shape",
        "ok": payload.get("blocked_at") == "h2-lib-missing"
              and payload.get("ok") is False
              and payload.get("vulnerable") is False
              and payload.get("mode") == "h2-single-packet",
        "detail": "blocked_at=%r ok=%r" % (payload.get("blocked_at"), payload.get("ok")),
    })

    shadow = os.path.join(workdir, "shadow")
    os.makedirs(shadow, exist_ok=True)
    with open(os.path.join(shadow, "h2.py"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# 故意遮蔽真实 h2：验证缺库时的结构化 blocked\n"
                 "raise ImportError('h2 hidden by h2-race-e2e')\n")
    env = dict(os.environ)
    env["PYTHONPATH"] = shadow + (os.pathsep + env["PYTHONPATH"]
                                  if env.get("PYTHONPATH") else "")
    env["PYTHONIOENCODING"] = "utf-8"
    cmd = [sys.executable, RACE_PROBE, "--mode", "h2-single-packet",
           "--url", "http://127.0.0.1:9/claim",
           "--balance-url", "http://127.0.0.1:9/balance",
           "--n", "2", "--no-dry-run", "--json"]
    rc, out = 3, ""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90,
                              env=env, encoding="utf-8", errors="replace")
        rc, out = proc.returncode, proc.stdout
    except Exception as exc:  # noqa: BLE001
        out = "%s: %s" % (type(exc).__name__, exc)
    blocked = None
    try:
        blocked = json.loads(out.strip().splitlines()[-1]).get("blocked_at")
    except Exception:  # noqa: BLE001
        blocked = None
    checks.append({
        "check": "missing-lib/cli-rc-and-blocked",
        "ok": rc == 3 and blocked == "h2-lib-missing",
        "detail": "rc=%r blocked_at=%r 期望 rc=3/blocked_at=h2-lib-missing" % (rc, blocked),
    })
    return checks


# ---------------------------------------------------------------- e2e per mode
def run_e2e(rp, server_mode, n=DEFAULT_N, start=INIT_BALANCE,
            body=DEFAULT_BODY, timeout=20.0):
    """Start one server in `server_mode`, fire the probe, stop, return both sides."""
    server = H2RaceServer(server_mode, start)
    url = balance_url = ""
    started = time.monotonic()
    try:
        server.start()
        url = "http://%s:%d/claim" % (LOOPBACK, server.h2_port)
        balance_url = "http://%s:%d/balance" % (LOOPBACK, server.ledger_port)
        result = run_probe(rp, url, balance_url, n, body, timeout)
    finally:
        server.stop()
    ledger = server.ledger.snapshot()
    ledger.update(server.stats)
    ledger["elapsed_ms"] = int((time.monotonic() - started) * 1000)
    ledger["h2_port"] = server.h2_port
    ledger["ledger_port"] = server.ledger_port
    return result, ledger


def run_checks(result, ledger, server_mode, n=DEFAULT_N, start=INIT_BALANCE):
    """Probe-side checks + server-side (independent) ledger checks."""
    checks = check_result(result, server_mode, n, start)
    want = expected(server_mode, n, start)

    def ck(name, cond, detail=""):
        checks.append({"check": "server/%s/%s" % (server_mode, name),
                       "ok": bool(cond), "detail": str(detail)[:300]})

    ck("single-h2-connection", ledger.get("h2_connections") == 1,
       "h2 连接数=%r，期望 1（一个 TCP 连接上 %d 个 stream 才是单包）"
       % (ledger.get("h2_connections"), n))
    ck("stream-count", ledger.get("h2_streams") == n,
       "服务端收到 %r 个完整 stream，期望 %d" % (ledger.get("h2_streams"), n))
    ck("attempts", ledger.get("attempts") == n,
       "服务端收到 %r 个 claim，期望 %d" % (ledger.get("attempts"), n))
    ck("granted", ledger.get("granted") == want["granted"],
       "服务端放行 %r 次，期望 %d" % (ledger.get("granted"), want["granted"]))
    ck("balance", ledger.get("balance") == want["after"],
       "账本 %r，期望 %d" % (ledger.get("balance"), want["after"]))
    ck("ledger-agrees-with-probe",
       result.get("after") == ledger.get("balance")
       and result.get("ledger_delta") == ledger.get("balance") - start,
       "probe(before=%r after=%r delta=%r) vs server(balance=%r)"
       % (result.get("before"), result.get("after"), result.get("ledger_delta"),
          ledger.get("balance")))
    return checks


# ------------------------------------------------------------------ self-test
def self_test():
    """Offline: drive the judge function and the Ledger stub. No sockets."""
    checks = []

    def ck(name, cond, detail=""):
        checks.append({"check": name, "ok": bool(cond), "detail": str(detail)[:300]})

    rp = load_race_probe()
    ck("import/race-probe-reused", hasattr(rp, "judge") and hasattr(rp, "run")
       and getattr(rp, "SCHEMA", None) == "seep.race-probe/1",
       "SCHEMA=%r" % (getattr(rp, "SCHEMA", None),))

    # -- expectation table is the single source of truth for both modes
    racy, safe = expected("racy"), expected("safe")
    ck("expect/table", racy["verdict"] == "fail" and safe["verdict"] == "pass"
       and racy["reproduced"] == DEFAULT_N - 1 and safe["reproduced"] == 0,
       "racy=%s safe=%s" % (racy, safe))

    # -- Ledger stub: racy must consume N, safe must consume exactly 1
    async def drive(mode, n=DEFAULT_N):
        ledger = Ledger(mode, INIT_BALANCE)
        results = await asyncio.gather(*[ledger.claim(i) for i in range(n)])
        return ledger, results

    for mode in SERVER_MODES:
        ledger, results = asyncio.run(drive(mode))
        want = expected(mode)
        granted = sum(1 for r in results if r["status"] == 200)
        conflicted = sum(1 for r in results if r["status"] == 409)
        ck("server-stub/%s/ledger" % mode,
           ledger.balance == want["after"] and ledger.granted == want["granted"]
           and granted == want["granted"] and conflicted == want["conflicts"],
           "balance=%d granted=%d 200=%d 409=%d" % (ledger.balance, ledger.granted,
                                                   granted, conflicted))
        verdict = rp.judge(INIT_BALANCE, ledger.balance, DEFAULT_N,
                           mode="h2-single-packet")
        ck("server-stub/%s/judge" % mode,
           verdict["verdict"] == want["verdict"]
           and verdict["vulnerable"] is want["vulnerable"]
           and verdict["reproduced"] == want["reproduced"]
           and verdict["mode"] == "h2-single-packet",
           "verdict=%r vulnerable=%r reproduced=%r"
           % (verdict["verdict"], verdict["vulnerable"], verdict["reproduced"]))

    # -- the same checks the live e2e runs, fed synthetic results
    for mode in SERVER_MODES:
        want = expected(mode)
        counts = {}
        if want["granted"]:
            counts["200"] = want["granted"]
        if want["conflicts"]:
            counts["409"] = want["conflicts"]
        synthetic = {
            "mode": "h2-single-packet", "ok": True, "verdict": want["verdict"],
            "vulnerable": want["vulnerable"], "reproduced": want["reproduced"],
            "blocked_at": None, "before": INIT_BALANCE, "after": want["after"],
            "ledger_delta": want["after"] - INIT_BALANCE,
            "status_codes": [200] * want["granted"] + [409] * want["conflicts"],
            "status_counts": counts,
            "sync": {"staged": DEFAULT_N, "release_rounds": 1, "final_byte": 1},
        }
        produced = check_result(synthetic, mode)
        ck("checker/%s/accepts-expected" % mode,
           all(c["ok"] for c in produced),
           [c["check"] for c in produced if not c["ok"]])
        wrong = dict(synthetic, verdict="pass" if want["verdict"] == "fail" else "fail")
        ck("checker/%s/rejects-inverted" % mode,
           not all(c["ok"] for c in check_result(wrong, mode)),
           "判定器必须拒绝反号结论")

    # -- blocked path stays honest (an exception is never a reproduction)
    blocked = rp.judge(INIT_BALANCE, INIT_BALANCE - DEFAULT_N, DEFAULT_N,
                       errors=["TimeoutError: read timed out"], mode="h2-single-packet")
    ck("judge/error-blocks", blocked["verdict"] == "blocked"
       and blocked["blocked_at"] == "network-error" and blocked["ok"] is False)

    # -- missing h2 shape (no network, no monkeypatch of imported module state)
    missing = rp.h2_missing_payload()
    ck("missing-lib/payload", missing["blocked_at"] == "h2-lib-missing"
       and missing["mode"] == "h2-single-packet" and missing["ok"] is False
       and missing["vulnerable"] is False, missing.get("hint", ""))

    # -- --help stays rc=0 (argparse exits with 0); captured so the JSON stays clean
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            main(["--help"])
        help_rc = None
    except SystemExit as exc:
        help_rc = exc.code
    ck("help/rc0", help_rc == 0 and "--self-test" in buf.getvalue(),
       "rc=%r help_len=%d" % (help_rc, len(buf.getvalue())))

    failed = [c for c in checks if not c["ok"]]
    print(json.dumps({"schema": SCHEMA, "tool": "h2-race-e2e.py", "version": VERSION,
                      "self_test": True, "ok": not failed, "checks": len(checks),
                      "failed": [c["check"] for c in failed]},
                     ensure_ascii=False, indent=None if "--json" in sys.argv else 2))
    return 0 if not failed else 1


# ---------------------------------------------------------------------- main
def main(argv):
    """CLI entry point (--help / --self-test / live e2e)."""
    ap = argparse.ArgumentParser(
        prog="h2-race-e2e.py",
        description="HTTP/2 单包竞态真机 e2e：本地 h2c 服务端 racy/safe 双档，"
                    "断言 race-probe.py 分别落在 fail/pass。",
        epilog="退出码：0 通过（含 h2 缺失 skipped）/ 1 断言失败 / 2 用法或环境错误。")
    ap.add_argument("--server-mode", choices=SERVER_MODES, default=None,
                    help="只跑一档（默认两档都跑：racy 必须 fail，safe 必须 pass）")
    ap.add_argument("--n", type=int, default=DEFAULT_N,
                    help="并发 stream 数（默认 %d）" % DEFAULT_N)
    ap.add_argument("--start-balance", type=int, default=INIT_BALANCE,
                    help="初始账本（默认 %d）" % INIT_BALANCE)
    ap.add_argument("--body", default=DEFAULT_BODY, help="POST /claim 的请求体")
    ap.add_argument("--timeout", type=float, default=20.0, help="单请求超时秒数（默认 20）")
    ap.add_argument("--json", action="store_true", help="单行 JSON 输出（便于管道）")
    ap.add_argument("--self-test", action="store_true",
                    help="离线自检：只跑判定函数与服务端桩，不联网")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.n < 2:
        print(json.dumps({"schema": SCHEMA, "ok": False, "blocked_at": "args",
                          "reason": "--n 至少为 2（要能打出并发）"}, ensure_ascii=False))
        return 2
    if args.n > 200:
        print(json.dumps({"schema": SCHEMA, "ok": False, "blocked_at": "args",
                          "reason": "--n 上限 200（这是证明，不是压测）"},
                         ensure_ascii=False))
        return 2
    if args.start_balance < args.n:
        print(json.dumps({"schema": SCHEMA, "ok": False, "blocked_at": "args",
                          "reason": "--start-balance 必须 >= --n（racy 档要能扣满 %d 次，"
                                    "否则账本触底会混入 409，判定不可比）" % args.n},
                         ensure_ascii=False))
        return 2

    modes = [args.server_mode] if args.server_mode else list(SERVER_MODES)
    checks, runs = [], []
    started = time.monotonic()

    try:
        rp = load_race_probe()
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"schema": SCHEMA, "ok": False, "blocked_at": "race-probe-missing",
                          "reason": "%s: %s" % (type(exc).__name__, exc),
                          "checks": 0, "server_mode": args.server_mode or "both"},
                         ensure_ascii=False))
        return 2

    workdir = tempfile.mkdtemp(prefix="h2-race-e2e-")
    missing_checks = missing_lib_checks(rp, workdir)
    checks.extend(missing_checks)
    missing_ok = all(c["ok"] for c in missing_checks)

    skipped = False
    if not h2_available():
        skipped = True
        if not args.json:
            print("[SKIP] h2 库缺失：跳过真机 h2 双档，仅验证 blocked_at=h2-lib-missing")
            for item in missing_checks:
                print("  [%s] %s — %s" % ("OK" if item["ok"] else "FAIL",
                                          item["check"], item["detail"]))
        payload = {
            "schema": SCHEMA, "tool": "h2-race-e2e.py", "version": VERSION,
            "ok": missing_ok, "skipped": True, "checks": len(checks),
            "server_mode": args.server_mode or "both",
            "verdict": None, "blocked_at": "h2-lib-missing",
            "failed": [c["check"] for c in checks if not c["ok"]],
            "runs": [],
            "missing_lib": {"ok": missing_ok, "blocked_at": "h2-lib-missing",
                            "probe_cli_rc": 3, "e2e_rc": 0,
                            "detail": [c for c in missing_checks]},
            "reason": "缺 h2：真机 e2e 跳过（skipped 不算失败），"
                      "blocked_at 契约仍已验证",
            "elapsed_ms": int((time.monotonic() - started) * 1000),
        }
        print(json.dumps(payload, ensure_ascii=False,
                         indent=None if args.json else 2))
        return 0 if missing_ok else 1

    for mode in modes:
        try:
            result, ledger = run_e2e(rp, mode, args.n, args.start_balance,
                                     args.body, args.timeout)
        except Exception as exc:  # noqa: BLE001 - structured failure, no traceback
            checks.append({"check": "server/%s/startup" % mode, "ok": False,
                           "detail": "%s: %s" % (type(exc).__name__, str(exc)[:200])})
            runs.append({"server_mode": mode, "ok": False, "verdict": None,
                         "vulnerable": None, "blocked_at": "server-startup",
                         "reason": "%s: %s" % (type(exc).__name__, str(exc)[:200])})
            continue
        mode_checks = run_checks(result, ledger, mode, args.n, args.start_balance)
        checks.extend(mode_checks)
        runs.append({
            "server_mode": mode, "ok": all(c["ok"] for c in mode_checks),
            "verdict": result.get("verdict"), "vulnerable": result.get("vulnerable"),
            "reproduced": result.get("reproduced"),
            "blocked_at": result.get("blocked_at"),
            "before": result.get("before"), "after": result.get("after"),
            "ledger_delta": result.get("ledger_delta"),
            "status_counts": result.get("status_counts"),
            "requests_fired": result.get("requests_fired"),
            "reason": result.get("reason"),
            "server_ledger": ledger,
            "failed_checks": [c["check"] for c in mode_checks if not c["ok"]],
        })
        if not args.json:
            summary = "verdict=%s vulnerable=%s delta=%s status=%s" % (
                result.get("verdict"), result.get("vulnerable"),
                result.get("ledger_delta"), result.get("status_counts"))
            print("[%s] %s — %s" % ("OK" if runs[-1]["ok"] else "FAIL", mode, summary))
            for item in mode_checks:
                if not item["ok"]:
                    print("  [FAIL] %s — %s" % (item["check"], item["detail"]))

    failed = [c for c in checks if not c["ok"]]
    verdicts = ",".join("%s=%s" % (r["server_mode"], r["verdict"]) for r in runs)
    blocked_at = next((r["blocked_at"] for r in runs if r.get("blocked_at")), None)
    payload = {
        "schema": SCHEMA, "tool": "h2-race-e2e.py", "version": VERSION,
        "ok": not failed, "checks": len(checks), "failed": [c["check"] for c in failed],
        "server_mode": args.server_mode or "both",
        "verdict": verdicts or None,
        "blocked_at": blocked_at,
        "skipped": skipped,
        "runs": runs,
        "missing_lib": {"ok": missing_ok, "blocked_at": "h2-lib-missing",
                        "probe_cli_rc": 3, "e2e_rc": 0 if not failed else 1,
                        "detail": missing_checks},
        "probe": {"path": RACE_PROBE, "mode": "h2-single-packet",
                  "judge": "reused (race-probe.judge / race-probe.run)"},
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "note": "racy 必须 fail（账本 -N）、safe 必须 pass（账本 -1）；"
                "异常一律 blocked，不得当竞态成功。",
    }
    print(json.dumps(payload, ensure_ascii=False, indent=None if args.json else 2))
    return 0 if not failed else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
    sys.exit(main(sys.argv[1:]))
