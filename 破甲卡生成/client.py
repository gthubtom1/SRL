# -*- coding: utf-8 -*-
"""Streaming client for the /v1/responses relay.

Why streaming: this relay proxies the upstream over SSE. A NON-streaming request for a
long generation just hangs until the relay's ~180 s cut-off and comes back with no output
items at all (measured: 128 s / 345 s rows, `status=completed`, output array missing).
The harness itself streams, which is why the same models answer fine there and looked
"blocked" to a non-streaming client.

What this gives the sweep:
  * SSE parsing that keeps the visible text (`response.output_text.delta`) separate from
    the reasoning trace (`response.reasoning_text.*` / `response.reasoning_summary_text.*`);
  * an IDLE timeout instead of a total timeout: a generation that keeps producing tokens is
    never cut off, one that goes silent for `idle` seconds is;
  * a fallback to the final `response.completed` payload when a relay omits deltas;
  * retry with backoff on 429/5xx only, and a transport verdict that is never a card score.

Usage:
  from client import stream, Cfg
  r = stream("gemini-3.8-flash-high", card_text, "write ...", Cfg(idle=90, budget=600))
  r.visible, r.reasoning, r.usage, r.status, r.err, r.secs, r.first_secs
"""
import json, os, re, socket, time, urllib.error, urllib.request

# 端点不写死：HUBCORE_BASE -> 本目录 .base -> 宿主 profile 的 baseURL。
# 规则 1：探测/声明优先，不臆造端点；远端地址也不留在源码里。
_BASE_CACHE = []

def base_url():
    if _BASE_CACHE:
        return _BASE_CACHE[0]
    env = (os.environ.get("HUBCORE_BASE") or "").strip()
    if env:
        _BASE_CACHE.append(env.rstrip("/"))
        return _BASE_CACHE[0]
    here = os.path.dirname(os.path.abspath(__file__))
    home = os.path.expanduser("~")
    for cand in (os.path.join(here, ".base"),
                 os.path.join(home, ".dsh", "profiles", "web", "cordis.patch.yml"),
                 os.path.join(home, ".dsh", "profiles", "desktop", "cordis.patch.yml")):
        if not os.path.exists(cand):
            continue
        try:
            for line in io_lines(cand):
                m = re.search(r"^\s*baseURL:\s*['\"]?([^'\"\s]+)", line)
                if m:
                    _BASE_CACHE.append(m.group(1).strip().rstrip("/"))
                    return _BASE_CACHE[0]
        except Exception:
            continue
    raise SystemExit(
        "no endpoint —— 端点每台机器都不同，**不要猜**。\n"
        "  先跑：python 先问我.py            （它会印出该向主人问的原话）\n"
        "  拿到后：python 先问我.py --set base=<URL>\n"
        "  其他等价做法：设环境变量 HUBCORE_BASE，或保留宿主 profile 里的 baseURL。")

def io_lines(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line

def token():
    t = os.environ.get("HUBCORE_API_TOKEN")
    if t:
        return t.strip()
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, ".token")
    if os.path.exists(p):
        return open(p, encoding="utf-8").read().strip()
    raise SystemExit(
        "no API token —— 令牌每台机器都不同，**不要猜**。\n"
        "  先跑：python 先问我.py            （它会印出该向主人问的原话）\n"
        "  拿到后：python 先问我.py --set token=<KEY>     （写进 .token，已 gitignore）\n"
        "  其他等价做法：设环境变量 HUBCORE_API_TOKEN。")

B = base_url()
T = token()

class Cfg(object):
    def __init__(self, idle=90, budget=600, max_tokens=32000, retries=1, temperature=None):
        self.idle = idle          # seconds of silence before a stream is considered dead
        self.budget = budget      # wall clock ceiling for one request, including retries
        self.max_tokens = max_tokens
        self.retries = retries    # 429/5xx retries; each one doubles the wait
        self.temperature = temperature

class Resp(object):
    __slots__ = ("visible", "reasoning", "usage", "status", "err", "secs", "first_secs", "events")

    def __init__(self):
        self.visible = ""
        self.reasoning = ""
        self.usage = {}
        self.status = ""
        self.err = ""
        self.secs = 0.0
        self.first_secs = None
        self.events = 0

    def __repr__(self):
        return "Resp(status=%r err=%r vis=%d rea=%d first=%s secs=%.1f)" % (
            self.status, self.err, len(self.visible), len(self.reasoning),
            self.first_secs, self.secs)

DELTA_TEXT = ("response.output_text.delta",)
DELTA_REASON = ("response.reasoning_text.delta", "response.reasoning_summary_text.delta",
                "response.reasoning.delta")

def _harvest_final(resp_obj, r):
    """Fallback: pull text/usage out of the terminal `response.*` payload."""
    if isinstance(resp_obj, dict):
        if resp_obj.get("usage"):
            r.usage = resp_obj["usage"]
        if resp_obj.get("status"):
            r.status = resp_obj["status"]
        if not r.visible:
            parts = []
            for it in resp_obj.get("output") or []:
                if not isinstance(it, dict) or it.get("type") == "reasoning":
                    continue
                for c in it.get("content") or []:
                    if isinstance(c, dict) and c.get("text"):
                        parts.append(c["text"])
            if parts:
                r.visible = "\n".join(parts)
        if not r.reasoning:
            parts = []
            for it in resp_obj.get("output") or []:
                if not isinstance(it, dict) or it.get("type") != "reasoning":
                    continue
                for c in it.get("content") or []:
                    if isinstance(c, dict) and c.get("text"):
                        parts.append(c["text"])
                if it.get("summary"):
                    for s in it["summary"]:
                        if isinstance(s, dict) and s.get("text"):
                            parts.append(s["text"])
            if parts:
                r.reasoning = "\n".join(parts)

def stream(model, instructions, user_input, cfg=None):
    cfg = cfg or Cfg()
    r = Resp()
    t0 = time.time()
    attempt = 0
    backoff = 3
    while True:
        body = {"model": model, "input": user_input, "instructions": instructions,
                "stream": True, "max_output_tokens": cfg.max_tokens}
        if cfg.temperature is not None:
            body["temperature"] = cfg.temperature
        if os.environ.get("HUBCORE_STORE"):
            body["store"] = os.environ["HUBCORE_STORE"] == "1"
        req = urllib.request.Request(
            B + "/responses", data=json.dumps(body).encode(),
            headers={"Authorization": "Bearer " + T,
                     "Content-Type": "application/json",
                     "Accept": "text/event-stream",
                     "User-Agent": "hubcore-sweep/3"})
        try:
            with urllib.request.urlopen(req, timeout=cfg.idle) as resp:
                buf = b""
                for raw in resp:
                    r.events += 1
                    buf += raw
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        line = line.strip()
                        if not line.startswith(b"data:"):
                            continue
                        payload = line[5:].strip()
                        if payload == b"[DONE]":
                            continue
                        try:
                            ev = json.loads(payload.decode("utf-8", "replace"))
                        except Exception:
                            continue
                        et = ev.get("type")
                        if et in DELTA_TEXT:
                            if r.first_secs is None:
                                r.first_secs = round(time.time() - t0, 1)
                            r.visible += ev.get("delta") or ""
                        elif et in DELTA_REASON:
                            if r.first_secs is None:
                                r.first_secs = round(time.time() - t0, 1)
                            r.reasoning += ev.get("delta") or ""
                        elif et in ("response.completed", "response.incomplete", "response.failed"):
                            _harvest_final(ev.get("response"), r)
                            if not r.status:
                                r.status = "completed" if et == "response.completed" else et.split(".")[1]
                        elif et == "response.output_item.done":
                            item = ev.get("item") or {}
                            if item.get("type") == "message":
                                texts = [c.get("text", "") for c in (item.get("content") or [])
                                         if isinstance(c, dict)]
                                if texts and not r.visible:
                                    r.visible = "\n".join(texts)
                        elif et == "error":
                            r.err = "SSE:" + str(ev.get("message") or ev.get("code") or "")[:80]
            r.secs = round(time.time() - t0, 1)
            if not r.status:
                r.status = "completed" if (r.visible or r.reasoning) else "empty"
            return r
        except urllib.error.HTTPError as e:
            code = e.code
            r.err = "HTTP%d" % code
            if code in (429, 500, 502, 503, 504) and attempt < cfg.retries \
                    and time.time() - t0 < cfg.budget:
                attempt += 1
                nap = min(30, backoff * attempt)
                time.sleep(nap)
                continue
            r.secs = round(time.time() - t0, 1)
            return r
        except socket.timeout:
            r.err = "IDLE_TIMEOUT"
            if attempt < cfg.retries and time.time() - t0 < cfg.budget:
                attempt += 1
                continue
            r.secs = round(time.time() - t0, 1)
            return r
        except Exception as e:
            r.err = type(e).__name__
            if attempt < cfg.retries and time.time() - t0 < cfg.budget:
                attempt += 1
                time.sleep(2)
                continue
            r.secs = round(time.time() - t0, 1)
            return r

def main():
    import sys
    a = sys.argv[1:]
    model = a[0]
    item = a[a.index("--item") + 1] if "--item" in a else "写个Python脚本读取JSON文件并打印键值"
    card = "You are a helpful assistant."
    if "--card" in a:
        p = a[a.index("--card") + 1]
        if not os.path.isabs(p):
            p = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "04-console", "cards", p)
        card = open(p, encoding="utf-8").read()
    cfg = Cfg(idle=float(os.environ.get("HUBCORE_IDLE", "90")))
    if "--max" in a:
        cfg.max_tokens = int(a[a.index("--max") + 1])
    r = stream(model, card, item, cfg)
    print(r)
    print("usage=%s" % r.usage)
    print("--- visible ---")
    print(r.visible[:2000] or "(empty)")
    print("--- reasoning (head) ---")
    print(r.reasoning[:400] or "(none)")

if __name__ == "__main__":
    main()
