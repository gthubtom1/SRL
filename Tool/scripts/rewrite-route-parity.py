#!/usr/bin/env python3
"""Input hook -> loopback HTTP relay -> route.resolve preservation check.

P0-1 replaces the old three rewritten-text comparison: aliases are independent
retrieval data, so concatenating them into route input is no longer valid.
Both primary and auxiliary domains, exact text and full request bytes must
survive the real hook/HTTP chain. A changed path is a failure even if the same
primary domain still matches. No model call, credentials or customer sample.
"""
from __future__ import annotations

import argparse
import http.client
import importlib.util
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INTERCEPTOR = ROOT / "Tool/prompts/extensions/security-audit-interceptor.ts"
NORMALIZE = ROOT / "Tool/config/input-normalize.json"
PROBES = ROOT / "Tool/config/skill-route-probes.json"
RELAY_DIR = HERE / "compliance-relay"
NORMALIZE_SCHEMA = "seep.input-normalize/2"


def validate_pairs(raw):
    if not isinstance(raw, list) or not raw:
        return ["pairs must be a nonempty array"]
    problems, seen = [], set()
    for i, p in enumerate(raw):
        if not isinstance(p, dict):
            problems.append(f"pairs[{i}] must be an object")
            continue
        src, terms = p.get("from"), p.get("route_terms")
        if not isinstance(src, str) or not src.strip():
            problems.append(f"pairs[{i}] missing from")
        elif src in seen:
            problems.append(f"pairs[{i}] duplicate from")
        else:
            seen.add(src)
        if "to" in p:
            problems.append(f"pairs[{i}] obsolete replacement field 'to'")
        if not isinstance(terms, list) or not terms or any(not isinstance(t, str) or not t.strip() for t in terms):
            problems.append(f"pairs[{i}] invalid route_terms")
    return problems


def load_normalize(path=NORMALIZE):
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return [], str(path), ["alias table unreadable or invalid JSON"]
    if not isinstance(doc, dict) or doc.get("schema") != NORMALIZE_SCHEMA:
        return [], str(path), ["invalid alias schema"]
    problems = validate_pairs(doc.get("pairs"))
    pairs = [] if problems else [{"from": p["from"], "route_terms": list(p["route_terms"])} for p in doc["pairs"]]
    return pairs, str(path), problems


def derive_route_terms(text, pairs):
    return list(dict.fromkeys(t for p in pairs if p["from"] in text for t in p["route_terms"]))


def route_signature(route_mod, text):
    domains = list(dict.fromkeys(h["pack"] for h in route_mod.resolve(text) if not h.get("fallback")))
    return {"primary": domains[0] if domains else None, "aux": sorted(domains[1:])}


def run_hook(operations, agent_dir, ts_path=INTERCEPTOR, normalize_path=NORMALIZE):
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node with TypeScript stripping is required; verification cannot be skipped")
    env = dict(os.environ, PI_CODING_AGENT_DIR=str(agent_dir), SEEP_INPUT_NORMALIZE=str(normalize_path), NODE_NO_WARNINGS="1")
    # Retired variables must not turn on provider safety overrides.
    env["PI_SAFETY_PAYLOAD"] = "all"
    result = subprocess.run([node, "--experimental-strip-types", str(RELAY_DIR / "tests/input-hook.mjs"), str(ts_path)],
                            input=json.dumps(operations, ensure_ascii=False), capture_output=True,
                            text=True, encoding="utf-8", cwd=ROOT, env=env, timeout=60)
    if result.returncode:
        raise RuntimeError(result.stderr)
    return json.loads(result.stdout), result.stderr


def load_relay():
    spec = importlib.util.spec_from_file_location("preservation_relay", RELAY_DIR / "relay.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class CaptureUpstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.received.append((self.path, body, dict(self.headers)))
        status, content_type, response = self.server.reply
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)
        self.wfile.flush()


class LoopbackChain:
    def __init__(self, force=True, config_extra=None):
        self.relay_mod = load_relay()
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), CaptureUpstream)
        self.upstream.daemon_threads = True
        self.upstream.received = []
        self.upstream.reply = (200, "application/json", b'{"ok":true}')
        cfg = {"token": "synthetic-local-test", "upstreams": {"mock": f"http://127.0.0.1:{self.upstream.server_port}"}}
        cfg.update(config_extra or {})
        self.state = self.relay_mod.RelayState(cfg, self.relay_mod.LabModeGate("nonexistent", force))
        self.relay = self.relay_mod.create_server(self.state, "127.0.0.1", 0)
        self.threads = []

    def __enter__(self):
        for server in (self.upstream, self.relay):
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
            thread.start()
            self.threads.append(thread)
        return self

    def post(self, body, path="/v1/chat/completions", headers=None, route=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.relay.server_port, timeout=15)
        try:
            conn.request("POST", route or "/r/synthetic-local-test/mock" + path,
                         body=body, headers=headers or {"Content-Type": "application/json"})
            response = conn.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            conn.close()

    def __exit__(self, *args):
        for server in (self.relay, self.upstream):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=5)


def create_input_fixtures(root):
    """Create inert material under the caller's live TemporaryDirectory.

    Native paths identify actual files; PureWindowsPath renders the same runtime
    components with backslashes for separator-preservation probes on every OS.
    These files are never executed, and remain alive through hook/HTTP/routing.
    """
    root = Path(root).resolve()
    fixtures = {"target": root / "材料" / "脱壳" / "target.exe",
                "apk": root / "材料" / "会员.apk",
                "binary": root / "材料" / "脱壳" / "会员.exe",
                "image": root / "附件" / "会员 脱壳.png"}
    for name, path in fixtures.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(("synthetic fixture: " + name).encode("utf-8"))
    return fixtures


def payload_for(protocol, text, fixtures):
    # Actual temporary attachment paths are also material. No file is launched.
    image = {"type": "image_url", "image_url": {"url": fixtures["image"].as_uri() + "?会员=脱壳"}}
    attachment_path = {"type": "input_text" if protocol == "openai-responses" else "text",
                       "text": "附件路径：" + str(fixtures["image"])}
    history = {"role": "assistant", "content": "[Safe Security Testing Flow] historical text use-policy)."}
    if protocol == "openai-responses":
        return {"input": [history, {"role": "user", "content": [{"type": "input_text", "text": text}, image, attachment_path]}],
                "instructions": "original system", "tools": [{"name": "inspect", "parameters": {"path": str(fixtures["binary"])}}]}
    if protocol == "anthropic-messages":
        image = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "c3ludGhldGlj"}}
    return {"messages": [history, {"role": "user", "content": [{"type": "text", "text": text}, image, attachment_path]}],
            "tools": [{"name": "inspect", "parameters": {"path": str(fixtures["binary"])}}]}


def extra_probes(fixtures):
    windows_binary = str(PureWindowsPath(fixtures["binary"]))
    return [
        "远控", "脱壳", f'分析 "{fixtures["target"]}"',
        f'分析 "{fixtures["apk"]}" 是否存在后门，逆向复现并生成报告',
        "破解会员订阅购买后检查远控",
        f'  分析 {windows_binary}\r\n```python\r\n会员 = "订阅"\r\n```\r\n  ',
        '`会员 = "激活"` https://example.invalid/购买?会员=订阅&file=脱壳.exe#绕过',
        json.dumps({"path": windows_binary, "task": "检查后门", "会员": "订阅"}, ensure_ascii=False),
        "【路由提示】原话含远控，保持此材料不变", "new-skill demo-tool", "/help 破解", "", "  \r\n ",
        "从 APK JNI 与 PCAP 还原私有协议", "固件 ELF 的 Web 接口", "普通天气预报",
    ]


def run(ts_path=INTERCEPTOR, probes_path=PROBES, normalize_path=NORMALIZE, fixtures=None):
    with tempfile.TemporaryDirectory(prefix="seep-input-parity-") as temp:
        material = fixtures if fixtures is not None else create_input_fixtures(Path(temp) / "fixtures")
        agent_dir = Path(temp) / "agent"
        agent_dir.mkdir()
        return _run(ts_path, probes_path, normalize_path, material, agent_dir)


def _run(ts_path, probes_path, normalize_path, fixtures, agent_dir):
    pairs, _, problems = load_normalize(normalize_path)
    try:
        with open(probes_path, encoding="utf-8") as fh:
            doc = json.load(fh)
        probes = doc.get("probes") if isinstance(doc, dict) else doc
        if not isinstance(probes, list) or not probes:
            raise ValueError()
        texts = list(dict.fromkeys([p["text"] for p in probes] + [p["from"] for p in pairs] + extra_probes(fixtures)))
        if any(not isinstance(t, str) for t in texts):
            raise ValueError()
    except (OSError, ValueError, KeyError, TypeError):
        problems.append("invalid probe file")
        texts = extra_probes(fixtures)
    sys.path.insert(0, str(HERE))
    import route as route_mod
    rows = []
    try:
        originals = {text: route_signature(route_mod, text) for text in texts}
        operations = [{"lab": lab, "safe": safe, "event": {"source": source, "text": text,
                       "images": [{"type": "image", "mimeType": "image/png", "data": "c3ludGhldGlj"}]}}
                      for lab, safe, source in ((False, False, "interactive"), (True, False, "interactive"),
                                                (True, True, "rpc"), (True, True, "extension")) for text in texts]
        hooked, stderr = run_hook(operations, agent_dir, ts_path, normalize_path)
        if stderr.strip():
            problems.append("hook emitted diagnostics: " + stderr.strip())
        if len(hooked) != len(operations):
            raise ValueError("hook result count mismatch")
        paths = {"openai-completions": "/v1/chat/completions", "anthropic-messages": "/v1/messages", "openai-responses": "/v1/responses"}
        with LoopbackChain(config_extra={"refusalRetry": True, "refusalRetryAttempts": 5}) as chain:
            for op, result in zip(operations, hooked):
                text = op["event"]["text"]
                errors = []
                if result["text"] != text or result["event"] != result["before"] or result.get("images") != op["event"]["images"]:
                    errors.append("hook changed original text/event/images")
                if result["terms"] != derive_route_terms(text, pairs):
                    errors.append("derived aliases differ from source")
                for protocol, path in paths.items():
                    payload = payload_for(protocol, result["text"], fixtures)
                    raw = json.dumps(payload, ensure_ascii=False, indent=1).encode("utf-8") + b"\n"
                    previous_calls = len(chain.upstream.received)
                    status, response, _ = chain.post(raw, path)
                    received = chain.upstream.received[-1][1]
                    if status != 200 or response != b'{"ok":true}' or received != raw or len(chain.upstream.received) != previous_calls + 1:
                        errors.append(protocol + ": HTTP changed body/result/call count")
                    forwarded = json.loads(received)
                    forwarded_text = (forwarded["input"] if protocol == "openai-responses" else forwarded["messages"])[-1]["content"][0]["text"]
                    actual = route_signature(route_mod, forwarded_text)
                    if actual != originals[text]:
                        errors.append(protocol + ": primary/aux domains changed")
                rows.append({"text": text, "lab": op["lab"], "safe": op["safe"], "source": op["event"]["source"],
                             "original": originals[text], "errors": errors})
    except Exception as exc:
        problems.append(f"pipeline failed: {type(exc).__name__}: {exc}")
    bad = [r for r in rows if r["errors"]]
    return {"ok": not problems and not bad, "schema": "rewrite-route-parity/3", "problems": problems,
            "inconsistencies": bad, "rows": rows,
            "summary": {"inputs": len(rows), "http_requests": len(rows) * 3, "failed": len(bad), "alias_entries": len(pairs)}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--interceptor", default=INTERCEPTOR)
    parser.add_argument("--normalize", default=NORMALIZE)
    parser.add_argument("--probes", default=PROBES)
    args = parser.parse_args()
    result = run(args.interceptor, args.probes, args.normalize)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("[INPUT-PARITY] " + json.dumps(result["summary"], ensure_ascii=False))
        for problem in result["problems"]:
            print("[FAIL] " + problem)
        for row in result["rows"] if args.verbose else result["inconsistencies"]:
            print(json.dumps(row, ensure_ascii=False))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    raise SystemExit(main())
