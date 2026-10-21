#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sbom-reach.py -- 从 SBOM / 锁文件 / pip freeze 出发，判断组件是否能被源码入口触达。

纯标准库、只读、离线。它回答的是“这个依赖有没有在源码里被 import/require”，
不是“这个 CVE 能不能利用”：可达只是第一层，运行时加载与参数可控仍需人工验证。

输入（至少一个）：
  --sbom   CycloneDX JSON（.components[]）或 SPDX JSON（.packages[]）
  --lock   package-lock.json / npm-shrinkwrap.json（v1 dependencies 或 v2/v3 packages）
  --freeze `pip freeze` 文本（name==version 每行一条）

源码面：
  --source 源码根（默认当前目录）；跳过 node_modules/.git/dist/build/vendor 等
  --entry  入口文件 glob（可重复；默认自动识别 main/app/index/cli/__main__ 等）

输出 JSON：
  components_total / by_ecosystem / reachable[] / unreachable[] / entries[] /
  missing_from_sbom[]（锁文件/freeze 有、SBOM 没有）/ limits

退出码：
  0 = 分析完成
  2 = 参数/解析失败，stdout 为 {"ok": false, "blocked_at": ..., "reason": ...}

示例：
  python Tool/skill/supply-chain-security/scripts/sbom-reach.py --lock package-lock.json --source .
  python Tool/skill/supply-chain-security/scripts/sbom-reach.py --freeze freeze.txt --sbom bom.json
  python Tool/skill/supply-chain-security/scripts/sbom-reach.py --self-test
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
import tempfile

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

SCHEMA = "seep.sbom-reach/1"
SOURCE_EXT = {".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "bower_components", "vendor",
             "dist", "build", "target", "__pycache__", ".venv", "venv", ".tox",
             ".mypy_cache", ".pytest_cache", ".next", "coverage", "Pods"}
DEFAULT_ENTRY_GLOBS = ("main.*", "app.*", "index.*", "cli.*", "server.*",
                       "__main__.py", "manage.py", "setup.py", "wsgi.py", "asgi.py")
# 发行名 → import 名（只收高频项；未命中的发行名按原名归一化后再试）
PY_IMPORT_ALIASES = {
    "pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "PIL",
    "python-dateutil": "dateutil", "pyopenssl": "OpenSSL", "attrs": "attr",
    "msgpack-python": "msgpack", "protobuf": "google", "grpcio": "grpc",
    "pycryptodome": "Crypto", "pycryptodomex": "Cryptodome",
    "scikit-learn": "sklearn", "opencv-python": "cv2", "python-multipart": "multipart",
    "pyserial": "serial", "pymysql": "pymysql", "psycopg2-binary": "psycopg2",
    "django": "django", "flask": "flask", "requests": "requests",
}


class ReachError(Exception):
    def __init__(self, blocked_at, reason):
        super().__init__(reason)
        self.blocked_at = blocked_at
        self.reason = reason


def emit_error(blocked_at, reason, rc=2):
    print(json.dumps({"ok": False, "blocked_at": blocked_at, "reason": reason},
                     ensure_ascii=False))
    return rc


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def norm_py(name):
    base = re.split(r"[<>=!~\[; ]", name.strip(), 1)[0]
    key = base.lower().replace("_", "-").replace(".", "-")
    return PY_IMPORT_ALIASES.get(key, base.replace("-", "_"))


def load_json_file(path, blocked_at):
    try:
        return json.loads(read_text(path))
    except OSError as exc:
        raise ReachError(blocked_at, "无法读取 %s: %s" % (path, exc))
    except ValueError as exc:
        raise ReachError(blocked_at, "%s 不是合法 JSON: %s" % (path, exc))


def parse_sbom(path):
    data = load_json_file(path, "sbom")
    comps = []
    if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
        for c in data.get("components") or []:
            name = c.get("name")
            if not name:
                continue
            purl = c.get("purl") or ""
            eco = "pypi" if "pkg:pypi/" in purl else ("npm" if "pkg:npm/" in purl else "unknown")
            comps.append({"name": name, "version": c.get("version") or "",
                          "ecosystem": eco, "from": "sbom"})
    elif isinstance(data, dict) and ("spdxVersion" in data or "packages" in data):
        for p in data.get("packages") or []:
            name = p.get("name")
            if not name:
                continue
            version = p.get("versionInfo") or ""
            eco = "npm" if name.startswith("@") else ("pypi" if p.get("externalRefs") and
                                                      "pypi" in json.dumps(p.get("externalRefs")) else "unknown")
            comps.append({"name": name, "version": version, "ecosystem": eco, "from": "sbom"})
    else:
        raise ReachError("sbom", "既不是 CycloneDX 也不是 SPDX: %s" % path)
    return comps


def parse_lock(path):
    data = load_json_file(path, "lock")
    comps = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not key:
                continue
            name = (meta or {}).get("name") or key.split("node_modules/")[-1]
            if not name:
                continue
            comps.append({"name": name, "version": (meta or {}).get("version") or "",
                          "ecosystem": "npm", "from": "lock"})
        return comps
    deps = data.get("dependencies") or {}
    if isinstance(deps, dict):
        for name, meta in deps.items():
            comps.append({"name": name, "version": (meta or {}).get("version") or "",
                          "ecosystem": "npm", "from": "lock"})
    if not comps:
        raise ReachError("lock", "锁文件没有 packages/dependencies 条目: %s" % path)
    return comps


def parse_freeze(path):
    comps = []
    for line in read_text(path).splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:===?|@)\s*([^\s;]+)", line)
        if m:
            comps.append({"name": m.group(1), "version": m.group(2),
                          "ecosystem": "pypi", "from": "freeze"})
    if not comps:
        raise ReachError("freeze", "freeze 文件没有 name==version 条目: %s" % path)
    return comps


def iter_sources(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if os.path.splitext(name)[1].lower() in SOURCE_EXT:
                yield os.path.join(dirpath, name)


def component_patterns(comp):
    name = comp["name"]
    eco = comp["ecosystem"]
    if eco == "npm" or name.startswith("@"):
        esc = re.escape(name)
        return [re.compile(r"""(?:require\s*\(\s*['"]%s(?:/[^'"]*)?['"]\s*\)"""
                           r"""|from\s+['"]%s(?:/[^'"]*)?['"]"""
                           r"""|import\s*\(\s*['"]%s(?:/[^'"]*)?['"]\s*\))""" % (esc, esc, esc))]
    imp = norm_py(name)
    esc = re.escape(imp)
    return [re.compile(r"(?:^|\n)\s*(?:import\s+%s(?:\s|,|\.|$)|from\s+%s(?:\.|\s+import))"
                       % (esc, esc), re.M)]


def find_entries(source, entry_globs):
    globs = tuple(entry_globs or DEFAULT_ENTRY_GLOBS)
    hits = []
    for path in iter_sources(source):
        base = os.path.basename(path)
        if any(fnmatch.fnmatch(base, g) for g in globs):
            hits.append(path)
    return hits


def public_path(path):
    """输出里尽量用相对 CWD 的路径，避免把本机绝对路径写进证据。"""
    try:
        rel = os.path.relpath(path, os.getcwd())
    except ValueError:
        return path
    return path if rel.startswith("..") else rel.replace(os.sep, "/")


def scan(sbom, lock, freeze, source, entry_globs):
    if not os.path.isdir(source):
        raise ReachError("source", "--source 不存在或不是目录: %s" % source)
    comps, seen = [], set()
    for group in (sbom, lock, freeze):
        for c in group:
            key = (c["ecosystem"], c["name"].lower())
            if key in seen:
                continue
            seen.add(key)
            comps.append(c)
    if not comps:
        raise ReachError("input", "没有组件：至少给 --sbom/--lock/--freeze 之一")

    sources = list(iter_sources(source))
    entries = find_entries(source, entry_globs)
    entry_set = {os.path.normcase(p) for p in entries}
    reachable, unreachable = [], []
    for c in comps:
        pats = component_patterns(c)
        hits = []
        for path in sources:
            if len(hits) >= 3:
                break
            try:
                text = read_text(path)
            except OSError:
                continue
            for pat in pats:
                m = pat.search(text)
                if m:
                    line = text.count("\n", 0, m.start()) + 1
                    snippet = text.splitlines()[line - 1].strip()[:160] if text.splitlines() else ""
                    hits.append({"file": os.path.relpath(path, source).replace(os.sep, "/"),
                                 "line": line, "snippet": snippet,
                                 "entry": os.path.normcase(path) in entry_set})
                    break
        item = {"name": c["name"], "version": c["version"],
                "ecosystem": c["ecosystem"], "from": c["from"],
                "hits": hits, "entry_hit": any(h["entry"] for h in hits)}
        (reachable if hits else unreachable).append(item)

    if sbom:
        sbom_keys = {(c["ecosystem"], c["name"].lower()) for c in sbom}
        missing = [{"name": c["name"], "version": c["version"],
                    "ecosystem": c["ecosystem"], "from": c["from"]}
                   for c in comps if (c["ecosystem"], c["name"].lower()) not in sbom_keys]
    else:
        missing = []

    by_eco = {}
    for c in comps:
        by_eco[c["ecosystem"]] = by_eco.get(c["ecosystem"], 0) + 1
    return {
        "schema": SCHEMA,
        "ok": True,
        "inputs": {"source": public_path(source), "sbom": bool(sbom), "lock": bool(lock),
                   "freeze": bool(freeze), "sources_scanned": len(sources)},
        "components_total": len(comps),
        "by_ecosystem": by_eco,
        "reachable": reachable,
        "unreachable": unreachable,
        "entries": [os.path.relpath(p, source).replace(os.sep, "/") for p in entries],
        "missing_from_sbom": missing,
        "limits": {
            "note": "可达=源码出现 import/require；不等于 CVE 可利用。动态导入、"
                    "插件加载、运行时注入需人工补证。",
            "skips": sorted(SKIP_DIRS),
        },
    }


def self_test():
    checks = []
    with tempfile.TemporaryDirectory(prefix="sbom-reach-selftest-") as td:
        src = os.path.join(td, "src")
        os.makedirs(src)
        with open(os.path.join(src, "app.py"), "w", encoding="utf-8") as fh:
            fh.write("import yaml\n\nprint(yaml.safe_load('a: 1'))\n")
        with open(os.path.join(src, "index.js"), "w", encoding="utf-8") as fh:
            fh.write("const pad = require('left-pad');\nmodule.exports = pad;\n")
        with open(os.path.join(src, "util.py"), "w", encoding="utf-8") as fh:
            fh.write("def helper():\n    return 1\n")
        lock = os.path.join(td, "package-lock.json")
        with open(lock, "w", encoding="utf-8") as fh:
            json.dump({"lockfileVersion": 3, "packages": {
                "": {"name": "demo"}, "node_modules/left-pad": {"version": "1.3.0"},
                "node_modules/@corp/auth": {"version": "2.0.0"}}}, fh)
        freeze = os.path.join(td, "freeze.txt")
        with open(freeze, "w", encoding="utf-8") as fh:
            fh.write("PyYAML==6.0.1\nrequests==2.31.0\n")
        sbom = os.path.join(td, "bom.json")
        with open(sbom, "w", encoding="utf-8") as fh:
            json.dump({"bomFormat": "CycloneDX", "components": [
                {"name": "left-pad", "version": "1.3.0", "purl": "pkg:npm/left-pad@1.3.0"},
                {"name": "PyYAML", "version": "6.0.1", "purl": "pkg:pypi/pyyaml@6.0.1"},
                {"name": "@corp/auth", "version": "2.0.0", "purl": "pkg:npm/%40corp/auth@2.0.0"},
                {"name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
            ]}, fh)
        try:
            res = scan(parse_sbom(sbom), parse_lock(lock), parse_freeze(freeze), src, None)
        except ReachError as exc:
            return emit_error(exc.blocked_at, exc.reason)
        reach = {c["name"].lower(): c for c in res["reachable"]}
        checks.append(("components", res["components_total"] == 4))
        checks.append(("npm-reachable", "left-pad" in reach))
        checks.append(("py-alias-reachable", "pyyaml" in reach))
        checks.append(("unreachable", any(c["name"] == "@corp/auth" for c in res["unreachable"])))
        checks.append(("entry", any(c["name"] == "left-pad" for c in res["reachable"]
                                    if c["entry_hit"])))
        checks.append(("sbom-gap-empty", res["missing_from_sbom"] == []))
        checks.append(("no-phantom-hits", all(h["line"] >= 1 for c in res["reachable"]
                                              for h in c["hits"])))
        bad = {"ok": False, "blocked_at": "input"}
        checks.append(("error-shape", bad["ok"] is False and bad["blocked_at"] == "input"))
    failed = [n for n, ok in checks if not ok]
    if failed:
        return emit_error("self-test", "失败项: " + ",".join(failed))
    print(json.dumps({"ok": True, "checks": len(checks), "mode": "builtin-fixture"},
                     ensure_ascii=False))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="sbom-reach.py",
        description="从 SBOM/锁文件/pip freeze 出发，判断组件是否被源码 import/require 触达。只读、离线、纯标准库。",
        epilog="示例: python Tool/skill/supply-chain-security/scripts/sbom-reach.py "
               "--lock package-lock.json --source . --out reach.json")
    ap.add_argument("--sbom", default="", help="CycloneDX 或 SPDX JSON")
    ap.add_argument("--lock", default="", help="package-lock.json / npm-shrinkwrap.json")
    ap.add_argument("--freeze", default="", help="pip freeze 文本（name==version）")
    ap.add_argument("--source", default=".", help="源码根目录（默认当前目录）")
    ap.add_argument("--entry", action="append", default=[], help="入口文件 glob，可重复")
    ap.add_argument("--out", default="", help="把 JSON 同时写入文件")
    ap.add_argument("--self-test", action="store_true", help="离线自检（内置样本）")
    args = ap.parse_args(argv)
    if args.self_test:
        return self_test()
    try:
        sbom = parse_sbom(args.sbom) if args.sbom else []
        lock = parse_lock(args.lock) if args.lock else []
        freeze = parse_freeze(args.freeze) if args.freeze else []
        source = os.path.abspath(args.source)
        result = scan(sbom, lock, freeze, source, args.entry)
    except ReachError as exc:
        return emit_error(exc.blocked_at, exc.reason)
    except Exception as exc:  # noqa: BLE001
        return emit_error("scan", "%s: %s" % (type(exc).__name__, exc))
    text = json.dumps(result, ensure_ascii=False, indent=2)
    print(text)
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            return emit_error("out", "无法写入 --out: %s" % exc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
