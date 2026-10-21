#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugin-triage.py -- 纯标准库插件包初筛（CRX/VSIX/ASAR/ZIP/目录）。

用法:
    python plugin-triage.py --path extension.crx
    python plugin-triage.py --path extension.vsix --json
    python plugin-triage.py --path app.asar --out out/
    python plugin-triage.py --path ./unpacked-extension

输出：容器识别、manifest/package/plugin.xml 入口、权限面、content script/
background 清单、asar 目录结构、可疑 API 与远程 URL。仅用于自有或明确
授权的插件；不执行包内代码。
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import sys
import zipfile

MAX_TEXT = 2 * 1024 * 1024
MAX_FILES = 4000
TEXT_EXT = {".js", ".mjs", ".cjs", ".ts", ".json", ".xml", ".html", ".htm", ".css", ".txt", ".yml", ".yaml", ".properties"}

SUSPICIOUS = [
    ("eval", re.compile(rb"\beval\s*\(")),
    ("new_Function", re.compile(rb"new\s+Function\s*\(")),
    ("child_process", re.compile(rb"child_process")),
    ("exec_spawn", re.compile(rb"\b(execFile|execSync|exec|spawn|spawnSync)\s*\(")),
    ("shell_openExternal", re.compile(rb"shell\.openExternal")),
    ("fs_access", re.compile(rb"\bfs\.(readFile|writeFile|readdir|unlink|rm|mkdir|open)")),
    ("ipc", re.compile(rb"ipc(Main|Renderer)\.(handle|on|invoke|send|sendSync)")),
    ("contextBridge", re.compile(rb"contextBridge\.exposeInMainWorld")),
    ("nodeIntegration_true", re.compile(rb"nodeIntegration\s*[:=]\s*true")),
    ("contextIsolation_false", re.compile(rb"contextIsolation\s*[:=]\s*false")),
    ("webSecurity_false", re.compile(rb"webSecurity\s*[:=]\s*false")),
    ("nativeMessaging", re.compile(rb"nativeMessaging|connectNative|sendNativeMessage")),
    ("chrome_cookies", re.compile(rb"chrome\.cookies|browser\.cookies")),
    ("webRequest", re.compile(rb"webRequest|declarativeNetRequest")),
    ("debugger", re.compile(rb"chrome\.debugger|browser\.debugger")),
    ("clipboard", re.compile(rb"clipboard(Read|Write)|navigator\.clipboard")),
    ("atob_base64", re.compile(rb"\batob\s*\(|Buffer\.from\([^)]*base64")),
    ("process_env", re.compile(rb"process\.env")),
    ("network_request", re.compile(rb"fetch\s*\(|XMLHttpRequest|https?\.request|net\.request")),
    ("unsafe_eval_csp", re.compile(rb"unsafe-eval")),
    ("remote_script", re.compile(rb"createElement\(['\"]script|importScripts\s*\(")),
]

URL_RE = re.compile(r"""(?:https?|wss?)://[^\s"'<>\)\]\}]+""", re.I)


class TriageError(Exception):
    pass


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(data, limit=MAX_TEXT):
    if isinstance(data, bytes):
        data = data[:limit]
        for enc in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
        return data.decode("latin-1", "replace")
    return data[:limit]


def parse_json_text(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def find_manifest(names):
    cands = [n for n in names if n.replace("\\", "/").lower().endswith("manifest.json")]
    cands.sort(key=lambda n: (n.count("/"), len(n)))
    return cands[0] if cands else None


def find_package(names):
    cands = [n for n in names if n.replace("\\", "/").lower().endswith("package.json")]
    cands.sort(key=lambda n: (0 if n.endswith("extension/package.json") else 1, n.count("/"), len(n)))
    return cands[0] if cands else None


def find_plugin_xml(names):
    cands = [n for n in names if n.replace("\\", "/").lower().endswith("meta-inf/plugin.xml")]
    return cands[0] if cands else None


def manifest_surface(manifest):
    if not isinstance(manifest, dict):
        return {}
    def as_list(v):
        return v if isinstance(v, list) else ([] if v is None else [v])
    bg = manifest.get("background") or {}
    cs = []
    for item in as_list(manifest.get("content_scripts")):
        if isinstance(item, dict):
            cs.append({
                "matches": as_list(item.get("matches")),
                "js": as_list(item.get("js")),
                "css": as_list(item.get("css")),
                "run_at": item.get("run_at", ""),
                "world": item.get("world", "ISOLATED"),
                "all_frames": bool(item.get("all_frames", False)),
            })
    war = []
    for item in as_list(manifest.get("web_accessible_resources")):
        if isinstance(item, dict):
            war.append({"resources": as_list(item.get("resources")), "matches": as_list(item.get("matches"))})
        elif isinstance(item, str):
            war.append({"resources": [item], "matches": []})
    return {
        "manifest_version": manifest.get("manifest_version"),
        "name": manifest.get("name"),
        "version": manifest.get("version"),
        "permissions": as_list(manifest.get("permissions")),
        "optional_permissions": as_list(manifest.get("optional_permissions")),
        "host_permissions": as_list(manifest.get("host_permissions")),
        "background": {
            "service_worker": bg.get("service_worker"),
            "scripts": as_list(bg.get("scripts")),
            "type": bg.get("type"),
            "persistent": bg.get("persistent"),
        },
        "content_scripts": cs,
        "web_accessible_resources": war,
        "externally_connectable": manifest.get("externally_connectable"),
        "commands": manifest.get("commands"),
        "options_page": manifest.get("options_page") or manifest.get("options_ui"),
        "devtools_page": manifest.get("devtools_page"),
        "action": manifest.get("action") or manifest.get("browser_action"),
        "csp": manifest.get("content_security_policy"),
        "key": manifest.get("key"),
        "update_url": manifest.get("update_url"),
    }


def package_surface(pkg):
    if not isinstance(pkg, dict):
        return {}
    contributes = pkg.get("contributes") or {}
    return {
        "name": pkg.get("name"),
        "version": pkg.get("version"),
        "main": pkg.get("main"),
        "activationEvents": pkg.get("activationEvents") or [],
        "commands": (contributes.get("commands") if isinstance(contributes, dict) else None) or [],
        "menus": list((contributes.get("menus") or {}).keys()) if isinstance(contributes, dict) and isinstance(contributes.get("menus"), dict) else [],
        "keybindings": contributes.get("keybindings") if isinstance(contributes, dict) else [],
        "configuration": bool(isinstance(contributes, dict) and contributes.get("configuration")),
        "dependencies": sorted((pkg.get("dependencies") or {}).keys()),
        "devDependencies": sorted((pkg.get("devDependencies") or {}).keys()),
        "scripts": pkg.get("scripts") or {},
        "engines": pkg.get("engines") or {},
        "preload": (pkg.get("preload") or (pkg.get("build") or {}).get("preload") if isinstance(pkg.get("build"), dict) else pkg.get("preload")),
    }


def scan_texts(files, max_files=MAX_FILES):
    """files: list of (name, bytes_or_text). Returns api hits, urls, scanned count."""
    hits = {}
    urls = set()
    scanned = 0
    for name, data in files:
        if scanned >= max_files:
            break
        if len(data) > MAX_TEXT:
            data = data[:MAX_TEXT]
        text = data if isinstance(data, str) else read_text(data)
        if not text:
            continue
        raw = text.encode("utf-8", "ignore")
        scanned += 1
        for hid, rx in SUSPICIOUS:
            found = rx.findall(raw)
            if found:
                h = hits.setdefault(hid, {"count": 0, "files": [], "examples": []})
                h["count"] += len(found)
                if name not in h["files"] and len(h["files"]) < 12:
                    h["files"].append(name)
                for m in rx.finditer(raw):
                    snippet = text[max(0, m.start() - 40):m.end() + 80].replace("\n", " ").strip()
                    if snippet and snippet not in h["examples"] and len(h["examples"]) < 3:
                        h["examples"].append(snippet[:180])
        for m in URL_RE.finditer(text):
            u = m.group(0).rstrip(".,;:'\"")
            if len(u) < 200:
                urls.add(u)
    return hits, sorted(urls)[:120], scanned


def zip_analysis(path):
    raw = open(path, "rb").read()
    container = "zip"
    if raw.startswith(b"Cr24"):
        i = raw.find(b"PK\x03\x04")
        if i < 0:
            raise TriageError("CRX 头后未找到 PK 头")
        raw = raw[i:]
        container = "crx"
    elif raw[:4] == b"PK\x03\x04":
        ext = os.path.splitext(path)[1].lower()
        container = {".vsix": "vsix", ".jar": "jar", ".xpi": "xpi"}.get(ext, "zip")
    else:
        raise TriageError("不是 ZIP/CRX/VSIX/JAR（magic=%s）" % raw[:8].hex())
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise TriageError("ZIP 解析失败: %s" % exc)
    names = zf.namelist()
    manifest_name = find_manifest(names)
    package_name = find_package(names)
    plugin_xml = find_plugin_xml(names)

    def get_json(name):
        if not name:
            return None
        try:
            return parse_json_text(read_text(zf.read(name)))
        except Exception:
            return None

    manifest = get_json(manifest_name)
    pkg = get_json(package_name)
    plugin_text = ""
    if plugin_xml:
        try:
            plugin_text = read_text(zf.read(plugin_xml))
        except Exception:
            plugin_text = ""

    texts = []
    for n in names:
        ext = os.path.splitext(n)[1].lower()
        if ext in TEXT_EXT and not n.endswith("/"):
            try:
                texts.append((n, zf.read(n)))
            except Exception:
                continue
    hits, urls, scanned = scan_texts(texts)

    interesting = [n for n in names if re.search(r"(^|/)(manifest\.json|package\.json|plugin\.xml|[^/]+\.(node|jsc|dll|so|exe|wasm|crx))$", n, re.I)]
    return {
        "container": container,
        "sha256": sha256_file(path),
        "size": os.path.getsize(path),
        "file_count": len(names),
        "top_level": sorted({n.split("/", 1)[0] for n in names})[:40],
        "interesting_files": interesting[:80],
        "entrypoints": {
            "manifest": manifest_name,
            "package": package_name,
            "plugin_xml": plugin_xml,
        },
        "manifest": manifest_surface(manifest),
        "package": package_surface(pkg),
        "plugin_xml": {
            "actions": len(re.findall(r"<action\b", plugin_text)),
            "extensions": len(re.findall(r"<extensions?\b", plugin_text)),
            "application_service": len(re.findall(r"<applicationService\b", plugin_text)),
            "idea_version": (re.search(r"<idea-version[^>]*>", plugin_text) or [""])[0],
        } if plugin_text else {},
        "suspicious_apis": hits,
        "remote_urls": urls,
        "scanned_text_files": scanned,
    }


def parse_asar_header(path):
    with open(path, "rb") as fh:
        head = fh.read(16)
    if len(head) < 12 or head[:4] != b"\x04\x00\x00\x00":
        raise TriageError("不是标准 asar（头 4 字节非 04 00 00 00）")
    header_size = int.from_bytes(head[4:8], "little")
    with open(path, "rb") as fh:
        data = fh.read()
    start = data.find(b"{", 8, 128)
    if start < 0:
        raise TriageError("asar 头中未找到 JSON 起点")
    decoder = json.JSONDecoder()
    try:
        obj, end = decoder.raw_decode(data[start:].decode("utf-8", "replace"))
    except Exception as exc:
        raise TriageError("asar JSON 头解析失败: %s" % exc)
    data_offset = max(8 + header_size, start + end)
    data_offset = (data_offset + 3) & ~3
    return obj, data_offset, len(data)


def walk_asar(node, prefix=""):
    entries = []
    for name, info in sorted((node.get("files") or {}).items()):
        p = (prefix + "/" + name).lstrip("/")
        if not isinstance(info, dict):
            continue
        if "files" in info:
            entries.append({"path": p, "dir": True})
            entries.extend(walk_asar(info, p))
        else:
            entries.append({
                "path": p, "dir": False, "size": info.get("size", 0),
                "offset": info.get("offset", 0), "unpacked": bool(info.get("unpacked", False)),
                "link": info.get("link"),
            })
    return entries


def asar_analysis(path):
    header, data_offset, total = parse_asar_header(path)
    entries = walk_asar(header)
    dirs = [e["path"] for e in entries if e["dir"]]
    files = [e for e in entries if not e["dir"]]
    interesting = [e["path"] for e in files if re.search(r"(^|/)(package\.json|[^/]+\.(node|jsc|dll|so|exe|wasm))$", e["path"], re.I)]
    pkg = None
    pkg_path = None
    pkg_entry = next((e for e in files if e["path"] == "package.json"), None)
    if pkg_entry:
        for delta in (0, 4, -4, 8, -8):
            try:
                with open(path, "rb") as fh:
                    fh.seek(max(0, data_offset + pkg_entry["offset"] + delta))
                    text = read_text(fh.read(min(pkg_entry.get("size") or 65536, MAX_TEXT)))
                start = text.find("{")
                if start >= 0:
                    pkg = parse_json_text(text[start:])
                if isinstance(pkg, dict) and ("name" in pkg or "main" in pkg):
                    pkg_path = pkg_entry["path"]
                    break
            except Exception:
                continue
    return {
        "container": "asar",
        "sha256": sha256_file(path),
        "size": total,
        "header_size": len(json.dumps(header)),
        "data_offset": data_offset,
        "dir_count": len(dirs),
        "file_count": len(files),
        "top_level": sorted({e["path"].split("/", 1)[0] for e in entries})[:40],
        "directories": dirs[:120],
        "interesting_files": interesting[:80],
        "unpacked_files": [e["path"] for e in files if e["unpacked"]][:80],
        "package": package_surface(pkg),
        "entrypoints": {"package": pkg_path or "package.json", "main": (pkg or {}).get("main") if isinstance(pkg, dict) else None},
    }


def dir_analysis(path):
    names = []
    for root, dirs, fs in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules")]
        for f in fs:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, path).replace("\\", "/")
            names.append(rel)
            if len(names) >= MAX_FILES:
                break
        if len(names) >= MAX_FILES:
            break
    manifest_name = find_manifest(names)
    package_name = find_package(names)
    plugin_xml = find_plugin_xml(names)

    def get_json(name):
        if not name:
            return None
        try:
            return parse_json_text(read_text(open(os.path.join(path, name), "rb").read()))
        except Exception:
            return None

    manifest = get_json(manifest_name)
    pkg = get_json(package_name)
    plugin_text = ""
    if plugin_xml:
        try:
            plugin_text = read_text(open(os.path.join(path, plugin_xml), "rb").read())
        except Exception:
            plugin_text = ""
    texts = []
    for n in names:
        if os.path.splitext(n)[1].lower() in TEXT_EXT:
            try:
                texts.append((n, open(os.path.join(path, n), "rb").read()))
            except Exception:
                continue
    hits, urls, scanned = scan_texts(texts)
    interesting = [n for n in names if re.search(r"(^|/)(manifest\.json|package\.json|plugin\.xml|[^/]+\.(node|jsc|dll|so|exe|wasm))$", n, re.I)]
    asar_files = [n for n in names if n.lower().endswith(".asar")]
    return {
        "container": "directory",
        "file_count": len(names),
        "top_level": sorted({n.split("/", 1)[0] for n in names})[:40],
        "interesting_files": interesting[:80],
        "asar_files": asar_files,
        "entrypoints": {"manifest": manifest_name, "package": package_name, "plugin_xml": plugin_xml},
        "manifest": manifest_surface(manifest),
        "package": package_surface(pkg),
        "plugin_xml": {
            "actions": len(re.findall(r"<action\b", plugin_text)),
            "extensions": len(re.findall(r"<extensions?\b", plugin_text)),
            "application_service": len(re.findall(r"<applicationService\b", plugin_text)),
        } if plugin_text else {},
        "suspicious_apis": hits,
        "remote_urls": urls,
        "scanned_text_files": scanned,
    }


def analyze(path):
    if not os.path.exists(path):
        raise TriageError("路径不存在")
    if os.path.isdir(path):
        result = dir_analysis(path)
    else:
        with open(path, "rb") as fh:
            magic = fh.read(8)
        if magic[:4] == b"\x04\x00\x00\x00":
            result = asar_analysis(path)
        elif magic[:4] == b"PK\x03\x04" or magic.startswith(b"Cr24"):
            result = zip_analysis(path)
        else:
            raise TriageError("无法识别的容器（magic=%s）；支持 crx/vsix/asar/zip/目录" % magic.hex())
    result["ok"] = True
    result["path"] = os.path.abspath(path)
    result["type"] = _type_label(result)
    result["conclusion"] = _conclusion(result)
    return result


def _type_label(r):
    c = r.get("container")
    if c == "crx":
        return "Chrome/Edge CRX 扩展"
    if c == "vsix":
        return "VS Code VSIX 扩展"
    if c == "jar":
        return "JetBrains/JAR 插件"
    if c == "xpi":
        return "Firefox XPI 扩展"
    if c == "asar":
        return "Electron asar 包"
    if c == "zip" and (r.get("entrypoints") or {}).get("manifest"):
        return "ZIP 浏览器扩展包"
    if c == "zip" and (r.get("entrypoints") or {}).get("package"):
        return "ZIP/Node 插件包"
    if c == "directory":
        if (r.get("entrypoints") or {}).get("manifest"):
            return "解压目录（浏览器扩展）"
        if (r.get("entrypoints") or {}).get("package"):
            return "解压目录（Node/Electron/VSIX）"
        return "插件目录"
    return "ZIP/未知插件包"


def _conclusion(r):
    e = r.get("entrypoints") or {}
    have = [k for k in ("manifest", "package", "plugin_xml") if e.get(k)]
    apis = r.get("suspicious_apis") or {}
    high = [k for k in ("nativeMessaging", "debugger", "child_process", "exec_spawn",
                        "shell_openExternal", "nodeIntegration_true", "contextIsolation_false")
            if k in apis]
    if not have:
        return "未找到 manifest/package/plugin.xml：只能确认容器与文件结构，入口未闭环"
    if high:
        return "入口已定位；高风险面=%s；需人工确认数据流与最小可改单元" % ",".join(high)
    return "入口已定位；未命中高风险 API 不代表安全，需补数据流与动态证据"


def print_human(r):
    print("== plugin triage ==")
    print("path      : %s" % r["path"])
    print("type      : %s  container=%s" % (r["type"], r.get("container")))
    if r.get("sha256"):
        print("sha256    : %s  size=%s" % (r["sha256"], r.get("size")))
    print("entry     : %s" % json.dumps(r.get("entrypoints") or {}, ensure_ascii=False))
    print("files     : %s  text_scanned=%s" % (r.get("file_count"), r.get("scanned_text_files")))
    m = r.get("manifest") or {}
    if m:
        print("\n-- manifest --")
        print("name/ver  : %s / %s  mv=%s" % (m.get("name"), m.get("version"), m.get("manifest_version")))
        print("permissions: %s" % ", ".join(m.get("permissions") or []) or "(none)")
        print("host_perms : %s" % ", ".join(m.get("host_permissions") or []) or "(none)")
        print("background : %s" % json.dumps(m.get("background") or {}, ensure_ascii=False))
        for cs in m.get("content_scripts") or []:
            print("content    : %s -> %s (world=%s, run_at=%s)" % (
                cs.get("matches"), cs.get("js"), cs.get("world"), cs.get("run_at")))
        if m.get("web_accessible_resources"):
            print("war        : %s" % json.dumps(m.get("web_accessible_resources"), ensure_ascii=False)[:300])
    p = r.get("package") or {}
    if p:
        print("\n-- package --")
        print("name/ver  : %s / %s" % (p.get("name"), p.get("version")))
        print("main      : %s  activation=%s" % (p.get("main"), p.get("activationEvents")))
        if p.get("commands"):
            print("commands  : %s" % json.dumps(p.get("commands"), ensure_ascii=False)[:300])
        if p.get("dependencies"):
            print("deps      : %s" % ", ".join(p.get("dependencies")[:20]))
    if r.get("plugin_xml"):
        print("\n-- plugin.xml -- %s" % json.dumps(r["plugin_xml"], ensure_ascii=False))
    if r.get("asar_files"):
        print("asar files: %s" % ", ".join(r["asar_files"]))
    if r.get("top_level"):
        print("\n-- top level -- %s" % ", ".join(r["top_level"]))
    if r.get("directories"):
        print("dirs      : %s" % ", ".join(r["directories"][:30]))
    if r.get("unpacked_files"):
        print("unpacked  : %s" % ", ".join(r["unpacked_files"][:20]))
    print("\n-- suspicious APIs --")
    if not r.get("suspicious_apis"):
        print("(none matched)")
    for k, v in sorted((r.get("suspicious_apis") or {}).items()):
        print("%-24s count=%-4d files=%s" % (k, v["count"], ", ".join(v["files"][:4])))
        for ex in v.get("examples", [])[:2]:
            print("    | %s" % ex)
    print("\n-- remote URLs --")
    for u in (r.get("remote_urls") or [])[:60]:
        print("  %s" % u)
    if not r.get("remote_urls"):
        print("(none)")
    print("\nconclusion: %s" % r.get("conclusion"))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="纯标准库插件初筛：CRX/VSIX/ASAR/ZIP/目录（manifest 权限面、入口、可疑 API、远程 URL）")
    ap.add_argument("--path", "-p", required=True, help="crx/vsix/asar/zip 文件或解压目录")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--out", help="写出 plugin-triage.json 的目录")
    args = ap.parse_args(argv)
    try:
        result = analyze(args.path)
    except TriageError as exc:
        err = {"ok": False, "error": "triage_failed", "path": args.path, "detail": str(exc),
               "hint": "先 file/xxd 确认容器；CRX/ZIP 可用 zipfile，asar 需标准头"}
        print(json.dumps(err, ensure_ascii=False) if args.json else "[FAIL] %s" % exc)
        return 2
    except OSError as exc:
        err = {"ok": False, "error": "io_error", "path": args.path, "detail": str(exc)}
        print(json.dumps(err, ensure_ascii=False) if args.json else "[FAIL] %s" % exc)
        return 2
    if args.out:
        os.makedirs(args.out, exist_ok=True)
        out = os.path.join(args.out, "plugin-triage.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
        print("wrote: %s" % out)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print_human(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
