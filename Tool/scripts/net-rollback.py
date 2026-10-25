#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""net-rollback.py -- 本机网络状态 快照 / 还原 / 探活。

为什么单独做一个标准件（2026-10-23 血案）：
  某次为了"接管授权服务端"，Agent 给正在上网的 DHCP 网卡挂了 /32 别名 IP，
  又用 `netsh winhttp set proxy` 指向本地假服务器。假服务器一杀，全机断网，
  用户只能靠自己找"断网恢复助手"才恢复。

  分析机常常就是用户的日常机。**改本机全局网络 = 把用户和 Agent 一起搞离线。**
  所以约定：任何触及网络状态的动作，必须先 snapshot，且必须有 restore 路径。

铁律（脚本已内置）：
  1. 绝不删除 PrefixOrigin=Dhcp 的地址（那是用户本来就在用的）。
  2. 绝不改动路由表（只报告，不动手）。
  3. hosts 只从快照副本还原，不做"智能合并"。
  4. restore 结束后一定跑 verify；verify 不过就非 0 退出。

用法:
    python Tool/scripts/net-rollback.py snapshot
    python Tool/scripts/net-rollback.py diff
    python Tool/scripts/net-rollback.py restore            # 从 latest 快照还原
    python Tool/scripts/net-rollback.py restore --from <file>
    python Tool/scripts/net-rollback.py verify             # 探活，0=通
    python Tool/scripts/net-rollback.py list

退出码：0 正常 / 1 探活失败 / 2 输入或环境错误
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone

HOME = os.path.expanduser("~")
STORE = os.path.join(HOME, ".seep", "net")
HOSTS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
PROBE_URLS = ("http://www.baidu.com", "http://connect.rom.miui.com/generate_204")


# ────────────────────────────── 基础设施 ──────────────────────────────

_DRY = False


def ps(script: str, timeout: int = 30) -> str:
    """跑一段 PowerShell，返回 stdout。

    编码处理：中文 Windows 上 netsh 之类原生程序按控制台代码页（GBK）输出，
    直接 utf-8 解会变乱码 —— 那样 "直接访问（没有代理服务器）" 就识别不到了。
    这里按 utf-8 → gbk → latin-1 依次回退。
    """
    if _DRY:
        print("[dry-run] " + script)
        return ""
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, timeout=timeout,
        )
        raw = p.stdout or b""
    except Exception:
        return ""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc).strip()
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace").strip()


def ps_json(script: str, timeout: int = 30):
    raw = ps("$ErrorActionPreference='SilentlyContinue';" + script + " | ConvertTo-Json -Depth 5 -Compress", timeout)
    if not raw:
        return []
    try:
        d = json.loads(raw)
        return d if isinstance(d, list) else [d]
    except Exception:
        return []


def read_hosts() -> str:
    try:
        with open(HOSTS, "rb") as f:
            return f.read().decode("utf-8", "replace")
    except Exception:
        return ""


def ensure_store() -> None:
    os.makedirs(STORE, exist_ok=True)


# ────────────────────────────── 采集 ──────────────────────────────

def collect() -> dict:
    ips = ps_json(
        "Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,InterfaceAlias,"
        "IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin"
    )
    adapters = ps_json(
        "Get-NetAdapter | Select-Object ifIndex,Name,InterfaceDescription,Status,MacAddress,ifOperStatus"
    )
    routes = ps_json(
        "Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0'} | "
        "Select-Object InterfaceIndex,NextHop,RouteMetric,DestinationPrefix"
    )
    dns = ps_json(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,InterfaceAlias,ServerAddresses"
    )
    winhttp_raw = ps("netsh winhttp show proxy")
    winhttp = parse_winhttp(winhttp_raw)
    env_proxy = {k: v for k, v in os.environ.items()
                 if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
    hosts_text = read_hosts()
    return {
        "schema": "seep-net-snapshot/1",
        "taken_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "ipv4_addresses": ips,
        "adapters": adapters,
        "default_routes": routes,
        "dns_servers": dns,
        "winhttp_proxy": winhttp,
        "winhttp_raw": winhttp_raw,
        "env_proxy": env_proxy,
        "hosts_path": HOSTS,
        "hosts_text": hosts_text,
        "hosts_nonblank_lines": [ln for ln in hosts_text.splitlines() if ln.strip() and not ln.strip().startswith("#")],
        "loopback_alias_hint": "以下地址若不在快照里且不是 Dhcp，就是被人后加的：",
    }


def parse_winhttp(raw: str) -> dict:
    low = (raw or "").lower()
    direct_markers = ("direct access", "直接访问", "没有代理服务器", "没有代理", "no proxy server")
    if any(m in low or m in (raw or "") for m in direct_markers):
        return {"mode": "direct", "raw": raw}
    server, bypass = "", ""
    for ln in (raw or "").splitlines():
        if ":" not in ln:
            continue
        k, _, v = ln.partition(":")
        k = k.strip().lower()
        if "proxy server" in k or "代理服务器" in k:
            server = v.strip()
        elif "bypass" in k or "绕过" in k:
            bypass = v.strip()
    return {"mode": "proxy" if server else "unknown", "server": server, "bypass": bypass, "raw": raw}


# ────────────────────────────── 快照 / 还原 ──────────────────────────────

def latest_path() -> str:
    return os.path.join(STORE, "latest.json")


def do_snapshot(args) -> int:
    ensure_store()
    snap = collect()
    ts = time.strftime("%Y%m%d-%H%M%S")
    path = os.path.join(STORE, f"net-{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snap, f, ensure_ascii=False, indent=1)
    shutil.copyfile(path, latest_path())
    # hosts 单独存一份纯文本，还原时直接覆盖
    if snap["hosts_text"]:
        with open(os.path.join(STORE, f"hosts-{ts}.bak"), "w", encoding="utf-8") as f:
            f.write(snap["hosts_text"])
    if args.json:
        print(json.dumps({"ok": True, "snapshot": path, "ips": len(snap["ipv4_addresses"]),
                          "winhttp": snap["winhttp_proxy"].get("mode")}, ensure_ascii=False))
    else:
        print(f"[snapshot] {path}")
        print(f"  网卡地址 {len(snap['ipv4_addresses'])} 条 / 默认路由 {len(snap['default_routes'])} 条"
              f" / WinHTTP 代理 = {snap['winhttp_proxy'].get('mode')}")
        print(f"  hosts 非注释行 {len(snap['hosts_nonblank_lines'])} 条")
    return 0


def load_snapshot(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def do_diff(args) -> int:
    path = args.from_file or latest_path()
    if not os.path.exists(path):
        print(f"[ERROR] 没有快照：{path}（先跑 snapshot）", file=sys.stderr)
        return 2
    old = load_snapshot(path)
    new = collect()

    def key_ips(s):
        return {(str(x.get("InterfaceIndex")), x.get("IPAddress"), str(x.get("PrefixLength"))) for x in s["ipv4_addresses"]}

    added = sorted(key_ips(new) - key_ips(old))
    removed = sorted(key_ips(old) - key_ips(new))
    rows = []
    if added:
        rows.append(("新增地址（可能是别人/上次操作加的）", added))
    if removed:
        rows.append(("消失地址", removed))
    if old["winhttp_proxy"].get("mode") != new["winhttp_proxy"].get("mode") or \
       old["winhttp_proxy"].get("server") != new["winhttp_proxy"].get("server"):
        rows.append(("WinHTTP 代理变了", [(old["winhttp_proxy"].get("mode"), old["winhttp_proxy"].get("server")),
                                       (new["winhttp_proxy"].get("mode"), new["winhttp_proxy"].get("server"))]))
    if old["hosts_nonblank_lines"] != new["hosts_nonblank_lines"]:
        rows.append(("hosts 变了", [old["hosts_nonblank_lines"], new["hosts_nonblank_lines"]]))
    if old["default_routes"] != new["default_routes"]:
        rows.append(("默认路由变了", [old["default_routes"], new["default_routes"]]))

    if args.json:
        print(json.dumps({"from": path, "drift": [r[0] for r in rows]}, ensure_ascii=False))
    else:
        print(f"[diff] 基准 = {path}")
        if not rows:
            print("  无漂移")
        for label, val in rows:
            print(f"  · {label}: {json.dumps(val, ensure_ascii=False)[:400]}")
    return 0


def do_restore(args) -> int:
    # 默认只演练：改整机网络是最贵的副作用，必须显式 --yes 才真执行
    global _DRY
    if not getattr(args, "yes", False):
        args.dry_run = True
    _DRY = bool(getattr(args, "dry_run", False))
    path = args.from_file or latest_path()
    if not os.path.exists(path):
        print(f"[ERROR] 没有快照可还原：{path}", file=sys.stderr)
        print("  兜底手工恢复：netsh winhttp reset proxy ; ipconfig /flushdns", file=sys.stderr)
        return 2
    snap = load_snapshot(path)
    acted = []

    # 1) WinHTTP 代理：快照是 direct 就 reset；是 proxy 就重新写回
    wp = snap.get("winhttp_proxy") or {}
    if wp.get("mode") == "direct":
        ps("netsh winhttp reset proxy")
        acted.append("netsh winhttp reset proxy")
    elif wp.get("mode") == "proxy" and wp.get("server"):
        bypass = wp.get("bypass") or ""
        ps(f"netsh winhttp set proxy {wp['server']}" + (f" bypass-list=\"{bypass}\"" if bypass else ""))
        acted.append(f"netsh winhttp set proxy {wp['server']}")

    # 2) 清掉"不是 Dhcp 且不在快照里"的地址（就是被后加的别名）
    keep = {(str(x.get("InterfaceIndex")), x.get("IPAddress"), str(x.get("PrefixLength")))
            for x in snap.get("ipv4_addresses", [])}
    for cur in collect()["ipv4_addresses"]:
        origin = str(cur.get("PrefixOrigin") or "")
        ident = (str(cur.get("InterfaceIndex")), cur.get("IPAddress"), str(cur.get("PrefixLength")))
        if ident in keep:
            continue
        if origin.lower() == "dhcp":
            continue          # 铁律 1：用户的 DHCP 地址绝不动
        if str(cur.get("IPAddress", "")).startswith("169.254."):
            continue          # APIPA，系统自己会收
        if args.dry_run:
            acted.append(f"[dry-run] 会删 {cur.get('InterfaceAlias')} {cur.get('IPAddress')}/{cur.get('PrefixLength')}")
            continue
        ps(f"Remove-NetIPAddress -InterfaceIndex {cur.get('InterfaceIndex')} "
           f"-IPAddress {cur.get('IPAddress')} -Confirm:$false")
        acted.append(f"Remove-NetIPAddress {cur.get('InterfaceAlias')} {cur.get('IPAddress')}/{cur.get('PrefixLength')}")

    # 3) hosts 还原（只在内容不同且快照有备份时）
    if snap.get("hosts_text") and read_hosts() != snap["hosts_text"] and not args.dry_run:
        try:
            with open(HOSTS, "wb") as f:
                f.write(snap["hosts_text"].encode("utf-8"))
            acted.append("hosts 已按快照还原")
        except PermissionError:
            acted.append("[WARN] hosts 需要管理员权限，未还原")
    elif snap.get("hosts_text") and read_hosts() != snap["hosts_text"]:
        acted.append("[dry-run] 会还原 hosts")

    # 4) DNS 缓存
    if not args.dry_run:
        ps("ipconfig /flushdns")
        acted.append("ipconfig /flushdns")

    ok, detail = verify_network()
    if args.json:
        print(json.dumps({"ok": ok, "from": path, "actions": acted, "verify": detail}, ensure_ascii=False))
    else:
        print(f"[restore] 基准 = {path}")
        for a in acted or ["（无需动作）"]:
            print(f"  - {a}")
        print(f"[verify] {'通' if ok else '不通'}")
        for k, v in detail.items():
            print(f"  {k}: {v}")
    return 0 if ok else 1


# ────────────────────────────── 探活 ──────────────────────────────

def verify_network() -> tuple[bool, dict]:
    detail: dict = {}
    routes = ps_json("Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0'} | "
                     "Select-Object InterfaceIndex,NextHop,RouteMetric")
    detail["default_routes"] = routes or "无（★这通常是断网主因）"

    aliases = [f"{a.get('InterfaceAlias')} {a.get('IPAddress')}/{a.get('PrefixLength')}"
               for a in collect()["ipv4_addresses"] if str(a.get("PrefixOrigin", "")).lower() == "manual"]
    detail["manual_ips"] = aliases or "无"

    tcp_ok, tcp_err = False, ""
    for host, port in (("223.5.5.5", 53), ("1.1.1.1", 443), ("119.29.29.29", 53)):
        try:
            with socket.create_connection((host, port), timeout=3):
                tcp_ok, tcp_err = True, f"{host}:{port} 可达"
                break
        except Exception as e:
            tcp_err = f"{host}:{port} {type(e).__name__}"
    detail["tcp_probe"] = tcp_err

    dns_ok, dns_err = False, ""
    try:
        dns_err = socket.gethostbyname("www.baidu.com")
        dns_ok = True
    except Exception as e:
        dns_err = f"DNS 解析失败: {type(e).__name__}"
    detail["dns_probe"] = dns_err

    http_ok, http_err = False, "未尝试"
    if args_proxy_free():
        for url in PROBE_URLS:
            try:
                req = urllib.request.Request(url, method="HEAD",
                                             headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=5) as r:
                    http_ok, http_err = True, f"{url} -> {r.status}"
                    break
            except Exception as e:
                http_err = f"{url} -> {type(e).__name__}"
    detail["http_probe"] = http_err

    wh = parse_winhttp(ps("netsh winhttp show proxy"))
    detail["winhttp_proxy"] = wh.get("mode")

    ok = bool(routes) and tcp_ok and dns_ok and (http_ok or wh.get("mode") != "proxy")
    return ok, detail


def args_proxy_free() -> bool:
    """系统代理指向本地死端口时，urllib 会被 env proxy 拖死；探活强制直连。"""
    for k in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        os.environ.pop(k, None)
    return True


def do_verify(args) -> int:
    ok, detail = verify_network()
    if args.json:
        print(json.dumps({"ok": ok, "verify": detail}, ensure_ascii=False))
    else:
        print(f"[verify] {'通' if ok else '不通'}")
        for k, v in detail.items():
            print(f"  {k}: {v}")
        if not ok:
            print("  提示：先 `net-rollback.py diff` 看漂移，再 `restore`。")
    return 0 if ok else 1


def do_list(args) -> int:
    ensure_store()
    files = sorted(glob.glob(os.path.join(STORE, "net-*.json")))
    if not files:
        print("（还没有快照）")
        return 0
    for f in files:
        sz = os.path.getsize(f)
        print(f"{os.path.basename(f):28s} {sz:8d}B  {time.strftime('%Y-%m-%d %H:%M', time.localtime(os.path.getmtime(f)))}")
    return 0


# ────────────────────────────── main ──────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="本机网络状态 快照/还原/探活")
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name, fn, help_ in (
        ("snapshot", do_snapshot, "采集当前状态并落盘"),
        ("diff", do_diff, "与快照比对，看漂移"),
        ("restore", do_restore, "按快照还原（默认 latest）"),
        ("verify", do_verify, "探活：默认路由 / TCP / DNS / HTTP"),
        ("list", do_list, "列出已有快照"),
    ):
        p = sub.add_parser(name, help=help_)
        p.add_argument("--json", action="store_true")
        if name in ("diff", "restore"):
            p.add_argument("--from", dest="from_file", default=None, help="指定快照文件")
            p.add_argument("--dry-run", action="store_true", help="只报告不改动（默认行为：未加 --yes 一律 dry-run）")
            p.add_argument("--yes", action="store_true", help="确认执行（不加则只报告）")
        p.set_defaults(func=fn)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
