#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本机网络快照、恢复计划、恢复与连通性检查。

snapshot 仅在采集完整时发布快照，保留 hosts 原始字节。
restore 默认演练；显式 --yes 后，按快照恢复 WinHTTP 和 hosts，
并只移除同一网卡上快照之外的 Manual IPv4 地址。DHCP 地址始终保留。
路由、DNS 服务器和缺失的原有地址只报告差异，不自动修改。
实际恢复要求命令成功、受检查状态一致且连通性检查通过；部分失败返回非零。

用法：
    python Tool/scripts/net-rollback.py snapshot --json
    python Tool/scripts/net-rollback.py diff --from <snapshot.json> --json
    python Tool/scripts/net-rollback.py restore --from <snapshot.json> --json
    python Tool/scripts/net-rollback.py restore --from <snapshot.json> --yes --json
    python Tool/scripts/net-rollback.py verify --json
    python Tool/scripts/net-rollback.py list

退出码：0 检查/演练/恢复成功；1 已尝试恢复但未完成，或探活失败；2 输入或环境错误。
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import glob
import json
import os
import socket
import subprocess
import sys
import time
import tempfile
import urllib.request
from datetime import datetime, timezone

HOME = os.path.expanduser("~")
STORE = os.path.join(HOME, ".seep", "net")
HOSTS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
PROBE_URLS = ("http://www.baidu.com", "http://connect.rom.miui.com/generate_204")


# ────────────────────────────── 基础设施 ──────────────────────────────

class NetworkStateError(ValueError):
    """A snapshot, observation or command cannot be trusted for restoration."""


def ps(script: str, timeout: int = 30) -> str:
    """Run PowerShell strictly; failed commands never look like empty success."""
    wrapper = ("$ErrorActionPreference='Stop'; $LASTEXITCODE=0; "
               "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); "
               + script + "; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }")
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", base64.b64encode(wrapper.encode("utf-16-le")).decode("ascii")],
            capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NetworkStateError("PowerShell unavailable or timed out") from exc
    if result.returncode != 0:
        raise NetworkStateError("PowerShell command failed (exit=%s)" % result.returncode)
    raw = result.stdout or b""
    for encoding in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(encoding).strip()
        except UnicodeDecodeError:
            continue
    raise NetworkStateError("PowerShell output could not be decoded")


def ps_json(script: str, timeout: int = 30):
    raw = ps("ConvertTo-Json -InputObject @(" + script + ") -Depth 5 -Compress", timeout)
    if not raw:
        raise NetworkStateError("PowerShell JSON collection returned no data")
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise NetworkStateError("PowerShell collection returned invalid JSON") from exc
    rows = value if isinstance(value, list) else [value]
    if any(not isinstance(item, dict) for item in rows):
        raise NetworkStateError("PowerShell collection contains a non-object row")
    return rows


def read_hosts_bytes() -> bytes:
    with open(HOSTS, "rb") as stream:
        return stream.read()


def read_hosts() -> str:
    return read_hosts_bytes().decode("utf-8", "replace")


def ensure_store() -> None:
    os.makedirs(STORE, exist_ok=True)


# ────────────────────────────── 采集 ──────────────────────────────

def collect() -> dict:
    errors = []
    def rows(label, script):
        try:
            return ps_json(script)
        except Exception as exc:
            errors.append("%s failed (%s)" % (label, type(exc).__name__))
            return []
    ips = rows("Get-NetIPAddress",
        "Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,InterfaceAlias,"
        "IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin")
    adapters = rows("Get-NetAdapter",
        "Get-NetAdapter | Select-Object ifIndex,Name,InterfaceDescription,Status,MacAddress,InterfaceGuid,ifOperStatus")
    routes = rows("Get-NetRoute",
        "Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.DestinationPrefix -eq '0.0.0.0/0'} | "
        "Select-Object InterfaceIndex,NextHop,RouteMetric,DestinationPrefix")
    dns = rows("Get-DnsClientServerAddress",
        "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object InterfaceIndex,InterfaceAlias,ServerAddresses")
    try:
        winhttp_raw = ps("netsh winhttp show proxy")
    except Exception as exc:
        winhttp_raw = ""
        errors.append("WinHTTP collection failed (%s)" % type(exc).__name__)
    winhttp = parse_winhttp(winhttp_raw)
    for name, value in (("IPv4 addresses", ips), ("adapters", adapters),
                        ("DNS configuration", dns)):
        if not value:
            errors.append("%s collection returned no data" % name)
    if winhttp.get("mode") == "unknown":
        errors.append("WinHTTP proxy mode could not be determined")
    try:
        hosts_bytes = read_hosts_bytes()
    except OSError as exc:
        hosts_bytes = b""
        errors.append("hosts collection failed (%s)" % type(exc).__name__)
    hosts_text = hosts_bytes.decode("utf-8", "replace")
    return {
        "schema": "seep-net-snapshot/1",
        "taken_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hostname": socket.gethostname(), "ipv4_addresses": ips, "adapters": adapters,
        "default_routes": routes, "dns_servers": dns, "winhttp_proxy": winhttp,
        "winhttp_raw": winhttp_raw,
        "env_proxy": {k: v for k, v in os.environ.items()
                      if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")},
        "hosts_path": HOSTS, "hosts_text": hosts_text,
        "hosts_base64": base64.b64encode(hosts_bytes).decode("ascii"),
        "hosts_nonblank_lines": [line for line in hosts_text.splitlines()
                                 if line.strip() and not line.strip().startswith("#")],
        "collection_errors": errors,
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


def _hosts_payload(snapshot: dict) -> bytes:
    if "hosts_base64" in snapshot:
        value = snapshot["hosts_base64"]
        if not isinstance(value, str):
            raise NetworkStateError("hosts_base64 must be text")
        try:
            data = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise NetworkStateError("hosts_base64 is invalid") from exc
        if snapshot.get("hosts_text") != data.decode("utf-8", "replace"):
            raise NetworkStateError("hosts byte/text representations disagree")
        return data
    text = snapshot.get("hosts_text")
    if not isinstance(text, str) or "\ufffd" in text:
        raise NetworkStateError("legacy hosts snapshot has no recoverable exact bytes")
    return text.encode("utf-8")


def _index(value) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise NetworkStateError("invalid network interface index")
    if isinstance(value, str) and not value.isascii():
        raise NetworkStateError("invalid network interface index")
    try:
        index = int(value)
    except ValueError as exc:
        raise NetworkStateError("invalid network interface index") from exc
    if index <= 0 or str(index) != str(value):
        raise NetworkStateError("invalid network interface index")
    return index


def _ip_key(row):
    return (_index(row["InterfaceIndex"]), str(ipaddress.IPv4Address(row["IPAddress"])),
            row["PrefixLength"])


def validate_snapshot(value: object) -> dict:
    if not isinstance(value, dict) or value.get("schema") != "seep-net-snapshot/1":
        raise NetworkStateError("invalid network snapshot schema")
    if (not isinstance(value.get("hostname"), str)
            or value["hostname"].casefold() != socket.gethostname().casefold()):
        raise NetworkStateError("snapshot belongs to another host")
    if not isinstance(value.get("taken_at"), str) or not value["taken_at"]:
        raise NetworkStateError("snapshot time is missing")
    if value.get("collection_errors") != []:
        raise NetworkStateError("network snapshot collection is incomplete")
    for key in ("ipv4_addresses", "adapters", "default_routes", "dns_servers"):
        rows = value.get(key)
        if (not isinstance(rows, list) or (not rows and key != "default_routes")
                or any(not isinstance(row, dict) for row in rows)):
            raise NetworkStateError("invalid or empty snapshot field: %s" % key)
    try:
        addresses = set()
        for row in value["ipv4_addresses"]:
            prefix = row.get("PrefixLength")
            if type(prefix) is not int or not 0 <= prefix <= 32:
                raise NetworkStateError("invalid IPv4 prefix length")
            if not isinstance(row.get("IPAddress"), str):
                raise NetworkStateError("IPv4 address must be text")
            key = _ip_key(row)
            if key in addresses or not isinstance(row.get("PrefixOrigin"), str) or not row["PrefixOrigin"]:
                raise NetworkStateError("duplicate or incomplete IPv4 record")
            addresses.add(key)
        adapters = {}
        for row in value["adapters"]:
            index = _index(row.get("ifIndex"))
            mac = row.get("MacAddress")
            guid = row.get("InterfaceGuid")
            if (index in adapters or (mac is not None and not isinstance(mac, str))
                    or (guid is not None and not isinstance(guid, str))):
                raise NetworkStateError("duplicate or invalid adapter identity")
            adapters[index] = _adapter_identity(row)
        for row in value["default_routes"]:
            _index(row.get("InterfaceIndex"))
            if not isinstance(row.get("NextHop"), str):
                raise NetworkStateError("route next hop must be text")
            ipaddress.IPv4Address(row["NextHop"])
        for row in value["dns_servers"]:
            _index(row.get("InterfaceIndex"))
            if not isinstance(row.get("ServerAddresses"), list):
                raise NetworkStateError("invalid DNS server list")
            for address in row["ServerAddresses"]:
                if not isinstance(address, str):
                    raise NetworkStateError("DNS server must be text")
                ipaddress.IPv4Address(address)
    except (KeyError, TypeError, ValueError) as exc:
        raise NetworkStateError("invalid network address or interface metadata") from exc
    proxy = value.get("winhttp_proxy")
    if not isinstance(proxy, dict) or proxy.get("mode") not in ("direct", "proxy"):
        raise NetworkStateError("unknown snapshot proxy mode")
    if proxy["mode"] == "proxy":
        if not isinstance(proxy.get("server"), str) or not proxy["server"].strip():
            raise NetworkStateError("proxy server is missing")
        for field in ("server", "bypass"):
            text = proxy.get(field, "")
            if not isinstance(text, str) or any(ord(char) < 32 or char == '"' for char in text):
                raise NetworkStateError("invalid proxy argument")
    _hosts_payload(value)
    return value


def _atomic_bytes(path: str, data: bytes) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    fd, temporary = tempfile.mkstemp(prefix=".seep-net-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _error_reason(exc: Exception) -> str:
    return str(exc) if isinstance(exc, NetworkStateError) else type(exc).__name__


def _result(args, value: dict, code: int) -> int:
    if args.json:
        print(json.dumps(value, ensure_ascii=False))
    else:
        print(json.dumps(value, ensure_ascii=False, indent=2))
    return code


def do_snapshot(args) -> int:
    try:
        snap = validate_snapshot(collect())
        ensure_store()
        stamp = time.strftime("%Y%m%d-%H%M%S") + "-%d" % time.time_ns()
        path = os.path.join(STORE, "net-%s.json" % stamp)
        payload = (json.dumps(snap, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
        _atomic_bytes(path, payload)
        _atomic_bytes(os.path.join(STORE, "hosts-%s.bak" % stamp), _hosts_payload(snap))
        _atomic_bytes(latest_path(), payload)
        return _result(args, {"ok": True, "snapshot": path, "ips": len(snap["ipv4_addresses"]),
                              "winhttp": snap["winhttp_proxy"]["mode"]}, 0)
    except Exception as exc:
        return _result(args, {"ok": False, "error": "snapshot_incomplete",
                              "reason": _error_reason(exc)}, 2)


def load_snapshot(path: str) -> dict:
    with open(path, encoding="utf-8") as stream:
        return validate_snapshot(json.load(stream))


def _proxy_identity(value):
    if value["mode"] == "direct":
        return ("direct",)
    return ("proxy", value["server"], value.get("bypass", ""))


def _drift(snapshot: dict, current: dict) -> list[str]:
    drift = []
    if _proxy_identity(snapshot["winhttp_proxy"]) != _proxy_identity(current["winhttp_proxy"]):
        drift.append("WinHTTP proxy differs")
    if _hosts_payload(snapshot) != _hosts_payload(current):
        drift.append("hosts bytes differ")
    before = {_ip_key(row) for row in snapshot["ipv4_addresses"]}
    now = {_ip_key(row) for row in current["ipv4_addresses"]}
    for row in current["ipv4_addresses"]:
        if (row["PrefixOrigin"].casefold() == "manual" and _ip_key(row) not in before
                and not row["IPAddress"].startswith("169.254.")):
            drift.append("extra manual IPv4 address: %s/%s" % (row["IPAddress"], row["PrefixLength"]))
    for row in snapshot["ipv4_addresses"]:
        if row["PrefixOrigin"].casefold() == "manual" and _ip_key(row) not in now:
            drift.append("missing original manual IPv4 address: %s" % row["IPAddress"])
    def canonical_rows(rows):
        return sorted(json.dumps(row, sort_keys=True) for row in rows)
    if canonical_rows(snapshot["default_routes"]) != canonical_rows(current["default_routes"]):
        drift.append("default routes differ (reported only)")
    if canonical_rows(snapshot["dns_servers"]) != canonical_rows(current["dns_servers"]):
        drift.append("DNS servers differ (reported only)")
    return drift


def do_diff(args) -> int:
    path = args.from_file or latest_path()
    try:
        snapshot = load_snapshot(path)
        current = validate_snapshot(collect())
        return _result(args, {"ok": True, "from": path, "drift": _drift(snapshot, current)}, 0)
    except Exception as exc:
        return _result(args, {"ok": False, "error": "diff_incomplete", "reason": _error_reason(exc)}, 2)


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _adapter_identity(row: dict):
    guid = row.get("InterfaceGuid")
    mac = row.get("MacAddress")
    if isinstance(guid, str) and guid.strip():
        return ("guid", guid.casefold())
    if isinstance(mac, str) and mac.strip():
        return ("mac", mac.casefold())
    return None


def _restore_plan(snapshot: dict, current: dict):
    commands = []
    proxy = snapshot["winhttp_proxy"]
    if _proxy_identity(proxy) != _proxy_identity(current["winhttp_proxy"]):
        if proxy["mode"] == "direct":
            commands.append(("reset WinHTTP proxy", "netsh winhttp reset proxy"))
        else:
            command = "netsh winhttp set proxy " + _ps_quote("proxy-server=" + proxy["server"])
            command += " " + _ps_quote("bypass-list=" + proxy.get("bypass", ""))
            commands.append(("restore WinHTTP proxy", command))
    before = {_ip_key(row) for row in snapshot["ipv4_addresses"]}
    existing_addresses = {(index, address) for index, address, _prefix in before}
    old_adapters = {_index(row["ifIndex"]): _adapter_identity(row) for row in snapshot["adapters"]}
    new_adapters = {_index(row["ifIndex"]): _adapter_identity(row) for row in current["adapters"]}
    for row in current["ipv4_addresses"]:
        index, address, prefix = _ip_key(row)
        if ((index, address) in existing_addresses or row["PrefixOrigin"].casefold() != "manual"
                or address.startswith("169.254.")):
            continue
        if not old_adapters.get(index) or old_adapters[index] != new_adapters.get(index):
            raise NetworkStateError("adapter identity changed; refuse address removal")
        commands.append(("remove extra manual IPv4 %s/%d" % (address, prefix),
                         "Remove-NetIPAddress -InterfaceIndex %d -IPAddress %s -PrefixLength %d -Confirm:$false"
                         % (index, _ps_quote(address), prefix)))
    return commands


def do_restore(args) -> int:
    path = args.from_file or latest_path()
    dry_run = bool(getattr(args, "dry_run", False) or not getattr(args, "yes", False))
    actions = []
    applied = False
    try:
        snapshot = load_snapshot(path)
        current = validate_snapshot(collect())
        commands = _restore_plan(snapshot, current)
        hosts_bytes = _hosts_payload(snapshot)
        hosts_change = read_hosts_bytes() != hosts_bytes
        plan = [label for label, _command in commands]
        if hosts_change:
            plan.append("restore exact hosts bytes")
        plan.append("flush DNS cache")
        if dry_run:
            return _result(args, {"ok": True, "from": path, "dry_run": True, "applied": False,
                                  "actions": [], "planned_actions": plan,
                                  "current_drift": _drift(snapshot, current)}, 0)
        for label, command in commands:
            applied = True
            ps(command)
            actions.append(label)
        if hosts_change:
            # Open in-place to preserve the system hosts file's existing ACL.
            applied = True
            with open(HOSTS, "wb") as stream:
                stream.write(hosts_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            actions.append("restored exact hosts bytes")
        applied = True
        ps("ipconfig /flushdns")
        actions.append("flushed DNS cache")
        after = validate_snapshot(collect())
        remaining = _drift(snapshot, after)
        if read_hosts_bytes() != hosts_bytes and "hosts bytes differ" not in remaining:
            remaining.append("hosts bytes differ")
        reachable, detail = verify_network()
        ok = reachable and not remaining
        return _result(args, {"ok": ok, "from": path, "dry_run": False, "applied": applied,
                              "actions": actions, "remaining_drift": remaining, "verify": detail},
                       0 if ok else 1)
    except Exception as exc:
        return _result(args, {"ok": False, "from": path, "dry_run": dry_run, "applied": applied,
                              "actions": actions, "error": "restore_incomplete",
                              "reason": _error_reason(exc)}, 1 if applied else 2)


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
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for url in PROBE_URLS:
        try:
            req = urllib.request.Request(url, method="HEAD",
                                         headers={"User-Agent": "Mozilla/5.0"})
            with opener.open(req, timeout=5) as r:
                http_ok, http_err = True, f"{url} -> {r.status}"
                break
        except Exception as e:
            http_err = f"{url} -> {type(e).__name__}"
    detail["http_probe"] = http_err

    wh = parse_winhttp(ps("netsh winhttp show proxy"))
    detail["winhttp_proxy"] = wh.get("mode")

    ok = bool(routes) and tcp_ok and dns_ok and (http_ok or wh.get("mode") == "direct")
    return ok, detail


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
    try:
        return args.func(args)
    except Exception as exc:
        return _result(args, {"ok": False, "error": "operation_incomplete", "reason": _error_reason(exc)}, 2)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
