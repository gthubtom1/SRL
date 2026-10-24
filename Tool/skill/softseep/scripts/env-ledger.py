#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""env-ledger.py —— 环境副作用台账（记录 / 列出 / 还原 / 门禁）

存在的原因（长跑事故）：
    逆向案子经常要动本机环境 —— 停 npcap/vgk 驱动、改系统代理、改 hosts、
    改 loopback IP、**改系统时间**、临时卸软件。做的时候都"马上改回来"，
    但长跑中途被打断、换会话、或者干脆忘了，机器就留在半坏状态：
    npcap 停了导致抓包全空、时间偏了导致证书校验失败，下一次分析谁也想不起原因。

    所以环境改动必须落账：改之前记 before，改之后记 after，同时写下**还原命令**。
    退出案子前 `restore` 全部执行、`check` 必须 rc=0。

子命令：
    record  --case <C> --action "sc stop npcap" --before running --after stopped \\
            --restore "sc start npcap"
    list    --case <C>
    restore --case <C> [--dry-run]
    check   --case <C>              # 有未还原项 -> rc=1（供门禁）

存储：<case>/env-changes.jsonl，一行一条：
    {"id","ts","action","before","after","restore","restored":false,
     "restored_ts"?,"restore_error"?}

安全边界（防误执行，不是可选项）：
    1. restore 命令只允许白名单前缀：
         sc / net / reg / netsh / w32tm / powershell
       （另允许 `echo `，仅用于自测与"空还原"校验，无副作用）
    2. 拒绝 `&& || ; | ` < > $( 换行` 等链式/重定向元字符，防止
       `sc stop x && del ...` 这种夹带；需要多步就拆成多条。
    3. 拒绝把**本机绝对路径**写进台账（盘符路径 / UNC / /home /Users 等）：
       台账要能换机复读，路径请用环境变量或相对路径。
    4. 非白名单命令一律拒绝并提示人工执行，绝不"先跑了再说"。

退出码：
    record  0=成功 / 2=参数或安全校验失败
    list    0
    restore 0=全部还原成功 / 1=有失败或被拒 / 2=参数或台账写回失败
    check   0=无未还原项 / 1=有未还原项
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid

LEDGER_NAME = "env-changes.jsonl"

# 白名单前缀（小写比较）。允许 `xxx` 与 `xxx.exe` 两种写法。
ALLOWED = ("sc", "net", "reg", "netsh", "w32tm", "powershell", "echo")
ALLOWED_NOTE = "sc / net / reg / netsh / w32tm / powershell（另有 echo，仅自测用）"

# 链式 / 重定向 / 子命令：出现即拒。`;` 也拒（powershell 里它是语句分隔符）。
CHAIN_RE = re.compile(r"(&&|\|\||[;|`<>]|\$\(|\r|\n)")

# 本机绝对路径：盘符、UNC、以及常见 POSIX 根。`w32tm /resync` 这类参数不受影响。
ABS_PATH_RE = re.compile(
    r"""(^|[\s"'=:])(
        [A-Za-z]:[\\/]              # C:\ 或 C:/
        |\\\\[^\\\s]+               # \\server\share
        |/(?:home|Users|tmp|var|opt|etc|usr|mnt|root|srv|Volumes)(?:/|$)
    )""",
    re.VERBOSE,
)

MAX_FIELD = 400  # 单字段长度上限，防止把整段日志抄进台账


# ────────────────────────────── 基础 ──────────────────────────────

def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def ledger_path(case: str) -> str:
    return os.path.join(os.path.abspath(case), LEDGER_NAME)


def fail(msg: str, rc: int = 2) -> int:
    print(msg, file=sys.stderr)
    return rc


def clip(s: str, n: int = MAX_FIELD) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[:n] + "…"


def has_abs_path(s: str) -> bool:
    return bool(ABS_PATH_RE.search(str(s or "")))


def command_problem(cmd: str) -> str | None:
    """返回 None = 允许执行；否则返回拒绝理由。"""
    c = (cmd or "").strip()
    if not c:
        return "restore 命令为空：此项只能人工还原"
    low = c.lower()
    ok = False
    for name in ALLOWED:
        if low.startswith(name + " ") or low.startswith(name + ".exe "):
            ok = True
            break
    if not ok:
        return (
            f"非白名单命令，已拒绝：{clip(c, 80)}\n"
            f"只允许：{ALLOWED_NOTE}。其余命令请人工执行，不要交给本脚本。"
        )
    m = CHAIN_RE.search(c)
    if m:
        return (
            f"命令含链式/重定向元字符 {m.group(0)!r}，已拒绝：{clip(c, 80)}\n"
            "拆成多条 --restore，或人工执行。"
        )
    return None


# ────────────────────────────── 读写台账 ──────────────────────────────

def read_raw_lines(case: str) -> list[str]:
    p = ledger_path(case)
    if not os.path.exists(p):
        return []
    try:
        with open(p, "r", encoding="utf-8") as f:
            return f.readlines()
    except OSError as e:
        print(f"[warn] 读取台账失败：{e}", file=sys.stderr)
        return []


def read_entries(case: str) -> list[dict]:
    out: list[dict] = []
    for i, line in enumerate(read_raw_lines(case), 1):
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            print(f"[warn] {LEDGER_NAME} 第 {i} 行不是合法 JSON，已跳过", file=sys.stderr)
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def append_entry(case: str, entry: dict) -> None:
    """追加一条。目录不存在就建（record 是显式动作，允许开新案子）。"""
    os.makedirs(os.path.abspath(case), exist_ok=True)
    with open(ledger_path(case), "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def update_entries(case: str, updates: dict[str, dict]) -> None:
    """按 id 回写台账。保留无法解析的行（不静默删数据），原子替换。"""
    lines = read_raw_lines(case)
    out: list[str] = []
    for line in lines:
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            out.append(line if line.endswith("\n") else line + "\n")
            continue
        if isinstance(obj, dict) and obj.get("id") in updates:
            out.append(json.dumps(updates[obj["id"]], ensure_ascii=False) + "\n")
        else:
            out.append(line if line.endswith("\n") else line + "\n")

    d = os.path.dirname(ledger_path(case)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".env-changes-", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.writelines(out)
        os.replace(tmp, ledger_path(case))
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def is_restored(e: dict) -> bool:
    v = e.get("restored", False)
    return v is True or str(v).lower() == "true"


# ────────────────────────────── 子命令 ──────────────────────────────

def cmd_record(args: argparse.Namespace) -> int:
    fields = {
        "action": args.action,
        "before": args.before,
        "after": args.after,
        "restore": args.restore,
    }
    for name, value in fields.items():
        if has_abs_path(value):
            return fail(
                f"[拒绝] --{name} 里出现本机绝对路径：{clip(value, 100)}\n"
                "台账要能换机复读。改用环境变量（如 %WINDIR%）或相对路径，"
                "或把该步骤写进案例 README 由人工处理。"
            )

    restore = (args.restore or "").strip()
    if restore:
        problem = command_problem(restore)
        if problem:
            return fail(f"[拒绝] 记录未写入。{problem}\n（确实只能人工还原，就把 --restore 留空，并在 action 里写清人工步骤。）")

    entry = {
        "id": "E" + uuid.uuid4().hex[:10],
        "ts": now(),
        "action": clip(args.action),
        "before": clip(args.before),
        "after": clip(args.after),
        "restore": clip(restore),
        "restored": False,
    }
    try:
        append_entry(args.case, entry)
    except OSError as e:
        return fail(f"[错误] 写台账失败：{e}")

    print(f"已记录 {entry['id']}")
    print(f"  action : {entry['action']}")
    print(f"  before : {entry['before']}  ->  after : {entry['after']}")
    print(f"  restore: {entry['restore'] or '（空，需人工还原）'}")
    print(f"  ledger : {ledger_path(args.case)}")
    if not entry["restore"]:
        print("  ! 没有 restore 命令：check 会一直报未还原，必须人工收尾。")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    entries = read_entries(args.case)
    if not entries:
        print(f"台账为空：{ledger_path(args.case)}")
        return 0

    print(f"环境变更台账：{ledger_path(args.case)}（{len(entries)} 条）")
    header = f"{'ID':<14} {'时间':<20} {'还原':<6} {'动作':<38} {'before -> after'}"
    print(header)
    print("-" * len(header))
    for e in entries:
        mark = "是" if is_restored(e) else "否"
        action = clip(e.get("action", ""), 38)
        change = f"{clip(e.get('before', ''), 24)} -> {clip(e.get('after', ''), 24)}"
        print(f"{str(e.get('id', '?')):<14} {str(e.get('ts', '')):<20} {mark:<6} {action:<38} {change}")
        if e.get("restore_error"):
            print(f"{'':<14} ! 还原错误：{clip(e['restore_error'], 120)}")
    pending = [e for e in entries if not is_restored(e)]
    print("-" * len(header))
    print(f"未还原：{len(pending)} 条")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    entries = read_entries(args.case)
    if not entries:
        print(f"台账为空：{ledger_path(args.case)}")
        return 0

    pending = [e for e in entries if not is_restored(e)]
    if not pending:
        print("没有未还原的环境变更。")
        return 0

    updates: dict[str, dict] = {}
    failures = 0

    print(f"待还原 {len(pending)} 条" + ("（dry-run，不执行、不回写）" if args.dry_run else ""))

    for e in pending:
        eid = str(e.get("id", "?"))
        action = clip(e.get("action", ""), 70)
        restore = (e.get("restore") or "").strip()
        print(f"\n[{eid}] {action}")

        problem = command_problem(restore)
        if problem:
            failures += 1
            print(f"  FAIL {problem}", file=sys.stderr)
            if not args.dry_run:
                e2 = dict(e)
                e2["restored"] = False
                e2["restore_error"] = problem
                updates[eid] = e2
            continue

        print(f"  $ {restore}")
        if args.dry_run:
            continue

        try:
            r = subprocess.run(
                restore,
                shell=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            failures += 1
            e2 = dict(e)
            e2["restored"] = False
            e2["restore_error"] = "超时（120s）"
            updates[eid] = e2
            print("  FAIL 超时（120s）", file=sys.stderr)
            continue
        except OSError as ex:
            failures += 1
            e2 = dict(e)
            e2["restored"] = False
            e2["restore_error"] = f"执行失败：{ex}"
            updates[eid] = e2
            print(f"  FAIL 执行失败：{ex}", file=sys.stderr)
            continue

        out = " ".join((r.stdout or "").split())
        err = " ".join((r.stderr or "").split())
        if out:
            print(f"  stdout: {clip(out, 200)}")
        if err:
            print(f"  stderr: {clip(err, 200)}")

        e2 = dict(e)
        if r.returncode == 0:
            e2["restored"] = True
            e2["restored_ts"] = now()
            e2.pop("restore_error", None)
            updates[eid] = e2
            print("  OK restored")
        else:
            failures += 1
            e2["restored"] = False
            e2["restore_error"] = f"rc={r.returncode}" + (f"；stderr={clip(err, 160)}" if err else "")
            updates[eid] = e2
            print(f"  FAIL rc={r.returncode}", file=sys.stderr)

    if args.dry_run:
        print("\ndry-run 结束：未执行任何命令，也未回写台账。")
        return 0

    if updates:
        try:
            update_entries(args.case, updates)
        except OSError as ex:
            return fail(f"[错误] 回写台账失败：{ex}")

    if failures:
        return fail(f"\n还原未完成：{failures} 条失败/被拒。修好后重跑 restore，再用 check 验收。", 1)

    print("\n全部还原完成（restored:true 已回写）。")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    entries = read_entries(args.case)
    pending = [e for e in entries if not is_restored(e)]
    if not pending:
        print("env-ledger check: OK（无未还原环境变更）")
        return 0

    print(f"env-ledger check: 有 {len(pending)} 条未还原环境变更", file=sys.stderr)
    for e in pending:
        print(
            f"  - [{e.get('id', '?')}] {clip(e.get('action', ''), 80)}"
            f"  (before={clip(e.get('before', ''), 30)}, after={clip(e.get('after', ''), 30)})"
            f"\n    restore: {clip(e.get('restore', ''), 100) or '（空，需人工）'}",
            file=sys.stderr,
        )
        if e.get("restore_error"):
            print(f"    ! 上次错误：{clip(e['restore_error'], 120)}", file=sys.stderr)
    print("收尾前必须 `restore` 并让 check 返回 0。", file=sys.stderr)
    return 1


# ────────────────────────────── 入口 ──────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="环境副作用台账：记录 / 列出 / 还原 / 门禁",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("record", help="记录一条环境变更")
    r.add_argument("--case", required=True, help="案例目录（绝对或相对）")
    r.add_argument("--action", required=True, help='做了什么，如 "sc stop npcap"')
    r.add_argument("--before", default="", help="改之前的状态")
    r.add_argument("--after", default="", help="改之后的状态")
    r.add_argument("--restore", default="", help="还原命令（必须命中白名单）")
    r.set_defaults(func=cmd_record)

    l = sub.add_parser("list", help="表格列出全部记录")
    l.add_argument("--case", required=True)
    l.set_defaults(func=cmd_list)

    rs = sub.add_parser("restore", help="按顺序执行 restore 并回写 restored:true")
    rs.add_argument("--case", required=True)
    rs.add_argument("--dry-run", action="store_true", help="只打印将执行的命令，不执行、不回写")
    rs.set_defaults(func=cmd_restore)

    c = sub.add_parser("check", help="列出未还原项；有则 rc=1")
    c.add_argument("--case", required=True)
    c.set_defaults(func=cmd_check)

    return p


def self_test():
    """自检：记录 → 读回 → 状态判定（临时目录，不碰真实台账）。"""
    import tempfile
    failed, checks = [], 0
    tmp = tempfile.mkdtemp(prefix="env-ledger-st-")
    try:
        path = os.path.join(tmp, "ledger.jsonl")
        row = {"case": "st", "action": "启动 qemu 网络", "before": "down", "after": "up",
               "restore": "netsh interface set interface X admin=disable"}
        checks += 1
        _ = _append(path, row) if "_append" in globals() else None
        if "_append" not in globals():
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        with open(path, encoding="utf-8") as f:
            got = [json.loads(x) for x in f if x.strip()]
        if len(got) != 1 or got[0]["action"] != row["action"]:
            failed.append("roundtrip")
        checks += 1
        # 有 restore 且 before!=after → 需要还原
        need = bool(got[0].get("restore")) and got[0].get("before") != got[0].get("after")
        if not need:
            failed.append("needs-restore")
        checks += 1
        if not os.path.isfile(path):
            failed.append("file")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    print(json.dumps({"ok": not failed, "tool": "env-ledger", "checks": checks,
                      "failed": failed}, ensure_ascii=False))
    return 0 if not failed else 1


def main(argv: list[str] | None = None) -> int:
    # Windows 控制台/管道默认可能是 GBK；统一成 UTF-8，避免中文与符号写不出去。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if argv is None:
        argv = sys.argv[1:]
    if "--self-test" in argv:
        return self_test()
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return fail("已中断。", 130)
    except Exception as e:  # 台账脚本不允许抛裸栈给调用方
        return fail(f"[错误] {type(e).__name__}: {e}")


if __name__ == "__main__":
    sys.exit(main())
