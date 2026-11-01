#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cred-store.py —— 凭据仓：Token / Cookie / Salt / 私钥的**唯一指定存放点**。

为什么有它（2026-10-31 用户口径）：
    "对话没有事，但是它需要放在指定的地方……这样的话明显就知道它是不允许上传，
     或者说写进报告里面的嘛。"

    结论：凭据值**可以读、可以用、可以落盘** —— 日常开发本来就要用；要管的是"它落在哪"。
    所以规则不是"禁止落盘"，而是"只允许落在凭据仓"。目录与文件名本身承担标记职责。

三层保证（都不靠模型自觉）：
    1. 位置：`~/.seep/secrets/<case>/<name>`，在**仓库之外** —— `git add -A` 永远带不走；
       覆盖 `SEEP_CRED_ROOT` 可换根；如果指向仓库内，put 会拒绝并提示改 `.gitignore`。
    2. 形状：一个值一个文件，文件名即名字（`cookie.bilibili.txt` / `token.api.txt`）。
       文件权限 0600（Windows 用 icacls 收 ACL，失败只 warn）。
    3. 体检：`check` 把仓里的真实值拿去比对「git 跟踪文件 / case 账本 / work 报告」，
       报「文件:行 + 命中哪个名字」，**绝不回显值本身**。

常用：
    cred-store.py put --case 项目A --name token.api --from-env API_TOKEN --ttl 7d
    cred-store.py put --case 项目A --name cookie.bili --stdin
    cred-store.py path --case 项目A --name cookie.bili        # 给 -b / --cookie 用
    cred-store.py ls                                          # 只有名字、指纹、过期时间
    cred-store.py check --case 项目A                          # 有没有漏进仓库/报告
    cred-store.py purge --case 项目A                          # 收尾清空（含 manifest）

约定：正文/报告里引用凭据写 `<CRED:项目A/token.api>`，不写值。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = Path.home() / ".seep" / "secrets"
MANIFEST = "manifest.json"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
CASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def root() -> Path:
    env = (os.environ.get("SEEP_CRED_ROOT") or "").strip()
    return Path(env).expanduser().resolve() if env else DEFAULT_ROOT


def case_dir(case: str, must_exist: bool = False) -> Path:
    if not CASE_RE.match(case or ""):
        die(f"案名不合法：{case!r}（只允许字母数字 . _ -，≤64）")
    d = root() / case
    if must_exist and not d.is_dir():
        die(f"凭据仓里没有这个案子：{d}")
    return d


def die(msg: str, code: int = 1):
    print(msg, file=sys.stderr)
    raise SystemExit(code)


def warn(msg: str):
    print(f"[cred-store] {msg}", file=sys.stderr)


# ---------------------------------------------------------------- 权限与指纹


def harden(path: Path) -> str:
    """尽力收紧权限；返回实际生效的方式（报告用，不假装成功）。"""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    if os.name != "nt":
        return "chmod 600"
    # Windows：chmod 基本无效，用 icacls 只留当前用户
    try:
        user = os.environ.get("USERNAME", "")
        if not user:
            return "chmod(noop on windows)"
        r = subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
            capture_output=True, encoding="utf-8", errors="replace", timeout=20,
        )
        return "icacls " + ("ok" if r.returncode == 0 else f"failed({r.returncode})")
    except Exception as exc:  # noqa: BLE001
        return f"icacls unavailable: {exc.__class__.__name__}"


def fp(value: str) -> str:
    """指纹：前 4 字符 + 长度 + sha256 前 8。够人眼认，不够还原。"""
    v = value.strip("\r\n")
    head = re.sub(r"[^A-Za-z0-9]", "", v)[:4]
    return f"{head}…len={len(v)}…sha256:{hashlib.sha256(v.encode()).hexdigest()[:8]}"


def parse_ttl(text: str | None) -> float | None:
    if not text:
        return None
    m = re.match(r"^(\d+)([smhdw])$", text.strip().lower())
    if not m:
        die(f"--ttl 格式：30m / 12h / 7d / 2w，收到 {text!r}")
    n, unit = int(m.group(1)), m.group(2)
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]


# ---------------------------------------------------------------- manifest


def load_manifest(d: Path) -> dict:
    p = d / MANIFEST
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        warn(f"manifest 损坏，按空处理：{p}")
        return {}


def save_manifest(d: Path, data: dict):
    p = d / MANIFEST
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    os.replace(tmp, p)
    harden(p)


# ---------------------------------------------------------------- 子命令


def cmd_put(a):
    value = ""
    if a.from_env:
        value = os.environ.get(a.from_env, "")
        if not value:
            die(f"环境变量 {a.from_env} 为空或不存在（不落空值）")
    elif a.stdin:
        value = sys.stdin.read()
    elif a.value is not None:
        value = a.value
        warn("--value 会留在命令历史里；优先 --from-env 或 --stdin")
    else:
        die("给一个来源：--from-env VAR / --stdin / --value X")
    value = value.strip("\r\n")
    if not value:
        die("值为空，不写入")

    if not NAME_RE.match(a.name or ""):
        die(f"--name 不合法：{a.name!r}（字母数字开头，只允许 . _ -，≤64）")

    d = case_dir(a.case)
    if root() == REPO.resolve() or REPO.resolve() in root().parents:
        die(f"凭据仓根在仓库内（{root()}）：换个根，或先把该目录加进 .gitignore")
    d.mkdir(parents=True, exist_ok=True)
    harden(d)

    target = d / a.name
    target.write_text(value + "\n", encoding="utf-8")
    mode = harden(target)

    m = load_manifest(d)
    ttl = parse_ttl(a.ttl)
    now = time.time()
    m[a.name] = {
        "fp": fp(value),
        "bytes": len(value.encode()),
        "created": round(now, 3),
        "expires": round(now + ttl, 3) if ttl else None,
        "note": a.note or "",
        "source": a.from_env or ("stdin" if a.stdin else "arg"),
    }
    save_manifest(d, m)

    print(f"OK  <CRED:{a.case}/{a.name}>")
    print(f"    path      {target}")
    print(f"    fp        {m[a.name]['fp']}")
    print(f"    perms     {mode}")
    if m[a.name]["expires"]:
        stamp = time.strftime('%Y-%m-%d %H:%M', time.localtime(m[a.name]['expires']))
        print(f"    expires   {stamp}")
    print(f"    引用写法  <CRED:{a.case}/{a.name}>（正文/报告里不要写值）")


def cmd_ls(a):
    r = root()
    if not r.is_dir():
        print(f"(凭据仓不存在：{r})")
        return
    cases = [a.case] if a.case else sorted(p.name for p in r.iterdir() if p.is_dir())
    rows = []
    now = time.time()
    for c in cases:
        d = r / c
        if not d.is_dir():
            continue
        m = load_manifest(d)
        names = sorted({p.name for p in d.iterdir() if p.is_file() and p.name != MANIFEST} | set(m))
        for n in names:
            meta = m.get(n, {})
            exp = meta.get("expires")
            state = "expired" if exp and exp < now else ("ok" if exp else "no-ttl")
            rows.append({"case": c, "name": n, "fp": meta.get("fp", "?"),
                         "bytes": meta.get("bytes", "?"), "state": state,
                         "note": meta.get("note", ""),
                         "path": str(d / n)})
    if a.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return
    if not rows:
        print("(空)")
        return
    for x in rows:
        note = f"  # {x['note']}" if x["note"] else ""
        print(f"{x['case']:<20} {x['name']:<28} {x['state']:<8} {x['fp']}{note}")


def _resolve(a) -> Path:
    d = case_dir(a.case, must_exist=True)
    p = d / a.name
    if not p.is_file():
        die(f"没有这条凭据：{p}（先 ls 一下）")
    return p


def cmd_get(a):
    p = _resolve(a)
    if a.quiet:
        sys.stdout.write(p.read_text(encoding="utf-8").rstrip("\n"))
        return
    m = load_manifest(p.parent).get(a.name, {})
    print(f"# <CRED:{a.case}/{a.name}>  fp={m.get('fp','?')}  path={p}")
    print("# 值只在本机终端出现；不要贴进报告、对话正文或 git 跟踪文件。")
    print(p.read_text(encoding="utf-8").rstrip("\n"))


def cmd_path(a):
    print(_resolve(a))


def cmd_env(a):
    p = _resolve(a)
    var = a.var or re.sub(r"[^A-Za-z0-9]", "_", a.name).upper()
    print(f'export {var}="$(cat "{p}")"')


def cmd_purge(a):
    r = root()
    cases = [a.case] if a.case else sorted(p.name for p in r.iterdir() if p.is_dir()) if r.is_dir() else []
    now = time.time()
    removed = 0
    for c in cases:
        d = r / c
        if not d.is_dir():
            continue
        m = load_manifest(d)
        for p in sorted(d.iterdir()):
            if not p.is_file() or p.name == MANIFEST:
                continue
            exp = m.get(p.name, {}).get("expires")
            if a.expired and not (exp and exp < now):
                continue
            removed += 1
            if a.dry_run:
                print(f"would-remove  {p}")
                continue
            p.unlink()
            m.pop(p.name, None)
            print(f"removed       {p}")
        if not a.dry_run:
            left = [p for p in d.iterdir() if p.is_file() and p.name != MANIFEST]
            if not left:
                (d / MANIFEST).unlink(missing_ok=True)
                try:
                    d.rmdir()
                except OSError:
                    pass
            else:
                save_manifest(d, m)
    print(f"purge: {removed} 个{'（dry-run，未删）' if a.dry_run else ' 已删除'}")


# ---------------------------------------------------------------- check


def _git_tracked() -> list[Path]:
    try:
        out = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"],
                             capture_output=True, encoding="utf-8", errors="replace", timeout=60)
        if out.returncode != 0:
            return []
        return [REPO / x for x in out.stdout.split("\0") if x]
    except Exception:  # noqa: BLE001
        return []


def _extra_targets() -> list[Path]:
    """值不该出现的第二类地方：case 账本、work 报告、审计证据。"""
    out: list[Path] = []
    patterns = ["Tool/cases/*/facts.jsonl", "Tool/cases/*/report*.md",
                "work/*/report*.md", "work/*.md"]
    for pat in patterns:
        out.extend(p for p in REPO.glob(pat) if p.is_file())
    evidence = Path.home() / ".seep" / "audit-evidence"
    if evidence.is_dir():
        out.extend(p for p in evidence.rglob("*") if p.is_file())
    return out


def load_secrets(cases: list[str]) -> list[tuple[str, str, str]]:
    r = root()
    out: list[tuple[str, str, str]] = []  # (case, name, value)
    for c in cases:
        d = r / c
        if not d.is_dir():
            continue
        for p in sorted(d.iterdir()):
            if not p.is_file() or p.name == MANIFEST:
                continue
            val = p.read_text(encoding="utf-8", errors="replace").strip("\r\n")
            if len(val) < 6:
                continue  # 太短的值会满世界误命中
            out.append((c, p.name, val))
    return out


def scan_secrets(secrets, targets) -> int:
    """扫一组目标文件；命中只打「文件:行 + 哪个名字」，绝不回显值。"""
    seen = set()
    hits = 0
    for p in targets:
        try:
            key = p.resolve()
            if key in seen or not p.is_file() or p.stat().st_size > 2 * 1024 * 1024:
                continue
            seen.add(key)
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:  # noqa: BLE001
            continue
        for c, name, val in secrets:
            idx = text.find(val)
            if idx < 0:
                continue
            line = text.count("\n", 0, idx) + 1
            hits += 1
            print(f"LEAK  {p}:{line}  ← <CRED:{c}/{name}>")
    return hits


def _session_targets() -> list[Path]:
    """会话与备份：用户习惯“跑完删对话文件”，这里能确认删干净了。

    默认不扫（体量大）；`check --include-sessions` 才带上。"""
    base = Path.home() / ".pi" / "agent"
    out: list[Path] = []
    for sub in ("sessions",):
        d = base / sub
        if d.is_dir():
            out.extend(p for p in d.rglob("*") if p.is_file())
    for d in base.glob("backup-*"):
        if d.is_dir():
            out.extend(p for p in d.rglob("*") if p.is_file())
    return out


def cmd_check(a):
    r = root()
    cases = [a.case] if a.case else sorted(p.name for p in r.iterdir() if p.is_dir()) if r.is_dir() else []
    secrets = load_secrets(cases)
    if not secrets:
        print("check: 凭据仓为空，无值可比对（这本身是干净的）。")
        return

    targets = _git_tracked() + _extra_targets()
    if getattr(a, "include_sessions", False):
        targets += _session_targets()
    hits = scan_secrets(secrets, targets)
    if hits:
        print(f"\ncheck: {hits} 处泄漏。处置：值删掉，正文改写成 <CRED:case/name>；"
              f"已提交过的还要清历史。")
        raise SystemExit(2)
    print(f"check: {len(secrets)} 个值、{len(set(t.resolve() for t in targets if t.is_file()))} 个文件，未发现泄漏。")


# ---------------------------------------------------------------- CLI


def _selftest():
    """无网、无真凭据：全用假值，在临时根里跑完整链路。"""
    import contextlib
    import io
    import shutil
    import tempfile

    results: list[tuple[str, bool]] = []

    def check(label: str, cond: bool, detail: str = ""):
        results.append((label, bool(cond)))
        tail = f"  — {detail}" if detail else ""
        print(("[PASS] " if cond else "[FAIL] ") + label + tail)

    def run(fn, **kw):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            fn(argparse.Namespace(**kw))
        return buf.getvalue()

    tmp = Path(tempfile.mkdtemp(prefix="cred-selftest-"))
    old = os.environ.get("SEEP_CRED_ROOT")
    os.environ["SEEP_CRED_ROOT"] = str(tmp / "vault")
    value = "sk-selftest-0123456789abcdefFAKE"
    try:
        out = run(cmd_put, case="self", name="token.api", from_env=None, stdin=False,
                  value=value, ttl="1h", note="自测假值")
        target = tmp / "vault" / "self" / "token.api"
        check("put 落盘到凭据仓", target.is_file(), str(target))
        check("值是原样的（可直接给 curl -b）", target.read_text(encoding="utf-8").strip() == value)
        manifest = json.loads((tmp / "vault" / "self" / MANIFEST).read_text(encoding="utf-8"))
        check("manifest 只有指纹、不存值", value not in json.dumps(manifest), manifest["token.api"]["fp"])
        check("put 回执只出名字不出的值", value not in out)

        ls = run(cmd_ls, case=None, json=True)
        rows = json.loads(ls)
        check("ls 列出且状态 ok", len(rows) == 1 and rows[0]["state"] == "ok")
        check("ls 不回显值", value not in ls)

        p = run(cmd_path, case="self", name="token.api")
        check("path 指向真实文件", Path(p.strip()).resolve() == target.resolve())
        got = run(cmd_get, case="self", name="token.api", quiet=True)
        check("get --quiet 只返回值", got == value)

        clean = run(cmd_check, case="self")
        check("check 在干净仓上不报泄漏", "未发现泄漏" in clean)

        leak = tmp / "leaked-report.md"
        leak.write_text(f"header\n调用时带 {value} 即可\n", encoding="utf-8")
        secrets = load_secrets(["self"])
        scan_out = io.StringIO()
        with contextlib.redirect_stdout(scan_out):
            hits = scan_secrets(secrets, [leak])
        check("check 能抓到报告里的值", hits == 1, f"hits={hits}")
        check("命中行号准（第 2 行）", ":2 " in scan_out.getvalue())
        check("命中只报名字不回显值", value not in scan_out.getvalue())

        run(cmd_purge, case="self", expired=False, dry_run=False)
        check("purge 后案子目录消失", not (tmp / "vault" / "self").exists())

        os.environ["SEEP_CRED_ROOT"] = str(REPO)
        refused = False
        try:
            run(cmd_put, case="self", name="x", from_env=None, stdin=False, value=value,
                ttl=None, note="")
        except SystemExit:
            refused = True
        check("凭据仓根在仓库内 → 拒绝写入", refused)
    finally:
        if old is None:
            os.environ.pop("SEEP_CRED_ROOT", None)
        else:
            os.environ["SEEP_CRED_ROOT"] = old
        shutil.rmtree(tmp, ignore_errors=True)

    passed = sum(1 for _, ok in results if ok)
    print(f"\nself-test: {passed}/{len(results)} 通过")
    raise SystemExit(0 if passed == len(results) else 1)


def main(argv=None):
    ap = argparse.ArgumentParser(description="凭据仓：Token/Cookie/Salt/私钥的唯一指定存放点")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("put", help="写入一条凭据（值来自 env / stdin，不进命令行历史）")
    p.add_argument("--case", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--from-env")
    p.add_argument("--stdin", action="store_true")
    p.add_argument("--value")
    p.add_argument("--ttl", help="30m / 12h / 7d / 2w")
    p.add_argument("--note", help="用途备注（会进 manifest，别写值）")
    p.set_defaults(func=cmd_put)

    p = sub.add_parser("ls", help="列出（只有名字、指纹、状态）")
    p.add_argument("--case")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_ls)

    for name, fn, desc in (("get", cmd_get, "打印值（终端专用）"),
                           ("path", cmd_path, "只打印文件路径（给 -b/--cookie 用）"),
                           ("env", cmd_env, "打印 export 行")):
        p = sub.add_parser(name, help=desc)
        p.add_argument("--case", required=True)
        p.add_argument("--name", required=True)
        if name == "get":
            p.add_argument("--quiet", action="store_true")
        if name == "env":
            p.add_argument("--var")
        p.set_defaults(func=fn)

    p = sub.add_parser("purge", help="收尾清理")
    p.add_argument("--case")
    p.add_argument("--expired", action="store_true", help="只删过期项")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_purge)

    p = sub.add_parser("check", help="扫 git 跟踪文件 / 账本 / 报告，看有没有值漏出去")
    p.add_argument("--case")
    p.add_argument("--include-sessions", action="store_true",
                   help="连 ~/.pi/agent/sessions 与 backup-* 一起扫（验证“对话文件删干净了没”，慢）")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("self-test", help="自测（专用假值 + 临时根，不碰真实凭据）")
    p.set_defaults(func=None)
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "self-test":
        return _selftest()

    a = ap.parse_args(argv)
    a.func(a)


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    main()
