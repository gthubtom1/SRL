#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""patch-verify.py — 补丁清单验收器（等长/偏移/哈希/回滚）。

输入：
  --file <原文件>        原始文件（只读；不会被覆盖）
  --manifest <json>      patch manifest（见下）
  --out <文件>           可选：把补丁后副本写到这里；回滚时写原始字节
  --rollback             可选：把原始/备份字节写回 --out，并校验 target_sha256
  --backup <文件>        可选：回滚源；优先级高于 manifest.rollback.backup

manifest 最小结构：
  {
    "target_sha256": "<原文件 sha256>",
    "patches": [
      {"offset": 123, "original": "F7D0", "new": "31C0", "id": "P1"}
    ],
    "result_sha256": "<补丁后 sha256>",
    "rollback": {"backup": "app.exe.bak"}
  }

校验：
  1) 原文件 sha256 == target_sha256；
  2) 每条 offset 在文件范围内；original 字节匹配；original/new 等长；
  3) 应用后 sha256 == result_sha256；
  4) --rollback 时写回原始/备份，复算 target_sha256。

用法：
  python Tool/skill/softseep/scripts/patch-verify.py --file app.exe --manifest patch.json
  python Tool/skill/softseep/scripts/patch-verify.py --file app.exe --manifest patch.json --out app.patched.exe
  python Tool/skill/softseep/scripts/patch-verify.py --file app.exe --manifest patch.json --out app.rolled.exe --rollback
  python Tool/skill/softseep/scripts/patch-verify.py --self-test

退出码：0 通过；2 失败（输出 {"ok": false, "blocked_at": ..., "reason": ...}）。
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def emit_fail(blocked_at: str, reason: str) -> int:
    print(json.dumps({"ok": False, "blocked_at": blocked_at, "reason": reason},
                     ensure_ascii=True))
    return 2


def load_manifest(path: str):
    with open(path, encoding="utf-8") as f:
        m = json.load(f)
    if not isinstance(m, dict):
        raise ValueError("manifest 顶层不是对象")
    if not m.get("target_sha256") or len(str(m["target_sha256"])) != 64:
        raise ValueError("manifest 缺 target_sha256 或长度不是 64")
    if not isinstance(m.get("patches"), list) or not m["patches"]:
        raise ValueError("manifest 缺 patches[] 或为空")
    if not m.get("result_sha256") or len(str(m["result_sha256"])) != 64:
        raise ValueError("manifest 缺 result_sha256 或长度不是 64")
    return m


def apply_patches(data: bytes, manifest: dict):
    patched = bytearray(data)
    for i, p in enumerate(manifest["patches"]):
        tag = "patches[%d]" % i
        if not isinstance(p, dict):
            raise ValueError(tag + " 不是对象")
        try:
            off = int(p.get("offset"))
        except (TypeError, ValueError):
            raise ValueError(tag + " 缺整数 offset")
        try:
            old = bytes.fromhex(str(p.get("original") or ""))
            new = bytes.fromhex(str(p.get("new") or ""))
        except ValueError:
            raise ValueError(tag + " original/new 不是 hex")
        if not old or not new:
            raise ValueError(tag + " original/new 为空")
        if len(old) != len(new):
            raise ValueError(tag + " original/new 不等长（%d vs %d）" % (len(old), len(new)))
        if off < 0 or off + len(old) > len(patched):
            raise ValueError("%s offset 0x%X 超出文件范围（文件 %d 字节）" % (tag, off, len(patched)))
        cur = bytes(patched[off:off + len(old)])
        if cur != old:
            raise ValueError("%s offset 0x%X 原始字节不符：期望 %s，实际 %s"
                             % (tag, off, old.hex().upper(), cur.hex().upper()))
        patched[off:off + len(new)] = new
    return bytes(patched)


def write_atomic(path: str, data: bytes):
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".patch-verify-", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def aliases(a: str, b: str) -> bool:
    if os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b)):
        return True
    try:
        return os.path.samefile(a, b)
    except OSError:
        return False


def run(file_path: str, manifest_path: str, out: str | None,
        rollback: bool, backup: str | None) -> int:
    if not os.path.isfile(file_path):
        return emit_fail("input", "原文件不存在：%s" % file_path)
    if not os.path.isfile(manifest_path):
        return emit_fail("manifest", "manifest 不存在：%s" % manifest_path)
    try:
        manifest = load_manifest(manifest_path)
    except Exception as exc:  # noqa: BLE001
        return emit_fail("manifest", "%s: %s" % (type(exc).__name__, exc))
    backup_path = backup or (manifest.get("rollback") or {}).get("backup") or (os.path.abspath(manifest_path) + ".rollback.backup")
    if not os.path.isabs(backup_path):
        backup_path = os.path.join(os.path.dirname(os.path.abspath(manifest_path)), backup_path)
    output_path = out or ((file_path + ".rollback") if rollback else None)
    if output_path and any(aliases(output_path, p) for p in (file_path, manifest_path, backup_path)):
        return emit_fail("output-alias", "输出必须是独立副本，不能覆盖输入、补丁清单或回滚备份")
    with open(file_path, "rb") as f:
        original = f.read()
    before = sha256(original)
    target_hash = str(manifest["target_sha256"]).lower()
    result_hash = str(manifest.get("result_sha256") or "").lower()
    is_patched = bool(result_hash) and before.lower() == result_hash
    if before.lower() != target_hash and not is_patched:
        return emit_fail("target-hash", "文件既不是原始态也不是补丁后态：期望 %s 或 %s，实际 %s"
                         % (target_hash[:12], result_hash[:12] or "-", before[:12]))

    if rollback:
        # 血案（R2 审计）：旧版没有 backup 时直接拿"当前原文件"当回滚源——
        # 一旦文件被二次补丁/覆盖，回滚回不到干净态，且看起来还 rc=0。
        # 现在：只从独立 backup 恢复；没有 backup 就拒绝，并告诉用户怎么补。
        src = backup or (manifest.get("rollback") or {}).get("backup")
        if not src:
            return emit_fail("rollback-source",
                             "manifest 无 rollback.backup，且未用 --backup 指定；"
                             "拒绝用当前文件冒充备份（先 --write-backup 或用 --backup 指定）")
        if not os.path.isabs(src):
            src = os.path.join(os.path.dirname(os.path.abspath(manifest_path)), src)
        if not os.path.isfile(src):
            return emit_fail("rollback-source", "回滚源不存在：%s" % src)
        with open(src, "rb") as f:
            rb = f.read()
        want = (manifest.get("rollback") or {}).get("backup_sha256") or target_hash
        if sha256(rb) != target_hash or sha256(rb) != str(want).lower():
            return emit_fail("rollback-hash", "回滚源必须匹配 target_sha256 和声明的 backup_sha256")
        target = out or (file_path + ".rollback")
        try:
            write_atomic(target, rb)
        except Exception as exc:  # noqa: BLE001
            return emit_fail("rollback-write", "%s: %s" % (type(exc).__name__, exc))
        print(json.dumps({"ok": True, "rollback": True, "out": target,
                          "sha256": before, "restored_sha256": sha256(rb),
                          "from_patched": is_patched,
                          "patches": len(manifest["patches"])},
                         ensure_ascii=True))
        return 0

    if is_patched:
        return emit_fail("target-hash", "文件已是补丁后状态；要恢复请用 --rollback，不要重复打补丁")

    # 打补丁前先落独立备份，并把 backup 路径/哈希写回 manifest（可审计、可回滚）。
    try:
        if not (manifest.get("rollback") or {}).get("backup"):
            bpath = manifest_path + ".rollback.backup"
            if not os.path.isfile(bpath):
                write_atomic(bpath, original)
            manifest.setdefault("rollback", {})
            manifest["rollback"]["backup"] = os.path.basename(bpath)
            manifest["rollback"]["backup_sha256"] = before
            write_atomic(manifest_path, (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        return emit_fail("backup", "%s: %s" % (type(exc).__name__, exc))

    try:
        patched = apply_patches(original, manifest)
    except Exception as exc:  # noqa: BLE001
        return emit_fail("patch-apply", "%s: %s" % (type(exc).__name__, exc))
    after = sha256(patched)
    if after.lower() != str(manifest["result_sha256"]).lower():
        return emit_fail("result-hash", "补丁后 sha256 不符：期望 %s，实际 %s"
                         % (str(manifest["result_sha256"])[:12], after[:12]))
    if out:
        try:
            write_atomic(out, patched)
        except Exception as exc:  # noqa: BLE001
            return emit_fail("write-out", "%s: %s" % (type(exc).__name__, exc))
    print(json.dumps({"ok": True, "patches": len(manifest["patches"]),
                      "sha256_before": before, "sha256_after": after,
                      "out": out or None}, ensure_ascii=True))
    return 0


def self_test() -> int:
    checks = 0
    tmp = tempfile.mkdtemp(prefix="patch-verify-")
    try:
        orig = b"ABCDEF0123456789"
        p = os.path.join(tmp, "app.bin")
        with open(p, "wb") as f:
            f.write(orig)
        patched = bytearray(orig)
        patched[2:4] = b"ZZ"
        m = {
            "target_sha256": sha256(orig),
            "patches": [{"id": "P1", "offset": 2, "original": "4344", "new": "5A5A"}],
            "result_sha256": sha256(bytes(patched)),
            "rollback": {"backup": "app.bin.bak"},
        }
        mp = os.path.join(tmp, "patch.json")
        with open(mp, "w", encoding="utf-8") as f:
            json.dump(m, f)
        with open(os.path.join(tmp, "app.bin.bak"), "wb") as f:
            f.write(orig)
        for collision in (p, mp, os.path.join(tmp, "app.bin.bak")):
            saved = open(collision, "rb").read()
            with contextlib.redirect_stdout(io.StringIO()):
                rc = run(p, mp, collision, False, None)
            assert rc == 2 and open(collision, "rb").read() == saved
            checks += 1
        hardlink = os.path.join(tmp, "alias.bin")
        os.link(p, hardlink)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = run(p, mp, hardlink, False, None)
        assert rc == 2 and open(p, "rb").read() == orig
        checks += 1
        out = os.path.join(tmp, "app.patched.bin")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run(p, mp, out, False, None)
        assert rc == 0, buf.getvalue()
        assert open(out, "rb").read() == bytes(patched)
        checks += 1
        rb = os.path.join(tmp, "app.rolled.bin")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run(out, mp, rb, True, None)
        assert rc == 0, buf.getvalue()
        assert open(rb, "rb").read() == orig
        checks += 1
        bad_backup = os.path.join(tmp, "bad.bak")
        with open(bad_backup, "wb") as f:
            f.write(b"wrong")
        m["rollback"]["backup_sha256"] = sha256(b"wrong")
        with open(mp, "w", encoding="utf-8") as f:
            json.dump(m, f)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = run(out, mp, rb, True, bad_backup)
        assert rc == 2 and open(rb, "rb").read() == orig
        checks += 1
        del m["rollback"]["backup_sha256"]
        m["patches"][0]["new"] = "5A5A5A"
        with open(mp, "w", encoding="utf-8") as f:
            json.dump(m, f)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = run(p, mp, None, False, None)
        assert rc == 2
        checks += 1
        m["patches"][0]["new"] = "5A5A"
        m["patches"][0]["original"] = "FFFF"
        with open(mp, "w", encoding="utf-8") as f:
            json.dump(m, f)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = run(p, mp, None, False, None)
        assert rc == 2
        checks += 1
        m["patches"][0]["original"] = "4344"
        m["target_sha256"] = "0" * 64
        with open(mp, "w", encoding="utf-8") as f:
            json.dump(m, f)
        with contextlib.redirect_stdout(io.StringIO()):
            rc = run(p, mp, None, False, None)
        assert rc == 2
        checks += 1
        print(json.dumps({"ok": True, "checks": checks}, ensure_ascii=True))
        return 0
    except Exception as exc:  # noqa: BLE001
        return emit_fail("self-test", "%s: %s" % (type(exc).__name__, exc))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="补丁清单验收：等长/偏移/补丁后哈希，支持回滚",
        epilog="退出码：0 通过；2 失败（输出 ok=false 的 JSON）")
    ap.add_argument("--file", default=None, help="原始文件（只读）")
    ap.add_argument("--manifest", default=None, help="patch manifest JSON")
    ap.add_argument("--out", default=None, help="补丁后副本输出路径")
    ap.add_argument("--rollback", action="store_true", help="回滚到原始/备份字节")
    ap.add_argument("--backup", default=None, help="回滚源（默认读 manifest.rollback.backup）")
    ap.add_argument("--self-test", action="store_true", help="离线自测，rc=0")
    a = ap.parse_args()
    if a.self_test:
        return self_test()
    if not a.file or not a.manifest:
        return emit_fail("args", "需要 --file 与 --manifest（或用 --self-test）")
    return run(a.file, a.manifest, a.out, a.rollback, a.backup)


if __name__ == "__main__":
    sys.exit(main())
