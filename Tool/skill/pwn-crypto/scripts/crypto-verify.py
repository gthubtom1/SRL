#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""crypto-verify.py — 密码学求解的回代验收（RSA/广播/HMAC/PRNG/ECB/CBC）。

原则：只认“回代成立”的证据。
    RSA      : pow(m, e, n) == c
    Håstad   : CRT 后开方精确，且每组 pow(m, e, n_i) == c_i
    HMAC     : hmac.compare_digest，且篡改后必须失败
    MT19937  : 624 个输出克隆状态，下 N 个输出逐位一致
    ECB      : 16 字节块相等关系可复现
    CBC      : 翻转 C[i-1] 后 P[i] 的目标字节按预期改变，解密不报 padding 错

用法：
    python Tool/skill/pwn-crypto/scripts/crypto-verify.py --rsa inputs/rsa.json
    python Tool/skill/pwn-crypto/scripts/crypto-verify.py --broadcast inputs/broadcast.json
    python Tool/skill/pwn-crypto/scripts/crypto-verify.py --hmac inputs/hmac.json
    python Tool/skill/pwn-crypto/scripts/crypto-verify.py --mt inputs/mt.json
    python Tool/skill/pwn-crypto/scripts/crypto-verify.py --ecb inputs/ecb.json
    python Tool/skill/pwn-crypto/scripts/crypto-verify.py --cbc inputs/cbc.json
    python Tool/skill/pwn-crypto/scripts/crypto-verify.py --self-test
输出：JSON。退出码：0 通过；1 回代失败；2 结构化失败（blocked_at/reason）。
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import sys

if sys.platform == "win32":
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass

try:  # AES 只是可选的“真实分组密码”后端；缺失时降级为只跑 RSA/HMAC/MT
    from Crypto.Cipher import AES  # type: ignore
    HAVE_AES = True
except Exception:  # noqa: BLE001
    AES = None
    HAVE_AES = False


def error_payload(blocked_at, reason):
    return {"ok": False, "blocked_at": blocked_at, "reason": reason}


def load_json(path):
    if not os.path.isfile(path):
        raise RuntimeError("input: 文件不存在 %s" % path)
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (OSError, ValueError) as exc:
        raise RuntimeError("input: JSON 解析失败 %s" % exc)


def iroot(n, k):
    """精确 k 次方根；不精确时返回 None（不猜近似解）。"""
    if n < 0 or k <= 0:
        return None
    if n in (0, 1):
        return n
    hi = 1 << ((n.bit_length() + k - 1) // k)
    lo = 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= n:
            lo = mid
        else:
            hi = mid - 1
    return lo if lo ** k == n else None


def crt(pairs):
    """pairs: [(r, m)]，m 两两互质；返回 (x, M)。"""
    x, M = 0, 1
    for r, m in pairs:
        g = pow(M, -1, m) if M % m else None
        if g is None:
            raise RuntimeError("crt: 模数不互质（先用 gcd 分解）")
        t = ((r - x) % m) * g % m
        x += M * t
        M *= m
    return x % M, M


def hex_to_bytes(s, field):
    try:
        return bytes.fromhex(str(s).replace(" ", ""))
    except ValueError as exc:
        raise RuntimeError("%s: 不是合法 hex (%s)" % (field, exc))


def as_ascii(m):
    raw = m.to_bytes((m.bit_length() + 7) // 8 or 1, "big")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


# ---------------------------------------------------------------- MT19937
class MT19937:
    N, M, MATRIX_A = 624, 397, 0x9908B0DF
    UPPER, LOWER = 0x80000000, 0x7FFFFFFF

    def __init__(self, state=None):
        self.mt = [0] * self.N
        self.index = self.N
        if state is not None:
            self.mt = list(state)

    def twist(self):
        for i in range(self.N):
            y = (self.mt[i] & self.UPPER) | (self.mt[(i + 1) % self.N] & self.LOWER)
            self.mt[i] = self.mt[(i + self.M) % self.N] ^ (y >> 1)
            if y & 1:
                self.mt[i] ^= self.MATRIX_A
        self.index = 0

    @staticmethod
    def temper(y):
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & 0xFFFFFFFF

    @staticmethod
    def _undo_right(y, shift):
        x = y
        for _ in range(5):
            x = y ^ (x >> shift)
        return x & 0xFFFFFFFF

    @staticmethod
    def _undo_left(y, shift, mask):
        x = y
        for _ in range(5):
            x = y ^ ((x << shift) & mask)
        return x & 0xFFFFFFFF

    @classmethod
    def untemper(cls, y):
        y = cls._undo_right(y, 18)
        y = cls._undo_left(y, 15, 0xEFC60000)
        y = cls._undo_left(y, 7, 0x9D2C5680)
        y = cls._undo_right(y, 11)
        return y & 0xFFFFFFFF

    def next_u32(self):
        if self.index >= self.N:
            self.twist()
        y = self.mt[self.index]
        self.index += 1
        return self.temper(y)


# ---------------------------------------------------------------- modes
def do_rsa(data):
    try:
        n, e, c = int(data["n"]), int(data["e"]), int(data["c"])
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("rsa: 需要整数 n/e/c（%s）" % exc)
    out = {"mode": "rsa", "n_bits": n.bit_length(), "e": e}
    m = data.get("m")
    if m is not None:
        m = int(m)
        ok = pow(m, e, n) == c
        out.update({"m": str(m), "ascii": as_ascii(m), "verified": ok,
                    "check": "pow(m,e,n)==c"})
        return out, 0 if ok else 1
    root = iroot(c, e) if e < 64 else None
    if root is None:
        return {"ok": False, "blocked_at": "rsa",
                "reason": "c 不是精确 e 次方（可能有填充或 m^e>=n）",
                "mode": "rsa", "e": e}, 2
    ok = pow(root, e, n) == c
    out.update({"m": str(root), "ascii": as_ascii(root), "verified": ok,
                "check": "iroot(c,e) 精确且回代成立"})
    return out, 0 if ok else 1


def do_broadcast(data):
    try:
        e = int(data["e"])
        pairs = []
        for item in data["pairs"]:
            if isinstance(item, dict):
                pairs.append((int(item["n"]), int(item["c"])))
            else:
                n, c = item
                pairs.append((int(n), int(c)))
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("broadcast: 需要 e 与 pairs[{n,c}]（%s）" % exc)
    if len(pairs) < e:
        return {"ok": False, "blocked_at": "broadcast",
                "reason": "只有 %d 组模数，Håstad 需要 ≥ e=%d 组" % (len(pairs), e)}, 2
    C, M = crt([(c, n) for n, c in pairs])
    m = iroot(C, e)
    if m is None:
        return {"ok": False, "blocked_at": "broadcast",
                "reason": "CRT 后不是精确 e 次方（m^e>=M 或消息不同）"}, 2
    checks = [pow(m, e, n) == c for n, c in pairs]
    ok = all(checks) and m ** e < M
    out = {"mode": "broadcast", "e": e, "moduli": len(pairs),
           "crt_bits": M.bit_length(), "m": str(m), "ascii": as_ascii(m),
           "per_modulus": checks, "m_pow_e_lt_M": m ** e < M, "verified": ok}
    return out, 0 if ok else 1


def do_hmac(data):
    algo = str(data.get("algo", "sha256")).lower()
    if algo not in hashlib.algorithms_available:
        raise RuntimeError("hmac: 不支持 algo=%s" % algo)
    key = hex_to_bytes(data.get("key_hex", ""), "key_hex")
    msg = hex_to_bytes(data.get("message_hex", ""), "message_hex")
    expected = str(data.get("expected_hex", "")).lower()
    got = hmac.new(key, msg, algo).hexdigest()
    ok = hmac.compare_digest(got, expected)
    tampered = hmac.new(key, msg + b"x", algo).hexdigest()
    out = {"mode": "hmac", "algo": algo, "digest": got, "expected": expected,
           "verified": ok, "tamper_rejected": not hmac.compare_digest(tampered, expected)}
    return out, 0 if ok else 1


def do_mt(data):
    outputs = data.get("outputs") or []
    if len(outputs) != 624:
        return {"ok": False, "blocked_at": "mt",
                "reason": "需要 624 个 32-bit 输出，实际 %d" % len(outputs)}, 2
    raw_expected = data.get("next")
    if raw_expected is None or raw_expected == []:
        return {"ok": False, "blocked_at": "mt",
                "reason": "需要 next 中至少一个真实后续输出用于回代"}, 2
    try:
        expected = [int(x) for x in raw_expected]
        predict = int(data.get("predict", max(8, len(expected))))
    except (TypeError, ValueError) as exc:
        return {"ok": False, "blocked_at": "mt",
                "reason": "next/predict 字段非法: %s" % exc}, 2
    if not expected:
        return {"ok": False, "blocked_at": "mt",
                "reason": "next 为空，不能证明状态克隆"}, 2
    if predict < 1:
        return {"ok": False, "blocked_at": "mt",
                "reason": "predict 必须 >= 1"}, 2
    state = [MT19937.untemper(int(x)) for x in outputs]
    gen = MT19937(state)
    predicted = [gen.next_u32() for _ in range(max(predict, len(expected)))]
    ok = predicted[:len(expected)] == expected
    out = {"mode": "mt19937", "state_cloned": True, "predicted": predicted,
           "expected": expected, "verified": ok}
    return out, 0 if ok else 1


def _aes_ecb(key):
    if not HAVE_AES:
        raise RuntimeError("aes: 未安装 pycryptodome（pip install pycryptodome）")
    return AES.new(key, AES.MODE_ECB)


def do_ecb(data):
    key = hex_to_bytes(data["key_hex"], "key_hex")
    pt = hex_to_bytes(data["plaintext_hex"], "plaintext_hex")
    if len(key) not in (16, 24, 32) or len(pt) % 16:
        raise RuntimeError("ecb: key 需 16/24/32B，明文需 16B 对齐")
    ct = _aes_ecb(key).encrypt(pt)
    blocks = [ct[i:i + 16].hex() for i in range(0, len(ct), 16)]
    dup = len(blocks) - len(set(blocks))
    out = {"mode": "ecb", "block_size": 16, "blocks": len(blocks),
           "duplicate_blocks": dup, "ciphertext_hex": ct.hex(),
           "ecb_detected": dup > 0, "verified": dup > 0}
    return out, 0 if dup > 0 else 1


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _cbc_decrypt(aes_ecb, iv, blocks):
    out, prev = b"", iv
    for b in blocks:
        out += _xor(aes_ecb.decrypt(b), prev)
        prev = b
    return out


def do_cbc(data):
    key = hex_to_bytes(data["key_hex"], "key_hex")
    iv = bytearray(hex_to_bytes(data["iv_hex"], "iv_hex"))
    ct = bytearray(hex_to_bytes(data["ciphertext_hex"], "ciphertext_hex"))
    idx = int(data.get("target_block", 1))
    pos = int(data.get("byte_index", 0))
    flip = int(data.get("xor", 1)) & 0xFF
    if len(iv) != 16 or len(ct) % 16 or not ct:
        raise RuntimeError("cbc: IV 必须 16B，密文必须 16B 对齐")
    nblocks = len(ct) // 16
    if not (0 <= idx < nblocks):
        raise RuntimeError("cbc: target_block 必须 0..%d" % (nblocks - 1))
    if not (0 <= pos < 16):
        raise RuntimeError("cbc: byte_index 必须 0..15")
    aes_ecb = _aes_ecb(key)
    blocks = [bytes(ct[i:i + 16]) for i in range(0, len(ct), 16)]
    before = _cbc_decrypt(aes_ecb, bytes(iv), blocks)
    if idx == 0:
        iv[pos] ^= flip                      # 第一块改 IV
    else:
        prev_block = bytearray(blocks[idx - 1])
        prev_block[pos] ^= flip              # 改 C[i-1] 使 P[i] 按 xor 翻转
        blocks[idx - 1] = bytes(prev_block)
    after = _cbc_decrypt(aes_ecb, bytes(iv), blocks)
    target = idx * 16 + pos
    ok = after[target] == before[target] ^ flip
    out = {"mode": "cbc", "target_block": idx, "byte_index": pos, "xor": flip,
           "target_offset": target,
           "plaintext_before_hex": before[target:target + 1].hex(),
           "plaintext_after_hex": after[target:target + 1].hex(),
           "verified": ok}
    return out, 0 if ok else 1


def _small_prime(bits, rng):
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand):
            return cand


def _is_probable_prime(n, rounds=24):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    rng = random.Random(0xC0FFEE)
    for _ in range(rounds):
        a = rng.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def self_test():
    checks = []
    rng = random.Random(20261021)
    # 1) RSA 小指数：真实素数与真实 pow 回代
    p, q = _small_prime(256, rng), _small_prime(256, rng)
    n = p * q
    e = 3
    m = int.from_bytes(b"pwn-crypto-rsa", "big")
    c = pow(m, e, n)
    r = do_rsa({"n": n, "e": e, "c": c})[0]
    checks.append(("rsa-iroot", r["verified"] and int(r["m"]) == m))
    # 2) Håstad 广播：3 组互质模数
    ms = m
    triples = []
    for _ in range(3):
        p1, q1 = _small_prime(256, rng), _small_prime(256, rng)
        n1 = p1 * q1
        triples.append({"n": n1, "c": pow(ms, e, n1)})
    r = do_broadcast({"e": e, "pairs": triples})[0]
    checks.append(("hastad-broadcast", r["verified"] and int(r["m"]) == ms))
    # 3) HMAC 真算 + 篡改必须失败
    key, msg = b"k" * 16, b"seep pwn-crypto"
    digest = hmac.new(key, msg, "sha256").hexdigest()
    r = do_hmac({"algo": "sha256", "key_hex": key.hex(),
                 "message_hex": msg.hex(), "expected_hex": digest})[0]
    checks.append(("hmac-compare", r["verified"] and r["tamper_rejected"]))
    # 4) MT19937：用 Python random 的真实输出克隆并预测
    seed = 20261021
    py = random.Random(seed)
    outs = [py.getrandbits(32) for _ in range(624)]
    nxt = [py.getrandbits(32) for _ in range(8)]
    r = do_mt({"outputs": outs, "next": nxt, "predict": 8})[0]
    checks.append(("mt19937-clone", r["verified"]))
    r, rc = do_mt({"outputs": outs})
    checks.append(("mt19937-requires-next",
                   rc == 2 and r.get("blocked_at") == "mt" and not r.get("verified", False)))
    # 5/6) AES-ECB 块关系与 CBC 位翻转（有 pycryptodome 才跑）
    if HAVE_AES:
        key = bytes(range(16))
        r = do_ecb({"key_hex": key.hex(), "plaintext_hex": (b"A" * 32).hex()})[0]
        checks.append(("aes-ecb-dup", r["verified"] and r["duplicate_blocks"] == 1))
        iv = bytes(range(16, 32))
        ct = AES.new(key, AES.MODE_CBC, iv).encrypt(b"B" * 32)
        r = do_cbc({"key_hex": key.hex(), "iv_hex": iv.hex(),
                    "ciphertext_hex": ct.hex(), "target_block": 1,
                    "byte_index": 3, "xor": 0x20})[0]
        checks.append(("aes-cbc-bitflip", r["verified"]))
    failed = [name for name, ok in checks if not ok]
    if failed:
        return error_payload("self-test", "失败项: " + ",".join(failed)), 2
    return {"ok": True, "checks": len(checks), "aes_backend": HAVE_AES}, 0


MODES = {"rsa": do_rsa, "broadcast": do_broadcast, "hmac": do_hmac,
         "mt": do_mt, "ecb": do_ecb, "cbc": do_cbc}


def main():
    ap = argparse.ArgumentParser(
        description="密码学回代验收：RSA/广播/HMAC/MT19937/ECB/CBC（真实算法，不造输出）",
        epilog="退出码：0 通过；1 回代失败；2 结构化失败。")
    for mode in MODES:
        ap.add_argument("--" + mode, metavar="JSON", help="%s 模式的输入 JSON" % mode)
    ap.add_argument("--self-test", action="store_true", help="内置真实算法自检（离线）")
    args = ap.parse_args()
    if args.self_test:
        try:
            payload, rc = self_test()
        except Exception as exc:  # noqa: BLE001
            payload, rc = error_payload("self-test", str(exc)[:200]), 2
        print(json.dumps(payload, ensure_ascii=False))
        return rc
    chosen = [(m, getattr(args, m)) for m in MODES if getattr(args, m)]
    if len(chosen) != 1:
        print(json.dumps(error_payload("args", "需要且只需要一个模式参数（或 --self-test）"),
                         ensure_ascii=False))
        return 2
    mode, path = chosen[0]
    try:
        data = load_json(path)
        result, rc = MODES[mode](data)
    except RuntimeError as exc:
        blocked, _, reason = str(exc).partition(": ")
        print(json.dumps(error_payload(blocked or mode, reason or str(exc)),
                         ensure_ascii=False))
        return 2
    except (KeyError, TypeError, ValueError) as exc:
        print(json.dumps(error_payload(mode, "输入字段错误: %s" % exc),
                         ensure_ascii=False))
        return 2
    except Exception as exc:  # noqa: BLE001 —— 兜底不抛裸栈
        print(json.dumps(error_payload("internal", str(exc)[:200]), ensure_ascii=False))
        return 2
    if "ok" not in result:
        result = dict(result)
        result["ok"] = bool(result.get("verified"))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
