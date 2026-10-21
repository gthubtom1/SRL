#!/usr/bin/env python3
"""生成真实算法输入：RSA 素数、Håstad 三模数、HMAC、MT19937、AES-ECB/CBC。
所有密文/摘要都由真实实现现场算出，随后交给 crypto-verify.py 回代。"""
import hashlib
import hmac
import json
import os
import random

from Crypto.Cipher import AES
from Crypto.Util.number import getPrime

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE)


def dump(name, obj):
    with open(os.path.join(OUT, name), "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)


msg = b"pwn-crypto-real-rsa"
m = int.from_bytes(msg, "big")
e = 3
p, q = getPrime(512), getPrime(512)
n = p * q
dump("rsa.json", {"n": n, "e": e, "c": pow(m, e, n),
                  "note": "m^3 < n，无填充；明文由 crypto-verify.py iroot 恢复"})

pairs = []
for _ in range(3):
    n_i = getPrime(512) * getPrime(512)
    pairs.append({"n": n_i, "c": pow(m, e, n_i)})
dump("broadcast.json", {"e": e, "pairs": pairs,
                        "note": "同一 m、e=3、三组互质 n；CRT 后应为精确立方"})

key, message = b"seep-key-00000001", b"pwn-crypto hmac evidence"
dump("hmac.json", {"algo": "sha256", "key_hex": key.hex(),
                   "message_hex": message.hex(),
                   "expected_hex": hmac.new(key, message, "sha256").hexdigest()})

seed = 20261021
py = random.Random(seed)
outs = [py.getrandbits(32) for _ in range(624)]
nxt = [py.getrandbits(32) for _ in range(8)]
dump("mt.json", {"outputs": outs, "next": nxt, "predict": 8,
                 "note": "624 个真实 getrandbits(32)；克隆后预测下 8 个"})

aes_key = bytes(range(16))
dump("ecb.json", {"key_hex": aes_key.hex(), "plaintext_hex": (b"A" * 32).hex(),
                   "note": "两个相同明文块 -> 两个相同密文块，证明 ECB 结构泄漏"})

iv = bytes(range(16, 32))
cbc_pt = b"balance=1000;to=alice;padding".ljust(32, b"!")
ct = AES.new(aes_key, AES.MODE_CBC, iv).encrypt(cbc_pt)
dump("cbc.json", {"key_hex": aes_key.hex(), "iv_hex": iv.hex(),
                  "ciphertext_hex": ct.hex(), "target_block": 1,
                  "byte_index": 3, "xor": 32,
                  "note": "翻转 C[0][3] 使 P[1][3] 按 xor 0x20 改变"})
print("inputs written")
