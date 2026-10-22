#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""captcha-angle.py —— 旋转类验证码的角度求解（纯 numpy + Pillow，本地、离线）。

它回答：这张图要转多少度才是"正的"（也就是提交给校验接口的那个角度）。

方法：先粗搜（步长 5°）再细搜（步长 0.5°）。评分 = 把图反向旋转 θ 后，
边缘能量在行/列方向投影的"尖锐度"（方差）。图正了，边缘就对齐，投影峰最尖。

为什么不是 OCR：旋转是几何量，不是文字；OCR 只用于字符码。

用法：
    python Tool/scripts/captcha-angle.py --image rotate.png
    python Tool/scripts/captcha-angle.py --image r.png --range 0 360 --json --out work/<case>/angle.json
    python Tool/scripts/captcha-angle.py --self-test

输出（--json）：
    {"ok": true, "schema": "seep.captcha-angle/1", "angle": 17.0, "confidence": 0.83,
     "ambiguous": false, "method": "rotate-search", "size": [280, 280],
     "candidates": [{"angle": 17.0, "score": 0.91}]}

90° 等价类：图对 90° 旋转对称时 4 个候选角（θ/θ+90/θ+180/θ+270）分数几乎相同，
只能定到等价类。此时输出 "ambiguous": true 且 confidence <= 0.35（不再假装高置信度），
并只用 angle_mod90 作为等价类代表；有箭头/文字等方向线索的图仍给唯一高置信角。

判据：confidence >= 0.6 → 直接提交；0.35–0.6 → 提交前在 ±1.5° 内试 2–3 次；< 0.35 → 换路（人工/换图）。
退出码：0 有结果 / 2 输入缺失或不可读 / 3 置信度过低（仍输出结果）。
"""
from __future__ import annotations

import argparse
import json
import os
import sys

try:
    import numpy as np
except Exception:  # noqa: BLE001
    print(json.dumps({"ok": False, "blocked_at": "tool-missing",
                      "reason": "需要 numpy：pip install numpy"}, ensure_ascii=False))
    sys.exit(2)

try:
    from PIL import Image
except Exception:  # noqa: BLE001
    Image = None

SCHEMA = "seep.captcha-angle/1"
# 4 个 90° 等价候选的分数极差 / 最高分低于该比例 → 判为「等价类不可分」。
AMBIGUOUS_SPREAD = 0.03
AMBIGUOUS_CONF_CAP = 0.35
# 方向项权重：把「上/下 + 左/右亮度不平衡」并入候选分数。
# 投影分数本身对 90° 旋转不变（rows.var+cols.var 换轴后相同），单靠它永远分不出
# 4 个等价类；方向项才能区分 θ 与 θ+90。90° 对称图上 4 类方向项相同 → 极差≈0。
DIR_WEIGHT = 1.0
LIMITS = [
    "图像本身没有方向性（纯色/放射对称）时置信度会低，属正常，不是算错",
    "只给角度，不含方向符号约定；有的平台要求 ±180 归一，按目标站点文档换算",
    "带透视/拉伸的旋转图（少见）需要先做单应性校正，本脚本不做",
    "图形对 90° 旋转对称（纯矩形/纯纹理）时只能定到等价类：看 angle_mod90；要唯一角需要箭头/文字等方向线索",
]


def _fail(blocked_at, reason, code=2):
    print(json.dumps({"ok": False, "blocked_at": blocked_at, "reason": reason},
                     ensure_ascii=False))
    return code


def load_gray(path):
    if Image is None:
        return None, "缺少 Pillow：pip install pillow"
    if not os.path.isfile(path):
        return None, "文件不存在: " + path
    try:
        im = Image.open(path).convert("L")
    except Exception as exc:  # noqa: BLE001
        return None, "无法解码图片: %s" % str(exc)[:80]
    return np.asarray(im, dtype=np.float32), None


def edge_map(gray):
    g = gray
    kx = np.array([[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]], dtype=np.float32)
    ky = kx.T
    pad = np.pad(g, 1, mode="edge")
    gx = np.zeros_like(g)
    gy = np.zeros_like(g)
    for dy in range(3):
        for dx in range(3):
            win = pad[dy:dy + g.shape[0], dx:dx + g.shape[1]]
            if kx[dy, dx]:
                gx += kx[dy, dx] * win
            if ky[dy, dx]:
                gy += ky[dy, dx] * win
    return np.sqrt(gx ** 2 + gy ** 2)


def _rotate_crop(gray, angle):
    """把图反向旋转 angle，裁掉旋转产生的边角（评分与方向项共用一次旋转结果）。"""
    if Image is None:
        return None
    im = Image.fromarray(gray.astype(np.uint8))
    rot = im.rotate(angle, resample=Image.BICUBIC, expand=False, fillcolor=int(np.median(gray)))
    arr = np.asarray(rot, dtype=np.float32)
    h, w = arr.shape
    m = max(2, int(min(h, w) * 0.08))
    return arr[m:h - m, m:w - m]


def _directional(arr):
    """上/下、左/右亮度不平衡（对 90° 旋转敏感，对 90° 对称图的 4 个等价类相同）。"""
    h, w = arr.shape
    up = float(arr[:h // 2].mean())
    dn = float(arr[h // 2:].mean())
    lf = float(arr[:, :w // 2].mean())
    rt = float(arr[:, w // 2:].mean())
    vbal = (dn - up) / (abs(dn) + abs(up) + 1e-9)
    hbal = (rt - lf) / (abs(rt) + abs(lf) + 1e-9)
    return vbal + 0.5 * hbal


def score_angle(gray, angle):
    """把图反向旋转 angle 后，边缘投影的尖锐度（越尖越说明对齐了）。"""
    arr = _rotate_crop(gray, angle)
    if arr is None or arr.size == 0 or min(arr.shape) < 4:
        return 0.0
    e = edge_map(arr)
    rows = e.sum(axis=1)
    cols = e.sum(axis=0)
    if rows.size < 3 or cols.size < 3:
        return 0.0
    return float(rows.var() + cols.var())


def class_scores(gray, base_angle):
    """90° 等价类的 4 个候选分数 + 相对极差（max-min 除以最高分）。

    投影分数对 90° 旋转不变，所以再加上方向项（DIR_WEIGHT）；
    90° 对称图上 4 个候选只有重采样噪声差 → 极差 < AMBIGUOUS_SPREAD。
    """
    rows = []
    for k in range(4):
        a = (base_angle + 90.0 * k) % 360.0
        arr = _rotate_crop(gray, a)
        sc = score_angle(gray, a)
        d = _directional(arr) if arr is not None and min(arr.shape) >= 4 else 0.0
        rows.append((a, sc, d))
    top = max(r[1] for r in rows) or 1.0
    comb = [r[1] / top + DIR_WEIGHT * r[2] for r in rows]
    spread = (max(comb) - min(comb)) / (abs(max(comb)) + 1e-9)
    return [(round(a, 1), round(c, 4)) for (a, _, _), c in zip(rows, comb)], spread


def solve(gray, lo=0.0, hi=360.0):
    coarse_step, fine_step = 5.0, 0.5
    best_a, best_s = lo, -1.0
    a = lo
    while a <= hi:
        sc = score_angle(gray, a % 360.0)
        if sc > best_s:
            best_a, best_s = a % 360.0, sc
        a += coarse_step
    fine_a, fine_s = best_a, best_s
    a = best_a - coarse_step
    while a <= best_a + coarse_step:
        sc = score_angle(gray, a % 360.0)
        if sc > fine_s:
            fine_a, fine_s = a % 360.0, sc
        a += fine_step
    # 置信度：与"次优区间"（离最优 >= 10°）的最高分比较
    second = -1.0
    a = lo
    while a <= hi:
        if abs(((a - fine_a + 180) % 360) - 180) >= 10 and abs((a - fine_a) % 90) >= 8:
            second = max(second, score_angle(gray, a % 360.0))
        a += coarse_step
    conf = 0.0
    if fine_s > 0 and second >= 0:
        conf = max(0.0, min(1.0, (fine_s - second) / (abs(fine_s) + 1e-9)))
    # 90° 等价类检查：θ / θ+90 / θ+180 / θ+270 四个候选分数接近 → 只能定到等价类。
    class_list, spread = class_scores(gray, fine_a)
    ambiguous = bool(spread < AMBIGUOUS_SPREAD)
    if ambiguous:
        conf = min(conf, AMBIGUOUS_CONF_CAP)
    candidates = [{"angle": round(fine_a, 1), "score": round(fine_s, 2)},
                  {"angle": round(best_a, 1), "score": round(best_s, 2)}]
    for a, c in class_list:
        candidates.append({"angle": a, "score": c})
    return {"angle": round(fine_a, 1), "angle_mod90": round(fine_a % 90.0, 1),
            "confidence": round(conf, 3), "ambiguous": ambiguous,
            "equivalence_class": [a for a, _ in class_list],
            "equivalence_spread": round(spread, 4),
            "method": "rotate-search", "candidates": candidates}


def self_test():
    checks, fails = [], []
    if Image is None:
        print(json.dumps({"ok": False, "blocked_at": "tool-missing",
                          "reason": "需要 Pillow"}, ensure_ascii=False))
        return 2
    import tempfile
    tmp = tempfile.mkdtemp(prefix="seep-angle-")
    path = os.path.join(tmp, "rot.png")
    rng = np.random.default_rng(20261022)
    n = 280
    img = np.full((n, n), 175, dtype=np.uint8)
    for _ in range(8):                                  # 方向性结构
        x0, y0 = int(rng.integers(10, n - 80)), int(rng.integers(10, n - 80))
        img[y0:y0 + int(rng.integers(12, 40)), x0:x0 + int(rng.integers(30, 70))] = int(rng.integers(25, 80))
    yy, xx = np.mgrid[0:n, 0:n]
    tri = (yy > 70) & (yy < 200) & (np.abs(xx - 140) < (yy - 70) * 0.85)   # 朝上三角形：破坏 90° 对称
    img[tri] = 28
    img = np.clip(img + rng.normal(0, 10, size=(n, n)), 0, 255).astype(np.uint8)
    truth = 17.0
    Image.fromarray(img).rotate(-truth, resample=Image.BICUBIC, expand=False,
                                fillcolor=175).save(path)

    gray, err = load_gray(path)
    checks.append(("load", err is None and gray is not None))
    if gray is not None:
        res = solve(gray)
        checks.append(("angle-mod90-err<=2", abs(res["angle_mod90"] - (truth % 90)) <= 2.0))
        checks.append(("confidence", res["confidence"] >= 0.35))
        checks.append(("schema", res["method"] == "rotate-search"))
        checks.append(("asymmetric-not-ambiguous", res.get("ambiguous") is False))

    # 对称图：居中圆环 + 居中方框（4 折 = 90° 旋转不变）→ 必须 ambiguous。
    sym_path = os.path.join(tmp, "sym.png")
    rng2 = np.random.default_rng(20261023)
    sym = np.full((n, n), 175, dtype=np.uint8)
    ring = np.abs(np.hypot(xx - n / 2.0, yy - n / 2.0) - 70) < 12
    box = (np.abs(xx - n / 2.0) < 90) & (np.abs(yy - n / 2.0) < 90) & ~(
        (np.abs(xx - n / 2.0) < 55) & (np.abs(yy - n / 2.0) < 55))
    sym[ring] = 30
    sym[box] = 60
    sym = np.clip(sym + rng2.normal(0, 8, size=(n, n)), 0, 255).astype(np.uint8)
    Image.fromarray(sym).rotate(-25.0, resample=Image.BICUBIC, expand=False,
                                fillcolor=175).save(sym_path)
    gray_s, err_s = load_gray(sym_path)
    checks.append(("sym-load", err_s is None and gray_s is not None))
    if gray_s is not None:
        rs = solve(gray_s)
        checks.append(("symmetric-ambiguous", rs.get("ambiguous") is True))
        checks.append(("symmetric-confidence<=0.35", rs["confidence"] <= 0.35))
    gray2, err2 = load_gray(os.path.join(tmp, "nope.png"))
    checks.append(("missing-input", gray2 is None and "不存在" in (err2 or "")))
    fails = [nm for nm, ok in checks if not ok]
    print(json.dumps({"ok": not fails, "tool": "captcha-angle.py",
                      "checks": len(checks), "failures": fails}, ensure_ascii=False))
    return 0 if not fails else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="旋转验证码角度求解（本地旋转搜索，不调外部识别）")
    ap.add_argument("--image", help="待求解的图片路径")
    ap.add_argument("--range", nargs=2, type=float, default=[0.0, 360.0], metavar=("LO", "HI"))
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="把 JSON 写到该路径（自动建父目录）")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    if not args.image:
        return _fail("input", "缺少 --image")

    gray, err = load_gray(args.image)
    if err:
        return _fail("input", err)
    res = solve(gray, args.range[0], args.range[1])
    payload = {"ok": True, "schema": SCHEMA, **res,
               "size": [int(gray.shape[1]), int(gray.shape[0])], "limits": LIMITS}
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    print(text)
    if args.out:
        try:
            parent = os.path.dirname(os.path.abspath(args.out))
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
            with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            return _fail("out-unwritable", "无法写 --out：%s" % exc)
    return 0 if payload["confidence"] >= 0.35 else 3


if __name__ == "__main__":
    sys.exit(main())
