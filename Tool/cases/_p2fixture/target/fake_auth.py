#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fake_auth.py —— 纯离线的「需要凭据的假目标」，供阶段机 / WAIT_USER 回放。

它只做一件事：读一个环境变量，比对常量，打印一行结论并给退出码。

    合法卡：CARD_CODE=TEST-CARD-0001  ->  stdout: OK:authorized    rc=0
    非法卡：CARD_CODE=WRONG           ->  stdout: DENY:invalid card rc=1
    缺  卡：（不设环境变量）           ->  stdout: DENY:invalid card rc=1

边界：无网络调用、无文件写入、无子进程、无注册表；输入值是与真实授权无关的虚构常量。
环境变量名按 card_code 读，Windows 大小写不敏感、类 Unix 环境用同一常量书写亦可（脚本两种拼写都查）。
"""
from __future__ import annotations

import os
import sys

CARD_VAR = "card_code"
VALID_CARD_CODE = "TEST-CARD-0001"

DENY_LINE = "DENY:invalid card"
OK_LINE = "OK:authorized"


def read_card() -> str:
    """读卡密：兼容 card_code / CARD_CODE 两种拼写，缺失或空串都算缺卡。"""
    for name in (CARD_VAR, CARD_VAR.upper()):
        value = os.environ.get(name)
        if value is not None:
            return value.strip()
    return ""


def main() -> int:
    card = read_card()
    if card and card == VALID_CARD_CODE:
        print(OK_LINE)
        return 0
    print(DENY_LINE)
    return 1


if __name__ == "__main__":
    sys.exit(main())
