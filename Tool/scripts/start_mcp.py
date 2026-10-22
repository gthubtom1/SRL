#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""start_mcp.py —— 在 IDA Pro 内启动 `ida_mcp` 插件（不是 CLI 脚本）。

用法（二选一）：
    IDA 内：File → Script file… → 选本文件
    命令行：idat -A -S"Tool/scripts/start_mcp.py" <样本>

在普通 Python 里执行会返回 `{"ok":false,"blocked_at":"tool-missing"}` + rc=2，
因为 `idaapi` 只存在于 IDA 的 Python 环境（这是预期行为，不是脚本坏了）。
"""
from __future__ import annotations

import json
import sys

USAGE = (
    "start_mcp.py —— 在 IDA Pro 内启动 ida_mcp 插件。\n"
    "  IDA 内：File → Script file… → 选本文件\n"
    "  命令行：idat -A -S\"Tool/scripts/start_mcp.py\" <样本>\n"
    "在普通 Python 里跑会返回 blocked_at=tool-missing（缺 idaapi），属预期。"
)


def main() -> int:
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print(USAGE)
        return 0
    try:
        import idaapi  # noqa: F401  仅 IDA 环境提供
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"ok": False, "blocked_at": "tool-missing",
                          "reason": "需要 IDA Pro 的 idaapi（本脚本在 IDA 内执行）：%s"
                                    % str(exc)[:80]}, ensure_ascii=False))
        return 2
    idaapi.load_and_run_plugin("ida_mcp", 1)
    print(json.dumps({"ok": True, "plugin": "ida_mcp"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
