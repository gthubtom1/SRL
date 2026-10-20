#!/usr/bin/env bash
# ==============================================================================
# Seep Reverse Lab — 跨平台 (Linux/macOS) 一键自动化安装部署脚本
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOL_DIR="$ROOT/Tool"
SAFE_DIR="$TOOL_DIR/mcp/Tool/safe"
AGENT_DIR="$HOME/.pi/agent"

echo "================================================================================"
echo "          Seep Reverse Lab — Linux/macOS 部署管线 (Installer)"
echo "================================================================================"
echo "  工作台物理根目录: $ROOT"
echo "  Agent 目标根目录: $AGENT_DIR"

# 1. 基础环境探测
# 注意：Windows 上 `python3` 可能是 Microsoft Store 占位程序——存在但不运行、返回非零。
# 因此不仅探测存在，还要验证能真正执行；否则依次回退到 python。
echo -e "\n[1/6] 🔍 检查基础运行环境..."
PY=""
if command -v python3 &>/dev/null && python3 -c "print(1)" &>/dev/null; then
    PY="python3"
elif command -v python &>/dev/null && python -c "print(1)" &>/dev/null; then
    PY="python"
fi
if [ -z "$PY" ]; then
    echo "❌ 错误: 未检测到可用的 Python 3.11+（python3/python 均不可执行）。请安装 Python 并勾选 Add to PATH。"
    exit 1
fi
PY_VER=$($PY -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "  [√] Python 解释器: $PY (v$PY_VER)"

# 2. 离线依赖解压
echo -e "\n[2/6] 📦 解压内置离线依赖..."
for mod in "js-reverse-mcp" "playwright-mcp"; do
    TARGET_DIR="$SAFE_DIR/$mod/node_modules"
    ZIP_FILE="$SAFE_DIR/$mod/node_modules.zip"
    if [ ! -d "$TARGET_DIR" ] && [ -f "$ZIP_FILE" ]; then
        echo "  正在解压: $ZIP_FILE -> $TARGET_DIR"
        # ★ 注意：unzip 遇到「反斜杠路径」等告警时返回码是 1（不是 0），
        # 在 set -e 下会直接把整个安装脚本打断。这里显式兜住，只告警不中断。
        if unzip -q "$ZIP_FILE" -d "$SAFE_DIR/$mod/"; then
            echo "  [√] $mod 依赖解压就绪"
        else
            if [ -d "$TARGET_DIR" ]; then
                echo "  [!] unzip 返回非零（通常是反斜杠条目告警），但依赖目录已生成，继续"
            else
                echo "  ⚠️ $mod 依赖解压失败，请手动执行: unzip -q \"$ZIP_FILE\" -d \"$SAFE_DIR/$mod/\""
            fi
        fi
    else
        echo "  [√] $mod 依赖目录已存在"
    fi
done

# 3. 赋予工具执行权限 + Radare2 运行时引擎探测
echo -e "\n[3/6] 🔧 配置文件执行权限 / Radare2 引擎..."
if [ -d "$SAFE_DIR/radare2/bin" ]; then
    chmod +x "$SAFE_DIR/radare2/bin/"* 2>/dev/null || true
fi
if [ -f "$SAFE_DIR/jadx/bin/jadx" ]; then
    chmod +x "$SAFE_DIR/jadx/bin/jadx" 2>/dev/null || true
fi

# 内置 radare2/bin 为 Windows 二进制 (*.exe/*.dll)，在 Linux/macOS 无法执行。
# seep MCP 的 _resolve_binary() 在非 Windows 下优先走系统 PATH，故此处确保系统已装 radare2。
if command -v radare2 &>/dev/null; then
    echo "  [√] Radare2 引擎: $(radare2 -v 2>/dev/null | head -1)"
elif [ "$(uname -s)" = "Darwin" ]; then
    if command -v brew &>/dev/null; then
        echo "  [i] 未检测到系统 radare2，正在通过 Homebrew 安装..."
        brew install radare2 && echo "  [√] Radare2 安装完成: $(radare2 -v 2>/dev/null | head -1)" \
            || echo "  ⚠️ brew install radare2 失败，请手动执行: brew install radare2"
    else
        echo "  ⚠️ 未检测到 radare2 与 Homebrew。请先安装 Homebrew，再执行: brew install radare2"
    fi
else
    echo "  ⚠️ 未检测到系统 radare2。请用包管理器安装 (如 apt install radare2 / 参见 https://rada.re)。"
fi
echo "  [√] 二进制可执行权限设置完成"

# 4. 安装 Python mcp 协议库
echo -e "\n[4/6] 🐍 安装 Python 协议支持..."
$PY -m pip install "mcp>=1.20,<1.29" --quiet || {
    echo "⚠️ 自动安装失败，建议手动执行: $PY -m pip install 'mcp>=1.20,<1.29'"
}
# 扩展资产可选依赖（缺失时对应工具会优雅降级，不阻断）
$PY -m pip install pefile curl-cffi zstandard requests --quiet 2>/dev/null || {
    echo "ℹ️ 扩展资产可选依赖未全部安装（pefile/curl-cffi/zstandard），对应工具会降级但不报错"
}
echo "  [√] Python MCP 协议支持就绪"

# 5. Pi Agent 配置同步
echo -e "\n[5/6] 🧠 部署 Pi Agent 技能与提示词..."
mkdir -p "$AGENT_DIR/skills" "$AGENT_DIR/extensions"

# 复制 Skills
if [ -d "$TOOL_DIR/skill" ]; then
    for s in "$TOOL_DIR/skill/"*; do
        if [ -d "$s" ]; then
            sname=$(basename "$s")
            if [ "$sname" = "safe-skills" ]; then
                for sub in "$s/"*; do
                    [ -d "$sub" ] || continue
                    subname="$(basename "$sub")"
                    # ★ 冲突守卫：与顶层技能同名则跳过，避免静默覆盖
                    #   （历史事故：safe-skills/ida-reverse 覆盖顶层 ida-reverse）
                    if [ -d "$TOOL_DIR/skill/$subname" ]; then
                        echo "  [!] safe-skills 子技能与顶层同名，已跳过: $subname"
                        continue
                    fi
                    cp -r "$sub" "$AGENT_DIR/skills/"
                done
            elif [ "$sname" != "update" ]; then
                cp -r "$s" "$AGENT_DIR/skills/"
            fi
        fi
    done
    echo "  [√] 技能包同步完成"
fi

# 复制提示词与扩展
# 注意：文件名是 SEEP.md（pi 内核会把 <agent-dir>/SYSTEM.md 当成替换默认提示词，导致重复注入）
[ -f "$TOOL_DIR/prompts/SEEP.md" ] && cp "$TOOL_DIR/prompts/SEEP.md" "$AGENT_DIR/"
[ -f "$TOOL_DIR/prompts/AGENTS.md" ] && cp "$TOOL_DIR/prompts/AGENTS.md" "$AGENT_DIR/"
# 迁移：旧版把规则写成 ~/.pi/agent/SYSTEM.md，会被 pi 内核当"替换默认提示词"，必须退役
if [ -f "$AGENT_DIR/SYSTEM.md" ] && grep -q "Seep Reverse Lab" "$AGENT_DIR/SYSTEM.md" 2>/dev/null; then
    mkdir -p "$AGENT_DIR/backup-retired-prompts"
    mv -f "$AGENT_DIR/SYSTEM.md" "$AGENT_DIR/backup-retired-prompts/SYSTEM.md.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    echo "  [√] 已退役旧版 SYSTEM.md（会被 pi 内核当替换提示词，导致规则重复注入）"
fi
if [ -d "$TOOL_DIR/prompts/extensions" ]; then
    cp "$TOOL_DIR/prompts/extensions/"*.ts "$AGENT_DIR/extensions/" 2>/dev/null || true
    # 扩展的配套规则文件（如 cmd-guard.rules.json：cmd-guard 从 __dirname 读它）
    cp "$TOOL_DIR/prompts/extensions/"*.json "$AGENT_DIR/extensions/" 2>/dev/null || true
    # 扩展的文档型配置（TOOL-CHAIN.md：cmd-guard 的 GUI→CLI 派生源）
    cp "$TOOL_DIR/prompts/extensions/"*.md "$AGENT_DIR/extensions/" 2>/dev/null || true
    # 自动安全退役与归档已融合的旧版独立扩展（其人设卡/RULES/粘性保护已100%全量融入 load-system-prompt.ts）
    if [ -f "$AGENT_DIR/extensions/prompt-compat.ts" ]; then
        mkdir -p "$AGENT_DIR/backup-retired-extensions"
        mv -f "$AGENT_DIR/extensions/prompt-compat.ts" "$AGENT_DIR/backup-retired-extensions/" 2>/dev/null || true
        echo "  [√] 已安全归档旧版独立扩展 prompt-compat.ts (消除双重注册冲突)"
    fi
    echo "  [√] 提示词与安全拦截扩展同步完成"
fi

# 6. 增量合并 Agent 配置（mcp.json + settings.json）
echo -e "
[6/6] 🧩 增量合并 Agent 配置 (mcp.json + settings.json)..."
#
# ★ 血案：旧实现用一行 sed 从模板生成 mcp.json，导致
#   · 路径是 Windows 反斜杠（Linux/macOS 下不存在，核心 MCP 起不来）
#   · ida 条目塞着未替换的 <IDA_PYTHON> 占位符且 lifecycle=eager
#   · 整文件覆写，用户自建 MCP 条目被清空，且无备份
# 现在统一走 Python 合并器：POSIX 路径、无占位符、只增不删、写前备份。
if [ -f "$SCRIPT_DIR/merge_agent_config.py" ]; then
    "$PY" "$SCRIPT_DIR/merge_agent_config.py" --root "$ROOT" --agent-dir "$AGENT_DIR" || {
        echo "  ⚠️ 配置合并器返回非零（可手动重跑: $PY setup/merge_agent_config.py --root . --agent-dir ~/.pi/agent）"
    }
else
    echo "  ⚠️ 未找到 setup/merge_agent_config.py，跳过 mcp.json 生成（请重新拉取仓库）"
fi

# 生成 Claude Code 项目级 .mcp.json（相对路径，可随仓库走）
if [ -f "$TOOL_DIR/mcp/mcp.json.template" ] && [ ! -f "$ROOT/.mcp.json" ]; then
    "$PY" - "$ROOT" <<'PYEOF' 2>/dev/null || true
import json, os, sys
root = sys.argv[1]
cfg = {"mcpServers": {
    "seep": {"command": "python", "args": ["Tool/mcp/seep_mcp_server.py"],
             "env": {"PYTHONIOENCODING": "utf-8"}, "transport": "stdio"},
    "js-reverse": {"command": "npx", "args": ["-y", "js-reverse-mcp"], "transport": "stdio"},
}}
open(os.path.join(root, ".mcp.json"), "w", encoding="utf-8").write(json.dumps(cfg, indent=2) + "
")
PYEOF
    echo "  [√] 已生成项目级 .mcp.json（Claude Code 免配加载）"
fi

echo "================================================================================"
echo "  🎉 恭喜！Seep Reverse Lab 在当前系统部署完毕！"
echo "  下一步提示:"
echo "  1. 退出并重新打开终端启动 Agent (Pi / Claude Code / DSH)"
echo "  2. 在对话框中发送: lab： 即可开启测试！"
echo "================================================================================"
