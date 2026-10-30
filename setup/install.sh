#!/usr/bin/env bash
# ==============================================================================
# Seep Reverse Lab — 跨平台 (Linux/macOS) 一键自动化安装部署脚本
# ==============================================================================
set -e
export PYTHONIOENCODING=utf-8

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOL_DIR="$ROOT/Tool"
SAFE_DIR="$TOOL_DIR/mcp/Tool/safe"
AGENT_DIR=""
SKIP_PACKAGES=0
SKIP_PYTHON=0
AGENT_ROOT_ARG=""

usage() {
    echo "用法: $0 [--agent-root PATH] [--skip-packages] [--skip-python]"
}
while [ $# -gt 0 ]; do
    case "$1" in
        --agent-root)
            if [ $# -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then
                echo '--agent-root 需要路径参数' >&2; exit 2
            fi
            shift; AGENT_ROOT_ARG="$1" ;;
        --skip-packages) SKIP_PACKAGES=1 ;;
        --skip-python) SKIP_PYTHON=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

echo "================================================================================"
echo "          Seep Reverse Lab — Linux/macOS 部署管线 (Installer)"
echo "================================================================================"
echo "  工作台物理根目录: $ROOT"

# 1. 基础环境探测
# 注意：Windows 上 `python3` 可能是 Microsoft Store 占位程序——存在但不运行、返回非零。
# 因此不仅探测存在，还要验证能真正执行；否则依次回退到 python。
echo -e "\n[1/7] 🔍 检查基础运行环境..."
PY=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' &>/dev/null; then
        PY="$candidate"
        break
    fi
done
if [ -z "$PY" ]; then
    echo "❌ 错误: 未检测到可用的 Python 3.11+（python3/python 均不可执行）。请安装 Python 并勾选 Add to PATH。"
    exit 1
fi
PY_VER=$($PY -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
    echo "❌ 需要 Python 3.11+，当前版本为 $PY_VER" >&2
    exit 1
fi
INSTALL_FAIL=0
RUNTIME_BRIDGE="$TOOL_DIR/scripts/runtime-root.py"

write_install_manifest() {
    local status="$1"
    "$PY" - "$ROOT" "$AGENT_DIR" "$INSTALL_MANIFEST" "$status" <<'PYMANIFEST'
from pathlib import Path
import hashlib
import json
import os
import sys
import tempfile

root = Path(sys.argv[1]).resolve()
agent = Path(sys.argv[2]).resolve()
manifest_path = Path(sys.argv[3])
status = sys.argv[4]
allowed = ("skills/", "prompts/", "agents/", "extensions/", "packages/pi-seep-ext/")
cache_dirs = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}

def sha(data):
    return hashlib.sha256(data).hexdigest()

def runtime_cache(rel):
    parts = Path(str(rel).replace("\\", "/")).parts
    return any(part in cache_dirs for part in parts) or Path(rel).suffix.lower() in (".pyc", ".pyo")

def safe_rel(rel):
    rel = str(rel).replace("\\", "/")
    parts = Path(rel).parts
    return (bool(rel) and not rel.startswith("/") and ".." not in parts
            and any(rel.startswith(prefix) for prefix in allowed))

def safe_target(base, rel):
    if not safe_rel(rel):
        return None
    target = base / Path(rel)
    try:
        target.resolve(strict=False).relative_to(base.resolve())
    except (OSError, ValueError):
        return None
    if any(part.is_symlink() for part in target.parents if part != base):
        return None
    return target

def record_deployed(rel, expected):
    if status == "installing" or runtime_cache(rel):
        return
    target = safe_target(agent, rel)
    if target is None:
        return
    try:
        if target.is_file() and not target.is_symlink():
            actual = sha(target.read_bytes())
            if actual == expected:
                managed[rel] = actual
    except OSError:
        pass

managed = {}
try:
    previous = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, ValueError):
    previous = {}
previous_ok = (isinstance(previous, dict)
               and previous.get("schema") == "seep-agent-install/1"
               and str(previous.get("source_root", "")) == str(root))
if previous_ok and isinstance(previous.get("managed_files"), dict):
    for rel, recorded in previous["managed_files"].items():
        if not safe_rel(rel) or runtime_cache(rel) or not isinstance(recorded, str):
            continue
        target = safe_target(agent, rel)
        if target is None:
            continue
        try:
            if target.is_file() and not target.is_symlink() and sha(target.read_bytes()) == recorded:
                managed[rel] = recorded
        except OSError:
            pass

preexisting = set()
if (previous_ok and previous.get("status") == "installing"
        and isinstance(previous.get("preexisting_files"), list)):
    preexisting.update(
        rel for rel in previous["preexisting_files"]
        if isinstance(rel, str) and safe_rel(rel)
    )
else:
    candidates = []
    tasks_root = root / "Tool" / "prompts" / "tasks"
    if tasks_root.is_dir():
        candidates.extend("prompts/" + path.name for path in tasks_root.glob("*.md")
                          if path.name != "README.md" and path.is_file() and not path.is_symlink())
    agents_root = root / "Tool" / "prompts" / "agents"
    if agents_root.is_dir():
        candidates.extend("agents/" + path.name for path in agents_root.glob("*.md")
                          if path.name != "README.md" and path.is_file() and not path.is_symlink())
    for rel in candidates:
        target = safe_target(agent, rel)
        if (rel not in managed and target is not None
                and target.exists() and not target.is_symlink()):
            preexisting.add(rel)

skill_root = root / "Tool" / "skill"
if skill_root.is_dir():
    for source in sorted(skill_root.iterdir(), key=lambda p: p.name):
        if not source.is_dir() or source.name.startswith("_") or source.name == "update":
            continue
        deployments = []
        if source.name == "safe-skills":
            for sub in sorted(source.iterdir(), key=lambda p: p.name):
                if (sub.is_dir() and not (skill_root / sub.name).exists()):
                    deployments.append(sub)
        else:
            deployments.append(source)
        for directory in deployments:
            for path in directory.rglob("*"):
                if not path.is_file() or path.is_symlink():
                    continue
                rel = "skills/" + directory.name + "/" + path.relative_to(directory).as_posix()
                record_deployed(rel, sha(path.read_bytes()))

tasks = root / "Tool" / "prompts" / "tasks"
if tasks.is_dir():
    root_posix = str(root).replace("\\", "/")
    for path in sorted(tasks.glob("*.md")):
        if path.name == "README.md" or not path.is_file() or path.is_symlink():
            continue
        text = path.read_text(encoding="utf-8-sig").replace("@SEEP_ROOT@", root_posix)
        rel = "prompts/" + path.name
        if rel not in preexisting or rel in managed:
            record_deployed(rel, sha(text.encode("utf-8")))

agents = root / "Tool" / "prompts" / "agents"
if agents.is_dir():
    for path in sorted(agents.glob("*.md")):
        if path.name == "README.md" or not path.is_file() or path.is_symlink():
            continue
        rel = "agents/" + path.name
        if rel not in preexisting or rel in managed:
            record_deployed(rel, sha(path.read_bytes()))

extensions = root / "Tool" / "prompts" / "extensions"
if extensions.is_dir():
    for path in sorted(extensions.iterdir(), key=lambda p: p.name):
        if (path.is_file() and not path.is_symlink()
                and path.suffix.lower() in (".ts", ".json", ".md")):
            rel = "extensions/" + path.name
            record_deployed(rel, sha(path.read_bytes()))

created = []
if isinstance(previous, dict) and isinstance(previous.get("created_paths"), list):
    created.extend(p for p in previous["created_paths"]
                   if p == "agents/settings.json")
if not (agent / "agents" / "settings.json").exists():
    created.append("agents/settings.json")
created = sorted(set(created))

version_path = root / "VERSION"
version = version_path.read_text(encoding="utf-8").strip() if version_path.is_file() else None
payload = {
    "schema": "seep-agent-install/1",
    "runtime_id": "seep-reverse-lab/softseep",
    "source_root": str(root),
    "version": version,
    "status": status,
    "managed_files": dict(sorted(managed.items())),
    "prompt_blocks": ["AGENTS.md", "SEEP.md"],
    "created_paths": created,
    "preexisting_files": sorted(preexisting),
}
agent.mkdir(parents=True, exist_ok=True)
fd, temporary = tempfile.mkstemp(prefix=".seep-install-", dir=agent)
try:
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(payload, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, manifest_path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PYMANIFEST
}

RESOLVE_ARGS=("$RUNTIME_BRIDGE" resolve)
[ -n "$AGENT_ROOT_ARG" ] && RESOLVE_ARGS+=(--agent-root "$AGENT_ROOT_ARG")
if ! RESOLVE_JSON="$($PY "${RESOLVE_ARGS[@]}")"; then
    echo "❌ Agent root 无效或 runtime-root helper 不可用" >&2
    exit 1
fi
AGENT_DIR="$($PY -c 'import json,sys; print(json.loads(sys.argv[1])["agent_root"])' "$RESOLVE_JSON")" || {
    echo "❌ Agent root 解析结果无效" >&2
    exit 1
}
[ -n "$AGENT_DIR" ] || { echo "❌ Agent root 为空" >&2; exit 1; }
INSTALL_MANIFEST="$AGENT_DIR/seep-install-manifest.json"
export PI_CODING_AGENT_DIR="$AGENT_DIR"
echo "  Agent 目标根目录: $AGENT_DIR"
# Fail before package installs or asset replacement when user inputs are invalid.
"$PY" "$SCRIPT_DIR/merge_agent_config.py" --root "$ROOT" --agent-dir "$AGENT_DIR" --validate-only || exit 1
echo "  [√] Python 解释器: $PY (v$PY_VER)"
if [ "$SKIP_PACKAGES" -eq 1 ]; then
    echo "  [i] 已跳过宿主/包检查 (--skip-packages)"
elif ! command -v node >/dev/null 2>&1 || ! command -v pi >/dev/null 2>&1; then
    echo "  [FAIL] Pi/Node 宿主不可用。可用 --skip-packages 仅准备配置，或从 https://pi.dev 安装宿主及 Node.js LTS 后重跑。"
    INSTALL_FAIL=1
fi

# 2. 离线依赖解压
if [ "$SKIP_PACKAGES" -eq 1 ]; then
    echo -e "\n[2/7] ⏭️ 已跳过离线依赖包解压 (--skip-packages)"
else
    echo -e "\n[2/7] 📦 解压内置离线依赖..."
for mod in "js-reverse-mcp" "playwright-mcp"; do
    TARGET_DIR="$SAFE_DIR/$mod/node_modules"
    ZIP_FILE="$SAFE_DIR/$mod/node_modules.zip"
    if [ -d "$TARGET_DIR" ]; then
        echo "  [√] $mod 依赖目录已存在"
    elif [ -f "$ZIP_FILE" ]; then
        echo "  正在解压: $ZIP_FILE -> $TARGET_DIR"
        # Only publish a complete extraction; failed partial trees cannot pass a rerun.
        STAGE_DIR="$(mktemp -d "$SAFE_DIR/$mod/.seep-extract-XXXXXX")" || exit 1
        if unzip -q "$ZIP_FILE" -d "$STAGE_DIR" && [ -d "$STAGE_DIR/node_modules" ] && mv "$STAGE_DIR/node_modules" "$TARGET_DIR"; then
            echo "  [√] $mod 依赖解压就绪"
        else
            echo "  [FAIL] $mod 依赖解压未完成" >&2
            INSTALL_FAIL=1
        fi
        rm -rf "$STAGE_DIR"
    else
        echo "  [FAIL] $mod 缺少依赖目录及归档: $ZIP_FILE" >&2
        INSTALL_FAIL=1
    fi
done
[ "$INSTALL_FAIL" -eq 0 ] || exit 1
fi

# 3. 赋予工具执行权限 + Radare2 运行时引擎探测
if [ "$SKIP_PACKAGES" -eq 1 ]; then
    echo -e "\n[3/7] ⏭️ 已跳过工具/包探测 (--skip-packages)"
else
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
fi

# 4. 安装 Python mcp 协议库
if [ "$SKIP_PACKAGES" -eq 1 ] || [ "$SKIP_PYTHON" -eq 1 ]; then
    echo -e "\n[4/7] ⏭️ 已跳过 Python 协议依赖 (--skip-packages/--skip-python)"
else
    echo -e "\n[4/7] 🐍 安装 Python 协议支持..."
$PY -m pip install "mcp>=1.20,<1.29" --quiet || {
    echo "❌ MCP 协议依赖安装失败：$PY -m pip install 'mcp>=1.20,<1.29'"
    INSTALL_FAIL=1
}
# 扩展资产可选依赖（缺失时对应工具会优雅降级，但要如实记录）
$PY -m pip install pefile curl-cffi zstandard requests --quiet 2>/dev/null || {
    echo "  [!] 扩展可选依赖未全部安装（后续相关工具会降级）"
}
if [ "$INSTALL_FAIL" -eq 0 ]; then
    echo "  [√] Python MCP 协议支持就绪"
else
    echo "  [FAIL] Python MCP 协议支持未就绪"
fi
fi

# 5. Pi Agent 配置同步
mkdir -p "$AGENT_DIR"
write_install_manifest installing || {
    echo "  [FAIL] 无法写入安装所有权清单；未部署任何工作台资产" >&2
    exit 1
}
mkdir -p "$AGENT_DIR/skills" "$AGENT_DIR/extensions"

remove_runtime_caches() {
    local target="$1"
    find "$target" -depth \( \
        -type d \( -name '__pycache__' -o -name '.pytest_cache' \
                   -o -name '.mypy_cache' -o -name '.ruff_cache' \) -o \
        -type f \( -name '*.pyc' -o -name '*.pyo' \) \
    \) -exec rm -rf -- {} +
}

deployment_file_is_owned() {
    local rel="$1" target="$2"
    "$PY" - "$INSTALL_MANIFEST" "$AGENT_DIR" "$ROOT" "$rel" "$target" <<'PYOWNED'
from pathlib import Path
import hashlib
import json
import sys

manifest_path, agent, root, rel, target = sys.argv[1:]
agent = Path(agent).resolve()
target = Path(target)
allowed = ("skills/", "prompts/", "agents/", "extensions/")
rel = str(rel).replace("\\", "/")
parts = Path(rel).parts
if (not rel or rel.startswith("/") or ".." in parts
        or not any(rel.startswith(prefix) for prefix in allowed)):
    raise SystemExit(1)
try:
    data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    recorded = (data.get("managed_files") or {}).get(rel)
    if (data.get("schema") != "seep-agent-install/1"
            or str(data.get("source_root", "")) != str(Path(root).resolve())
            or not isinstance(recorded, str)):
        raise SystemExit(1)
    target.resolve(strict=False).relative_to(agent)
    if any(part.is_symlink() for part in target.parents if part != agent):
        raise SystemExit(1)
    if not target.is_file() or target.is_symlink():
        raise SystemExit(1)
    actual = hashlib.sha256(target.read_bytes()).hexdigest()
except (OSError, ValueError, TypeError):
    raise SystemExit(1)
raise SystemExit(0 if actual == recorded else 1)
PYOWNED
}

backup_replace_skill() {
    local src="$1" dst="$2" name="$3" backup_root="" backup_path=""
    if [ -e "$dst" ]; then
        backup_root="$(mktemp -d "$AGENT_DIR/backup-install-skills-XXXXXX")" || return 1
        backup_path="$backup_root/$name"
        if ! cp -a "$dst" "$backup_path" || [ ! -e "$backup_path" ]; then
            rm -rf "$backup_root"
            return 1
        fi
        echo "  [i] 已备份既有 skill: $name -> $backup_path"
        if ! rm -rf "$dst"; then return 1; fi
    fi
    if [ "${SEEP_INTERNAL_TEST_FAIL_SKILL_COPY:-}" = "$name" ]; then
        rm -rf "$dst"
        if [ -n "$backup_path" ] && [ -e "$backup_path" ]; then
            cp -a "$backup_path" "$dst" || return 2
            echo "  [i] 注入的复制失败，已从备份回滚既有 skill: $name" >&2
        fi
        return 1
    fi
    if ! cp -r "$src" "$(dirname "$dst")/" || ! remove_runtime_caches "$dst"; then
        rm -rf "$dst"
        if [ -n "$backup_path" ] && [ -e "$backup_path" ]; then
            cp -a "$backup_path" "$dst" || return 2
            echo "  [i] 复制失败，已从备份回滚既有 skill: $name" >&2
        fi
        return 1
    fi
    [ -e "$dst" ]
}

replace_task_asset() {
    local src="$1" dst="$2" root="$3" backup_root="" backup_path="" temporary
    temporary="$(mktemp "$(dirname "$dst")/.seep-task-XXXXXX")" || return 1
    if [ -e "$dst" ] || [ -L "$dst" ]; then
        backup_root="$(mktemp -d "$AGENT_DIR/backup-install-tasks-XXXXXX")" || {
            rm -f "$temporary"; return 1;
        }
        backup_path="$backup_root/$(basename "$dst")"
        if ! cp -p "$dst" "$backup_path"; then
            rm -rf "$backup_root" "$temporary"
            return 1
        fi
        echo "  [i] 已备份既有任务卡: $(basename "$dst")"
    fi
    if ! "$PY" - "$src" "$temporary" "$root" <<'PYTASK'
from pathlib import Path
import sys
source, destination, root = sys.argv[1:]
text = Path(source).read_text(encoding="utf-8-sig").replace(
    "@SEEP_ROOT@", str(Path(root).resolve()).replace("\\", "/"))
Path(destination).write_text(text, encoding="utf-8", newline="\n")
PYTASK
    then
        rm -f "$temporary"
        [ -n "$backup_path" ] && rm -rf "$backup_root"
        return 1
    fi
    if ! mv -f "$temporary" "$dst"; then
        rm -f "$temporary"
        if [ -n "$backup_path" ] && [ -e "$backup_path" ] && [ ! -e "$dst" ]; then
            cp -p "$backup_path" "$dst" || true
        fi
        return 1
    fi
    [ -e "$dst" ]
}

replace_extension_asset() {
    local src="$1" dst="$2" backup_root="" backup_path="" temporary
    temporary="$(mktemp "$(dirname "$dst")/.seep-extension-XXXXXX")" || return 1
    if [ -e "$dst" ]; then
        backup_root="$(mktemp -d "$AGENT_DIR/backup-install-extensions-XXXXXX")" || {
            rm -f "$temporary"; return 1;
        }
        backup_path="$backup_root/$(basename "$dst")"
        if ! cp -p "$dst" "$backup_path"; then
            rm -rf "$backup_root" "$temporary"
            return 1
        fi
        echo "  [i] 已备份既有扩展资产: $(basename "$dst")"
    fi
    if ! cp "$src" "$temporary" || ! mv -f "$temporary" "$dst"; then
        rm -f "$temporary"
        if [ -n "$backup_path" ] && [ -e "$backup_path" ] && [ ! -e "$dst" ]; then
            cp -p "$backup_path" "$dst" || true
        fi
        return 1
    fi
    [ -e "$dst" ]
}

# 复制 Skills
if [ -d "$TOOL_DIR/skill" ]; then
    for s in "$TOOL_DIR/skill/"*; do
        if [ -d "$s" ]; then
            sname=$(basename "$s")
            # ★ S3「索引 32→9」：`_pending/` 是归档区（不索引、不路由、不部署）
            case "$sname" in _*) continue ;; esac
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
                    if ! backup_replace_skill "$sub" "$AGENT_DIR/skills/$subname" "$subname"; then
                        echo "  [FAIL] 既有 skill 备份/复制失败，保持安装失败状态: $subname"
                        INSTALL_FAIL=1
                    fi
                done
            elif [ "$sname" != "update" ]; then
                if ! backup_replace_skill "$s" "$AGENT_DIR/skills/$sname" "$sname"; then
                    echo "  [FAIL] 既有 skill 备份/复制失败，保持安装失败状态: $sname"
                    INSTALL_FAIL=1
                fi
            fi
        fi
    done
    echo "  [√] 技能包同步完成"
fi

# 复制提示词与扩展
# 注意：文件名是 SEEP.md（pi 内核会把 <agent-dir>/SYSTEM.md 当成替换默认提示词，导致重复注入）
"$PY" "$SCRIPT_DIR/merge_agent_config.py" --root "$ROOT" --agent-dir "$AGENT_DIR" --prompts-only || INSTALL_FAIL=1
# 任务卡（prompt templates）：Tool/prompts/tasks/*.md → ~/.pi/agent/prompts/<name>.md
#   pi 把每个文件当一条 /slash 命令，所以「说明文件」不能拷进去（部署成 /README 就是废命令）。
#   ★ 对齐 Windows 侧 install-pi.ps1：跳过 README.md，并如实报“拷了几个”，不编造不存在的命令。
if [ -d "$TOOL_DIR/prompts/tasks" ]; then
    mkdir -p "$AGENT_DIR/prompts"
    task_count=0
    for t in "$TOOL_DIR/prompts/tasks/"*.md; do
        [ -f "$t" ] || continue
        tbase="$(basename "$t")"
        if [ "$tbase" = "README.md" ]; then
            continue
        fi
        task_dest="$AGENT_DIR/prompts/$tbase"
        if { [ -e "$task_dest" ] || [ -L "$task_dest" ]; } \
                && ! deployment_file_is_owned "prompts/$tbase" "$task_dest"; then
            echo "  [i] 保留无法证明归工作台所有的 prompt task: $tbase"
        else
            if replace_task_asset "$t" "$task_dest" "$ROOT"; then
                task_count=$((task_count + 1))
            else
                echo "  [FAIL] 任务卡同步失败: $tbase" >&2
                INSTALL_FAIL=1
            fi
        fi
    done
    echo "  [√] 任务卡已同步 $task_count 个 md -> $AGENT_DIR/prompts/"
fi

# Match the Windows deployment of source-provided agent roles, preserving
# pre-existing user roles with the same names.
if [ -d "$TOOL_DIR/prompts/agents" ]; then
    mkdir -p "$AGENT_DIR/agents"
    for role in "$TOOL_DIR/prompts/agents/"*.md; do
        [ -f "$role" ] || continue
        role_name="$(basename "$role")"
        [ "$role_name" = README.md ] && continue
        role_dest="$AGENT_DIR/agents/$role_name"
        if { [ -e "$role_dest" ] || [ -L "$role_dest" ]; } \
                && ! deployment_file_is_owned "agents/$role_name" "$role_dest"; then
            echo "  [i] 保留无法证明归工作台所有的 agent: $role_name"
        else
            if ! replace_extension_asset "$role" "$role_dest"; then
                echo "  [FAIL] Agent 定义同步失败: $role_name" >&2
                INSTALL_FAIL=1
            fi
        fi
    done
    if ! "$PY" "$SCRIPT_DIR/merge_agent_config.py" --root "$ROOT" --agent-dir "$AGENT_DIR" --agents-only; then
        echo '  [FAIL] Agent 设置未就绪' >&2
        INSTALL_FAIL=1
    fi
else
    echo '  [FAIL] 缺少 Agent 定义源目录' >&2
    INSTALL_FAIL=1
fi

# 迁移：旧版把规则写成 ~/.pi/agent/SYSTEM.md，会被 pi 内核当"替换默认提示词"，必须退役
if [ -f "$AGENT_DIR/SYSTEM.md" ] && grep -q "Seep Reverse Lab" "$AGENT_DIR/SYSTEM.md" 2>/dev/null; then
    mkdir -p "$AGENT_DIR/backup-retired-prompts"
    mv -f "$AGENT_DIR/SYSTEM.md" "$AGENT_DIR/backup-retired-prompts/SYSTEM.md.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    echo "  [√] 已退役旧版 SYSTEM.md（会被 pi 内核当替换提示词，导致规则重复注入）"
fi
if [ -d "$TOOL_DIR/prompts/extensions" ]; then
    for asset in "$TOOL_DIR/prompts/extensions/"*.ts "$TOOL_DIR/prompts/extensions/"*.json "$TOOL_DIR/prompts/extensions/"*.md; do
        [ -f "$asset" ] || continue
        if ! replace_extension_asset "$asset" "$AGENT_DIR/extensions/$(basename "$asset")"; then
            echo "  [FAIL] 扩展同步失败: $(basename "$asset")" >&2
            INSTALL_FAIL=1
        fi
    done
    # 扩展的配套规则文件（如 cmd-guard.rules.json：cmd-guard 从 __dirname 读它）
    # 扩展的文档型配置（TOOL-CHAIN.md：cmd-guard 的 GUI→CLI 派生源）
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
[6/7] 🧩 增量合并 Agent 配置 (mcp.json + settings.json)..."
#
# ★ 血案：旧实现用一行 sed 从模板生成 mcp.json，导致
#   · 路径是 Windows 反斜杠（Linux/macOS 下不存在，核心 MCP 起不来）
#   · ida 条目塞着未替换的 <IDA_PYTHON> 占位符且 lifecycle=eager
#   · 整文件覆写，用户自建 MCP 条目被清空，且无备份
# 现在统一走 Python 合并器：POSIX 路径、无占位符、只增不删、写前备份。
if [ -f "$SCRIPT_DIR/merge_agent_config.py" ]; then
    "$PY" "$SCRIPT_DIR/merge_agent_config.py" --root "$ROOT" --agent-dir "$AGENT_DIR" || {
        echo "  [FAIL] 配置合并器失败"
        INSTALL_FAIL=1
    }
else
    echo "  [FAIL] 未找到 setup/merge_agent_config.py，无法生成 Agent 配置"
    INSTALL_FAIL=1
fi

# 生成 Claude Code 项目级 .mcp.json（相对路径，可随仓库走）
if [ -f "$TOOL_DIR/mcp/mcp.json.template" ] && [ ! -f "$ROOT/.mcp.json" ]; then
    if "$PY" - "$ROOT" <<'PYEOF' 2>/dev/null
import json, os, sys
root = sys.argv[1]
cfg = {"mcpServers": {
    "seep": {"command": "python", "args": ["Tool/mcp/seep_mcp_server.py"],
             "env": {"PYTHONIOENCODING": "utf-8"}, "transport": "stdio"},
    "js-reverse": {"command": "npx", "args": ["-y", "js-reverse-mcp"], "transport": "stdio"},
}}
with open(os.path.join(root, ".mcp.json"), "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
PYEOF
    then
        echo "  [√] 已生成项目级 .mcp.json（Claude Code 免配加载）"
    else
        echo "  [FAIL] 项目级 .mcp.json 生成失败"
        INSTALL_FAIL=1
    fi
fi
echo "================================================================================"
echo "  [i] 配置合并完成：部署结论由第 7 步自检决定（不再无条件报「部署完毕」）"
echo "================================================================================"

# 6.5 runtime 注册：source/deployed entry hash 和当前 source runtime 必须先验证
ENTRY_SOURCE="$TOOL_DIR/skill/softseep/scripts/version-migrate.py"
ENTRY_DEST="$AGENT_DIR/skills/softseep/scripts/version-migrate.py"
if ! "$PY" "$RUNTIME_BRIDGE" register --agent-root "$AGENT_DIR" --runtime-root "$ROOT" --entry-source "$ENTRY_SOURCE" --entry-dest "$ENTRY_DEST"; then
    echo "  [FAIL] runtime 注册失败，拒绝假登记 success"
    INSTALL_FAIL=1
else
    echo "  [√] runtime 已验证并完成注册（config-only，source runtime 必须保留）"
fi

# 7. 部署自检（与 Windows 侧 setup/install.ps1 最后一步完全一致）
#    ★ 血案：旧版这里无条件打印「🎉 部署完毕」，装没装好根本不看，属于对客户说假话。
#      现在结论只由 check.py --env 的退出码决定：非 0 就报「部署未完成」并以非 0 退出。
echo -e "
[7/7] 🩺 部署自检 (python Tool/scripts/check.py --env)..."
ENV_RC=0
# set -e 会让失败的 python 直接中断脚本，这里要拿到真实退出码再自行判定
set +e
"$PY" "$ROOT/Tool/scripts/check.py" --env
ENV_RC=$?
set -e

echo "================================================================================"
MANIFEST_STATUS=incomplete
if [ "$ENV_RC" -eq 0 ] && [ "$INSTALL_FAIL" -eq 0 ]; then
    MANIFEST_STATUS=complete
fi
if ! write_install_manifest "$MANIFEST_STATUS"; then
    echo "  [FAIL] 无法更新安装所有权清单" >&2
    INSTALL_FAIL=1
fi
if [ "$ENV_RC" -eq 0 ] && [ "$INSTALL_FAIL" -eq 0 ]; then
    echo "  🎉 恭喜！Seep Reverse Lab 在当前系统部署完毕！"
    echo "  下一步提示:"
    echo "  1. 用相同 AgentRoot 重开 Pi 会话，检查技能、扩展与 MCP 实际加载。"
    echo "  2. 直接说明任务和材料；lab：是可选交互。其他宿主接入需单独验证。"
else
    echo "  ⚠️ 部署未完成：体检未通过（明细见上方 check.py --env 输出，退出码 $ENV_RC）"
    echo "     修好后重跑: bash setup/install.sh"
fi
echo "================================================================================"
if [ "$ENV_RC" -ne 0 ] && [ "$INSTALL_FAIL" -eq 0 ]; then
    INSTALL_FAIL=1
fi
exit "$INSTALL_FAIL"
