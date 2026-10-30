#!/usr/bin/env bash
# ============================================================================
#  Seep 逆向工程工作台 —— 一键卸载 (Linux / macOS)
# ============================================================================
#  设计原则：只移除工作台自己装的东西，绝不碰你的数据。
#
#  卸载范围（逐项可关）：
#    · <agent-root>/skills/<工作台技能>      —— 当前启用的工作台技能
#    · <agent-root>/AGENTS.md / SEEP.md      —— 工作台写入的提示词（旧版为 SYSTEM.md，一并清理）
#    · <agent-root>/extensions/*.ts          —— 工作台扩展
#    · <agent-root>/mcp.json 中的 seep / js-reverse / playwright 条目
#    · <agent-root>/settings.json 中工作台加入的 packages
#    · lab-mode.flag 不在安装所有权清单内，保留用户现有标志
#
#  严格保护（永不删除）：
#    · models.json / auth.json / sessions/ / logs/
#    · 你自己添加的 Skill、MCP 条目、settings.json 字段
#    · 你自己的 backup-* 备份目录（除非显式 --purge）
#
#  用法：
#    ./setup/uninstall.sh --dry-run
#    ./setup/uninstall.sh
#    ./setup/uninstall.sh --yes --keep-skills
#    ./setup/uninstall.sh --restore "<agent-root>/backup-uninstall-20261011-120000"
# ============================================================================
set -uo pipefail

DRY_RUN=0; ASSUME_YES=0
KEEP_SKILLS=0; KEEP_PROMPTS=0; KEEP_MCP=0; KEEP_PACKAGES=0; KEEP_LAB_FLAG=0
PURGE=0; RESTORE=""; AGENT_ROOT_ARG=""

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run|-n)     DRY_RUN=1 ;;
        --yes|-y)         ASSUME_YES=1 ;;
        --keep-skills)    KEEP_SKILLS=1 ;;
        --keep-prompts)   KEEP_PROMPTS=1 ;;
        --keep-mcp)       KEEP_MCP=1 ;;
        --keep-packages)  KEEP_PACKAGES=1 ;;
        --keep-lab-flag)  KEEP_LAB_FLAG=1 ;;
        --purge)          PURGE=1 ;;
        --agent-root|--restore)
            if [ $# -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then
                echo "$1 需要路径参数" >&2; exit 2
            fi
            option="$1"; shift
            if [ "$option" = --agent-root ]; then AGENT_ROOT_ARG="$1"; else RESTORE="$1"; fi ;;
        -h|--help)
            sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "未知参数: $1（用 --help 查看用法）" >&2; exit 2 ;;
    esac
    shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOL_DIR="$ROOT/Tool"
AGENT_DIR=""
RUNTIME_BRIDGE="$TOOL_DIR/scripts/runtime-root.py"
PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 11))' >/dev/null 2>&1; then PY="$candidate"; break; fi
done
[ -n "$PY" ] || { echo "❌ 未检测到可用 Python 3.11+" >&2; exit 1; }
RESOLVE_ARGS=("$RUNTIME_BRIDGE" resolve)
[ -n "$AGENT_ROOT_ARG" ] && RESOLVE_ARGS+=(--agent-root "$AGENT_ROOT_ARG")
if ! RESOLVE_JSON="$($PY "${RESOLVE_ARGS[@]}")"; then echo "❌ Agent root 无效" >&2; exit 1; fi
AGENT_DIR="$($PY -c 'import json,sys; print(json.loads(sys.argv[1])["agent_root"])' "$RESOLVE_JSON")" || exit 1
SKILLS_DIR="$AGENT_DIR/skills"
EXT_DIR="$AGENT_DIR/extensions"
MCP_JSON="$AGENT_DIR/mcp.json"
SET_JSON="$AGENT_DIR/settings.json"
LAB_FLAG="$AGENT_DIR/lab-mode.flag"
ORIGIN_JSON="$AGENT_DIR/seep-runtime.json"
INSTALL_MANIFEST="$AGENT_DIR/seep-install-manifest.json"

if [ -t 1 ]; then
    RED=$'\033[1;31m'; GREEN=$'\033[1;32m'; YELLOW=$'\033[1;33m'
    CYAN=$'\033[1;36m'; GRAY=$'\033[0;37m'; MAGENTA=$'\033[1;35m'; RESET=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; CYAN=''; GRAY=''; MAGENTA=''; RESET=''
fi

step()  { printf '\n%b>>> %s%b\n' "$CYAN" "$*" "$RESET"; }
ok()    { printf '    %b[OK]%b %s\n' "$GREEN" "$RESET" "$*"; }
warn()  { printf '    %b[!!]%b %s\n' "$YELLOW" "$RESET" "$*"; }
info()  { printf '    %b[..]%b %s\n' "$GRAY" "$RESET" "$*"; }
fail()  { printf '    %b[FAIL]%b %s\n' "$RED" "$RESET" "$*"; }

REMOVED=0; FAILED=0

# ---------------------------------------------------------------------------
# 工作台自有资产清单（与 install.sh / install-pi.ps1 严格对齐）
# ---------------------------------------------------------------------------
workbench_skill_names() {
    local src="$ROOT/Tool/skill" d sub
    [ -d "$src" ] || return 0
    {
        for d in "$src"/*/; do
            [ -d "$d" ] || continue
            local name; name="$(basename "$d")"
            case "$name" in _*) continue ;; esac
            if [ "$name" = "safe-skills" ]; then
                for sub in "$d"*/; do [ -d "$sub" ] && basename "$sub"; done
            elif [ "$name" != "update" ]; then
                echo "$name"
            fi
        done
    } | awk '!seen[$0]++'
}

WORKBENCH_PACKAGES=(
    "npm:pi-open-tui" "npm:pi-web-access" "npm:@juicesharp/rpiv-todo"
    "npm:@narumitw/pi-btw" "npm:@narumitw/pi-plan-mode" "npm:@narumitw/pi-usage"
    "npm:pi-mcp-extension" "npm:@smoose/pi-themes" "npm:pi-tool-display"
    "npm:@juicesharp/rpiv-ask-user-question" "npm:pi-playwright" "npm:pi-goal-x"
)

PERSONA_PACKAGE_SOURCE="$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8-sig"))["source"])' "$SCRIPT_DIR/pi-persona-rewind.package.json")"
PERSONA_PACKAGE_SOURCE="${PERSONA_PACKAGE_SOURCE%$'\r'}"
WORKBENCH_PACKAGES+=("$PERSONA_PACKAGE_SOURCE")

# 用 Python 做 JSON 读写（零新依赖，仅标准库）
# 注意：Windows 下 Python 默认把 \n 转成 \r\n，会让读出的键名带尾随 \r，
# 因此所有 helper 都强制以 LF 输出，并在 bash 侧再防御性剥离一次。
json_keys() {  # json_keys <file> <top-level-key>
    "$PY" - "$1" "$2" <<'PY' 2>/dev/null
import json, sys, io, os
try:
    sys.stdout.reconfigure(newline='\n')
except Exception:
    pass
p, k = sys.argv[1], sys.argv[2]
if not os.path.exists(p): sys.exit(0)
try:
    d = json.loads(io.open(p, encoding='utf-8-sig').read())
except Exception:
    sys.exit(0)
v = d.get(k)
if isinstance(v, dict):
    for name in v: sys.stdout.write(str(name) + '\n')
elif isinstance(v, list):
    for item in v:
        if isinstance(item, dict) and item.get('source') == './packages/pi-seep-ext':
            item = item['source']
        sys.stdout.write(str(item) + '\n')
PY
}

# 判定 MCP 条目是否归工作台所有（看 args 是否指向工作台组件）
mcp_entry_is_ours() {  # mcp_entry_is_ours <name>
    local name="${1%$'\r'}"
    "$PY" - "$MCP_JSON" "$name" "$ROOT" <<'PY' 2>/dev/null
import json, sys, io, os
try:
    p, name, root = sys.argv[1:]
    with open(os.path.join(root, 'Tool/config/mcp-servers.json'), encoding='utf-8-sig') as stream:
        names = json.load(stream)['servers']
    if name not in names: sys.exit(1)
    with open(p, encoding='utf-8-sig') as stream:
        e = json.load(stream).get('mcpServers', {}).get(name, {})
    parts = [str(e.get('command', '')), str(e.get('url', ''))] + [str(a) for a in e.get('args', [])]
    text = ' '.join(parts).replace('\\', '/').lower()
    markers = (root.replace('\\', '/').lower(), 'seep_mcp_server.py', 'js-reverse-mcp', '@playwright/mcp', 'mcp-launch.py')
    sys.exit(0 if any(marker and marker in text for marker in markers) else 1)
except Exception:
    sys.exit(1)
PY
}

owned_deployed_files() {
    "$PY" - "$ROOT" "$AGENT_DIR" "$INSTALL_MANIFEST" <<'PY'
from pathlib import Path
import hashlib
import json
import sys

root = Path(sys.argv[1]).resolve()
agent = Path(sys.argv[2]).resolve()
manifest_path = Path(sys.argv[3])
allowed = ("skills/", "prompts/", "agents/", "extensions/")

def sha(data):
    return hashlib.sha256(data).hexdigest()

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

owned = {}
recognized = False
created_paths = []
try:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, ValueError):
    data = {}
if (isinstance(data, dict) and data.get("schema") == "seep-agent-install/1"
        and str(data.get("source_root", "")) == str(root)):
    recognized = True
    if isinstance(data.get("created_paths"), list):
        created_paths = [p for p in data["created_paths"] if p == "agents/settings.json"]
    files = data.get("managed_files")
    if isinstance(files, dict):
        for rel, recorded in files.items():
            if not safe_rel(rel) or not isinstance(recorded, str):
                continue
            target = safe_target(agent, rel)
            if target is None:
                continue
            try:
                if target.is_file() and not target.is_symlink() and sha(target.read_bytes()) == recorded:
                    owned[rel] = recorded
            except OSError:
                if target.is_file() and not target.is_symlink():
                    owned[rel] = recorded

print("manifest\t1" if recognized else "manifest\t0")
for path in sorted(set(created_paths)):
    print("created\t" + path)
for rel, recorded in sorted(owned.items()):
    print("file\t" + rel + "\t" + recorded)
PY
}

# ===========================================================================
# 模式 A：从备份恢复
# ===========================================================================
if [ -n "$RESTORE" ]; then
    echo -e "\n${MAGENTA}╔══════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${MAGENTA}║   Seep 工作台 —— 从备份恢复                                   ║${RESET}"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════╝${RESET}"

    if [ ! -d "$RESTORE" ]; then fail "备份目录不存在: $RESTORE"; exit 1; fi

    step "1/2  扫描备份内容"
    info "备份目录: $RESTORE"
    COUNT=$(find "$RESTORE" -type f 2>/dev/null | wc -l | tr -d ' ')
    info "文件数: $COUNT"

    step "2/2  恢复"
    if [ "$DRY_RUN" = "1" ]; then
        while IFS= read -r f; do
            [ -z "$f" ] && continue
            info "将恢复: ${f#$RESTORE/}"
        done < <(find "$RESTORE" -type f 2>/dev/null)
        warn '--dry-run 模式，未做任何修改'
        exit 0
    fi
    RESTORED=0
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        rel="${f#$RESTORE/}"
        dst="$AGENT_DIR/$rel"
        mkdir -p "$(dirname "$dst")"
        if cp "$f" "$dst" 2>/dev/null; then RESTORED=$((RESTORED+1));
        else fail "恢复失败: $rel"; FAILED=$((FAILED+1)); fi
    done < <(find "$RESTORE" -type f 2>/dev/null)
    ok "已恢复 $RESTORED 个文件"
    info "请完全重启 Agent 会话后生效"
    [ "$FAILED" -eq 0 ] || exit 1
    exit 0
fi

OWNED_RELS=()
OWNED_HASHES=()
MANIFEST_RECOGNIZED=0
MANIFEST_CREATED_PATHS=()
while IFS=$'\t' read -r kind first second; do
    kind="${kind%$'\r'}"
    first="${first%$'\r'}"
    second="${second%$'\r'}"
    case "$kind" in
        manifest) [ "$first" = "1" ] && MANIFEST_RECOGNIZED=1 ;;
        created) [ -n "$first" ] && MANIFEST_CREATED_PATHS+=("$first") ;;
        file)
            [ -n "$first" ] && [ -n "$second" ] || continue
            OWNED_RELS+=("$first")
            OWNED_HASHES+=("$second")
            ;;
    esac
done < <(owned_deployed_files)

if ! "$PY" "$RUNTIME_BRIDGE" validate --agent-root "$AGENT_DIR" --runtime-root "$ROOT" >/dev/null 2>&1; then
    warn 'runtime 注册缺失或损坏；将依据安装所有权清单和逐文件哈希执行安全清理'
    if [ "$MANIFEST_RECOGNIZED" -eq 0 ] && [ "${#OWNED_RELS[@]}" -eq 0 ]; then
        warn '未找到可信安装清单；只处理配置中的明确工作台条目，无法证明所有权的文件全部保留'
    fi
else
    info 'runtime 注册有效，并与当前 source root 一致'
fi

# ===========================================================================
# 模式 B：卸载
# ===========================================================================
"$PY" "$SCRIPT_DIR/merge_agent_config.py" --root "$ROOT" --agent-dir "$AGENT_DIR" --validate-configs-only || {
    fail '配置无效，尚未移除任何项目'; exit 1;
}
if [ "$KEEP_PROMPTS" = "0" ]; then
    "$PY" "$SCRIPT_DIR/merge_agent_config.py" --root "$ROOT" --agent-dir "$AGENT_DIR" --remove-prompts-only --dry-run || {
        fail '提示词边界无效，尚未移除任何项目'; exit 1;
    }
fi
echo -e "\n${MAGENTA}╔══════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${MAGENTA}║   Seep 逆向工程工作台 —— 一键卸载                             ║${RESET}"
echo -e "${MAGENTA}╚══════════════════════════════════════════════════════════════╝${RESET}"
[ "$DRY_RUN" = "1" ] && warn 'DRY-RUN 模式：只预览，不做任何修改'

# ---------------------------------------------------------------- 1. 盘点
step '1/5  盘点将要移除的内容'

SKILL_NAMES=$(workbench_skill_names)
SKILL_HITS=()
TASK_HITS=()
AGENT_HITS=()
EXTENSION_HITS=()
MANAGED_FILE_HITS=()
for i in "${!OWNED_RELS[@]}"; do
    rel="${OWNED_RELS[$i]}"
    case "$rel" in
        skills/*)
            [ "$KEEP_SKILLS" = "0" ] || continue
            skill_name="${rel#skills/}"; skill_name="${skill_name%%/*}"
            SKILL_HITS+=("$skill_name")
            MANAGED_FILE_HITS+=("$rel")
            ;;
        prompts/*)
            [ "$KEEP_PROMPTS" = "0" ] || continue
            TASK_HITS+=("$rel")
            MANAGED_FILE_HITS+=("$rel")
            ;;
        agents/*)
            [ "$KEEP_PROMPTS" = "0" ] || continue
            AGENT_HITS+=("$rel")
            MANAGED_FILE_HITS+=("$rel")
            ;;
        extensions/*)
            [ "$KEEP_PROMPTS" = "0" ] || continue
            EXTENSION_HITS+=("$rel")
            MANAGED_FILE_HITS+=("$rel")
            ;;
    esac
done
if [ "${#SKILL_HITS[@]}" -gt 0 ]; then
    mapfile -t SKILL_HITS < <(printf '%s\n' "${SKILL_HITS[@]}" | awk '!seen[$0]++')
fi

PROMPT_HITS=()
if [ "$KEEP_PROMPTS" = "0" ]; then
    for f in AGENTS.md SEEP.md SYSTEM.md; do
        if [ -f "$AGENT_DIR/$f" ] && grep -Eiq '<!--[[:space:]]*seep:managed:|Seep Reverse Lab|seep-reverse-lab|SEEP 工作台' "$AGENT_DIR/$f" 2>/dev/null; then
            PROMPT_HITS+=("$f")
        fi
    done
fi

MCP_HITS=()
if [ "$KEEP_MCP" = "0" ] && [ -f "$MCP_JSON" ]; then
    while IFS= read -r k; do
        k="${k%$'\r'}"
        [ -z "$k" ] && continue
        mcp_entry_is_ours "$k" && MCP_HITS+=("$k")
    done < <(json_keys "$MCP_JSON" mcpServers)
fi

PKG_HITS=()
if [ "$KEEP_PACKAGES" = "0" ] && [ -f "$SET_JSON" ]; then
    while IFS= read -r pkg; do
        pkg="${pkg%$'\r'}"
        [ -z "$pkg" ] && continue
        for wp in "${WORKBENCH_PACKAGES[@]}"; do
            [ "$pkg" = "$wp" ] && PKG_HITS+=("$pkg") && break
        done
    done < <(json_keys "$SET_JSON" packages)
fi
if [ "$KEEP_PACKAGES" = "0" ] && [ -d "$AGENT_DIR/packages/pi-seep-ext" ]; then
    if ! printf '%s\n' "${PKG_HITS[@]:-}" | grep -Fxq "$PERSONA_PACKAGE_SOURCE"; then
        PKG_HITS+=("$PERSONA_PACKAGE_SOURCE")
    fi
fi

FLAG_HITS=()
if [ -f "$LAB_FLAG" ]; then
    info '保留 lab-mode.flag：安装清单不能证明该文件由工作台创建'
fi
ORIGIN_HITS=()
[ -f "$ORIGIN_JSON" ] && ORIGIN_HITS+=("seep-runtime.json")
MANIFEST_HITS=()
[ -f "$INSTALL_MANIFEST" ] && [ "$KEEP_PACKAGES" = "0" ] && MANIFEST_HITS+=("seep-install-manifest.json")
AGENT_SETTINGS_HITS=()
if [ "$MANIFEST_RECOGNIZED" -eq 1 ] && [ -f "$AGENT_DIR/agents/settings.json" ]; then
    for created in "${MANIFEST_CREATED_PATHS[@]:-}"; do
        [ "$created" = "agents/settings.json" ] && AGENT_SETTINGS_HITS+=("agents/settings.json")
    done
fi

report_plan() {  # report_plan <label> <count> <joined>
    local label="$1" n="$2" joined="$3"
    if [ "$n" -eq 0 ]; then info "$label : （无）"; else ok "$label : $n 项 -> $joined"; fi
}
report_plan '技能 (skills)'        "${#SKILL_HITS[@]}"  "$(IFS=', '; echo "${SKILL_HITS[*]:-}")"
report_plan '任务卡 (prompts)'      "${#TASK_HITS[@]}"   "$(IFS=', '; echo "${TASK_HITS[*]:-}")"
report_plan '子代理定义 (agents)'   "${#AGENT_HITS[@]}"  "$(IFS=', '; echo "${AGENT_HITS[*]:-}")"
report_plan '安全扩展 (extensions)' "${#EXTENSION_HITS[@]}" "$(IFS=', '; echo "${EXTENSION_HITS[*]:-}")"
report_plan '提示词管理块'          "${#PROMPT_HITS[@]}" "$(IFS=', '; echo "${PROMPT_HITS[*]:-}")"
report_plan 'MCP 条目'             "${#MCP_HITS[@]}"    "$(IFS=', '; echo "${MCP_HITS[*]:-}")"
report_plan 'settings packages'    "${#PKG_HITS[@]}"    "$(IFS=', '; echo "${PKG_HITS[*]:-}")"
report_plan '实验环境标志'          "${#FLAG_HITS[@]}"   "$(IFS=', '; echo "${FLAG_HITS[*]:-}")"
report_plan 'runtime registration'  "${#ORIGIN_HITS[@]}"  "$(IFS=', '; echo "${ORIGIN_HITS[*]:-}")"
report_plan 'install ownership manifest' "${#MANIFEST_HITS[@]}" "$(IFS=', '; echo "${MANIFEST_HITS[*]:-}")"
report_plan 'agent settings ownership' "${#AGENT_SETTINGS_HITS[@]}" "$(IFS=', '; echo "${AGENT_SETTINGS_HITS[*]:-}")"

# ---------------------------------------------------------------- 2. 保护声明
step '2/5  用户自有数据保护声明'
for f in models.json auth.json sessions logs; do
    [ -e "$AGENT_DIR/$f" ] && ok "保留: $f"
done
USER_MCP=()
while IFS= read -r k; do
    k="${k%$'\r'}"
    [ -z "$k" ] && continue
    mcp_entry_is_ours "$k" || USER_MCP+=("$k")
done < <(json_keys "$MCP_JSON" mcpServers)
[ "${#USER_MCP[@]}" -gt 0 ] && ok "保留你自己的 MCP 条目: $(IFS=', '; echo "${USER_MCP[*]}")"
USER_SKILLS=()
if [ -d "$SKILLS_DIR" ]; then
    for d in "$SKILLS_DIR"/*/; do
        [ -d "$d" ] || continue
        n="$(basename "$d")"
        echo "$SKILL_NAMES" | grep -qx "$n" || USER_SKILLS+=("$n")
    done
fi
[ "${#USER_SKILLS[@]}" -gt 0 ] && ok "保留你自己安装的技能: $(IFS=', '; echo "${USER_SKILLS[*]}")"

TOTAL=$(( ${#MANAGED_FILE_HITS[@]} + ${#PROMPT_HITS[@]} + ${#MCP_HITS[@]} + ${#PKG_HITS[@]}
          + ${#FLAG_HITS[@]} + ${#ORIGIN_HITS[@]} + ${#MANIFEST_HITS[@]}
          + ${#AGENT_SETTINGS_HITS[@]} ))
if [ "$TOTAL" -eq 0 ]; then
    echo -e "\n${GREEN}[√] 没有发现需要移除的工作台内容，系统已是干净状态。${RESET}"
    exit 0
fi

if [ "$DRY_RUN" = "1" ]; then
    echo -e "\n${YELLOW}[DRY-RUN] 以上 $TOTAL 项将被移除，未做任何修改。${RESET}"
    info '去掉 --dry-run 参数即可真正执行'
    exit 0
fi

# ---------------------------------------------------------------- 3. 确认
if [ "$ASSUME_YES" = "0" ]; then
    echo -e "\n${YELLOW}即将移除以上 $TOTAL 项。你的数据（模型凭据 / 自定义配置）不会被触碰。${RESET}"
    read -r -p '确认卸载？输入 yes 继续: ' ans
    case "$ans" in yes|y|Y|YES) ;; *) info '已取消'; exit 0 ;; esac
fi

# ---------------------------------------------------------------- 4. 执行
step '3/5  备份受影响文件'
BACKUP_ROOT="$(mktemp -d "$AGENT_DIR/backup-uninstall-$(date +%Y%m%d-%H%M%S)-XXXXXX")" || exit 1
info "备份目录: $BACKUP_ROOT"

backup_item() {  # backup_item <src> <rel-label>
    [ -e "$1" ] || return 0
    mkdir -p "$BACKUP_ROOT/$(dirname "$2")"
    if cp -r "$1" "$BACKUP_ROOT/$2" 2>/dev/null; then info "已备份: $2"
    else fail "备份失败，原件保留: $2"; FAILED=$((FAILED+1)); fi
}
for rel in "${MANAGED_FILE_HITS[@]:-}"; do
    [ -n "$rel" ] && backup_item "$AGENT_DIR/$rel" "$rel"
done
for f in "${PROMPT_HITS[@]:-}"; do [ -n "$f" ] && backup_item "$AGENT_DIR/$f" "$f"; done
if [ "${#MCP_HITS[@]}" -gt 0 ] || [ "${#PKG_HITS[@]}" -gt 0 ]; then
    backup_item "$MCP_JSON" 'mcp.json'
    backup_item "$SET_JSON" 'settings.json'
fi
[ "${#FLAG_HITS[@]}" -gt 0 ] && backup_item "$LAB_FLAG" 'lab-mode.flag'
[ "${#ORIGIN_HITS[@]}" -gt 0 ] && backup_item "$ORIGIN_JSON" 'seep-runtime.json'
[ "${#MANIFEST_HITS[@]}" -gt 0 ] && backup_item "$INSTALL_MANIFEST" 'seep-install-manifest.json'
[ "${#AGENT_SETTINGS_HITS[@]}" -gt 0 ] && backup_item "$AGENT_DIR/agents/settings.json" 'agents/settings.json'

step '4/5  执行移除'
[ "$FAILED" -eq 0 ] || { fail '备份未完整成功，尚未移除任何项目'; exit 1; }
if [ "$KEEP_PROMPTS" = 0 ] && [ "${#PROMPT_HITS[@]}" -gt 0 ]; then
    "$PY" "$SCRIPT_DIR/merge_agent_config.py" --root "$ROOT" --agent-dir "$AGENT_DIR" --remove-prompts-only || FAILED=$((FAILED+1))
fi
for rel in "${MANAGED_FILE_HITS[@]:-}"; do
    [ -z "$rel" ] && continue
    expected_hash=""
    for i in "${!OWNED_RELS[@]}"; do
        if [ "${OWNED_RELS[$i]}" = "$rel" ]; then expected_hash="${OWNED_HASHES[$i]}"; break; fi
    done
    actual_hash="$("$PY" -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$AGENT_DIR/$rel" 2>/dev/null)"
    if [ -z "$expected_hash" ] || [ "$actual_hash" != "$expected_hash" ]; then
        warn "文件与安装清单哈希不一致，已保留: $rel [${actual_hash:0:12} != ${expected_hash:0:12}]"
        continue
    fi
    if rm -f "$AGENT_DIR/$rel" 2>/dev/null; then
        ok "已移除: $rel"; REMOVED=$((REMOVED+1))
        if [[ "$rel" == skills/* ]]; then
            prune_parent="$(dirname "$AGENT_DIR/$rel")"
            while [ "$prune_parent" != "$SKILLS_DIR" ] && [[ "$prune_parent" == "$SKILLS_DIR/"* ]]; do
                [ -d "$prune_parent" ] && [ ! -L "$prune_parent" ] || break
                if [ -n "$(find "$prune_parent" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
                    break
                fi
                rmdir -- "$prune_parent" 2>/dev/null || break
                prune_parent="$(dirname "$prune_parent")"
            done
        fi
    else fail "移除失败: $rel"; FAILED=$((FAILED+1)); fi
done

# MCP：外科手术式移除，保留用户其他条目
if [ "${#MCP_HITS[@]}" -gt 0 ]; then
    MCP_LIST="$(IFS=','; echo "${MCP_HITS[*]}")"
    if "$PY" "$SCRIPT_DIR/merge_agent_config.py" --root "$ROOT" --agent-dir "$AGENT_DIR" --remove-mcp "${MCP_HITS[@]}"; then
        ok "已移除 MCP 条目: $MCP_LIST"; REMOVED=$((REMOVED+${#MCP_HITS[@]}))
    else fail 'mcp.json 清理失败'; FAILED=$((FAILED+1)); fi
fi

# settings.json：只移除工作台加入的 packages
if [ "${#PKG_HITS[@]}" -gt 0 ]; then
    if "$PY" "$SCRIPT_DIR/merge_agent_config.py" --root "$ROOT" --agent-dir "$AGENT_DIR" --remove-packages; then
        ok "已从 settings.json 移除 ${#PKG_HITS[@]} 个 packages"; REMOVED=$((REMOVED+${#PKG_HITS[@]}))
    else fail 'settings.json 清理失败'; FAILED=$((FAILED+1)); fi
fi

if [ "${#FLAG_HITS[@]}" -gt 0 ]; then
    if rm -f "$LAB_FLAG" 2>/dev/null; then ok '已移除 lab-mode.flag（实验环境已退出）'; REMOVED=$((REMOVED+1))
    else fail '移除 lab-mode.flag 失败'; FAILED=$((FAILED+1)); fi
fi
if [ "${#AGENT_SETTINGS_HITS[@]}" -gt 0 ]; then
    if "$PY" - "$AGENT_DIR/agents/settings.json" <<'PYAGENTS'
from pathlib import Path
import json
import os
import sys
import tempfile

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8-sig"))
if not isinstance(data, dict):
    raise SystemExit(3)
defaults = {"version": 1, "builtInEnabled": True, "maxConcurrent": 5}
for key, value in defaults.items():
    if data.get(key) == value:
        data.pop(key, None)
if data:
    fd, temporary = tempfile.mkstemp(prefix=".seep-agent-settings-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
else:
    path.unlink()
PYAGENTS
    then ok '已清理安装器创建的 agents/settings.json（用户字段保留）'; REMOVED=$((REMOVED+1))
    else fail 'agents/settings.json 清理失败'; FAILED=$((FAILED+1)); fi
fi
if [ "${#ORIGIN_HITS[@]}" -gt 0 ] && [ "$FAILED" -eq 0 ]; then
    if rm -f "$ORIGIN_JSON" 2>/dev/null; then ok '已移除 runtime 注册（source runtime 保留）'; REMOVED=$((REMOVED+1))
    else fail '移除 runtime 注册失败'; FAILED=$((FAILED+1)); fi
fi
if [ "${#MANIFEST_HITS[@]}" -gt 0 ] && [ "$FAILED" -eq 0 ]; then
    if rm -f "$INSTALL_MANIFEST" 2>/dev/null; then ok '已移除安装所有权清单'; REMOVED=$((REMOVED+1))
    else fail '移除安装所有权清单失败'; FAILED=$((FAILED+1)); fi
fi

# ---------------------------------------------------------------- 5. 深度清理
if [ "$PURGE" = "1" ]; then
    step '5/5  深度清理 (--purge)'
    PURGED=0
    while IFS= read -r b; do
        [ -z "$b" ] && continue
        [ "$b" = "$BACKUP_ROOT" ] && continue
        rm -rf "$b" 2>/dev/null && PURGED=$((PURGED+1)) || warn "无法删除: $(basename "$b")"
    done < <(find "$AGENT_DIR" -maxdepth 1 -type d -name 'backup-*' 2>/dev/null)
    ok "深度清理完成，共 $PURGED 项（source runtime 与用户级状态保留）"
else
    step '5/5  深度清理'
    info '未启用 --purge，历史备份与生成配置均已保留'
fi

# ---------------------------------------------------------------- 报告
echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${RESET}"
if [ "$FAILED" -eq 0 ]; then echo -e "${GREEN}║   卸载完成                                                    ║${RESET}"
else fail '卸载未完成，runtime 注册保留，处理失败后重试'; fi
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${RESET}"
ok "已移除: $REMOVED 项"
[ "$FAILED" -gt 0 ] && fail "失败: $FAILED 项（多为文件被占用，关闭 Agent 后重试）"
info "卸载备份: $BACKUP_ROOT"
info "如需恢复: ./setup/uninstall.sh --restore \"$BACKUP_ROOT\""
echo
info '工作台本体目录未删除。若确认不再需要，可手动删除整个工作台文件夹。'
if [ "$FAILED" -gt 0 ]; then exit 1; fi
exit 0
