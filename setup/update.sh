#!/usr/bin/env bash
# ==============================================================================
# Seep 逆向工程工作台 —— 已有用户一键更新 (Linux / macOS)
# ==============================================================================
# 执行流程：
#   1. 记录当前版本与用户自有数据指纹
#   2. 自动探测代理并 git pull 拉取最新代码
#   3. 对比版本，打印 CHANGELOG 变更说明
#   4. 调用 install.sh 做幂等增量同步
#   5. 校验用户自有数据未被覆盖
#   6. 跑官方基准自检并输出更新报告
#
# 安全承诺：
#   · 用户自有数据 (models.json / auth.json / 自定义 MCP 条目 / lab-mode.flag) 永不被覆盖
#   · 覆盖前自动备份到 ~/.pi/agent/backup-<时间戳>/
#
# 用法：
#   ./setup/update.sh
#   ./setup/update.sh --dry-run
#   ./setup/update.sh --no-pull
# ==============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
AGENT_DIR=""
AGENT_ROOT_ARG=""
VERSION_FILE="$ROOT/VERSION"
CHANGELOG_FILE="$ROOT/docs/CHANGELOG.md"
MCP_JSON=""
PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 11))' >/dev/null 2>&1; then PY="$candidate"; break; fi
done
[ -n "$PY" ] || { echo "❌ 未检测到可用 Python 3.11+" >&2; exit 1; }
RUNTIME_BRIDGE="$ROOT/Tool/scripts/runtime-root.py"

# 仓库地址解析（修复：原先硬编码 angusdevgo 原版仓库，导致 fork 用户“更新工作台”
# 会去拉原版仓库、把本地优化覆盖/回退）。现在以当前工作副本的实际 origin 为准；
# 仅在无 origin 时回退到环境变量 SEEP_REPO_URL；都没有则返回空。
resolve_repo_url() {
    if [ -n "${SEEP_REPO_URL:-}" ]; then echo "$SEEP_REPO_URL"; return; fi
    if [ -e "$ROOT/.git" ] && command -v git >/dev/null 2>&1; then
        git -C "$ROOT" remote get-url origin 2>/dev/null || true
    fi
}
raw_version_url() {
    local u="$1"
    [ -z "$u" ] && return 0
    u="${u%.git}"; u="${u%/}"
    if [[ "$u" =~ github\.com[:/]([^/]+)/([^/]+)$ ]]; then
        echo "https://raw.githubusercontent.com/${BASH_REMATCH[1]}/${BASH_REMATCH[2]}/main/VERSION"
    fi
}
REPO_URL="$(resolve_repo_url)"

GREEN="\033[1;32m"; RED="\033[1;31m"; YELLOW="\033[1;33m"
CYAN="\033[1;36m"; WHITE="\033[1;37m"; GRAY="\033[0;37m"; RESET="\033[0m"

DRY_RUN=0; NO_PULL=0; SKIP_VERIFY=0; SKIP_PACKAGES=0; SKIP_PYTHON=0
STASHED=0; STASH_SHA=""; CHECK_ONLY=0
WARNINGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1 ;;
        --no-pull) NO_PULL=1 ;;
        --check) CHECK_ONLY=1 ;;
        --skip-verify) SKIP_VERIFY=1 ;;
        --skip-packages) SKIP_PACKAGES=1 ;;
        --skip-python) SKIP_PYTHON=1 ;;
        --agent-root)
            if [ $# -lt 2 ] || [ -z "$2" ] || [[ "$2" == --* ]]; then
                echo '--agent-root 需要路径参数' >&2; exit 2
            fi
            shift; AGENT_ROOT_ARG="$1" ;;
        -h|--help) echo "用法: $0 [--agent-root PATH] [--dry-run] [--no-pull] [--skip-packages] [--skip-python] [--check] [--skip-verify]"; exit 0 ;;
        *) echo "未知参数: $1" >&2; exit 2 ;;
    esac
    shift
done
RESOLVE_ARGS=("$RUNTIME_BRIDGE" resolve)
[ -n "$AGENT_ROOT_ARG" ] && RESOLVE_ARGS+=(--agent-root "$AGENT_ROOT_ARG")
if ! RESOLVE_JSON="$($PY "${RESOLVE_ARGS[@]}")"; then echo "❌ Agent root 无效" >&2; exit 1; fi
AGENT_DIR="$($PY -c 'import json,sys; print(json.loads(sys.argv[1])["agent_root"])' "$RESOLVE_JSON")" || exit 1
MCP_JSON="$AGENT_DIR/mcp.json"
export PI_CODING_AGENT_DIR="$AGENT_DIR"

step()  { printf '\n%b>>> %s%b\n' "$CYAN" "$1" "$RESET"; }
ok()    { printf '    %b[OK]%b %s\n' "$GREEN" "$RESET" "$1"; }
warn()  { printf '    %b[!!]%b %s\n' "$YELLOW" "$RESET" "$1"; WARNINGS+=("$1"); }
info()  { printf '    %b[..]%b %s\n' "$GRAY" "$RESET" "$1"; }
fail()  { printf '    %b[FAIL]%b %s\n' "$RED" "$RESET" "$1"; }

restore_update_stash() {
    [ "$STASHED" = 1 ] || return 0
    if [ -z "$STASH_SHA" ]; then
        fail '自动 stash 已创建，但无法确认其提交号；未恢复任何本地改动'
        return 1
    fi
    POP_REF=""
    STASH_INDEX=0
    while IFS= read -r listed_sha; do
        if [ "$listed_sha" = "$STASH_SHA" ]; then POP_REF="stash@{$STASH_INDEX}"; break; fi
        STASH_INDEX=$((STASH_INDEX + 1))
    done < <(git -C "$ROOT" stash list --format='%H' 2>/dev/null)
    if [ -z "$POP_REF" ]; then
        fail "自动 stash ${STASH_SHA:0:12} 已不在 stash 列表；未继续更新"
        return 1
    fi
    if git -C "$ROOT" stash pop "$POP_REF" 2>&1 | sed 's/^/    /'; then
        STASHED=0
        STASH_SHA=""
        ok '拉取前暂存的本地改动已自动恢复'
        return 0
    fi
    fail "本地改动恢复失败；stash ${STASH_SHA:0:12} 已明确保留"
    info "请在干净工作区手动恢复: git -C \"$ROOT\" stash apply $STASH_SHA"
    return 1
}

get_version() {
    if [ -f "$VERSION_FILE" ]; then
        tr -d '[:space:]' < "$VERSION_FILE"
    else
        echo "unknown"
    fi
}

# 用 python3 安全解析 mcp.json 的服务名（不存在则输出空）
mcp_keys() {
    [ -f "$MCP_JSON" ] || return 0
    "$PY" - "$MCP_JSON" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8-sig") as handle:
        d = json.load(handle)
    if not isinstance(d, dict) or not isinstance(d.get("mcpServers", {}), dict):
        raise ValueError("mcpServers must be an object")
    print("\n".join(d.get("mcpServers", {})))
except (OSError, ValueError):
    print("mcp.json 无效或不可读，原件保留", file=sys.stderr)
    sys.exit(1)
PY
}

protected_fingerprints() {
    "$PY" - "$AGENT_DIR" <<'PY'
import hashlib, json, sys
from pathlib import Path
try:
    root = Path(sys.argv[1])
    fingerprints = {}
    for name in ("models.json", "auth.json", "lab-mode.flag"):
        path = root / name
        fingerprints[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
    print(json.dumps(fingerprints, sort_keys=True))
except OSError:
    print("无法读取受保护用户文件，停止完整性校验", file=sys.stderr)
    sys.exit(1)
PY
}

detect_proxy() {
    for p in 10808 7897 7890; do
        if command -v ss >/dev/null 2>&1; then
            ss -ltn 2>/dev/null | grep -q ":$p " && { echo "$p"; return; }
        elif command -v netstat >/dev/null 2>&1; then
            netstat -ltn 2>/dev/null | grep -q ":$p " && { echo "$p"; return; }
        elif command -v lsof >/dev/null 2>&1; then
            lsof -nP -iTCP:"$p" -sTCP:LISTEN >/dev/null 2>&1 && { echo "$p"; return; }
        fi
    done
}

echo -e "${CYAN}================================================================================${RESET}"
echo -e "${CYAN}          Seep Reverse Lab — 已有用户一键更新 (Updater)${RESET}"
echo -e "${CYAN}================================================================================${RESET}"
echo -e "  工作台根目录: $ROOT"

OLD_VERSION="$(get_version)"

if [ $CHECK_ONLY -eq 1 ]; then
    echo -e "\n${CYAN}>>> 正在检查远程最新版本...${RESET}"
    PROXY_PORT="$(detect_proxy || true)"
    GIT_PROXY=()
    [ -n "$PROXY_PORT" ] && GIT_PROXY=("-c" "http.proxy=http://127.0.0.1:$PROXY_PORT" "-c" "https.proxy=http://127.0.0.1:$PROXY_PORT")

    if [ -e "$ROOT/.git" ]; then
        REMOTE_LINE="$(git -C "$ROOT" "${GIT_PROXY[@]}" ls-remote origin refs/heads/main 2>/dev/null || true)"
        LOCAL_SHA="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || true)"
        if [ -n "$REMOTE_LINE" ] && [ -n "$LOCAL_SHA" ]; then
            REMOTE_SHA="$(echo "$REMOTE_LINE" | awk '{print $1}')"
            if [ "$REMOTE_SHA" = "$LOCAL_SHA" ]; then
                echo -e "  ${GREEN}[OK]${RESET} 当前工作台已是最新版本 (v$OLD_VERSION, commit ${LOCAL_SHA:0:7})"
                exit 0
            else
                echo -e "  ${YELLOW}[UPDATE]${RESET} 检测到远程仓库有新版本/新提交！(本地: ${LOCAL_SHA:0:7}, 远程: ${REMOTE_SHA:0:7})"
                echo -e "  提示: 执行 ./setup/update.sh 即可一键更新。"
                exit 2
            fi
        fi
    fi

    # 通过 curl 探测 VERSION
    CURL_PROXY=()
    [ -n "$PROXY_PORT" ] && CURL_PROXY=("-x" "http://127.0.0.1:$PROXY_PORT")
    R_VER="$(curl -fsSL "${CURL_PROXY[@]}" --max-time 5 "$(raw_version_url "$REPO_URL")" 2>/dev/null | tr -d '[:space:]' || true)"
    if [ -z "$R_VER" ]; then info "无法确认远程版本，当前版本为 v$OLD_VERSION"; exit 1; fi
    if [ -n "$R_VER" ] && [ "$R_VER" != "$OLD_VERSION" ]; then
        echo -e "  ${YELLOW}[UPDATE]${RESET} 检测到新版本 v$R_VER 发布！(当前本地版本: v$OLD_VERSION)"
        echo -e "  提示: 执行 ./setup/update.sh 即可一键更新。"
        exit 2
    else
        echo -e "  ${GREEN}[OK]${RESET} 当前工作台已是最新版本 (v$OLD_VERSION)"
        exit 0
    fi
fi
IS_GIT=0; [ -e "$ROOT/.git" ] && IS_GIT=1

echo -e "  当前版本    : v$OLD_VERSION"
echo -e "  Git 仓库    : $([ "$IS_GIT" = 1 ] && echo '是（支持 git pull）' || echo '否（压缩包部署）')"
echo -e "  运行模式    : $([ "$DRY_RUN" = 1 ] && echo 'DRY RUN（不修改任何文件）' || echo '正常更新')"

BEFORE_KEYS="$(mcp_keys)" || { fail "无法读取现有 MCP 配置，停止更新"; exit 1; }
BEFORE_PROTECTED="$(protected_fingerprints)" || exit 1
info "更新前 mcp.json 中的 MCP 服务: $(if [ -n "$BEFORE_KEYS" ]; then echo "$BEFORE_KEYS" | tr '\n' ' '; else echo '（无）'; fi)"
info "受保护的用户自有数据: models.json, auth.json, lab-mode.flag"

if [ "$DRY_RUN" = 1 ]; then
    echo -e "\n  ${YELLOW}[DRY RUN] 将要执行的步骤：${RESET}"
    echo -e "    1. $([ "$NO_PULL" = 1 ] && echo '跳过 git pull（--no-pull）' || echo '自动探测代理并 git pull 拉取最新代码')"
    echo -e "    2. 打印 CHANGELOG 版本变更说明"
    echo -e "    3. 调用 setup/install.sh 做幂等增量同步（自动备份 + 保护自定义 MCP）"
    echo -e "    4. 校验用户自有数据未被覆盖"
    echo -e "    5. 跑 Tool/scripts/check.py 官方基准自检"
    echo -e "\n  未修改任何文件。去掉 --dry-run 即执行真实更新。\n"
    exit 0
fi

# ------------------------------------------------------------------ 1. 拉取
step "1/6  拉取最新代码"

if [ "$NO_PULL" = 1 ]; then
    info "已指定 --no-pull，跳过 git pull"
elif [ "$IS_GIT" != 1 ]; then
    fail "当前目录是压缩包部署，尚未拉取新代码，更新已停止。"
    info "请先下载新版本并合并到当前目录，再用相同 AgentRoot 加 --no-pull 同步；也可另行 git clone 后安装。"
    exit 1
else
    command -v git >/dev/null 2>&1 || { fail "未找到 Git，无法拉取新代码"; exit 1; }
    PROXY_PORT="$(detect_proxy)"
    PROXY_ARGS=()
    if [ -n "$PROXY_PORT" ]; then
        info "检测到可用代理端口: $PROXY_PORT"
        PROXY_ARGS=(-c "http.proxy=http://127.0.0.1:$PROXY_PORT" -c "https.proxy=http://127.0.0.1:$PROXY_PORT")
    else
        info "未检测到常见代理端口，尝试直连"
    fi

    cd "$ROOT" || exit 1
    DIRTY="$(git status --porcelain 2>/dev/null)" || { fail "无法检查 Git 工作区状态，停止更新"; exit 1; }
    if [ -n "$DIRTY" ]; then
        warn "工作区存在本地改动，将先 stash 再拉取"
        if git stash push -u -m "seep-update-autostash-$(date +%Y%m%d-%H%M%S)" >/dev/null 2>&1; then
            STASHED=1
            STASH_SHA="$(git rev-parse --verify refs/stash 2>/dev/null)" || {
                if git stash pop 'stash@{0}' 2>&1 | sed 's/^/    /'; then
                    STASHED=0
                    STASH_SHA=""
                    fail 'stash 提交号记录失败；本地改动已恢复，更新已取消'
                else
                    fail 'stash 提交号记录失败且自动恢复失败；stash@{0} 已保留'
                fi
                exit 1
            }
        else fail "本地改动保存失败，尚未拉取代码"; exit 1; fi
    fi

    if git "${PROXY_ARGS[@]}" pull --rebase origin main 2>&1 | sed 's/^/    /'; then
        PULL_RC=0
    else
        PULL_RC=1
    fi
    restore_update_stash || exit 1
    if [ "$PULL_RC" -eq 0 ]; then
        ok "代码已更新到最新版本"
    else
        fail "git pull 失败（可能是网络或代理问题）"
        info "可尝试：git -c http.proxy=http://127.0.0.1:<你的端口> pull --rebase origin main"
        info "或使用 --no-pull：先手动下载最新压缩包覆盖，再运行 update.sh --no-pull"
        exit 1
    fi
fi

# ------------------------------------------------------------------ 2. 版本
step "2/6  版本变更说明"

NEW_VERSION="$(get_version)"
if [ "$OLD_VERSION" = "$NEW_VERSION" ]; then
    info "版本未变化（v$NEW_VERSION）—— 将执行一次幂等重同步（补齐可能缺失的组件）"
else
    ok "版本已更新: v$OLD_VERSION  ->  v$NEW_VERSION"
fi

if [ -f "$CHANGELOG_FILE" ]; then
    echo -e "\n  ${YELLOW}---------- 本次版本变更摘要 ----------${RESET}"
    awk '/^##[[:space:]]*\[/{n++; if(n==2) exit} n>=1{print "  " $0}' "$CHANGELOG_FILE" | head -60
    echo -e "  ${YELLOW}--------------------------------------${RESET}\n"
fi

# ------------------------------------------------------------------ 3. 同步
step "3/6  执行幂等增量同步（自动备份 + 保护自定义配置）"
INSTALL_FAILED=0
INSTALL_ARGS=(--agent-root "$AGENT_DIR")
[ "$SKIP_PACKAGES" = 1 ] && INSTALL_ARGS+=(--skip-packages)
[ "$SKIP_PYTHON" = 1 ] && INSTALL_ARGS+=(--skip-python)
if bash "$SCRIPT_DIR/install.sh" "${INSTALL_ARGS[@]}"; then
    ok "增量同步完成"
else
    warn "install.sh 返回非零，部分步骤可能未完成，请查看上方输出"
    INSTALL_FAILED=1
fi

# ------------------------------------------------------------------ 4. 校验
step "4/6  用户自有数据零丢失校验"

AFTER_KEYS="$(mcp_keys)" || { fail "更新后的 MCP 配置无效"; INSTALL_FAILED=1; }
LOST=""
if [ -n "$BEFORE_KEYS" ]; then
    while IFS= read -r k; do
        [ -z "$k" ] && continue
        echo "$AFTER_KEYS" | grep -Fqx -- "$k" || LOST="$LOST $k"
    done <<< "$BEFORE_KEYS"
fi

if [ -n "$LOST" ]; then
    INSTALL_FAILED=1
    fail "检测到自定义 MCP 服务丢失:$LOST"
    info "请从备份目录恢复：$AGENT_DIR/backup-*/mcp.json"
else
    ok "mcp.json 中的 MCP 服务全部保留（共 $(if [ -n "$AFTER_KEYS" ]; then echo "$AFTER_KEYS" | wc -l | tr -d ' '; else echo 0; fi) 个）"
fi

if AFTER_PROTECTED="$(protected_fingerprints)" && [ "$BEFORE_PROTECTED" = "$AFTER_PROTECTED" ]; then
    ok "models.json、auth.json、lab-mode.flag 的内容与存在状态均未变化"
else
    fail "受保护用户文件的内容或存在状态发生变化，或无法完成校验"
    INSTALL_FAILED=1
fi

# ------------------------------------------------------------------ 5. 自检
if [ "$SKIP_VERIFY" = 0 ]; then
    step "5/6  官方基准自检"
    if (cd "$ROOT" && "$PY" Tool/scripts/check.py --env); then
        ok "自检全部通过"
    else
        warn "自检存在未通过项，请查看上方红色标记"
        INSTALL_FAILED=1
    fi
else
    step "5/6  官方基准自检（已跳过 --skip-verify）"
fi

# ------------------------------------------------------------------ 6. 报告
step "6/6  更新完成报告"

echo -e "\n${WHITE}================================================================================${RESET}"
if [ "$INSTALL_FAILED" = 1 ]; then
    echo -e "  ${YELLOW}Seep 工作台更新未完成，请处理上方失败后重试${RESET}"
else
    echo -e "  ${GREEN}Seep 工作台更新完成:  v$OLD_VERSION  ->  v$NEW_VERSION${RESET}"
fi
echo -e "${WHITE}================================================================================${RESET}"

cat <<EOF

  同步范围与结果见上方逐项输出；出现失败时请先处理失败项。

  下一步:
    1) 以相同 AgentRoot 重开 Pi 会话，确认技能、扩展与 MCP 实际加载。
    2) 直接说明任务和材料；lab：是可选交互。其他宿主需单独验证。

  如需回滚:
    · 配置备份位于: $AGENT_DIR/backup-<时间戳>/
    · 代码版本:     git -C "$ROOT" log --oneline -10；先保留本地修改再选择恢复版本。

EOF

if [ "$INSTALL_FAILED" = 1 ]; then exit 1; fi
exit 0
