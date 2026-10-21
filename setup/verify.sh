#!/usr/bin/env bash
# ==============================================================================
# Seep Reverse Lab — Linux / macOS 原生全彩自检与部署核验脚本 (Verifier)
# 对应 Windows check.ps1 / verify.ps1，输出结构化 ANSI 彩色报告
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOL_DIR="$ROOT/Tool"
SAFE_DIR="$TOOL_DIR/mcp/Tool/safe"
KB_DIR="$TOOL_DIR/mcp/Tool/reverselab/kb"
AGENT_DIR="$HOME/.pi/agent"
MANUAL_DIR="$ROOT/MANUAL"

GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
WHITE="\033[1;37m"
RESET="\033[0m"

OK_COUNT=0
FAIL_COUNT=0
OPTN_COUNT=0

check_item() {
    local cat="$1"
    local name="$2"
    shift 2
    if "$@"; then
        echo -e "  [${GREEN}√ PASS${RESET}] $name"
        ((OK_COUNT++))
    else
        echo -e "  [${RED}X FAIL${RESET}] $name"
        ((FAIL_COUNT++))
    fi
}

check_optn() {
    local cat="$1"
    local name="$2"
    local note="$3"
    shift 3
    if "$@"; then
        echo -e "  [${GREEN}√ PASS${RESET}] $name"
        ((OK_COUNT++))
    else
        echo -e "  [${YELLOW}! OPTN${RESET}] $name ($note)"
        ((OPTN_COUNT++))
    fi
}

echo -e "${CYAN}================================================================================${RESET}"
echo -e "${CYAN}          Seep Reverse Lab — Linux/macOS 部署完备性体检 (Verifier)             ${RESET}"
echo -e "${CYAN}================================================================================${RESET}"
echo -e "  工作台物理根目录: $ROOT"
echo -e "  宿主操作系统内核: $(uname -s) $(uname -r) ($(uname -m))"
echo -e "  基准核验清单规范: MANUAL/DEPLOYMENT-CHECKLIST.md"

# 探测 Python 命令（优先 python3，其次 python；且要求能真正执行——
# 避开 Windows Store 的 python3 占位程序：它存在但不运行、返回非零，会把自检误判为失败）
if command -v python3 &>/dev/null && python3 -c "print(1)" &>/dev/null; then
    PY_BIN="python3"
elif command -v python &>/dev/null && python -c "print(1)" &>/dev/null; then
    PY_BIN="python"
else
    PY_BIN=""
fi

test_python_syntax() {
    [ -n "$PY_BIN" ] && (cd "$ROOT" && "$PY_BIN" -c "import ast; ast.parse(open('Tool/mcp/seep_mcp_server.py', encoding='utf-8').read())")
}

test_ext_assets() {
    local sp="$TOOL_DIR/mcp/seep_mcp_server.py"
    local et="$TOOL_DIR/config/engine-tiers.json"
    local ed="$TOOL_DIR/docs/EXT-ASSETS.md"
    local mp="$TOOL_DIR/docs/MERGE-PLAYBOOK.md"
    [ -f "$sp" ] && [ -f "$et" ] && [ -f "$ed" ] && [ -f "$mp" ] && \
        grep -q 'def seep_ensure_tool' "$sp" && grep -q 'def seep_packer_detect' "$sp" && \
        grep -q 'def seep_http_replay' "$sp" && grep -q 'def seep_web_recon' "$sp"
}

test_tool_autodiscover() {
    local ta="$TOOL_DIR/mcp/tool_autodiscover.py"
    local tc="$TOOL_DIR/config/tool-capabilities.json"
    [ -f "$ta" ] && [ -f "$tc" ] && \
        grep -q 'def discover' "$ta" && grep -q 'def plan_control' "$ta" && \
        grep -q 'def register_mcp' "$ta" && grep -q 'def research_control' "$ta" && \
        grep -q '"tools"' "$tc" && \
        grep -q 'tools.local.json' "$ROOT/.gitignore"
}

test_ext_assets_coverage() {
    local tst="$TOOL_DIR/mcp/test_ext_assets.py"
    [ -f "$tst" ] || return 1
    grep -q 'tool_autodiscover' "$tst" && grep -q 'plan_control' "$tst" && grep -q 'register_mcp' "$tst"
}

test_python_mcp() {
    [ -n "$PY_BIN" ] && "$PY_BIN" -c "import mcp" 2>/dev/null
}

test_python_avail() {
    [ -n "$PY_BIN" ]
}
echo -e "\n${WHITE}[1/9] 📁 核心架构与工程目录树${RESET}"
check_item "架构" "工作台主目录完整 (Tool/)" test -d "$TOOL_DIR"
check_item "架构" "技能包目录完整 (Tool/skill/)" test -d "$TOOL_DIR/skill"
check_item "架构" "MCP服务引擎目录 (Tool/mcp/)" test -d "$TOOL_DIR/mcp"
check_item "架构" "系统提示词层 (Tool/prompts/)" test -d "$TOOL_DIR/prompts"
test_cases_count() {
    [ -d "$TOOL_DIR/cases" ] || return 1
    local n
    n=$(find "$TOOL_DIR/cases" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
    [ "$n" -ge 14 ]
}
check_item "架构" "十四大脱敏案例工程 (Tool/cases/ ≥14 个工程)" test_cases_count
check_item "架构" "上游开源验证集 (Tool/upstream/ 3大开源项目)" test -d "$TOOL_DIR/upstream/apk-reverse" -a -d "$TOOL_DIR/upstream/open-tgtylab" -a -d "$TOOL_DIR/upstream/open-reverselab"
check_item "架构" "MCP专用运行时强约定 (Tool/mcp/Tool/)" test -d "$TOOL_DIR/mcp/Tool"

# 1b. 版本与更新链路
check_item "版本" "版本标识与变更日志 (VERSION + CHANGELOG.md)" test -f "$ROOT/VERSION" -a -f "$ROOT/CHANGELOG.md"
check_item "版本" "已有用户一键更新脚本 (update.ps1 + update.sh)" test -f "$ROOT/setup/update.ps1" -a -f "$ROOT/setup/update.sh"
check_item "架构" "上游定点防外溢规则与同步引擎 (upstream-rules.json + sync-upstream.py)" test -f "$ROOT/setup/upstream-rules.json" -a -f "$ROOT/setup/sync-upstream.py" -a -f "$ROOT/setup/sync-upstream.sh" -a -f "$ROOT/update.bat"
# 任务路由自洽性：routing.json 里的每个 route.skill 必须真实存在，
# 且 priority / fallbackId 与 routes 一一对应。
test_routing_coherence() {
    local chk="$TOOL_DIR/scripts/verify-routing-coherence.py"
    [ -f "$chk" ] || return 1
    [ -n "$PY_BIN" ] || return 0
    ( cd "$ROOT" && "$PY_BIN" "$chk" >/dev/null 2>&1 )
}
check_item "路由" "任务路由表自洽 (routing.json ↔ 技能落位)" test_routing_coherence
check_item "版本" "一键卸载脚本 (uninstall.ps1 + uninstall.sh)" test -f "$ROOT/setup/uninstall.ps1" -a -f "$ROOT/setup/uninstall.sh"

# 2. 知识库
echo -e "\n${WHITE}[2/9] 📚 攻防实战知识库与战术模板 (KB)${RESET}"
test_kb_count() {
    [ -d "$KB_DIR" ] || return 1
    local n
    n=$(find "$KB_DIR" -name '*.md' | wc -l | tr -d ' ')
    [ "$n" -ge 280 ]
}
check_item "知识库" "战术实战笔记 (292 篇完整检索库 ≥280 篇)" test_kb_count
check_item "知识库" "内置 MCP 源码组件 (ReverseLab/Ghidra/JSHook)" test -d "$TOOL_DIR/mcp/Tool/reverselab/tools/skills/mcp"


# 提示词契约态断言（与 verify.ps1 的「SEEP.md 契约态 / 三件套就绪」等价）
check_seep_contract() {
    local p="$TOOL_DIR/prompts/SEEP.md"
    [ -f "$p" ] || return 1
    local len
    len=$("$PY_BIN" -c "import sys;print(len(open(sys.argv[1],encoding='utf-8').read()))" "$p" 2>/dev/null || wc -m < "$p")
    [ "${len:-99999}" -le 2500 ] || return 1
    grep -q "AGENTS.md" "$p" || return 1
    grep -q "routing.json" "$p" || return 1
    grep -q "seep_status" "$p" || return 1
    if grep -qE "[0-9]+[[:space:]]*个工具" "$p"; then return 1; fi
    return 0
}

check_prompt_stack() {
    [ ! -f "$TOOL_DIR/prompts/SYSTEM.md" ] || return 1
    grep -q "BOUNDARY_ANCHOR" "$TOOL_DIR/prompts/extensions/load-system-prompt.ts" || return 1
    grep -q "seep-boundary" "$TOOL_DIR/prompts/extensions/load-system-prompt.ts" || return 1
    grep -q "appendBoundaryTail" "$TOOL_DIR/prompts/extensions/security-audit-interceptor.ts" || return 1
    grep -q "looksLikePersonaCard" "$TOOL_DIR/prompts/extensions/security-audit-interceptor.ts" || return 1
    [ -f "$TOOL_DIR/prompts/extensions/cmd-guard.ts" ] || return 1
    [ -f "$TOOL_DIR/prompts/extensions/cmd-guard.rules.json" ] || return 1
    [ -f "$TOOL_DIR/prompts/extensions/TOOL-CHAIN.md" ] || return 1
    [ -f "$TOOL_DIR/prompts/extensions/retry-level.ts" ] || return 1
    [ -f "$TOOL_DIR/config/tool-runtimes.json" ] || return 1
    [ -f "$TOOL_DIR/scripts/tool-run.ps1" ] || return 1
    [ -f "$TOOL_DIR/prompts/tasks/reverse.md" ] || return 1
    [ -f "$TOOL_DIR/prompts/tasks/reverse-deliverable.md" ] || return 1
    [ -d "$TOOL_DIR/mcp/kb_local" ] || return 1
    grep -q "kb_local" "$TOOL_DIR/mcp/seep_mcp_server.py" || return 1
    return 0
}

# 3. 提示词
echo -e "\n${WHITE}[3/9] 🧠 智能体指令系统与运行时拦截扩展 (Prompts & Extensions)${RESET}"
check_item "提示词" "Pi Agent 系统指令 (SEEP.md 契约态)" check_seep_contract
check_item "提示词" "提示词槽位 / 边界锚 / 人格守卫三者就绪" check_prompt_stack
check_item "提示词" "通用跨 Agent 规范 (AGENTS.md)" test -f "$TOOL_DIR/prompts/AGENTS.md"
check_item "提示词" "Claude Code 项目级规范 (CLAUDE.md 在项目根)" test -f "$ROOT/CLAUDE.md"
check_item "提示词" "DeepSeek Harness 配置文件 (DSH-PROFILE.md)" test -f "$ROOT/DSH-PROFILE.md"
check_item "扩展"   "底层安全放行与 Lab 状态机扩展 (.ts)" test -f "$TOOL_DIR/prompts/extensions/security-audit-interceptor.ts"

# 4. 技能系统
echo -e "\n${WHITE}[4/9] 🛠️ 逆向工程专业技能库 (Skills - 全量，含 00–04 阶段技能)${RESET}"
test_softseep_refs() {
    [ -f "$TOOL_DIR/skill/softseep/SKILL.md" ] || return 1
    local n
    n=$(find "$TOOL_DIR/skill/softseep/references" -name '*.md' 2>/dev/null | wc -l | tr -d ' ')
    [ "$n" -ge 8 ] || return 1
    # ★ 与 verify.ps1 同步：五阶段技能（00–04）必须齐全（缺一个，换机器就少一环）
    local k
    for k in 00-analysis 01-gate-bypass 02-ui-rebrand 03-license-hookup 04-version-migrate 05-backend-rebuild; do
        [ -f "$TOOL_DIR/skill/$k/SKILL.md" ] || return 1
    done
    # 脱壳闭环是 01 的上游依赖，缺了 01 的 A–D 路线就断
    [ -f "$TOOL_DIR/skill/unpack-loop/SKILL.md" ]
}
check_item "Skill" "核心总控调度器 (softseep 包含 8 大专题库)" test_softseep_refs
test_apkseep_layout() {
    [ -f "$TOOL_DIR/skill/apkseep/SKILL.md" ] || return 1
    [ -d "$TOOL_DIR/skill/apkseep/references" ] || return 1
    [ -d "$TOOL_DIR/skill/apkseep/scripts" ] || return 1
}
check_item "Skill" "移动端逆向全链路 (apkseep 包含 45 篇规范与 56 脚本)" test_apkseep_layout
test_ida_reverse_contract() {
    local f="$TOOL_DIR/skill/ida-reverse/SKILL.md"
    [ -f "$f" ] || return 1
    grep -q '13337' "$f"
}
check_item "Skill" "IDA Pro 自动化联动 (ida-reverse 含 13337 唤醒规约)" test_ida_reverse_contract
check_item "Skill" "通用许可/卡密校验突破规范 (license-bypass)" test -f "$TOOL_DIR/skill/client-license-validation-bypass/SKILL.md"
check_item "Skill" "增量追版与特征迁移技能 (version-migration)" test -f "$TOOL_DIR/skill/version-migration/SKILL.md"
test_safe_skills_count() {
    [ -d "$TOOL_DIR/skill/safe-skills" ] || return 1
    local n
    n=$(find "$TOOL_DIR/skill/safe-skills" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
    [ "$n" -ge 5 ]
}
check_item "Skill" "独立战术安全技能包 (safe-skills 5组)" test_safe_skills_count

# SKILL.md 带 UTF-8 BOM 时，frontmatter 解析器无法识别首行 `---`，技能会被静默跳过（Issue #6）
test_skill_no_bom() {
    local f first3
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        first3=$(head -c 3 "$f" 2>/dev/null | od -An -tx1 | tr -d ' \n')
        [ "$first3" = "efbbbf" ] && return 1
    done < <(find "$TOOL_DIR/skill" -name 'SKILL.md' 2>/dev/null)
    return 0
}
check_item "Skill" "技能 SKILL.md 无 UTF-8 BOM（否则被 Agent 静默跳过）" test_skill_no_bom

if [ -d "$AGENT_DIR" ]; then
    check_optn "部署" "Pi Agent 本地技能同步 (~/.pi/agent/skills/softseep)" "可运行 ./setup/install.sh 同步" test -f "$AGENT_DIR/skills/softseep/SKILL.md"
fi

# 5. MCP 自动化服务层与底层工具
echo -e "\n${WHITE}[5/9] 🔌 MCP 服务引擎与物理内置工具箱 (Native Tools)${RESET}"
check_item "MCP" "核心服务端脚本 (seep_mcp_server.py 语法自洽)" test_python_syntax
check_item "MCP" "扩展资产：8 个新工具 + 引擎链 + 文档 (含 protocol/resource/packer)" test_ext_assets
check_item "MCP" "工具自动发现插件 (tool_autodiscover.py + 能力表 + 状态隔离)" test_tool_autodiscover

# 功能自测：真正跑一遍扩展资产测试（不是只看文件在不在）
test_ext_assets_suite() {
    local tst="$TOOL_DIR/mcp/test_ext_assets.py"
    [ -n "$PY_BIN" ] || return 1
    [ -f "$tst" ] || return 1
    ( cd "$TOOL_DIR/mcp" && "$PY_BIN" test_ext_assets.py >/dev/null 2>&1 )
}
check_item "MCP" "扩展资产功能自测 (test_ext_assets.py 全项实跑)" test_ext_assets_suite

check_item "MCP" "工具自动发现功能自测已覆盖 (test_ext_assets.py 含自动发现用例)" test_ext_assets_coverage
check_item "工具箱" "Jadx 反编译引擎 (jadx-1.5.6 完整就绪)" test -f "$SAFE_DIR/jadx/lib/jadx-1.5.6-all.jar"
test_radare2() {
    command -v radare2 &>/dev/null || test -f "$SAFE_DIR/radare2/bin/radare2.exe"
}
check_item "工具箱" "Radare2 二进制套件 (跨平台探测系统/内置 r2)" test_radare2
check_item "工具箱" "Apktool 资源拆解重构环境 (apktool.jar)" test -f "$SAFE_DIR/apktool/apktool.jar"
check_item "工具箱" "Frida/LSPosed 动态插桩模板库 (hook-mcp)" test -d "$SAFE_DIR/hook-mcp/templates"
check_item "依赖" "Web/JS 逆向调试引擎依赖已解压 (js-reverse-mcp/node_modules)" test -d "$SAFE_DIR/js-reverse-mcp/node_modules" -o -f "$SAFE_DIR/js-reverse-mcp/node_modules.zip"
check_item "依赖" "Playwright 浏览器自动化依赖已解压 (playwright-mcp/node_modules)" test -d "$SAFE_DIR/playwright-mcp/node_modules" -o -f "$SAFE_DIR/playwright-mcp/node_modules.zip"

# 6. 环境运行时
echo -e "\n${WHITE}[6/9] ⚙️ 外部运行时与商业授权协同 (Runtime & Commercial)${RESET}"
check_item "运行时" "Python 解释器 (python3/python 且可执行)" test_python_avail
check_optn "协议" "Python mcp 协议库支持 (mcp>=1.20,<1.29)" "运行 pip install 'mcp>=1.20,<1.29'" test_python_mcp
test_ida_avail() {
    # 与 verify.ps1 同口径：IDA_DIR → PATH(idat/ida64/ida) → tool-run 的八层发现
    local n
    if [ -n "$IDA_DIR" ] && [ -d "$IDA_DIR" ]; then
        for n in idat.exe idat ida64.exe ida64 ida.exe ida; do
            [ -f "$IDA_DIR/$n" ] && return 0
        done
    fi
    for n in idat idat.exe ida64 ida64.exe ida ida.exe; do
        command -v "$n" >/dev/null 2>&1 && return 0
    done
    # 与 ps1 的 tool-run 发现对齐：八层探测（含常见目录/注册表/开始菜单）
    if command -v python >/dev/null 2>&1; then
        local pypath="$TOOL_DIR/mcp"
        # git-bash/MSYS 下 $TOOL_DIR 是 POSIX 路径（/d/...），Windows 版 python 读不了 → 转成原生路径
        command -v cygpath >/dev/null 2>&1 && pypath=$(cygpath -w "$pypath" 2>/dev/null || echo "$pypath")
        python -c "import sys;sys.path.insert(0,r'$pypath');import tool_autodiscover as A;sys.exit(0 if A.discover('ida',use_registry=False).get('available') else 1)" >/dev/null 2>&1 && return 0
    fi
    return 1
}
check_optn "商业软件" "IDA Pro 商业反编译器协同 (可选)" "无授权不影响核心链路，系统自动使用 Radare2 降级" test_ida_avail
check_optn "配置" "Claude Code 项目级 MCP 注册 (.mcp.json 在根目录)" "直接在根目录启动 claude 即可" test -f "$ROOT/.mcp.json"

# 跨平台安装链自校验：mcp.json 里 seep 的启动脚本必须真实存在。
# 血案：旧版用 sed 替换模板会生成反斜杠路径（/home/x/Seep\Tool\...），
# 文件不存在 → 核心 MCP 静默起不来，而"文件存在性"检查完全抓不到。
test_agent_mcp_seep_path() {
    local m="$AGENT_DIR/mcp.json"
    [ -f "$m" ] || return 0          # 未部署 Pi 时不判失败
    [ -n "$PY_BIN" ] || return 0
    "$PY_BIN" - "$m" "$ROOT" <<'PYEOF'
import json, os, sys, io
m, root = sys.argv[1], sys.argv[2]
try:
    d = json.loads(io.open(m, encoding="utf-8-sig").read())
    arg0 = (d.get("mcpServers") or {}).get("seep", {}).get("args", [None])[0]
except Exception:
    sys.exit(1)
if not arg0:
    sys.exit(1)
p = arg0 if os.path.isabs(arg0) else os.path.join(root, arg0)
sys.exit(0 if os.path.isfile(p) else 1)
PYEOF
}
check_item "配置" "Pi Agent mcp.json 的 seep 启动路径可解析（跨平台安装链自检）" test_agent_mcp_seep_path

# 7. 战术手册
echo -e "\n${WHITE}[7/9] 📚 MANUAL/ 战术手册完备性校验${RESET}"
check_item "手册" "零基础实战通关指南 (MANUAL/ZERO-TO-HERO-WORKFLOW.md)" test -f "$MANUAL_DIR/ZERO-TO-HERO-WORKFLOW.md"
check_item "手册" "外挂技能创作标准指南 (MANUAL/SKILL-CREATION-GUIDE.md)" test -f "$MANUAL_DIR/SKILL-CREATION-GUIDE.md"
check_item "手册" "环境预要求指南 (MANUAL/PREREQUISITES.md)" test -f "$MANUAL_DIR/PREREQUISITES.md"
check_item "手册" "IDA Pro 商业软件接入指南 (MANUAL/IDA-PRO.md)" test -f "$MANUAL_DIR/IDA-PRO.md"
check_item "手册" "反调试绕过战术手册 (MANUAL/ANTI-DEBUG.md)" test -f "$MANUAL_DIR/ANTI-DEBUG.md"
check_item "手册" "通用脱壳前置分析 SOP (MANUAL/UNPACKING.md)" test -f "$MANUAL_DIR/UNPACKING.md"
check_item "手册" "PoC 闭环自动化验证 SOP (MANUAL/POC-VALIDATION.md)" test -f "$MANUAL_DIR/POC-VALIDATION.md"
check_item "手册" "全景部署与多 Agent 集成指南 (MANUAL/DEPLOYMENT.md)" test -f "$MANUAL_DIR/DEPLOYMENT.md"
check_item "手册" "官方部署资产核验基准清单 (MANUAL/DEPLOYMENT-CHECKLIST.md)" test -f "$MANUAL_DIR/DEPLOYMENT-CHECKLIST.md"
check_item "手册" "跨平台运行与战术等价指南 (MANUAL/CROSS-PLATFORM.md)" test -f "$MANUAL_DIR/CROSS-PLATFORM.md"
check_item "手册" "合规转译中继与防拒体系 (MANUAL/COMPLIANCE-RELAY.md)" test -f "$MANUAL_DIR/COMPLIANCE-RELAY.md"

# 8. 合规转译中继
# 7bis. 运维脚本在位（审计 D1：新增脚本必须进两平台门禁）
test_case_state_smoke() {
    local cs="$TOOL_DIR/scripts/case_state.py"
    [ -f "$cs" ] || return 1
    local tmp
    tmp=$(mktemp -d 2>/dev/null || echo "/tmp/seep_case_$$")
    python "$cs" init --case "$tmp" >/dev/null 2>&1 || { rm -rf "$tmp"; return 1; }
    python "$cs" gate --case "$tmp" >/dev/null 2>&1
    local rc=$?
    rm -rf "$tmp"
    [ "$rc" -eq 1 ]
}
check_item "脚本" "案子闸可执行 (case_state.py init + gate)" test_case_state_smoke

test_migrate_smoke() {
    local mg="$TOOL_DIR/scripts/migrate.py"
    [ -f "$mg" ] || return 1
    python "$mg" --help 2>&1 | grep -q align
}
check_item "脚本" "追版引擎可执行 (migrate.py)" test_migrate_smoke

test_mcp_doctor_smoke() {
    local md="$TOOL_DIR/scripts/mcp-doctor.py"
    [ -f "$md" ] || return 1
    python "$md" --quick --json 2>&1 | head -c 200 | grep -q '"servers"'
}
check_item "脚本" "MCP 验连可执行 (mcp-doctor.py)" test_mcp_doctor_smoke

echo -e "\n${WHITE}[8/9] 🌐 合规转译中继与规则同步校验${RESET}"
RELAY_DIR="$TOOL_DIR/scripts/compliance-relay"

check_item "中继" "中继主程序 (relay.py 纯标准库实现)" test -f "$RELAY_DIR/relay.py"
check_item "中继" "规则提取器 (extract-rules.py)" test -f "$RELAY_DIR/extract-rules.py"
check_item "中继" "上下文守卫白名单 (guard-prefixes.json)" test -f "$RELAY_DIR/guard-prefixes.json"
check_item "中继" "中继单元测试套件 (tests/test_relay.py)" test -f "$RELAY_DIR/tests/test_relay.py"

test_relay_rules_sync() {
    [ -n "$PY_BIN" ] || return 1
    test -f "$RELAY_DIR/sensitive-rules.json" || return 1
    (cd "$RELAY_DIR" && "$PY_BIN" extract-rules.py --check >/dev/null 2>&1)
}
check_item "中继" "规则表与 TS 源同步 (sensitive-rules.json)" test_relay_rules_sync

# 9. 脱敏与隐私走查
echo -e "\n${WHITE}[9/9] 🔒 脱敏与个人隐私走查 (递归全深度扫描)${RESET}"

PRIVACY_RX='C:[\\/]{1,2}Users[\\/]{1,2}Angus|AngusDevLab|angusdevlab|angus\.vip@|angusdev\.top|\bAngus\b|C:[\\/]{1,2}Users[\\/]{1,2}toti|[A-Za-z]:[\\/]{1,2}Project[\\/]'

test_privacy_clean() {
    local hits files
    if [ -d "$ROOT/.git" ]; then
        # 只扫描将被发布的 git 跟踪文件（本地生成物已 gitignore，不属发布范围）
        files=$(git -C "$ROOT" ls-files 2>/dev/null \
            | grep -vE '^(setup/verify\.(ps1|sh))$' \
            | grep -vE '^Tool/(upstream|mcp/Tool)/' \
            | grep -vE '\.(exe|dll|so|dylib|jar|zip|7z|png|jpg|jpeg|gif|ico|pdf|bin|dmp|pyc|idb|i64|ttf|woff|woff2)$')
        [ -z "$files" ] && return 0
        hits=$(cd "$ROOT" && printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 grep -InE "$PRIVACY_RX" 2>/dev/null | head -3)
    else
        # 非 git 环境：回退到文件系统扫描
        hits=$(grep -rInE "$PRIVACY_RX" "$ROOT" \
            --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=__pycache__ \
            --exclude-dir=upstream --exclude-dir=dist \
            --exclude=verify.sh --exclude=verify.ps1 2>/dev/null \
            | grep -v "/Tool/mcp/Tool/" | head -3)
    fi
    [ -z "$hits" ]
}
check_item "脱敏" "个人隐私零残留 (已跟踪文件全深度扫描)" test_privacy_clean

test_generated_untracked() {
    [ -d "$ROOT/.git" ] || return 0
    local tracked f
    tracked=$(git -C "$ROOT" ls-files 2>/dev/null)
    for f in opencode.jsonc setup/cordis.generated.yml Tool/scripts/compliance-relay/relay-config.json; do
        if echo "$tracked" | grep -qx "$f"; then return 1; fi
    done
    return 0
}
check_item "脱敏" "含本机路径的生成物未被 git 追踪" test_generated_untracked

test_no_product_names() {
    ! grep -rIlE 'xyplorer|bandizip|boosterx|1218\.io' "$TOOL_DIR/cases" 2>/dev/null | grep -q .
}
check_optn "脱敏" "目标产品名残留统计 (功能性标识符可保留)" \
    "存在目标产品名（含 README 已声明的功能性必需标识符）；如为叙述性提及请脱敏" test_no_product_names

echo -e "\n${CYAN}================================================================================${RESET}"
echo -e "  [体检报告] 核心检查通过: ${GREEN}$OK_COUNT${RESET} 项 | 异常阻断: ${RED}$FAIL_COUNT${RESET} 项 | 关注项: ${YELLOW}$OPTN_COUNT${RESET} 项"
echo -e "${CYAN}================================================================================${RESET}"

if [ $FAIL_COUNT -eq 0 ]; then
    echo -e "\n  ${GREEN}🎉 结论: 工作台在当前 $(uname -s) 环境处于 [READY / 完备就绪] 状态！${RESET}"
    echo -e "  输入 ${CYAN}lab：${RESET} 即可开启白盒测试！\n"
    exit 0
else
    echo -e "\n  ${RED}❌ 结论: 存在未通过的核心检查项，请检查上述红色标记。${RESET}\n"
    exit 1
fi
