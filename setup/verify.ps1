#Requires -Version 5.1
<#
  Seep 逆向工程工作台 —— 部署完备性体检与校验仪表盘 (System Health & Integrity Verifier)
  支持独立运行、双击运行、或由 Agent 调用以验证工作台是否完整就绪。
  支持 -Detailed / -Audit 参数输出基于 MANUAL/DEPLOYMENT-CHECKLIST.md 的结构化双向校对看板。
#>
[CmdletBinding()]
param(
    [Alias("Audit")]
    [switch]$Detailed
)

# 强制 UTF-8 编码输出，杜绝控制台中文乱码
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$ToolDir   = Join-Path $Root 'Tool'
$ToolsDir  = Join-Path $Root 'Tool\mcp\Tool\safe'
$KbDir     = Join-Path $Root 'Tool\mcp\Tool\reverselab\kb'
$AgentDir  = Join-Path $env:USERPROFILE '.pi\agent'
$ManualDir = Join-Path $Root 'MANUAL'
$localSkills = Join-Path $ToolDir 'skill'

$script:OkCount = 0
$script:FailList = @()
$script:TodoList = @()

# 结构化校对明细表（供 Detailed 模式使用）
$script:AuditTable = [System.Collections.ArrayList]::new()

function Test-CheckItem {
    param(
        [string]$Category,
        [string]$ItemName,
        [scriptblock]$Predicate,
        [string]$Remedy,
        [string]$Expected = "存在且完整",
        [string]$TargetLocation = ""
    )
    $actualStr = ""
    try {
        $passed = & $Predicate
        if ($passed) {
            Write-Host ("  [√ PASS] {0}" -f $ItemName) -ForegroundColor Green
            $script:OkCount++
            $script:AuditTable.Add([PSCustomObject]@{
                Category = $Category
                Name = $ItemName
                Target = $TargetLocation
                Expected = $Expected
                Actual = "通过"
                Status = "🟢 READY"
                Note = "完备就绪"
            }) | Out-Null
        } else {
            Write-Host ("  [X FAIL] {0}" -f $ItemName) -ForegroundColor Red
            $script:FailList += @{ Category = $Category; Name = $ItemName; Fix = $Remedy }
            $script:AuditTable.Add([PSCustomObject]@{
                Category = $Category
                Name = $ItemName
                Target = $TargetLocation
                Expected = $Expected
                Actual = "缺失/异常"
                Status = "🔴 MISSING"
                Note = $Remedy
            }) | Out-Null
        }
    } catch {
        Write-Host ("  [X FAIL] {0} (异常: {1})" -f $ItemName, $_.Exception.Message) -ForegroundColor Red
        $script:FailList += @{ Category = $Category; Name = $ItemName; Fix = $Remedy }
        $script:AuditTable.Add([PSCustomObject]@{
            Category = $Category
            Name = $ItemName
            Target = $TargetLocation
            Expected = $Expected
            Actual = "异常: $($_.Exception.Message)"
            Status = "🔴 MISSING"
            Note = $Remedy
        }) | Out-Null
    }
}

function Test-ManualItem {
    param(
        [string]$Category,
        [string]$ItemName,
        [scriptblock]$Predicate,
        [string]$Guidance,
        [string]$Expected = "可选扩展",
        [string]$TargetLocation = ""
    )
    try {
        $passed = & $Predicate
        if ($passed) {
            Write-Host ("  [√ PASS] {0}" -f $ItemName) -ForegroundColor Green
            $script:OkCount++
            $script:AuditTable.Add([PSCustomObject]@{
                Category = $Category
                Name = $ItemName
                Target = $TargetLocation
                Expected = $Expected
                Actual = "已配置/已连接"
                Status = "🟢 READY"
                Note = "功能正常"
            }) | Out-Null
        } else {
            Write-Host ("  [! OPTN] {0} ({1})" -f $ItemName, $Guidance) -ForegroundColor Yellow
            $script:TodoList += @{ Category = $Category; Name = $ItemName; Note = $Guidance }
            $script:AuditTable.Add([PSCustomObject]@{
                Category = $Category
                Name = $ItemName
                Target = $TargetLocation
                Expected = $Expected
                Actual = "未配置 (自动降级)"
                Status = "🟡 DEGRADED"
                Note = $Guidance
            }) | Out-Null
        }
    } catch {
        Write-Host ("  [! OPTN] {0} ({1})" -f $ItemName, $Guidance) -ForegroundColor Yellow
        $script:TodoList += @{ Category = $Category; Name = $ItemName; Note = $Guidance }
        $script:AuditTable.Add([PSCustomObject]@{
            Category = $Category
            Name = $ItemName
            Target = $TargetLocation
            Expected = $Expected
            Actual = "未配置 (自动降级)"
            Status = "🟡 DEGRADED"
            Note = $Guidance
        }) | Out-Null
    }
}

Write-Host @"
================================================================================
          Seep Reverse Lab — 工作台部署完备性校验与健康体检 (Verifier)
================================================================================
  工作台物理根目录: $Root
  宿主操作系统环境: Windows $([Environment]::OSVersion.Version.ToString()) ($([IntPtr]::Size * 8)-bit)
  校对基准手册: MANUAL/DEPLOYMENT-CHECKLIST.md
"@ -ForegroundColor Cyan

# -----------------------------------------------------------------------------
# 1. 核心目录与包结构
# -----------------------------------------------------------------------------
Write-Host "`n[1/9] 📁 核心架构与工程目录树" -ForegroundColor White
Test-CheckItem "架构" "工作台主目录完整 (Tool/)" { Test-Path $ToolDir } "请检查是否完整解压或下载了 Seep 完整仓库" "Tool/ 存在" "$Root\Tool"
Test-CheckItem "架构" "技能包目录完整 (Tool/skill/)" { Test-Path (Join-Path $ToolDir 'skill') } "检查 Tool/skill 是否存在" "Tool/skill 存在" "$ToolDir\skill"
Test-CheckItem "架构" "MCP服务引擎目录 (Tool/mcp/)" { Test-Path (Join-Path $ToolDir 'mcp') } "检查 Tool/mcp 是否存在" "Tool/mcp 存在" "$ToolDir\mcp"
Test-CheckItem "架构" "系统提示词层 (Tool/prompts/)" { Test-Path (Join-Path $ToolDir 'prompts') } "检查 Tool/prompts 是否存在" "Tool/prompts 存在" "$ToolDir\prompts"
Test-CheckItem "架构" "十四大脱敏案例工程 (Tool/cases/)" { 
    $cases = Join-Path $ToolDir 'cases'
    (Test-Path $cases) -and ((Get-ChildItem $cases -Directory).Count -ge 14)
} "检查 14 个项目案例目录是否存在" "≥14 个项目工程" "$ToolDir\cases"
Test-CheckItem "架构" "上游开源验证集 (Tool/upstream/ 3大开源项目)" { 
    (Test-Path (Join-Path $ToolDir 'upstream\apk-reverse')) -and
    (Test-Path (Join-Path $ToolDir 'upstream\open-tgtylab')) -and
    (Test-Path (Join-Path $ToolDir 'upstream\open-reverselab'))
} "检查 apk-reverse, open-tgtylab, open-reverselab 上游工程目录是否完备" "3 大完整上游" "$ToolDir\upstream"
Test-CheckItem "架构" "MCP专用运行时强约定 (Tool/mcp/Tool/)" { Test-Path (Join-Path $ToolDir 'mcp\Tool') } "严禁重命名或搬移 Tool/mcp/Tool 目录" "运行时目录存在" "$ToolDir\mcp\Tool"

# -----------------------------------------------------------------------------
# 1b. 版本与更新链路
# -----------------------------------------------------------------------------
Test-CheckItem "版本" "版本标识与变更日志 (VERSION + CHANGELOG.md)" {
    (Test-Path (Join-Path $Root 'VERSION')) -and (Test-Path (Join-Path $Root 'CHANGELOG.md'))
} "缺失 VERSION 或 CHANGELOG.md，重新拉取仓库" "两者在位" "$Root\VERSION"

Test-CheckItem "版本" "已有用户一键更新脚本 (update.ps1 + update.sh)" {
    (Test-Path (Join-Path $Root 'setup\update.ps1')) -and (Test-Path (Join-Path $Root 'setup\update.sh'))
} "更新脚本缺失，重新拉取仓库" "两个脚本在位" "$Root\setup"

Test-CheckItem "架构" "上游定点防外溢规则与同步引擎 (upstream-rules.json + sync-upstream.py)" {
    (Test-Path (Join-Path $Root 'setup\upstream-rules.json')) -and
    (Test-Path (Join-Path $Root 'setup\sync-upstream.py')) -and
    (Test-Path (Join-Path $Root 'setup\sync-upstream.ps1')) -and
    (Test-Path (Join-Path $Root 'update.bat'))
} "上游规则或同步引擎缺失，请重新拉取仓库" "规则清单、引擎与批处理在位" "$Root\setup\upstream-rules.json"

# 任务路由自洽性：routing.json 里的每个 route.skill 必须真实存在，
# 且 priority / fallbackId 与 routes 一一对应。路由指向空气时，运行期极难发现。
Test-CheckItem "路由" "任务路由表自洽 (routing.json 与技能落位一致)" {
    $scriptsDir = Join-Path $ToolDir 'scripts'
    $chk = Join-Path $scriptsDir 'verify-routing-coherence.py'
    if (-not (Test-Path -LiteralPath $chk)) { return $false }
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { return $true }
    & python $chk 2>&1 | Out-Null
    $LASTEXITCODE -eq 0
} "路由表与技能落位不一致（或 routing.json 缺失）；运行 python Tool/scripts/verify-routing-coherence.py 查看详情" "routes/priority/fallback/skill 全部自洽" "Tool/scripts/routing.json"

Test-CheckItem "版本" "一键卸载脚本 (uninstall.ps1 + uninstall.sh)" {
    (Test-Path (Join-Path $Root 'setup\uninstall.ps1')) -and (Test-Path (Join-Path $Root 'setup\uninstall.sh'))
} "卸载脚本缺失，重新拉取仓库" "两个脚本在位" "$Root\setup"

# -----------------------------------------------------------------------------
# 2. 知识库与战术资产
# -----------------------------------------------------------------------------
Write-Host "`n[2/9] 📚 攻防实战知识库与战术模板 (KB)" -ForegroundColor White
Test-CheckItem "知识库" "战术实战笔记 (292 篇完整检索库)" {
    (Test-Path $KbDir) -and ((Get-ChildItem $KbDir -Recurse -Filter '*.md').Count -ge 280)
} "Tool/mcp/Tool/reverselab/kb/ 文件缺失，请确认完整拉取" "≥289 篇笔记" "$KbDir"
Test-CheckItem "知识库" "内置 MCP 源码组件 (ReverseLab/Ghidra/JSHook)" {
    $m = Join-Path $Root 'Tool\mcp\Tool\reverselab\tools\skills\mcp'
    (Test-Path $m) -and ((Get-ChildItem $m -Directory).Count -ge 3)
} "reverselab 内置 MCP 源码组件缺失" "3 组 MCP 源码" "$Root\Tool\mcp\Tool\reverselab\tools\skills\mcp"

# -----------------------------------------------------------------------------
# 3. 智能体提示词与多平台适配
# -----------------------------------------------------------------------------
Write-Host "`n[3/9] 🧠 智能体指令系统与运行时拦截扩展 (Prompts & Extensions)" -ForegroundColor White
Test-CheckItem "提示词" "Pi Agent 系统指令 (SEEP.md 已就绪 / 去个人化 / 契约态)" {
    $p = Join-Path $ToolDir 'prompts\SEEP.md'
    if (-not (Test-Path $p)) { return $false }
    $raw = Get-Content -LiteralPath $p -Raw -Encoding UTF8
    ($raw.Length -le 2500) -and
    (-not (Select-String -Path $p -Pattern '小π|主人' -Quiet)) -and
    (-not ($raw -match '\d+\s*个工具')) -and
    ($raw -match 'AGENTS\.md') -and ($raw -match 'routing\.json') -and ($raw -match 'seep_status')
} "SEEP.md 缺失 / 未脱敏 / 超过 2500 字符 / 写死工具数量 / 缺事实源指针" "契约态 (<=2500 + 四指针)" "$ToolDir\prompts\SEEP.md"
Test-CheckItem "提示词" "提示词槽位 / 边界锚 / 人格守卫三者就绪" {
    if (Test-Path (Join-Path $ToolDir 'prompts\SYSTEM.md')) { return $false }
    $ext = Join-Path $ToolDir 'prompts\extensions'
    $loadTs = Join-Path $ext 'load-system-prompt.ts'
    $icpTs  = Join-Path $ext 'security-audit-interceptor.ts'
    if (-not ((Test-Path $loadTs) -and (Test-Path $icpTs))) { return $false }
    $a = Get-Content -LiteralPath $loadTs -Raw -Encoding UTF8
    $b = Get-Content -LiteralPath $icpTs -Raw -Encoding UTF8
    $cg = Join-Path $ext 'cmd-guard.ts'
    $cgr = Join-Path $ext 'cmd-guard.rules.json'
    $cgt = Join-Path $ext 'TOOL-CHAIN.md'
    $rl  = Join-Path $ext 'retry-level.ts'
    $rt  = Join-Path $ToolDir 'config\tool-runtimes.json'
    $task1 = Join-Path $ToolDir 'prompts\tasks\reverse.md'
    $task2 = Join-Path $ToolDir 'prompts\tasks\reverse-deliverable.md'
    $tr  = Join-Path $ToolDir 'scripts\tool-run.ps1'
    $kbLocalWired = (Select-String -Path (Join-Path $ToolDir 'mcp\seep_mcp_server.py') -Pattern 'kb_local' -Quiet)
    $kbLocalDir = Test-Path (Join-Path $ToolDir 'mcp\kb_local')
    ($a -match 'BOUNDARY_ANCHOR') -and ($a -match 'seep-boundary') -and
    ($b -match 'BOUNDARY-ANCHOR') -and ($b -match 'appendBoundaryTail') -and
    ($b -match 'looksLikePersonaCard') -and
    (Test-Path $cg) -and (Test-Path $cgr) -and (Test-Path $cgt) -and (Test-Path $rl) -and
    (Test-Path $rt) -and (Test-Path $tr) -and (Test-Path $task1) -and (Test-Path $task2) -and
    $kbLocalWired -and $kbLocalDir
} "SYSTEM.md 槽位未释放 / 边界锚缺失 / 人格守卫仍是枚举式名单" "槽位空 + 双层锚 + 结构判定守卫" "$ToolDir\prompts"
Test-CheckItem "提示词" "通用跨 Agent 规范 (AGENTS.md)" { Test-Path (Join-Path $ToolDir 'prompts\AGENTS.md') } "检查 AGENTS.md" "规范文件存在" "$ToolDir\prompts\AGENTS.md"
Test-CheckItem "提示词" "Claude Code 项目级规范 (CLAUDE.md 在项目根)" { Test-Path (Join-Path $Root 'CLAUDE.md') } "项目根缺失 CLAUDE.md" "CLAUDE.md 在根目录" "$Root\CLAUDE.md"
Test-CheckItem "提示词" "DeepSeek Harness 配置文件 (DSH-PROFILE.md)" { Test-Path (Join-Path $Root 'DSH-PROFILE.md') } "缺失 DSH-PROFILE.md" "DSH-PROFILE.md 在根目录" "$Root\DSH-PROFILE.md"
Test-CheckItem "扩展"   "底层安全放行与 Lab 状态机扩展 (.ts)" {
    Test-Path (Join-Path $ToolDir 'prompts\extensions\security-audit-interceptor.ts')
} "安全拦截扩展缺失，无法实现 lab: 状态机与防拒功能" "扩展文件在位" "$ToolDir\prompts\extensions\security-audit-interceptor.ts"

# -----------------------------------------------------------------------------
# 4. 技能系统完备性 (Skills System)
# -----------------------------------------------------------------------------
Write-Host "`n[4/9] 🛠️ 逆向工程专业技能库 (Skills - 11 大组件)" -ForegroundColor White
Test-CheckItem "Skill" "核心总控调度器 (softseep 包含 8 大专题库)" {
    $r = Join-Path $localSkills 'softseep\references'
    (Test-Path (Join-Path $localSkills 'softseep\SKILL.md')) -and 
    (Test-Path $r) -and ((Get-ChildItem $r -Filter '*.md').Count -ge 8)
} "softseep 或其 references 目录不完整" "SKILL.md + ≥8 refs" "$localSkills\softseep"

Test-CheckItem "Skill" "移动端逆向全链路 (apkseep 包含 45 篇规范与 56 脚本)" {
    $r = Join-Path $localSkills 'apkseep\references'
    $s = Join-Path $localSkills 'apkseep\scripts'
    (Test-Path (Join-Path $localSkills 'apkseep\SKILL.md')) -and (Test-Path $r) -and (Test-Path $s)
} "apkseep 工程不完整" "SKILL.md + 45 refs + 56 scripts" "$localSkills\apkseep"

Test-CheckItem "Skill" "IDA Pro 自动化联动 (ida-reverse 含 13337 唤醒规约)" {
    $f = Join-Path $localSkills 'ida-reverse\SKILL.md'
    (Test-Path $f) -and (Select-String -Path $f -Pattern '13337' -Quiet)
} "ida-reverse 技能缺失或被同名 safe-skills 版本覆盖（缺 13337 唤醒规约）" "SKILL.md + 13337 规约" "$localSkills\ida-reverse"

Test-CheckItem "Skill" "通用许可/卡密校验突破规范 (license-bypass)" {
    Test-Path (Join-Path $localSkills 'client-license-validation-bypass\SKILL.md')
} "client-license-validation-bypass 技能缺失" "SKILL.md 在位" "$localSkills\client-license-validation-bypass"

Test-CheckItem "Skill" "增量追版与特征迁移技能 (version-migration)" {
    Test-Path (Join-Path $localSkills 'version-migration\SKILL.md')
} "version-migration 技能缺失" "SKILL.md 在位" "$localSkills\version-migration"

Test-CheckItem "Skill" "独立战术安全技能包 (safe-skills 5组)" {
    $ss = Join-Path $localSkills 'safe-skills'
    (Test-Path $ss) -and ((Get-ChildItem $ss -Directory).Count -ge 5)
} "safe-skills 目录缺失或不足 5 个技能包" "5 组独立技能包" "$localSkills\safe-skills"

# SKILL.md 带 UTF-8 BOM 时，YAML frontmatter 解析器无法识别首行 `---`，
# 整条技能会被 DSH / Claude Code 等 Agent 静默跳过（参见 GitHub Issue #6）。
Test-CheckItem "Skill" "技能 SKILL.md 无 UTF-8 BOM（否则被 Agent 静默跳过）" {
    $bad = @(Get-ChildItem -Path (Join-Path $ToolDir 'skill') -Recurse -Filter 'SKILL.md' -ErrorAction SilentlyContinue |
        Where-Object {
            $b = [System.IO.File]::ReadAllBytes($_.FullName)
            ($b.Length -ge 3) -and ($b[0] -eq 0xEF) -and ($b[1] -eq 0xBB) -and ($b[2] -eq 0xBF)
        })
    -not $bad
} "存在带 BOM 的 SKILL.md，Agent 会静默跳过该技能；请运行 python setup/clean-format.py 修复" "全部无 BOM" "Tool/skill/**/SKILL.md"

# 如果检测到用户本地的 Pi Agent 目录，则额外校验是否已同步部署到系统
if (Test-Path $AgentDir) {
    Test-ManualItem "部署" "Pi Agent 本地技能同步 (~/.pi/agent/skills/softseep)" {
        Test-Path (Join-Path $AgentDir 'skills\softseep\SKILL.md')
    } "已安装 Pi 但尚未部署，可运行 powershell -File setup\install-pi.ps1 完成同步" "已同步到用户主目录" "$AgentDir\skills\softseep"
}

# -----------------------------------------------------------------------------
# 5. MCP 自动化服务层与底层工具 (MCP & Native Tools)
# -----------------------------------------------------------------------------
Write-Host "`n[5/9] 🔌 MCP 服务引擎与物理内置工具箱 (Native Tools)" -ForegroundColor White

Test-CheckItem "MCP" "核心服务端脚本 (seep_mcp_server.py 语法自洽)" {
    $sp = Join-Path $ToolDir 'mcp\seep_mcp_server.py'
    if (Test-Path $sp) {
        $pyCmd = Get-Command python -ErrorAction SilentlyContinue
        if ($pyCmd) {
            & python -c "import ast; ast.parse(open(r'$sp', encoding='utf-8').read())" 2>&1 | Out-Null
            $LASTEXITCODE -eq 0
        } else { $true }
    } else { $false }
} "seep_mcp_server.py 丢失或存在 Python 语法解析错误" "38 个原生工具定义（含 15 个扩展资产）" "$ToolDir\mcp\seep_mcp_server.py"

Test-CheckItem "MCP" "扩展资产：8 个新工具 + 声明式引擎链 + 说明文档" {
    $sp = Join-Path $ToolDir 'mcp\seep_mcp_server.py'
    $et = Join-Path $ToolDir 'config\engine-tiers.json'
    $ed = Join-Path $ToolDir 'docs\EXT-ASSETS.md'
    $mp = Join-Path $ToolDir 'docs\MERGE-PLAYBOOK.md'
    if ((Test-Path $sp) -and (Test-Path $et) -and (Test-Path $ed) -and (Test-Path $mp)) {
        $src = Get-Content -LiteralPath $sp -Raw -Encoding UTF8
        ($src -match 'def seep_ensure_tool') -and
        ($src -match 'def seep_decompile_auto') -and
        ($src -match 'def seep_pe_resources') -and
        ($src -match 'def seep_mem_strings') -and
        ($src -match 'def seep_pcap_extract') -and
        ($src -match 'def seep_packer_detect') -and
        ($src -match 'def seep_http_replay') -and
        ($src -match 'def seep_web_recon')
    } else { $false }
} "扩展资产缺失（新增工具/engine-tiers.json/EXT-ASSETS.md/MERGE-PLAYBOOK.md 任一不见）" "8 工具 + 引擎链 + 文档" "$ToolDir"

Test-CheckItem "MCP" "扩展资产功能自测 (test_ext_assets.py 30 项)" {
    $py = Get-Command python -ErrorAction SilentlyContinue
    $tst = Join-Path $ToolDir 'mcp\test_ext_assets.py'
    if ($py -and (Test-Path $tst)) {
        Push-Location (Join-Path $ToolDir 'mcp')
        try {
            & python test_ext_assets.py 2>&1 | Out-Null
            $LASTEXITCODE -eq 0
        } finally { Pop-Location }
    } else { $false }
} "扩展资产功能自测未通过（在 Tool/mcp 下跑 python test_ext_assets.py 看详情）" "30 项全过" "$ToolDir\mcp\test_ext_assets.py"

Test-CheckItem "MCP" "工具自动发现插件 (tool_autodiscover.py + 声明式能力表 + 本机状态隔离)" {
    $ta = Join-Path $ToolDir 'mcp\tool_autodiscover.py'
    $tc = Join-Path $ToolDir 'config\tool-capabilities.json'
    $gi = Join-Path $Root '.gitignore'
    if ((Test-Path $ta) -and (Test-Path $tc)) {
        $src = Get-Content -LiteralPath $ta -Raw -Encoding UTF8
        $cap = Get-Content -LiteralPath $tc -Raw -Encoding UTF8
        $giOk = $false
        if (Test-Path $gi) { $giOk = ((Get-Content -LiteralPath $gi -Raw -Encoding UTF8) -match 'tools\.local\.json') }
        ($src -match 'def discover') -and
        ($src -match 'def plan_control') -and
        ($src -match 'def register_mcp') -and
        ($src -match 'def research_control') -and
        ($cap -match '"tools"') -and
        $giOk
    } else { $false }
} "工具自动发现插件缺失（tool_autodiscover.py / tool-capabilities.json / .gitignore 未忽略 tools.local.json）" "插件 + 能力表 + 状态不入库" "$ToolDir\mcp\tool_autodiscover.py"

Test-CheckItem "MCP" "工具自动发现功能自测已覆盖 (test_ext_assets.py 含自动发现用例)" {
    $tst = Join-Path $ToolDir 'mcp\test_ext_assets.py'
    if (Test-Path $tst) {
        $src = Get-Content -LiteralPath $tst -Raw -Encoding UTF8
        ($src -match 'tool_autodiscover') -and
        ($src -match 'discover\(') -and
        ($src -match 'plan_control') -and
        ($src -match 'register_mcp')
    } else { $false }
} "自动发现测试用例缺失（test_ext_assets.py 应含 tool_autodiscover 用例）" "用例已覆盖（实跑见上方扩展资产自测）" "$ToolDir\mcp\test_ext_assets.py"

Test-CheckItem "工具箱" "Jadx 反编译引擎 (jadx-1.5.6 完整就绪)" {
    $j = Join-Path $ToolsDir 'jadx\lib\jadx-1.5.6-all.jar'
    $b = Join-Path $ToolsDir 'jadx\bin\jadx.bat'
    (Test-Path $j) -and (Test-Path $b)
} "Jadx 缺失，请运行 powershell -File setup\repair-tools.ps1 -Only jadx 恢复" "jadx.bat + jar" "$ToolsDir\jadx"

Test-CheckItem "工具箱" "Radare2 二进制全套工具 (r2/rabin2/radiff2/rasm2)" {
    $r2 = Join-Path $ToolsDir 'radare2\bin\radare2.exe'
    $rb = Join-Path $ToolsDir 'radare2\bin\rabin2.exe'
    (Test-Path $r2) -and (Test-Path $rb)
} "Radare2 二进制套件缺失，请运行 setup\repair-tools.ps1 -Only radare2 恢复" "全套二进制在位" "$ToolsDir\radare2"

Test-CheckItem "工具箱" "Apktool 资源拆解重构环境 (apktool.jar + bat)" {
    $aj = Join-Path $ToolsDir 'apktool\apktool.jar'
    $ab = Join-Path $ToolsDir 'apktool\apktool.bat'
    (Test-Path $aj) -and (Test-Path $ab)
} "Apktool 环境缺失，请运行 setup\repair-tools.ps1 -Only apktool 恢复" "apktool.jar + bat" "$ToolsDir\apktool"

Test-CheckItem "工具箱" "Frida/LSPosed 动态插桩模板库 (hook-mcp)" {
    Test-Path (Join-Path $ToolsDir 'hook-mcp\templates')
} "hook-mcp 模板目录缺失" "templates 目录在位" "$ToolsDir\hook-mcp\templates"

# 检查依赖包是否已经解压 (首次部署解压检查)
Test-CheckItem "依赖" "Web/JS 逆向调试引擎依赖已解压 (js-reverse-mcp/node_modules)" {
    (Test-Path (Join-Path $ToolsDir 'js-reverse-mcp\node_modules')) -or 
    (Test-Path (Join-Path $ToolsDir 'js-reverse-mcp\node_modules.zip'))
} "未找到 js-reverse-mcp 依赖或压缩包" "node_modules 已就绪" "$ToolsDir\js-reverse-mcp"

Test-CheckItem "依赖" "Playwright 浏览器自动化依赖已解压 (playwright-mcp/node_modules)" {
    (Test-Path (Join-Path $ToolsDir 'playwright-mcp\node_modules')) -or 
    (Test-Path (Join-Path $ToolsDir 'playwright-mcp\node_modules.zip'))
} "未找到 playwright-mcp 依赖或压缩包" "node_modules 已就绪" "$ToolsDir\playwright-mcp"

# -----------------------------------------------------------------------------
# 6. 环境运行时与第三方依赖配置
# -----------------------------------------------------------------------------
Write-Host "`n[6/9] ⚙️ 外部运行时与商业授权协同 (Runtime & Commercial)" -ForegroundColor White
Test-CheckItem "运行时" "Python 解释器 (3.11+ 且可执行)" {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { return $false }
    # 不仅判断存在，还要真正能执行且版本 >= 3.11（避开 Windows Store 占位程序等假 python）
    $out = & python -c "import sys; print('%d.%d' % (sys.version_info.major, sys.version_info.minor))" 2>&1
    if ($LASTEXITCODE -ne 0 -or -not $out) { return $false }
    $ver = ($out | Select-Object -First 1).ToString().Trim()
    $parts = $ver.Split('.')
    if ($parts.Count -lt 2) { return $false }
    $major = [int]$parts[0]; $minor = [int]$parts[1]
    ($major -gt 3) -or ($major -eq 3 -and $minor -ge 11)
} "系统未安装 Python 3.11+ 或 python 不可执行（若为 Windows Store 占位程序请安装官方 Python 并勾选 Add to PATH）" "Python 3.11+" "PATH"

Test-ManualItem "协议" "Python mcp 协议库环境支持 (mcp>=1.20,<1.29)" {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) {
        & python -c "import mcp" 2>&1 | Out-Null
        $LASTEXITCODE -eq 0
    } else { $false }
} "运行 pip install ""mcp>=1.20,<1.29"" 补齐协议支持" "mcp 库已安装" "Python site-packages"

Test-ManualItem "商业软件" "IDA Pro 商业反编译器协同 (需自备独立授权)" {
    $found = $false
    foreach ($c in @('D:\Tool\IDA Pro', 'C:\Program Files\IDA Pro', 'C:\Program Files\IDA Professional 9.0', 'C:\IDA Pro')) {
        if (Test-Path (Join-Path $c 'ida.exe')) { $found = $true; break }
    }
    $found
} "未检测到本地 IDA Pro，如无授权不影响核心链路，系统自动降级使用 Radare2（详见 MANUAL\IDA-PRO.md）" "商业授权可选" "本地安装目录"

Test-ManualItem "配置" "Claude Code 项目级 MCP 注册 (.mcp.json 在根目录)" {
    Test-Path (Join-Path $Root '.mcp.json')
} "根目录已备好 .mcp.json，在根目录直接执行 claude 即可免配加载" ".mcp.json 存在" "$Root\.mcp.json"

# 跨平台安装链自校验：mcp.json 里 seep 的启动脚本必须真实存在。
# 血案：Linux/macOS 上用 sed 替换模板会生成反斜杠路径（/home/x/Seep\Tool\...），
# 文件不存在 → 核心 MCP 静默起不来，而"文件存在性"检查完全抓不到。
Test-CheckItem "配置" "Pi Agent mcp.json 的 seep 启动路径可解析（跨平台安装链自检）" {
    $m = Join-Path $AgentDir 'mcp.json'
    if (-not (Test-Path $m)) { return $true }   # 未部署 Pi 时不判失败
    try {
        $raw = [System.IO.File]::ReadAllText($m, [System.Text.Encoding]::UTF8)
        if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
        $obj = $raw | ConvertFrom-Json
        $arg0 = @($obj.mcpServers.seep.args)[0]
        if (-not $arg0) { return $false }
        $p = [string]$arg0
        if (-not [System.IO.Path]::IsPathRooted($p)) { $p = Join-Path $Root $p }
        # 反斜杠路径在非 Windows 上必然不存在；这里用 Test-Path 统一判定
        return (Test-Path -LiteralPath $p)
    } catch { return $false }
} "mcp.json 中 seep 的 args[0] 指向不存在的脚本；请重跑 setup/install.sh 或 setup/merge_agent_config.py 重建配置" "seep 启动脚本路径真实存在" "$AgentDir\mcp.json"

# -----------------------------------------------------------------------------
# 7. MANUAL/ 战术手册完备性校验 (Tactical Manuals)
# -----------------------------------------------------------------------------
Write-Host "`n[7/9] 📚 MANUAL/ 战术手册完备性校验" -ForegroundColor White

Test-CheckItem "手册" "零基础实战通关指南 (MANUAL/ZERO-TO-HERO-WORKFLOW.md)" {
    Test-Path (Join-Path $ManualDir 'ZERO-TO-HERO-WORKFLOW.md')
} "零基础实战通关指南缺失，重新拉取仓库" "文件在位" "$ManualDir\ZERO-TO-HERO-WORKFLOW.md"

Test-CheckItem "手册" "外挂技能创作标准指南 (MANUAL/SKILL-CREATION-GUIDE.md)" {
    Test-Path (Join-Path $ManualDir 'SKILL-CREATION-GUIDE.md')
} "外挂技能创作指南缺失，重新拉取仓库" "文件在位" "$ManualDir\SKILL-CREATION-GUIDE.md"

Test-CheckItem "手册" "环境预要求指南 (MANUAL/PREREQUISITES.md)" {
    Test-Path (Join-Path $ManualDir 'PREREQUISITES.md')
} "安装指南缺失，重新拉取仓库" "文件在位" "$ManualDir\PREREQUISITES.md"

Test-CheckItem "手册" "IDA Pro 商业软件接入指南 (MANUAL/IDA-PRO.md)" {
    Test-Path (Join-Path $ManualDir 'IDA-PRO.md')
} "IDA-PRO 指南缺失" "文件在位" "$ManualDir\IDA-PRO.md"

Test-CheckItem "手册" "反调试绕过战术手册 (MANUAL/ANTI-DEBUG.md)" {
    Test-Path (Join-Path $ManualDir 'ANTI-DEBUG.md')
} "调试应对手册缺失，重新拉取仓库" "文件在位" "$ManualDir\ANTI-DEBUG.md"

Test-CheckItem "手册" "通用脱壳前置分析 SOP (MANUAL/UNPACKING.md)" {
    Test-Path (Join-Path $ManualDir 'UNPACKING.md')
} "脱壳手册缺失，重新拉取仓库" "文件在位" "$ManualDir\UNPACKING.md"

Test-CheckItem "手册" "PoC 闭环自动化验证 SOP (MANUAL/POC-VALIDATION.md)" {
    Test-Path (Join-Path $ManualDir 'POC-VALIDATION.md')
} "PoC 验证手册缺失，重新拉取仓库" "文件在位" "$ManualDir\POC-VALIDATION.md"

Test-CheckItem "手册" "全景部署与多 Agent 集成指南 (MANUAL/DEPLOYMENT.md)" {
    Test-Path (Join-Path $ManualDir 'DEPLOYMENT.md')
} "部署手册缺失，重新拉取仓库" "文件在位" "$ManualDir\DEPLOYMENT.md"

Test-CheckItem "手册" "官方部署资产核验基准清单 (MANUAL/DEPLOYMENT-CHECKLIST.md)" {
    Test-Path (Join-Path $ManualDir 'DEPLOYMENT-CHECKLIST.md')
} "核验清单缺失，重新拉取仓库" "SSOT 清单在位" "$ManualDir\DEPLOYMENT-CHECKLIST.md"

Test-CheckItem "手册" "跨平台运行与战术等价指南 (MANUAL/CROSS-PLATFORM.md)" {
    Test-Path (Join-Path $ManualDir 'CROSS-PLATFORM.md')
} "跨平台手册缺失，重新拉取仓库" "文件在位" "$ManualDir\CROSS-PLATFORM.md"

Test-CheckItem "手册" "合规转译中继与防拒体系 (MANUAL/COMPLIANCE-RELAY.md)" {
    Test-Path (Join-Path $ManualDir 'COMPLIANCE-RELAY.md')
} "合规中继手册缺失，重新拉取仓库" "文件在位" "$ManualDir\COMPLIANCE-RELAY.md"

# -----------------------------------------------------------------------------
# 8. 合规转译中继（网络层防拒）
# -----------------------------------------------------------------------------
Write-Host "`n[8/9] 🌐 合规转译中继与规则同步校验" -ForegroundColor White
$RelayDir = Join-Path $ToolDir 'scripts\compliance-relay'

Test-CheckItem "中继" "中继主程序 (relay.py 纯标准库实现)" {
    Test-Path (Join-Path $RelayDir 'relay.py')
} "relay.py 缺失，重新拉取仓库" "relay.py 在位" "$RelayDir\relay.py"

Test-CheckItem "中继" "规则提取器 (extract-rules.py)" {
    Test-Path (Join-Path $RelayDir 'extract-rules.py')
} "extract-rules.py 缺失，重新拉取仓库" "提取器在位" "$RelayDir\extract-rules.py"

Test-CheckItem "中继" "上下文守卫白名单 (guard-prefixes.json)" {
    Test-Path (Join-Path $RelayDir 'guard-prefixes.json')
} "guard-prefixes.json 缺失，重新拉取仓库" "白名单在位" "$RelayDir\guard-prefixes.json"

Test-CheckItem "中继" "规则表与 TS 源同步 (sensitive-rules.json)" {
    $rules = Join-Path $RelayDir 'sensitive-rules.json'
    if (-not (Test-Path $rules)) { return $false }
    $py = Get-Command python -ErrorAction SilentlyContinue
    if (-not $py) { return (Test-Path $rules) }
    Push-Location $RelayDir
    try {
        & python extract-rules.py --check 2>&1 | Out-Null
        $LASTEXITCODE -eq 0
    } finally { Pop-Location }
} "规则表与 TS 源不一致，请运行 python Tool/scripts/compliance-relay/extract-rules.py" "与 TS 源同步" "$RelayDir\sensitive-rules.json"

Test-CheckItem "中继" "中继单元测试套件 (tests/test_relay.py)" {
    Test-Path (Join-Path $RelayDir 'tests\test_relay.py')
} "测试套件缺失，重新拉取仓库" "测试套件在位" "$RelayDir\tests\test_relay.py"

# -----------------------------------------------------------------------------
# 9. 脱敏与隐私走查（递归全深度）
# -----------------------------------------------------------------------------
Write-Host "`n[9/9] 🔒 脱敏与个人隐私走查 (递归全深度扫描)" -ForegroundColor White

# 个人隐私模式：绝对路径 / 个人身份 / 私有邮箱 / 私有域名 / 裸用户名
$PrivacyPattern = 'C:[\\/]{1,2}Users[\\/]{1,2}Angus|AngusDevLab|angusdevlab|angus\.vip@|angusdev\.top|\bAngus\b|C:[\\/]{1,2}Users[\\/]{1,2}toti|[A-Za-z]:[\\/]{1,2}Project[\\/]'

# 排除：第三方依赖、上游镜像、构建产物，以及扫描器自身（其模式定义会自匹配）
$PrivacyExcludeRegex = '\\node_modules\\|\\__pycache__\\|\\Tool\\upstream\\|\\Tool\\mcp\\Tool\\|\\\.git\\|\\dist\\'
$PrivacyExcludeNames = @('verify.ps1', 'verify.sh')
$BinaryExt = @('.exe','.dll','.so','.dylib','.jar','.zip','.7z','.png','.jpg','.jpeg','.gif','.ico','.pdf','.bin','.dmp','.pyc','.idb','.i64','.ttf','.woff','.woff2')

Test-CheckItem "脱敏" "个人隐私零残留 (已跟踪文件全深度扫描)" {
    $PrivacyPathExclude = '^(setup/verify\.(ps1|sh))$|^Tool/(upstream|mcp/Tool)/'
    $PrivacyExtExclude = '\.(exe|dll|so|dylib|jar|zip|7z|png|jpg|jpeg|gif|ico|pdf|bin|dmp|pyc|idb|i64|ttf|woff|woff2)$'

    if (Test-Path (Join-Path $Root '.git')) {
        # 只扫描将被发布的 git 跟踪文件（本地生成物已 gitignore，不属发布范围）
        $tracked = & git -C $Root -c core.quotepath=false ls-files 2>$null
        if (-not $tracked) { return $true }
        $files = @($tracked |
            Where-Object { $_ -notmatch $PrivacyPathExclude -and $_ -notmatch $PrivacyExtExclude } |
            ForEach-Object { Join-Path $Root ($_ -replace '/', '\') } |
            Where-Object { Test-Path -LiteralPath $_ })
        if ($files.Count -eq 0) { return $true }
        $hits = Select-String -Path $files -Pattern $PrivacyPattern -CaseSensitive -ErrorAction SilentlyContinue
        return (-not $hits)
    }

    # 非 git 环境：回退到文件系统扫描（排除依赖与构建产物）
    $hits = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.FullName -notmatch $PrivacyExcludeRegex -and
                $PrivacyExcludeNames -notcontains $_.Name -and
                $BinaryExt -notcontains $_.Extension.ToLower()
            } |
            Select-String -Pattern $PrivacyPattern -CaseSensitive -ErrorAction SilentlyContinue
    -not $hits
} "发现个人隐私残留，请立即脱敏后重新提交" "零残留" "git 已跟踪文件（排除第三方依赖与上游镜像）"

Test-CheckItem "脱敏" "含本机路径的生成物未被 git 追踪" {
    if (-not (Test-Path (Join-Path $Root '.git'))) { return $true }
    $tracked = & git -C $Root ls-files 2>$null
    $mustIgnore = @('opencode.jsonc', 'setup/cordis.generated.yml', 'Tool/scripts/compliance-relay/relay-config.json')
    foreach ($f in $mustIgnore) {
        if ($tracked -contains $f) { return $false }
    }
    $true
} "生成物含本机绝对路径或访问令牌，不应入库；请从索引移除并确认 .gitignore" "未被追踪" "git index"

Test-ManualItem "脱敏" "目标产品名残留统计 (功能性标识符可保留)" {
    $cases = Join-Path $ToolDir 'cases'
    if (-not (Test-Path $cases)) { return $true }
    $names = 'xyplorer|bandizip|boosterx|1218\.io'
    $hits = Get-ChildItem -Path $cases -Recurse -File -ErrorAction SilentlyContinue |
            Select-String -Pattern $names -ErrorAction SilentlyContinue
    -not $hits
} "存在目标产品名（含 README 已声明的功能性必需标识符，如注册表路径 / API 域名 / 代码符号）；如为叙述性提及请脱敏" "零残留" "$cases"

# -----------------------------------------------------------------------------
# 详细校对模式输出 (-Detailed / -Audit)
# -----------------------------------------------------------------------------
if ($Detailed) {
    Write-Host "`n================================================================================" -ForegroundColor Cyan
    Write-Host "       📊 官方基准核对报表 (Detailed Baseline vs Actual Alignment Table)" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ("{0,-8} | {1,-35} | {2,-15} | {3,-15} | {4}" -f "类别", "资产/组件名称", "官方期望值", "实测状态", "说明与降级指引") -ForegroundColor White
    Write-Host ("-" * 105) -ForegroundColor Gray
    foreach ($row in $script:AuditTable) {
        $color = switch ($row.Status) {
            "🟢 READY" { [ConsoleColor]::Green }
            "🟡 DEGRADED" { [ConsoleColor]::Yellow }
            "🔴 MISSING" { [ConsoleColor]::Red }
            default { [ConsoleColor]::White }
        }
        $line = "{0,-8} | {1,-35} | {2,-15} | {3,-15} | {4}" -f $row.Category, $row.Name, $row.Expected, $row.Status, $row.Note
        Write-Host $line -ForegroundColor $color
    }
    Write-Host ("-" * 105) -ForegroundColor Gray
}

# -----------------------------------------------------------------------------
# 汇总仪表盘
# -----------------------------------------------------------------------------
Write-Host "`n================================================================================" -ForegroundColor White
Write-Host ("  [体检报告] 核心检查通过: {0} 项" -f $script:OkCount) -ForegroundColor Green

if ($script:FailList.Count -gt 0) {
    Write-Host ("`n  [!] 发现异常阻断项 ({0} 项):" -f $script:FailList.Count) -ForegroundColor Red
    foreach ($err in $script:FailList) {
        Write-Host ("    * [{0}] {1}" -f $err.Category, $err.Name) -ForegroundColor Red
        Write-Host ("      -> 整改建议: {0}" -f $err.Fix) -ForegroundColor Gray
    }
}

if ($script:TodoList.Count -gt 0) {
    Write-Host ("`n  [*] 可选/建议关注项 ({0} 项):" -f $script:TodoList.Count) -ForegroundColor Yellow
    foreach ($todo in $script:TodoList) {
        Write-Host ("    * [{0}] {1}" -f $todo.Category, $todo.Name) -ForegroundColor Yellow
        Write-Host ("      -> 说明/指南: {0}" -f $todo.Note) -ForegroundColor Gray
    }
}

Write-Host "================================================================================" -ForegroundColor White

if ($script:FailList.Count -eq 0) {
    Write-Host "`n  🎉 结论: 工作台处于 [READY / 完备就绪] 状态！" -ForegroundColor Green
    Write-Host "  基准清单对照完成，核心资产全部对齐。" -ForegroundColor Green
    Write-Host "  您可以直接在 Agent (Pi / Claude / DSH / Codex) 中发送: lab： 开启测试！`n" -ForegroundColor Cyan
    exit 0
} else {
    Write-Host "`n  ❌ 结论: 当前工作台存在未满足的核心依赖，请按照上述红色整改建议修复。`n" -ForegroundColor Red
    exit 1
}
