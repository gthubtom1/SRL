#Requires -Version 5.1
# reverse-skill PRIMARY router.
# 规则单一事实源：skills/config/routing.json（勿在本脚本内硬编码路由表）。
# CLI 兼容旧版：-Hint / -OutDir；输出 route-scope.md；退出码 0 成功 / 2 配置或技能缺失。
# 读取 UTF-8 BOM 源以保证 Windows PowerShell 5.1 下 CJK 正常。
param(
    [string] $Hint = '',
    [string] $OutDir = '',
    [string] $ProjectRoot = ''
)
$ErrorActionPreference = 'Stop'

# Lowercase for Latin tokens; CJK unchanged by ToLowerInvariant.
$t = if ($Hint) { $Hint.ToLowerInvariant() } else { '' }

# ★ 2026-10-22 审计 P0：.NET 正则的 \b 把 CJK 也当 word 字符，所以「APK去广告」「Unity IL2CPP透视」
#   这类「英文词紧跟中文」的输入，规则里的 \bapk\b / il2cpp\b 全部匹配不上 → 直接掉进兵底。
#   修法：匹配前在 ASCII 与 CJK 交界处补空格（只改用于匹配的副本，不动原输入）。
$t = [regex]::Replace($t, '([ -~])([　-〿一-鿿＀-￯])', '$1 $2')
$t = [regex]::Replace($t, '([　-〿一-鿿＀-￯])([ -~])', '$1 $2')

$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$skillsRoot = Split-Path -Parent $scriptDir
$packageRoot = Split-Path -Parent $skillsRoot
# --- 路由配置定位（单一事实源）---
# 本仓库把 reverse-skill 的 skills/ 树摊平进了 Tool/，因此 routing.json 实际位于
# 脚本同级目录 Tool/scripts/routing.json；为兼容旧布局再兜底 Tool/config/routing.json。
$configCandidates = @(
    (Join-Path $scriptDir 'routing.json'),
    (Join-Path $skillsRoot 'config/routing.json')
)
$configPath = $null
foreach ($c in $configCandidates) {
    if (Test-Path -LiteralPath $c) { $configPath = $c; break }
}

# --- 读取路由配置（单一事实源） ---
if (-not $configPath) {
    Write-Host ("ERROR: routing config missing. Tried: {0}" -f ($configCandidates -join ' | ')) -ForegroundColor Red
    Write-Host 'Restore Tool/scripts/routing.json (git checkout / git pull) and retry.' -ForegroundColor Yellow
    exit 2
}
try {
    $cfg = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json
} catch {
    Write-Host ("ERROR: routing config is not valid JSON: {0}" -f $_.Exception.Message) -ForegroundColor Red
    exit 2
}

# --- 规则匹配：每条 keyword 规则命中则计入候选集（与旧版逐条 if 行为一致） ---
$sel = New-Object System.Collections.Generic.List[string]
foreach ($route in $cfg.routes.PSObject.Properties) {
    $id = $route.Name
    foreach ($kw in $route.Value.keywords) {
        # ★ 血案修复（2026-10-21 审计 P0）：原先 $hit 从 $false 起，只有 `must` 命中才会置真，
        # 于是「只有 mustAll、没有 must」的组合规则**永远不可能命中**——R23 的 kubectl+RBAC、
        # R25 的 6 条组合词、R28 的 npm+registry 全部是死规则，而门禁另一套实现却判它们有效。
        # 现在：有 must 就以 must 起判；没有 must 但有 mustAll/exclude 时从真起判，
        # 保证「组合限定词单独成条」也能生效。
        $hit = $true
        if ($null -ne $kw.must) { $hit = ($t -match $kw.must) }
        # mustAll：全部子正则都匹配才成立
        if ($hit -and $null -ne $kw.mustAll) {
            foreach ($m in $kw.mustAll) {
                if ($t -notmatch $m) { $hit = $false; break }
            }
        }
        # exclude：命中则本条规则不触发（防误伤，如 越狱/LLM 语境、域控/攻击链）
        if ($hit -and $null -ne $kw.exclude -and $t -match $kw.exclude) { $hit = $false }
        if ($hit) { [void]$sel.Add($id) }
    }
}

# --- 计分：只作展示；PRIMARY 由 priority 决定（2026-10-21 审计 P0-2） ---
# 旧口径「命中规则条数多者胜」会让多规则域系统性吞并单规则域：
# R29(4 条) 永远压过 R1/R8/R9(各 1 条) —— "Frida 在 android 上 hook" 被判成 softseep。
# 词写得再准也没用。现在改为 **priority 优先**：按 priority 顺序取第一个有命中的域，
# 分数只用于展示"命中了几条规则"。代价是要人工维护 priority 顺序（已有自检保证一一对应）。
$scores = [ordered]@{}
foreach ($item in $sel) {
    if (-not $scores.Contains($item)) { $scores[$item] = 0 }
    $scores[$item] = $scores[$item] + 1
}

$uniq = New-Object System.Collections.Generic.List[string]
foreach ($d in $scores.Keys) { [void]$uniq.Add($d) }

# --- priority 自检：路由表与 priority 必须一一对应，防新增路由漏加优先级 ---
$routeIds = @($cfg.routes.PSObject.Properties | ForEach-Object { $_.Name })
$missingInPriority = @($routeIds | Where-Object { $_ -notin @($cfg.priority) })
$extraInPriority = @($cfg.priority | Where-Object { $_ -notin $routeIds })
if ($missingInPriority.Count -gt 0 -or $extraInPriority.Count -gt 0) {
    Write-Host 'WARN: routing.json routes/priority mismatch:' -ForegroundColor Yellow
    if ($missingInPriority.Count -gt 0) { Write-Host ("  routes not in priority: {0}" -f ($missingInPriority -join ', ')) -ForegroundColor Yellow }
    if ($extraInPriority.Count -gt 0) { Write-Host ("  priority not in routes: {0}" -f ($extraInPriority -join ', ')) -ForegroundColor Yellow }
}

# --- PRIMARY = priority 顺序里第一个命中的域；fallback 不参与竞争 ---
$priority = @($cfg.priority)
$fallbackId = $cfg.meta.fallbackId
$primary = $null
$maxScore = 0
foreach ($p in $priority) {
    if ($p -eq $fallbackId) { continue }   # R0 的 `.*` 是兜底，不是候选
    if ($scores.Contains($p)) { $primary = $p; $maxScore = $scores[$p]; break }
}

$notes = New-Object System.Collections.Generic.List[string]
$confidence = 'low'
if ($null -eq $primary) {
    $primary = $fallbackId
    if ($t) { [void]$notes.Add('No strong keyword hit; open routing.md full matrix') }
    else { [void]$notes.Add('Empty hint; provide task text') }
} else {
    $confidence = if ($uniq.Count -eq 1) { 'high' } else { 'medium' }
}

# 防御：priority 若含 routes 之外的幽灵 id（配置错误），回退到 fallback 而非崩溃
if ($routeIds -notcontains $primary) {
    Write-Host ("WARN: primary id '{0}' not in routes; falling back to {1}" -f $primary, $fallbackId) -ForegroundColor Yellow
    $primary = $fallbackId
}

# 复用当前主线的项目工作根解析，避免把路由产物写进 skill 包。
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$skillsRoot = Split-Path -Parent $scriptDir
$packageRoot = Split-Path -Parent $skillsRoot
. (Join-Path (Join-Path $scriptDir 'lib') 'WorkRoot.ps1')
$projectRoot = Resolve-ReverseProjectRoot -RequestedRoot $ProjectRoot

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $workRoot = Join-Path $projectRoot 'work'
    $OutDir = Join-Path $workRoot ("master-route-{0}" -f $stamp)
}

$primaryPath = $cfg.routes.$primary.skill
$primaryLabel = $cfg.routes.$primary.label
# 技能根解析：兼容 skills/<name>/SKILL.md、Tool/skill/<name>/SKILL.md、
# Tool/skill/safe-skills/<name>/SKILL.md 三种落位。
$skillRel = $primaryPath -replace '/', [IO.Path]::DirectorySeparatorChar
$skillRootCandidates = @(
    (Join-Path $skillsRoot $skillRel),
    (Join-Path (Join-Path $skillsRoot 'skill') $skillRel),
    (Join-Path (Join-Path (Join-Path $skillsRoot 'skill') 'safe-skills') $skillRel)
)
$skillAbs = $null
foreach ($c in $skillRootCandidates) {
    if (Test-Path -LiteralPath $c) { $skillAbs = $c; break }
}
if (-not $skillAbs) {
    $skillAbs = $skillRootCandidates[0]
}
if (-not (Test-Path -LiteralPath $skillAbs)) {
    Write-Host ("ERROR: PRIMARY skill missing: {0}" -f $skillAbs) -ForegroundColor Red
    exit 2
}

# --- 输出目录（默认调用方项目 work\master-route-<ts>） ---
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    if ($packageRoot -and (Test-Path -LiteralPath $packageRoot)) {
        $OutDir = Join-Path (Join-Path $packageRoot 'work') ("master-route-{0}" -f $stamp)
    } else {
        $tmpBase = if ($env:TEMP) { $env:TEMP } else { [System.IO.Path]::GetTempPath() }
        $OutDir = Join-Path (Join-Path $tmpBase 'reverse-skill-route') ("master-route-{0}" -f $stamp)
    }
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# --- 写 route-scope.md（格式与旧版一致，下游脚本解析 primary_skill / primary） ---
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('# reverse-skill Master route (PRIMARY)')
[void]$sb.AppendLine(("- created: {0}" -f (Get-Date -Format 'o')))
[void]$sb.AppendLine(("- package: reverse-skill"))
$hintOneLine = (($Hint -replace '[\r\n]+', ' ').Trim())
[void]$sb.AppendLine(("- hint: {0}" -f $hintOneLine))
[void]$sb.AppendLine(("- primary: {0}" -f $primary))
[void]$sb.AppendLine(("- primary_label: {0}" -f $primaryLabel))
[void]$sb.AppendLine(("- primary_skill: skills/{0}" -f $primaryPath))
[void]$sb.AppendLine(("- confidence: {0}" -f $confidence))
[void]$sb.AppendLine(("- project_root: {0}" -f $projectRoot))
$sec = New-Object System.Collections.Generic.List[string]
foreach ($d in $uniq) {
    if ($d -ne $primary) { [void]$sec.Add(("skills/{0}" -f $cfg.routes.$d.skill)) }
}
$secText = if ($sec.Count -gt 0) { ($sec -join ', ') } else { '(none)' }
[void]$sb.AppendLine(("- secondary: {0}" -f $secText))
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## MUST open next')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('1. skills/MASTER-ROUTING.md')
[void]$sb.AppendLine(("2. skills/{0}" -f $primaryPath))
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Notes')
if ($notes.Count -eq 0) { [void]$sb.AppendLine('- (none)') }
foreach ($n in $notes) { [void]$sb.AppendLine(("- {0}" -f $n)) }

# UTF-8 with BOM for route-scope (Windows notepad-friendly)
$utf8 = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText((Join-Path $OutDir 'route-scope.md'), $sb.ToString(), $utf8)

# 显示真实解析到的技能相对路径（不再是硬编码的 skills/ 前缀）
# 注意：Windows PowerShell 5.1（.NET Framework）没有 [IO.Path]::GetRelativePath，
# 这里手工做前缀裁剪，保证 5.1 / 7.x 行为一致。
$primaryShown = $skillAbs
if ($packageRoot -and $skillAbs.StartsWith($packageRoot, [StringComparison]::OrdinalIgnoreCase)) {
    $primaryShown = $skillAbs.Substring($packageRoot.Length).TrimStart([char]92, [char]47)
}
$primaryShown = $primaryShown.Replace([System.IO.Path]::DirectorySeparatorChar, [char]47)
Write-Host ("PRIMARY -> {0}" -f $primaryShown) -ForegroundColor Green
Write-Host ("Label: {0} | confidence: {1}" -f $primaryLabel, $confidence)
foreach ($n in $notes) { Write-Host ("NOTE: {0}" -f $n) -ForegroundColor Yellow }
Write-Host ("Wrote {0}\route-scope.md" -f $OutDir)
Write-Host 'ACTION: Open PRIMARY SKILL.md now and execute ACTION REQUIRED.' -ForegroundColor Yellow
