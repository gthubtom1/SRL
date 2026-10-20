#Requires -Version 5.1
<#
  Seep 工作台 —— 一键配置 Pi Agent 运行环境 (加强版)
  包含：
    1. 备份原 ~/.pi/agent 配置
    2. 同步 11 个 Skill
    3. 同步提示词与安全放行扩展
    4. 增量合并 mcp.json（保护已有用户配置，UTF-8 No BOM，反斜杠安全转义）
    5. 配置 settings.json
#>
[CmdletBinding()]
param(
    [switch]$SkipPackages
)

$ErrorActionPreference = 'Continue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$NormalizedRoot = $Root.Replace('\', '/')
$ToolDir   = Join-Path $Root 'Tool'
$AgentDir  = Join-Path $env:USERPROFILE '.pi\agent'
$SkillsDir = Join-Path $AgentDir 'skills'
$ExtDir    = Join-Path $AgentDir 'extensions'

function Write-Ok($m)   { Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }
function Write-Info($m) { Write-Host "    [..] $m" -ForegroundColor Gray }

Write-Host "`n  === Pi Agent 环境配置 ===" -ForegroundColor Cyan

# ---------------------------------------------------------------- 1. 目录与备份
foreach ($d in @($AgentDir, $SkillsDir, $ExtDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

$backup = Join-Path $AgentDir ("backup-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$needBackup = @('SEEP.md', 'AGENTS.md', 'mcp.json', 'settings.json')
$hasOld = $false
foreach ($f in $needBackup) {
    if (Test-Path (Join-Path $AgentDir $f)) { $hasOld = $true; break }
}
if ($hasOld) {
    New-Item -ItemType Directory -Path $backup -Force | Out-Null
    $n = 0
    foreach ($f in $needBackup) {
        $p = Join-Path $AgentDir $f
        if (Test-Path $p) { Copy-Item $p $backup -Force; $n++ }
    }
    Write-Ok "已安全备份原有配置 ($n 个文件) -> $backup"
}

# ---------------------------------------------------------------- 2. Skill 同步
$srcSkills = Join-Path $ToolDir 'skill'
if (Test-Path $srcSkills) {
    foreach ($s in (Get-ChildItem $srcSkills -Directory)) {
        if ($s.Name -eq 'safe-skills') {
            foreach ($sub in (Get-ChildItem $s.FullName -Directory)) {
                $dst = Join-Path $SkillsDir $sub.Name
                # ★ 冲突守卫：safe-skills 的子技能若与顶层技能同名，会静默覆盖顶层那份
                #   （历史事故：safe-skills/ida-reverse 覆盖了顶层 ida-reverse，
                #    导致带 13337 全自动唤醒规约的核心技能丢失）。
                $topLevel = Join-Path $srcSkills $sub.Name
                if ((Test-Path $topLevel) -and $sub.Name -ne 'safe-skills') {
                    Write-Warn "safeskills 子技能与顶层技能同名，已跳过以免覆盖: $($sub.Name)"
                    continue
                }
                if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
                Copy-Item $sub.FullName $dst -Recurse -Force
            }
            Write-Ok 'safe-skills 子技能 -> ~/.pi/agent/skills/'
        } elseif ($s.Name -ne 'update') {
            $dst = Join-Path $SkillsDir $s.Name
            if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
            Copy-Item $s.FullName $dst -Recurse -Force
            Write-Ok "skill: $($s.Name)"
        }
    }
} else { Write-Warn "未找到 $srcSkills" }

# ---------------------------------------------------------------- 3. 提示词 + 扩展
$srcPrompt = Join-Path $ToolDir 'prompts'
# ★ 文件名是 SEEP.md，不是 SYSTEM.md：pi 内核把 <agent-dir>/SYSTEM.md 理解为「替换默认系统提示词」，
#   与扩展的 sections["seep-reverse-lab"] 叠加会让整份规则在提示词里出现两次，并顶掉 pi 自带的默认提示词。
foreach ($f in @('SEEP.md', 'AGENTS.md')) {
    $src = Join-Path $srcPrompt $f
    if (Test-Path $src) { Copy-Item $src (Join-Path $AgentDir $f) -Force; Write-Ok "prompt: $f" }
    else { Write-Warn "未找到 $f" }
}

# 迁移：旧版把规则写成 ~/.pi/agent/SYSTEM.md，会被 pi 内核当“替换默认提示词”，必须退役
$legacySystem = Join-Path $AgentDir 'SYSTEM.md'
if (Test-Path $legacySystem) {
    $isOurs = Select-String -Path $legacySystem -Pattern 'Seep Reverse Lab' -Quiet
    if ($isOurs) {
        $retired = Join-Path $AgentDir 'backup-retired-prompts'
        if (-not (Test-Path $retired)) { New-Item -ItemType Directory -Path $retired -Force | Out-Null }
        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        Move-Item -Path $legacySystem -Destination (Join-Path $retired "SYSTEM.md.$stamp") -Force
        Write-Ok "已退役旧版 SYSTEM.md（会被 pi 内核当替换提示词）-> backup-retired-prompts/SYSTEM.md.$stamp"
    } else {
        Write-Warn "检测到非本工作台的 ~/.pi/agent/SYSTEM.md，保持原样（未迁移）"
    }
}
$srcExt = Join-Path $srcPrompt 'extensions'
if (Test-Path $srcExt) {
    foreach ($f in (Get-ChildItem $srcExt -Filter '*.ts')) {
        Copy-Item $f.FullName (Join-Path $ExtDir $f.Name) -Force
        Write-Ok "extension: $($f.Name)"
    }
    # 扩展的配套规则文件（如 cmd-guard.rules.json：cmd-guard 从 __dirname 读它）
    foreach ($f in (Get-ChildItem $srcExt -Filter '*.json' -ErrorAction SilentlyContinue)) {
        Copy-Item $f.FullName (Join-Path $ExtDir $f.Name) -Force
        Write-Ok "extension rules: $($f.Name)"
    }
    # 自动安全退役与归档已融合的旧版独立扩展（其人设卡/RULES/粘性保护已100%全量融入 load-system-prompt.ts）
    $legacyCompat = Join-Path $ExtDir 'prompt-compat.ts'
    if (Test-Path $legacyCompat) {
        $retiredDir = Join-Path $AgentDir 'backup-retired-extensions'
        if (-not (Test-Path $retiredDir)) { New-Item -ItemType Directory -Path $retiredDir -Force | Out-Null }
        Move-Item -Path $legacyCompat -Destination (Join-Path $retiredDir 'prompt-compat.ts') -Force
        Write-Ok "已安全归档旧版独立扩展 prompt-compat.ts -> backup-retired-extensions/ (消除双重注册冲突)"
    }
}

# ---------------------------------------------------------------- 4. 增量安全合并 mcp.json (UTF-8 No BOM, 无覆盖隐患)
$dstMcp = Join-Path $AgentDir 'mcp.json'
$existingConfig = [PSCustomObject]@{ mcpServers = [PSCustomObject]@{} }

if (Test-Path $dstMcp) {
    try {
        $rawMcp = [System.IO.File]::ReadAllText($dstMcp, [System.Text.Encoding]::UTF8)
        # 注意：不能用 $rawMcp.StartsWith([char]0xFEFF)。
        # .NET 默认 StartsWith 使用文化敏感比较，而 U+FEFF（BOM）是可忽略字符，
        # 等价于空字符串，会导致任何字符串都“以 BOM 开头”，从而误删首字符并破坏 JSON。
        if ($rawMcp.Length -gt 0 -and [int]$rawMcp[0] -eq 0xFEFF) { $rawMcp = $rawMcp.Substring(1) }
        $existingConfig = $rawMcp | ConvertFrom-Json
    } catch {
        Write-Warn "现有 mcp.json 语法异常，正在安全初始化..."
        $existingConfig = [PSCustomObject]@{ mcpServers = [PSCustomObject]@{} }
    }
}

if (-not $existingConfig.mcpServers) {
    $existingConfig | Add-Member -NotePropertyName 'mcpServers' -NotePropertyValue ([PSCustomObject]@{}) -Force
}

# 挂载核心 seep MCP
$seepServerPy = "$NormalizedRoot/Tool/mcp/seep_mcp_server.py"
$seepEntry = [PSCustomObject]@{
    command = "python"
    args    = @($seepServerPy)
    env     = [PSCustomObject]@{
        PYTHONIOENCODING = "utf-8"
    }
    transport = "stdio"
}
$existingConfig.mcpServers | Add-Member -NotePropertyName 'seep' -NotePropertyValue $seepEntry -Force

# 挂载 js-reverse
$jsReverseEntry = [PSCustomObject]@{
    command   = "npx"
    args      = @("-y", "js-reverse-mcp")
    transport = "stdio"
    lifecycle = "lazy"
}
$existingConfig.mcpServers | Add-Member -NotePropertyName 'js-reverse' -NotePropertyValue $jsReverseEntry -Force

# 挂载 playwright (若不存在才添加模板，不冲掉用户现有 Token)
if (-not $existingConfig.mcpServers.playwright) {
    $playwrightEntry = [PSCustomObject]@{
        command   = "npx"
        args      = @("-y", "@playwright/mcp@latest", "--extension")
        env       = [PSCustomObject]@{
            PLAYWRIGHT_MCP_EXTENSION_TOKEN = "<YOUR_PLAYWRIGHT_TOKEN>"
        }
        transport = "stdio"
        lifecycle = "eager"
    }
    $existingConfig.mcpServers | Add-Member -NotePropertyName 'playwright' -NotePropertyValue $playwrightEntry -Force
}

# 序列化为 UTF-8 No BOM 格式写入
$finalMcpJson = $existingConfig | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($dstMcp, $finalMcpJson, (New-Object System.Text.UTF8Encoding $false))
Write-Ok "mcp.json 已增量合并完成（保护已有第三方配置，UTF-8 无BOM格式）"

# ---------------------------------------------------------------- 5. settings.json (增量合并 packages)
$dstSettings = Join-Path $AgentDir 'settings.json'
$packages = @(
    'npm:pi-open-tui',
    'npm:pi-web-access',
    'npm:@juicesharp/rpiv-todo',
    'npm:@narumitw/pi-btw',
    'npm:@narumitw/pi-plan-mode',
    'npm:@narumitw/pi-usage',
    'npm:@smoose/pi-themes',
    'npm:pi-tool-display',
    'npm:@juicesharp/rpiv-ask-user-question',
    'npm:pi-playwright',
    'npm:pi-goal-x'
)

$settings = [PSCustomObject]@{}
if (Test-Path $dstSettings) {
    try {
        $rawSet = [System.IO.File]::ReadAllText($dstSettings, [System.Text.Encoding]::UTF8)
        # 同上：必须用序数/字符比较，避免文化敏感比较误判 BOM
        if ($rawSet.Length -gt 0 -and [int]$rawSet[0] -eq 0xFEFF) { $rawSet = $rawSet.Substring(1) }
        $settings = $rawSet | ConvertFrom-Json
    } catch { $settings = [PSCustomObject]@{} }
}

$currentPackages = @()
if ($settings.packages) { $currentPackages = @($settings.packages) }
# 退役条目：曾与 pi 1.3+ 内置 MCP 抢 /mcp（replaceable 机制会丢弃内置、启动报
# [Extension issues]）。重跑本脚本时主动剔除，保证从旧版升级上来也能恢复内置。
$retiredPackages = @('npm:pi-mcp-extension')
$foundRetired = @($currentPackages | Where-Object { $retiredPackages -contains $_ })
if ($foundRetired.Count -gt 0) {
    $currentPackages = @($currentPackages | Where-Object { $retiredPackages -notcontains $_ })
    Write-Warn ("已剔除退役扩展（与 pi 内置 MCP 抢名）: " + ($foundRetired -join ', '))
}
foreach ($pkg in $packages) {
    if ($currentPackages -notcontains $pkg) { $currentPackages += $pkg }
}

$settings | Add-Member -NotePropertyName 'packages' -NotePropertyValue $currentPackages -Force
$finalSettingsJson = $settings | ConvertTo-Json -Depth 10
[System.IO.File]::WriteAllText($dstSettings, $finalSettingsJson, (New-Object System.Text.UTF8Encoding $false))
Write-Ok "settings.json 已安全同步（$($currentPackages.Count) 个 packages）"

# ---------------------------------------------------------------- 6. 安装扩展包
if (-not $SkipPackages) {
    $pi = Get-Command pi -ErrorAction SilentlyContinue
    if ($pi) {
        Write-Info 'pi update --extensions ...'
        & pi update --extensions 2>&1 | ForEach-Object { Write-Info $_ }
        if ($LASTEXITCODE -eq 0) { Write-Ok 'pi 扩展包已更新' }
        else { Write-Warn 'pi update 失败，可稍后手动执行：pi update --extensions' }
    } else {
        Write-Warn '未找到 pi 命令，跳过扩展包更新'
    }
}

# ---------------------------------------------------------------- 7. 扩展命名冲突自检（pi 的 replaceable 内置）
# 背景：pi 把部分内置标记为 replaceable（内置 MCP 即其一）。第三方扩展只要注册了同名
# 工具/命令/旗标（如 /mcp），内置就会被静默顶掉并在启动时打 [Extension issues]。
# 本步在**装完就报**，而不是等用户看启动横幅。
$conflictScript = Join-Path $ToolDir 'scripts\check-extension-conflicts.py'
if (Test-Path $conflictScript) {
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) {
        Write-Info '检查已装扩展是否与 pi 内置抢名（replaceable）...'
        & python $conflictScript 2>&1 | ForEach-Object { Write-Info $_ }
        if ($LASTEXITCODE -ne 0) {
            Write-Warn '存在扩展与 pi 内置同名冲突：该扩展会顶掉内置，启动会出现 [Extension issues]。按上面提示处置。'
        } else {
            Write-Ok '扩展命名无冲突（pi 内置 MCP 等保持生效）'
        }
    }
}

exit 0
