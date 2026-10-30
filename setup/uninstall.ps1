#Requires -Version 5.1
<#
  Seep 逆向工程工作台 —— 一键卸载 (Uninstaller)
  ================================================================
  设计原则：**只移除工作台自己装的东西，绝不碰你的数据。**

  卸载范围（精准白名单，逐项可关）：
    · ~/.pi/agent/skills/<工作台技能>      —— 当前启用的工作台技能
    · ~/.pi/agent/AGENTS.md / SEEP.md      —— 工作台写入的提示词（旧版为 SYSTEM.md，一并清理）
    · ~/.pi/agent/extensions/*.ts          —— 工作台扩展
    · ~/.pi/agent/mcp.json 中的工作台 MCP 条目（清单取 Tool/config/mcp-servers.json：seep / js-reverse / playwright / ida / x64dbg）
    · ~/.pi/agent/settings.json 中工作台加入的 packages
    · ~/.pi/agent/lab-mode.flag            —— 仅在安装清单能证明归属时清理

  严格保护（永不删除）：
    · models.json / auth.json / sessions/ / logs/
    · 你自己添加的 Skill、MCP 条目、settings.json 字段
    · 你自己的 backup-* 备份目录（除非显式 -Purge）

  安全机制：
    · 默认交互确认；-Yes 跳过
    · 删除前把受影响文件整体备份到 ~/.pi/agent/backup-uninstall-<时间戳>/
    · -DryRun 只预览，不做任何修改
    · -Restore <备份目录> 反向恢复

  用法：
    powershell -ExecutionPolicy Bypass -File .\setup\uninstall.ps1 -DryRun
    powershell -ExecutionPolicy Bypass -File .\setup\uninstall.ps1
    powershell -ExecutionPolicy Bypass -File .\setup\uninstall.ps1 -Yes -KeepSkills
    powershell -ExecutionPolicy Bypass -File .\setup\uninstall.ps1 -Restore "<agent-root>\backup-uninstall-20261011-120000"
#>
[CmdletBinding()]
param(
    [switch]$DryRun,          # 只显示将要做什么，不做任何修改
    [switch]$Yes,             # 跳过交互确认
    [switch]$KeepSkills,      # 保留已安装的技能
    [switch]$KeepPrompts,     # 保留 AGENTS.md / SEEP.md / extensions
    [switch]$KeepMcp,         # 保留 mcp.json 中的工作台条目
    [switch]$KeepPackages,    # 保留 settings.json 中工作台加入的 packages
    [switch]$KeepLabFlag,     # 兼容旧参数；无法证明归属的 lab-mode.flag 始终保留
    [switch]$Purge,           # 同时清理 backup-* 备份目录与生成的配置
    [string]$Restore = '',     # 从指定备份目录恢复，而非卸载
    [string]$AgentRoot = ''    # 显式 Pi agent root
)

$ErrorActionPreference = 'Continue'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding = $utf8NoBom
$OutputEncoding = $utf8NoBom
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONUTF8 = '1'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$AgentDir  = $null
$SkillsDir = $null
$ExtDir    = $null
$McpJson   = $null
$SetJson   = $null
$LabFlag   = $null
$InstallManifest = $null

$script:Removed = 0
$script:Kept    = 0
$script:Failed  = 0

function Write-Step($m)  { Write-Host "`n>>> $m" -ForegroundColor Cyan }
function Write-Ok($m)    { Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn2($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }
function Write-Info($m)  { Write-Host "    [..] $m" -ForegroundColor Gray }
function Write-Fail($m)  { Write-Host "    [FAIL] $m" -ForegroundColor Red }

$runtimeBridge = Join-Path $Root 'Tool\scripts\runtime-root.py'
$resolveArgs = @($runtimeBridge, 'resolve')
if ($AgentRoot -ne '') { $resolveArgs += @('--agent-root', $AgentRoot) }
$resolveOutput = @(& python @resolveArgs 2>&1)
if ($LASTEXITCODE -ne 0) {
    Write-Fail "AgentRoot 无效或 runtime helper 不可用: $($resolveOutput -join ' ')"
    exit 1
}
try {
    $resolvedAgent = (($resolveOutput -join "`n") | ConvertFrom-Json)
    if (-not $resolvedAgent.ok -or [string]::IsNullOrWhiteSpace([string]$resolvedAgent.agent_root)) { throw 'resolver returned no agent root' }
    $AgentDir = [System.IO.Path]::GetFullPath([string]$resolvedAgent.agent_root)
} catch {
    Write-Fail "AgentRoot 解析结果无效: $($_.Exception.Message)"
    exit 1
}
$SkillsDir = Join-Path $AgentDir 'skills'
$ExtDir    = Join-Path $AgentDir 'extensions'
$McpJson   = Join-Path $AgentDir 'mcp.json'
$SetJson   = Join-Path $AgentDir 'settings.json'
$LabFlag   = Join-Path $AgentDir 'lab-mode.flag'
$InstallManifest = Join-Path $AgentDir 'seep-install-manifest.json'

$originPath = Join-Path $AgentDir 'seep-runtime.json'

$ownershipScript = @'
from pathlib import Path
import hashlib
import json
import os
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
                    # Keep an unreadable candidate only until backup. Deletion below
                    # re-hashes the current file and aborts this item on any drift.
                    owned[rel] = recorded

print(json.dumps({
    "ok": True,
    "manifest_recognized": recognized,
    "created_paths": sorted(set(created_paths)),
    "files": dict(sorted(owned.items())),
}, ensure_ascii=True))
'@
$ownershipRaw = @($ownershipScript | & python - $Root $AgentDir $InstallManifest 2>&1)
if ($LASTEXITCODE -ne 0) {
    Write-Fail "无法验证已安装资产，未修改任何内容: $($ownershipRaw -join ' ')"
    exit 1
}
try {
    $ownership = (($ownershipRaw -join "`n") | ConvertFrom-Json -ErrorAction Stop)
} catch {
    Write-Fail '安装资产所有权清单无法解析，未修改任何内容'
    exit 1
}
$script:OwnedFiles = @{}
if ($ownership.files) {
    foreach ($p in $ownership.files.PSObject.Properties) { $script:OwnedFiles[$p.Name] = [string]$p.Value }
}
$script:ManifestRecognized = [bool]$ownership.manifest_recognized
$script:ManifestCreatedPaths = @($ownership.created_paths)

# ---------------------------------------------------------------------------
# 读取 JSON（序数比较剥 BOM，避免 .NET 文化敏感比较误判）
# ---------------------------------------------------------------------------
function Read-JsonFile([string]$path) {
    if (-not (Test-Path $path)) { return $null }
    try {
        $raw = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
        if ($raw.Length -gt 0 -and [int]$raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
        return ($raw | ConvertFrom-Json)
    } catch {
        Write-Fail "解析失败: $path -> $($_.Exception.Message.Split([char]10)[0])"
        return $null
    }
}

function Get-FileSha256([string]$path) {
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($hash.ComputeHash($stream)) -replace '-', '').ToLowerInvariant()
    } finally {
        $hash.Dispose()
        $stream.Dispose()
    }
}

function Test-WorkbenchPrompt([string]$path) {
    if (-not (Test-Path $path)) { return $false }
    try {
        $text = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
        return ($text -match '<!--\s*seep:managed\b|Seep Reverse Lab|seep-reverse-lab|SEEP 工作台')
    } catch { return $false }
}

# ---------------------------------------------------------------------------
# 工作台「自有资产」清单 —— 与 install-pi.ps1 严格对齐
# ---------------------------------------------------------------------------
function Get-WorkbenchSkillNames {
    $names = @()
    $src = Join-Path $Root 'Tool\skill'
    if (-not (Test-Path $src)) { return $names }
    foreach ($s in (Get-ChildItem $src -Directory -ErrorAction SilentlyContinue)) {
        if ($s.Name.StartsWith('_')) { continue }
        if ($s.Name -eq 'safe-skills') {
            foreach ($sub in (Get-ChildItem $s.FullName -Directory -ErrorAction SilentlyContinue)) {
                $names += $sub.Name
            }
        } elseif ($s.Name -ne 'update') {
            $names += $s.Name
        }
    }
    return ($names | Select-Object -Unique)
}

# 工作台「自有扩展」白名单（与 install-pi.ps1 严格对齐）
# ★ 血案：旧实现无差别删除 ~/.pi/agent/extensions/*.ts，会把用户自己装的扩展
# （例如 cmd-guard.ts）一起删掉，违背"绝不碰你的数据"的承诺。
# 现在只删 Tool/prompts/extensions/ 里真实随包分发的资产，后缀范围与 install-pi.ps1
# 的 Copy-Item 一致（*.ts / *.json / *.md）。
$ExtAssetSuffixes = @('.ts', '.json', '.md')

function Get-WorkbenchExtensionNames {
    $names = @()
    $src = Join-Path $Root 'Tool\prompts\extensions'
    if (Test-Path $src) {
        # ★ 血案：`-Include` 参数不带 `-Recurse` 时**恒返回空**（PS 5.1 语义），
        #   于是白名单永远是空数组 → 扩展永远删不掉（卸载后残留，重装再叠加）。
        #   install-pi.ps1 只拷顶层 *.ts/*.json/*.md，这里按同一口径列顶层文件。
        foreach ($f in (Get-ChildItem $src -File -ErrorAction SilentlyContinue)) {
            if ($ExtAssetSuffixes -contains $f.Extension.ToLower()) { $names += $f.Name }
        }
    }
    return $names
}

# 工作台「自有 MCP 条目」清单：直接读**安装器用的那份**清单文件。
# ★ 血案：旧实现硬编码 seep / js-reverse / playwright 三个名字，但安装器实际会写 5 个
#   （含 ida / x64dbg）→ 卸完之后这两个条目永久残留任用户 mcp.json 里。
#   现在“安装器写什么，卸载就认什么”；新增 MCP 只改 json，两边自动对齐。
function Get-WorkbenchMcpNames {
    $names = @()
    $cfg = Read-JsonFile (Join-Path $Root 'Tool\config\mcp-servers.json')
    if ($cfg -and $cfg.servers) {
        foreach ($p in $cfg.servers.PSObject.Properties) { $names += $p.Name }
    }
    return @($names | Select-Object -Unique)
}
$WorkbenchMcpNames = @(Get-WorkbenchMcpNames)

# 条目认领的双重判据：① 名字在安装清单里 ② 命令/参数确实指向工作台。
# 只看名字会把用户自己建的同名条目一起删掉（违背「绝不碰你的数据」）。
$WorkbenchMcpMarkers = @('seep_mcp_server.py', 'js-reverse-mcp', '@playwright/mcp', 'mcp-launch.py')

function Test-McpEntryIsOurs([string]$name, $entry) {
    if ($WorkbenchMcpNames -notcontains $name) { return $false }
    $parts = @()
    if ($entry) {
        if ($entry.command) { $parts += [string]$entry.command }
        if ($entry.args) { $parts += @($entry.args | ForEach-Object { [string]$_ }) }
        if ($entry.url) { $parts += [string]$entry.url }
    }
    $argStr = ($parts -join ' ')
    if ([string]::IsNullOrWhiteSpace($argStr)) { return $false }
    $rootWin = "$Root"
    $rootPosix = $rootWin.Replace('\', '/')
    # 用 OrdinalIgnoreCase 的 IndexOf 而不是 -like：仓库路径里的 [] 会被当成通配符
    if ($argStr.IndexOf($rootWin, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    if ($argStr.IndexOf($rootPosix, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    foreach ($mk in $WorkbenchMcpMarkers) {
        if ($argStr.IndexOf($mk, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

$WorkbenchPackages = @(
    'npm:pi-open-tui', 'npm:pi-web-access', 'npm:@juicesharp/rpiv-todo',
    'npm:@narumitw/pi-btw', 'npm:@narumitw/pi-plan-mode', 'npm:@narumitw/pi-usage',
    'npm:pi-mcp-extension', 'npm:@smoose/pi-themes', 'npm:pi-tool-display',
    'npm:@juicesharp/rpiv-ask-user-question', 'npm:pi-playwright', 'npm:pi-goal-x'
)

$PersonaPackageSource = (Read-JsonFile (Join-Path $ScriptDir 'pi-persona-rewind.package.json')).source
$WorkbenchPackages += $PersonaPackageSource

# 只有参数中确实指向工作台组件时，才认定该 MCP 条目归工作台所有
# （实现见上方 Test-McpEntryIsOurs：清单名 + 路径/组件标记双重判据）

# ---------------------------------------------------------------------------
# 备份：把即将被删除/修改的文件整体拷进备份目录
# ---------------------------------------------------------------------------
function Backup-Item([string]$src, [string]$backupRoot, [string]$label) {
    if (-not (Test-Path $src)) { return }
    $dst = Join-Path $backupRoot $label
    $parent = Split-Path -Parent $dst
    if (-not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    try {
        Copy-Item $src $dst -Recurse -Force -ErrorAction Stop
        Write-Info "已备份: $label"
    } catch {
        Write-Fail "备份失败，停止卸载并保留原件: $label"
        $script:Failed++
    }
}

# ===========================================================================
# 模式 A：从备份恢复
# ===========================================================================
if ($Restore) {
    Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
    Write-Host "║   Seep 工作台 —— 从备份恢复                                   ║" -ForegroundColor Magenta
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta

    if (-not (Test-Path -LiteralPath $Restore -PathType Container)) {
        Write-Fail "备份目录不存在: $Restore"
        exit 1
    }
    $Restore = (Get-Item -LiteralPath $Restore -ErrorAction Stop).FullName.TrimEnd('\', '/')
    Write-Step "1/2  扫描备份内容"
    $items = @(Get-ChildItem -LiteralPath $Restore -Recurse -Force -ErrorAction Stop)
    Write-Info "备份目录: $Restore"
    Write-Info "条目数: $($items.Count)"

    Write-Step "2/2  恢复"
    if ($DryRun) {
        foreach ($i in $items) { Write-Info "将恢复: $($i.FullName.Substring($Restore.Length).TrimStart('\'))" }
        Write-Warn2 '-DryRun 模式，未做任何修改'
        exit 0
    }
    $restored = 0
    foreach ($i in $items) {
        $rel = $i.FullName.Substring($Restore.Length).TrimStart('\')
        $dst = Join-Path $AgentDir $rel
        try {
            if ($i.PSIsContainer) {
                if (-not (Test-Path $dst)) { New-Item -ItemType Directory -Path $dst -Force -ErrorAction Stop | Out-Null }
            } else {
                $p = Split-Path -Parent $dst
                if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force -ErrorAction Stop | Out-Null }
                Copy-Item $i.FullName $dst -Force -ErrorAction Stop
                $restored++
            }
        } catch { Write-Fail "恢复失败: $rel"; $script:Failed++ }
    }
    Write-Ok "已恢复 $restored 个文件"
    Write-Info "请完全重启 Agent 会话后生效"
    if ($script:Failed -gt 0) { exit 1 }
    exit 0
}

# ===========================================================================
# 模式 B：卸载
# ===========================================================================
$validateArgs = @($runtimeBridge, 'validate', '--agent-root', $AgentDir, '--runtime-root', $Root)
$validateOutput = @(& python @validateArgs 2>&1)
if ($LASTEXITCODE -eq 0) {
    Write-Info 'runtime 注册有效，并与当前 source root 一致'
} else {
    Write-Warn2 "runtime 注册缺失或损坏；将依据安装所有权清单和逐文件哈希执行安全清理: $($validateOutput -join ' ')"
    if (-not $script:ManifestRecognized -and $script:OwnedFiles.Count -eq 0) {
        Write-Warn2 '未找到可信安装清单；只处理配置中的明确工作台条目，无法证明所有权的文件全部保留'
    }
}

& python (Join-Path $ScriptDir 'merge_agent_config.py') --root $Root --agent-dir $AgentDir --validate-configs-only
if ($LASTEXITCODE -ne 0) { Write-Fail '配置无效，尚未移除任何项目'; exit 1 }
if (-not $KeepPrompts) {
    & python (Join-Path $ScriptDir 'merge_agent_config.py') --root $Root --agent-dir $AgentDir --remove-prompts-only --dry-run
    if ($LASTEXITCODE -ne 0) { Write-Fail '提示词边界无效，尚未移除任何项目'; exit 1 }
}
Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║   Seep 逆向工程工作台 —— 一键卸载                             ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
if ($DryRun) { Write-Warn2 'DRY-RUN 模式：只预览，不做任何修改' }

# ---------------------------------------------------------------- 1. 盘点
Write-Step '1/5  盘点将要移除的内容'
$plan = [ordered]@{}

$managedFileHits = @($script:OwnedFiles.Keys | Sort-Object)
$skillHits = @()
$taskHits = @()
$agentHits = @()
$extensionHits = @()
foreach ($rel in $managedFileHits) {
    if ($rel.StartsWith('skills/') -and -not $KeepSkills) {
        $skillHits += (($rel -split '/')[1])
    } elseif ($rel.StartsWith('prompts/') -and -not $KeepPrompts) {
        $taskHits += $rel
    } elseif ($rel.StartsWith('agents/') -and -not $KeepPrompts) {
        $agentHits += $rel
    } elseif ($rel.StartsWith('extensions/') -and -not $KeepPrompts) {
        $extensionHits += $rel
    }
}
$skillHits = @($skillHits | Sort-Object -Unique)
$plan['技能 (skills)'] = $skillHits
$plan['任务卡 (prompts)'] = $taskHits
$plan['子代理定义 (agents)'] = $agentHits
$plan['安全扩展 (extensions)'] = $extensionHits

$promptHits = @()
if (-not $KeepPrompts) {
    foreach ($f in @('AGENTS.md', 'SEEP.md', 'SYSTEM.md')) {
        $promptPath = Join-Path $AgentDir $f
        if (Test-WorkbenchPrompt $promptPath) { $promptHits += $f }
    }
}
$plan['提示词管理块'] = $promptHits

$mcpCfg = Read-JsonFile $McpJson
$mcpHits = @()
if ((-not $KeepMcp) -and $mcpCfg -and $mcpCfg.mcpServers) {
    foreach ($p in $mcpCfg.mcpServers.PSObject.Properties) {
        if (Test-McpEntryIsOurs $p.Name $p.Value) { $mcpHits += $p.Name }
    }
}
$plan['MCP 条目'] = $mcpHits

$setCfg = Read-JsonFile $SetJson
$pkgHits = @()
if ((-not $KeepPackages) -and $setCfg -and $setCfg.packages) {
    foreach ($pkg in @($setCfg.packages)) {
        $source = if ($pkg -is [string]) { $pkg } else { $pkg.source }
        if (($pkg -is [string] -and $WorkbenchPackages -contains $pkg) -or $source -eq $PersonaPackageSource) {
            $pkgHits += $source
        }
    }
}
if (-not $KeepPackages -and (Test-Path (Join-Path $AgentDir 'packages/pi-seep-ext')) -and
    $pkgHits -notcontains $PersonaPackageSource) { $pkgHits += $PersonaPackageSource }
$plan['settings packages'] = $pkgHits

$flagHits = @()
# The current installer neither creates nor registers lab-mode.flag. A
# pre-existing flag is therefore user state, not workbench ownership. Legacy
# installs without explicit ownership metadata remain protected as well.
if ((-not $KeepLabFlag) -and (Test-Path $LabFlag)) {
    Write-Info '保留 lab-mode.flag：安装清单不能证明该文件由工作台创建'
}
$plan['实验环境标志'] = $flagHits

$originHits = @()
if (Test-Path $originPath) { $originHits += 'seep-runtime.json' }
$plan['runtime registration'] = $originHits

$manifestHits = @()
if ((Test-Path $InstallManifest) -and -not $KeepPackages) { $manifestHits += 'seep-install-manifest.json' }
$plan['install ownership manifest'] = $manifestHits

$agentSettingsHits = @()
if ($script:ManifestCreatedPaths -contains 'agents/settings.json' -and
    (Test-Path (Join-Path $AgentDir 'agents\settings.json'))) {
    $agentSettingsHits += 'agents/settings.json'
}
$plan['agent settings ownership'] = $agentSettingsHits

foreach ($k in $plan.Keys) {
    $v = $plan[$k]
    if ($v.Count -eq 0) { Write-Info "$k : （无）" }
    else { Write-Ok "$k : $($v.Count) 项 -> $($v -join ', ')" }
}

# 保护声明
Write-Step '2/5  用户自有数据保护声明'
foreach ($f in @('models.json', 'auth.json', 'sessions/', 'logs/')) {
    if (Test-Path (Join-Path $AgentDir $f)) { Write-Ok "保留: $f" }
}
$userMcp = @()
if ($mcpCfg -and $mcpCfg.mcpServers) {
    foreach ($p in $mcpCfg.mcpServers.PSObject.Properties) {
        if (-not (Test-McpEntryIsOurs $p.Name $p.Value)) { $userMcp += $p.Name }
    }
}
if ($userMcp.Count -gt 0) { Write-Ok "保留你自己的 MCP 条目: $($userMcp -join ', ')" }
$userSkills = @()
$skillNames = @(Get-WorkbenchSkillNames)
if (Test-Path $SkillsDir) {
    foreach ($d in (Get-ChildItem $SkillsDir -Directory -ErrorAction SilentlyContinue)) {
        if ($skillNames -notcontains $d.Name) { $userSkills += $d.Name }
    }
}
if ($userSkills.Count -gt 0) { Write-Ok "保留你自己安装的技能: $($userSkills -join ', ')" }

$totalToRemove = 0
foreach ($k in $plan.Keys) { $totalToRemove += $plan[$k].Count }
if ($totalToRemove -eq 0) {
    Write-Host "`n[√] 没有发现需要移除的工作台内容，系统已是干净状态。" -ForegroundColor Green
    exit 0
}

if ($DryRun) {
    Write-Host "`n[DRY-RUN] 以上 $totalToRemove 项将被移除，未做任何修改。" -ForegroundColor Yellow
    Write-Info '去掉 -DryRun 参数即可真正执行'
    exit 0
}

# ---------------------------------------------------------------- 3. 确认
if (-not $Yes) {
    Write-Host "`n即将移除以上 $totalToRemove 项。你的数据（模型凭据 / 自定义配置）不会被触碰。" -ForegroundColor Yellow
    $ans = Read-Host '确认卸载？输入 yes 继续'
    if ($ans -notin @('yes', 'y', 'Y', 'YES')) { Write-Info '已取消'; exit 0 }
}

# ---------------------------------------------------------------- 4. 执行
Write-Step '3/5  备份受影响文件'
$stamp = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N')
$backupRoot = Join-Path $AgentDir "backup-uninstall-$stamp"
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
Write-Info "备份目录: $backupRoot"

$fileHitsToRemove = @($taskHits + $agentHits + $extensionHits)
foreach ($rel in @($script:OwnedFiles.Keys)) {
    if ($skillHits.Count -gt 0 -and $rel.StartsWith('skills/')) {
        $fileHitsToRemove += $rel
    }
}
foreach ($rel in @($fileHitsToRemove | Sort-Object -Unique)) {
    Backup-Item (Join-Path $AgentDir ($rel -replace '/', '\')) $backupRoot $rel
}
foreach ($f in @('AGENTS.md', 'SEEP.md', 'SYSTEM.md')) {
    if ($promptHits -contains $f) { Backup-Item (Join-Path $AgentDir $f) $backupRoot $f }
}
if ($mcpHits.Count -gt 0 -or $pkgHits.Count -gt 0) {
    Backup-Item $McpJson $backupRoot 'mcp.json'
    Backup-Item $SetJson $backupRoot 'settings.json'
}
if ($flagHits.Count -gt 0) { Backup-Item $LabFlag $backupRoot 'lab-mode.flag' }
if ($originHits.Count -gt 0) { Backup-Item $originPath $backupRoot 'seep-runtime.json' }
if ($manifestHits.Count -gt 0) { Backup-Item $InstallManifest $backupRoot 'seep-install-manifest.json' }
if ($agentSettingsHits.Count -gt 0) {
    Backup-Item (Join-Path $AgentDir 'agents\settings.json') $backupRoot 'agents/settings.json'
}

Write-Step '4/5  执行移除'
if ($script:Failed -gt 0) { Write-Fail '备份未完整成功，尚未移除任何项目'; exit 1 }
foreach ($rel in @($fileHitsToRemove | Sort-Object -Unique)) {
    $p = Join-Path $AgentDir ($rel -replace '/', '\')
    try {
        if (Test-Path $p) {
            $expectedHash = [string]$script:OwnedFiles[$rel]
            $actualHash = Get-FileSha256 $p
            if ($actualHash -ne $expectedHash) {
                Write-Warn2 "文件与安装清单哈希不一致，已保留: $rel"
                continue
            }
            Remove-Item -LiteralPath $p -Force -ErrorAction Stop
            Write-Ok "已移除: $rel"; $script:Removed++
            if ($rel.StartsWith('skills/')) {
                # Prune only ancestors of the file just removed. Sweeping all
                # empty directories would also delete unrelated user skills.
                $skillsRootFull = [System.IO.Path]::GetFullPath($SkillsDir).TrimEnd('\', '/')
                $parentFull = [System.IO.Path]::GetFullPath((Split-Path -Parent $p))
                $skillsPrefix = $skillsRootFull + [System.IO.Path]::DirectorySeparatorChar
                while ($parentFull.StartsWith($skillsPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $parentInfo = Get-Item -LiteralPath $parentFull -Force -ErrorAction SilentlyContinue
                    if (-not $parentInfo -or
                        (($parentInfo.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
                        @(Get-ChildItem -LiteralPath $parentFull -Force -ErrorAction SilentlyContinue).Count -gt 0) {
                        break
                    }
                    try { Remove-Item -LiteralPath $parentFull -Force -ErrorAction Stop }
                    catch { break }
                    $parentFull = [System.IO.Path]::GetDirectoryName($parentFull)
                }
            }
        }
    } catch { Write-Fail "移除失败: $rel ($($_.Exception.Message))"; $script:Failed++ }
}
if ($promptHits -contains 'AGENTS.md' -or $promptHits -contains 'SEEP.md') {
    try {
        & python (Join-Path $ScriptDir 'merge_agent_config.py') --root $Root --agent-dir $AgentDir --remove-prompts-only
        if ($LASTEXITCODE -ne 0) { throw 'managed prompt removal failed' }
        Write-Ok '已移除工作台管理的提示词块（用户追加文本保留）'
    } catch { Write-Fail "提示词块清理失败: $($_.Exception.Message)"; $script:Failed++ }
}

# MCP：外科手术式移除，保留用户其他条目
if ($mcpHits.Count -gt 0) {
    try {
        $removeArgs = @((Join-Path $ScriptDir 'merge_agent_config.py'), '--root', $Root, '--agent-dir', $AgentDir, '--remove-mcp') + @($mcpHits)
        & python @removeArgs
        if ($LASTEXITCODE -ne 0) { throw 'MCP configuration cleanup failed' }
        Write-Ok "已移除 MCP 条目: $($mcpHits -join ', ')"
        $script:Removed += $mcpHits.Count
    } catch { Write-Fail "mcp.json 清理失败: $($_.Exception.Message)"; $script:Failed++ }
}

# settings.json：只移除工作台加入的 packages
if ($pkgHits.Count -gt 0) {
    try {
        & python (Join-Path $ScriptDir 'merge_agent_config.py') --root $Root --agent-dir $AgentDir --remove-packages
        if ($LASTEXITCODE -ne 0) { throw 'package configuration cleanup failed' }
        Write-Ok "已从 settings.json 移除 $($pkgHits.Count) 个 packages"
        $script:Removed += $pkgHits.Count
    } catch { Write-Fail "settings.json 清理失败: $($_.Exception.Message)"; $script:Failed++ }
}

if ($flagHits.Count -gt 0) {
    try {
        Remove-Item $LabFlag -Force -ErrorAction Stop
        Write-Ok '已移除 lab-mode.flag（实验环境已退出）'; $script:Removed++
    } catch { Write-Fail '移除 lab-mode.flag 失败'; $script:Failed++ }
}

if ($agentSettingsHits.Count -gt 0) {
    $agentSettingsPath = Join-Path $AgentDir 'agents\settings.json'
    if (Test-Path $agentSettingsPath) {
        $agentSettingsScript = @'
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
'@
        try {
            $agentSettingsScript | & python - $agentSettingsPath
            if ($LASTEXITCODE -ne 0) { throw 'managed agent settings cleanup failed' }
            Write-Ok '已清理安装器创建的 agents/settings.json（用户字段保留）'
            $script:Removed++
        } catch { Write-Fail "agents/settings.json 清理失败: $($_.Exception.Message)"; $script:Failed++ }
    }
}

if ($originHits.Count -gt 0 -and $script:Failed -eq 0) {
    try {
        Remove-Item $originPath -Force -ErrorAction Stop
        Write-Ok '已移除 runtime 注册（source runtime 保留）'; $script:Removed++
    } catch { Write-Fail '移除 runtime 注册失败'; $script:Failed++ }
}
if ($manifestHits.Count -gt 0 -and $script:Failed -eq 0) {
    try {
        Remove-Item $InstallManifest -Force -ErrorAction Stop
        Write-Ok '已移除安装所有权清单'
        $script:Removed++
    } catch { Write-Fail '移除安装所有权清单失败'; $script:Failed++ }
}

# ---------------------------------------------------------------- 5. 可选深度清理
if ($Purge) {
    Write-Step '5/5  深度清理 (-Purge)'
    $purged = 0
    foreach ($b in (Get-ChildItem $AgentDir -Directory -Filter 'backup-*' -ErrorAction SilentlyContinue)) {
        if ($b.FullName -eq $backupRoot) { continue }  # 保留本次卸载备份
        try { Remove-Item $b.FullName -Recurse -Force -ErrorAction Stop; $purged++ }
        catch { Write-Warn2 "无法删除: $($b.Name)" }
    }
    Write-Info 'source runtime 与用户级状态均保留；Purge 只处理安装器在该 AgentRoot 下的旧备份'
    Write-Ok "深度清理完成，共 $purged 项（本次卸载备份已保留）"
} else {
    Write-Step '5/5  深度清理'
    Write-Info '未启用 -Purge，历史备份与生成配置均已保留'
}

# ---------------------------------------------------------------- 报告
Write-Host "`n╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Green
if ($script:Failed -gt 0) { Write-Fail '卸载未完成，runtime 注册保留，关闭占用进程后重试' }
else { Write-Host "║   卸载完成                                                    ║" -ForegroundColor Green }
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Ok "已移除: $($script:Removed) 项"
if ($script:Failed -gt 0) { Write-Fail "失败: $($script:Failed) 项（多为文件被占用，关闭 Agent 后重试）" }
Write-Info "卸载备份: $backupRoot"
Write-Info "如需恢复: powershell -File .\setup\uninstall.ps1 -Restore `"$backupRoot`""
Write-Host ''
Write-Info '工作台本体目录未删除。若确认不再需要，可手动删除整个工作台文件夹。'
Write-Info '请完全重启 Agent 会话，使卸载生效。'
if ($script:Failed -gt 0) { exit 1 }
exit 0
