#Requires -Version 5.1
<#
  Seep 逆向工程工作台 —— 一键安装总控 (加强交互与无损部署版)
  包含：
    1. 解压离线依赖 (node_modules.zip)
    2. Python 协议依赖安装
    3. Pi Agent / Claude Code / DSH / OpenCode 配置生成
    4. 智能 IDA Pro 探测与自定义路径交互引导
    5. 全维度健康核验
#>
[CmdletBinding()]
param(
    [string]$IdaRoot = '',        # 自定义 IDA Pro 安装目录
    [switch]$SkipPython,          # 跳过 Python 依赖
    [switch]$SkipPi,              # 跳过 pi 环境配置
    [switch]$SkipTools,           # 跳过 IDA Pro 配置
    [switch]$OnlyVerify,          # 仅跑自检
    [switch]$NonInteractive,       # 非交互静默模式
    [switch]$SkipPackages,         # 离线模式：跳过 Pi/离线包安装
    [string]$AgentRoot = ''        # 显式 Pi agent root
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

$script:Failed = @()

# Match the executable name written into host configs before invoking helpers.
& python -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>$null
if (-not $? -or $LASTEXITCODE -ne 0) {
    Write-Host '    [FAIL] 需要可通过 python 命令运行的 Python 3.11+，请安装并加入 PATH。' -ForegroundColor Red
    exit 1
}

function Write-Step($title) {
    Write-Host "`n>>> $title" -ForegroundColor Cyan
}

function Write-Ok($msg) {
    Write-Host "    [OK] $msg" -ForegroundColor Green
}

function Write-Warn($msg) {
    Write-Host "    [!!] $msg" -ForegroundColor Yellow
}

function Write-Err($msg) {
    Write-Host "    [FAIL] $msg" -ForegroundColor Red
}

$runtimeBridge = Join-Path $Root 'Tool\scripts\runtime-root.py'
$resolveArgs = @($runtimeBridge, 'resolve')
if ($AgentRoot -ne '') { $resolveArgs += @('--agent-root', $AgentRoot) }
$resolveOutput = @(& python @resolveArgs 2>&1)
if ($LASTEXITCODE -ne 0) {
    Write-Err "AgentRoot 无效或 runtime helper 不可用: $($resolveOutput -join ' ')"
    exit 1
}
try {
    $resolvedAgent = (($resolveOutput -join "`n") | ConvertFrom-Json)
    if (-not $resolvedAgent.ok -or [string]::IsNullOrWhiteSpace([string]$resolvedAgent.agent_root)) { throw 'resolver returned no agent root' }
    $AgentDir = [System.IO.Path]::GetFullPath([string]$resolvedAgent.agent_root)
} catch {
    Write-Err "AgentRoot 解析结果无效: $($_.Exception.Message)"
    exit 1
}

$env:PI_CODING_AGENT_DIR = $AgentDir

function Test-Environment {
    Write-Step '检测基础运行环境'

    # Python
    $py = Get-Command python -ErrorAction SilentlyContinue
    if ($py) {
        $ver = & python --version 2>&1
        Write-Ok "Python 可用: $ver ($($py.Source))"
    } else {
        Write-Err '未找到 Python。请安装 Python 3.11+ 并勾选 Add to PATH'
        $script:Failed += 'Python'
    }

    # Node.js
    $node = Get-Command node -ErrorAction SilentlyContinue
    if ($node) {
        $ver = & node --version 2>&1
        Write-Ok "Node.js 可用: $ver"
    } elseif ($SkipPi -or $SkipPackages) {
        Write-Host '    [SKIP] 未找到 Node.js；已指定 -SkipPi/-SkipPackages，只同步不依赖 Node 的配置'
    } else {
        Write-Err 'Pi 需要 Node.js；请先从 https://nodejs.org 安装 LTS 后重跑安装器'
        $script:Failed += 'Node.js'
    }

    # Git
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        $ver = & git --version 2>&1
        Write-Ok "Git 可用: $ver"
    } else {
        Write-Warn '未找到 Git'
    }

    # 内置工具检查
    $toolsDir = Join-Path $Root 'Tool\mcp\Tool\safe'
    if (Test-Path $toolsDir) {
        $need = @('Tool\mcp\Tool\safe\radare2\bin\radare2.exe',
                  'Tool\mcp\Tool\safe\jadx\bin\jadx.bat',
                  'Tool\mcp\Tool\safe\apktool\apktool.jar',
                  'Tool\mcp\Tool\reverselab\kb')
        $miss = @()
        foreach ($n in $need) { if (-not (Test-Path (Join-Path $Root $n))) { $miss += $n } }
        if ($miss.Count -eq 0) { Write-Ok '内置离线逆向工具箱完整' }
        else { Write-Warn "内置工具缺失 $($miss.Count) 项（可用 repair-tools.ps1 修复）" }
    }
}

# ---------------------------------------------------------------- 主流程
Write-Host @"
================================================================
  Seep 逆向工程工作台 — 官方部署流水线 (Installer)
================================================================
  工作台物理根目录: $Root
"@ -ForegroundColor White

if ($OnlyVerify) {
    & python (Join-Path (Split-Path $ScriptDir -Parent) "Tool/scripts/check.py") --env
    exit $LASTEXITCODE
}

# 首次部署：解压 node_modules（GitHub clone 后只需一次）
if (-not $SkipPackages -and ((-not (Test-Path (Join-Path $Root 'Tool\mcp\Tool\safe\js-reverse-mcp\node_modules'))) -or
    (-not (Test-Path (Join-Path $Root 'Tool\mcp\Tool\safe\playwright-mcp\node_modules'))) -or
    (-not (Test-Path (Join-Path $Root 'Tool\mcp\Tool\safe\ida-pro-mcp\.venv'))))) {
    Write-Step '解压离线依赖包（首次部署）'
    & (Join-Path $ScriptDir 'extract-deps.ps1')
    if ($LASTEXITCODE -ne 0) { $script:Failed += 'extract-deps' }
} elseif ($SkipPackages) {
    Write-Host '    [SKIP] 已指定 -SkipPackages，跳过离线依赖包解压'
}

Test-Environment

if ($script:Failed.Count -gt 0) {
    Write-Err "环境检测失败: $($script:Failed -join ', ')"
    Write-Host "`n请先解决上述问题（见 Tool\docs\BOOTSTRAP.md），然后重新运行。" -ForegroundColor Yellow
    exit 1
}

if (-not $SkipPython) {
    Write-Step '安装 Python 协议依赖'
    & (Join-Path $ScriptDir 'install-python.ps1')
    if ($LASTEXITCODE -ne 0) { $script:Failed += 'python-deps' }
}

if (-not $SkipPi) {
    Write-Step '配置 Pi Agent 环境 (增量合并 mcp.json 与 settings.json)'
    $piParams = @{ AgentRoot = $AgentDir }
    if ($SkipPackages) { $piParams['SkipPackages'] = $true }
    & (Join-Path $ScriptDir 'install-pi.ps1') @piParams
    if ($LASTEXITCODE -ne 0) { $script:Failed += 'pi' }
}

# 自动生成 Claude / OpenCode / DSH 配置文件
Write-Step '生成多 Agent 配置文件 (.mcp.json / opencode.jsonc / cordis.generated.yml)'
& (Join-Path $ScriptDir 'generate-configs.ps1')
if ($LASTEXITCODE -ne 0) { $script:Failed += 'generate-configs' }

if (-not $SkipTools) {
    Write-Step '配置与探测 IDA Pro（商业软件，需自备授权）'
    $idaParams = @{ AgentRoot = $AgentDir }
    if ($SkipPython -or $SkipPackages) { $idaParams['SkipPip'] = $true }
    if ($IdaRoot -ne '') { $idaParams['IdaRoot'] = $IdaRoot }
    if (-not $NonInteractive) { $idaParams['Interactive'] = $true }
    & (Join-Path $ScriptDir 'install-ida.ps1') @idaParams
    # 未发现可选 IDA 返回 0；明确的配置/写入失败必须计入部署结果。
    if ($LASTEXITCODE -ne 0) { $script:Failed += 'ida-config' }
}

Write-Step '执行环境体检 (python Tool/scripts/check.py --env)'
# ★ 这一步的退出码就是「部署到底成没成」的唯一输入。
#   血案：旧版把 check.py 的退出码直接丢掉，于是体检全红也照样打印
#   「🎉 全套组件已部署完成」—— 对客户说假话，属于最伤信任的一类缺陷。
$envOut = @()
& python (Join-Path (Split-Path $ScriptDir -Parent) "Tool/scripts/check.py") --env | ForEach-Object {
    $envOut += "$_"
    Write-Host "    $_"
}
$envRc = $LASTEXITCODE

# 体检失败项数：优先读 env-check.py 的「缺 N 项」，读不到就至少记 1（有失败就有失败项）
$envFailCount = 0
$m = [regex]::Match(($envOut -join "`n"), '缺\s*(\d+)\s*项')
if ($m.Success) { $envFailCount = [int]$m.Groups[1].Value }
elseif ($envRc -ne 0) { $envFailCount = 1 }

$deployOk = ($envRc -eq 0 -and $script:Failed.Count -eq 0)

# ---------------------------------------------------------------- 总结
Write-Host "`n=================================================================" -ForegroundColor White
if ($deployOk) {
    Write-Host '  [OK] 受管组件已同步，当前 Pi 环境检查通过。' -ForegroundColor Green
} else {
    if ($script:Failed.Count -gt 0) {
        Write-Host "  [!!] 部分步骤失败: $($script:Failed -join ', ')" -ForegroundColor Yellow
    }
    if ($envRc -ne 0) {
        Write-Host "  ⚠ 部署未完成：体检有 $envFailCount 项未通过（见上）" -ForegroundColor Red
        Write-Host '     按上方「下一步」处理，并使用相同 AgentRoot 重新检查；仅缺模型登录时无需重装。' -ForegroundColor Yellow
    }
}
Write-Host "=================================================================" -ForegroundColor White

if ($deployOk) {
    Write-Host @"

开工指南:
  1) 以相同 AgentRoot 新开宿主会话，确认技能、扩展与 MCP 实际加载。
  2) 用自然语言说明目标和材料；lab：是可选 Pi 交互。其他宿主接入需另行验证。
  3) 上传 GitHub / 交付客户前: python Tool/scripts/pre-upload-check.py

"@ -ForegroundColor Cyan
} else {
    Write-Host "`n当前安装环境未就绪。按上方缺项与下一步处理，再对相同 AgentRoot 运行环境检查。" -ForegroundColor Yellow
}

exit ($(if ($deployOk) { 0 } else { 1 }))
