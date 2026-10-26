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
    [switch]$NonInteractive       # 非交互静默模式
)

$ErrorActionPreference = 'Continue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$AgentDir  = Join-Path $env:USERPROFILE '.pi\agent'

$script:Failed = @()

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
    } else {
        Write-Warn '未找到 Node.js（可选，用于 JS 逆向与 Playwright 自动化）'
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
if (-not (Test-Path (Join-Path $Root 'Tool\mcp\Tool\safe\js-reverse-mcp\node_modules')) -or
    -not (Test-Path (Join-Path $Root 'Tool\mcp\Tool\safe\playwright-mcp\node_modules'))) {
    Write-Step '解压离线依赖包（首次部署）'
    & (Join-Path $ScriptDir 'extract-deps.ps1')
}

Test-Environment

if ($script:Failed.Count -gt 0) {
    Write-Err "环境检测失败: $($script:Failed -join ', ')"
    Write-Host "`n请先解决上述问题（见 MANUAL\PREREQUISITES.md），然后重新运行。" -ForegroundColor Yellow
    exit 1
}

if (-not $SkipPython) {
    Write-Step '安装 Python 协议依赖'
    & (Join-Path $ScriptDir 'install-python.ps1')
    if ($LASTEXITCODE -ne 0) { $script:Failed += 'python-deps' }
}

if (-not $SkipPi) {
    Write-Step '配置 Pi Agent 环境 (增量合并 mcp.json 与 settings.json)'
    & (Join-Path $ScriptDir 'install-pi.ps1')
    if ($LASTEXITCODE -ne 0) { $script:Failed += 'pi' }
}

# 自动生成 Claude / OpenCode / DSH 配置文件
Write-Step '生成多 Agent 配置文件 (.mcp.json / opencode.jsonc / cordis.generated.yml)'
& (Join-Path $ScriptDir 'generate-configs.ps1')

if (-not $SkipTools) {
    Write-Step '配置与探测 IDA Pro（商业软件，需自备授权）'
    $idaParams = @{}
    if ($IdaRoot -ne '') { $idaParams['IdaRoot'] = $IdaRoot }
    if (-not $NonInteractive) { $idaParams['Interactive'] = $true }
    & (Join-Path $ScriptDir 'install-ida.ps1') @idaParams
    # IDA 缺失不算失败（有免费 Radare2 替代路线）
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
    Write-Host '  🎉 恭喜！Seep 工作台全套组件已部署完成！' -ForegroundColor Green
} else {
    if ($script:Failed.Count -gt 0) {
        Write-Host "  [!!] 部分步骤失败: $($script:Failed -join ', ')" -ForegroundColor Yellow
    }
    if ($envRc -ne 0) {
        Write-Host "  ⚠ 部署未完成：体检有 $envFailCount 项未通过（见上）" -ForegroundColor Red
        Write-Host '     修好后重跑: powershell -ExecutionPolicy Bypass -File setup\install.ps1' -ForegroundColor Yellow
    }
}
Write-Host "=================================================================" -ForegroundColor White

if ($deployOk) {
    Write-Host @"

开工指南:
  1) 双击根目录 start.bat 打开会话（或自己启动 Agent：Pi / Claude Code / DSH / OpenCode）
  2) 在对话框中输入:  lab： 即可开启白盒测试！
  3) 上传 GitHub / 交付客户前: python Tool/scripts/pre-upload-check.py

"@ -ForegroundColor Cyan
} else {
    Write-Host "`n部署未完成，先修完上面的失败项再开工（体检明细见上方 python Tool/scripts/check.py --env 输出）。" -ForegroundColor Yellow
}

exit ($(if ($deployOk) { 0 } else { 1 }))
