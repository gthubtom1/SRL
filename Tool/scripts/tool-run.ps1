#Requires -Version 5.1
<#
  tool-run.ps1 —— 通用「工具运行阶梯」执行器

  设计原则（长期，与 AGENTS.md §四点五.5 一致）：
    通道优先级 = 工具自带 MCP/stdio > CLI/headless > GUI(+MCP) > 人工
    只要 headless / CLI 能把事做完，就绝不启动 GUI。

  为什么用配置驱动：工具会越来越多（x64dbg / x32dbg / IDA / Ghidra / JEB / Binary Ninja / dnSpy …）。
  把"它能被 AI 控制哪些通道、每个通道怎么起、怎么判断就绪"写进 Tool/config/tool-runtimes.json，
  脚本本身零工具名、零绝对路径 —— 新增工具只加一条，不用改代码。

  用法：
    powershell -File Tool/scripts/tool-run.ps1 -ListModes                 # 看全量阶梯
    powershell -File Tool/scripts/tool-run.ps1 -Tool ida -ListModes        # 看单个工具
    powershell -File Tool/scripts/tool-run.ps1 -Tool x64dbg [-Target <样本>]
    powershell -File Tool/scripts/tool-run.ps1 -Tool ida -Mode headless-cli -Target <样本>   # 只打印命令
    powershell -File Tool/scripts/tool-run.ps1 -Tool ghidra -Mode cli-headless -Target <样本> -Run

  退出码：0=就绪或已打印命令 / 2=配置或路径缺失 / 3=启动失败 / 4=等待超时 / 5=没有可用通道
#>
[CmdletBinding()]
param(
    [string]$Tool = '',
    [string]$Target = '',
    [string]$Mode = '',
    [switch]$ListModes,
    [switch]$Run,
    [int]$TimeoutSec = 0
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$ConfigPath = Join-Path $Root 'Tool\config\tool-runtimes.json'
$PyDir = Join-Path $Root 'Tool\mcp'

function Out-Json($obj) { $obj | ConvertTo-Json -Depth 8 -Compress }

if (-not (Test-Path $ConfigPath)) { Out-Json @{ status = 'ERR'; reason = "缺少 $ConfigPath" }; exit 2 }
$cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json

# ---------------------------------------------------------------- ListModes
if ($ListModes) {
    $names = if ($Tool) { @($Tool) } else { @($cfg.tools.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($n in $names) {
        $t = $cfg.tools.$n
        if (-not $t) { continue }
        Write-Output ("== $n   prefer: " + ($t.prefer -join ' > '))
        foreach ($m in $t.modes) {
            $r = if ($m.ready) { "port " + $m.ready.port } else { 'cli' }
            Write-Output ("   - {0,-14} [{1,-9}] {2}  ({3})" -f $m.id, $m.kind, $m.why, $r)
            if ($m.knownIssue) { Write-Output ("       ! " + $m.knownIssue) }
        }
    }
    exit 0
}

if (-not $Tool) { Out-Json @{ status = 'ERR'; reason = '需要 -Tool <id> 或 -ListModes' }; exit 2 }
$toolCfg = $cfg.tools.$Tool
if (-not $toolCfg) { Out-Json @{ status = 'ERR'; reason = "tool-runtimes.json 里没有 '$Tool'" }; exit 2 }

# ---------------------------------------------------------------- 工具函数
function Resolve-ToolExe([string]$toolId, $exeCandidates) {
    $found = ''
    try {
        $py = (Get-Command python -ErrorAction SilentlyContinue).Source
        if ($py) {
            $code = "import sys;sys.path.insert(0,r'$PyDir');import tool_autodiscover as A;r=A.discover(r'$toolId', use_registry=False);print(r.get('command') or '')"
            $found = (& $py -c $code 2>$null | Select-Object -Last 1)
        }
    } catch { }
    if (-not $found -and $exeCandidates) {
        foreach ($n in $exeCandidates) {
            $g = (Get-Command $n -ErrorAction SilentlyContinue).Source
            if ($g) { $found = $g; break }
        }
    }
    if ($found -and $exeCandidates) {
        foreach ($n in $exeCandidates) {
            $alt = Join-Path (Split-Path -Parent $found) $n
            if (Test-Path $alt) { return $alt }
        }
    }
    return $found
}

function Test-Port([int]$p, [int]$ms = 800) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect('127.0.0.1', $p, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($ms)) { return $false }
        $client.EndConnect($iar); return $true
    } catch { return $false } finally { $client.Close() }
}

$modes = $toolCfg.modes
if ($Mode) {
    $modes = @($toolCfg.modes | Where-Object { $_.id -eq $Mode })
    if (-not $modes) { Out-Json @{ status = 'ERR'; reason = "'$Tool' 没有模式 '$Mode'" }; exit 2 }
}

# ---------------------------------------------------------------- 逐个通道尝试
foreach ($m in $modes) {
    # CLI 通道：只解析并打印命令（-Run 才真执行）
    if ($m.kind -eq 'cli') {
        $tid = if ($m.toolId) { $m.toolId } else { $Tool }
        $exe = Resolve-ToolExe $tid $m.fallbackExe
        if (-not $exe -and $m.fallbackExe) {
            foreach ($n in $m.fallbackExe) { $g = (Get-Command $n -ErrorAction SilentlyContinue).Source; if ($g) { $exe = $g; break } }
        }
        $cmd = $m.command
        if ($exe) {
            $dir = Split-Path -Parent $exe
            $cmd = $cmd.Replace('{exeDir}', $dir).Replace('{exeName}', (Split-Path -Leaf $exe))
        }
        $cmd = $cmd.Replace('{target}', $Target).Replace('{workDir}', (Join-Path $Root 'work')).Replace('{script}', 'ANALYZE_SCRIPT')
        if ($Run -and $exe) {
            $out = & cmd /c $cmd 2>&1
            Out-Json @{ status = 'RAN'; tool = $Tool; mode = $m.id; kind = 'cli'; command = $cmd; exit = $LASTEXITCODE; output = (($out | Select-Object -Last 20) -join "`n") }
            exit $LASTEXITCODE
        }
        Out-Json @{ status = 'CLI_READY'; tool = $Tool; mode = $m.id; kind = 'cli'; command = $cmd; note = 'headless 通道：无需 GUI。加 -Run 直接执行。' }
        exit 0
    }

    # 带端点的通道
    $port = [int]$m.ready.port
    if (Test-Port $port) {
        Out-Json @{ status = 'ALREADY_READY'; tool = $Tool; mode = $m.id; port = $port; endpoint = $m.endpoint; auth = $m.auth }
        exit 0
    }

    $exe = Resolve-ToolExe $m.start.toolId $m.start.exeCandidates
    if (-not $exe -or -not (Test-Path $exe)) {
        continue   # 这条通道起不来，继续下一条
    }

    $argList = @()
    foreach ($a in $m.start.args) {
        if ($a -eq '{target}') { if ($Target -and (Test-Path $Target)) { $argList += $Target } }
        else { $argList += $a }
    }

    # ★ 启动方式：用 WMI Win32_Process.Create「脱离式」启动。
    #   不能用 Start-Process -RedirectStandard*：GUI 子进程会一直占着重定向句柄，
    #   PowerShell 退出时挂住（实测卡满 300s），外层一杀，x64dbg 跟着被杀 → 9094 消失。
    #   Win32_Process.Create 不继承句柄，既不挂调用方，也不怕调用方被 kill。
    $cmdLine = '"' + $exe + '"'
    if ($argList -and $argList.Count -gt 0) {
        $cmdLine += ' ' + (($argList | ForEach-Object { '"' + $_ + '"' }) -join ' ')
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
            CommandLine      = $cmdLine
            CurrentDirectory = (Split-Path -Parent $exe)
        }
        $procPid = [int]$r.ProcessId
    } catch { continue }
    if (-not $procPid) { continue }
    if ($m.postLaunchKeys) {
        try {
            Add-Type -AssemblyName System.Windows.Forms
            Start-Sleep -Seconds 4
            try { $ws = New-Object -ComObject WScript.Shell; [void]$ws.AppActivate($procPid) } catch { }
            Start-Sleep -Milliseconds 800
            [System.Windows.Forms.SendKeys]::SendWait($m.postLaunchKeys)
        } catch { }
    }

    $limit = if ($TimeoutSec -gt 0) { $TimeoutSec } else { [int]$m.ready.timeoutSec }
    if ($limit -le 0) { $limit = 120 }
    while ($sw.Elapsed.TotalSeconds -lt $limit) {
        if (Test-Port $port 500) {
            Out-Json @{ status = 'READY'; tool = $Tool; mode = $m.id; kind = $m.kind; exe = $exe; target = $Target; port = $port; seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); endpoint = $m.endpoint; auth = $m.auth }
            exit 0
        }
        Start-Sleep -Milliseconds 700
    }
    Out-Json @{ status = 'TIMEOUT'; tool = $Tool; mode = $m.id; exe = $exe; port = $port; waitedSec = [math]::Round($sw.Elapsed.TotalSeconds, 1); log = $logErr; hint = '该通道超时，可继续尝试下一档（去掉 -Mode 让它自动降级），或看日志里是否弹了对话框。' }
    exit 4
}

Out-Json @{ status = 'NO_MODE_AVAILABLE'; tool = $Tool; reason = '所有通道都起不来（可执行文件缺失或均未就绪）' }
exit 5
