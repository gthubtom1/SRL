#Requires -Version 5.1
<#
  wake-gui-mcp.ps1 —— 通用「GUI 宿主型 MCP」唤醒器

  为什么需要：x64dbg / IDA 这类工具的 MCP 服务是**宿主进程里的插件**提供的。
  宿主没开 → 端点不存在 → MCP 调用直接 WinError 10061。等用户手动点开是不可接受的，
  Agent 应该自己起、自己等就绪。

  设计原则（长期）：**工具清单在 Tool/config/gui-hosts.json，脚本里不写任何工具名、不写死路径**。
  以后新增 GUI 工具（x96dbg / JEB / Binary Ninja …）只加一条配置，本脚本不用改。

  用法：
    powershell -File Tool\scripts\wake-gui-mcp.ps1 -Tool x64dbg
    powershell -File Tool\scripts\wake-gui-mcp.ps1 -Tool ida -Target D:\samples\a.exe
    powershell -File Tool\scripts\wake-gui-mcp.ps1 -Tool x64dbg -TimeoutSec 120

  退出码：0=已就绪 / 2=配置或路径缺失 / 3=启动失败 / 4=等待超时
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Tool,
    [string]$Target = '',
    [int]$TimeoutSec = 0
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$ConfigPath = Join-Path $Root 'Tool\config\gui-hosts.json'
$PyDir = Join-Path $Root 'Tool\mcp'

function Out-Json($obj) {
    $obj | ConvertTo-Json -Depth 6 -Compress
}

if (-not (Test-Path $ConfigPath)) {
    Out-Json @{ status = 'ERR'; reason = "缺少配置文件 $ConfigPath" }
    exit 2
}

$cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
$key = $Tool.ToLower()
$hostCfg = $null
foreach ($p in $cfg.hosts.PSObject.Properties) {
    if ($p.Name.ToLower() -eq $key -or ($p.Value.toolId -and $p.Value.toolId.ToLower() -eq $key)) { $hostCfg = $p.Value; break }
}
if (-not $hostCfg) {
    Out-Json @{ status = 'ERR'; reason = "gui-hosts.json 里没有 '$Tool'（已知：$((($cfg.hosts.PSObject.Properties | ForEach-Object { $_.Name }) -join ', '))）" }
    exit 2
}

# ---------------------------------------------------------------- 1. 定位 exe（复用六层探测）
$exe = ''
try {
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if ($py) {
        $code = "import sys;sys.path.insert(0,r'$PyDir');import tool_autodiscover as A;r=A.discover(r'$($hostCfg.toolId)', use_registry=False);print(r.get('command') or '')"
        $exe = (& $py -c $code 2>$null | Select-Object -Last 1)
    }
} catch { }
if (-not $exe -and $hostCfg.exeName) {
    $exe = (Get-Command $hostCfg.exeName -ErrorAction SilentlyContinue).Source
}
if (-not $exe -or -not (Test-Path $exe)) {
    Out-Json @{ status = 'ERR'; reason = "探测不到 $($hostCfg.toolId) 的可执行文件；可设 SEEP_$($hostCfg.toolId.ToUpper())_PATH 或在 gui-hosts.json 里写 exeName" }
    exit 2
}

# 需要换 exe（例如 ida 探测到 headless 的 idat.exe，但 GUI 路线要 ida64.exe）
# 需要换 exe（例如探测到 headless 的 idat.exe，但 GUI 路线要 ida.exe / ida64.exe）
$pickNames = @()
if ($hostCfg.exeCandidates) { $pickNames = @($hostCfg.exeCandidates) }
elseif ($hostCfg.exeName) { $pickNames = @($hostCfg.exeName) }
foreach ($n in $pickNames) {
    $alt = Join-Path (Split-Path -Parent $exe) $n
    if (Test-Path $alt) { $exe = $alt; break }
}

# ---------------------------------------------------------------- 2. 端口是否已经就绪
$port = [int]$hostCfg.ready.port
function Test-Port([int]$p, [int]$ms = 800) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $iar = $client.BeginConnect('127.0.0.1', $p, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($ms)) { return $false }
        $client.EndConnect($iar)
        return $true
    } catch { return $false } finally { $client.Close() }
}

if (Test-Port $port) {
    Out-Json @{ status = 'ALREADY_READY'; tool = $hostCfg.toolId; exe = $exe; port = $port; mcp = $hostCfg.mcp }
    exit 0
}

# ---------------------------------------------------------------- 3. 组装参数并启动
$args = @()
if ($hostCfg.args) {
    foreach ($a in $hostCfg.args) {
        if ($a -eq '{target}') {
            if ($Target -and (Test-Path $Target)) { $args += $Target }
        } else { $args += $a }
    }
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$logOut = Join-Path $env:TEMP ("wake-gui-" + $hostCfg.toolId + ".out.log")
$logErr = Join-Path $env:TEMP ("wake-gui-" + $hostCfg.toolId + ".err.log")
try {
    # ★ 必须重定向：GUI 子进程若继承本脚本的 stdout/stderr，脚本退出后管道仍开着，
    #   调用方会一直等（实测挂 180s）。重定向到临时文件即可。
    $proc = Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory (Split-Path -Parent $exe) `
        -RedirectStandardOutput $logOut -RedirectStandardError $logErr -PassThru
} catch {
    Out-Json @{ status = 'ERR'; reason = "启动失败: $($_.Exception.Message)"; exe = $exe }
    exit 3
}

# 有些宿主的 MCP 插件**不会自启**（IDA 的 mcp-plugin 要按 Ctrl+Alt+M）。
# 配置里写 postLaunchKeys 即可：启动后把窗口拉到前台，再发一次热键。
if ($hostCfg.postLaunchKeys) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Start-Sleep -Seconds 4
        try {
            $ws = New-Object -ComObject WScript.Shell
            [void]$ws.AppActivate($proc.Id)
        } catch { }
        Start-Sleep -Milliseconds 800
        [System.Windows.Forms.SendKeys]::SendWait($hostCfg.postLaunchKeys)
        Start-Sleep -Milliseconds 500
    } catch { }
}

# ---------------------------------------------------------------- 4. 等端口就绪
$limit = if ($TimeoutSec -gt 0) { $TimeoutSec } else { [int]$hostCfg.ready.timeoutSec }
if ($limit -le 0) { $limit = 120 }
while ($sw.Elapsed.TotalSeconds -lt $limit) {
    if (Test-Port $port 500) {
        Out-Json @{
            status  = 'READY'
            tool    = $hostCfg.toolId
            exe     = $exe
            target  = $Target
            port    = $port
            seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            mcp     = $hostCfg.mcp
            hint    = '宿主已起、端点已就绪。若要 MCP 能连，按 mcp 字段里的 transport 处理（SSE 需 mcp-remote 桥接）。'
        }
        exit 0
    }
    Start-Sleep -Milliseconds 700
}

Out-Json @{ status = 'TIMEOUT'; tool = $hostCfg.toolId; exe = $exe; port = $port; waitedSec = [math]::Round($sw.Elapsed.TotalSeconds, 1); hint = '宿主可能弹了对话框（首次运行/许可/崩溃恢复）。看一眼窗口，或在 gui-hosts.json 调大 timeoutSec。' }
exit 4
