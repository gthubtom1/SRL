#Requires -Version 5.1
<#
  tool-run.ps1 —— 通用「工具运行阶梯」执行器

  设计原则（长期，与 AGENTS.md §四点五.4 一致）：
    通道优先级 = 工具自带 MCP/stdio > CLI/headless > GUI(+MCP) > 人工
    只要 headless / CLI 能把事做完，就绝不启动 GUI。

  为什么用配置驱动：工具会越来越多（x64dbg / x32dbg / IDA / Ghidra / JEB / Binary Ninja / dnSpy …）。
  把"它能被 AI 控制哪些通道、每个通道怎么起、怎么判断就绪"写进 Tool/config/tool-runtimes.json，
  脚本本身零工具名、零绝对路径 —— 新增工具只加一条，不用改代码。

  三条硬规则（都是血案换来的，别改回去）：
    1. 本文件必须带 UTF-8 BOM：PowerShell 5.1 会把无 BOM 的中文脚本读成 ANSI → ParserError → 脚本根本不执行。
    2. 启动必须「脱离式」（Invoke-CimMethod Win32_Process Create）：
       Start-Process -RedirectStandard* 会让 GUI 子进程占住句柄，PowerShell 退出时挂死，外层一杀目标跟着死。
    3. 任何失败都必须输出结构化 JSON（stage + candidates + next），不许空着退出：
       静默失败会让 agent 继续用 bash 手搓十几分钟，用户只看到一次转瞬即逝的报错弹窗。

  用法：
    powershell -File Tool/scripts/tool-run.ps1 -ListModes                     # 看全量阶梯
    powershell -File Tool/scripts/tool-run.ps1 -Tool ida -ListModes           # 看单个工具
    powershell -File Tool/scripts/tool-run.ps1 -Tool x64dbg [-Target <样本>]
    powershell -File Tool/scripts/tool-run.ps1 -Tool x64dbg -Use "D:\...\x64dbg.exe"   # 手工指定
    powershell -File Tool/scripts/tool-run.ps1 -Tool x64dbg -Refresh          # 忽略路径缓存重新探测
    powershell -File Tool/scripts/tool-run.ps1 -Tool ghidra -Mode cli-headless -Target <样本> -Run

  退出码：0=就绪 / 2=配置缺失 / 3=启动失败 / 4=等待超时 / 5=没有可用通道
#>
[CmdletBinding()]
param(
    [string]$Tool = '',
    [string]$Target = '',
    [string]$Mode = '',
    [string]$Use = '',
    [switch]$ListModes,
    [switch]$Run,
    [switch]$Refresh,
    [int]$TimeoutSec = 0
)

$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root = Split-Path -Parent (Split-Path -Parent $ScriptDir)
$ConfigPath = Join-Path $Root 'Tool\config\tool-runtimes.json'
$PyDir = Join-Path $Root 'Tool\mcp'
$CachePath = Join-Path $env:USERPROFILE '.seep\tool-paths.json'

function Out-Json($obj) { $obj | ConvertTo-Json -Depth 8 -Compress }

if (-not (Test-Path $ConfigPath)) {
    Out-Json @{ status = 'FAILED'; stage = 'config'; reason = "缺少 $ConfigPath"; next = '重新 clone 仓库或修复 tool-runtimes.json' }
    exit 2
}
$cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json

# ---------------------------------------------------------------- 路径缓存
function Read-Cache {
    # ★ 不存在时返回 $null，绝不能返回 @{}：空 Hashtable 在 PowerShell 里是"真值"，
    #   后面用 .PSObject.Properties 遍历它拿到的是 .NET 属性名（IsFixedSize/Count/Keys…），
    #   会把这些名字当成工具名写进缓存 —— 实测会写出一个完全错误的 JSON。
    if (-not (Test-Path $CachePath)) { return $null }
    try { return (Get-Content -LiteralPath $CachePath -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { return $null }
}

function Write-Cache([string]$toolId, [string]$exe, [string]$via) {
    $via = $via -replace '^cache:', ''   # 别把 'cache:' 前缀写进缓存（否则下一轮变成 cache:cache:scan）
    try {
        $dir = Split-Path -Parent $CachePath
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $obj = @{}
        $old = Read-Cache
        if ($old -is [System.Collections.IDictionary]) {
            foreach ($k in $old.Keys) { $obj[$k] = $old[$k] }
        } elseif ($old) {
            foreach ($p in $old.PSObject.Properties) { $obj[$p.Name] = $p.Value }
        }
        $obj[$toolId] = [pscustomobject]@{
            exe      = $exe
            via      = $via
            verified = (Get-Date -Format 'yyyy-MM-dd')
        }
        ($obj | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $CachePath -Encoding UTF8
    } catch { }
}

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

if (-not $Tool) { Out-Json @{ status = 'FAILED'; stage = 'config'; reason = '需要 -Tool <id> 或 -ListModes' }; exit 2 }
$toolCfg = $cfg.tools.$Tool
if (-not $toolCfg) { Out-Json @{ status = 'FAILED'; stage = 'config'; reason = "tool-runtimes.json 里没有 '$Tool'" }; exit 2 }

# ---------------------------------------------------------------- 工具函数
function Resolve-ToolExe([string]$toolId, $exeCandidates) {
    <#
      返回 @{ exe; via; candidates }；exe 为空表示真的没找到。
      via 取值：manual / cache / env / PATH / common_dir / registry / startmenu / everything / scan / alias
    #>
    $candidates = @()
    $result = @{ exe = ''; via = ''; candidates = @() }

    # ① 手工指定
    if ($Use -and (Test-Path $Use)) {
        return @{ exe = (Resolve-Path -LiteralPath $Use).Path; via = 'manual'; candidates = @($Use) }
    }

    # ② 上次成功的路径（0ms 命中）
    if (-not $Refresh) {
        $cache = Read-Cache
        $hit = $null
        if ($cache -and $cache.PSObject.Properties.Name -contains $toolId) { $hit = $cache.$toolId }
        if ($hit -and $hit.exe -and (Test-Path $hit.exe)) {
            return @{ exe = $hit.exe; via = ('cache:' + $hit.via); candidates = @($hit.exe) }
        }
    }

    # ③ 八层发现（env / PATH / 常见目录 / 注册表 / 开始菜单 / Everything / 递归扫描 / 别名）
    try {
        $py = (Get-Command python -ErrorAction SilentlyContinue).Source
        if ($py) {
            $code = "import sys,json;sys.path.insert(0,r'$PyDir');import tool_autodiscover as A;"
            $code += "r=A.discover(r'$toolId', use_registry=True);print(json.dumps(r))"
            $raw = (& $py -c $code 2>$null | Select-Object -Last 1)
            if ($raw) {
                $d = $raw | ConvertFrom-Json
                if ($d.command) {
                    return @{ exe = $d.command; via = $d.via; candidates = @($d.command) }
                }
                if ($d.layers_tried) { $result.candidates = @() }
            }
        }
    } catch { }

    # ④ 配置里声明的备选名（兜底）
    if ($exeCandidates) {
        foreach ($n in $exeCandidates) {
            $g = (Get-Command $n -ErrorAction SilentlyContinue).Source
            if ($g) { return @{ exe = $g; via = 'alias'; candidates = @($g) } }
        }
    }
    return $result
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
    if (-not $modes) { Out-Json @{ status = 'FAILED'; stage = 'config'; reason = "'$Tool' 没有模式 '$Mode'"; next = '用 -ListModes 看可用通道' }; exit 2 }
}

$tried = @()

# ---------------------------------------------------------------- 逐个通道尝试
foreach ($m in $modes) {
    # CLI 通道：只解析并打印命令（-Run 才真执行）
    if ($m.kind -eq 'cli') {
        $tid = if ($m.toolId) { $m.toolId } else { $Tool }
        $res = Resolve-ToolExe $tid $m.fallbackExe
        $exe = $res.exe
        $cmd = $m.command
        if ($exe) {
            $dir = Split-Path -Parent $exe
            $cmd = $cmd.Replace('{exeDir}', $dir).Replace('{exeName}', (Split-Path -Leaf $exe))
        }
        $cmd = $cmd.Replace('{target}', $Target).Replace('{workDir}', (Join-Path $Root 'work')).Replace('{script}', 'ANALYZE_SCRIPT')
        if (-not $exe) {
            $tried += [pscustomobject]@{ mode = $m.id; stage = 'discover'; reason = '可执行文件未找到' }
            continue
        }
        if ($Run) {
            $out = & cmd /c $cmd 2>&1
            Out-Json @{ status = 'RAN'; tool = $Tool; mode = $m.id; kind = 'cli'; via = $res.via; command = $cmd; exit = $LASTEXITCODE; output = (($out | Select-Object -Last 20) -join "`n") }
            exit $LASTEXITCODE
        }
        Write-Cache $tid $exe $res.via
        Out-Json @{ status = 'CLI_READY'; tool = $Tool; mode = $m.id; kind = 'cli'; via = $res.via; exe = $exe; command = $cmd; note = 'headless 通道：无需 GUI。加 -Run 直接执行。' }
        exit 0
    }

    # 带端点的通道
    $port = [int]$m.ready.port
    if (Test-Port $port) {
        Out-Json @{ status = 'ALREADY_READY'; tool = $Tool; mode = $m.id; port = $port; endpoint = $m.endpoint; auth = $m.auth; note = '服务已在跑；若本会话 MCP 仍不可用，在 TUI 执行 /mcp reconnect ' + $Tool }
        exit 0
    }

    $res = Resolve-ToolExe $m.start.toolId $m.start.exeCandidates
    $exe = $res.exe
    if (-not $exe -or -not (Test-Path $exe)) {
        $tried += [pscustomobject]@{ mode = $m.id; stage = 'discover'; reason = '可执行文件未找到' }
        continue   # 这条通道起不来，继续下一条
    }

    $argList = @()
    foreach ($a in $m.start.args) {
        if ($a -eq '{target}') { if ($Target -and (Test-Path $Target)) { $argList += $Target } }
        else { $argList += $a }
    }

    # ★ 启动方式：用 WMI Win32_Process.Create「脱离式」启动（见文件头规则 2）。
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
    } catch {
        $tried += [pscustomobject]@{ mode = $m.id; stage = 'spawn'; reason = ('启动进程失败：' + $_.Exception.Message); exe = $exe }
        continue
    }
    if (-not $procPid) {
        $tried += [pscustomobject]@{ mode = $m.id; stage = 'spawn'; reason = 'Win32_Process.Create 未返回 PID'; exe = $exe }
        continue
    }
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
            Write-Cache $m.start.toolId $exe $res.via
            Out-Json @{
                status   = 'READY'; tool = $Tool; mode = $m.id; kind = $m.kind; exe = $exe; via = $res.via
                target   = $Target; port = $port; seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
                endpoint = $m.endpoint; auth = $m.auth; pid = $procPid
                note     = 'MCP 工具在会话启动时注册；若本会话调不到，执行 /mcp reconnect ' + $Tool
            }
            exit 0
        }
        Start-Sleep -Milliseconds 700
    }
    Out-Json @{
        status = 'TIMEOUT'; stage = 'port'; tool = $Tool; mode = $m.id; exe = $exe; via = $res.via
        port = $port; waitedSec = [math]::Round($sw.Elapsed.TotalSeconds, 1); pid = $procPid
        hint = '进程起来了但端口没开：多半是 MCP 插件未加载（x64dbg 在 GUI 里按 Ctrl+Alt+M）、端口被占、或被安全软件拦。'
        next = '看窗口是否弹对话框；确认插件 MCP 是否勾选自动启动；必要时 -Use <另一个 exe> 换通道。'
    }
    exit 4
}

# ---------------------------------------------------------------- 全通道失败
$last = $tried | Where-Object { $_.stage -eq 'spawn' } | Select-Object -First 1
if (-not $last) { $last = $tried | Where-Object { $_.stage -eq 'port' } | Select-Object -First 1 }
if (-not $last) { $last = $tried | Select-Object -First 1 }
Out-Json @{
    status     = 'FAILED'
    stage      = if ($last) { $last.stage } else { 'discover' }
    tool       = $Tool
    reason     = if ($last) { $last.reason } else { '所有通道都起不来（可执行文件缺失或均未就绪）' }
    candidates = @($tried)
    next       = @(
        '手工指定路径：tool-run.ps1 -Tool ' + $Tool + ' -Use "<exe 的绝对路径>"',
        '设环境变量 SEEP_' + ($Tool.ToUpper() -replace '[^A-Z0-9]', '_') + '_PATH=<exe 路径>',
        '若确实未安装：seep_tool_install(tool_id="' + $Tool + '") 或按 tool-capabilities.json 的下载地址装'
    ) -join '；'
    hint       = '八层发现：环境变量→PATH→常见目录→注册表→开始菜单快捷方式→Everything 索引→递归扫描→别名'
}
exit 5
