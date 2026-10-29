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
    [string]$Script = '',
    [string]$WorkDir = '',
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
$DiscoveryScript = Join-Path $PyDir 'tool_autodiscover.py'
$PythonCommand = Get-Command python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1

function Out-Json($obj) { $obj | ConvertTo-Json -Depth 8 -Compress }

function Write-NextStep([string]$toolName) {
    Write-Output ("下一步：由当前智能体宿主重新加载 " + $toolName + " 的 MCP 配置，并核对本会话工具表。")
}

if (-not (Test-Path $ConfigPath)) {
    Out-Json @{ status = 'FAILED'; stage = 'config'; reason = "缺少 $ConfigPath"; next = '重新 clone 仓库或修复 tool-runtimes.json' }
    exit 2
}
try {
    $cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $cfg.tools -or $cfg.tools -is [array] -or $cfg.tools -is [string]) { throw 'tools 必须是对象' }
} catch {
    Out-Json @{ status = 'FAILED'; stage = 'config'; reason = $_.Exception.Message }
    exit 2
}

# ---------------------------------------------------------------- 路径缓存
function Write-Cache([string]$toolId, [string]$exe, [string]$via) {
    $via = $via -replace '^cache:', ''
    try {
        if ($PythonCommand) {
            & $PythonCommand.Source -X utf8 $DiscoveryScript cache-put $toolId $exe $via 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { Write-Warning '工具路径缓存未保存，原缓存已保留。' }
        }
    } catch { Write-Warning ('工具路径缓存未保存：' + $_.Exception.Message) }
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
if ($Use -and -not (Test-Path -LiteralPath $Use -PathType Leaf)) {
    Out-Json @{ status = 'FAILED'; stage = 'discover'; reason = '-Use 必须指向现有文件'; path = $Use }
    exit 2
}
$toolCfg = $cfg.tools.$Tool
if (-not $toolCfg) { Out-Json @{ status = 'FAILED'; stage = 'config'; reason = "tool-runtimes.json 里没有 '$Tool'" }; exit 2 }
if ($TimeoutSec -lt 0 -or $TimeoutSec -gt 43200) {
    Out-Json @{ status = 'FAILED'; stage = 'parameters'; reason = '-TimeoutSec 必须在 0 到 43200 秒之间' }; exit 2
}
try {
    if ($Target) { $Target = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Target) }
    if ($WorkDir) { $WorkDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($WorkDir) }
} catch { Out-Json @{ status = 'FAILED'; stage = 'parameters'; reason = $_.Exception.Message }; exit 2 }

# ---------------------------------------------------------------- 工具函数
function Resolve-ToolExe([string]$toolId, $exeCandidates) {
    <#
      返回 @{ exe; via; candidates }；exe 为空表示真的没找到。
      via 取值：manual / cache / env / PATH / common_dir / registry / startmenu / everything / scan / alias
    #>
    $candidates = @()
    $result = @{ exe = ''; via = ''; candidates = @() }

    # ① 手工指定
    if ($Use -and (Test-Path -LiteralPath $Use -PathType Leaf)) {
        return @{ exe = (Resolve-Path -LiteralPath $Use).Path; via = 'manual'; candidates = @($Use) }
    }

    # ② 共用 Python 发现器，避免旧缓存绕过显式环境路径和目标架构。
    try {
        if ($PythonCommand) {
            $discoveryArgs = @('-X', 'utf8', $DiscoveryScript, 'discover', $toolId)
            if ($Target) { $discoveryArgs += @('--target', $Target) }
            if ($Refresh) { $discoveryArgs += '--no-cache' }
            foreach ($candidate in $exeCandidates) { $discoveryArgs += @('--exe-candidate', $candidate) }
            $raw = (& $PythonCommand.Source @discoveryArgs 2>$null | Out-String)
            if ($LASTEXITCODE -eq 0 -and $raw) {
                $d = $raw | ConvertFrom-Json
                if ($d.available -and $d.command) {
                    return @{ exe = $d.command; via = $d.via; candidates = @($d.command) }
                }
                if ($d.layers_tried) { $result.candidates = @() }
                return $result
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

function Test-McpEndpoint($runtimeMode, [string]$exePath, [int]$probeTimeout = 8) {
    $requestFile = $null
    try {
        if (-not $PythonCommand -or -not $runtimeMode.endpoint.url) {
            return @{ ok = $false; stage = 'config'; error = '协议验证需要 Python 和 endpoint.url，端口监听不能替代握手' }
        }
        $headers = @{}
        if ($runtimeMode.auth.header) {
            if (-not $exePath -or -not $runtimeMode.auth.authJson) { throw '无法定位 MCP 认证文件' }
            $authPath = $runtimeMode.auth.authJson.Replace('{exeDir}', (Split-Path -Parent $exePath))
            $authData = Get-Content -LiteralPath $authPath -Raw -Encoding UTF8 | ConvertFrom-Json
            $tokenKey = ($runtimeMode.auth.fromFile -split '#')[-1]
            $token = $authData.$tokenKey
            if ($token -isnot [string] -or -not $token) { throw 'MCP 认证文件缺少令牌' }
            $headers[$runtimeMode.auth.header] = if ($token -match '^Bearer ') { $token } else { 'Bearer ' + $token }
        }
        $request = @{ url = $runtimeMode.endpoint.url; transport = $runtimeMode.endpoint.transport; headers = $headers; timeout = $probeTimeout }
        $requestFile = [IO.Path]::GetTempFileName()
        [IO.File]::WriteAllText($requestFile, ($request | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
        # PowerShell 5.1 can turn native stderr (including SDK logging) into a
        # terminating error under Stop. The JSON result determines probe state.
        $ErrorActionPreference = 'Continue'
        $raw = & $PythonCommand.Source -X utf8 (Join-Path $ScriptDir 'lib\mcp_http.py') --request-file $requestFile 2>$null | Out-String
        $ErrorActionPreference = 'Stop'
        if (-not $raw) { throw 'MCP 验证器未返回结果' }
        $result = $raw | ConvertFrom-Json
        if ($result.ok -and $result.tools -le 0) { return @{ ok = $false; stage = 'tools'; error = '握手成功但服务未提供工具' } }
        return $result
    } catch { return @{ ok = $false; stage = 'handshake'; error = $_.Exception.Message } }
    finally { if ($requestFile -and (Test-Path -LiteralPath $requestFile)) { Remove-Item -LiteralPath $requestFile -Force } }
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
        if (-not $exe) {
            $tried += [pscustomobject]@{ mode = $m.id; stage = 'discover'; reason = '可执行文件未找到' }
            continue
        }
        $hasArgv = $null -ne $m.argv
        if ($hasArgv -and ($m.argv -isnot [array] -or @($m.argv | Where-Object { $_ -isnot [string] }).Count)) {
            Out-Json @{ status = 'FAILED'; stage = 'config'; reason = '模式 argv 必须是字符串数组'; tool = $Tool; mode = $m.id }; exit 2
        }
        $toolArgs = @()
        $missing = @()
        $runDir = if ($WorkDir) { $WorkDir } else { Join-Path $Root ('work\' + $Tool + '-' + [guid]::NewGuid().ToString('N')) }
        try {
            $scriptPath = if ($Script -and $m.scriptKind -eq 'file') { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Script) } else { $Script }
            $scriptDir = if ($scriptPath -and $m.scriptKind -eq 'file') { Split-Path -Parent $scriptPath } else { '' }
            $scriptName = if ($scriptPath -and $m.scriptKind -eq 'file') { Split-Path -Leaf $scriptPath } else { '' }
            foreach ($argument in $m.argv) {
                foreach ($placeholder in [regex]::Matches($argument, '\{[A-Za-z_][A-Za-z0-9_]*\}')) {
                    if ($placeholder.Value -notin @('{target}', '{workDir}', '{script}', '{scriptDir}', '{scriptName}')) {
                        Out-Json @{ status = 'FAILED'; stage = 'config'; reason = ('未知模式占位符：' + $placeholder.Value); tool = $Tool; mode = $m.id }; exit 2
                    }
                }
                if ($argument.Contains('{target}') -and (-not $Target -or -not (Test-Path -LiteralPath $Target -PathType Leaf))) { $missing += '-Target 需要现有文件' }
                if ($argument.Contains('{script}') -or $argument.Contains('{scriptDir}') -or $argument.Contains('{scriptName}')) {
                    if (-not $Script) { $missing += '-Script 未提供' }
                    elseif ($m.scriptKind -eq 'file' -and -not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) { $missing += '-Script 需要现有脚本文件' }
                }
                $substitutions = @{ '{target}' = $Target; '{workDir}' = $runDir; '{script}' = $scriptPath; '{scriptDir}' = $scriptDir; '{scriptName}' = $scriptName }
                $toolArgs += [regex]::Replace($argument, '\{[A-Za-z_][A-Za-z0-9_]*\}', { param($match) $substitutions[$match.Value] })
            }
        } catch { Out-Json @{ status = 'FAILED'; stage = 'parameters'; reason = $_.Exception.Message; tool = $Tool; mode = $m.id }; exit 2 }
        if ($Run) {
            if (-not $PythonCommand -or -not $hasArgv) {
                Out-Json @{ status = 'FAILED'; stage = 'config'; reason = '执行需要 Python 和该模式的 argv 声明'; tool = $Tool; mode = $m.id }
                exit 2
            }
            if ($missing.Count) {
                Out-Json @{ status = 'FAILED'; stage = 'parameters'; reason = ($missing | Select-Object -Unique) -join '; '; tool = $Tool; mode = $m.id }
                exit 2
            }
            $requestFile = $null
            try {
                New-Item -ItemType Directory -Path $runDir -Force | Out-Null
                $requestFile = [IO.Path]::GetTempFileName()
                # -WorkDir (or the per-run generated work directory) is the
                # execution context. toolArgs already contain absolute target
                # and script paths, so changing cwd here cannot rebase inputs.
                $request = @{ argv = @($exe) + $toolArgs; cwd = $runDir; timeout = $(if ($TimeoutSec -gt 0) { $TimeoutSec } else { 600 }) }
                $request.context = @{ tool = $Tool; mode = $m.id; exe = $exe; workDir = $runDir; target = $Target }
                [IO.File]::WriteAllText($requestFile, ($request | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
                & $PythonCommand.Source -X utf8 $DiscoveryScript execute --request-file $requestFile
                $executionExit = $LASTEXITCODE
            } catch {
                Out-Json @{ status = 'FAILED'; stage = 'execution'; reason = $_.Exception.Message; tool = $Tool; mode = $m.id; exe = $exe; workDir = $runDir }
                $executionExit = 3
            } finally {
                if ($requestFile -and (Test-Path -LiteralPath $requestFile)) { Remove-Item -LiteralPath $requestFile -Force }
            }
            exit $executionExit
        }
        Write-Cache $tid $exe $res.via
        Out-Json @{ status = 'CLI_READY'; tool = $Tool; mode = $m.id; kind = 'cli'; via = $res.via; exe = $exe; argv = @($exe) + $toolArgs; argv_declared = $hasArgv; workDir = $runDir; missing_inputs = @($missing | Select-Object -Unique); runtime_verified = $false; note = '已找到 CLI 路径，尚未运行；补齐 missing_inputs 后加 -Run 执行并检查结果。' }
        exit 0
    }

    # 带端点的通道
    $port = [int]$m.ready.port
    if ($port -lt 1 -or $port -gt 65535 -or -not $m.endpoint.url) {
        $tried += [pscustomobject]@{ mode = $m.id; stage = 'config'; reason = '缺少有效端口或 MCP endpoint.url，无法验证控制通道' }
        continue
    }
    $res = Resolve-ToolExe $m.start.toolId $m.start.exeCandidates
    $exe = $res.exe
    if (Test-Port $port) {
        $probe = Test-McpEndpoint $m $exe
        if ($probe.ok) {
            Write-NextStep $Tool
            Out-Json @{ status = 'ALREADY_READY'; tool = $Tool; mode = $m.id; port = $port; endpoint = $m.endpoint; handshake = $probe; session_verified = $false; note = '独立 MCP 握手成功；当前宿主仍需核对本会话工具表' }
            exit 0
        }
        $tried += [pscustomobject]@{ mode = $m.id; stage = 'handshake'; reason = $probe.error; port = $port }
        continue
    }

    if (-not $exe -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) {
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
            $ws = New-Object -ComObject WScript.Shell
            if ($ws.AppActivate($procPid)) {
                Start-Sleep -Milliseconds 800
                [System.Windows.Forms.SendKeys]::SendWait($m.postLaunchKeys)
            }
        } catch { }
    }

    $limit = if ($TimeoutSec -gt 0) { $TimeoutSec } else { [int]$m.ready.timeoutSec }
    if ($limit -le 0) { $limit = 120 }
    while ($sw.Elapsed.TotalSeconds -lt $limit) {
        if (Test-Port $port 500) {
            $probe = Test-McpEndpoint $m $exe ([math]::Max(1, [math]::Min(8, [int]($limit - $sw.Elapsed.TotalSeconds))))
            if ($probe.ok) {
                Write-Cache $m.start.toolId $exe $res.via
                Write-NextStep $Tool
                Out-Json @{
                    status   = 'READY'; tool = $Tool; mode = $m.id; kind = $m.kind; exe = $exe; via = $res.via
                    target   = $Target; port = $port; seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
                    endpoint = $m.endpoint; pid = $procPid; handshake = $probe; session_verified = $false
                    note     = '独立 MCP 握手成功；当前宿主仍需核对本会话工具表'
                }
                exit 0
            }
        }
        Start-Sleep -Milliseconds 700
    }
    Out-Json @{
        status = 'TIMEOUT'; stage = 'handshake'; tool = $Tool; mode = $m.id; exe = $exe; via = $res.via
        port = $port; waitedSec = [math]::Round($sw.Elapsed.TotalSeconds, 1); pid = $procPid
        handshake = $probe
        hint = '已启动进程，但未完成 MCP 协议握手；检查插件、认证、端口和协议配置。'
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
        '若确实未安装：seep_ensure_tool(tool_id="' + $Tool + '")，或用 tool_autodiscover.py install 查看白名单方案'
    ) -join '；'
    hint       = '八层发现：环境变量→PATH→常见目录→注册表→开始菜单快捷方式→Everything 索引→递归扫描→别名'
}
exit 5
