#Requires -Version 5.1
<#
  Seep 工作台 —— IDA Pro 探测与配置 (加强版)
  解决：
    1. 支持交互式输入/参数传参/全盘智能多点探测自定义路径（解决写死 D:\Tool\IDA Pro 问题）
    2. 支持 IDA 9.x 原生 idalib_supervisor 模式及传统 server.py 模式
    3. 写入 JSON 时严格转义反斜杠与使用 UTF-8 No BOM，杜绝 Node.js JSON.parse 崩溃
    4. 增量合并 mcp.json，杜绝覆盖用户已有的其他 MCP 配置（如 x64dbg）
#>
[CmdletBinding()]
param(
    [string]$IdaRoot = '',
    [switch]$SkipPip,
    [switch]$Interactive,
    [string]$AgentRoot = ''
)

$ErrorActionPreference = 'Continue'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$ToolDir   = Join-Path $Root 'Tool'

function Write-Ok($m)   { Write-Host "    [OK] $m" -ForegroundColor Green }
function Write-Warn($m) { Write-Host "    [!!] $m" -ForegroundColor Yellow }
function Write-Info($m) { Write-Host "    [..] $m" -ForegroundColor Gray }

$resolveArgs = @((Join-Path $ToolDir 'scripts\runtime-root.py'), 'resolve')
if ($AgentRoot -ne '') { $resolveArgs += @('--agent-root', $AgentRoot) }
$resolveOutput = @(& python @resolveArgs 2>&1)
if ($LASTEXITCODE -ne 0) { Write-Warn 'AgentRoot 无效或运行根目录解析器不可用'; exit 1 }
try {
    $resolved = (($resolveOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop)
    if (-not $resolved.ok -or [string]::IsNullOrWhiteSpace([string]$resolved.agent_root)) { throw 'missing AgentRoot' }
    $AgentDir = [IO.Path]::GetFullPath([string]$resolved.agent_root)
} catch { Write-Warn 'AgentRoot 解析失败，未修改配置'; exit 1 }
$McpJson = Join-Path $AgentDir 'mcp.json'
$jsonObj = [PSCustomObject]@{ mcpServers = [PSCustomObject]@{} }
if (Test-Path -LiteralPath $McpJson) {
    try {
        $jsonObj = [IO.File]::ReadAllText($McpJson, [Text.Encoding]::UTF8) | ConvertFrom-Json -ErrorAction Stop
        if ($jsonObj -isnot [PSCustomObject]) { throw 'expected object' }
        $serversProperty = $jsonObj.PSObject.Properties['mcpServers']
        if ($serversProperty -and $serversProperty.Value -isnot [PSCustomObject]) { throw 'mcpServers must be an object' }
    } catch { Write-Warn '现有 mcp.json 无效，原件保留，请修正后重试'; exit 1 }
}

Write-Host "`n  === IDA Pro 智能探测与配置 ===" -ForegroundColor Cyan

# ---------------------------------------------------------------- 1. 探测
$found = $null

if ($IdaRoot -ne '') {
    if (-not (Test-Path -LiteralPath (Join-Path $IdaRoot 'ida.exe') -PathType Leaf)) {
        Write-Warn '指定的 IdaRoot 缺少 ida.exe，未修改配置'
        exit 1
    }
    $found = (Resolve-Path -LiteralPath $IdaRoot).Path
}

if (-not $found) {
    # 常用候选路径列表（覆盖 C/D/E/F 盘常见安装目录、桌面、Program Files）
    $candidates = @(
        'D:\Tool\IDA Pro',
        'C:\Program Files\IDA Pro',
        'C:\Program Files\IDA Professional 9.0',
        'C:\Program Files\IDA Pro 9.4',
        'C:\Program Files\IDA Professional 9.4',
        'C:\Program Files\IDA Free',
        'C:\IDA Pro',
        'C:\IDA',
        'D:\IDA Pro',
        'D:\IDA',
        'E:\IDA Pro',
        'F:\IDA Pro',
        (Join-Path $env:USERPROFILE 'Desktop\IDA Pro\App\IDA Pro'),
        (Join-Path $env:USERPROFILE 'Desktop\IDA Pro 9.4\App\IDA Pro'),
        (Join-Path $env:USERPROFILE 'Tools\IDA Pro 9.4\App\IDA Pro')
    )

    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c 'ida.exe')) {
            $found = (Resolve-Path $c).Path
            break
        }
    }
}

# 有界目录扫描：便携版 / 绿化版常放在 `...\disasm\IDA Pro 9.x`、`...\Tools\IDA*` 这类位置，
# 既不进注册表也不在默认候选表里。只扫固定几个根，深度 <=2，绝不盘根递归。
if (-not $found) {
    # ★ 不写死盘符：按本机实际存在的盘枚举 <盘>:\Tools / \Tools\disasm / \Program Files，
    #   外加用户目录下的 Tools —— 换电脑、换盘符都能命中，且不存在的路径直接跳过。
    $scanRoots = @()
    foreach ($d in (Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue)) {
        $driveRoot = $d.Root
        if (-not $driveRoot) { continue }
        foreach ($sub in @('Tools', 'Tools\disasm', 'Program Files')) {
            $scanRoots += (Join-Path $driveRoot $sub)
        }
    }
    $scanRoots += (Join-Path $env:USERPROFILE 'Tools')
    foreach ($scanRoot in $scanRoots) {
        if (-not (Test-Path -LiteralPath $scanRoot)) { continue }
        $hits = Get-ChildItem -LiteralPath $scanRoot -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match 'IDA' }
        foreach ($h in $hits) {
            if (Test-Path (Join-Path $h.FullName 'ida.exe')) { $found = $h.FullName; break }
            # 再看一层（IDA Pro 9.x 常再套一层同名目录）
            $sub = Get-ChildItem -LiteralPath $h.FullName -Directory -ErrorAction SilentlyContinue |
                   Where-Object { $_.Name -match 'IDA' -or $_.Name -match 'App' }
            foreach ($s in $sub) {
                if (Test-Path (Join-Path $s.FullName 'ida.exe')) { $found = $s.FullName; break }
            }
            if ($found) { break }
        }
        if ($found) { break }
    }
    if ($found) { Write-Info "扫描命中 IDA: $found" }
}

# 注册表与快捷方式探测
if (-not $found) {
    $regPaths = @(
        'HKCU:\Software\Hex-Rays\IDA Pro',
        'HKLM:\SOFTWARE\Hex-Rays\IDA Pro',
        'HKCU:\Software\Hex-Rays\IDA',
        'HKLM:\SOFTWARE\Hex-Rays\IDA'
    )
    foreach ($rp in $regPaths) {
        if (Test-Path $rp) {
            $prop = (Get-ItemProperty $rp -ErrorAction SilentlyContinue).InstallDir
            if ($prop -and (Test-Path (Join-Path $prop 'ida.exe'))) {
                $found = (Resolve-Path $prop).Path
                break
            }
        }
    }
}

# 若仍未找到且允许交互，则提示用户输入
if (-not $found -and $Interactive) {
    Write-Host "`n    [?] 未在默认路径检测到 IDA Pro。" -ForegroundColor Yellow
    $userInput = Read-Host "    请输入您的 IDA Pro 完整安装目录 (直接回车跳过)"
    if ($userInput -and $userInput.Trim() -ne '') {
        $uPath = $userInput.Trim().Trim('"').Trim("'")
        if (Test-Path (Join-Path $uPath 'ida.exe')) {
            $found = (Resolve-Path $uPath).Path
        } else {
            Write-Warn '该目录缺少 ida.exe，已跳过 IDA 绑定'
        }
    }
}

if (-not $found) {
    Write-Warn '未检测到 IDA Pro 安装路径'
    Write-Host @'

    说明：IDA Pro 为商业软件，本工作台不随包分发。
    · 若无需 IDA Pro，可在需要时检查 Radare2 等替代工具；具体任务能力需实际验证。
    · 若已安装但路径特殊，可随时运行以下命令绑定：
        powershell -ExecutionPolicy Bypass -File .\setup\install-ida.ps1 -IdaRoot "F:\你的\IDA路径"
'@ -ForegroundColor Gray
    exit 0
}

Write-Ok "已成功定位 IDA Pro: $found"

# ---------------------------------------------------------------- 2. 定位 Python
$idaPy = $null
$pyCandidates = @(
    (Join-Path $found 'python311\python.exe'),
    (Join-Path $found 'python3\python.exe'),
    (Join-Path $found 'python\python.exe'),
    (Join-Path $found 'plugins\idapython3\python.exe')
)

foreach ($p in $pyCandidates) {
    if (Test-Path $p) { $idaPy = (Resolve-Path $p).Path; break }
}

if (-not $idaPy) {
    $g = Get-Command python -ErrorAction SilentlyContinue
    if ($g) { $idaPy = $g.Source; Write-Warn "IDA 内置 Python 未找到，改用系统全局 Python: $idaPy" }
}

if ($idaPy) {
    Write-Ok "IDA Python 解释器: $idaPy"
} else {
    Write-Warn '未找到可用的 Python 解释器，IDA MCP 连通性可能受限'
}

# ---------------------------------------------------------------- 3. 装配 ida-pro-mcp
if (-not $SkipPip -and $idaPy) {
    Write-Info '正在为 IDA Python 检查与安装 ida-pro-mcp 依赖...'
    # ★ ida-pro-mcp 1.4 的 server.py 仍是 `from mcp.server.fastmcp import FastMCP`，
    #   而 mcp 2.x 已把 FastMCP 改名为 MCPServer → 直接 ModuleNotFoundError，MCP 显示 failed。
    #   所以这里必须把 mcp 钉在 <2（实测 1.30 可用）。
    & $idaPy -m pip install --quiet --upgrade ida-pro-mcp "mcp<2" 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'ida-pro-mcp 已就绪'
    } else {
        Write-Warn 'ida-pro-mcp 自动 pip 安装失败（可手动执行: & $idaPy -m pip install ida-pro-mcp）'
        exit 1
    }
}

# ---------------------------------------------------------------- 4. 解析 IDA MCP 服务端入口
# 优先策略：
# A. IDA 9.x 原生 supervisor 模块模式 (支持 -m ida_pro_mcp.idalib_supervisor --stdio)
# B. 传统 server.py 脚本模式 (自动递归寻找包含 ida_pro_mcp\server.py 的真实目录)
$serverArgs = @()
$serverScript = $null

$spCandidates = @(
    (Join-Path $found 'python311\Lib\site-packages\ida_pro_mcp\server.py'),
    (Join-Path $found 'python3\Lib\site-packages\ida_pro_mcp\server.py'),
    (Join-Path $found 'Lib\site-packages\ida_pro_mcp\server.py'),
    (Join-Path $found 'plugins\ida_pro_mcp\server.py')
)

foreach ($sp in $spCandidates) {
    if (Test-Path $sp) {
        $serverScript = (Resolve-Path $sp).Path
        break
    }
}

if ($serverScript) {
    # 转换为正斜杠，防止 JSON 转义崩溃
    $serverScriptNorm = $serverScript.Replace('\', '/')
    $serverArgs = @($serverScriptNorm)
    Write-Ok "定位到 IDA Server 脚本: $serverScript"
} else {
    # 采用模块方式拉起
    $serverArgs = @("-m", "ida_pro_mcp.idalib_supervisor", "--stdio")
    Write-Ok "配置为 IDA 原生模块运行模式 (-m ida_pro_mcp.idalib_supervisor)"
}

# ---------------------------------------------------------------- 5. 安全增量写入 mcp.json (UTF-8 No BOM + 保护已有配置)
try {
    if (-not $jsonObj.mcpServers) {
        $jsonObj | Add-Member -NotePropertyName 'mcpServers' -NotePropertyValue ([PSCustomObject]@{}) -Force
    }

    $idaPyNorm = if ($idaPy) { $idaPy.Replace('\', '/') } else { "python" }

    # 增量设置 ida 配置，不覆盖用户已有的其他 mcp 服务（如 x64dbg/playwright）
    $idaEntry = [PSCustomObject]@{
        command = $idaPyNorm
        args    = $serverArgs
        env     = [PSCustomObject]@{
            PYTHONIOENCODING = "utf-8"
        }
        transport = "stdio"
        lifecycle = "eager"
        requestTimeoutMs = 180000
    }

    $jsonObj.mcpServers | Add-Member -NotePropertyName 'ida' -NotePropertyValue $idaEntry -Force

    $jsonFinal = $jsonObj | ConvertTo-Json -Depth 100
    # 强制以 UTF-8 No BOM 写入，杜绝 Node.js JSON.parse 崩溃
    New-Item -ItemType Directory -Path $AgentDir -Force -ErrorAction Stop | Out-Null
    if (Test-Path -LiteralPath $McpJson) {
        Copy-Item -LiteralPath $McpJson -Destination ($McpJson + '.bak-' + [guid]::NewGuid().ToString('N')) -ErrorAction Stop
    }
    $temporary = $McpJson + '.tmp-' + [guid]::NewGuid().ToString('N')
    try {
        [IO.File]::WriteAllText($temporary, $jsonFinal, (New-Object System.Text.UTF8Encoding $false))
        Move-Item -LiteralPath $temporary -Destination $McpJson -Force -ErrorAction Stop
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
    Write-Ok "mcp.json 已增量更新（UTF-8 No BOM，保护已有配置）"
    Write-Info "  IDA 安装根目录 = $found"
    Write-Info "  IDA Python 路径 = $idaPyNorm"
} catch { Write-Warn 'IDA 配置写入失败，未报告绑定成功，请检查备份与文件权限'; exit 1 }

Write-Host "`n    配置已生成；请在对应宿主重新连接 IDA MCP，确认实际连通性。" -ForegroundColor Cyan
exit 0
