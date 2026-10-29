#Requires -Version 5.1
<#
  Seep 工作台 — 各 Agent 配置一键自愈与绝对路径展开生成器 (Config Generator)
  用于自动生成：
  1. Claude Code 项目级配置 (.mcp.json)
  2. OpenCode 官方格式工作区配置 (opencode.jsonc)
  3. DeepSeek Harness (DSH) 官方 Cordis Overlay 补丁 (cordis.generated.yml，采用 - insert: 语法)
#>
[CmdletBinding()]
param(
    [switch]$PrintOnly
)

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'

function Merge-Defaults($Existing, $Defaults) {
    foreach ($property in $Defaults.PSObject.Properties) {
        $old = $Existing.PSObject.Properties[$property.Name]
        if ($null -eq $old) {
            $Existing | Add-Member -NotePropertyName $property.Name -NotePropertyValue $property.Value
        } elseif ($property.Value -is [PSCustomObject] -and $old.Value -is [PSCustomObject]) {
            Merge-Defaults $old.Value $property.Value
        }
    }
}

function Write-MergedConfig([string]$Path, [string]$DefaultsText) {
    $defaults = $DefaultsText | ConvertFrom-Json
    $raw = ''
    $merged = $defaults
    if (Test-Path -LiteralPath $Path) {
        $raw = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        # Keep quoted strings intact while accepting JSONC comments/trailing commas.
        $tokens = '"(?:\\.|[^"\\])*"|/\*[\s\S]*?\*/|//[^\r\n]*'
        $plain = [regex]::Replace($raw, $tokens, [System.Text.RegularExpressions.MatchEvaluator]{
            param($m)
            if ($m.Value.StartsWith('"')) { return $m.Value }
            return ' '
        })
        $plain = [regex]::Replace($plain, '"(?:\\.|[^"\\])*"|,\s*(?=[}\]])', [System.Text.RegularExpressions.MatchEvaluator]{
            param($m)
            if ($m.Value.StartsWith('"')) { return $m.Value }
            return ''
        })
        $merged = $plain | ConvertFrom-Json -ErrorAction Stop
        if ($merged -isnot [PSCustomObject]) { throw '配置必须是 JSON 对象，原文件保留' }
        Merge-Defaults $merged $defaults
    }
    # Refresh only a recognized Seep server path, retaining custom server fields.
    foreach ($container in @($merged.mcpServers, $merged.mcp)) {
        if ($container -and $container.seep) {
            foreach ($field in @('args', 'command')) {
                $value = $container.seep.$field
                if ($value -is [array]) {
                    $container.seep.$field = @($value | ForEach-Object {
                        if ([string]$_ -match '(^|[/\\])seep_mcp_server\.py$') { $McpServerPy } else { $_ }
                    })
                }
            }
        }
    }
    $text = ($merged | ConvertTo-Json -Depth 100) + "`n"
    if ($raw.Trim() -eq $text.Trim()) { return }
    if (Test-Path -LiteralPath $Path) {
        Copy-Item -LiteralPath $Path -Destination ($Path + '.bak-' + [guid]::NewGuid().ToString('N')) -ErrorAction Stop
    }
    $temp = $Path + '.tmp-' + [guid]::NewGuid().ToString('N')
    try {
        [System.IO.File]::WriteAllText($temp, $text, (New-Object System.Text.UTF8Encoding $false))
        Move-Item -LiteralPath $temp -Destination $Path -Force -ErrorAction Stop
    } finally {
        if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force }
    }
    Write-Host "  [OK] 已增量合并（原文件已备份）: $Path" -ForegroundColor Green
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$NormalizedRoot = $Root.Replace('\', '/')
$ToolDir   = Join-Path $Root 'Tool'
$McpServerPy = "$NormalizedRoot/Tool/mcp/seep_mcp_server.py"

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "          Seep Reverse Lab — 多 Agent 配置文件生成与自愈器" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "  检测到工作台物理根目录: $Root" -ForegroundColor White
Write-Host "  标准化 POSIX 路径表示: $NormalizedRoot" -ForegroundColor Gray

# -----------------------------------------------------------------------------
# 1. 生成 Claude Code 项目级 .mcp.json
# -----------------------------------------------------------------------------
Write-Host "`n[1/3] 正在生成 Claude Code 项目级配置 (.mcp.json)..." -ForegroundColor White
# 说明：本文件生成的内容必须与仓库里已提交的 .mcp.json **完全一致**，
# 否则每跑一次 install.ps1 都会把受跟踪文件改脏、并可能丢掉 ghidra 条目。
$claudeMcpJson = @"
{
  "mcpServers": {
    "seep": {
      "command": "python",
      "args": [
        "Tool/mcp/seep_mcp_server.py"
      ],
      "env": {
        "PYTHONIOENCODING": "utf-8"
      },
      "transport": "stdio"
    },
    "js-reverse": {
      "command": "npx",
      "args": [
        "-y",
        "js-reverse-mcp"
      ],
      "transport": "stdio"
    },
    "ghidra": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/LaurieWired/GhidraMCP",
        "ghidra-mcp",
        "--headless"
      ],
      "transport": "stdio"
    }
  }
}
"@
$claudeDest = Join-Path $Root '.mcp.json'
if (-not $PrintOnly) {
    Write-MergedConfig $claudeDest $claudeMcpJson
}

# -----------------------------------------------------------------------------
# 2. 生成 OpenCode 官方标准工作区配置 (opencode.jsonc)
# -----------------------------------------------------------------------------
Write-Host "`n[2/3] 正在生成 OpenCode 官方标准配置 (opencode.jsonc)..." -ForegroundColor White
$openCodeJsonc = @"
{
  "`$schema": "https://opencode.ai/config.json",
  "mcp": {
    "seep": {
      "type": "local",
      "command": [
        "python",
        "$McpServerPy"
      ],
      "enabled": true,
      "environment": {
        "PYTHONIOENCODING": "utf-8"
      }
    }
  }
}
"@
$openCodeDest = Join-Path $Root 'opencode.jsonc'
if (-not $PrintOnly) {
    Write-MergedConfig $openCodeDest $openCodeJsonc
}

# -----------------------------------------------------------------------------
# 3. 生成 DeepSeek Harness 官方 Cordis Overlay 补丁 (cordis.generated.yml)
# -----------------------------------------------------------------------------
Write-Host "`n[3/3] 正在生成 DeepSeek Harness (DSH) 官方补丁 (cordis.generated.yml)..." -ForegroundColor White
$dshYaml = @"
# ==============================================================================
# DeepSeek Harness (Cordis) Overlay 补丁 — 遵循 DSH 官方 - insert: 规范
# 生成基准目录: $NormalizedRoot
# 使用方法:
#   1. 命令行启动: dsh web --patch "$NormalizedRoot/setup/cordis.generated.yml"
#   2. 配置文件合并: 写入 `$DSH_HOME/profiles/<name>/cordis.patch.yml 或 `$DSH_HOME/cordis.patch.yml
# ==============================================================================
- insert:
    - id: seep-mcp
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: seep
        transport: stdio
        command: python
        args:
          - '$McpServerPy'
        env:
          PYTHONIOENCODING: utf-8
        cwd: !!js process.cwd()
"@
$dshDest = Join-Path $ScriptDir 'cordis.generated.yml'
if (-not $PrintOnly) {
    [System.IO.File]::WriteAllText($dshDest, $dshYaml, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "  [√] 已生成: $dshDest (顶层采用官方 - insert: 语法)" -ForegroundColor Green
}

Write-Host "`n================================================================================" -ForegroundColor Cyan
Write-Host "  🎉 所有 Agent 配置文件生成完毕！" -ForegroundColor Green
Write-Host "  - OpenCode: 直接启动 opencode，自动识别根目录 opencode.jsonc" -ForegroundColor White
Write-Host "  - DSH: 可执行 dsh web --patch `"$NormalizedRoot/setup/cordis.generated.yml`"" -ForegroundColor White
Write-Host "================================================================================" -ForegroundColor Cyan
exit 0
