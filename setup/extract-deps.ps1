#Requires -Version 5.1
<#
  首次运行：解压 node_modules.zip / venv.zip（从 GitHub clone 后执行一次）
  用法：powershell -ExecutionPolicy Bypass -File .\extract-deps.ps1
#>
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$SafeDir   = Join-Path $Root 'Tool\mcp\Tool\safe'

$zips = @(
    @{ Zip = "$SafeDir\js-reverse-mcp\node_modules.zip";  Dest = "$SafeDir\js-reverse-mcp\node_modules" }
    @{ Zip = "$SafeDir\playwright-mcp\node_modules.zip";  Dest = "$SafeDir\playwright-mcp\node_modules" }
    @{ Zip = "$SafeDir\ida-pro-mcp\venv.zip";            Dest = "$SafeDir\ida-pro-mcp\.venv" }
)

$failed = 0
foreach ($z in $zips) {
    $name = (Split-Path $z.Dest -Leaf)
    if (Test-Path $z.Dest) {
        if (Test-Path (Join-Path $z.Dest $name)) {
            Write-Host "  [FAIL] $name 是双层旧布局；保留原目录，请移走该错误依赖目录后重跑" -ForegroundColor Red
            $failed++
            continue
        }
        Write-Host "  [SKIP] $name (已存在)" -ForegroundColor Green
        continue
    }
    if (-not (Test-Path $z.Zip)) {
        Write-Host "  [FAIL] $name.zip 不存在" -ForegroundColor Red
        $failed++
        continue
    }
    $stage = Join-Path (Split-Path $z.Dest -Parent) ('.seep-extract-' + [guid]::NewGuid().ToString('N'))
    try {
        New-Item -ItemType Directory -Path $stage -ErrorAction Stop | Out-Null
        Expand-Archive -LiteralPath $z.Zip -DestinationPath $stage -ErrorAction Stop
        $extracted = Join-Path $stage $name
        if (-not (Test-Path -LiteralPath $extracted -PathType Container)) { throw '离线包缺少预期顶层目录' }
        Move-Item -LiteralPath $extracted -Destination $z.Dest -ErrorAction Stop
        Write-Host "  [OK] $name 已按包内布局解压" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] $name 解压失败，未报告可用: $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    } finally {
        # Stage is an explicitly created child of this dependency's parent.
        $stageAbsolute = [System.IO.Path]::GetFullPath($stage)
        $allowedParent = [System.IO.Path]::GetFullPath((Split-Path $z.Dest -Parent)).TrimEnd('\') + '\'
        if (-not $stageAbsolute.StartsWith($allowedParent, [System.StringComparison]::OrdinalIgnoreCase)) { throw '解压清理边界无效' }
        if (Test-Path -LiteralPath $stageAbsolute) { Remove-Item -LiteralPath $stageAbsolute -Recurse -Force }
    }
}
if ($failed -gt 0) { Write-Host "  依赖解压未完成：$failed 项失败" -ForegroundColor Red; exit 1 }
Write-Host "`n  依赖布局已准备；工具连通性仍由环境检查确认。" -ForegroundColor Cyan
exit 0
