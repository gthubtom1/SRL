#Requires -Version 5.1
<#
  build.ps1 —— 从源码重建 Tool/samples 下的练习样本（Windows + MinGW/gcc）。
  无 gcc / windres 时跳过对应样本，不报错（扩展工具测试本身不依赖这些样本）。
#>
$ErrorActionPreference = 'Continue'
$Here = $PSScriptRoot
$Src  = Join-Path $Here 'src'
$failedCount = 0

function Have($name) { return [bool](Get-Command $name -ErrorAction SilentlyContinue) }

if (-not (Have 'gcc')) {
    Write-Host '[跳过] 未找到 gcc，样本不重建（这不影响扩展工具本身）。' -ForegroundColor Yellow
    exit 0
}

# 1) 基础 crackme
Write-Host '构建 crackme_basic.exe ...' -ForegroundColor Cyan
& gcc -O2 -o (Join-Path $Here 'crackme_basic.exe') (Join-Path $Src 'crackme_basic.c')
if ($LASTEXITCODE -eq 0) { Write-Host '  [OK] crackme_basic.exe' -ForegroundColor Green }
else { $failedCount++ }

# 2) 反调试演示
Write-Host '构建 antidebug_demo.exe ...' -ForegroundColor Cyan
& gcc -O2 -o (Join-Path $Here 'antidebug_demo.exe') (Join-Path $Src 'antidebug_demo.c') -lpsapi
if ($LASTEXITCODE -eq 0) { Write-Host '  [OK] antidebug_demo.exe' -ForegroundColor Green }
else { $failedCount++ }

# 3) 资源样本（需 windres + python 生成 payload）
if (Have 'windres') {
    Write-Host '生成 payload.bin 并构建 resource_blob.exe ...' -ForegroundColor Cyan
    $py = Get-Command python -ErrorAction SilentlyContinue
    $resourceOk = $false
    if ($py) {
        & $py.Source (Join-Path $Src 'gen_payload.py')
        if ($LASTEXITCODE -eq 0) {
            Push-Location $Src
            try {
                & windres resource.rc -O coff -o resource.res
                if ($LASTEXITCODE -eq 0) {
                    & gcc -O2 -o (Join-Path $Here 'resource_blob.exe') resource_blob.c resource.res
                    $resourceOk = ($LASTEXITCODE -eq 0)
                }
            } finally { Pop-Location }
        }
    }
    if ($resourceOk) { Write-Host '  [OK] resource_blob.exe' -ForegroundColor Green }
    else { $failedCount++ }
} else {
    Write-Host '[跳过] 未找到 windres，resource_blob.exe 不重建。' -ForegroundColor Yellow
}

if ($failedCount -gt 0) {
    Write-Host "`nFailed sample builds: $failedCount" -ForegroundColor Red
    exit 1
}
Write-Host "`n完成。样本在 $Here" -ForegroundColor Cyan
exit 0
