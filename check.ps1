# Seep Reverse Lab - 一键测试入口（唯一入口）
#   powershell -File check.ps1            -> 全量（6 套件）
#   powershell -File check.ps1 -Fast      -> 提交前快跑
param([switch]$Fast, [switch]$Detailed)
$root = $PSScriptRoot
$args2 = @()
if ($Fast) { $args2 += '--fast' }
& python (Join-Path $root 'Tool\scripts\check.py') @args2
exit $LASTEXITCODE
