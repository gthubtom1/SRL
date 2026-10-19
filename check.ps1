#Requires -Version 5.1
<#
  Seep Reverse Lab (v1.8.0 增强版) — 根目录快捷健康体检入口
  ================================================================
  本文件为根目录便捷入口，真实校验流水线位于 setup\verify.ps1。
  支持 55 项核心资产全维度自动化体检。

  用法:
    powershell -ExecutionPolicy Bypass -File .\check.ps1
    powershell -ExecutionPolicy Bypass -File .\check.ps1 -Detailed
#>
& (Join-Path $PSScriptRoot 'setup\verify.ps1') @args
exit $LASTEXITCODE
