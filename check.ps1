#Requires -Version 5.1
<#
  Seep Reverse Lab — 根目录快捷健康体检入口（版本取自 VERSION 文件）
  ================================================================
  本文件为根目录便捷入口，真实校验流水线位于 setup\verify.ps1。
  支持 60 项核心资产全维度自动化体检。

  用法:
    powershell -ExecutionPolicy Bypass -File .\check.ps1
    powershell -ExecutionPolicy Bypass -File .\check.ps1 -Detailed
#>
& (Join-Path $PSScriptRoot 'setup\verify.ps1') @args
exit $LASTEXITCODE
