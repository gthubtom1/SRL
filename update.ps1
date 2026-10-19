#Requires -Version 5.1
<#
  Seep Reverse Lab (v1.8.0 增强版) — 根目录一键更新快捷入口
  ================================================================
  本文件为根目录便捷入口，真实更新流水线位于 setup\update.ps1。
  已完全适配个人 Fork 仓库（自动以当前 Git origin 为准，绝不覆盖回原版）。

  用法：
    powershell -ExecutionPolicy Bypass -File .\update.ps1
    powershell -ExecutionPolicy Bypass -File .\update.ps1 -DryRun
#>
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scriptDir 'setup\update.ps1') @args
exit $LASTEXITCODE
