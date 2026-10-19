@echo off
rem ================================================================
rem Seep Reverse Lab — 根目录一键体检批处理入口（版本取自 VERSION 文件）
rem 实际执行: setup\verify.ps1 (支持 60 项全维度自检)
rem ================================================================
setlocal
chcp 65001 >nul
title Seep Reverse Lab - Verifier
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup\verify.ps1" %*
set EXIT_CODE=%ERRORLEVEL%
echo.
pause
exit /b %EXIT_CODE%
