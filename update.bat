@echo off
rem ================================================================
rem Seep Reverse Lab — 根目录一键更新批处理入口（版本取自 VERSION 文件）
rem 实际执行: setup\update.ps1 (已自适应个人 Fork 仓库)
rem ================================================================
setlocal
chcp 65001 >nul
title Seep Reverse Lab - Updater
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup\update.ps1" %*
set EXIT_CODE=%ERRORLEVEL%
echo.
pause
exit /b %EXIT_CODE%
