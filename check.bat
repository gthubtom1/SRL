@echo off
rem Seep Reverse Lab - one-click test (delegates to check.ps1 -> Tool/scripts/check.py)
setlocal
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0check.ps1" %*
set EXIT_CODE=%ERRORLEVEL%
echo.
pause
exit /b %EXIT_CODE%
