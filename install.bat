@echo off
rem ===========================================================================
rem Seep Reverse Lab - 一键安装入口
rem 这是整份工作台【唯一需要双击的文件】：双击它即可，不需要自己开 PowerShell。
rem
rem 本文件只做转交（不是安装器）：真正逻辑全在 setup\install.ps1，
rem 这里不做任何安装动作、不改任何文件、不判断任何环境。
rem
rem 命令行用法（可选）：install.bat 等价于双击；
rem   install.bat -SkipPython -NonInteractive 等参数会原样转交 install.ps1。
rem ===========================================================================
setlocal
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup\install.ps1" %*
set EXIT_CODE=%ERRORLEVEL%
echo.
if not "%EXIT_CODE%"=="0" echo [!!] 安装/自检未全部通过（退出码 %EXIT_CODE%），请把上面的输出整段发给支持人员。
if "%EXIT_CODE%"=="0" echo [OK] 安装流程已结束；成功与否以上面的结果为准。
echo.
pause
exit /b %EXIT_CODE%
