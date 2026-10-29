@echo off
rem ===========================================================================
rem Seep Reverse Lab - 一键安装入口
rem 这是整份工作台【唯一需要双击的文件】：双击它即可，不需要自己开 PowerShell。
rem
rem 本文件只做两件事：① 环境体检（缺 Python/Node/Git 时打印一段可直接贴给 AI 的话）；
rem                    ② 转交 setup\install.ps1（真正逻辑全在那里）。
rem
rem R7 评审 P0-1（前半）：原来缺东西只打印一句“请安装 …”，客户不会做。
rem   现在改成：把「要装什么、怎么装、装完怎么办」写成一段话，
rem   客户整段复制贴给任意 AI 助手就能被代做；装完再双击本文件继续。
rem
rem 命令行用法（可选）：install.bat 等价于双击；
rem   install.bat -SkipPython -NonInteractive 等参数会原样转交 install.ps1。
rem ===========================================================================
setlocal
chcp 65001 >nul

rem ── ① 环境体检（只读：只查版本，不改任何东西）────────────────────────────
set "MISS_PY="
set "MISS_NODE="
set "MISS_GIT="
rem 所有后续脚本与 MCP 配置都调用 python；仅有 py 启动器不能证明这些入口可用。
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" >nul 2>nul
if errorlevel 1 set "MISS_PY=1"
node --version >nul 2>nul
if errorlevel 1 set "MISS_NODE=1"
git --version >nul 2>nul
if errorlevel 1 set "MISS_GIT=1"

if defined MISS_PY goto :need_ai
if defined MISS_NODE goto :need_ai
if defined MISS_GIT goto :need_ai
goto :run

:need_ai
echo.
echo ============================================================
echo  [!!] 这台机器还缺东西，先别急着装 —— 让 AI 助手帮你装
echo ============================================================
if defined MISS_PY echo   缺：可通过 python 命令运行的 Python 3.11 或更高（必装）
if defined MISS_NODE echo   缺：Node.js LTS（可选，但要 JS 逆向 / 自动化就需要）
if defined MISS_GIT echo   缺：Git for Windows（可选，但要装更新 / 回滚 / 交付就需要）
echo.
echo   ---------- 下面这段【整段复制】，直接贴给你的 AI 助手 ----------
echo   我的 Windows 电脑上要装一个逆向分析工作台，现在还缺下面这些，
echo   请帮我在这台机器上装好，并告诉我每一项装完的版本号：
echo     1. Python 3.11 或更高（安装时务必勾选 "Add python.exe to PATH"）
echo     2. Node.js LTS（同一台机器）
echo     3. Git for Windows
echo   安装方式你定：用 winget 一键装也可以，例如
echo     winget install -e --id Python.Python.3.11
echo     winget install -e --id OpenJS.NodeJS.LTS
echo     winget install -e --id Git.Git
echo   装的时候不要改我的系统代理、网卡、DNS、防火墙、注册表安全策略；
echo   装完请用 python --version / node --version / git --version 各跑一遍，
echo   把三行输出贴给我确认。我的系统是 Windows。
echo   ---------- 复制到这里结束 ----------
echo.
echo   装完这三样后，再回到这个文件夹，双击一次 install.bat 就能继续装依赖。
echo ============================================================
echo.

if defined MISS_PY goto :stop
rem Node / Git 属可选（install.ps1 只会警告）：先继续跑完，装完再双击一次即可启用相关能力。
echo   [提示] Node / Git 是可选项：本次先继续跑安装；等你装完再双击一次本文件即可。
goto :run

:stop
echo   [停止] 缺 Python 时装不下去（依赖全靠它），装完 python --version 有输出后再双击本文件。
echo.
pause
exit /b 1

rem ── ② 转交 setup\install.ps1 ─────────────────────────────────────────────
:run
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup\install.ps1" %*
set EXIT_CODE=%ERRORLEVEL%
echo.
if not "%EXIT_CODE%"=="0" echo [!!] 安装/自检未全部通过（退出码 %EXIT_CODE%），请把上面的输出整段发给支持人员。
if "%EXIT_CODE%"=="0" echo [OK] 安装流程已结束；成功与否以上面的结果为准。
echo.
pause
exit /b %EXIT_CODE%
