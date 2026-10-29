@echo off
rem ===========================================================================
rem Seep Reverse Lab - 打开产品入口（不是安装器）
rem
rem 双击本文件 = 在仓库根目录打开一个【可对话的 Agent 会话】。
rem 本文件验证安装、开启实验模式标志后转交会话；不安装依赖。
rem 还没装过？先双击同目录的 install.bat（一次性），再回来双击本文件。
rem
rem 退出码：没装好 / 没找到 pi 时为 1；启动后透传 pi 的实际退出码。
rem ===========================================================================
setlocal
chcp 65001 >nul
cd /d "%~dp0"

echo =================================================================
echo  Seep 工作台 - 会话入口
echo  仓库: %CD%
echo =================================================================
echo.

rem ---- 1) 与安装器/Pi 使用同一 AgentRoot
if not defined PI_CODING_AGENT_DIR if defined PI_AGENT_DIR set "PI_CODING_AGENT_DIR=%PI_AGENT_DIR%"
if not defined PI_CODING_AGENT_DIR set "PI_CODING_AGENT_DIR=%USERPROFILE%\.pi\agent"
set "SEEP_NOT_INSTALLED="
if not exist "%PI_CODING_AGENT_DIR%\SEEP.md" set "SEEP_NOT_INSTALLED=1"
if not exist "%PI_CODING_AGENT_DIR%\seep-runtime.json" set "SEEP_NOT_INSTALLED=1"
if not exist "%PI_CODING_AGENT_DIR%\skills\softseep\SKILL.md" set "SEEP_NOT_INSTALLED=1"
python "%CD%\Tool\scripts\runtime-root.py" validate --agent-root "%PI_CODING_AGENT_DIR%" --runtime-root "%CD%" >nul 2>nul
if errorlevel 1 set "SEEP_NOT_INSTALLED=1"
if defined SEEP_NOT_INSTALLED (
    echo [!!] 还没检测到已安装的 Agent 配置:
    echo      %PI_CODING_AGENT_DIR%
    echo      需要有效的 runtime 注册、softseep 技能与提示词；仅保留 SEEP.md 不算已安装。
    echo      请先双击仓库根目录下的 install.bat 完成安装，再回来双击本文件。
    echo.
    pause
    exit /b 1
)

rem ---- 2) 实验模式：自动开启（写 lab-mode.flag，于是「lab：」可以省略）
rem     语义不变：标志文件在 = 实验模式开；会话里说「退出实验」仍然会把它删掉。
rem     写不进去不算致命：提示一句，继续开会话（用户仍可手动输入 lab：）。
set "LABFLAG=%PI_CODING_AGENT_DIR%\lab-mode.flag"
if not exist "%PI_CODING_AGENT_DIR%" mkdir "%PI_CODING_AGENT_DIR%" 2>nul
>"%LABFLAG%" echo %DATE% %TIME% 2>nul
if exist "%LABFLAG%" echo [实验模式] 已开启（无需输入 lab：）
if not exist "%LABFLAG%" echo [!] 自动开启实验模式失败：会话照常启动，进去后可手动输入 lab：。
echo.
echo 进入会话后直接说明任务和材料。
echo 退出实验环境:      退出实验
echo 关闭本窗口 = 结束会话。
echo.

rem ---- 3) 主路径：用已安装的 pi 在当前目录（仓库根）开交互式会话
where pi >nul 2>nul
if not errorlevel 1 goto run_pi

rem ---- 4) 退化路径：没装 pi，打印一条可复制的话（不硬装、不猜路径）
echo [!] 没有在 PATH 里找到 pi 命令，无法自动开会话。请任选一种方式：
echo.
echo  A. 打开"命令提示符"，复制粘贴这一行并回车:
echo       cd /d "%CD%" ^&^& pi
echo.
echo  B. 已安装 pi-web 的话，复制粘贴这一行（浏览器里对话）:
echo       cd /d "%CD%" ^&^& pi-web
echo.
echo  C. 都没有? 说明还没装好，先双击 install.bat 完成安装。
echo.
pause
exit /b 1

:run_pi
echo [启动] pi - 当前目录即仓库根，进入后可直接对话
echo.
call pi
set "RC=%ERRORLEVEL%"
echo.
echo [结束] pi 退出码 %RC%
if not "%RC%"=="0" echo [!!] 会话异常退出，把上面的提示整段发给支持人员。
echo.
pause
exit /b %RC%
