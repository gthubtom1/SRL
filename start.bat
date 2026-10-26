@echo off
rem ===========================================================================
rem Seep Reverse Lab - 打开产品入口（不是安装器）
rem
rem 双击本文件 = 在仓库根目录打开一个【可对话的 Agent 会话】。
rem 本文件只做"转交 + 提示"：不安装任何东西、不改任何文件、不判断环境是否合格。
rem 还没装过？先双击同目录的 install.bat（一次性），再回来双击本文件。
rem
rem 退出码：0 = 会话正常结束；1 = 没装好 / 没找到 pi 命令（看屏幕上的提示）。
rem ===========================================================================
setlocal
chcp 65001 >nul
cd /d "%~dp0"

echo =================================================================
echo  Seep 工作台 - 会话入口
echo  仓库: %CD%
echo =================================================================
echo.

rem ---- 1) 最小前置检查：Agent 配置没落地就别开会话（否则用户对着空壳说话）
if not exist "%USERPROFILE%\.pi\agent\SEEP.md" (
    echo [!!] 还没检测到已安装的 Agent 配置:
    echo      %USERPROFILE%\.pi\agent\SEEP.md
    echo      请先双击仓库根目录下的 install.bat 完成安装，再回来双击本文件。
    echo.
    pause
    exit /b 1
)

echo 进入会话后先输入:  lab：
echo 退出实验环境:      退出实验
echo 关闭本窗口 = 结束会话。
echo.

rem ---- 2) 主路径：用已安装的 pi 在当前目录（仓库根）开交互式会话
where pi >nul 2>nul
if not errorlevel 1 goto run_pi

rem ---- 3) 退化路径：没装 pi，打印一条可复制的话（不硬装、不猜路径）
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
