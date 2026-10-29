@echo off
chcp 65001 >nul
setlocal
REM Optional pi-web launcher. Set PI_WEB_HOSTNAME and PI_WEB_PORT to select
REM the interface and port; existing authentication/allowed-host settings remain.
cd /d "%~dp0.."
if not defined PI_CODING_AGENT_DIR if defined PI_AGENT_DIR set "PI_CODING_AGENT_DIR=%PI_AGENT_DIR%"
if not defined PI_WEB_HOSTNAME set "PI_WEB_HOSTNAME=127.0.0.1"
if not defined PI_WEB_PORT set "PI_WEB_PORT=30141"
set "PI_WEB_NO_OPEN=1"
where pi-web >nul 2>nul
if errorlevel 1 (
    echo [x] 找不到 pi-web。请先安装可用宿主，并确认 pi-web 在 PATH 中。
    pause
    exit /b 1
)

title Seep - pi-web
echo 启动 pi-web: %PI_WEB_HOSTNAME%:%PI_WEB_PORT%
echo 如需局域网访问，可先设置 PI_WEB_HOSTNAME；沿用已有宿主访问配置。
echo 保持这个窗口开着；端口冲突时请根据宿主报错处理。
echo.
call pi-web -H "%PI_WEB_HOSTNAME%" -p "%PI_WEB_PORT%" --no-open %*
set "RC=%ERRORLEVEL%"
echo.
echo pi-web 已退出，退出码 %RC%。按任意键关闭。
pause >nul
exit /b %RC%
