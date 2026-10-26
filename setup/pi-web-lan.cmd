@echo off
chcp 65001 >nul
setlocal
REM ============================================================
REM  pi-web 启动器（LAN + Tailscale，无密码）
REM  0.0.0.0 是"监听所有网卡"，不是网址；本脚本只打印能打开的地址。
REM  路径全部动态解析（node 从 PATH 找、pi-web 从 npm root -g 推），不写死盘符。
REM ============================================================

REM --- 局域网 IP（走默认路由的那块网卡）---
set "LANIP="
for /f "usebackq delims=" %%I in (`powershell -NoProfile -Command "$r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1; (Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $r.InterfaceIndex).IPAddress"`) do set "LANIP=%%I"
if not defined LANIP set "LANIP=127.0.0.1"

REM --- node 与 pi-web 的入口 ---
set "NODE="
for /f "delims=" %%N in ('where node 2^>nul') do if not defined NODE set "NODE=%%N"
if not defined NODE if exist "%ProgramFiles%\nodejs\node.exe" set "NODE=%ProgramFiles%\nodejs\node.exe"
set "PIWEB="
for /f "delims=" %%R in ('npm root -g 2^>nul') do if not defined PIWEB set "PIWEB=%%R\@agegr\pi-web\bin\pi-web.js"
if not defined PIWEB set "PIWEB=%APPDATA%\npm\node_modules\@agegr\pi-web\bin\pi-web.js"

if not defined NODE echo [x] 找不到 node.exe：先装 Node.js LTS，再双击本文件。& pause & exit /b 1
if not exist "%PIWEB%" echo [x] 找不到 pi-web：先跑 npm i -g @agegr/pi-web，再双击本文件。& pause & exit /b 1

title pi-web :30141   LAN http://%LANIP%:30141

set "PI_WEB_HOSTNAME=0.0.0.0"
set "PI_WEB_ALLOWED_HOSTS=127.0.0.1,localhost,%LANIP%,desktop-k0m8llt.taila4f324.ts.net"
set "PI_WEB_PASSWORD="
set "PI_WEB_NO_OPEN=1"

echo [1/3] 停掉旧的 :30141 ...
for /f "tokens=5" %%P in ('netstat -ano ^| findstr /c:":30141" ^| findstr /i "LISTENING"') do taskkill /PID %%P /T /F >nul 2>&1
timeout /t 2 /nobreak >nul

echo [2/3] 启动 pi-web（监听所有网卡，端口 30141）...
echo.
echo         本机打开    http://127.0.0.1:30141
echo         局域网      http://%LANIP%:30141
echo         Tailscale   http://100.96.110.117:30141
echo         MagicDNS    http://desktop-k0m8llt.taila4f324.ts.net:30141
echo.
echo         注意：0.0.0.0:30141 只是监听地址，浏览器不能直接开。
echo [3/3] 保持这个窗口开着（关掉 = 停止服务）

"%NODE%" "%PIWEB%" -H 0.0.0.0 -p 30141 --no-open

echo.
echo pi-web 已退出。按任意键关闭。
pause >nul
