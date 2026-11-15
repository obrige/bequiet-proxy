@echo off
REM 启动 bequiet-proxy（HTTP 代理 9090 / SOCKS5 代理 1080）
REM Start bequiet-proxy (HTTP proxy on 9090, SOCKS5 proxy on 1080)
setlocal
where python >nul 2>&1 || (echo python not found in PATH & exit /b 1)
python "%~dp0bequiet_proxy.py" --http-port 9090 --socks-port 1080 %*
endlocal
