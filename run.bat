@echo off
REM ---------------------------------------------------------------------------
REM Tikpilot launcher for Windows. Just double-click this file.
REM
REM NOTE for developers: keep this file ASCII-only with CRLF line endings, and
REM never switch the console code page from inside the script. Doing either
REM breaks the way cmd.exe parses the rest of the file.
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"
title Tikpilot

REM --- 1. Looking for Python -------------------------------------------------
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"

if not defined PY (
    echo.
    echo  [!] Python not found.
    echo.
    echo  Download it here: https://www.python.org/downloads/
    echo  Important: tick "Add python.exe to PATH" during the install.
    echo  Then reopen this folder and run run.bat again.
    echo.
    pause
    exit /b 1
)

REM --- 2. Virtual environment ------------------------------------------------
if not exist ".venv\Scripts\uvicorn.exe" (
    echo.
    echo  First run: creating the environment and installing dependencies.
    echo  This takes a minute or two and needs internet access.
    echo.
    %PY% -m venv .venv
    if errorlevel 1 goto error
    ".venv\Scripts\python.exe" -m pip install --upgrade pip --quiet --disable-pip-version-check
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt --disable-pip-version-check
    if errorlevel 1 goto error
    echo.
    echo  Dependencies installed.
)

REM --- 3. Run ----------------------------------------------------------------
if "%PORT%"=="" set PORT=8080

echo.
echo  ============================================================
echo    Tikpilot is running:  http://127.0.0.1:%PORT%
echo    Login: admin            Password: admin
echo.
echo    Do not close this window, the server runs inside it.
echo    To stop: Ctrl+C
echo  ============================================================
echo.

REM Open the browser after a short delay without blocking the server start
start "" /b powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 4; Start-Process 'http://127.0.0.1:%PORT%'" >nul 2>nul

".venv\Scripts\uvicorn.exe" app.main:app --host 0.0.0.0 --port %PORT%

echo.
echo  Server stopped.
pause
exit /b 0

:error
echo.
echo  [!] Something went wrong, read the text above.
echo.
pause
exit /b 1
