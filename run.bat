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
REM Existence is not enough. A .venv copied from another computer still has
REM the old interpreter path baked into every .exe in Scripts, and the
REM launcher dies with "Unable to create process using ...". So ask the
REM environment whether it actually works, and rebuild it when it does not.
set "VENV_OK="
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import uvicorn, fastapi" >nul 2>nul && set "VENV_OK=1"
)

if not defined VENV_OK (
    echo.
    if exist ".venv" (
        echo  The environment in .venv does not work on this computer, rebuilding.
        echo  This is normal when the folder was copied from another machine.
    ) else (
        echo  First run: creating the environment and installing dependencies.
    )
    echo  This takes a minute or two and needs internet access.
    echo.
    %PY% -m venv --clear .venv
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

REM python -m, not uvicorn.exe: the .exe carries a hardcoded path to the
REM interpreter it was installed with, and that path is wrong after a copy.
".venv\Scripts\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port %PORT%

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
