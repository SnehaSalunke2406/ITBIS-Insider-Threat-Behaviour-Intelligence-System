@echo off
setlocal
cd /d "%~dp0"

title Insider Threat Behaviour Intelligence System

echo.
echo ============================================================
echo   INSIDER THREAT BEHAVIOUR INTELLIGENCE SYSTEM
echo ============================================================
echo.
echo This Windows launcher does NOT use Docker.
echo.

set "PY="
if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PY if exist "%ProgramFiles%\Python312\python.exe" set "PY=%ProgramFiles%\Python312\python.exe"
if not defined PY (
    where py >nul 2>&1
    if not errorlevel 1 set "PY=py -3.12"
)
if not defined PY (
    where python >nul 2>&1
    if not errorlevel 1 set "PY=python"
)

if not defined PY (
    echo ERROR: Python 3.12 was not found.
    echo Please install Python 3.12 and run this file again.
    goto FAIL
)

echo [1/4] Using Python: %PY%

if not exist ".venv\Scripts\python.exe" (
    echo [2/4] Creating virtual environment...
    %PY% -m venv .venv
    if errorlevel 1 goto FAIL
) else (
    echo [2/4] Virtual environment already exists.
)

if not exist ".env" (
    echo Creating local configuration...
    copy /Y ".env.example" ".env" >nul
)

echo [3/4] Installing/checking Python packages...
".venv\Scripts\python.exe" -m pip install -r "backend\requirements.txt"
if errorlevel 1 goto FAIL

echo [4/4] Initializing demo data and starting server...
pushd backend
"..\.venv\Scripts\python.exe" seed.py
if errorlevel 1 (
    popd
    goto FAIL
)

echo.
echo ============================================================
echo   ITBIS IS RUNNING
echo   Open: http://localhost:8000
echo   Login: admin@ueba.com
echo   Password: admin123
echo ============================================================
echo.
"..\.venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
popd

echo.
echo Server stopped.
goto END

:FAIL
echo.
echo ============================================================
echo   ITBIS DID NOT START
echo ============================================================
echo Read the ERROR shown above and send it to ChatGPT.
echo.

:END
pause
endlocal
