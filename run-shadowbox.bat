@echo off
setlocal
title ShadowBox launcher
cd /d "%~dp0"
set "ROOT=%~dp0"
set "PY=%ROOT%.venv\Scripts\python.exe"

where npm >nul 2>nul
if errorlevel 1 (
  echo [ERROR] Node.js / npm not found. Install it from https://nodejs.org then run again.
  pause
  exit /b 1
)

if not exist "%PY%" (
  echo [1/3] Creating Python virtual environment...
  where python >nul 2>nul
  if errorlevel 1 (
    echo [ERROR] Python not found on PATH. Install Python 3.10 or newer then run again.
    pause
    exit /b 1
  )
  python -m venv "%ROOT%.venv"
  if errorlevel 1 (
    echo [ERROR] Could not create the virtual environment.
    pause
    exit /b 1
  )
)

"%PY%" -c "import fastapi, uvicorn, yara_x" >nul 2>nul
if errorlevel 1 (
  echo [2/3] Installing backend dependencies...
  "%PY%" -m pip install -r "%ROOT%backend\requirements.txt"
  if errorlevel 1 (
    echo [ERROR] pip install failed. Check your internet connection.
    pause
    exit /b 1
  )
)

if not exist "%ROOT%apps\web\node_modules" (
  echo [3/3] Installing web dependencies...
  pushd "%ROOT%apps\web"
  call npm install
  if errorlevel 1 (
    popd
    echo [ERROR] npm install failed.
    pause
    exit /b 1
  )
  popd
)

echo Starting ShadowBox backend on http://127.0.0.1:8000
start "ShadowBox Backend" /d "%ROOT%backend" cmd /k ""%PY%" -m uvicorn app.main:app --host 127.0.0.1 --port 8000"

echo Starting ShadowBox web UI on http://127.0.0.1:5173
start "ShadowBox Web" /d "%ROOT%apps\web" cmd /k "npm run dev"

timeout /t 5 /nobreak >nul
start "" "http://127.0.0.1:5173"

echo.
echo ShadowBox is running in two new windows (Backend and Web).
echo Close those two windows to stop it. API docs: http://127.0.0.1:8000/docs
echo.
pause
endlocal
