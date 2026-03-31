@echo off
echo Starting CSPM Dashboard...
echo.

REM Start the Go backend in a new window
start "CSPM Backend" cmd /k "cd /d "%~dp0backend" && go run . && pause"

REM Give the backend a moment to start
timeout /t 2 /nobreak > nul

REM Start the frontend in this window
cd /d "%~dp0frontend"
npm run dev
