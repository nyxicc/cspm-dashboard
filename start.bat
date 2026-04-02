@echo off
echo Starting CSPM Dashboard...
echo.

REM Load variables from .env if it exists
if exist "%~dp0.env" (
  for /f "usebackq tokens=1,* delims==" %%A in ("%~dp0.env") do set "%%A=%%B"
)

REM Start the Go backend in a new window (inherits env vars set above)
set "BACKEND_DIR=%~dp0backend"
start "CSPM Backend" cmd /k "cd /d "%BACKEND_DIR%" && go run . && pause"

REM Wait until the backend is actually listening on port 8080
echo Waiting for backend to be ready...
:waitloop
timeout /t 1 /nobreak > nul
powershell -Command "try { (New-Object Net.Sockets.TcpClient('localhost', 8080)).Close(); exit 0 } catch { exit 1 }" > nul 2>&1
if errorlevel 1 goto waitloop
echo Backend is ready.

REM Start the frontend in this window
cd /d "%~dp0frontend"
start "" "http://localhost:5173"
npm run dev
