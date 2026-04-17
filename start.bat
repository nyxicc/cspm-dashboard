@echo off
echo Starting CSPM Dashboard...
echo.

REM Load variables from .env if it exists
if exist "%~dp0.env" (
  for /f "usebackq tokens=1,* delims==" %%A in ("%~dp0.env") do set "%%A=%%B"
)

REM Build the backend binary if it doesn't exist.
REM Running the pre-built exe avoids a 60s+ recompile on every start.
pushd "%~dp0backend"
if not exist "cspm-backend.exe" (
  echo Building backend binary...
  go build -o cspm-backend.exe .
)
REM Use cmd /c to pass a script file so env vars (ANTHROPIC_API_KEY etc.)
REM are inherited by the new window — cmd /k with a quoted string drops them.
start "CSPM Backend" cmd /k "cspm-backend.exe"
popd

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
