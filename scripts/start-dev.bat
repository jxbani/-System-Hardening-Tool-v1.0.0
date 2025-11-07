@echo off
REM start-dev.bat - Development startup script for Windows
REM Starts Flask backend, React dev server, and Electron

setlocal enabledelayedexpansion

REM Configuration
set FLASK_PORT=5000
set REACT_PORT=3000
set MAX_WAIT=60
set CHECK_INTERVAL=2

REM Process IDs
set FLASK_PID=
set REACT_PID=

REM Colors (using Windows 10+ ANSI support)
set "GREEN=[32m"
set "YELLOW=[33m"
set "BLUE=[34m"
set "RED=[31m"
set "NC=[0m"

echo %GREEN%========================================%NC%
echo %GREEN%  System Hardening Tool - Dev Startup  %NC%
echo %GREEN%========================================%NC%
echo.

REM Get project root directory
set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
cd /d "%PROJECT_ROOT%"

echo %BLUE%Project root: %PROJECT_ROOT%%NC%
echo.

REM Check if required directories exist
if not exist "%PROJECT_ROOT%\src\backend" (
    echo %RED%Error: Backend directory not found%NC%
    exit /b 1
)

if not exist "%PROJECT_ROOT%\src\frontend" (
    echo %RED%Error: Frontend directory not found%NC%
    exit /b 1
)

REM Create logs directory if it doesn't exist
if not exist "%PROJECT_ROOT%\logs" (
    mkdir "%PROJECT_ROOT%\logs"
)

REM Check if ports are available
echo %BLUE%Checking port availability...%NC%

netstat -ano | findstr ":%FLASK_PORT% " | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
    echo %RED%Error: Port %FLASK_PORT% is already in use%NC%
    echo %YELLOW%Please stop the process using this port or change FLASK_PORT%NC%
    exit /b 1
)

netstat -ano | findstr ":%REACT_PORT% " | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
    echo %RED%Error: Port %REACT_PORT% is already in use%NC%
    echo %YELLOW%Please stop the process using this port or change REACT_PORT%NC%
    exit /b 1
)

echo %GREEN%Ports are available%NC%
echo.

REM Determine Python command
where python >nul 2>&1
if %errorlevel% equ 0 (
    set PYTHON_CMD=python
) else (
    where python3 >nul 2>&1
    if %errorlevel% equ 0 (
        set PYTHON_CMD=python3
    ) else (
        echo %RED%Error: Python not found%NC%
        exit /b 1
    )
)

REM Check if Flask app exists
set "FLASK_APP=%PROJECT_ROOT%\src\backend\app.py"
if not exist "%FLASK_APP%" (
    echo %RED%Error: Flask app not found at %FLASK_APP%%NC%
    exit /b 1
)

REM Start Flask backend
echo %BLUE%Starting Flask backend...%NC%
cd /d "%PROJECT_ROOT%"

set FLASK_ENV=development
set PORT=%FLASK_PORT%

start /B cmd /c "%PYTHON_CMD% "%FLASK_APP%" > "%PROJECT_ROOT%\logs\flask.log" 2>&1"

REM Get Flask PID (approximate - Windows doesn't make this easy)
for /f "tokens=2" %%a in ('tasklist /fi "imagename eq python.exe" /fo list ^| findstr "PID:"') do (
    set FLASK_PID=%%a
)

echo %GREEN%Flask backend started%NC%
echo %YELLOW%Flask logs: %PROJECT_ROOT%\logs\flask.log%NC%
echo.

REM Wait for Flask to be ready
echo %BLUE%Waiting for Flask backend on port %FLASK_PORT%...%NC%
set /a elapsed=0

:wait_flask
if !elapsed! geq %MAX_WAIT% (
    echo %RED%Timeout waiting for Flask backend%NC%
    echo %YELLOW%Check logs at: %PROJECT_ROOT%\logs\flask.log%NC%
    goto cleanup
)

netstat -ano | findstr ":%FLASK_PORT% " | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
    echo %GREEN%Flask backend is ready!%NC%
    goto flask_ready
)

timeout /t %CHECK_INTERVAL% /nobreak >nul
set /a elapsed+=CHECK_INTERVAL
echo %YELLOW%Waiting... (!elapsed!/%MAX_WAIT%s)%NC%
goto wait_flask

:flask_ready

REM Start React dev server
echo.
echo %BLUE%Starting React dev server...%NC%
cd /d "%PROJECT_ROOT%\src\frontend"

REM Check if package.json exists
if not exist "package.json" (
    echo %RED%Error: Frontend package.json not found%NC%
    goto cleanup
)

REM Check if node_modules exists
if not exist "node_modules" (
    echo %YELLOW%node_modules not found. Running npm install...%NC%
    call npm install
    if %errorlevel% neq 0 (
        echo %RED%Failed to install frontend dependencies%NC%
        goto cleanup
    )
)

REM Start React dev server in background
start /B cmd /c "npm run dev > "%PROJECT_ROOT%\logs\react.log" 2>&1"

REM Get React PID (approximate)
for /f "tokens=2" %%a in ('tasklist /fi "imagename eq node.exe" /fo list ^| findstr "PID:"') do (
    set REACT_PID=%%a
)

echo %GREEN%React dev server started%NC%
echo %YELLOW%React logs: %PROJECT_ROOT%\logs\react.log%NC%
echo.

REM Wait for React to be ready
echo %BLUE%Waiting for React dev server on port %REACT_PORT%...%NC%
set /a elapsed=0

:wait_react
if !elapsed! geq %MAX_WAIT% (
    echo %RED%Timeout waiting for React dev server%NC%
    echo %YELLOW%Check logs at: %PROJECT_ROOT%\logs\react.log%NC%
    goto cleanup
)

netstat -ano | findstr ":%REACT_PORT% " | findstr "LISTENING" >nul
if %errorlevel% equ 0 (
    echo %GREEN%React dev server is ready!%NC%
    goto react_ready
)

timeout /t %CHECK_INTERVAL% /nobreak >nul
set /a elapsed+=CHECK_INTERVAL
echo %YELLOW%Waiting... (!elapsed!/%MAX_WAIT%s)%NC%
goto wait_react

:react_ready

REM Start Electron
echo.
echo %BLUE%Starting Electron...%NC%
cd /d "%PROJECT_ROOT%"

REM Check if node_modules exists in root
if not exist "node_modules" (
    echo %YELLOW%node_modules not found in root. Running npm install...%NC%
    call npm install
    if %errorlevel% neq 0 (
        echo %RED%Failed to install root dependencies%NC%
        goto cleanup
    )
)

REM Set environment variables for Electron
set NODE_ENV=development

echo %GREEN%========================================%NC%
echo %GREEN%All services are ready!%NC%
echo %GREEN%========================================%NC%
echo %BLUE%Flask backend:     http://localhost:%FLASK_PORT%%NC%
echo %BLUE%React dev server:  http://localhost:%REACT_PORT%%NC%
echo %YELLOW%Press Ctrl+C to stop all services%NC%
echo.

REM Start Electron (this will block until Electron exits)
call npm run electron:dev

REM When Electron exits, cleanup
echo %GREEN%Electron exited%NC%
goto cleanup

:cleanup
echo.
echo %YELLOW%Cleaning up processes...%NC%

REM Kill processes on Flask port
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%FLASK_PORT% " ^| findstr "LISTENING"') do (
    echo %BLUE%Stopping Flask backend (PID: %%a)...%NC%
    taskkill /F /PID %%a >nul 2>&1
)

REM Kill processes on React port
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":%REACT_PORT% " ^| findstr "LISTENING"') do (
    echo %BLUE%Stopping React dev server (PID: %%a)...%NC%
    taskkill /F /PID %%a >nul 2>&1
)

REM Additional cleanup - kill any stray Python and Node processes related to our app
REM (Be careful with this - it might kill other Python/Node processes)
REM Uncomment if needed:
REM taskkill /F /IM python.exe /T >nul 2>&1
REM taskkill /F /IM node.exe /T >nul 2>&1

echo %GREEN%Cleanup complete%NC%

endlocal
exit /b 0
