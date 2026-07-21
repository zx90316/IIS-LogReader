@echo off
setlocal
cd /d "%~dp0"
echo Building antivirus-friendly standalone release (default)...
echo For onefile: scripts\build_nuitka.ps1 -Mode onefile
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\build_nuitka.ps1" -Mode standalone %*
if errorlevel 1 (
  echo.
  echo Build failed.
  pause
  exit /b 1
)
echo.
pause
