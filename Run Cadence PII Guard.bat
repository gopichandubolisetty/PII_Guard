@echo off
setlocal
set "SCRIPT=%~dp0cadence_pii_guard.py"

if exist "%~dp0.venv\Scripts\python.exe" (
  "%~dp0.venv\Scripts\python.exe" "%SCRIPT%"
  goto done
)

where py >nul 2>nul
if not errorlevel 1 (
  py -3 "%SCRIPT%"
  goto done
)

where python >nul 2>nul
if not errorlevel 1 (
  python "%SCRIPT%"
  goto done
)

echo Python 3 was not found. Install Python 3, then follow README.md to create .venv and install requirements.
pause

:done
endlocal
