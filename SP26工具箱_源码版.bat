@echo off
setlocal
cd /d "%~dp0"
set "SP26PYW="
where pythonw >nul 2>&1 && set "SP26PYW=pythonw"
if not defined SP26PYW (
  where py >nul 2>&1 && set "SP26PYW=py -3w"
)
if not defined SP26PYW (
  echo [ERROR] pythonw not found. Install Python 3 or add it to PATH.
  pause
  exit /b 1
)
wscript //nologo "launch_panel.vbs"
exit /b 0
