@echo off
setlocal enabledelayedexpansion

rem Interactive launcher. The scanner saves and displays its own report before
rem offering follow-up actions. Quitting the start menu is not a scan result.

title Zero Breach Toolkit - spyware indicator check

rem Run from this script's own folder, so the default IOC path resolves.
cd /d "%~dp0"

rem Find Python: the PATH first, then the py launcher.
set "PY="
where python >nul 2>&1
if %errorlevel%==0 set "PY=python"
if not defined PY (
  where py >nul 2>&1
  if !errorlevel!==0 set "PY=py"
)
if not defined PY (
  echo.
  echo  Python was not found on this PC.
  echo.
  echo  Install Python from https://www.python.org/downloads/ and tick
  echo  "Add python.exe to PATH" in the installer, then run this again.
  echo.
  pause
  exit /b 1
)

rem Timestamp for the saved report, via Python so the format is not locale-dependent.
set "STAMP="
for /f "delims=" %%T in ('%PY% -c "import datetime;print(datetime.datetime.now().strftime('%%Y%%m%%d-%%H%%M%%S'))"') do set "STAMP=%%T"
if not defined STAMP set "STAMP=latest"

rem Resolve ..\findings to a real absolute path, so the "Saved:" lines printed at
rem the end read as a path someone can actually copy, not one containing "..".
for %%I in ("%~dp0..\findings") do set "OUTDIR=%%~fI"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
set "TXT=%OUTDIR%\scan-%STAMP%.txt"
set "JSON=%OUTDIR%\scan-%STAMP%.json"

cls
echo ========================================================================
echo   Zero Breach Toolkit - choose what to check
echo ========================================================================
echo.
echo  Checks read local evidence and do not change system settings.
echo  Reports are saved locally. Updates use the internet; guided Android
echo  acquisition collects private phone records after owner consent.
echo.
echo  Choose a check from the menu. Progress appears while it runs.
echo  Press Ctrl+C once to stop a check and preserve completed evidence.
echo.
echo ========================================================================
echo.

rem Keep stdout visible for acquisition prompts and the post-scan workflow.
%PY% -X utf8 zero-breach-toolkit.py --json "%JSON%" --report "%TXT%"
set "RC=%errorlevel%"

echo.
echo ========================================================================
if "%RC%"=="4" (
  echo   Nothing was checked. No scan verdict or report was produced.
) else if "%RC%"=="2" (
  echo   RESULT: something matched. Read the report above - a match means
  echo   INVESTIGATE, not "you are infected". The referral links above are
  echo   the right next step.
) else if "%RC%"=="0" (
  echo   RESULT: no actionable findings. Saved references may be listed.
  echo   Read the report above -
  echo   it is not a clean bill of health.
) else if "%RC%"=="3" (
  echo   RESULT: no actionable findings, but some checks or indicator sources
  echo   were incomplete. Read the gaps above; those places were not cleared.
) else (
  echo   The scan could not run properly. The report above says why.
)
echo.
if not "%RC%"=="4" (
  if exist "%TXT%" echo   Saved: %TXT%
  if exist "%JSON%" echo   Saved: %JSON%
)
echo ========================================================================
echo.
pause
endlocal
