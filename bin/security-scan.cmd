@echo off
rem Run scan.py next to this folder (prefers the py launcher, falls back to python)
setlocal
set "ROOT=%~dp0.."
where py >nul 2>nul && (py -3 "%ROOT%\scan.py" %* & exit /b %ERRORLEVEL%)
python "%ROOT%\scan.py" %*
exit /b %ERRORLEVEL%
