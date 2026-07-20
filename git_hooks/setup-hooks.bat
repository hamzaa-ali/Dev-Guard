@echo off
:: ═══════════════════════════════════════════════════════════
:: DevGuard Git Hook Setup Script (Windows)
::
:: Run this script once to install the pre-push hook.
:: After installation, every git push will be scanned.
::
:: Usage: Double-click this file OR run in terminal:
::   git_hooks\setup-hooks.bat
:: ═══════════════════════════════════════════════════════════

echo.
echo ╔══════════════════════════════════════════╗
echo ║     DevGuard Hook Setup (Windows)        ║
echo ╚══════════════════════════════════════════╝
echo.

:: Check if .git folder exists
if not exist ".git" (
    echo ERROR: Run this script from the root of your git repository.
    echo        You must be in the folder that contains the .git folder.
    echo.
    pause
    exit /b 1
)

:: Create hooks directory if it doesn't exist
if not exist ".git\hooks" mkdir ".git\hooks"

:: Copy the pre-push hook
echo Installing pre-push hook...
copy /Y "git_hooks\pre-push" ".git\hooks\pre-push" >nul

if %errorlevel% neq 0 (
    echo ERROR: Failed to copy hook file.
    pause
    exit /b 1
)

echo.
echo ✅ Pre-push hook installed successfully!
echo.
echo    From now on, every git push will be scanned
echo    for hardcoded secrets before leaving your machine.
echo.
echo    To test: try pushing a file with a fake API key.
echo    The push will be blocked automatically.
echo.
pause