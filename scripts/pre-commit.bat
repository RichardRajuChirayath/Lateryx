@echo off
REM ============================================
REM Lateryx Pre-Commit Hook (Windows)
REM ============================================
REM Automatically scans your Terraform files for security issues
REM before allowing a commit.
REM
REM INSTALLATION:
REM   1. Copy this file to: .git\hooks\pre-commit
REM   2. Remove the .bat extension
REM ============================================

echo.
echo [93m🛡️  Lateryx Pre-Commit Security Check[0m
echo ────────────────────────────────────────

REM Check if lateryx is available
python -c "from src.cli import main" 2>nul
if errorlevel 1 (
    echo [93m⚠️  Lateryx not found in Python path. Skipping scan.[0m
    echo    Install with: pip install -e .
    exit /b 0
)

REM Find and scan Terraform directories
set HAS_ISSUES=false

for /r %%d in (*.tf) do (
    set "tf_dir=%%~dpd"
    goto :found_tf
)
goto :no_tf

:found_tf
echo.
echo [93m📂 Scanning current directory for Terraform files...[0m
python -m src.cli scan . --fail-on-breach --severity HIGH
if errorlevel 1 (
    set HAS_ISSUES=true
)
goto :check_result

:no_tf
echo [92m✅ No Terraform files found. Skipping security scan.[0m
exit /b 0

:check_result
echo.
echo ────────────────────────────────────────

if "%HAS_ISSUES%"=="true" (
    echo.
    echo [91m╔════════════════════════════════════════════════════════════╗[0m
    echo [91m║  ❌ COMMIT BLOCKED                                         ║[0m
    echo [91m║  Security issues were detected in your infrastructure.     ║[0m
    echo [91m║                                                            ║[0m
    echo [91m║  Please fix the issues above before committing.            ║[0m
    echo [91m║  To bypass (not recommended): git commit --no-verify       ║[0m
    echo [91m╚════════════════════════════════════════════════════════════╝[0m
    echo.
    exit /b 1
) else (
    echo [92m✅ All security checks passed. Proceeding with commit.[0m
    echo.
    exit /b 0
)
