@echo off
setlocal enabledelayedexpansion

echo ==================================================
echo   pcdlint - Prompt-Cache Determinism Linter
echo   Setup ^& Verification Script (Windows)
echo ==================================================
echo.

echo [1/5] Checking Python environment...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    exit /b 1
)

python -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)"
if errorlevel 1 (
    echo ERROR: Python 3.10+ is required.
    exit /b 1
)
echo   Python version check passed.

echo.
echo [2/5] Setting up virtual environment...
if not exist ".venv" (
    echo   Creating virtual environment at .venv...
    python -m venv .venv
)
call .venv\Scripts\activate.bat

echo.
echo [3/5] Installing package with dev dependencies...
pip install --upgrade pip -q
pip install -e ".[dev]" -q
if errorlevel 1 (
    echo ERROR: installation failed.
    exit /b 1
)
echo   Installation complete.

echo.
echo [4/5] Running test suite...
python -m pytest -v
if errorlevel 1 (
    echo ERROR: test suite failed.
    exit /b 1
)

echo.
echo [5/5] Running verification on demo files...
echo.
echo --- Testing Clean / Good Case (demo_good.py) ---
python -m pcdlint.cli check examples/demo_good.py
if errorlevel 1 (
    echo ERROR: demo_good.py should produce 0 errors.
    exit /b 1
)

echo.
echo --- Testing Buggy Case (demo_buggy.py) ---
python -m pcdlint.cli check examples/demo_buggy.py
REM Exit 1 means findings, which is what this demo is for. Exit 0 means it
REM stopped demonstrating the bugs, and exit 2 means pcdlint could not
REM analyze it -- a broken run must not pass for the same reason a clean
REM one must not fail. `if not errorlevel 1` alone would accept 2.
if errorlevel 2 (
    echo ERROR: pcdlint could not analyze demo_buggy.py.
    exit /b 1
)
if not errorlevel 1 (
    echo ERROR: demo_buggy.py should report violations and exit with code 1.
    exit /b 1
)

echo.
echo ==================================================
echo   Setup ^& Verification Successful!
echo ==================================================
echo.
echo Usage:
echo   pcdlint check ^<file_or_dir^>
echo   pcdlint check src/ --format json
echo   pytest
echo.
