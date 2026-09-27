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
echo   Installation complete.

echo.
echo [4/5] Running test suite...
python -m pytest -v

echo.
echo [5/5] Running verification on demo files...
echo.
echo --- Testing Clean / Good Case (demo_good.py) ---
python -m pcdlint.cli check demo_good.py
if errorlevel 1 (
    echo ERROR: demo_good.py should produce 0 errors.
    exit /b 1
)

echo.
echo --- Testing Buggy Case (demo_buggy.py) ---
python -m pcdlint.cli check demo_buggy.py

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
