#!/usr/bin/env bash
# ==============================================================================
# pcdlint - Setup & Installation Script
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "=================================================="
echo "  pcdlint - Prompt-Cache Determinism Linter"
echo "  Setup & Verification Script"
echo "=================================================="
echo ""

# 1. Check Python environment
echo "[1/5] Checking Python environment..."
PYTHON_BIN=""
# Test which binary actually works (avoid Windows store stubs)
for cmd in python python3; do
    if command -v "$cmd" &>/dev/null && "$cmd" -c "import sys" &>/dev/null; then
        PYTHON_BIN="$cmd"
        break
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "ERROR: Working Python executable not found in PATH."
    exit 1
fi

PY_VER=$($PYTHON_BIN -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "  Found Python: $PY_VER ($($PYTHON_BIN --version))"

$PYTHON_BIN -c "import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)" || {
    echo "ERROR: Python 3.10+ is required (found $PY_VER)."
    exit 1
}

# 2. Virtual Environment Setup (skip if already inside virtual environment or create .venv)
echo ""
echo "[2/5] Setting up virtual environment..."
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "  Creating virtual environment at $VENV_DIR..."
    $PYTHON_BIN -m venv "$VENV_DIR" || echo "  Using existing environment."
fi

if [ -f "$VENV_DIR/bin/activate" ]; then
    source "$VENV_DIR/bin/activate"
elif [ -f "$VENV_DIR/Scripts/activate" ]; then
    source "$VENV_DIR/Scripts/activate"
fi

# 3. Install dependencies
echo ""
echo "[3/5] Installing package in editable mode with dev dependencies..."
$PYTHON_BIN -m pip install -e ".[dev]" -q
echo "  Installation complete."

# 4. Run test suite
echo ""
echo "[4/5] Running test suite via pytest..."
$PYTHON_BIN -m pytest -v

# 5. Run live demo verification
echo ""
echo "[5/5] Running verification on demo files..."
echo ""
echo "--- Testing Clean / Good Case (demo_good.py) ---"
$PYTHON_BIN -m pcdlint.cli check examples/demo_good.py

echo ""
echo "--- Testing Buggy Case (demo_buggy.py) ---"
# Expected to exit with code 1 due to violations
$PYTHON_BIN -m pcdlint.cli check examples/demo_buggy.py || true

echo ""
echo "=================================================="
echo "  Setup & Verification Successful!"
echo "=================================================="
echo ""
echo "Usage:"
echo "  pcdlint check <file_or_dir>             # Run linter"
echo "  pcdlint check src/ --format json        # JSON output"
echo "  pcdlint check src/ --fail-on-warn       # CI mode"
echo "  python -m pytest                        # Run tests"
echo ""
