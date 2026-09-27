# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Environment Setup
```bash
pip install -e ".[dev]"
```
Or use the automated setup scripts:
- Windows: `setup.bat`
- Linux/macOS: `./setup.sh`

### Testing
```bash
# Run all tests
pytest

# Run a specific test file
pytest tests/test_pcdlint.py

# Run a single test
pytest tests/test_pcdlint.py -k test_pcl001_detects_datetime_at_start_of_system_prompt

# Run tests via Python module (when pytest is not directly on PATH)
python -m pytest
```

### Linting & Running pcdlint
```bash
# Lint current codebase (used in CI)
pcdlint check src/ tests/ --fail-on-warn

# Lint a file or directory directly
pcdlint check <file_or_directory>
# or via module:
python -m pcdlint.cli check <file_or_directory>

# Output diagnostics as JSON
pcdlint check src/ --format json

# Verify against test demo files
pcdlint check demo_good.py    # Clean case (0 issues)
pcdlint check demo_buggy.py   # Buggy case (triggers PCL001-PCL004)
```

## Architecture & Code Structure

`pcdlint` is a zero-dependency static taint analyzer (relying on Python's built-in `ast` module, plus `rich` for terminal UI) that detects non-deterministic code patterns invalidating LLM Prompt Caching (OpenAI and Anthropic SDKs).

### Core Pipeline Flow

```
Target File/Directory
        │
        ▼
pcdlint.analyzer.analyze_path / analyze_code
        │
        ├─► AST Parsing (ast.parse)
        │
        ├─► pcdlint.taint.TaintTracker
        │     - Detects non-deterministic sources (datetime, uuid, random, secrets, os.urandom)
        │     - Tracks taint propagation through assignments, f-strings, concatenation, and str/method casts
        │     - Identifies static prefix solids (constants, uppercase vars, strings >= 200 chars)
        │     - Tracks sets and dynamic tool list mutations across branches
        │
        ├─► pcdlint.rules.RuleEngine
        │     - Pre-scans for prompt variables and LLM sink calls
        │     - Evaluates AST nodes against 4 lint rules
        │
        ▼
Deduplicated Diagnostics (sorted by file, lineno, col_offset)
        │
        ▼
pcdlint.cli (Text via Rich table or JSON formatting, exit code 0 or 1)
```

### Rule System

| Rule ID | Rule Name | Severity | Detection Target |
|---------|-----------|----------|------------------|
| `PCL001` | `prefix-taint-injection` | ERROR | Dynamic value placed before static prompt text in LLM `system` param or `messages` prefix (supports Anthropic content blocks & `cache_control`) |
| `PCL002` | `unsorted-json-in-prefix` | WARNING | `json.dumps()` without `sort_keys=True` flowing into prompt or LLM call |
| `PCL003` | `set-iteration-in-prompt` | ERROR | Unsorted sets in `.join()`, `str()`, or f-string interpolations |
| `PCL004` | `dynamic-tools-mutation` | WARNING | `tools` parameter altered conditionally in if/else, shuffled, or initialized from an unordered set |

### Package Structure & Aliases
- `src/pcdlint/`: Primary implementation containing `analyzer.py`, `taint.py`, `rules.py`, `models.py`, `cli.py`.
- `src/pclint/`: Backward-compatible alias package that re-exports all models, tracker, engine, and CLI functions from `pcdlint`.
- Both `pcdlint` and `pclint` commands map to `pcdlint.cli:main` in `pyproject.toml`.
