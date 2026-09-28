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

# Run tests under the CI coverage gate (91% floor)
python -m pytest --cov=pcdlint --cov-fail-under=91 --cov-report=term-missing
```

### Linting & Running pcdlint
```bash
# Ruff and mypy (both run in CI; mypy config pins python_version = 3.10)
ruff check src/ tests/
mypy

# Lint current codebase (used in CI)
pcdlint check src/ tests/ --fail-on-warn

# Lint a file or directory directly
pcdlint check <file_or_directory>
# or via module:
python -m pcdlint.cli check <file_or_directory>

# Output diagnostics as JSON, or SARIF 2.1.0 for GitHub Code Scanning
pcdlint check src/ --format json
pcdlint check src/ --format sarif > pcdlint.sarif

# Apply mechanical fixes in place (PCL002 sort_keys, PCL003 sorted)
pcdlint check src/ --fix

# Only report findings on lines changed vs a git ref (default: HEAD)
pcdlint check src/ --diff origin/main

# Verify against test demo files
pcdlint check examples/demo_good.py    # Clean case (0 issues)
pcdlint check examples/demo_buggy.py   # Buggy case (triggers PCL001-PCL004)
```

## Architecture & Code Structure

`pcdlint` is a zero-dependency static taint analyzer (relying on Python's built-in `ast` module, plus `rich` for terminal UI) that detects non-deterministic code patterns invalidating LLM Prompt Caching (OpenAI and Anthropic SDKs).

### Core Pipeline Flow

```
Target File/Directory
        │
        ▼
pcdlint.analyzer.analyze_path(_ex) / analyze_code(_ex)
        │
        ├─► AST Parsing (ast.parse) — a SyntaxError is reported, never swallowed
        │
        ├─► pcdlint.taint.TaintTracker
        │     - Detects non-deterministic sources (datetime, time, uuid, random,
        │       secrets, os.urandom, os.getpid — see TAINT_SOURCES)
        │     - Assigns every node a lexical scope; bindings are keyed (scope, name) and
        │       strong-updated on reassignment, so one function's `system` never bleeds
        │       into another's
        │     - Tracks taint propagation through assignments, f-strings, concatenation,
        │       .format()/str() casts, join(), and local-function return values
        │     - Identifies static prefix solids (string constants, repeated strings
        │       such as "rules " * 30, uppercase vars) at >= 200 chars
        │     - Tracks sets, conditional (branch) construction, and tool list mutations
        │     - Walks each if/try/loop arm from a shared snapshot and may-merges them:
        │       taint unions, static text must agree, and the conditional flag only
        │       survives when the arms provably bind a name differently
        │     - Resolves function summaries (taint origin, is_set, unsorted-json ids)
        │       to a fixpoint, so declaration order does not limit call depth
        │
        ├─► pcdlint.rules.RuleEngine.run(tree, file_path)
        │     - Pre-scans for variables that reach an LLM sink call
        │     - Evaluates AST nodes against 5 lint rules (source-order walk)
        │     - PCL002/PCL003 attach TextEdit spans for --fix; the other two cannot
        │
        ├─► pcdlint.disables.parse(source_code) + pcdlint.config.load_for(file_path)
        │     - Single suppression point: rules never see comments or config
        │     - Drops findings under `# pcdlint: disable` (line / named / file scope)
        │     - Applies allowlist-then-denylist select/ignore (CLI flags override config)
        │     - A bad config is returned as an error, so it exits 2 rather than
        │       silently running different rules than were asked for
        │
        ▼
Deduplicated Diagnostics (sorted by file, lineno, col_offset)
        │
        ▼
pcdlint.cli
        - --diff filters to lines git reports as changed (a failed diff exits 2,
          it never reports a false clean run)
        - --fix splices the attached edits via pcdlint.fixer, refuses any rewrite
          that no longer parses, re-analyzes, and reports findings it skipped
        - text / json / sarif 2.1.0 on stdout, errors and fix summary on stderr
        exit 0 = clean, 1 = findings (ERROR, or WARNING with --fail-on-warn),
        2 = a path could not be analyzed, or --diff could not run
```

Tests live in `tests/test_pcdlint.py` (rules/CLI), `tests/test_pclint.py` (alias package),
`tests/test_hardening.py` (regression + robustness cases), `tests/test_fix.py` (autofix
spans and application), `tests/test_output.py` (SARIF and `--diff`) and
`tests/test_main.py` (the `python -m pcdlint` entry point).

### Rule System

| Rule ID | Rule Name | Severity | `--fix` | Detection Target |
|---------|-----------|----------|---------|------------------|
| `PCL001` | `prefix-taint-injection` | ERROR | — | Dynamic value placed before static prompt text in LLM `system` param or `messages`/`input` prefix (supports Anthropic content blocks, `cache_control` breakpoints, and positional args) |
| `PCL002` | `unsorted-json-in-prefix` | WARNING | ✅ | `json.dumps()` without `sort_keys=True` whose result reaches a prompt or LLM call (tracked through intermediate variables) |
| `PCL003` | `set-iteration-in-prompt` | ERROR | ✅ | Unsorted sets in `.join()`, `str()`, or f-string interpolations |
| `PCL004` | `dynamic-tools-mutation` | WARNING | — | `tools` parameter altered conditionally in if/else, shuffled, built from an unordered set, or assembled from a branch-assigned helper |
| `PCL005` | `taint-before-cache-breakpoint` | ERROR | — | Taint anywhere before the last `cache_control` breakpoint on an Anthropic `messages` call — a total miss, which PCL001's static-first ordering cannot see |

### Package Structure & Aliases
- `src/pcdlint/`: Primary implementation containing `analyzer.py`, `taint.py`, `rules.py`, `models.py`, `cli.py`, `fixer.py` (applies the `TextEdit` spans a rule attached — byte-precise splicing, overlap dropping), plus `disables.py` (parses `# pcdlint: disable` comments with `tokenize`) and `config.py` (reads `[tool.pcdlint]` from the nearest `pyproject.toml` above each file, via `tomllib`/`tomli`).
- `src/pclint/`: Backward-compatible alias package that re-exports all models, tracker, engine, and CLI functions from `pcdlint`.
- Both `pcdlint` and `pclint` commands map to `pcdlint.cli:main` in `pyproject.toml`.
