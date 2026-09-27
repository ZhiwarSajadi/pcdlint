# pcdlint (Prompt-Cache Determinism Linter)

[![CI Status](https://github.com/ZhiwarSajadi/pcdlint/workflows/CI/badge.svg)](https://github.com/ZhiwarSajadi/pcdlint/actions)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://opensource.org/licenses/MIT)

A static taint analysis linter that detects code patterns silently invalidating LLM Prompt Caching (OpenAI & Anthropic SDKs).

---

## The $10,000 Bug Explained

LLM prompt caching works by storing the **prefix** of a prompt in a fast cache. When the prefix matches a cached version, the model skips re-processing the prefix — delivering a **10x read discount** versus the full write cost.

The catch? The cache key is computed from the **exact byte sequence** of the prompt prefix. A single non-deterministic character at position 0 — like `datetime.now()` — changes every single byte, making the cache **completely useless**.

```
Full Write Cost:  ██████████  ($0.030 / 1K tokens)
Cache Read Cost:  █          ($0.003 / 1K tokens)  ← 10x cheaper
```

One `datetime.now()` at character 0 silently destroys cache hits, wasting money on every request.

---

## ❌ Bad Code (0% Cache Hit)

```python
from datetime import datetime

system = f"Time: {datetime.now()}\n{STATIC_RULES}"
#                                    ^^^^^^^^^^^^ PREFIX TAINTED — every request has a unique prefix

client.chat.completions.create(
    model="gpt-4",
    system=system,  # Cache MISS every time!
)
```

## ✅ Good Code (90% Cost Reduction)

```python
from datetime import datetime

system = f"{STATIC_RULES}\nTime: {datetime.now()}"
#       ^^^^^^^^^^^^^^ Static prefix first, dynamic value at the end — cache prefix preserved

client.chat.completions.create(
    model="gpt-4",
    system=system,  # Cache HIT — prefix bytes match across requests!
)
```

---

## Rule Reference

| Rule ID | Name | Severity | Description |
|---------|------|----------|-------------|
| `PCL001` | `prefix-taint-injection` | ERROR | Dynamic value placed before static prompt text invalidates cache prefix |
| `PCL002` | `unsorted-json-in-prefix` | WARNING | `json.dumps()` without `sort_keys=True` produces non-deterministic output |
| `PCL003` | `set-iteration-in-prompt` | ERROR | Python's `PYTHONHASHSEED` randomizes set iteration order across processes |
| `PCL004` | `dynamic-tools-mutation` | WARNING | Changing tool definition order invalidates the entire prompt cache hierarchy |

---

## Installation

```bash
pip install prompt-cache-lint
```

Or install from source with dev dependencies:

```bash
pip install -e ".[dev]"
```

## CLI Usage

```bash
# Check a single file
pcdlint check src/my_app.py

# Check multiple paths
pcdlint check src/ tests/

# Output as JSON
pcdlint check src/ --format json

# Fail on warnings (useful for CI)
pcdlint check src/ --fail-on-warn
```

## GitHub Actions CI Integration

```yaml
name: pcdlint
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install prompt-cache-lint
      - run: pcdlint check src/ --fail-on-warn
```

---

## How It Works

1. **AST Parsing**: Uses Python's built-in `ast` module to parse source files — no external compilers needed.
2. **Taint Tracking**: Identifies non-deterministic sources (`datetime.now()`, `uuid.uuid4()`, `os.urandom()`, etc.) and tracks their propagation through f-strings, concatenation, and `.format()`.
3. **Prefix Analysis**: Precisely determines if a tainted expression appears **before** a static prefix solid in the prompt string.
4. **Rule Matching**: Checks tainted prompts against LLM API sink calls (`chat.completions.create`, `messages.create`, etc.) and reports violations.
