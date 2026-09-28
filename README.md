# pcdlint (Prompt-Cache Determinism Linter)

[![CI Status](https://github.com/ZhiwarSajadi/pcdlint/actions/workflows/ci.yml/badge.svg)](https://github.com/ZhiwarSajadi/pcdlint/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/pcdlint)](https://pypi.org/project/pcdlint/)
[![Python versions](https://img.shields.io/pypi/pyversions/pcdlint)](https://pypi.org/project/pcdlint/)
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
    messages=[{"role": "system", "content": system}],  # Cache MISS every time!
)
```

## ✅ Good Code (90% Cost Reduction)

```python
from datetime import datetime

system = f"{STATIC_RULES}\nTime: {datetime.now()}"
#       ^^^^^^^^^^^^^^ Static prefix first, dynamic value at the end — cache prefix preserved

client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "system", "content": system}],  # Cache HIT — prefix bytes match!
)
```

---

## Rule Reference

| Rule ID | Name | Severity | `--fix` | Description |
|---------|------|----------|---------|-------------|
| `PCL001` | `prefix-taint-injection` | ERROR | — | Dynamic value placed before static prompt text invalidates cache prefix |
| `PCL002` | `unsorted-json-in-prefix` | WARNING | ✅ | `json.dumps()` without `sort_keys=True` produces non-deterministic output |
| `PCL003` | `set-iteration-in-prompt` | ERROR | ✅ | Python's `PYTHONHASHSEED` randomizes set iteration order across processes |
| `PCL004` | `dynamic-tools-mutation` | WARNING | — | Changing tool definition order invalidates the entire prompt cache hierarchy |

`PCL001` and `PCL004` have no mechanical fix: only you know where the dynamic
value belongs, or what the tool order should be.

---

## Installation

```bash
pip install pcdlint
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

# Output SARIF 2.1.0 for GitHub Code Scanning
pcdlint check src/ --format sarif > pcdlint.sarif

# Apply the mechanical fixes (PCL002 sort_keys, PCL003 sorted) in place
pcdlint check src/ --fix

# Only report findings on lines this branch changed (default ref: HEAD)
pcdlint check src/ --diff origin/main

# Fail on warnings (useful for CI)
pcdlint check src/ --fail-on-warn

# Run only some rules / skip others (overrides [tool.pcdlint])
pcdlint check src/ --select PCL001,PCL003
pcdlint check src/ --ignore PCL002

# Equivalent module forms (no console script needed)
python -m pcdlint check src/
python -m pclint check src/
```

`--fix` rewrites only what it can rewrite safely, re-reads the files so the
report and the exit code describe what is on disk now, and tells you how many
findings it had to leave to you. A rewrite that would no longer parse is
reported and skipped rather than written.

`--diff` needs `git`. It compares the working tree against `REF` and keeps a
finding only when **the line the finding points at** changed — a finding on an
untouched line stays hidden even if the value it refers to was edited. Pair it
with `--fix` to repair only what a PR introduced.

A file git does not know about yet counts as wholly new, so every finding in
it is reported; files your `.gitignore` excludes are left out entirely.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | Findings at ERROR severity, or any WARNING when `--fail-on-warn` is set |
| `2` | A path could not be analyzed: missing, not a `.py` file, not valid UTF-8, a syntax error, or `--diff` could not run (no git, not a repository, unknown ref) |

Exit code `2` exists so a typo'd path or a broken file can never look like a clean run
in CI. Errors are printed to stderr; `--format json` output on stdout stays valid JSON.
A failed `--diff` also exits `2`: reporting "no findings" because git was
unavailable would be the linter lying about your code.

## Configuration

Rules can be turned on and off from `pyproject.toml` or the command line:

```toml
[tool.pcdlint]
select = ["PCL001", "PCL003"]   # run only these rules
ignore = ["PCL002"]             # skip these, applied after select
```

The **nearest `pyproject.toml` above each analyzed file** is used, so a monorepo
can give every package its own rule set. `select` is an allowlist; `ignore` is a
denylist applied after it.

`--select` and `--ignore` take a comma-separated list and are repeatable. Each
flag **replaces** the corresponding config value for that run rather than merging
with it, so `--ignore PCL002` overrides a configured `ignore` list outright.

A config with an unknown key, an unknown rule id, or broken TOML exits `2` with a
message on stderr. It never falls back to defaults — otherwise `select = ["PCL999"]`
would make the run look clean.

## Suppressing a Finding

Switch rules off on a single line with a `# pcdlint: disable` comment, placed on
the line pcdlint reports:

```python
system = f"Time: {now}\n{STATIC_RULES}"  # pcdlint: disable
```

| Form | Scope |
|------|-------|
| `... # pcdlint: disable` | that line, every rule |
| `... # pcdlint: disable=PCL001,PCL003` | that line, the named rules only |
| `# pcdlint: disable` alone on its own line | the whole file |
| `# pcdlint: disable=PCL002` alone on its own line | the whole file, the named rules only |

Comments are read with Python's tokenizer, so the same text inside a string
literal is data and does nothing. A marker naming a rule that does not exist
suppresses nothing — a typo surfaces the finding instead of hiding it.

The marker may sit anywhere in the comment and be written without padding, so
it can share a token with another pragma. All of these suppress:

```python
system = ...  # type: ignore  # pcdlint: disable
system = ...  # noqa: E501 pcdlint: disable
system = ...  #pcdlint:disable
```

It still has to be a complete marker: `# pcdlint: disable-all` and prose that
merely mentions the keyword do not count.

Comment the line pcdlint prints. For `PCL001` that is the line holding the
`system=...` argument, not the line where the tainted value was built.

## GitHub Actions CI Integration

```yaml
name: pcdlint
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install pcdlint
      - run: pcdlint check src/ --fail-on-warn
      # Findings appear directly on the PR diff via Code Scanning.
      - run: pcdlint check src/ --format sarif > pcdlint.sarif
      - uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: pcdlint.sarif
```

Code Scanning has to be enabled for the repository (free for public repos).
Add `continue-on-error: true` to the upload step if some of your repositories
do not have it enabled.

To lint only the lines a pull request changed, swap the last check for:

```yaml
      - run: pcdlint check src/ --diff "origin/${{ github.base_ref }}" --fail-on-warn
```

---

## How It Works

1. **AST Parsing**: Uses Python's built-in `ast` module to parse source files — no external compilers needed.
2. **Taint Tracking**: Identifies non-deterministic sources (`datetime.now()`, `uuid.uuid4()`, `os.urandom()`, etc.) and tracks their propagation through f-strings, concatenation, and `.format()`.
3. **Prefix Analysis**: Precisely determines if a tainted expression appears **before** a static prefix solid in the prompt string.
4. **Rule Matching**: Checks tainted prompts against LLM API sink calls (`chat.completions.create`, `messages.create`, etc.) and reports violations.
