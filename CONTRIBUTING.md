# Contributing

Thanks for helping. pcdlint is a small static analyzer, so most changes
come down to a rule's behaviour and the tests that pin it down.

## Setup

```bash
pip install -e ".[dev]"
```

Or run `./setup.sh` (Linux/macOS) / `setup.bat` (Windows), which install and
then run the suite for you.

## Before you open a pull request

Every one of these is a CI job, so running them locally saves a round trip:

```bash
ruff check src/ tests/
mypy
python -m pytest --cov=pcdlint --cov-fail-under=91 --cov-report=term-missing
pcdlint check src/ tests/ --fail-on-warn
```

`pcdlint` lints itself; that self-check is the last line of the last job.

## Changing or adding a rule

- Tests come first. A test that passes before you write it proves nothing —
  watch it fail, then make it pass.
- A rule that has a mechanical `--fix` must attach `TextEdit` spans that
  splice correctly at byte offsets (`ast.col_offset` counts UTF-8 bytes).
  If the rewrite could change behaviour for a legal input, report the
  finding without edits instead.
- PCL001–PCL004 are the public rule ids. Additions need an entry in
  `KNOWN_RULE_IDS` and `RULE_SHORT_DESCRIPTIONS`, plus a row in the README
  table; selectors and `# pcdlint: disable` comments validate against them.

## Style

Ruff and mypy are the arbiters. Comments explain *why* something is the way
it is, not what the line does — the surrounding code already does that.

## Releases

Version numbers live in two places: `pyproject.toml` and
`src/pcdlint/__init__.py`. `tests/test_packaging.py` fails if they disagree.
Publishing happens by tagging `vX.Y.Z`, which the publish workflow checks
against `pyproject.toml` before uploading to PyPI.
