## What this changes

<!-- One or two sentences. Link the issue with `Fixes #N` if there is one. -->

## How it was verified

<!-- Commands you actually ran, and what they printed. -->

```bash
ruff check src/ tests/
mypy
python -m pytest --cov=pcdlint --cov-fail-under=91
pcdlint check src/ tests/ --fail-on-warn
```

## Checklist

- [ ] A test failed before the fix, and passes now.
- [ ] No new rule id, or `KNOWN_RULE_IDS`, `RULE_SHORT_DESCRIPTIONS` and the
      README table were all updated together.
- [ ] Any `--fix` change still splices at byte offsets and cannot rewrite
      bytes outside the span it was given.
- [ ] Docs updated if behaviour or flags changed.
