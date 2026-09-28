# Changelog

All notable changes to pcdlint are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `--diff` no longer misfiles hunks after a line that merely looks like a
  file header. An added line whose text is `++ foo` renders as `+++ foo`
  (and a removed `-- x` as `--- x`), which used to re-point the parser at a
  file that does not exist and drop every later hunk. Each hunk body is now
  consumed against the counts in its own header.
- `--diff` no longer drops files whose names are not plain ASCII. git
  octal-quotes such paths by default (`+++ "caf\303\251.py"`), so the header
  never matched the real file and its findings vanished; git now runs with
  `core.quotePath=false`, and the untracked-file listing is read with `-z`
  so names cannot be mangled by quoting at all.
- PCL002 no longer offers an autofix for a `json.dumps()` that unpacks
  `**kwargs`. Appending `, sort_keys=True` to `json.dumps(x, **opts)`
  parses cleanly -- so the post-fix `ast.parse` guard could not see it --
  and raises `TypeError: got multiple values for keyword argument` whenever
  `opts` already defines `sort_keys`. The finding is still reported; the
  rewrite is withheld.
- An empty `select` -- `[tool.pcdlint] select = []`, `--select ","` or
  `--select ""` -- is now an error (exit 2). It used to switch every rule
  off and report a clean run. An empty `ignore` is still accepted, since it
  only means "ignore nothing".
- `--fix` combined with `--diff` now re-applies the diff filter after the
  post-rewrite re-analysis, so the report and the exit code cover only the
  lines the change introduced rather than every finding in the touched files.

## [0.2.0] - 2026-09-28

Marking a release means tagging it `vX.Y.Z`: the publish workflow refuses to
upload when the tag and `pyproject.toml` disagree.

### Added

- `--fix` applies the two mechanical rewrites (PCL002 `sort_keys=True`,
  PCL003 `sorted(...)`), re-reads what it wrote, and reports the findings it
  had to leave to a human.
- `--diff [REF]` reports only findings on lines git says changed, so a PR
  can gate on what it introduced. Untracked files count as wholly new.
- `--select` / `--ignore` and a nearest-`pyproject.toml` `[tool.pcdlint]`
  section for turning rules on and off; a bad config exits 2 rather than
  silently running different rules.
- `# pcdlint: disable` suppression comments, line- and file-scoped, parsed
  with `tokenize` so text inside a string literal does nothing.
- `--format sarif` emits SARIF 2.1.0 for GitHub Code Scanning.
- Exit code 2 separates "a path could not be analyzed" from "clean".

### Changed

- Branch-sensitive taint merging, fixpoint function summaries, and five
  more taint sources (`time.time_ns`, `uuid.uuid1`, `random.randrange`,
  `secrets.token_*`, `os.getpid`).
- The distribution package is named `pcdlint`; `pclint` remains a supported
  alias package and console script.

### Fixed

- `--fix` no longer rewrites line endings: it reads and writes bytes, so an
  LF file on Windows stays LF and a UTF-8 BOM survives the rewrite.
- `--fix` no longer attaches `sorted(...)` to a set whose elements cannot be
  ordered — `sorted({1, "a"})` raises `TypeError` at runtime.
- A UTF-8 BOM is stripped on read instead of turning the file into a parse
  error (which failed the whole run with exit 2).
- PCL003 now requires the set iteration to reach a prompt. A
  `", ".join(tags)` feeding a log line is no longer an ERROR with a fix.
- PCL002 now fires on a `json.dumps()` passed inline to the call, and on
  `from json import dumps` / `import json as J` — the tracker and the rule
  disagreed on what counts.
- Calls that merely take `messages=` and `model=` are no longer treated as
  LLM sinks; only the Anthropic and OpenAI SDK call shapes are.
- An UPPER_CASE name alone no longer marks a value as a cache-safe static
  prefix, which had been muting real PCL001 findings.
- `--diff` reports findings in files git has not been told about yet, and
  still ignores `.gitignore`d ones.
- `pcdlint check` no longer swallows a real path named `check`.
- Cache and vendored directories (`.pytest_cache`, `site-packages`, `env`)
  are skipped when walking a tree.

## [0.1.0] - 2026-09-27

First release: the four rules (PCL001 prefix-taint, PCL002 unsorted JSON,
PCL003 unsorted set, PCL004 dynamic tools), text and JSON output, the
`pclint` alias, and `python -m pcdlint`.

[Unreleased]: https://github.com/ZhiwarSajadi/pcdlint/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ZhiwarSajadi/pcdlint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ZhiwarSajadi/pcdlint/releases/tag/v0.1.0
