# Changelog

All notable changes to pcdlint are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `PCL005 taint-before-cache-breakpoint` (ERROR). OpenAI caches the longest
  matching prefix, so a dynamic value at the end still earns partial hits and
  `PCL001`'s "static first" test is enough. Anthropic only hits when every
  byte up to a `cache_control` breakpoint is identical, so the same code is a
  **100% miss** there -- and `PCL001` never reported it because the static
  text came first. `PCL005` flags any taint in a system block or message up
  to and including the last one carrying `cache_control`, on `messages.*`
  calls only, when a breakpoint is actually present. `PCL001`'s fix text now
  speaks to the provider too: Anthropic is told to move the value after a
  breakpoint, OpenAI to the end.
- `exclude` in `[tool.pcdlint]` and a repeatable `--exclude GLOB` flag keep
  files out of a directory scan entirely (the flag overrides the config, like
  `--select`/`--ignore`). Globs match the bare file name *and* the path
  relative to what was scanned. Any folder holding a `pyvenv.cfg` is skipped
  too, so `venv311/` and `.venv-py312/` no longer need their own name on the
  skip list. Left alone as optional: honouring `.gitignore`, and reading
  `.ipynb` code cells.

### Changed

- The version now lives in one place: `pcdlint.__version__`, which
  `pyproject.toml` reads through `[tool.setuptools.dynamic]`. Bumping a
  release means editing one file, not two that drift. Version is now
  `0.3.0`.
- The `pclint` alias package emits a `DeprecationWarning` on import and goes
  away in 1.0: the top-level name can clash with any other distribution that
  ships one. The `pclint` console script is unaffected.
- `demo_good.py` / `demo_buggy.py` moved to `examples/`, so the repo's own
  `[tool.pcdlint] exclude = ["examples/*"]` keeps `pcdlint check .` clean on
  this repository. CI's smoke test, `setup.bat`/`setup.sh` and the test
  fixtures follow the new path.
- `exclude` now filters only what a **directory walk** discovers. A file you
  name on the command line is always analyzed -- otherwise whether it was
  filtered depended on whether you passed a relative or absolute path.
- `CLAUDE.md` and `docs/superpowers/` stay in the repo as contributor
  documentation, and are already absent from the sdist (verified by building
  one: packages, `tests/`, `README.md`, `LICENSE` only), so no `MANIFEST.in`
  is needed.
- Every third-party action is pinned to a commit SHA with a `# vX` comment,
  so a tag cannot be retargeted out from under the build -- including
  `pypa/gh-action-pypi-publish`, which is the one that publishes. Dependabot
  keeps the pins current. `actions/checkout` is at v7 and
  `actions/setup-python` at v7 (Dependabot PRs #1 and #2, both merged after
  their CI passed); neither workflow used an input those releases removed.
  The publish workflow now runs on a protected `environment: pypi`, runs the
  test suite before building, and no longer offers `workflow_dispatch` --
  dispatching from a branch carries no tag, so the tag/version check would
  have failed every time. The README's CI example matches.
- JSON output carries `fixable` (so a consumer knows what `--fix` will touch
  without re-running) plus `end_lineno` / `end_col_offset`. Text output
  escapes Rich markup in the path, message and fix suggestion, so a file
  called `[bold]x.py` prints its name instead of being parsed as a tag.
- SARIF output is closer to what Code Scanning expects. Columns are converted
  to SARIF's own units -- ast reports UTF-8 byte offsets, SARIF defaults to
  UTF-16, so the two disagreed on every line with a non-ASCII character
  before the finding. Regions now carry `endLine`/`endColumn` (the
  `Diagnostic` keeps both ends), and every rule declares
  `defaultConfiguration.level` so a consumer can filter on severity before
  any result exists. Optional items left alone: SARIF `fixes` for the
  mechanical rewrites, and `originalUriBaseIds` for repo-root-relative URIs.
- README accuracy pass: the examples now use `gpt-4o` (the old `gpt-4` does
  not support prompt caching, so the snippet never cached), the flat "10x
  read discount" is now "up to 90% cheaper, depending on provider and model"
  with links to both pricing pages, and a new section contrasts OpenAI's
  automatic longest-prefix caching with Anthropic's `cache_control`
  breakpoints -- which is what `PCL001` and `PCL005` are each modelling.
- PCL002 no longer claims `json.dumps()` is always non-deterministic. CPython
  dicts keep insertion order, so the key order only varies when the dict was
  *built* differently -- merged dicts, sets, DB rows, `**` spreads. The
  finding and the README now say exactly that, and point at `sort_keys=True`
  as what makes it deterministic however it was built. Still a WARNING.
- A `# pcdlint: disable` alone on its own line now switches off **the next
  line of code** unless it sits above the first statement of the file, where
  it keeps switching off the whole file as before. It used to be file-scoped
  wherever it appeared, so the eslint/pylint habit of putting one above the
  call you meant silently muted every other finding in the file. Blank and
  comment-only lines between the marker and its target are skipped.

### Performance

- The nearest `pyproject.toml` is looked up once per directory instead of
  once per file, so a 500-file package no longer parses the same config 500
  times. Errors are never cached: a broken config still raises (exit 2) on
  every file it governs.
- `_reaches_prompt` is no longer called for every node in the file. PCL003
  now matches the node's shape first and only then asks whether it reaches a
  prompt, and the question itself is answered from a reverse index built once
  per run instead of a scan of every entry in the flow table -- so the
  per-node cost no longer grows with the file.

### Fixed

- An internal analyzer fault no longer looks like a finding. A left-nested
  concatenation of 1,000 or more terms parses fine, but overflowed the stack
  in `taint.py` and escaped `main()` as exit 1 -- which the contract reserves
  for "findings", so CI could not tell a crash from a lint failure. The `+`
  walks in `_static_str_len` and `_flatten_string_expr` are iterative now:
  their depth tracked operand count rather than nesting depth, while
  `ast.parse` accepts either. Anything that still overflows, and any
  unexpected exception, becomes a one-line error naming the file instead of a
  traceback -- exit 2, never 1.
- Rules now judge a call against the bindings it ran with, not the ones the
  file ended up with. Tracking covers the whole file before any rule sees
  it, so a name rebound *after* an LLM call made that call look clean:
  `p = ...`, then `create(system=p)`, then `p = STATIC` reported nothing.
  The state at each module-level sink statement is snapshotted during the
  walk and the rules resolve against it. A call inside a function is
  deliberately left alone -- its execution point is unknowable, and freezing
  it where the `def` sits would hide module-level names bound after the
  definition.
- Marks set on the first tracking pass survive the later passes. Any file
  with a local helper function needs more than one pass, and each pass
  rebinds names with a plain `Assign` -- which cleared `tools_mutated` and
  the `+=` taint that pass 0 had just recorded, so `tools.append(...)` in an
  `if` and `prompt += f"{...}"` stopped reporting PCL004/PCL001. The flags
  are re-applied every pass (they are idempotent); only the in-place list
  rebuild stays on pass 0, since repeating it would duplicate elements.
- `match` blocks and `except*` handlers are tracked now. `ast.match_case` and
  `ast.ExceptHandler` are not `ast.stmt`, so their bodies were skipped
  entirely, and `ast.TryStar` was not routed to the try handler at all --
  a prompt assigned inside a `case` or an `except*` arm looked clean. Each
  case arm runs from one snapshot and may-merges with the rest, plus an
  implicit no-match path unless an irrefutable `case _` guarantees one runs.
  A match arm is also marked conditional like an `if` arm, so a
  `tools.append(...)` inside one reports PCL004.
- Taint sources are now resolved through the file's own imports, so
  `from datetime import datetime as dt; dt.now()`, `import random as rnd;
  rnd.choice(x)` and `from uuid import uuid4 as u; u()` are all recognised.
  Newly registered sources: `uuid.uuid6`, `uuid.uuid7`, `random.uniform`,
  `random.getrandbits`, `datetime.today`, `time.strftime`,
  `time.ctime`, `time.localtime`, `time.gmtime`, `django.utils.timezone.now`
  and `pd.Timestamp.now` (`time.strftime`/`ctime`/`localtime`/`gmtime` are
  only flagged when no time argument is passed -- given one, they are pure
  functions of it). `hash()` of a `str`/`bytes` is a source too, since
  `PYTHONHASHSEED` salts it exactly as it salts set iteration.
- Two names that only resembled taint sources are no longer matched:
  `event.time()` read as `time.time`, and an unimported bare `choice(...)`
  read as `random.choice`.
- `random.shuffle(x)` now taints `x` itself, not just the tools list it is
  usually called on.
- `instructions=` on an OpenAI Responses API call is now judged as a system
  prompt. It is the Responses spelling of `system=` and was skipped entirely,
  so a tainted prefix passed that way produced no finding.
- LLM sink detection now matches the SDK call shape exactly instead of
  searching for substrings. Newly recognised: `chat.completions.parse`,
  `beta.chat.completions.parse`, `responses.parse`, `responses.stream`,
  `messages.stream`, `chat.completions.stream`, `beta.messages.create`, and
  any async client spelling the same shapes. No longer mistaken for a sink:
  `self.messages_repo.create_user(...)`, `db.messages.create_index(...)` and
  `x.completions.recreate(...)`.
- Suppression markers no longer have to open the comment. `# type: ignore  #
  pcdlint: disable` and `# noqa: E501 pcdlint: disable` are a single comment
  token and used to be ignored, as was the unpadded `#pcdlint:disable`. The
  marker must still be a complete word, so `# pcdlint: disable-all` and prose
  mentioning the keyword still suppress nothing.
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
[0.2.0]: https://github.com/ZhiwarSajadi/pcdlint/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ZhiwarSajadi/pcdlint/releases/tag/v0.1.0
