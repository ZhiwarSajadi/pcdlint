# Changelog

All notable changes to pcdlint are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `[tool.pcdlint] taint-sources` and `sinks`, for the calls this linter
  cannot know about. `taint-sources` names qualified calls that are
  nondeterministic, so `mypkg.jitter()` taints like `uuid.uuid4()`;
  `sinks` names qualified calls that take a prompt, so every argument
  inside one is judged as payload. Both are taken at the project's word —
  matched exactly or on a dot boundary, with no requirement that the call
  also look like an LLM API. A name that is not a dotted name is an error
  rather than a rule that silently never fires.
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

- Nine nondeterministic calls are now recognised as taint sources:
  `secrets.choice`, `secrets.randbelow`, `random.randbytes`,
  `random.gauss`, `time.process_time`, `time.thread_time`,
  `socket.gethostname`, `platform.node` and `getpass.getuser`. Each was
  verified against the installed module before being added; `arrow`,
  `pendulum` and `numpy.random` were not available here to verify, and
  rather than guess at their dotted names the new `taint-sources` key
  covers them.
- A suffix match against a source name now needs an imported prefix.
  `self.random.choice(...)` on a seeded `random.Random` ends exactly like
  `random.choice` and was reported as nondeterministic, while
  `datetime.date.today` only ever gets there through a line that said
  `import datetime`. Exact matches are unchanged — that is the spelling
  the table names. A local object named `time` whose `.time()` is called
  still matches, and remains a documented limitation.
- `prompt=` is read as the payload of a call. Anthropic's legacy
  completions API spells its input that way, and neither the system nor
  the messages lookup looked at it, so `completions.create(prompt=...)`
  was a sink whose payload was never judged.
- `litellm.completion` and `litellm.acompletion` are sinks. They are bare
  functions rather than `resource.method`, so the shape rule could not
  see them at all.
- Added the false-positive regression sweep: a deterministic sample of
  ~100 standard-library files must produce zero findings, zero analysis
  errors and zero crashes. The full stdlib (721 files) was measured clean
  too; the sample keeps the suite at ~4s instead of ~30s. Its limits are
  documented in the test rather than implied — the stdlib has no LLM sink,
  so it guards crashes and sink-independent false positives, while the
  R-02–R-07 repros (each already a permanent unit test with its controls)
  carry the precision guarantee.
- The setup scripts stop hiding failures. `setup.sh` ran
  `venv "$VENV_DIR" || echo "Using existing environment."`, so a failed
  virtualenv creation (the usual cause being a missing `python3-venv`)
  printed a comforting message and then installed into the system Python.
  It now explains the failure and exits. The buggy-demo check was
  `|| true`, which swallowed exit 2 — "could not analyze" — alongside the
  expected exit 1; it now requires exactly 1. `setup.bat` had the same
  hole in the other direction: `if not errorlevel 1` accepts exit 2 as a
  pass, so it checks for 2 explicitly first.
- The demo files no longer pass `system=` to `chat.completions.create`,
  which has no such parameter — the system prompt belongs in `messages` as
  a system role, which is where the README's examples already put it. Both
  demos are restructured the same way; `demo_good.py` still reports 0
  findings and `demo_buggy.py` still reports PCL001–PCL004, so no test or
  CI smoke assertion changed. A test parses both demos and fails if either
  ever passes `system=` to a `chat.completions` call again.
- Stale statements corrected across the docs. PCL005 landed but several
  places still said "the 4 rules": `CONTRIBUTING.md` listed PCL001–PCL004
  as the public ids, `rules.py` (both packages) and `models.py` counted
  four, and the `config.py` unknown-key error named only `select` and
  `ignore` while `exclude` has been valid since 0.3.0. `CONTRIBUTING.md`
  also still described the version as living in two places and the
  publish workflow as checking `pyproject.toml`; it is single-sourced in
  `pcdlint.__version__` and the workflow reads `__init__.py`. `CLAUDE.md`
  called the tool "zero-dependency" while `rich` (and `tomli` on 3.10)
  are runtime dependencies, and `dependabot.yml` said actions were pinned
  "by major tag" when they are SHA-pinned. The rule-count wording is now
  number-free so the next rule cannot make it stale again.
- The README's GitHub Actions recipe uploaded SARIF only on runs that had
  no findings. `pcdlint check --format sarif > f` exits 1 when it reports
  anything, so the step failed and the job stopped before the upload --
  precisely the run whose results were wanted. The recipe now absorbs exit
  1 (`|| test $? -eq 1`, verified against the real CLI: findings → step 0
  with results in the file, an unanalyzable path → step 1), uploads, and
  enforces in a separate step afterwards. The `--diff` variant also
  documents `fetch-depth: 0`: a default checkout is a shallow single-ref
  clone, where `origin/<base>` does not exist and pcdlint exits 2.
- **Set detection (R-17).** `PCL003` only recognised a set spelled `{...}`,
  `set(...)`, or a name already tracked as one. It now also reports: a local
  helper whose summary says it returns a set (PCL004 already knew that); the
  set operators `|`, `&`, `-`, `^` and `.union/.intersection/.difference`;
  `frozenset(...)`; `list()`/`tuple()`/`map()` over a set, which copy its
  order rather than fixing it; and a comprehension or generator iterating
  one. The `--fix` rule keeps its shape and now has branches to match it: an
  edit is offered only where `sorted()` is provably safe, so a helper's
  return value reports with no edit rather than a rewrite of something whose
  elements nobody can see. Left undone and recorded as a known gap: a
  `for x in a_set:` loop that accumulates into prompt text.
- **Taint propagation (R-16).** Constructs that carried a dynamic value into
  a prompt without being reported now are:
  - `self.system = f"..."` in `__init__`, read as `system=self.system` —
    attribute targets were never tracked, and `get_prefix_tainted` had no
    `Attribute` branch either, so a prompt built on an object reported
    nothing. `self.x` bindings are now keyed by the **class** scope rather
    than the method, because `__init__` and `go` are different scopes and a
    method-held binding would be invisible from its sibling. Two classes
    stay separate — a test pins that one class's timestamp cannot answer
    for another.
  - `system, user = f"...{datetime.now()}...", "hi"` — only plain `ast.Name`
    targets were tracked, so a tuple/list target was skipped whole and
    bound nothing. Targets now pair element-wise with a Tuple/List value of
    the same length; anything else still binds nothing rather than
    guessing which expression belongs to which name.
  - `build(datetime.now())` where `def build(ts)` returns an f-string
    containing `ts` — a function summary only recorded a *statically*
    known return origin, and a parameter has none, so whatever the caller
    passed was lost at the boundary. Summaries now record which parameters
    the return expression reads, and the call site checks those arguments
    positionally and by keyword. A helper that ignores its argument still
    reports nothing.
  - `self.build()` — summaries were keyed and looked up only for a
    bare-name callee, so a method never found the summary its own class
    declared. Lookup goes through the class scope, and because `self` is
    bound at the call site parameter positions shift by one for a bound
    method. `returns_set` uses the same path, so PCL004 sees method-built
    tool lists too. Two classes with the same method name stay separate.
  - `system = await build()` — `ast.Await` was not unwrapped, so nothing
    behind an `await` could be seen.
  - `rid = int(time.time() * 1000)` and `-tainted` — only `+` was looked
    inside, so a non-additive `BinOp` and any `UnaryOp` swallowed taint.
    Arithmetic on a dynamic value is still dynamic. This also covers the
    `"Time: %s" % datetime.now()` spelling.
  - `system=(s := f"...")` — `ast.NamedExpr` was not unwrapped, so a walrus
    hid whatever it wrapped.
  - `system=(f"..." if flag else STATIC_RULES)` inline in a call —
    `get_prefix_tainted` had no `IfExp` branch while `get_taint_origin_of_node`
    did, so the two disagreed on which expressions they understand. A new
    test sweeps nine shapes through both and fails the moment one of them
    gains a branch the other lacks.
  - `f"{ctx['t']}"` for `ctx = {"t": datetime.now()}` — `ast.Subscript` had
    no branch, so looking a value up by key lost it. A literal key against
    a literal dict resolves exactly, so `ctx['static']` in a dict that also
    holds the time stays static; a computed key or a `**` merge asks about
    every value instead.
- `PCL005` now sees Anthropic's automatic caching. A single `cache_control`
  field at the top level of the request applies the breakpoint to the last
  cacheable block, but the rule only looked for `cache_control` *inside*
  `system`/`messages`, so it reported nothing for a 100% miss. A
  request-level breakpoint now makes taint anywhere in the request count;
  "only when a breakpoint is present" is unchanged, and a clean prompt with
  the same breakpoint still reports nothing.
- Line numbers are Python's now, not `str.splitlines()`'s. `splitlines()`
  also breaks on form feed, `\v`, `\x1c`–`\x1e`, `\x85`, U+2028 and
  U+2029; `ast` and `tokenize` do not. After any of those earlier in a file
  every `# pcdlint: disable` below it was mapped to the wrong row — so a
  suppression could silently stop applying — and SARIF's `endColumn`, which
  is measured against `lines[end_lineno - 1]`, was read off the line above
  (a measured 9 instead of 96 on the regression fixture). `disables.parse`
  and the SARIF column reader now share one `source_lines()` helper that
  folds `\r\n`/`\r`, matching what the tokenizer treats as a newline.
- The linted file's own `SyntaxWarning`s no longer reach stderr. `ast.parse`
  warns about an invalid escape such as `re.compile("\d+")`, so an ordinary
  run printed a warning about the user's code that had nothing to do with
  pcdlint. Both `ast.parse` sites — the analyzer and the post-`--fix`
  syntax guard — filter it.
- Overlapping paths no longer double-report. `pcdlint check app app/mod.py`
  analysed the same file twice and printed the same finding twice, so every
  count a consumer read — the JSON array length, the SARIF results, the
  summary table — was inflated. Findings are now keyed on a normalized,
  case-folded path plus line, column and rule.
- A directory named `env` is no longer skipped silently. It is a common
  name for application code, and dropping it cost findings with no message
  explaining why. Real virtualenvs are already caught by the `pyvenv.cfg`
  rule, which does not care what the folder is called. The rest of the
  built-in skip list — `build`, `dist` and the tool caches — is now
  enumerated in the README instead of being a thing you discover when your
  source turns up missing from a run.
- Text output no longer hard-wraps at 80 columns when stdout is not a TTY.
  rich word-wraps a non-interactive console, which split
  `path:line:col` across lines and broke grep, editors and GitHub problem
  matchers — exactly the environment CI runs in. Finding lines are printed
  with `soft_wrap=True` and stay on one line however long the path is.
- A path may now follow an option:
  `pcdlint check first --fail-on-warn second` analyses both. argparse stops
  matching the `paths` positional at the first option, so `second` was
  rejected as "unrecognized arguments" -- exit 2, "a path could not be
  analyzed", for a path it never tried. `main()` uses
  `parse_intermixed_args()` now. The pre-existing ambiguity of
  `--diff [REF]` is unchanged: a token written directly after `--diff` is
  still read as its REF, and `--diff` at the end still means `HEAD`.
- Tracking no longer edits the tree it was handed. `messages.append(...)`
  and `.extend()` grew the `ast.List` that `ast.parse` produced, and since
  control-flow snapshots and per-call snapshots are shallow copies, every
  one of them saw the change -- including snapshots taken *before* the
  append ran. A call was therefore judged against a list append that had
  not happened yet. The list is now rebuilt and rebound copy-on-write, so
  each moment keeps its own node and `ast.dump(tree)` is identical before
  and after analysis.
- `PCL002` no longer reports a `json.dumps()` of a literal. A dict literal
  is insertion-ordered, so its output is the same every run and
  `sort_keys=True` changes nothing; `sort_keys` is meaningless on a list
  too. The README's CI recipe uses `--fail-on-warn`, so this was
  build-failing noise over correct code. A name, a call, a comprehension,
  a `**` merge and anything else assembled at runtime still reports, and a
  set literal still has no order to preserve.
- A sink now has to look like a completion, not just spell like one.
  `twilio.messages.create(body=", ".join(tags), ...)` is `.messages.create`
  like any Anthropic call and sent a text message, yet every node inside it
  was judged as prompt payload -- reporting `PCL003` and `PCL002` over a
  phone number. The dotted path must now be accompanied by a model or a
  prompt payload keyword (`model`, `messages`, `input`, `system`,
  `instructions`, `prompt`, `tools`), or by the legacy positional
  `create(model, messages)` form, which carries no keywords. This only ever
  narrows what counts as a sink: there is still no fallback accepting a bare
  `messages=` + `model=` pair, which is what any local helper looks like.
- A prompt-shaped *name* only means something in a file that deals with an
  LLM. `context = ", ".join(tags)` in a script that never mentions one used
  to report `PCL003` -- an ERROR that carries an autofix, so it could fail a
  build and rewrite ordinary data code on nothing but the word "context".
  Reachability through a real sink was always proof and still is; the name
  heuristic now additionally requires a recognized sink call or an import of
  `anthropic`/`openai`/`litellm`. Two tests that pinned the old behaviour
  were updated to include a call site, since what they were really testing
  was detection and the rewrite.
- A dynamic first *user* message is no longer reported when the call has a
  separate `system=`/`instructions=` argument. Anthropic keeps the system
  prompt out of `messages`, so `messages[0]` is the first turn rather than
  the start of the string -- and the README tells users to move dynamic
  values there, which made the tool contradict its own advice. `messages[0]`
  is treated as the prefix only when no such argument is present, when its
  role is `system`/`developer`, or when it carries `cache_control` (a
  breakpoint, where the rule is unchanged).
- Text already bound to a name now counts as text that comes *before* a
  later `+=`. `prompt = STATIC_RULES` followed by
  `prompt += f"\nTime: {datetime.now()}"` is the ordering this README
  recommends, but the augmented assignment only ever looked at its own
  right-hand side: with no static solid in it, Rule 3 fired inside the
  first 500 characters and reported `PCL001`. The same happened to
  `prompt = prompt + f"..."`. Bindings now record how much static text they
  open with, so a lowercase name earns solid status once it actually holds
  `STATIC_SOLID_MIN_CHARS` of it. The measurement is deliberately not a
  verdict about shouty names: `SYSTEM_PROMPT = "head: "` is still six
  characters, and taint appended to it is still reported.
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
